#!/usr/bin/env bash
# Verify the core and everything that depends on it, in one command.
#
#   ./verify-all.sh           full run
#   ./verify-all.sh --quick   without fuzz build and Android lint
#
# `cargo test` in this directory builds the core only. Its consumers are
# built separately and would not notice a breaking change:
#
#   jni/  cli/  gui/        separate crates, deliberately outside the workspace
#   ../musyboard-android    the keyboard app, builds jni/ with cargo-ndk
#   ../musyboard-ios        the WebAssembly bridge, in its own repository
#
# Exit status:
#   0  everything ran and passed
#   1  something failed: stops at the first failure and shows its log tail
#   2  passed, but at least one project was NOT checked
#
# The script never fixes anything: a check that modifies what it checks is no
# longer a check. When it knows the fix, it prints it.
#
# Android instrumented tests are not run: they need a running emulator.

set -uo pipefail

CORE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANDROID="${MUSY_ANDROID:-$CORE/../musyboard-android}"
IOS="${MUSY_IOS:-$CORE/../musyboard-ios}"
JSPY="${MUSY_JSPY:-$HOME/jstest-venv/bin/python}"
export PATH="$PATH:$HOME/.cargo/bin"

QUICK=0
[ "${1:-}" = "--quick" ] && QUICK=1

LOG="$(mktemp -d)"
SKIPPED=()
NOT_RUN=()

if [ -t 1 ]; then V=$'\e[32m'; R=$'\e[31m'; G=$'\e[33m'; B=$'\e[1m'; N=$'\e[0m'; else V= R= G= B= N=; fi

section() { printf '\n%s== %s ==%s\n' "$B" "$1" "$N"; }

# step NAME DIR COMMAND...
# Runs, logs everything, and stops at the first failure.
step() {
  local name="$1" dir="$2"; shift 2
  local file="$LOG/$(printf '%s' "$name" | tr -c 'A-Za-z0-9' '_').log"
  local start=$SECONDS
  printf '  %-58s' "$name"
  if (cd "$dir" && "$@") >"$file" 2>&1; then
    printf '%sok%s  %ss\n' "$V" "$N" "$((SECONDS - start))"
  else
    printf '%sFAILED%s\n\n' "$R" "$N"
    tail -n 30 "$file" | sed 's/^/    | /'
    printf '\n  Full log: %s\n' "$file"
    printf '\n%sRED%s, stopped at "%s".\n' "$R" "$N" "$name"
    exit 1
  fi
}

skip() {
  SKIPPED+=("$1: $2")
  printf '  %sSKIPPED%s %s: %s\n' "$G" "$N" "$1" "$2"
}

revision() {
  local dirty=""
  [ -n "$(git -C "$1" status --porcelain 2>/dev/null)" ] && dirty=" + uncommitted changes"
  printf '%s%s' "$(git -C "$1" log --format=%h -1 2>/dev/null || echo '?')" "$dirty"
}

printf '%sVerifying core, bridges and apps%s\n' "$B" "$N"
printf '  core     %s\n' "$(revision "$CORE")"
[ -d "$ANDROID" ] && printf '  Android  %s\n' "$(revision "$ANDROID")"
[ -d "$IOS" ] && printf '  iOS      %s\n' "$(revision "$IOS")"
[ "$QUICK" = 1 ] && printf '  %squick mode%s: no fuzz build, no Android lint\n' "$G" "$N"

# ---------------------------------------------------------------------------
section "core"
step "test" "$CORE" cargo test
step "clippy" "$CORE" cargo clippy --all-targets -- -D warnings
if [ "$QUICK" = 1 ]; then
  NOT_RUN+=("core fuzz build")
else
  # The fuzz targets build `Header` by hand and live outside the workspace:
  # a format change breaks them and `cargo test` does not notice.
  step "fuzz build (nightly)" "$CORE" cargo +nightly fuzz build
fi

# ---------------------------------------------------------------------------
section "bridges in the core repository"
step "jni: test" "$CORE/jni" cargo test --release
step "jni: clippy" "$CORE/jni" cargo clippy --all-targets -- -D warnings
step "cli: test" "$CORE/cli" cargo test
step "cli: clippy" "$CORE/cli" cargo clippy --all-targets -- -D warnings
step "gui: test" "$CORE/gui" cargo test
step "gui: clippy" "$CORE/gui" cargo clippy --all-targets -- -D warnings

# ---------------------------------------------------------------------------
section "musyboard-ios"
if [ ! -f "$IOS/Cargo.toml" ]; then
  skip "musyboard-ios" "not found in $IOS (set MUSY_IOS)"
else
  WASM="${CARGO_TARGET_DIR:-$IOS/target}/wasm32-unknown-unknown/release/musyboard_wasm.wasm"
  step "test" "$IOS" cargo test
  step "clippy" "$IOS" cargo clippy --all-targets -- -D warnings
  # Same flags as the published binary (paths remapped), and fails if
  # dist/ is not what the source produces.
  step "build wasm32, dist/ matches the source" "$IOS" ./build-wasm.sh --check

  # Scriptable instantiates the module with an empty import object, so the
  # binary must have no import section. Walk the sections rather than
  # searching for strings.
  step "binary has no imports" "$IOS" python3 - "$WASM" <<'PY'
import sys
d = open(sys.argv[1], 'rb').read()
if d[:4] != b'\x00asm':
    sys.exit("not a wasm module")
def leb(i):
    r = s = 0
    while True:
        x = d[i]; i += 1; r |= (x & 0x7f) << s; s += 7
        if not x & 0x80:
            return r, i
i, exports = 8, 0
while i < len(d):
    sid = d[i]; size, i = leb(i + 1)
    if sid == 2:
        sys.exit("the binary has an import section: Scriptable cannot load it with empty imports")
    if sid == 7:
        exports, _ = leb(i)
    i += size
print(len(d), "bytes,", exports, "exports, no imports")
PY

  if [ -x "$JSPY" ] && "$JSPY" -c 'import quickjs' 2>/dev/null; then
    for t in "$IOS"/scriptable/test-*.js; do
      step "JS: $(basename "$t")" "$IOS" "$JSPY" - scriptable/MusyBoard.js "$t" <<'PY'
import re, sys, quickjs
source = open(sys.argv[1]).read() + open(sys.argv[2]).read()
ctx = quickjs.Context()
out = []
ctx.add_callable('__out', lambda s: out.append(s))
ctx.eval('var print = function(s){ __out(String(s)); };')
try:
    ctx.eval('(async function(){' + source + '})()')
except Exception as e:
    out.append('EXCEPTION: ' + str(e))
print('\n'.join(out))
# Require the summary line with zero failures. An unexpected error halfway
# through stops execution before it is printed, so no line means red.
results = [re.search(r'(\d+) passati, (\d+) falliti', o) for o in out]
results = [m for m in results if m]
if not results or int(results[-1].group(2)) != 0 or int(results[-1].group(1)) == 0:
    sys.exit(1)
PY
    done
  else
    skip "musyboard-ios JS tests" "QuickJS not found ($JSPY with the quickjs module; set MUSY_JSPY)"
  fi

fi

# ---------------------------------------------------------------------------
section "musyboard-android"
if [ ! -f "$ANDROID/gradlew" ]; then
  skip "musyboard-android" "not found in $ANDROID (set MUSY_ANDROID)"
else
  export ANDROID_HOME="${ANDROID_HOME:-$HOME/android-sdk}"
  if [ -z "${JAVA_HOME:-}" ]; then
    JAVA_HOME="$(ls -d "$HOME"/jdks/jdk-21* 2>/dev/null | head -n 1)"
    export JAVA_HOME
  fi
  if [ ! -d "$ANDROID_HOME" ] || [ -z "$JAVA_HOME" ] || [ ! -d "$JAVA_HOME" ]; then
    skip "musyboard-android" "ANDROID_HOME or JAVA_HOME not found"
  else
    # `runTests` rather than `debug`: the variant HeliBoard created for tests,
    # which skips the tests documenting known upstream bugs (`...Fails`).
    # `-PsenzaRete` excludes XLinkTest, which queries third-party sites.
    step "JVM tests (including Robolectric)" "$ANDROID" ./gradlew :app:testRunTestsUnitTest -PsenzaRete
    NOT_RUN+=("link checks against the internet (XLinkTest): depend on third-party sites")
    # assembleDebug rebuilds jni/ with cargo-ndk from the sibling core and,
    # before packaging, checks that no unexpected permission (INTERNET
    # included) entered the merged manifest.
    step "APK (rebuilds jni, checks permissions)" "$ANDROID" ./gradlew --quiet :app:assembleDebug
    if [ "$QUICK" = 1 ]; then
      NOT_RUN+=("Android lint")
    else
      step "release lint" "$ANDROID" ./gradlew --quiet :app:lintVitalRelease
    fi
  fi
fi
NOT_RUN+=("Android instrumented tests (need an emulator)")

# ---------------------------------------------------------------------------
printf '\n'
for n in "${NOT_RUN[@]}"; do printf '  not run: %s\n' "$n"; done
if [ "${#SKIPPED[@]}" -gt 0 ]; then
  printf '\n%sGREEN, BUT INCOMPLETE%s: %s to check:\n' "$G" "$N" "${#SKIPPED[@]}"
  for s in "${SKIPPED[@]}"; do printf '  - %s\n' "$s"; done
  exit 2
fi
printf '\n%sGREEN%s: core, bridges and apps build and pass together.\n' "$V" "$N"
exit 0
