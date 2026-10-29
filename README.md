# MusyBoard core

The cryptographic core of **MusyBoard**, an Android keyboard that encrypts
messages *inside the keyboard*, before the text ever reaches the chat app. The
chat app (and its servers, backups and content scanners) only ever sees
ciphertext.

This repository contains the cryptography and the message format, written in
Rust, plus the bridges and tools built on top of it:

| Path | Crate | What it is |
|---|---|---|
| `src/` | `keyboard-cipher-core` | The core: key agreement, AEAD, message format, keyring logic. `#![forbid(unsafe_code)]`, no I/O |
| `jni/` | `keyboard-cipher-jni` | JNI bridge used by the Android app; the only place where `unsafe` exists |
| `cli/` | `keyboard-cipher-cli` | `kc`, a command-line second party for testing and for use from a PC |
| `gui/` | `keyboard-cipher-gui` | A small desktop app (egui) to read and write messages from a computer |
| `fuzz/` | | `cargo-fuzz` targets for the decoder and the parser |
| `docs/` | | Protocol specification, threat model, known issues |

Related repositories:

- [musyboard-android](https://github.com/muzif98/musyboard-android): the
  keyboard app, a fork of [HeliBoard](https://github.com/HeliBorg/HeliBoard)
  that builds this core from source.
- [musyboard-ios](https://github.com/muzif98/musyboard-ios): the same core
  compiled to WebAssembly and run inside Scriptable on iPhone.

> **Status: experimental, not independently audited.** The design has been
> reviewed only internally (code review, fuzzing, emulator testing). Do not rely
> on it where a mistake would have serious consequences.

## Why

The design targets one adversary: **platform-side mass scanning with bulk
retention**, such as the proposed EU "Chat Control" regulation. That means
automated, indiscriminate analysis of everyone's messages, with ciphertext
kept for later. It is not designed against a targeted attacker who invests
resources in one person, and it says so explicitly.

The constraints that shape everything:

- **No server, no handshake, no return channel.** Messages are one-shot blobs
  copied and pasted into third-party chat apps. They arrive late, out of order
  and more than once.
- **The keyboard sees the input field, never the chat history.** Writing into
  the field is native for a keyboard; reading is not. Encryption therefore
  never touches the clipboard; decryption does.
- **No network permission.** The app has no `INTERNET` permission at all.

## How it works

### Primitives

| Purpose | Primitive |
|---|---|
| Key agreement | X25519 (low-order points rejected) |
| Authenticated encryption | XChaCha20-Poly1305, 192-bit random nonce |
| Key derivation | HKDF-SHA-256, the nonce is the salt |
| Backup key derivation | Argon2id (64 MiB, 3 passes) |
| Text encoding | z-base-32, lowercase, strict canonical decoding |

All dependencies are pure Rust. Randomness and the current time are always
passed in by the caller, so the core is deterministic under test and every
format has frozen known-answer vectors.

### What a message looks like

```text
kc/ybndrfg8ejkmcpqxot1uwisza345h769...
```

A short cosmetic prefix (`kc/`, chosen so that chat apps do not turn it into a
link) followed by z-base-32, which survives autocorrect: no uppercase, no
punctuation, no ambiguous characters. The version, kind (message, identity
card, file, burn request) and scheme are inside the body and authenticated, so
from the outside every blob looks the same.

### Schemes

Every message is encrypted with XChaCha20-Poly1305 under a key derived with
HKDF from one or two X25519 exchanges. The schemes differ in which keys take
part:

| Scheme | Key material | Properties |
|---|---|---|
| Static | `DH(sender, recipient)` | Readable by both sides forever. Sender key in clear (used for first contact) |
| Ephemeral sender | `DH(eph, recipient) ‖ DH(sender, recipient)` | Sender identity hidden; stolen sender key does not open past messages |
| **Forward secrecy** (default) | `DH(eph, prekey) ‖ DH(sender, prekey)` | Each side carries a fresh temporary key *inside* the ciphertext; reading a message destroys older keys. Long-term keys alone open nothing from the second message on |
| Epoch ("burnable") | `DH(sender, recipient_epoch)` | Rereadable history for both sides until either side burns the conversation |
| Group | per-member slots wrapping one content key | Up to 8 recipients, no per-slot identifiers; no forward secrecy and no author authentication, both stated in the UI |

The sender is never trusted from the header. A blob is only attributed to a
contact after it decrypts, and pinning a new key (trust on first use) happens
only after a successful decryption. Every failure, whatever the cause, is the
same opaque error.

The full byte-level specification is in [docs/PROTOCOL.md](docs/PROTOCOL.md).

### Identity and trust

- One X25519 identity per user, valid for every contact.
- First contact through an **identity card** blob written straight into the
  chat field, or in person with a QR code (the high-assurance path).
- Contacts are pinned by public key (TOFU). Names are local labels; assigning
  a name already used by another key is reported as a conflict, Signal's
  "safety number changed", and never resolved automatically.
- **Fingerprints**: 120 bits, 24 z-base-32 characters in 6 groups of 4, for
  comparison out of band.
- **Backups**: identity and keyring encrypted with a passphrase (Argon2id +
  XChaCha20-Poly1305), with the parameters authenticated so they cannot be
  weakened by editing the file.

## What it protects, and what it does not

Protected:

- message content from the platform, its servers, cloud backups and automated
  scanning;
- integrity of every blob (header, scheme and kind are authenticated, no
  downgrade);
- past messages after a key compromise, when forward secrecy is on;
- plaintext never reaching the chat app's input field.

Not protected, by explicit choice:

- a compromised phone (root, keyloggers, malicious accessibility services);
- metadata: who talks to whom, when, and how much;
- the fact that encryption is being used (the `kc/` prefix is matchable);
- message length;
- replay of a valid blob (made visible by an authenticated composition time,
  not prevented);
- a future quantum computer ("harvest now, decrypt later"): X25519 is not
  post-quantum. A slot in the format is reserved for a hybrid scheme.

The complete threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md),
and the accepted residual risks and open questions in
[docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md).

## Building and testing

Requirements: stable Rust (MSRV 1.75), and a nightly toolchain only for
fuzzing.

```sh
cargo test                                  # core: unit tests and frozen KATs
cargo clippy --all-targets -- -D warnings

(cd jni && cargo test)                      # JNI bridge
(cd cli && cargo build --release)           # the `kc` binary
(cd gui && cargo build --release)           # the desktop app

cargo +nightly fuzz run roundtrip           # also: parse, decode
```

To build and test everything that depends on the core, including the Android
app and the iOS bridge checked out next to it as `../musyboard-android` and
`../musyboard-ios`:

```sh
./verify-all.sh            # full run
./verify-all.sh --quick    # skips the fuzz build and Android lint
```

The Android app builds the JNI library from this repository with `cargo-ndk`;
no prebuilt binaries are committed.

Code quality rules enforced by the compiler: no `unsafe` in the core; clippy
denies `unwrap`, `expect`, `panic!`, `todo!`, direct indexing and arithmetic
that can overflow; secrets are zeroized on drop and never implement `Debug`.

## `kc`, the command-line party

With the phone alone you can only encrypt to yourself, which tests nothing that
needs two identities (first contact, key change, label conflicts). `kc` is a
second, independent party:

```sh
kc init                         # create an identity
kc card                         # print an identity card to paste into a chat
kc decrypt "<blob>"             # decrypt, or pin an identity card
kc name 0 alice                 # name a contact
kc encrypt --to alice "hello"   # encrypt (forward secrecy on; --no-fs to disable)
kc contacts
kc archive chat-export.html     # decrypt every blob found in a file
```

`KC_HOME` moves the state directory, so several identities can live side by
side. The private key is stored in clear, protected only by file permissions:
it is a testing tool, and its identity is not worth as much as the phone's.

## Documentation

- [DESIGN.md](DESIGN.md): every design decision and the reason behind it.
- [docs/PROTOCOL.md](docs/PROTOCOL.md): byte-level specification.
- [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md): adversary, scope and
  assumptions.
- [docs/KNOWN_ISSUES.md](docs/KNOWN_ISSUES.md): accepted risks and open
  questions.

## Security

Please report vulnerabilities privately through GitHub's private vulnerability
reporting on this repository.

## License

GPL-3.0-only. See [LICENSE](LICENSE). All third-party dependencies are under
licenses compatible with it (MIT, Apache-2.0, BSD, Unlicense, Unicode-3.0).
