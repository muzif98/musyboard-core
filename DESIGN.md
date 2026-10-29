# Design decisions

This document records the decisions behind the core and the reasons for each
of them. The byte-level format is specified in [docs/PROTOCOL.md](docs/PROTOCOL.md);
this file explains *why* it looks the way it does.

Decisions are referred to by letter (C, D, E, F, G, H, I, J, K, L) in the code
and in the other documents. A closed decision is not reopened without new
information; where an alternative was considered and rejected, the reason is
written down so that it is not rediscovered as an "improvement".

## Contents

- [Scope of the crate](#scope-of-the-crate)
- [Usage model](#usage-model)
- [Threat model in short](#threat-model-in-short)
- [Primitives](#primitives)
- [Surface encoding (E)](#surface-encoding-e)
- [Sentinel](#sentinel)
- [Envelope format](#envelope-format)
- [Composition timestamp (C)](#composition-timestamp-c)
- [Errors](#errors)
- [Secrets in memory](#secrets-in-memory)
- [Static scheme and the nonce](#static-scheme-and-the-nonce)
- [Fingerprint (D)](#fingerprint-d)
- [Identity, TOFU and labels (F)](#identity-tofu-and-labels-f)
- [First contact](#first-contact)
- [How a blob reaches the keyboard](#how-a-blob-reaches-the-keyboard)
- [Companion activity and permissions](#companion-activity-and-permissions)
- [Current recipient](#current-recipient)
- [Ephemeral sender (H)](#ephemeral-sender-h)
- [Full forward secrecy (I)](#full-forward-secrecy-i)
- [Burnable conversation (J)](#burnable-conversation-j)
- [Encrypted files (G)](#encrypted-files-g)
- [Group messages (K)](#group-messages-k)
- [Post-quantum slot (L)](#post-quantum-slot-l)
- [A family of bugs: self-poisoning state](#a-family-of-bugs-self-poisoning-state)
- [Implementation rules](#implementation-rules)
- [Testing](#testing)

## Scope of the crate

The core does key derivation, AEAD, serialisation of the format, surface
encoding and the TOFU keyring logic (as an abstraction).

It does **not** do I/O, filesystem, network, storage, JNI, system clock or UI.
Randomness and the current time are **injected** by the caller as parameters,
never taken from globals. Without this, test vectors for the format could not
be written and tests would not be deterministic.

The JNI bridge lives in a **separate crate** (`jni/`). The separation is not
organisational: in a JNI bridge `unsafe` is unavoidable (the `extern "system"`
symbols depend on the JNI contract, not on the type system), while the core is
and stays `#![forbid(unsafe_code)]`. Keeping them together would give up that
guarantee exactly where it matters most. The bridge has one extra rule: **no
panic may cross the boundary**. Unwinding out of an `extern` function is
undefined behaviour, not a clean crash, so every entry point is wrapped in
`catch_unwind`.

## Usage model

One-shot messages, copied and pasted inside third-party chat apps. There is no
return channel, no handshake and no shared state between the parties. Messages
arrive late, out of order and more than once. Any assumption of interactivity
is wrong by construction.

## Threat model in short

The full threat model is in [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

The reference adversary is **platform-side mass scanning** (as in the proposed
EU "Chat Control" regulation): automated, indiscriminate analysis of every
user's content with bulk retention. It is **not** a targeted adversary
investing resources in one user. This distinction drives most of the design:
defending against a classifier running over all traffic is a different problem
from defending against an analyst looking at you.

Protected: the content of messages from whoever reads the chat (platform,
servers, cloud backups, automated scanning), and the ciphertext from tampering.
Plaintext never reaches the chat app: encryption happens in the keyboard,
before the content enters the app.

Not protected, by explicit choice:

- a compromised endpoint (keylogger, root, screenshots, accessibility
  services) and scanning at OS level rather than app level;
- social metadata: who talks to whom stays visible to the platform with any
  design;
- the fact that encryption is used. The sentinel is the one element of the
  format that a single regex can match over all traffic. The pseudo-link
  defends against a human eye, not against a classifier. The alternative (no
  sentinel, recognition by attempted decryption) was evaluated and rejected
  for usability;
- correlation of messages from the same sender through the public key in
  clear. Near-zero cost against this adversary, which already knows the
  sending account. Against a targeted adversary the assessment would differ.
  The ephemeral schemes (H, I) do not have this residual;
- compromise of long-term keys, **unless forward secrecy is on** (I). That is
  the risk that bulk retention makes grow over time: an archive kept today plus
  keys stolen tomorrow equals retroactive decryption. With the chain active,
  long-term keys no longer open anything from the second message on,
  attachments included;
- **replay** of a valid blob. A blob is valid forever and can be reposted.
  Low priority here, because replay is an active, targeted action, not
  something that emerges from mass scanning. Mitigation (C): the composition
  timestamp inside the ciphertext, shown in the UI. It does not prevent replay;
  it makes it *visible to a human*.

## Primitives

- **X25519** for key agreement. Widely deployed, mature pure-Rust
  implementations, 32-byte keys.
- **XChaCha20-Poly1305** as AEAD. No need for AES hardware, constant time in
  pure software. The 192-bit nonce is mandatory here because the static ECDH
  secret is fixed per pair of identities (see
  [Static scheme and the nonce](#static-scheme-and-the-nonce)).
- **HKDF-SHA-256** to derive the AEAD key from the ECDH output. The raw
  shared secret is never used as a key.
- **Argon2id** for backups only. A backup leaves the device, so whoever gets it
  can try passphrases offline and in parallel; it needs a *slow* KDF. HKDF is
  fast on purpose and is exactly the wrong tool there.
- Every X25519 operation rejects non-contributory (low-order) results.
- All dependencies are pure Rust; no crate that links C code is accepted when a
  pure-Rust alternative exists.

## Surface encoding (E)

**Lowercase z-base-32.** It survives autocorrect: no uppercase, no
punctuation, no visually ambiguous characters.

**Implemented in-house** (`src/encoding.rs`) rather than taken from a crate.
The specification is bit-oriented and only the byte-aligned case is needed
here, so the semantics of the padding bits had to be decided and frozen.

**Strict decoding**: characters outside the alphabet (uppercase included),
lengths that cannot come from whole bytes, and non-zero trailing padding bits
are all rejected. Without this, one blob would have several distinct textual
forms, and two identical messages might not compare equal as strings.

**Test vectors.** The EXAMPLES table of the specification has ten rows, but
only two are byte-aligned: `F0 BF C7 -> "6n9hq"` and `D4 7A 04 -> "4t7ye"`.
The others encode sub-octet quantities that this API does not express. The
30-bit row is also **wrong in the specification itself**: its base32 column has
7 characters where 30 bits need 6, and its z-base-32 value (`6im5sd`) does not
match its own base-2 column, which gives `6im54d`. This was confirmed
independently: the Go implementation `corvus-ch/zbase32` computes `6im54d` and
notes in its tests that it differs from the specification by one character.
The specification is a static text file with no maintainer, so there is no
upstream to fix. That row is not used in any form. Coverage of other lengths
comes from differential testing against the `zbase32` crate, not from invented
vectors.

## Sentinel

- A cosmetic pseudo-link (`kc/`), not a bare string. It is aesthetics and
  social plausibility for a human eye only, **not** a security property. Never
  clickable, never a real domain, never a network request.
- It **must not be recognised by chat linkifiers**; otherwise the platform
  unfurls it server-side and sends the blob to a third party. Hence no `://`,
  no `www.`, no `label.tld` pattern. The slash is not in the z-base-32
  alphabet, so the separator is unambiguous.
- It stays in clear by necessity: it identifies the blob before decryption.
- **It does not contain the version.** The version lives in exactly one place,
  the first byte of the body. A version in the sentinel would be a second
  source of truth, with a concrete consequence: a blob from a future version
  would not be recognised as ours, and the user would read "this text is not
  encrypted" instead of "update the app".
- **Recognition tolerates surrounding text.** `parse` does not require the
  sentinel at the start nor the blob to run to the end: it looks for the
  sentinel anywhere and takes the maximal run of alphabet characters after it.
  Real inputs are never clean (clipboard and share sheet add a newline, manual
  selection drags in a "look: " prefix). A valid blob with a trailing `\n` is
  not foreign, it is ours.

## Envelope format

- Two text blob kinds (`Message`, `IdentityCard`) are distinguished by a `kind`
  byte **inside** the body, not by different sentinels: from outside they must
  be indistinguishable. A dedicated sentinel for identity cards would be a
  clear-text marker of "this user is adding a new contact", collected for free
  by mass scanning.
- `kind` is part of the AAD, so a blob cannot be reinterpreted as a different
  kind.
- **`kind` protects the type, not the scheme.** Two schemes can share a `kind`
  and derive the same key: the static `seal` and `seal_epoch_bootstrap` both
  compute `DH(sender_identity, recipient_identity)` with the same recipient in
  the HKDF info. The only difference is the flags byte, which is in the AAD,
  but the AAD is built from the flags the blob **declares about itself**. The
  tag would verify and the plaintext would be read with the wrong layout (32
  bytes of message taken as an epoch key). Therefore **every opening function
  checks the scheme it expects internally**, not in the caller: `SchemaEpoca`
  for the two epoch variants, and the `Origin::Mittente` check on the static
  path. Doing it only in the dispatcher was not enough, because those functions
  are public and are also called from `jni/`, `cli/` and `gui/`.
- **Flags are not a field** of `Header`; they are a function of its `Origin`.
  Two sources of truth for the same fact would make it possible to build an
  inconsistent header, which fails authentication opaquely, the hardest
  failure to diagnose. For the derivation to stay valid, `parse` **rejects
  undefined flag bits** instead of ignoring them.
- **`parse` returning `Ok` says nothing about integrity.** The ciphertext has
  variable length, so truncating it yields a well-formed message with a shorter
  ciphertext, and no length field could prove otherwise (it would be in clear
  and an attacker would adjust it). Truncation is caught by the Poly1305 tag at
  decryption, which is the right place. The parser only guarantees a complete
  header and at least one tag's worth of ciphertext.
- **Identity cards carry random padding.** Without it, a card would have a
  fixed length (39 bytes, 68 characters) while the shortest message has 127
  characters: one length rule would isolate all cards in all traffic. That is
  exactly the marker that putting `kind` inside the body was meant to avoid.
  The padding moves the length into the range of short messages. As a
  consequence, a card has no unique textual form, unlike a message; that is
  the point. *Accepted residual:* over many samples the distributions remain
  distinguishable (cards are uniform, messages follow text lengths). This
  defends against a cheap rule applied to all traffic, not against statistics
  on a chosen user.
- *Accepted residual:* blob length reveals plaintext length. It adds nothing
  to what the platform would see without the system (the text itself), so no
  padding is paid for it.
- **Identity cards carry a 4-byte checksum.** It is not authentication and does
  not claim to be: a card can be replaced in transit, which is the risk TOFU
  accepts. It protects against **corruption**: a truncated card would be
  pinned as a valid key, and every later message to that contact would fail
  opaquely.
- A version byte comes first. The tier byte is in the **authenticated** part
  (AAD), so an active attacker cannot force a downgrade.
- The `ForwardSecret` tier is parsed but not executable (`TierUnsupported`).
  It is not to be confused with decision I, which implements forward secrecy
  **inside** the baseline tier through flag bits. The tier is a free slot in
  the format for a future scheme, not the mechanism in use.
- The format is permanent: once a version is released, changes add a new
  version instead of modifying the old one.

## Composition timestamp (C)

The composition time is the first 8 bytes of the plaintext, inside the
ciphertext. It is authenticated by the AEAD without being in the AAD, and
invisible to the platform (which knows the message time anyway).

*Why not a validity window in the AAD*, which would actually prevent replay:
it would make legitimate messages read late fail to decrypt, and in a system
where the recipient takes a deliberate action for every message, reading three
days later is normal. It would also need a clock in the core, which has none
by design.

*Why not a cache of seen nonces*, which would block replay: it needs
persistent state that grows without bound, and the core is stateless by
construction.

The timestamp is **authenticated but not verifiable**: nobody can prove the
sender's clock was right. It is shown and never used for automatic decisions.
An absurd timestamp is not an error, and rejecting messages on a strange date
would make the system unusable for anyone whose phone clock is wrong. (Where
state does depend on it, see
[self-poisoning state](#a-family-of-bugs-self-poisoning-state).)

## Errors

- Any AEAD failure is a single opaque `Error::Crypto`. "Invalid tag", "wrong
  key" and "corrupted nonce" are **never** distinguished: that would be a
  channel that helps an attacker. Diagnostics here are not to be "improved".
- No sentinel is `NotOurBlob`, a **normal outcome**, not a serious error: the
  keyboard uses it to decide whether to offer "decrypt".
- Unknown versions and tiers are `UnsupportedVersion` / `TierUnsupported`,
  which the UI shows as "update the app", never as "corrupted".
- One public `Error` type for the whole crate.

## Secrets in memory

- Private keys and plaintext are zeroized on drop and never implement
  `Debug`, `Display` or `Serialize`.
- The guarantee stops at the JNI boundary: a `java.lang.String` is immutable
  and cannot be zeroized. Secrets cross to the JVM as **`byte[]`**, never as
  `String`. This is why the public API returns `Plaintext`, not `String`.

## Static scheme and the nonce

- Baseline sender authentication is static-static ECDH between our secret and
  the recipient's public key (`crypto_box`-style).
- The sender's public key is in the header **in clear**: it is what makes the
  first TOFU contact work. The resulting linkability is accepted (see the
  threat model).
- `sender_pub` is an **optional field signalled by a flag bit**, not a field
  assumed to be present. This is what later made the ephemeral schemes (H, I)
  possible without breaking the format; no code may assume it is there.

The same pair of identities always produces the same ECDH secret. The random
192-bit nonce is therefore **the only thing** that prevents keystream reuse:
never counters, never short nonces, never nonces derived from content. The
nonce is also the HKDF salt, so the effective AEAD key changes on every
message.

## Fingerprint (D)

SHA-256 with domain separation over the public key, truncated to **120 bits**,
rendered in z-base-32 in groups of 4: **24 characters in 6 groups**. Frozen:
it is what two people read aloud or compare on screen, and changing it would
invalidate every verification already done.

*Why 120 and not 96*: the binding property is **second-preimage** resistance
(to impersonate Bob you need a key whose fingerprint equals Bob's, which is
fixed and not chosen by the attacker), and 96 bits are enough for that. But
**collision** resistance is half the length, and 48 bits are within reach of
anyone with GPUs. No flow depends on collisions today, because pinning stores
the full key, not the fingerprint, but the format is permanent and a future UI
might rely on it without noticing. The margin costs four characters.

No word list: maintenance, localisation and phonetic ambiguity are not worth
the gain, and the z-base-32 alphabet is already chosen to be unambiguous.

## Identity, TOFU and labels (F)

- On first appearance a peer's public key is pinned **without a label**.
- **The identity of a contact is a local label assigned by the user** (F).
  Without it, two different keys are just two different peers, and "Mark's key
  changed" is not even expressible: the keyring is indexed by public key.
- Hence **pinning can never be a conflict**. When an unknown key arrives, the
  system cannot know whether it is a new contact or a known one with a new
  phone; only the user knows. `PinOutcome` has two cases, and conflicts live in
  `LabelOutcome`.
- The conflict fires **when a name already used by another key is assigned**.
  This is Signal's "safety number changed" model, and it is the right moment to
  show both fingerprints, because it is the only moment in which the user is
  declaring who someone is. On conflict **nothing changes**: the old key keeps
  the name until explicit confirmation.
- The conflict is an **outcome** (`LabelOutcome::Conflict`), not an `Err`: it
  is not a failure, it is a state that needs UI.
- `replace_pinned` moves the label to the new key and **clears `verified`**:
  a new key has, by definition, not been compared out of band.
- *Residual:* a key change is not detected **automatically** on arrival, only
  when the user names the new peer. Automatic detection would require inferring
  identity from the app context, which is noisy with several contacts.

## First contact

- There is **one** identity, valid for every recipient. There is no per-contact
  key: the pairwise secret is computed, not exchanged. Any UI suggesting
  otherwise is wrong.
- Every static-scheme message carries `sender_pub`, so receiving one pins the
  sender automatically. Only the very first contact in one direction is left.
- For that case there is the **identity card** blob. The keyboard writes it
  straight into the text field with `commitText` and the user presses send. No
  clipboard. An asymmetry that runs through the whole project: **writing into
  the field is native for an IME, reading is not**. The keyboard sees the input
  field, never the chat history. This is why encryption never goes through the
  clipboard and decryption does.
- Bootstrap cost: one tap, once per contact, in one direction.
- The in-person QR code is the high-assurance path: the only thing that closes
  first-contact MITM, which TOFU alone does not.

## How a blob reaches the keyboard

Four paths, all equivalent for the core: they deliver a string, and
`handle_incoming_text` does not know which one it came from.

1. **Clipboard**: the baseline, works everywhere. The default IME is
   explicitly allowed to read the clipboard on Android 10+, and HeliBoard
   already reads it for clipboard history, so the marginal privacy cost is nil.
   The Android 12 toast appears the *first* time an app reads data placed by
   another app, and `getPrimaryClipDescription()` never triggers it. Hence:
   passive polling of the description, reading the content only on an explicit
   user gesture.
2. **`ACTION_PROCESS_TEXT`**: a companion activity adds "Decrypt" to the text
   selection toolbar. One tap, no clipboard. Only works where the app uses the
   standard selection toolbar (not, for example, in apps with a custom
   long-press menu). Excellent where present, unreliable as the only path.
3. **Share sheet (`ACTION_SEND`)**: universal fallback, more taps. The
   decrypted text appears in our own activity and never touches the chat app.
4. **Input field**: if the blob is in the field the IME is serving. Free,
   marginal in chat, useful for email and notes.

**Excluded: `NotificationListenerService`.** It would give automatic decryption
of incoming messages, but requires access to *all* notifications on the
device, which demolishes the premise of the project; and notifications truncate
long text, so it would not work on blobs anyway.

**Architectural limit, accepted as a product constraint:** no path gives
automatic decryption of what scrolls through the chat. The recipient takes a
deliberate action for each message received.

## Companion activity and permissions

Paths 2 and 3 are system intents: an `InputMethodService` cannot receive them,
so an activity is needed. It lives in the **same APK** as the IME: same
process, same identity, same keyring. Two APKs would mean two copies of the
private key or an IPC channel carrying secrets.

**A trap not to repeat.** The `ACTION_PROCESS_TEXT` contract lets the activity
return replacement text to the caller with `setResult(RESULT_OK, ...)`. It is
the natural implementation of that intent and the worst possible one here:
returning the plaintext hands it to the chat app the selection came from,
exactly the app the project exists to keep it away from. `setResult` is never
called with data; the activity exits without a result and the text in the
calling app stays encrypted.

Mandatory attributes on any activity showing plaintext: `FLAG_SECURE` (before
any `setContentView`), `noHistory`, `excludeFromRecents`, `taskAffinity=""`,
`launchMode=singleTask`. Without `excludeFromRecents` / `FLAG_SECURE` the system
saves a screenshot of the decrypted text to disk for the Recents screen.

**No permissions, including `CAMERA`.** The app has no `INTERNET` permission;
that is its main property, and it acquires no others. Consequence for QR codes:
**they are shown, not scanned.** Generating a code needs no permission, reading
one needs `CAMERA`, and that permission is not taken. In-person first contact
is still closed, because it is enough that *one* side scans: the other points
any QR reader at the code, gets the `kc/...` string and shares it into the app.
This is a choice, not a gap waiting to be filled.

The contacts UI is not in the launcher; it is reached from the keyboard
settings. An icon would be a second visible marker of the system and would do
nothing a settings entry does not.

## Current recipient

A keyboard does not know who you are talking to. `EditorInfo` gives the app's
package, not the conversation, and there is no API for that. An accessibility
service reading the screen would know, and is **excluded**: it would destroy
the premise of the project.

The recipient is established in this order:

1. **implicitly, by decrypting**: whoever reads and then replies has already
   chosen by reading. This makes the dominant case automatic;
2. **by memory, per package**: one contact per app means zero interaction;
3. **explicitly, from the toolbar**: the fallback for several contacts in the
   same app. Only an already pinned peer can be chosen.

Within one app the **last sender read** wins. This rule makes the common case
automatic and is also the only one that can surprise the user, so it has a
dedicated test.

**Critical order in `handle_incoming_text`: decrypt BEFORE touching the
keyring.** A successful decryption is the proof that the writer really holds
the declared private key and that the message was for us. Pinning first would
let anyone fill the keyring with invented peers, or show the user a false "key
changed" warning by sending garbage.

Never guess. With no recipient the result is `UnknownPeer` and the user is
asked: encrypting for the wrong person is the worst possible failure.

## Ephemeral sender (H)

An alternative scheme in the same tier: the key in the header is single-use and
the sender's identity does not appear in clear. Signalled by the `EPHEMERAL`
flag bit, which always comes with `SENDER_PUB`; "ephemeral without a key" is an
inconsistent header and the parser rejects it.

The AEAD key comes from **two concatenated exchanges**:

```text
secret = DH(ephemeral, recipient) || DH(sender, recipient)
```

The first gives half forward secrecy: the ephemeral key is dropped right away,
so whoever later obtains the *sender's* stable key cannot reopen yesterday's
messages. The second is the **proof of identity**: only the holder of the
sender's private key can produce that secret, so a successful decryption proves
who wrote.

**Why not a signature:** it would need Ed25519 next to X25519, that is, one
more primitive and one more field to verify. Here the proof comes from the
derivation itself, with no extra surface.

**How the recipient knows who wrote:** it does not, it tries. One decryption
per pinned contact; the first that succeeds identifies the sender. With a few
dozen contacts the cost is not noticeable. Senders who are not in the keyring
are not recognised, by design: an unknown sender must be introduced with an
identity card first, otherwise anyone could make messages appear in the
keyring. When all attempts fail the error is `Crypto` like any other.
Distinguishing "none of my contacts" from "corrupted" would tell an attacker
something about the keyring.

**What it does not solve:** whoever obtains the **recipient's** key still opens
everything, because both exchanges go through it. That requires a temporary
key on the receiving side too, which is decision I.

**Compatibility:** an ephemeral message cannot be opened by an older version.
The choice therefore belongs to the caller, not the core: the core does not
know the recipient's version, and guessing would produce unreadable messages.

## Full forward secrecy (I)

Closes the gap left by H: the **recipient** also contributes a temporary key.
Signalled by the `PREKEY` bit, which always implies `EPHEMERAL`.

```text
secret = DH(ephemeral, recipient_prekey) || DH(sender, recipient_prekey)
```

**The prekey travels inside the ciphertext, not in the header.** In clear it
would be an identifier that changes every message but links the two ends of a
conversation, handing mass scanning exactly the correlation that the ephemeral
sender removes.

**How the chain starts.** The first message cannot have full forward secrecy:
we do not have a prekey of the other side yet. It falls back to scheme H, and
**still carries its own prekey inside the ciphertext**. Hence the rule: *every*
message carries one, including those that do not use one. If only messages
already using a prekey carried one, the chain would never start.

The fallback **cannot be forced as a downgrade**: it depends on what the other
side sent us in the past, not on what the incoming message declares.

**Per-contact state** lives in the keyring (`PrekeyStore` in the core: a data
structure without I/O, so the three front-ends do not each have their own
version). Up to `MAX_PREKEY_MIE = 64` of our prekeys are kept per contact; a
long message split into parts uses one key per part.

**That number is not a trade-off on forward secrecy.** One of our prekeys only
opens messages encrypted with it, and the surplus ones never opened anything,
because no message used them. Keeping more does not lengthen any openable past.
The cap exists for one reason only: to stop the state from growing towards a
contact who never answers (64 keys are 2 KB per contact). It is also the cost
of reading: a forward-secret blob that opens with nothing costs, in the worst
case, contacts × 64 × 2 Diffie-Hellman operations.

Three keys (an earlier value) were too few, for a practical reason found by
testing: whoever replies uses the latest prekey **they have seen**, not the
latest that exists. With three, four messages in a row before a reply were
enough to make that reply unreadable, and four messages in a row are normal in
a chat. There is a test with twenty.

**The act that produces the property is `drop_my_prekeys_older_than`**, that
is, throwing keys away, not encrypting.

**And it is READING that throws away, not replying.** The call is on the
decryption path (`prova_con_le_prekey`, `prova_le_prekey_sul_file`): opening a
message immediately kills all of our prekeys older than the one it used,
without waiting for a reply.

Not everything older is thrown away: `truncate` keeps the used key and the
newer ones, and **never fewer than `CODA_MINIMA = 8`**. Without that minimum,
opening a message destroyed every older unread message from the same person.
Two messages read in a different order from the one they were sent in were
enough, and with copy-paste people open whichever blob is under their finger.
To the user this looked like "sometimes their messages are unreadable". Test:
`due_messaggi_letti_fuori_ordine_si_aprono_tutti_e_due`.

**What the minimum costs, stated in full.** The eight most recent keys survive
a read, so within that window a message can be reopened, including one already
read, and someone who seizes the phone opens up to eight more. It is a real
weakening of forward secrecy, **bounded by construction**: a fixed number, not
a growing window, and it slides away by itself because every sent message
pushes a new key in. Beyond the eighth the chain kills as before;
`la_cronologia_non_si_rilegge` checks both sides. The trade-off is eight more
messages readable by someone who seizes the phone, against messages that do not
arrive at all. A security property that makes the system unreliable gets
switched off by users, and then protects nothing.

The UI wording is therefore: *a message can be reopened until the
conversation has moved on by a few messages*. Throwing away the key just used
as well (a message opens once only) was **considered and rejected**: it gains
little, because whoever seizes the phone right after recovers a message that
was just on screen, and costs a visible malfunction.

**Encrypting is no longer a read-only operation.** It generates a new prekey
and stores it in the keyring, so every caller must persist immediately: a
process that dies first takes with it the key the other side will reply with.
This holds for all front-ends (keyboard, GUI, CLI) and is written on the JNI
signature, because it cannot be guessed from there.

**The price:** a message opens once only. No history; archive and "rebuild
chat" features reopen nothing sent this way. That is why there is a switch
(one, on by default), and its text states the price, not only the benefit.

**Attachments use the chain too** (`encrypt_file_with`): a file without the
chain is a bigger hole than a message without it, since a photo is worth more
than a line of text and stays on the recipient's phone. Attachments use **the
same per-contact state** as messages: it is the same conversation with the same
person, and two separate chains would mean twice the keys to keep and twice the
chances of not throwing them away. `kind` stays in the AAD, so an attachment
cannot be read as a message even with the chain; there is a test.

## Burnable conversation (J)

Answers the question "can I make the messages with one person unreadable, for
both of us?". Yes, **with forward secrecy off**, and with a limit that must be
stated first.

**What is guaranteed and what is not.** On our side it is cryptographic: the
keys disappear and do not come back. On the other side it is a **request**:
their app has to honour it. Someone who wants to keep the messages can, and the
platform has its own copy of the ciphertext anyway. It is not remote deletion,
and the UI must not describe it as such.

**Why a new scheme was needed.** Without the chain, the reading key is not
stored anywhere: it is **recomputed** from the identity and the sender's
public key, which travels in clear. There is nothing to delete; forgetting a
contact makes nothing unreadable (there is a test that checks this). A
**per-contact** key was needed, and until then it only existed with the chain
on, where there is no history anyway.

**The scheme.** One epoch key per contact, which **does not rotate per
message**. This is exactly the difference from decision I, and what makes
history possible:

```text
secret = DH(sender, recipient_epoch)
```

No ephemeral key: without one, the derivation can be repeated, so the message
can be reread by its author too. Signalled by `PREKEY` **without**
`EPHEMERAL`.

**The epoch has its own place in the keyring, separate from the chain.** At
first it was "the most recent of my prekeys": two things with opposite rules in
the same container. The chain exists to rotate and be thrown away; the epoch
exists **because it does not rotate**. Sharing a container, reading a
forward-secret message threw the epoch away, and the burnable conversation
became unreadable with nobody having burned it, with an `Error::Crypto`
indistinguishable from a damaged blob. Test:
`leggere_un_messaggio_non_brucia_l_epoca`.

Two rules follow. Whoever reads an epoch message looks at `my_epoch`, not at
the chain; and the on-disk format stores the epoch in its own field, never as
an extra column on a chain row. A reader that mistook it for a prekey would
throw it away on the first read, reintroducing the bug from the storage side.

**The `EPOCH_OFFER` bit**: "the ciphertext carries my epoch key". Distinct from
`PREKEY`, which says the opposite (*using* the other side's key). They must be
separate because the first message carries one's own epoch key without being
able to use the other's. Without the distinction that message would have to be
ephemeral, that is, not rereadable by its author, which is the case this
decision exists to make possible.

**The burn** is a new `kind` (`Burn`), not a message with a marker in the text:
`kind` is in the AAD, so a burn is never a disguised message or vice versa. It
carries no text. The recipient **decrypts** it to learn who sent it; otherwise
anyone could reset other people's conversations by sending a random blob
(there is a test).

**A burn can be reposted, and that cannot be prevented.** A blob is valid
forever: whoever saw it in the chat can paste it again months later and destroy
a conversation that had restarted in the meantime. This is the replay of the
threat model applied to the only **destructive, repeatable** operation in the
system. Rejecting it by date is ruled out by decision C for the same reason as
everywhere else: the timestamp is authenticated but not verifiable, and a wrong
clock is not an attack. What remains is C's defence, making it **visible to a
human**: all front-ends show when the burn request was composed. When that date
is read the conversation is already destroyed; a repost is discovered, not
prevented. Preventing it would mean remembering per contact the time of the
last honoured burn and ignoring older ones, at the price of more per-contact
state and another storage format change; that was not taken.

**Accepted residual:** the **first** message of a conversation does not burn.
It is encrypted to the other side's identity, because when it is sent nothing
shared exists yet, and the identity survives a burn by definition. This holds
for any message a recipient can open without prior state. It would be closed by
putting an epoch key in the **identity card**, so that an opening message is no
longer needed.

**After a burn the conversation restarts by itself**, without exchanging
identity cards again: whoever no longer has an epoch key of the other side
starts again from the opening message, which carries a new one.

## Encrypted files (G)

**G1: yes, as a document attachment.** The file is chosen from the contacts
activity, encrypted into a binary container, and handed to the chat through the
share sheet, which sends it as a *document*; chat apps do not recompress
documents. The recipient shares it back into the app.

Two technical constraints decide the shape:

1. *An IME cannot attach a file.* It can insert text and, on Android 7.1+,
   images through `commitContent` (the GIF keyboard path), but the receiving
   app treats that content **as an image and recompresses it**, which destroys
   the ciphertext. Audio cannot be inserted at all. So any solution goes
   through the companion activity and the share sheet, not the keyboard.
2. *The text format inflates by 1.6×*: a 500 KB photo would be 800 KB of
   characters. Out of scale for a chat field.

**Accepted residual:** the chat shows an attachment that opens with nothing
else, a much stronger marker than a text blob, and its **size** reveals far
more than the length of a text. Accepted because the observed alternative is
worse: without this path, photos are sent anyway, in clear, in the same
conversation.

**G2: binary container, same envelope, `kind = File`.** No z-base-32 and no
separate format. `kind` is in the AAD, so an attachment is never read as a
message. A separate format would have meant a second parser to keep in step
with the first, that is, two ways of getting the same thing wrong.

**G3: declared `.kc` extension, original file name DROPPED.** The attachment
is named `kc-<random>.kc`. Blending in is not a property this project counts as
security (an extension like `.dat` would fool nobody who looks at the first
bytes), so the extension is declared. The name, on the other hand, is real
metadata and is removed: `IMG_20260810_marks-birthday.jpg.kc` would by itself
tell almost everything (date, occasion, person) to anyone who sees the
attachment pass. The original name exists only inside the ciphertext.

**G4: the recipient is always explicit**, and the recipient remembered for the
app is **not** used even when present. A file sent to the wrong person cannot be
withdrawn and, unlike a message, **stays on the recipient's phone**. For a
message the shortcut is worth the risk; for a file it is not.

**G5: received plaintext never touches the disk.** It lives in memory, is shown
in a `FLAG_SECURE` window, and reaches the disk only if the user saves it
through the system document picker, with an explicit gesture and a destination
of their choice. The save dialog says what that means: from then on it is a file
like any other and enters the gallery and backups. Outgoing ciphertext goes
through `cacheDir/cipher-share`, which is **emptied on every share**, keeping
only the last file. It is not secret (it is encrypted), but a folder that
accumulates is a list of how many files you sent and when.

**G6: the smaller of 50 MB and a quarter of the heap; no splitting.** The cap is
not a fixed number because encrypting holds the plaintext, the ciphertext and
the JNI copies in memory: about four times the file. On a phone that cannot
handle the limit, the user is told **before**, instead of waiting for the
encryption and then dying of `OutOfMemoryError`. No splitting: it would multiply
the marker G1 already accepts reluctantly. The 50 MB value is a conjecture to be
revised with real data.

## Group messages (K)

One blob, read by several people, **pasted into ONE group conversation**. It is
not the same blob sent to N separate chats: that would be worse than encrypting
N times, because the same string in N conversations reveals the full set of
recipients to anyone who compares traffic for equality. This is a format
constraint, not usage advice.

### K1: group messages are encrypted but not forward-secret

One ephemeral sender key for the whole envelope; each recipient gets the content
key wrapped to their **identity**, not to a prekey. No per-slot prekeys, no
per-slot mode. Five reasons, by weight; the first two are sufficient on their
own.

1. **Full forward secrecy could not be bought anyway: a group has the forward
   secrecy of its weakest member.** The text is encrypted once under a content
   key, and that key can be recovered from *any* slot. The message stays
   openable as long as one recipient has not advanced their chain. My destroyed
   prekey protects my slot; if another member's identity leaks, the attacker
   replays the whole group history **from their slot**. Between two people
   forward secrecy is a property they build together; among ten it is lost if
   one loses it. Per-slot prekeys would protect the wrapper, not the message.
2. **One-time prekeys need a distributor, and there is none.** Prekeys are
   per contact and are replenished when that contact writes. Between two people
   piggybacking is enough: turns alternate and there are two parties. In a
   group it is not:
   - **silent members never get any.** Whoever reads and never writes never
     supplies fresh prekeys, so the fallback is the identity anyway. Forward
     secrecy for the talkative and none for the others, and the sender cannot
     know which one they got;
   - **two senders pick the same prekey.** Prekeys are single-use, many people
     write at once in a group, and nobody sees what the others consumed. Either
     someone's send fails, or the same prekey is **silently** reused. A reused
     prekey is worse than none, because the UI keeps promising a property that
     no longer holds.
3. **It would break a deliberate invariant.** `Header::flags` is a function of
   `origin`, not a field, so that two sources of truth cannot produce an
   inconsistent header. A per-slot mode reintroduces exactly that, where a
   mistake would not show: a valid header lying about which scheme was used.
4. **It would leak something about third parties.** With a per-slot mode,
   each recipient would learn how many co-recipients are on full forward
   secrecy and how many on the fallback.
5. **A reason that does NOT hold, recorded so it is not rediscovered: size.**
   Per-slot prekeys would fit in the blob. With 4096 characters and about 116
   bytes of header, around twenty slots fit with room for a real message. The
   constraint is prekey coordination, not size.

**What does not change:** one-to-one messages remain `version = 1`, byte for
byte. The group is a new format (`version = 2`), not a change to the existing
one. It is also the only way for an older version to say "update the app"
instead of "corrupted message": a new `kind` or a flag bit would give
`Error::Format`, shown with the same sentence as a damaged blob.

**Condition 1: a group must not weaken one-to-one conversations.** Group slots
do not touch the secrets on which one-to-one forward secrecy depends. This
rests on two things:

1. **The derivation domain is genuinely separate**:
   `KDF_DOMAIN_GROUP = "keyboard-cipher/v2/group-slot"` against
   `KDF_DOMAIN = "keyboard-cipher/v1/baseline"`. This is needed because "no
   material in common" is **false**: a slot key comes from
   `DH(ephemeral, recipient) || DH(sender, recipient)`, the same bytes a
   one-to-one message to that person with that ephemeral key would produce.
   The derivation separates them, not the ingredients. `derive_ephemeral_key`
   and `derive_group_slot_key` are **two functions with different names**, not
   one with a "domain" parameter: a parameter can be passed wrong; here the
   mistake cannot be expressed.
2. **Slots use the identity, never a prekey or an epoch key.** Encrypting or
   opening a group leaves the one-to-one chain where it was.

Originally both used `KDF_DOMAIN`, and only the version byte at the start of the
AAD (which ends up in the HKDF info) separated them. It worked, but as an
*emergent* property that a change to the AAD layout would have broken silently.
The separate domain and its test were added together; the version byte in the
AAD remains as a second defence. This changed the slot keys once, while groups
were new; **that string is now frozen**. Tests:
`uno_slot_di_gruppo_non_condivide_il_contesto_con_un_messaggio_a_due` and
`un_gruppo_non_tocca_la_catena_a_due`.

**Condition 2: say it where the user reads it.** A group message opens to
anyone who obtains the identity of **any** member, and stays openable until
everyone has replied. Whoever records the group's traffic today and gets hold
of one member's phone in a year reads everything that member could read. The
forward secrecy switch promises that "from the second message on, neither
stable key is enough to open anything"; for a group that sentence is false and
must not appear. A group is presented as **encrypted, but not safe against a
lost phone**. With the label the choice is legitimate; without it, it would be
a lie.

**Condition 3: the way out is a version, not a flag bit.** If groups ever get
forward secrecy, it will be `version = 3`, for the same reason the group is
`version = 2`. The four free high bits in `Flags::KNOWN` look like the obvious
hook and are the wrong place. The known technical path is **sender keys**:
each member has a chain that it advances alone on every message it sends,
which removes the distributor problem of reason 2, at the price of per-member,
per-group state and recovery for members who missed messages.

**No per-slot identifier.** No "key hint" to skip attempts. Each slot key
derives from `DH(ephemeral, recipient) || DH(sender, recipient)`, so group
membership is **not verifiable** by outsiders. A stable per-recipient identifier
would make it verifiable, disguised as an optimisation; the cost it would save
was measured and is negligible, because the number of X25519 operations does
not depend on the number of slots.

**Consequence for decision I.** Destroying keys on read was most harmful in
groups, where people scroll back constantly. With K1 in this form, that
question concerns only one-to-one conversations.

### K2: slot format

```text
envelope version = 2
  header      as version 1, with the sender's ephemeral key in Origin
  n_slot      1 byte
  slot[i]     48 bytes: wrapped content key (32) + tag (16)
  payload     the text, encrypted ONCE with the content key
```

Readers **try the slots one by one**. The cost is negligible and measured: the
number of X25519 operations does not depend on the slots, only the number of
symmetric attempts does.

Each slot's nonce is derived from the envelope nonce **and the index**, and the
index goes into the AAD together with `n_slot`. Binding the index prevents
reordering slots; binding the count prevents truncating some away: a recipient
removed from the blob must not look like a blob created without them. The
payload AAD also binds the hash of the slot block, so replacing one member's
slot with a copy of another breaks the payload for everyone instead of silently
excluding one reader.

Slots are in **random order**, not in the order names were ticked: position
must say nothing about who is inside.

**The sender has a slot of their own.** Otherwise the sender could not reread
what they wrote: the ephemeral key is dropped after sending, so the other slots
cannot be recomputed. In a format that by choice has no forward secrecy, where
history exists on purpose, a message unreadable to its author would be
inconsistent. It reveals nothing new: that the sender is in the group is
already known.

### K3: cap of 8 recipients

Plus the sender's slot, so 9 slots. At 48 bytes per slot that is 432 bytes,
well inside 4096 characters after encoding, with room for a real message. The
cap can be raised later without breaking blobs already sent: `n_slot` is a
byte.

### K4: no decoy slots

Blob length reveals how many people are in the group. It is weak metadata
(whoever looks already sees it is a group conversation, since that is where the
blob was pasted), and padding would cost space on every message, including
one-to-one ones. Recorded as a **choice**: whoever wants to hide it can add
slots up to a fixed number and pay for it.

### K5: saved groups and ad-hoc selection

Several contacts can be ticked when choosing the recipient, and that selection
can be saved under a name. A saved group is a local label over a set of keys,
exactly as a contact name is a local label over a key: it does not travel, is
not in the ciphertext, and nobody else knows it.

### K6: in a group the author is NOT authenticated, and is not shown

The payload is encrypted with the content key, which by construction **every**
member has. Its AAD binds version, kind, tier, flags, ephemeral key and count:
nothing that says **who wrote it**. So any member who opened the message can
encrypt another one with the same key, nonce and AAD, reattach the **original
slots byte for byte**, and get an indistinguishable blob. Readers attribute the
text to the original sender, because the sender is inferred from which slot
opens, and the slots are untouched.

This is not the intended deniability of the static scheme, where only the
recipient can forge, and only towards themselves. **Here forgery is towards
third parties.**

The options were: sign the payload (removes deniability, which the project
keeps elsewhere on purpose), a per-recipient MAC (larger slots), or accept it
and not show the author. **The third was chosen.** Hence the rule, a condition
and not advice: **the UI shows no author for group messages.** No name, no
fingerprint, no "verified". It shows that it is a group message, how many
people could read it, and that the author cannot be established.

The `sender` field still means something: who built **the slots**. Opening a
slot proves its builder knew `DH(sender, recipient)`, so the field is not
false, only insufficient to attribute the text.

If the group should ever authenticate the author, the path is a per-recipient
MAC inside the slot, as `version = 3`. It is not a compatible addition.

## Post-quantum slot (L)

Neither closed nor open: **reserved**. The scheme is not implemented now, but
its place in the format is assigned today, because it could not be later.

**Why it concerns this project specifically.** The adversary is mass scanning
**with bulk retention**: collect now, analyse later, the literal definition of
*harvest now, decrypt later*. X25519 is not post-quantum, and forward secrecy
does not help: it defends against a key stolen tomorrow, not against an
algorithm broken tomorrow (the ephemeral keys are X25519 too). If a useful
quantum computer arrives, everything retained opens, including conversations the
chain protected. It is the most serious weakness of the system today, not
because it is imminent but because it is the one the threat model makes
relevant **by construction**.

**The slot: `tier = 2`.** Not a flag bit, not a new version. The `tier` byte
has always been the free slot for a future scheme; it is authenticated (no
forced downgrade) and read **first**, before the parser commits to any layout.
A hybrid scheme needs exactly that, because its header will differ: an
ML-KEM-768 ciphertext is 1088 bytes, does not fit a 32-byte field and cannot
live inside the ciphertext, because it is needed **to derive** the key. A flag
bit is wrong for the reason given in K, condition 3. A new version is wrong too:
the version distinguishes envelope *shapes* (one-to-one, group), and a hybrid
must be able to have both.

**What was done, and is the only testable part.** An unknown tier used to return
`Error::Format`, which the UI shows with the same sentence as a damaged blob. The
first hybrid message would have shown "corrupted message" on every older
installation. It now returns `TierUnsupported`, that is, "update the app". An
exit has to be opened *before* it is needed: when hybrid messages start
circulating, installations that say "corrupted" will already be out there.

*Accepted price:* a genuinely corrupted blob whose tier byte lands on an
undefined value says "update the app" instead of "damaged". That is the right
direction to be wrong in: whoever updates and retries finds out the truth;
whoever is told "corrupted" about a valid message has no way out.

The two levels stay distinct for **known** tiers: `ForwardSecret` parses without
complaint and is rejected at execution. "I cannot read it" and "I cannot run
it" remain different things.

**Not decided yet:** the primitive (ML-KEM-768 is the obvious candidate, not a
choice made), how the two secrets combine (the sound rule is to concatenate
them into HKDF, so that **both** must be broken), and what happens to blob
size, which with 1088 more bytes exceeds a chat field and might force hybrid
messages to travel as attachments. Whoever implements it must not touch
`Baseline` or `ForwardSecret`, and must not reuse the number 2. Test:
`il_tier_ibrido_dice_aggiorna_non_corrotto`.

## A family of bugs: self-poisoning state

Not a decision but a **review criterion**, written down because four bugs of
the same shape were found together, after one of them had reached a real user.

**The shape.** State that only moves in one direction, and moves on a value
**we do not control**: the timestamp declared by the sender, or the existence of
an old blob that anyone can repost. The damage is not an error but a
**permanent, silent** failure that shows up as "sometimes it doesn't work" and
leaves no way out.

The four, all in `api.rs`:

- `seen_at` advanced by the sender's timestamp on the **prekey** path;
- the same on the **epoch** path (`seen_at` is shared, so fixing only one would
  have achieved nothing);
- `burned_at`, where it was worse: a burn request dated in the future
  **disabled every later burn**, silently;
- the epoch migration fallback, which adopted an old prekey as the epoch
  **overwriting the current one**: an old reposted blob was enough.

**The rule that closes them all.** A recency comparison is made against the
**smaller of the declared time and our own**. The defence against going
backwards stays intact (an old blob has an old date however you look at it),
while a future date is cut down to when we actually received it and can no
longer poison anything. And state that exists to **migrate** is written only
when its slot is empty.

**Why it slipped through.** Decision C already says the timestamp is
"authenticated but not verifiable" and must not drive automatic decisions. Each
point looked like a reasonable exception, with a comment explaining why it was
fine there. None of the four comments was wrong about its own case; all four
only considered the clock going **back**, and none the clock going **forward**.

**What to ask about every new piece of state:** can it only move one way? Who
pushes it? If it is pushed too far, what stops working, and does the user
notice? If the answer to the last question is "no", it needs a cut-off against
a value of our own.

## Implementation rules

- `#![forbid(unsafe_code)]` in the core.
- No panics in production: clippy denies `unwrap_used`, `expect_used`,
  `panic`, `indexing_slicing`, `arithmetic_side_effects` and `todo`
  (`clippy::panic` does not fire on `todo!()`, hence the separate lint).
- One public `Error` type (thiserror).
- No dependency that brings in C code when a pure-Rust alternative exists.
- The format is permanent: a released version is never modified; a new version
  is added instead.
- `Cargo.lock` is versioned on purpose: builds must be reproducible and
  dependency versions pinned.

## Testing

- Known-answer vectors for the **primitives** come from the upstream crates and
  are not rewritten.
- Vectors for **our formats** are produced with a fixed RNG and frozen as KATs.
  A change that breaks one is a format change, not a refactor. There is **one
  KAT per format**: static message, envelope round trip, identity card,
  fingerprint, group with two recipients and the minimal group. The group KATs
  were added after a change to the slot derivation domain (a real compatibility
  break) passed the entire test suite unnoticed: a format not covered by a
  vector can move silently, and then users find out months later from a message
  that does not open. **Whoever adds a format adds its KAT in the same commit.**
- z-base-32 vectors come from the specification (see E). Test vectors are never
  invented: a wrong vector is worse than none.
- Mandatory negative tests: bit flips in the ciphertext, the AAD and the tier
  byte; unknown version; missing sentinel; truncated input; flags inconsistent
  with length.
- Every parser is exercised on hostile input with `cargo-fuzz` (nightly):
  - `decode`: `encoding::decode` never panics, and when it decodes,
    `encode(decode(s)) == s`;
  - `parse`: `format::parse` never panics. Half the inputs are prefixed with
    the sentinel, otherwise the fuzzer would stay on the `NotOurBlob` branch;
  - `roundtrip`: builds **valid** blobs of every format from the input,
    re-parses them (they must round-trip), then corrupts and truncates them.
    This is the target that matters: it reaches about three times the coverage
    of `parse`. **Whoever adds a format updates this target in the same
    commit**; when groups were added it could only produce version 1 for a
    while, and the group parser was outside fuzzing.
  - The fuzz crate is outside the core workspace, so a format change can stop
    it from *compiling* without `cargo test` noticing. After any change to
    `format.rs`, run `cargo +nightly fuzz build`.
  - The corpus is ignored by git (regenerable, unbounded); crash artefacts are
    versioned, because they reproduce a bug.
  - Longest recorded campaign: about 146 million inputs, no crashes.
- `cargo test` in the core builds the core only. The core has five consumers
  (JNI bridge, CLI, GUI, Android app, iOS bridge), and twice a core change
  broke one that nobody rebuilt. `verify-all.sh` rebuilds and tests all
  of them, stops at the first failure, and exits with 2 if it had to skip a
  project: a green result that did not look is not a green result.
