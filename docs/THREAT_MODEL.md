# Threat model

## What the system is

An Android keyboard (a fork of HeliBoard) that encrypts text **inside the
keyboard, before it reaches the chat app**, and inserts the ciphertext into the
app's text field. The recipient copies the blob, and the keyboard (or a
companion Activity in the same APK) decrypts it and shows the plaintext in a
window of its own. The chat app only ever sees ciphertext.

Usage model: one-shot messages pasted into third-party chat apps. There is no
return channel, no handshake and no shared state between the parties.
Messages arrive late, out of order and repeatedly. The keyboard sees the input
field, never the chat history.

The APK has **no `INTERNET` permission** and no camera permission.

## Reference adversary

**Platform-side mass scanning with bulk retention**: automated,
indiscriminate analysis of all users' content by the chat platform (or under a
legal mandate such as the proposed EU CSA regulation), with ciphertext stored
for later analysis. This is **not** a targeted adversary investing in one
user. The distinction drives most design choices: defending against a
classifier running over all traffic is a different problem from defending
against an analyst looking at you.

## In scope (the system claims to protect against)

1. **Reading message content** by the platform, its servers, cloud backups and
   automated content scanning.
2. **Tampering** with ciphertext (AEAD integrity, header and scheme bound in
   the AAD, no downgrade by editing the tier or flags).
3. **Retroactive decryption after long-term key compromise**, when forward
   secrecy is on (default). From the second message of a conversation, the
   long-term keys alone open nothing, attachments included. See §5.3 of
   [PROTOCOL.md](PROTOCOL.md) for the 8-key read window that weakens this
   deliberately.
4. **Cheap, traffic-wide classification** of *what kind* of blob is sent:
   identity cards are padded into the message length range, and message kind
   is inside the encrypted body.
5. **Impersonation** after first contact: TOFU pinning, and label conflicts
   (a known name moving to a new key) are surfaced and never resolved
   automatically.
6. **Plaintext leaking to the chat app** through the keyboard itself: the
   composition buffer never goes to the app's field, the Activities that show
   plaintext are always `FLAG_SECURE`, the keyboard window is `FLAG_SECURE`
   while the compose row or the decrypted panel is on screen (a setting, on by
   default), and decryption never returns text to the calling app
   (`ACTION_PROCESS_TEXT` never calls `setResult` with data).

## Out of scope, by explicit choice

- **Compromised endpoint**: root, keyloggers, malicious accessibility
  services, screen capture at OS level, OS-level scanning.
- **Social metadata**: who talks to whom, when, and how much stays visible to
  the platform with any design.
- **The fact that encryption is used.** The `kc/` sentinel can be matched by a
  single regex over all traffic. Accepted for usability.
- **Correlation of messages from the same sender** through the sender public
  key in clear (epoch and static schemes). Near-zero cost against the
  reference adversary, which already knows the sending account. The
  ephemeral/forward-secrecy schemes do not have it.
- **Length of the plaintext** (visible from blob length; no padding except for
  identity cards).
- **Replay** of a valid blob, including a burn request. Mitigated only by
  showing the authenticated-but-unverifiable composition timestamp.
- **First-contact MITM** when the identity card goes through the chat itself.
  Closed only by the in-person QR exchange (one side shows, the other scans
  with any QR reader and shares the text into the app).
- **Quantum adversary** ("harvest now, decrypt later"). X25519 is not
  post-quantum, and forward secrecy does not help against a broken algorithm.
  This is the most serious weakness relative to the reference adversary.
  Tier byte `2` is reserved for a hybrid scheme; nothing is implemented.
- **Group messages**: no forward secrecy (anyone who later obtains any member's
  identity reads the group history), and no author authentication (any
  member can forge a message attributed to another). Both are stated in the
  UI.
- **Burn as remote deletion**: a burn request destroys keys on our side
  cryptographically, but the other side only honours it if its app does.

## Device-side assumptions (Android)

- Long-term secrets are stored encrypted with an AES-256-GCM key in Android
  Keystore (`setUnlockedDeviceRequired(true)` on API 28+, no user
  authentication per operation). The app is `directBootAware`, so the
  at-rest protection before first unlock comes from that key flag, not from
  file-based encryption.
- The plaintext being typed lives in the keyboard process in a `CharSequence`
  buffer and in Java/Kotlin `String`s, which cannot be zeroized. Zeroization
  guarantees stop at the JNI boundary (the bridge passes `byte[]`, never
  `String`, but the UI layer cannot avoid strings).
- The keyboard reads the clipboard (allowed for the default IME on Android
  10+) to recognise copied blobs.
- A foreground service keeps the process alive so copied blobs can be noticed.
  It is not meant to hold plaintext; please verify.

## What we would most like a reviewer to break

In rough priority order:

1. Any way to make a message **encrypt for the wrong person**, or decrypt and
   be **attributed to the wrong sender** (trial decryption over contacts,
   per-app recipient state, scheme confusion between 0x01 and 0x09).
2. Any **cross-scheme or cross-kind confusion**: a blob accepted under a
   scheme or kind other than the one it was produced with.
3. **State poisoning**: one-directional state (`seen_at`, `burned_at`, prekey
   and epoch slots) pushed by attacker-controlled values into a permanently
   broken conversation. Four such bugs were already found and fixed; the rule
   is "compare against min(claimed, local now)".
4. The **group construction**: slot binding (index, count, slot-block hash),
   the derived slot nonces, and the K6 forgery we accept.
5. **Forward secrecy accounting**: whether prekeys and ephemeral secrets are
   really dropped and zeroized when the design says they are.
6. **Android integration**: the plaintext composition buffer, clipboard
   auto-open, `FLAG_SECURE` coverage, Keystore wrapping, and the JNI bridge
   (`catch_unwind` on every entry point, no `String` for secrets).
