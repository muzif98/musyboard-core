# Known issues, accepted risks and open questions

This file lists what is already known, so that review time goes to what is
not. "Accepted" means a deliberate decision recorded in
[DESIGN.md](../DESIGN.md); arguments that a decision is wrong are welcome.

## 1. Accepted residual risks (by design)

| # | Residual | Where decided |
|---|---|---|
| R1 | `kc/` sentinel makes encrypted traffic matchable by one regex | Threat model; [Sentinel](../DESIGN.md#sentinel) |
| R2 | Sender public key in clear in static and epoch schemes, so messages from the same sender are linkable | Threat model; decision H removes it only for ephemeral/forward-secrecy schemes |
| R3 | Blob length reveals plaintext length (no padding except identity cards) | [Envelope format](../DESIGN.md#envelope-format) |
| R4 | Identity cards remain statistically distinguishable over many samples (uniform length vs. text-like lengths) | [Envelope format](../DESIGN.md#envelope-format) |
| R5 | Replay of any valid blob, including burn requests; only the composition time is shown | Decisions C and J |
| R6 | The 8 most recent prekeys survive a read (`CODA_MINIMA = 8`), so up to 8 already-read forward-secrecy messages can be reopened by someone who seizes the device | Decision I |
| R7 | The first message of an epoch conversation is encrypted to the identity and survives a burn | Decision J |
| R8 | Group messages have no forward secrecy and no author authentication (any member can forge a message that other members attribute to someone else) | Decision K1, K6 |
| R9 | Group size is visible from blob length (no decoy slots) | Decision K4 |
| R10 | Attachments are visible as `.kc` files of a given size | Decision G |
| R11 | Key change of a contact is not detected automatically on arrival, only when the user assigns the existing name to the new key | [F](../DESIGN.md#identity-tofu-and-labels-f) |
| R12 | No post-quantum protection; tier `2` reserved | Decision L |
| R13 | Plaintext in the Android UI layer lives in `String`/`CharSequence` and cannot be zeroized | [Secrets in memory](../DESIGN.md#secrets-in-memory) |

## 2. Questions we would like answered

1. **Static vs. epoch-bootstrap key equivalence.** Schemes `0x01` and `0x09`
   derive the same AEAD key from the same inputs; only the flags byte in the
   AAD differs, and that byte is the one the blob declares. We rely on every
   opening function checking the expected scheme internally. Is there any path
   (core, JNI, CLI, GUI) that opens one as the other?
2. **Trial decryption cost.** A forward-secrecy blob that opens with nothing
   costs, in the worst case, `contacts × 64 × 2` X25519 operations (see the
   commit that raised `MAX_PREKEY_MIE` from 32 to 64). Is this a practical
   denial-of-service on a phone, given that blobs arrive by copy-paste?
3. **Auto-pinning on the static path.** A static (`0x01`) or epoch-bootstrap
   message from an unknown key is decrypted, its key is pinned without a label,
   and it becomes the current recipient for that app ("decrypting sets the
   recipient"). This is intended TOFU behaviour. Is the resulting UX safe
   against someone who pastes a blob from a fresh key into a chat?
4. **Group slot nonces.** `nonce_i = nonce XOR (i + 1)` on the last byte, with
   per-slot keys from a dedicated HKDF domain. We believe nonce reuse needs both
   the same member twice and the same index, which deduplication prevents.
   Please confirm.
5. **Group shuffle.** Fisher-Yates using `next_u32() % (i + 1)` with `i ≤ 8`.
   The modulo bias is negligible at this size; we mention it only for
   completeness.
6. **Backup parameter bounds.** On import, Argon2 parameters are bounded above
   (memory exhaustion) but **not below**. A backup we export always uses the
   defaults, and editing the header makes the file fail to open. A weak file
   could only come from someone else's tool. Should import also enforce a
   minimum?
7. **Epoch state and the burn timestamp.** `burned_at` and `seen_at` compare
   against `min(claimed time, local now)`. Four bugs of this "self-poisoning
   state" family were found and fixed. Are there more?

## 3. Android integration: open items

| Item | Status |
|---|---|
| Recipient is per **app**, not per **conversation**: in an app with several chats a half-written draft follows you into another chat, and the label under the compose row is the only guard against encrypting for the wrong person | **Open**, design decision pending |
| Draft plaintext stays in the keyboard's memory when you switch to an app where the compose row is suppressed | Open, intended so far |
| Not yet tested on a physical device: password and search fields, groups, attachments, "forget contact", burn, part queue across a forced stop, two different contacts in one app | Untested |
| API 21–22 (the app's `minSdk` is 21, but encryption needs API 23 and reports itself unavailable below) | Untested |

## 4. Previous reviews

None external. All review so far has been internal: code review, fuzzing and
emulator testing. The fuzzing and KAT discipline is described in
[DESIGN.md](../DESIGN.md#testing).
