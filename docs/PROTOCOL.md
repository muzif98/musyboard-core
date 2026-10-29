# keyboard-cipher protocol specification

Status: describes the code in this repository. Where
this document and the code disagree, **the code is authoritative and the
disagreement is a finding**. Every value below was read from the source, not
from the design notes. File and function names point to `src/` unless stated.

## 1. Primitives

| Purpose | Primitive | Crate |
|---|---|---|
| Key agreement | X25519 | `x25519-dalek` 2 (`static_secrets`, `zeroize`) |
| AEAD | XChaCha20-Poly1305 (24-byte nonce, 16-byte tag) | `chacha20poly1305` 0.10 |
| KDF | HKDF-SHA-256 | `hkdf` 0.12, `sha2` 0.10 |
| Backup KDF | Argon2id v0x13 | `argon2` 0.5 |
| Hash (fingerprint, checksums) | SHA-256 | `sha2` 0.10 |
| Text encoding | z-base-32, lowercase, in-house (`encoding.rs`) | none |

All dependencies are pure Rust. The core is `#![forbid(unsafe_code)]`, has no
I/O, no clock and no global RNG: randomness (`RngCore + CryptoRng`) and the
current time (`now_unix: i64`) are always passed in by the caller.

**Low-order points.** Every X25519 operation goes through
`diffie_hellman()` in `keys.rs`, which returns `Error::Crypto` when
`SharedSecret::was_contributory()` is false. The raw DH output is never used as
a key directly.

## 2. Keys and long-term state

- **Identity**: one X25519 static key pair per user, used for all contacts.
  There are no per-contact identities.
- **Fingerprint** (`keys.rs`, `Fingerprint::of`):
  `SHA-256("keyboard-cipher/v1/fingerprint" || pubkey)`, truncated to 15 bytes
  (120 bits), shown as 24 z-base-32 characters in 6 groups of 4.
- **Keyring** (TOFU, indexed by public key). Per peer it holds an optional
  user-assigned label, a `verified` flag, and state for the two session
  schemes:
  - *chain* (forward secrecy, §5.3): up to `MAX_PREKEY_MIE = 64` of **our**
    prekey secrets for that peer (newest first) and the **peer's** latest
    prekey public key, plus `seen_at`;
  - *epoch* (§5.4): **our** epoch secret for that peer, the **peer's** epoch
    public key, `seen_at`, `burned_at`.
- Pinning happens only **after** a successful decryption (`api.rs`,
  `handle_incoming_text`): a valid AEAD tag is the proof that the sender holds
  the private key and that the message was for us.
- Label conflicts ("this name already belongs to another key") are an outcome
  (`LabelOutcome::Conflict`), never an automatic change. `replace_pinned`
  moves the label and clears `verified`.

## 3. Surface encoding

A text blob is:

```text
"kc/" || zbase32(body)
```

- Alphabet `ybndrfg8ejkmcpqxot1uwisza345h769`, lowercase only.
- Strict decoding: characters outside the alphabet (uppercase included),
  lengths that cannot come from whole bytes, and non-zero trailing padding
  bits are rejected. Each body therefore has exactly one textual form
  (identity cards excepted, see §4.2).
- The sentinel `kc/` is cosmetic. It is found **anywhere** in the input, and
  the maximal run of alphabet characters after it is taken; fewer than 16
  characters means "not ours" (`NotOurBlob`). It deliberately contains no
  version and no dot, so chat linkifiers do not unfurl it.
- Files (§4.4) are not text: the body bytes are written raw to a `.kc` file.

## 4. Envelope formats

All multi-byte integers are little-endian unless stated. `||` is
concatenation.

### 4.1 Version 1, kinds Message (0), File (2), Burn (3)

```text
body = version(1)=0x01 || kind(1) || tier(1) || flags(1)
     || [ key(32)  if flags & SENDER_PUB ]
     || nonce(24)
     || ciphertext(len(inner) + 16)
```

- `tier`: `0` Baseline (the only executable tier), `1` ForwardSecret (parsed,
  rejected at execution with `TierUnsupported`), `2` **reserved** for a
  future hybrid post-quantum scheme. Any unknown tier is `TierUnsupported`
  ("update the app"), not `Format`.
- `flags` (bits): `0x01 SENDER_PUB`, `0x02 EPHEMERAL`, `0x04 PREKEY`,
  `0x08 EPOCH_OFFER`. The upper four bits must be zero. `flags` is not stored
  in the header struct; it is a function of `Origin` (`Header::flags`), so an
  inconsistent header cannot be built.
- Valid flag values and their meaning (`format.rs`, `parse_message`):

  | flags | `Origin` | `key` field is | Scheme (§5) |
  |---|---|---|---|
  | `0x00` | `Assente` | absent | none produced today |
  | `0x01` | `Mittente` | sender identity | static |
  | `0x03` | `Effimera` | sender ephemeral | ephemeral sender |
  | `0x07` | `EffimeraConPrekey` | sender ephemeral | full forward secrecy (chain) |
  | `0x09` | `MittenteConEpoca` | sender identity | epoch bootstrap |
  | `0x0D` | `MittenteConPrekey` | sender identity | epoch |

  Rejected: any flag without `SENDER_PUB`; `PREKEY` without `EPHEMERAL` and
  without `EPOCH_OFFER` (`0x05`); `EPHEMERAL` with `EPOCH_OFFER`.
- The parser guarantees only that the header is complete and that at least a
  tag's worth of ciphertext remains. A successful parse says nothing about
  integrity; truncation is caught by the Poly1305 tag.

**AAD** (`format::build_aad`):

```text
aad = 0x01 || kind || tier || flags || [ key(32) if present ]
```

The nonce is not in the AAD; it is the HKDF salt (§5.1) and the AEAD nonce.

### 4.2 Identity card, kind IdentityCard (1)

```text
body = 0x01 || 0x01 || flags(1)=0x00 || public(32) || checksum(4) || padding
checksum = SHA-256("keyboard-cipher/v1/identity-card" || public)[0..4]
```

The body is padded with random bytes to a uniformly random total length in
`[76, 276]`, so that cards fall inside the length range of short messages and
cannot be isolated by a length rule. The card is **not** authenticated: the
checksum only detects corruption (a truncated key would otherwise be pinned).
Substitution in transit is the risk TOFU accepts; the in-person QR code is the
high-assurance path.

### 4.3 Version 2, group message

```text
body = version(1)=0x02 || kind(1)=0x00 || tier(1) || flags(1)=0x03
     || ephemeral(32) || nonce(24)
     || n_slot(1)                         // 2 ..= 9
     || slot[0..n_slot]  (48 bytes each: wrapped content key(32) || tag(16))
     || ciphertext
```

Group AAD (`format::build_group_aad`):

```text
aad = 0x02 || kind || tier || flags || ephemeral(32) || n_slot || index
      [ || SHA-256(slot block) ]          // payload only
```

`index` is the slot index for a slot and `0xFF` for the payload. The payload
AAD also binds the SHA-256 of the concatenated slot block, so replacing one
member's slot with a copy of another breaks the payload for everyone instead
of silently excluding one reader.

### 4.4 File container

Same layout as §4.1 with `kind = 0x02`, written as raw bytes (no sentinel, no
z-base-32) to a file named `kc-<random>.kc`. The inner plaintext after the
timestamp is:

```text
name_len(2) || name || mime_len(2) || mime || content     // name, mime ≤ 512 bytes
```

The original file name only exists inside the ciphertext.

## 5. Schemes

### 5.1 Common construction (`baseline.rs`)

For every one-to-one scheme:

```text
nonce  = 24 random bytes from the caller's CSPRNG
key    = HKDF-SHA-256( salt = nonce,
                       ikm  = <scheme-specific shared secret>,
                       info = DOMAIN || aad || R )         -> 32 bytes
inner  = timestamp(8, i64 LE) || [ carried_key(32) ] || plaintext
ct     = XChaCha20-Poly1305.Encrypt(key, nonce, inner, aad)
```

- `DOMAIN = "keyboard-cipher/v1/baseline"` for every one-to-one scheme.
- `R` is the recipient-side public key named per scheme below.
- The timestamp is the composition time claimed by the sender. It is
  authenticated but not verifiable; the UI shows it and **never** makes an
  automatic decision on it (replay is made visible, not prevented).
- Because the static-static shared secret is identical for every message
  between two identities, the random 192-bit nonce (used both as HKDF salt and
  AEAD nonce) is the only thing that varies the key per message. There are no
  counters and no derived nonces.

### 5.2 Static (`flags = 0x01`), `seal` / `open`

```text
ikm = DH(sender_identity, recipient_identity)      R = recipient identity
inner = timestamp || plaintext
```

Readable by both parties forever. Used today for files sent with forward
secrecy off and for reading older messages; new text messages use §5.4 or
§5.3.

### 5.3 Ephemeral sender and full forward secrecy (decisions H and I)

```text
ephemeral sender (0x03):      ikm = DH(eph, recipient_identity) || DH(sender_identity, recipient_identity)
full forward secrecy (0x07):  ikm = DH(eph, peer_prekey)       || DH(sender_identity, peer_prekey)
R = recipient identity (both cases)
inner = timestamp || my_new_prekey_pub(32) || plaintext
```

- `eph` is generated per message and dropped right after.
  `DOMAIN = "keyboard-cipher/v1/baseline"` (function `derive_ephemeral_key`).
- The sender identity is not in clear. The recipient finds the sender by
  trial-decrypting with each pinned contact; the first success identifies
  the sender. Senders who are not pinned are not recognised (by design: an
  unknown sender must send an identity card first). All failures are the same
  opaque `Error::Crypto`.
- **Chain.** Every message carries a fresh prekey of the sender (also the
  first message, which cannot use the peer's prekey yet; this is how the
  chain starts). Encrypting stores the new prekey secret
  (`push_my_prekey`, capped at `MAX_PREKEY_MIE = 64`), so encryption mutates
  state and the caller must persist it before sending.
- The peer's prekey is used if known and valid (contributory), otherwise the
  sender falls back to 0x03. The fallback depends on what the peer sent
  before, not on anything in the incoming message, so it is not a forced
  downgrade.
- **Destruction happens on read.** Opening a 0x07 message calls
  `drop_my_prekeys_older_than`, which keeps the prekey that was used and the
  newer ones, but never fewer than `CODA_MINIMA = 8`. The minimum exists
  because out-of-order reading otherwise destroyed unread older messages.
  Cost: the 8 most recent prekeys survive a read, so up to 8 already-read
  messages can be reopened by someone who seizes the device.
- `seen_at` (the newest sender timestamp accepted for the peer's prekey) is
  compared against `min(claimed timestamp, local now)`, so a future-dated
  message cannot freeze the state.

### 5.4 Epoch ("burnable conversation", decision J)

Used when forward secrecy is **off**. Gives a re-readable history (both
parties can reopen their messages) that can be destroyed on request.

```text
epoch bootstrap (0x09):  ikm = DH(sender_identity, recipient_identity)   R = recipient identity
epoch (0x0D):            ikm = DH(sender_identity, peer_epoch_pub)        R = peer_epoch_pub
inner = timestamp || my_epoch_pub(32) || plaintext
```

- Each side keeps one epoch secret per contact that does **not** rotate per
  message. It is stored separately from the chain; reading a chain message
  never touches it.
- The bootstrap is used when the peer's epoch key is not known yet, and after
  a burn.
- **Scheme confusion.** Static (0x01) and epoch bootstrap (0x09) derive the
  same key from the same inputs; only the flags byte differs, and that byte is
  in the AAD as declared by the blob itself. So every opening function checks
  the scheme it expects internally (`SchemaEpoca`, and the `Origin::Mittente`
  check on the static path), not only in the dispatcher.

### 5.5 Burn (kind 3)

An authenticated request to destroy the epoch keys of one conversation. It
carries no text; it is encrypted like an epoch or epoch-bootstrap message with
`kind = 0x03` (in the AAD, so a burn cannot be mistaken for a message). On
receipt (`handle_incoming_text`): decrypt to learn the sender; reject if
`min(claimed time, now) <= burned_at`; otherwise store `burned_at` and destroy
the epoch state for that peer. Remote deletion is not claimed: the other app
must honour the request. A burn blob stays valid forever and can be replayed;
the UI shows its composition date (accepted residual).

### 5.6 Group (decision K, version 2)

```text
members   = recipients ∪ {sender}, deduplicated, 2..=9, Fisher-Yates shuffled
eph       = fresh ephemeral; nonce = 24 random bytes
K_content = 32 random bytes
slot i:   ikm   = DH(eph, member_i) || DH(sender_identity, member_i)
          key_i = HKDF(salt = nonce_i, ikm, info = "keyboard-cipher/v2/group-slot" || aad_slot_i || member_i)
          nonce_i = nonce with last byte XOR (i + 1)
          slot_i = XChaCha20-Poly1305(key_i, nonce_i, K_content, aad_slot_i)
payload:  ct = XChaCha20-Poly1305(K_content, nonce, timestamp || plaintext, aad_payload)
```

- No forward secrecy (slots target identities); this is stated in the UI.
- No per-slot identifier: readers trial-open slots, so membership is not
  verifiable by outsiders.
- **Author is not authenticated** (K6): any member knows `K_content` and can
  re-encrypt a different payload under the original slots. The UI therefore
  shows no author for group messages.
- Separate KDF domain from one-to-one messages: the slot ikm is byte-identical
  to a 0x03 message to the same member with the same `eph`, and only the
  domain separates them (test
  `uno_slot_di_gruppo_non_condivide_il_contesto_con_un_messaggio_a_due`).

## 6. Backup container (`backup.rs`)

```text
backup = version(1)=0x01 || salt(16) || m_cost(4, BE) || t_cost(4, BE) || p_cost(1)
       || nonce(24) || XChaCha20-Poly1305(key, nonce, identity_secret(32) || keyring, aad)
key = Argon2id(password = passphrase, salt, secret = "keyboard-cipher/v1/backup",
              m_cost, t_cost, p_cost, version 0x13) -> 32 bytes
aad = header (the 26 bytes before the nonce)
```

The domain string is passed as Argon2's optional `secret` input
(`Argon2::new_with_secret`), not as AEAD associated data. Because the header is
the AAD, rewriting the cost parameters to weaker values makes the file fail to
open rather than silently weakening it.

Defaults: `m_cost = 65536` KiB, `t_cost = 3`, `p_cost = 1`. On import the
parameters are bounded above (`m_cost ≤ 262144`, `t_cost ≤ 8`,
`1 ≤ p_cost ≤ 4`) to prevent a crafted file from exhausting memory. Empty
passphrases are rejected. The backup contains the identity and the keyring
only (on Android, saved groups and per-app recipients are stored separately
and are **not** in the backup).

## 7. Error model

- Any AEAD failure, any failed trial over contacts and any scheme mismatch
  gives a single opaque `Error::Crypto`. The code must never distinguish
  "bad tag" from "wrong key" from "not for you".
- `NotOurBlob` (no sentinel) is a normal outcome, not an error.
- `UnsupportedVersion` / `TierUnsupported` mean "update the app".
- Own messages that cannot be reopened are `OwnMessage` (recipient no longer
  in the keyring) or `OwnMessageKeyGone` (the recipient-side key was rotated
  or burned); both are decided **before** any decryption attempt from data
  already known.

## 8. Known-answer tests

Frozen vectors (fixed RNG) exist for: static message (`KAT_BASELINE`), format
round trip (`KAT_MESSAGGIO`), identity card (`KAT_IDENTITY_CARD`),
fingerprint, group with two recipients (`KAT_GRUPPO`) and the minimal group
(`KAT_GRUPPO_MINIMO`). A change that breaks one of them is a format change.
z-base-32 is tested against the two byte-aligned rows of the specification
(`F0 BF C7 -> 6n9hq`, `D4 7A 04 -> 4t7ye`) and by differential testing
against the `zbase32` crate. The 30-bit example row of the specification is
itself wrong and is deliberately not used.
