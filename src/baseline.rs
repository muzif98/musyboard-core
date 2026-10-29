//! Baseline tier: stateless encryption. The only tier implemented.
//!
//! Static scheme:
//! ```text
//! dh   = X25519(our_secret, peer_pubkey)              // static-static
//! key  = HKDF-SHA256(ikm = dh, salt = nonce, info = domain || aad || recipient_pub)
//! ct   = XChaCha20-Poly1305(key, nonce, plaintext, aad)
//! ```
//!
//! The ECDH secret is STATIC for each pair of identities: the same `dh`
//! protects every message between them. Hence three non-negotiable rules:
//!
//!   1. The nonce is the ONLY thing preventing keystream reuse: 24 bytes from
//!      a CSPRNG for every message. Never counters, never short nonces, never
//!      nonces derived from content.
//!   2. The nonce is also the HKDF salt, so the effective AEAD key changes on
//!      every message even though `dh` never does.
//!   3. The raw `dh` is never used as a key: it always goes through the KDF.
//!
//! The ephemeral, forward-secrecy and epoch schemes (decisions H, I, J) and
//! group messages (decision K) are built on the same construction.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::error::{Error, Result};
use crate::format::{self, Header, Kind, Origin, ParsedEnvelope, Tier, NONCE_LEN, TAG_LEN};
use crate::keys::{Ephemeral, EphemeralSecret, Identity, PublicKey, KEY_LEN};

/// Domain separation string for HKDF. Frozen: changing it changes every
/// derived key and breaks compatibility with version 1.
const KDF_DOMAIN: &[u8] = b"keyboard-cipher/v1/baseline";

/// Derivation domain for **group slots**, separate from one-to-one messages
/// (decision K1, condition 1).
///
/// Needed because a slot key comes from **the same secret bytes** that a
/// one-to-one message to that person with that ephemeral key would produce:
/// `DH(ephemeral, recipient) || DH(sender, recipient)`. The separation is
/// explicit and local, and does not depend on the layout of the AAD.
///
/// **Changing this string changes slot keys**, making group blobs already sent
/// unreadable. Not a parameter to touch.
const KDF_DOMAIN_GROUP: &[u8] = b"keyboard-cipher/v2/group-slot";

/// XChaCha20-Poly1305 key length.
const AEAD_KEY_LEN: usize = 32;

/// Composition timestamp, at the start of the plaintext INSIDE the ciphertext.
///
/// The answer to replay (decision C). It does not prevent it (a valid blob
/// stays valid forever) but makes it VISIBLE: the recipient sees when the
/// message was written next to a conversation in which it appears today.
///
/// Not a validity window in the AAD, which would prevent replay but make
/// legitimate messages read late fail to decrypt, and would need a clock in
/// the core. Not a cache of seen nonces either: unbounded persistent state, and
/// the core is stateless by construction.
///
/// Inside the ciphertext it adds no metadata for the platform (which knows the
/// message time anyway), and it is authenticated by the AEAD without being in
/// the AAD.
const TIMESTAMP_LEN: usize = 8;

/// Freshly decrypted plaintext. Zeroized on drop, never logged, never converted
/// to `String` at the JNI boundary (a `java.lang.String` cannot be zeroized).
///
/// The absence of `Debug`, `Display` and `Clone` is deliberate.
pub struct Plaintext {
    testo: Zeroizing<Vec<u8>>,
    sent_at_unix: i64,
}

impl Plaintext {
    pub fn as_bytes(&self) -> &[u8] {
        &self.testo
    }

    pub fn len(&self) -> usize {
        self.testo.len()
    }

    pub fn is_empty(&self) -> bool {
        self.testo.is_empty()
    }

    /// When the sender composed the message, by their clock.
    ///
    /// Authenticated (it is inside the ciphertext) but **not verified**: nobody
    /// can prove the sender's clock was right. Used to show a date next to the
    /// message, so that a blob reposted months later stands out. Do not use it
    /// for automatic decisions.
    pub fn sent_at_unix(&self) -> i64 {
        self.sent_at_unix
    }
}

/// Encrypts `plaintext` for `recipient`, producing the final string for the
/// chat (sentinel + z-base-32).
///
/// The sender's public key goes into the header IN CLEAR: the recipient needs
/// it for the first TOFU contact. The resulting linkability is accepted (see
/// the threat model).
///
/// The RNG is injected: it is needed for the nonce, and must be fixable in KATs.
pub fn seal<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<String> {
    let (header, ciphertext) = seal_inner(Kind::Message, sender, recipient, plaintext, now_unix, rng)?;
    Ok(format::serialize_message(&header, &ciphertext))
}

/// Like [`seal`] but for a file: same scheme, different `kind`, raw bytes
/// instead of text.
///
/// `kind` is in the AAD, so a file cannot be reopened as a message even with
/// the right key: the separation is authenticated, not a matter of container.
pub fn seal_file<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (header, ciphertext) = seal_inner(Kind::File, sender, recipient, plaintext, now_unix, rng)?;
    Ok(format::serialize_file(&header, &ciphertext))
}

fn seal_inner<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::Mittente(sender.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);

    let shared = sender.diffie_hellman(recipient)?;
    let key = derive_key(&shared, &nonce, &aad, recipient)?;

    // The timestamp travels at the start of the plaintext, i.e. inside the
    // ciphertext.
    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN.saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Encrypts with an **ephemeral sender**: the key in the header is single-use
/// and your identity does not appear in clear.
///
/// The AEAD key comes from two exchanges together:
///
/// ```text
/// secret = DH(ephemeral, recipient) || DH(sender, recipient)
/// ```
///
/// The first gives half forward secrecy: the ephemeral key is dropped
/// immediately, so whoever later obtains your stable key cannot reopen
/// earlier messages. The second is the proof of identity: only the holder of
/// the sender's private key can produce that secret, so a successful
/// decryption proves who wrote, **without signatures**.
///
/// The opposite case remains: whoever obtains the **recipient's** key still
/// opens everything, because both exchanges go through it. That needs a
/// temporary key on the recipient side too ([`seal_forward`]).
pub fn seal_ephemeral<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<String> {
    let (header, ciphertext) = sigilla_effimero(
        Kind::Message,
        sender,
        recipient,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_message(&header, &ciphertext))
}

/// [`seal_ephemeral`] for an attachment: same derivation, binary framing.
pub fn seal_file_ephemeral<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (header, ciphertext) = sigilla_effimero(
        Kind::File,
        sender,
        recipient,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_file(&header, &ciphertext))
}

/// The common body. `kind` is in the AAD, so an attachment cannot be read as a
/// message nor vice versa.
#[allow(clippy::too_many_arguments)]
fn sigilla_effimero<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let effimera = Ephemeral::generate(rng)?;

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::Effimera(effimera.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_ephemeral_key(
        &*effimera.diffie_hellman(recipient)?,
        &*sender.diffie_hellman(recipient)?,
        &nonce,
        &aad,
        recipient,
    )?;

    // The prekey travels here too, and this is what **starts** the chain:
    // without it the recipient would never get a temporary key of ours, and
    // full forward secrecy would never begin. It is inside the ciphertext
    // because it must be authenticated: in clear, anyone could replace it and
    // hijack the rest of the conversation.
    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_prekey.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Tries to open an ephemeral-sender message **assuming** `candidato` wrote it.
///
/// The recipient does not know who wrote, and calls this for each contact
/// until one succeeds. Failure is [`Error::Crypto`] like any other and does not
/// distinguish "not them" from "corrupted": that would give an attacker an
/// oracle on who is in the keyring.
pub fn open_ephemeral(
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_effimero(Kind::Message, recipient, candidato, parsed)
}

/// [`open_ephemeral`] for an attachment.
pub fn open_file_ephemeral(
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_effimero(Kind::File, recipient, candidato, parsed)
}

fn apri_effimero(
    kind: Kind,
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    let Origin::Effimera(effimera) = &parsed.header.origin else {
        return Err(Error::Crypto);
    };
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let key = derive_ephemeral_key(
        &*recipient.diffie_hellman(effimera)?,
        &*recipient.diffie_hellman(candidato)?,
        &parsed.header.nonce,
        &aad,
        &recipient.public(),
    )?;

    let aperto = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );
    stacca_prekey(&aperto)
}

/// Splits timestamp, the sender's prekey and text.
fn stacca_prekey(aperto: &[u8]) -> Result<(PublicKey, Plaintext)> {
    let inizio = TIMESTAMP_LEN;
    let fine = inizio.saturating_add(KEY_LEN);
    let chiave = aperto
        .get(inizio..fine)
        .ok_or(Error::Format("plaintext senza prekey: mittente malformato"))?;
    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(chiave);

    let mut senza = Zeroizing::new(Vec::with_capacity(aperto.len()));
    senza.extend_from_slice(aperto.get(..inizio).unwrap_or(&[]));
    senza.extend_from_slice(aperto.get(fine..).unwrap_or(&[]));
    Ok((PublicKey::from_bytes(bytes), stacca_timestamp(&senza)?))
}

/// Encrypts with **full forward secrecy**: sender ephemeral key and recipient
/// temporary key.
///
/// ```text
/// secret = DH(ephemeral, prekey) || DH(sender, prekey)
/// ```
///
/// Both exchanges go through the **recipient's prekey**. Once it is dropped,
/// nobody can open the message: not an adversary holding both stable keys,
/// not the recipient. The price is that **history cannot be reread**
/// (decision I).
///
/// The second exchange remains the proof of identity: only the holder of the
/// sender's private key can produce it.
///
/// `mia_prekey` travels **inside** the ciphertext, at the start of the
/// plaintext: it is the key the recipient will reply to, and must be
/// authenticated; in clear, anyone could replace it.
pub fn seal_forward<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<String> {
    let (header, ciphertext) = sigilla_avanti(
        Kind::Message,
        sender,
        recipient,
        prekey_destinatario,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_message(&header, &ciphertext))
}

/// [`seal_forward`] for an attachment.
#[allow(clippy::too_many_arguments)]
pub fn seal_file_forward<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let (header, ciphertext) = sigilla_avanti(
        Kind::File,
        sender,
        recipient,
        prekey_destinatario,
        mia_prekey,
        plaintext,
        now_unix,
        rng,
    )?;
    Ok(format::serialize_file(&header, &ciphertext))
}

#[allow(clippy::too_many_arguments)]
fn sigilla_avanti<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: &PublicKey,
    mia_prekey: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let effimera = Ephemeral::generate(rng)?;

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::EffimeraConPrekey(effimera.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_ephemeral_key(
        &*effimera.diffie_hellman(prekey_destinatario)?,
        &*sender.diffie_hellman(prekey_destinatario)?,
        &nonce,
        &aad,
        recipient,
    )?;

    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_prekey.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Tries to open a fully forward-secret message, assuming `candidato` wrote it
/// using our prekey `mia_prekey`.
///
/// Also returns the **sender's next prekey**, taken from inside the ciphertext
/// and authenticated by the AEAD: the one to reply to.
pub fn open_forward(
    mia_prekey: &EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_avanti(Kind::Message, mia_prekey, candidato, destinatario, parsed)
}

/// [`open_forward`] for an attachment.
pub fn open_file_forward(
    mia_prekey: &EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_avanti(Kind::File, mia_prekey, candidato, destinatario, parsed)
}

fn apri_avanti(
    kind: Kind,
    mia_prekey: &EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    let Origin::EffimeraConPrekey(effimera) = &parsed.header.origin else {
        return Err(Error::Crypto);
    };
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let key = derive_ephemeral_key(
        &*mia_prekey.diffie_hellman(effimera)?,
        &*mia_prekey.diffie_hellman(candidato)?,
        &parsed.header.nonce,
        &aad,
        destinatario,
    )?;

    let aperto = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    // Timestamp, then the sender's prekey, then the text. All authenticated:
    // if something is missing here, the sender produced a malformed plaintext;
    // it is not an attack.
    stacca_prekey(&aperto)
}

/// Nonce of one slot: the envelope nonce with the index mixed in.
///
/// With different keys the same nonce would not be reuse, and in theory the
/// envelope nonce could serve every slot. But keys differ **only if recipients
/// differ**: a recipient selected twice by mistake would give two slots with
/// the same key and the same nonce, which with XChaCha20-Poly1305 is a total
/// break. One byte of difference makes that mistake harmless.
fn nonce_slot(nonce: &[u8; NONCE_LEN], indice: u8) -> [u8; NONCE_LEN] {
    let mut fuori = *nonce;
    if let Some(ultimo) = fuori.last_mut() {
        *ultimo ^= indice.wrapping_add(1);
    }
    fuori
}

/// Encrypts for several recipients (decision K).
///
/// The text is encrypted **once** with a random content key; each recipient
/// gets that key in a 48-byte slot sealed to their identity. Readers try the
/// slots one by one: there are no per-slot identifiers, so that group
/// membership is not verifiable from outside.
///
/// **The sender is always in the list**: the ephemeral key is dropped after
/// sending, so without a slot of their own the sender could not reread the
/// message, which would be inconsistent in a format that by choice keeps
/// history.
///
/// Returns header, shuffled slot block and ciphertext.
pub fn seal_group<R: RngCore + CryptoRng>(
    sender: &Identity,
    destinatari: &[PublicKey],
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>, Vec<u8>)> {
    if destinatari.is_empty() {
        return Err(Error::Format("un gruppo senza destinatari"));
    }
    // Sender at the end, duplicates removed: the same person chosen twice is a
    // selection mistake, not a second recipient.
    let mut lista: Vec<PublicKey> = Vec::with_capacity(destinatari.len().saturating_add(1));
    for chiave in destinatari.iter().chain(std::iter::once(&sender.public())) {
        if !lista.iter().any(|k| k == chiave) {
            lista.push(chiave.clone());
        }
    }
    if lista.len() > format::MAX_SLOT {
        return Err(Error::Format("troppi destinatari"));
    }
    // Fewer than two slots is not a group: it happens when the only recipient is
    // the sender, merged by the deduplication above.
    if lista.len() < 2 {
        return Err(Error::Format("un gruppo vuole almeno due slot"));
    }

    // Shuffle: the position of a slot must say nothing about who is inside, and
    // without this the sender would always be last. Fisher-Yates with
    // `checked_rem` rather than `%`: the divisor cannot be zero here, but the
    // project bans arithmetic that could panic.
    //
    // The modulo introduces a tiny bias. For nine positions it is irrelevant,
    // and this chooses slot order, not a key.
    for i in (1..lista.len()).rev() {
        let j = usize::try_from(rng.next_u32())
            .unwrap_or(0)
            .checked_rem(i.saturating_add(1))
            .unwrap_or(0);
        lista.swap(i, j);
    }

    let effimera = Ephemeral::generate(rng)?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::Effimera(effimera.public()),
        nonce,
    };
    let n_slot = u8::try_from(lista.len()).map_err(|_| Error::Format("troppi destinatari"))?;

    let mut chiave_contenuto = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    rng.fill_bytes(chiave_contenuto.as_mut());

    // Slots BEFORE the payload: the payload is bound to their hash, so they
    // must exist first.
    let mut slots = Vec::with_capacity(lista.len().saturating_mul(format::SLOT_LEN));
    for (i, destinatario) in lista.iter().enumerate() {
        let indice = u8::try_from(i).map_err(|_| Error::Format("troppi destinatari"))?;
        let aad = format::build_group_aad(Kind::Message, &header, n_slot, Some(indice), None);
        let nonce_i = nonce_slot(&nonce, indice);
        let chiave = derive_group_slot_key(
            &*effimera.diffie_hellman(destinatario)?,
            &*sender.diffie_hellman(destinatario)?,
            &nonce_i,
            &aad,
            destinatario,
        )?;
        let slot = XChaCha20Poly1305::new((&*chiave).into())
            .encrypt(
                XNonce::from_slice(&nonce_i),
                Payload {
                    msg: chiave_contenuto.as_ref(),
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?;
        if slot.len() != format::SLOT_LEN {
            return Err(Error::Crypto);
        }
        slots.extend_from_slice(&slot);
    }

    // The payload, encrypted once and bound to the slot block.
    let impronta = format::impronta_slot(&slots);
    let aad_payload =
        format::build_group_aad(Kind::Message, &header, n_slot, None, Some(&impronta));
    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN.saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(plaintext);
    let ciphertext = XChaCha20Poly1305::new((&*chiave_contenuto).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad_payload,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, slots, ciphertext))
}

/// Opens a group message trying `mittente` as the author.
///
/// The header only carries the ephemeral key, so the writer is not recorded
/// anywhere: as for ephemeral messages, readers try their contacts. Rereading
/// one's own message works the same way, with `mittente` set to one's own key.
pub fn open_group(
    recipient: &Identity,
    mittente: &PublicKey,
    parsed: &format::ParsedGroup<'_>,
) -> Result<Plaintext> {
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    let Origin::Effimera(effimera) = &parsed.header.origin else {
        return Err(Error::Crypto);
    };
    let n_slot = u8::try_from(parsed.slot_count()).map_err(|_| Error::Crypto)?;

    let dh_effimero = recipient.diffie_hellman(effimera)?;
    let dh_statico = recipient.diffie_hellman(mittente)?;
    let mio = recipient.public();

    for i in 0..parsed.slot_count() {
        let Some(slot) = parsed.slot(i) else { continue };
        let indice = u8::try_from(i).map_err(|_| Error::Crypto)?;
        let aad =
            format::build_group_aad(Kind::Message, &parsed.header, n_slot, Some(indice), None);
        let nonce_i = nonce_slot(&parsed.header.nonce, indice);
        let chiave = derive_group_slot_key(&dh_effimero, &dh_statico, &nonce_i, &aad, &mio)?;
        let Ok(contenuto) = XChaCha20Poly1305::new((&*chiave).into()).decrypt(
            XNonce::from_slice(&nonce_i),
            Payload {
                msg: slot,
                aad: &aad,
            },
        ) else {
            // Not our slot: move on. This is the cost of having no per-slot
            // identifiers, and it is only symmetric work: the two X25519
            // operations are done once, outside the loop.
            continue;
        };
        let contenuto = Zeroizing::new(contenuto);
        if contenuto.len() != AEAD_KEY_LEN {
            return Err(Error::Crypto);
        }
        let mut chiave_contenuto = Zeroizing::new([0u8; AEAD_KEY_LEN]);
        chiave_contenuto.copy_from_slice(&contenuto);

        let impronta = format::impronta_slot(parsed.slots);
        let aad_payload = format::build_group_aad(
            Kind::Message,
            &parsed.header,
            n_slot,
            None,
            Some(&impronta),
        );
        let inner = Zeroizing::new(
            XChaCha20Poly1305::new((&*chiave_contenuto).into())
                .decrypt(
                    XNonce::from_slice(&parsed.header.nonce),
                    Payload {
                        msg: parsed.ciphertext,
                        aad: &aad_payload,
                    },
                )
                .map_err(|_| Error::Crypto)?,
        );
        return stacca_timestamp(&inner);
    }
    Err(Error::Crypto)
}

/// Key of a one-to-one message with an ephemeral key (decisions H and I).
fn derive_ephemeral_key(
    dh_effimero: &[u8; 32],
    dh_statico: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    derive_con_dominio(KDF_DOMAIN, dh_effimero, dh_statico, nonce, aad, recipient)
}

/// Key of a **group slot** (decision K2).
///
/// Two functions with different names rather than one with a "domain"
/// parameter: a parameter can be passed wrong, and here that would make a group
/// context coincide with a one-to-one one, which K1 condition 1 forbids. With
/// two names the mistake cannot be expressed.
fn derive_group_slot_key(
    dh_effimero: &[u8; 32],
    dh_statico: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    derive_con_dominio(
        KDF_DOMAIN_GROUP,
        dh_effimero,
        dh_statico,
        nonce,
        aad,
        recipient,
    )
}

/// Like [`derive_key`], with the two secrets concatenated as input material.
///
/// Concatenated, not added or mixed: HKDF takes raw material of any length,
/// and any combination invented here would be a new primitive for no reason.
fn derive_con_dominio(
    dominio: &[u8],
    dh_effimero: &[u8; 32],
    dh_statico: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let mut materiale = Zeroizing::new(Vec::with_capacity(64));
    materiale.extend_from_slice(dh_effimero);
    materiale.extend_from_slice(dh_statico);

    let mut info = Vec::with_capacity(
        dominio
            .len()
            .saturating_add(aad.len())
            .saturating_add(recipient.as_bytes().len()),
    );
    info.extend_from_slice(dominio);
    info.extend_from_slice(aad);
    info.extend_from_slice(recipient.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), &materiale);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hkdf.expand(&info, key.as_mut()).map_err(|_| Error::Crypto)?;
    Ok(key)
}

/// Inverse of [`seal`].
///
/// `sender_pub` comes from the header when the flag is set; the parameter is
/// explicit so this signature survives schemes that obtain it elsewhere.
///
/// Returns [`Error::Crypto`] for any AEAD failure without distinguishing the
/// cause: invalid tag, wrong key and corrupted nonce give the same error.
///
/// `open` does not consult the keyring and decides nothing about TOFU.
/// Decrypting only says "the holder of this private key wrote this"; whether
/// that is the expected key for the peer is a separate question, asked by
/// [`crate::api`] afterwards.
pub fn open(
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    open_inner(Kind::Message, recipient, sender_pub, parsed)
}

/// Inverse of [`seal_file`]. See [`open`]: only `kind` changes, and since it
/// is in the AAD the two paths are not interchangeable.
pub fn open_file(
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    open_inner(Kind::File, recipient, sender_pub, parsed)
}

/// Encrypts **with an epoch** (decision J): sender key in clear, encrypted to
/// the recipient's epoch key.
///
/// No ephemeral key, and that is the point: the derivation can be redone, so
/// the message can be reread, also by its author. Confidentiality comes from
/// an act rather than from time: once either epoch key is destroyed, the
/// message no longer opens on that side.
///
/// `mia_epoca` travels inside the ciphertext as in the other modes: that is how
/// the other side learns which key to write to.
pub fn seal_epoch<R: RngCore + CryptoRng>(
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_a_epoca(
        Kind::Message,
        sender,
        epoca_destinatario,
        mia_epoca,
        plaintext,
        now_unix,
        rng,
    )
}

/// A burn request to the other side's epoch key. Same derivation, different
/// `kind`; `kind` is in the AAD, so a burn is never a disguised message or vice
/// versa.
#[allow(clippy::too_many_arguments)]
pub fn seal_burn_epoch<R: RngCore + CryptoRng>(
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    mia_epoca: &PublicKey,
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_a_epoca(
        Kind::Burn,
        sender,
        epoca_destinatario,
        mia_epoca,
        &[],
        now_unix,
        rng,
    )
}

#[allow(clippy::too_many_arguments)]
fn sigilla_a_epoca<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::MittenteConPrekey(sender.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_key(
        &*sender.diffie_hellman(epoca_destinatario)?,
        &nonce,
        &aad,
        epoca_destinatario,
    )?;

    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_epoca.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;

    Ok((header, ciphertext))
}

/// Opens a **received** epoch message: needs our epoch key.
///
/// Once that key is destroyed this stops working forever. That is what makes
/// deletion real rather than cosmetic.
pub fn open_epoch(
    mia_epoca: &EphemeralSecret,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca(
        &*mia_epoca.diffie_hellman(mittente)?,
        &mia_epoca.public(),
        parsed,
    )
}

/// Opens an epoch message **we wrote**, with the recipient's epoch key we kept.
///
/// Once we drop it we can no longer reread what we sent them: the half of the
/// burn that concerns us.
pub fn open_epoch_as_sender(
    sender: &Identity,
    epoca_destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca(
        &*sender.diffie_hellman(epoca_destinatario)?,
        epoca_destinatario,
        parsed,
    )
}

fn apri_epoca(
    shared: &[u8; KEY_LEN],
    epoca_destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(
        Kind::Message,
        SchemaEpoca::Epoca,
        shared,
        epoca_destinatario,
        parsed,
    )
}

/// Which of the two epoch schemes is expected.
///
/// Needed because the two **derive the same key**: static `seal` and
/// `seal_epoch_bootstrap` both compute `DH(sender_identity,
/// recipient_identity)` with the same `recipient` in the info and the same
/// `kind`. The only difference is the flags byte, which is in the AAD, but the
/// AAD is built from `parsed.header`, i.e. from the flags the blob **declares
/// about itself**. The tag would verify and the text would be read with the
/// wrong layout: 32 bytes of message taken as an epoch key, or vice versa.
///
/// The check lives inside the functions every caller goes through (they are
/// public and used by `jni/`, `cli/` and `gui/`), not only in `api.rs`.
#[derive(Clone, Copy, PartialEq, Eq)]
enum SchemaEpoca {
    /// Encrypted to the other side's epoch key: `Origin::MittenteConPrekey`.
    Epoca,
    /// First message, encrypted to their identity: `Origin::MittenteConEpoca`.
    Bootstrap,
}

fn apri_epoca_con(
    kind: Kind,
    schema: SchemaEpoca,
    shared: &[u8; KEY_LEN],
    epoca_destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    // First of all: if the scheme is not the expected one, the key would match
    // and the tag would verify. `Error::Crypto` rather than `Format`:
    // distinguishing would tell a guesser which scheme they hit.
    let coerente = match schema {
        SchemaEpoca::Epoca => parsed.header.origin.uses_epoch(),
        SchemaEpoca::Bootstrap => parsed.header.origin.is_epoch_bootstrap(),
    };
    if !coerente {
        return Err(Error::Crypto);
    }
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let key = derive_key(shared, &parsed.header.nonce, &aad, epoca_destinatario)?;

    let inner = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    stacca_prekey(&inner)
}

/// The **first** message of an epoch conversation: encrypted to the recipient's
/// identity like the static scheme, but carrying our epoch key inside the
/// ciphertext.
///
/// It starts the conversation without a handshake and stays rereadable by both
/// sides, unlike the ephemeral fallback, which would have made the first
/// message of every conversation unreadable to its author.
pub fn seal_epoch_bootstrap<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_verso_identita(
        Kind::Message,
        sender,
        recipient,
        mia_epoca,
        plaintext,
        now_unix,
        rng,
    )
}

/// Opens a **received** epoch bootstrap: only our identity is needed.
pub fn open_epoch_bootstrap(
    recipient: &Identity,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(
        Kind::Message,
        SchemaEpoca::Bootstrap,
        &*recipient.diffie_hellman(mittente)?,
        &recipient.public(),
        parsed,
    )
}

/// Opens an epoch bootstrap **we wrote**.
pub fn open_epoch_bootstrap_as_sender(
    sender: &Identity,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(
        Kind::Message,
        SchemaEpoca::Bootstrap,
        &*sender.diffie_hellman(destinatario)?,
        destinatario,
        parsed,
    )
}

#[allow(clippy::too_many_arguments)]
fn sigilla_verso_identita<R: RngCore + CryptoRng>(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    mia_epoca: &PublicKey,
    plaintext: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);
    let header = Header {
        tier: Tier::Baseline,
        origin: Origin::MittenteConEpoca(sender.public()),
        nonce,
    };
    let aad = format::build_aad(kind, &header);
    let key = derive_key(&*sender.diffie_hellman(recipient)?, &nonce, &aad, recipient)?;

    let mut inner = Zeroizing::new(Vec::with_capacity(
        TIMESTAMP_LEN
            .saturating_add(KEY_LEN)
            .saturating_add(plaintext.len()),
    ));
    inner.extend_from_slice(&now_unix.to_le_bytes());
    inner.extend_from_slice(mia_epoca.as_bytes());
    inner.extend_from_slice(plaintext);

    let ciphertext = XChaCha20Poly1305::new((&*key).into())
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &aad,
            },
        )
        .map_err(|_| Error::Crypto)?;
    Ok((header, ciphertext))
}

/// The burn request when we have no epoch key of the other side: encrypted to
/// their identity, which we always have.
///
/// Used when we already burned first and still want to ask them. It carries
/// our new epoch key, so the conversation can restart right after.
pub fn seal_burn_static<R: RngCore + CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    mia_epoca: &PublicKey,
    now_unix: i64,
    rng: &mut R,
) -> Result<(Header, Vec<u8>)> {
    sigilla_verso_identita(Kind::Burn, sender, recipient, mia_epoca, &[], now_unix, rng)
}

/// Verifies a burn request received in the static scheme.
pub fn open_burn_static(
    recipient: &Identity,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_rogo(
        SchemaEpoca::Bootstrap,
        &*recipient.diffie_hellman(mittente)?,
        &recipient.public(),
        parsed,
    )
}

/// Verifies a burn request encrypted to our epoch key.
pub fn open_burn_epoch(
    mia_epoca: &EphemeralSecret,
    mittente: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_rogo(
        SchemaEpoca::Epoca,
        &*mia_epoca.diffie_hellman(mittente)?,
        &mia_epoca.public(),
        parsed,
    )
}

fn apri_rogo(
    schema: SchemaEpoca,
    shared: &[u8; KEY_LEN],
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, Plaintext)> {
    apri_epoca_con(Kind::Burn, schema, shared, destinatario, parsed)
}

/// Reopens a message **we wrote**, trying `recipient` as the recipient.
///
/// Works because the ECDH secret is symmetric: the sender has their private key
/// and the other's public key, exactly what is needed to redo the same key. It
/// weakens nothing: whoever has our private key can do it anyway, which is
/// precisely what having forward secrecy off does not promise to prevent.
///
/// **Only without forward secrecy.** With the chain on, the single-use key was
/// destroyed right after encrypting, and there is no equivalent: that is the
/// point of the switch.
///
/// The recipient is not recorded anywhere, so the caller tries its contacts, as
/// it already does for ephemeral senders.
pub fn open_as_sender(
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    apri_come_mittente(Kind::Message, sender, recipient, parsed)
}

/// [`open_as_sender`] for an attachment.
pub fn open_file_as_sender(
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    apri_come_mittente(Kind::File, sender, recipient, parsed)
}

fn apri_come_mittente(
    kind: Kind,
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    // The static scheme is `Origin::Mittente` only: the twin of the check that
    // [`open_inner`] and [`apri_epoca_con`] already have. Without it, reopening
    // one's own message could open a blob produced by `seal_epoch_bootstrap`
    // this way (same key, valid tag), and its first 32 bytes, an epoch key,
    // would appear at the start of the text shown as one's own.
    //
    // Not exploitable by a network attacker and not reachable from `api.rs`,
    // which dispatches first. But the protection must live in the function,
    // not in the habits of its callers (see `DESIGN.md`, envelope format).
    if !matches!(parsed.header.origin, Origin::Mittente(_)) {
        return Err(Error::Crypto);
    }
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let shared = sender.diffie_hellman(recipient)?;
    let key = derive_key(&shared, &parsed.header.nonce, &aad, recipient)?;

    let inner = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    stacca_timestamp(&inner)
}

fn open_inner(
    kind: Kind,
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<Plaintext> {
    // The reserved tier is rejected here, not in the parser: "cannot read" and
    // "cannot run" are different things, and the caller must be able to tell
    // them apart to show the right message.
    if parsed.header.tier != Tier::Baseline {
        return Err(Error::TierUnsupported);
    }
    if parsed.ciphertext.len() < TAG_LEN {
        return Err(Error::Crypto);
    }

    // The static scheme is `Origin::Mittente` only. Without this check an epoch
    // bootstrap (same key, see [`SchemaEpoca`]) would open here and its first 32
    // bytes (an epoch key) would end up at the start of the text shown.
    if !matches!(parsed.header.origin, Origin::Mittente(_)) {
        return Err(Error::Crypto);
    }

    let aad = format::build_aad(kind, &parsed.header);
    let shared = recipient.diffie_hellman(sender_pub)?;
    let key = derive_key(&shared, &parsed.header.nonce, &aad, &recipient.public())?;

    let inner = Zeroizing::new(
        XChaCha20Poly1305::new((&*key).into())
            .decrypt(
                XNonce::from_slice(&parsed.header.nonce),
                Payload {
                    msg: parsed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    stacca_timestamp(&inner)
}

/// Splits the timestamp from the text after a successful decryption.
///
/// The tag already authenticated everything: if the timestamp is missing, the
/// sender produced a malformed plaintext; it is not an attack.
fn stacca_timestamp(inner: &[u8]) -> Result<Plaintext> {
    let stampa = inner.get(..TIMESTAMP_LEN).ok_or(Error::Format(
        "plaintext senza timestamp: mittente malformato",
    ))?;
    let mut bytes = [0u8; TIMESTAMP_LEN];
    bytes.copy_from_slice(stampa);
    let testo = inner.get(TIMESTAMP_LEN..).unwrap_or(&[]).to_vec();

    Ok(Plaintext {
        testo: Zeroizing::new(testo),
        sent_at_unix: i64::from_le_bytes(bytes),
    })
}

/// Derives the AEAD key from the ECDH secret.
///
/// The nonce is the salt: with a static per-pair secret, this is what makes the
/// effective key different for every message.
///
/// The `info` contains the domain, the AAD (which already includes version,
/// kind, tier, flags and the sender's public key) and the RECIPIENT's public
/// key. The latter is not in the AAD and is not strictly needed (the ECDH
/// secret already depends on both keys), but binding it explicitly costs zero
/// bytes on the wire.
fn derive_key(
    shared: &[u8; 32],
    nonce: &[u8; NONCE_LEN],
    aad: &[u8],
    recipient: &PublicKey,
) -> Result<Zeroizing<[u8; AEAD_KEY_LEN]>> {
    let mut info = Vec::with_capacity(
        KDF_DOMAIN
            .len()
            .saturating_add(aad.len())
            .saturating_add(recipient.as_bytes().len()),
    );
    info.extend_from_slice(KDF_DOMAIN);
    info.extend_from_slice(aad);
    info.extend_from_slice(recipient.as_bytes());

    let hkdf = Hkdf::<Sha256>::new(Some(nonce), shared);
    let mut key = Zeroizing::new([0u8; AEAD_KEY_LEN]);
    hkdf.expand(&info, key.as_mut()).map_err(|_| Error::Crypto)?;
    Ok(key)
}

#[cfg(test)]
// In tests `unwrap` and `panic!` are intended.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::format::{ParsedBlob, SENTINEL};
    use hex_literal::hex;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn identita(seed: u8) -> Identity {
        Identity::from_secret_bytes([seed; 32]).unwrap()
    }

    // ====================================================================
    // Group messages (decision K)
    // ====================================================================

    fn gruppo(
        mittente: &Identity,
        destinatari: &[PublicKey],
        testo: &[u8],
        seme: u8,
    ) -> String {
        let (header, slots, ciphertext) =
            seal_group(mittente, destinatari, testo, 1_700_000_000, &mut rng(seme)).unwrap();
        format::serialize_group(&header, &slots, &ciphertext).unwrap()
    }

    fn apri_gruppo(blob: &str, chi: &Identity, mittente: &PublicKey) -> Result<Plaintext> {
        let mut buf = Vec::new();
        let ParsedBlob::Group(parsed) = format::parse(blob, &mut buf)? else {
            panic!("atteso un gruppo")
        };
        open_group(chi, mittente, &parsed)
    }

    #[test]
    fn tutti_i_destinatari_aprono_e_gli_altri_no() {
        let alice = identita(1);
        let babbo = identita(2);
        let mamma = identita(3);
        let fratello = identita(4);
        let estraneo = identita(9);

        let blob = gruppo(
            &alice,
            &[babbo.public(), mamma.public(), fratello.public()],
            b"ci vediamo domenica",
            7,
        );

        for chi in [&babbo, &mamma, &fratello] {
            let aperto = apri_gruppo(&blob, chi, &alice.public()).unwrap();
            assert_eq!(aperto.as_bytes(), b"ci vediamo domenica");
        }

        // Alice rereads what she wrote: that is what her own slot is for.
        let riletto = apri_gruppo(&blob, &alice, &alice.public()).unwrap();
        assert_eq!(riletto.as_bytes(), b"ci vediamo domenica");

        // Someone outside the group cannot get in, even knowing who wrote.
        assert!(apri_gruppo(&blob, &estraneo, &alice.public()).is_err());
        // A recipient who assumes the wrong sender cannot get in either: the
        // key also depends on the writer's identity.
        assert!(apri_gruppo(&blob, &babbo, &mamma.public()).is_err());
    }

    /// This is what the index in the AAD is for: a moved slot would otherwise
    /// open, because the key does not depend on the position.
    #[test]
    fn riordinare_gli_slot_rompe_il_messaggio() {
        let alice = identita(1);
        let babbo = identita(2);
        let mamma = identita(3);
        let blob = gruppo(&alice, &[babbo.public(), mamma.public()], b"ciao", 8);

        let payload = blob.strip_prefix(SENTINEL).unwrap();
        let mut corpo = crate::encoding::decode(payload).unwrap();
        // Header: version, kind, tier, flags, key(32), nonce(24), n_slot.
        let inizio = 4 + KEY_LEN + NONCE_LEN + 1;
        let (primo, secondo) = (inizio, inizio + format::SLOT_LEN);
        for i in 0..format::SLOT_LEN {
            corpo.swap(primo + i, secondo + i);
        }
        let manomesso = format!("{SENTINEL}{}", crate::encoding::encode(&corpo));

        assert!(
            apri_gruppo(&manomesso, &babbo, &alice.public()).is_err(),
            "uno slot spostato non deve aprirsi",
        );
    }

    /// This is what the count in the AAD is for: removing a recipient must not
    /// make the blob look as if it had been created without them.
    #[test]
    fn togliere_uno_slot_rompe_il_messaggio() {
        let alice = identita(1);
        let babbo = identita(2);
        let mamma = identita(3);
        let blob = gruppo(&alice, &[babbo.public(), mamma.public()], b"ciao", 9);

        let payload = blob.strip_prefix(SENTINEL).unwrap();
        let mut corpo = crate::encoding::decode(payload).unwrap();
        let posizione_conteggio = 4 + KEY_LEN + NONCE_LEN;
        let inizio = posizione_conteggio + 1;
        // Drop the last slot and lower the count accordingly: the shape stays
        // valid, only who can read changes.
        let Some(&n) = corpo.get(posizione_conteggio) else {
            panic!("il conteggio deve stare nel corpo")
        };
        if let Some(slot) = corpo.get_mut(posizione_conteggio) {
            *slot = n.saturating_sub(1);
        }
        let taglio = inizio + usize::from(n.saturating_sub(1)) * format::SLOT_LEN;
        corpo.drain(taglio..taglio.saturating_add(format::SLOT_LEN));
        let manomesso = format!("{SENTINEL}{}", crate::encoding::encode(&corpo));

        // None of the remaining members must be able to open it: the payload
        // AAD binds the count, so the text no longer decrypts for anyone.
        assert!(apri_gruppo(&manomesso, &babbo, &alice.public()).is_err());
        assert!(apri_gruppo(&manomesso, &mamma, &alice.public()).is_err());
    }

    /// Replacing one person's slot with a copy of another's used to leave
    /// count, length and shape intact: the blob stayed readable for everyone
    /// else, and the excluded person saw the same error as for a corrupted blob.
    /// Targeted, invisible censorship.
    #[test]
    fn sostituire_uno_slot_rompe_il_messaggio_per_tutti() {
        let alice = identita(1);
        let babbo = identita(2);
        let mamma = identita(3);
        let blob = gruppo(&alice, &[babbo.public(), mamma.public()], b"ciao", 21);

        let payload = blob.strip_prefix(SENTINEL).unwrap();
        let mut corpo = crate::encoding::decode(payload).unwrap();
        let inizio = 4 + KEY_LEN + NONCE_LEN + 1;
        // Slot 1 becomes a copy of slot 0: whoever opened with slot 1 is shut
        // out.
        let (primo, secondo) = (inizio, inizio + format::SLOT_LEN);
        for i in 0..format::SLOT_LEN {
            let Some(&byte) = corpo.get(primo + i) else {
                panic!("lo slot 0 deve stare nel corpo")
            };
            if let Some(slot) = corpo.get_mut(secondo + i) {
                *slot = byte;
            }
        }
        let manomesso = format!("{SENTINEL}{}", crate::encoding::encode(&corpo));

        // THE LINE THAT MATTERS: it breaks for everyone, not only for the
        // excluded person, so tampering is an evident failure rather than
        // silent censorship.
        for chi in [&babbo, &mamma, &alice] {
            assert!(
                apri_gruppo(&manomesso, chi, &alice.public()).is_err(),
                "uno slot sostituito deve rompere il messaggio per chiunque",
            );
        }
    }

    #[test]
    fn un_gruppo_non_e_un_messaggio_e_viceversa() {
        let alice = identita(1);
        let babbo = identita(2);

        // A group cannot be read as a one-to-one message: different versions,
        // and the parser says so BEFORE any decryption attempt.
        let blob = gruppo(&alice, &[babbo.public()], b"ciao", 10);
        let mut buf = Vec::new();
        assert!(matches!(
            format::parse(&blob, &mut buf).unwrap(),
            ParsedBlob::Group(_)
        ));

        // And a one-to-one message cannot be read as a group.
        let normale = seal(&alice, &babbo.public(), b"ciao", 1, &mut rng(11)).unwrap();
        let mut buf = Vec::new();
        assert!(matches!(
            format::parse(&normale, &mut buf).unwrap(),
            ParsedBlob::Message(_)
        ));
    }

    /// Decision K1, condition 1: group slots and one-to-one messages must never
    /// share a derivation context.
    ///
    /// Both derivations get **exactly the same arguments**: same two ECDH
    /// secrets, same nonce, same AAD, same recipient. This is the worst case,
    /// and it is not contrived: a slot key really comes from
    /// `DH(ephemeral, dest) || DH(sender, dest)`, the same bytes a one-to-one
    /// message to that person with that ephemeral key would produce. If the two
    /// keys coincided, a ciphertext from one world would open with the key of
    /// the other. The separation no longer depends on the AAD contents.
    #[test]
    fn uno_slot_di_gruppo_non_condivide_il_contesto_con_un_messaggio_a_due() {
        let mittente = identita(1);
        let destinatario = identita(2);
        let effimera = Ephemeral::generate(&mut rng(7)).unwrap();

        let dh_effimero = effimera.diffie_hellman(&destinatario.public()).unwrap();
        let dh_statico = mittente.diffie_hellman(&destinatario.public()).unwrap();
        let nonce = [9u8; NONCE_LEN];
        let aad = b"stesso aad per tutti e due";

        let a_due = derive_ephemeral_key(
            &dh_effimero,
            &dh_statico,
            &nonce,
            aad,
            &destinatario.public(),
        )
        .unwrap();
        let slot = derive_group_slot_key(
            &dh_effimero,
            &dh_statico,
            &nonce,
            aad,
            &destinatario.public(),
        )
        .unwrap();

        assert_ne!(*a_due, *slot);
    }

    #[test]
    fn il_tetto_e_i_doppioni() {
        let alice = identita(1);
        let babbo = identita(2);

        // The same recipient twice is one slot: a selection mistake, not a
        // second recipient.
        let blob = gruppo(&alice, &[babbo.public(), babbo.public()], b"ciao", 12);
        let mut buf = Vec::new();
        let ParsedBlob::Group(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        assert_eq!(parsed.slot_count(), 2, "babbo e alice, non babbo due volte");

        // Beyond the cap it is rejected with a format error: not a
        // cryptographic failure, a request that cannot be served.
        let troppi: Vec<PublicKey> = (10..20u8).map(|s| identita(s).public()).collect();
        assert!(seal_group(&alice, &troppi, b"ciao", 1, &mut rng(13)).is_err());

        // And a group with nobody in it is not a group.
        assert!(seal_group(&alice, &[], b"ciao", 1, &mut rng(14)).is_err());
    }

    /// The two schemes that derive the SAME key must not be interchangeable,
    /// here from the side of someone rereading their own message:
    /// `open_as_sender` must not open an epoch bootstrap.
    #[test]
    fn rileggere_il_proprio_non_apre_un_altro_schema() {
        let alice = identita(0x11);
        let bob = identita(0x22);
        let mia_epoca = EphemeralSecret::from_bytes([0x44; KEY_LEN]);

        let (header, ciphertext) = seal_epoch_bootstrap(
            &alice,
            &bob.public(),
            &mia_epoca.public(),
            b"ciao",
            1,
            &mut rng(3),
        )
        .unwrap();
        let bootstrap = format::serialize_message(&header, &ciphertext);
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&bootstrap, &mut buf).unwrap() else {
            panic!("atteso un messaggio")
        };

        // This used to open, and the 32 bytes of the epoch key appeared at the
        // start of the text shown as one's own message.
        assert!(open_as_sender(&alice, &bob.public(), &parsed).is_err());
        // And the right path still works on the same blob.
        assert!(open_epoch_bootstrap_as_sender(&alice, &bob.public(), &parsed).is_ok());
    }

    #[test]
    fn statico_e_bootstrap_a_epoca_non_sono_intercambiabili() {
        let alice = identita(0x11);
        let bob = identita(0x22);
        let mia_epoca = EphemeralSecret::from_bytes([0x33; KEY_LEN]);

        // Static read as bootstrap.
        let statico = seal(&alice, &bob.public(), b"IL CANCELLO E 1234", 1, &mut rng(1)).unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&statico, &mut buf).unwrap() else {
            panic!("atteso un messaggio")
        };
        assert!(
            open_epoch_bootstrap(&bob, &alice.public(), &parsed).is_err(),
            "un messaggio statico non deve aprirsi come bootstrap a epoca",
        );
        // And the right path still works on the same blob: the new check did
        // not close it too.
        assert!(open(&bob, &alice.public(), &parsed).is_ok());

        // Bootstrap read as static.
        let (header, ciphertext) = seal_epoch_bootstrap(
            &alice,
            &bob.public(),
            &mia_epoca.public(),
            b"ciao",
            1,
            &mut rng(2),
        )
        .unwrap();
        let bootstrap = format::serialize_message(&header, &ciphertext);
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&bootstrap, &mut buf).unwrap() else {
            panic!("atteso un messaggio")
        };
        assert!(
            open(&bob, &alice.public(), &parsed).is_err(),
            "un bootstrap a epoca non deve aprirsi come statico",
        );
        assert!(open_epoch_bootstrap(&bob, &alice.public(), &parsed).is_ok());
    }

    /// Decrypts a string produced by `seal`, taking the sender from the header
    /// as a real caller would.
    fn apri(destinatario: &Identity, testo: &str) -> Result<Plaintext> {
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(testo, &mut buf)? else {
            panic!("atteso un messaggio");
        };
        // If tampering cleared the SENDER_PUB flag there is no sender and
        // nothing to try: an error, not a reason to panic.
        let sender = parsed
            .header
            .sender_pub()
            .ok_or(Error::Format("sender_pub assente"))?;
        open(destinatario, sender, &parsed)
    }

    #[test]
    fn round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let messaggio = b"ciao, questo non lo legge la piattaforma";

        let testo = seal(&alice, &bob.public(), messaggio, 1_700_000_000, &mut rng(9)).unwrap();
        assert!(testo.starts_with(SENTINEL));
        assert_eq!(apri(&bob, &testo).unwrap().as_bytes(), messaggio);
    }

    #[test]
    fn plaintext_vuoto_e_lungo() {
        let alice = identita(3);
        let bob = identita(4);

        for messaggio in [vec![], vec![0xAAu8; 4096]] {
            let testo = seal(&alice, &bob.public(), &messaggio, 1_700_000_000, &mut rng(1)).unwrap();
            assert_eq!(apri(&bob, &testo).unwrap().as_bytes(), &messaggio[..]);
        }
    }

    /// With a static ECDH secret, two encryptions of the same text must still
    /// differ: otherwise the nonce would not be fresh and the keystream would
    /// be reused.
    #[test]
    fn nonce_fresco_a_ogni_messaggio() {
        let alice = identita(5);
        let bob = identita(6);
        let mut r = rng(42);

        let uno = seal(&alice, &bob.public(), b"stesso testo", 1_700_000_000, &mut r).unwrap();
        let due = seal(&alice, &bob.public(), b"stesso testo", 1_700_000_000, &mut r).unwrap();
        assert_ne!(uno, due);
    }

    #[test]
    fn destinatario_sbagliato() {
        let alice = identita(7);
        let bob = identita(8);
        let carol = identita(9);

        let testo = seal(&alice, &bob.public(), b"per bob", 1_700_000_000, &mut rng(3)).unwrap();
        assert!(matches!(apri(&carol, &testo), Err(Error::Crypto)));
    }

    #[test]
    fn mittente_dichiarato_sbagliato() {
        let alice = identita(10);
        let bob = identita(11);
        let mallory = identita(12);

        let testo = seal(&alice, &bob.public(), b"da alice", 1_700_000_000, &mut rng(4)).unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&testo, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert!(matches!(
            open(&bob, &mallory.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Full round trip of the ephemeral-sender scheme.
    #[test]
    fn effimero_round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let mia = prekey(4);
        let blob =
            seal_ephemeral(&alice, &bob.public(), &mia.public(), b"ciao", 99, &mut rng).unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!("doveva essere un messaggio");
        };
        let (prekey_ricevuta, aperto) = open_ephemeral(&bob, &alice.public(), &parsed).unwrap();
        assert_eq!(aperto.as_bytes(), b"ciao");
        assert_eq!(aperto.sent_at_unix(), 99);
        // The intermediate message carries the prekey too: that is how the
        // chain starts.
        assert_eq!(prekey_ricevuta, mia.public());
    }

    /// Alice's key appears nowhere in clear: that is what removes linkability
    /// between her messages.
    #[test]
    fn effimero_non_mostra_il_mittente() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let blob = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!("doveva essere un messaggio");
        };
        assert!(parsed.header.sender_pub().is_none());
        assert!(parsed.header.origin.is_ephemeral());
        let effimera = parsed.header.origin.key().unwrap();
        assert_ne!(effimera, &alice.public());
        assert!(!buf.windows(32).any(|w| w == alice.public().as_bytes()));
    }

    /// Trying the wrong key fails: that is what makes trial decryption a proof
    /// of identity rather than a guess.
    #[test]
    fn effimero_col_candidato_sbagliato_non_si_apre() {
        let alice = identita(1);
        let bob = identita(2);
        let carol = identita(3);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let blob = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!("doveva essere un messaggio");
        };
        assert!(matches!(
            open_ephemeral(&bob, &carol.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Two identical messages produce neither the same blob nor the same
    /// ephemeral key: if it repeated, there would be no forward secrecy.
    #[test]
    fn effimero_ogni_messaggio_ha_la_sua_chiave() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);
        let uno = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();
        let due = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();
        assert_ne!(uno, due);

        let (mut a, mut b) = (Vec::new(), Vec::new());
        let ParsedBlob::Message(p1) = format::parse(&uno, &mut a).unwrap() else { panic!() };
        let ParsedBlob::Message(p2) = format::parse(&due, &mut b).unwrap() else { panic!() };
        assert_ne!(p1.header.origin.key(), p2.header.origin.key());
    }

    /// An ephemeral message does not open through the normal path, and vice
    /// versa: flags are in the AAD, so the two forms are not interchangeable.
    #[test]
    fn effimero_e_normale_non_si_scambiano() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([7; 32]);

        let effimero = seal_ephemeral(&alice, &bob.public(), &prekey(4).public(), b"ciao", 1, &mut rng).unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&effimero, &mut buf).unwrap() else {
            panic!()
        };
        assert!(matches!(open(&bob, &alice.public(), &parsed), Err(Error::Crypto)));

        let normale = seal(&alice, &bob.public(), b"ciao", 1, &mut rng).unwrap();
        let mut buf2 = Vec::new();
        let ParsedBlob::Message(p2) = format::parse(&normale, &mut buf2).unwrap() else {
            panic!()
        };
        assert!(matches!(
            open_ephemeral(&bob, &alice.public(), &p2),
            Err(Error::Crypto)
        ));
    }

    fn prekey(seed: u8) -> EphemeralSecret {
        EphemeralSecret::from_bytes([seed; 32])
    }

    /// Full round trip of full forward secrecy, with the reply prekey coming
    /// back from the ciphertext.
    #[test]
    fn forward_round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let prekey_bob = prekey(9);
        let prekey_alice = prekey(8);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);

        let blob = seal_forward(
            &alice,
            &bob.public(),
            &prekey_bob.public(),
            &prekey_alice.public(),
            b"ciao",
            77,
            &mut rng,
        )
        .unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        let (prossima, aperto) =
            open_forward(&prekey_bob, &alice.public(), &bob.public(), &parsed).unwrap();
        assert_eq!(aperto.as_bytes(), b"ciao");
        assert_eq!(aperto.sent_at_unix(), 77);
        // The prekey Bob will reply to is the one Alice put inside the
        // ciphertext, hence authenticated: nobody could have replaced it.
        assert_eq!(prossima, prekey_alice.public());
    }

    /// **The property that justifies everything.** Without the recipient's
    /// prekey the message does not open, even with both stable keys.
    #[test]
    fn buttata_la_prekey_il_messaggio_e_morto() {
        let alice = identita(1);
        let bob = identita(2);
        let prekey_bob = prekey(9);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        let blob = seal_forward(
            &alice,
            &bob.public(),
            &prekey_bob.public(),
            &prekey(8).public(),
            b"segreto",
            1,
            &mut rng,
        )
        .unwrap();

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        // Bob dropped that prekey and has another: his identity is no longer
        // enough.
        let altra = prekey(77);
        assert!(matches!(
            open_forward(&altra, &alice.public(), &bob.public(), &parsed),
            Err(Error::Crypto)
        ));
        // Nor does the path without prekey work, because flags are in the AAD.
        assert!(matches!(
            open_ephemeral(&bob, &alice.public(), &parsed),
            Err(Error::Crypto)
        ));
        assert!(matches!(
            open(&bob, &alice.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// The sender stays proven: with the wrong candidate it does not open.
    #[test]
    fn forward_col_candidato_sbagliato_non_si_apre() {
        let alice = identita(1);
        let bob = identita(2);
        let carol = identita(3);
        let prekey_bob = prekey(9);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([5; 32]);
        let blob = seal_forward(
            &alice,
            &bob.public(),
            &prekey_bob.public(),
            &prekey(8).public(),
            b"ciao",
            1,
            &mut rng,
        )
        .unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        assert!(matches!(
            open_forward(&prekey_bob, &carol.public(), &bob.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// Every single bit of the blob is protected: flipping any one must prevent
    /// decryption. Covers ciphertext, tag, nonce, sender public key, flags and
    /// tier byte at once.
    #[test]
    fn ogni_bit_flip_e_intercettato() {
        let alice = identita(13);
        let bob = identita(14);
        let testo = seal(&alice, &bob.public(), b"integro", 1_700_000_000, &mut rng(5)).unwrap();

        let payload = testo.strip_prefix(SENTINEL).unwrap();
        let originale = crate::encoding::decode(payload).unwrap();

        for i in 0..originale.len() {
            for bit in 0..8u8 {
                let mut body = originale.clone();
                let Some(slot) = body.get_mut(i) else { continue };
                *slot ^= 1 << bit;
                if body == originale {
                    continue;
                }

                let mutato = format!("{SENTINEL}{}", crate::encoding::encode(&body));
                assert!(
                    apri(&bob, &mutato).is_err(),
                    "bit {bit} del byte {i} passato inosservato"
                );
            }
        }
    }

    /// Anti-downgrade test. Changing the tier byte from Baseline to
    /// ForwardSecret must give an attacker nothing useful: the tier is in the
    /// AAD, so tampering is detectable.
    ///
    /// The expected error here is `TierUnsupported` because `open` rejects the
    /// tier before reaching the AEAD. The point is that it does NOT decrypt: if
    /// that tier is ever implemented, this test must keep failing decryption,
    /// with `Crypto` instead of `TierUnsupported`.
    #[test]
    fn downgrade_del_tier_rifiutato() {
        let alice = identita(15);
        let bob = identita(16);
        let testo = seal(&alice, &bob.public(), b"tier baseline", 1_700_000_000, &mut rng(6)).unwrap();

        let payload = testo.strip_prefix(SENTINEL).unwrap();
        let mut body = crate::encoding::decode(payload).unwrap();
        // byte 2 = tier (after version and kind)
        *body.get_mut(2).unwrap() = Tier::ForwardSecret as u8;
        let manomesso = format!("{SENTINEL}{}", crate::encoding::encode(&body));

        assert!(matches!(apri(&bob, &manomesso), Err(Error::TierUnsupported)));
    }

    /// A low-order public key yields an all-zero shared secret, the same for
    /// everyone: whoever receives it as `sender_pub` would derive an AEAD key
    /// anyone can recompute. It must be rejected before deriving anything.
    ///
    /// The seven points below are the complete set of small-order points of
    /// curve25519, in the form used by libsodium's tests.
    ///
    /// Note: `[0xFF; 32]` is NOT in this set, however degenerate it looks.
    /// X25519 clears the top bit of the coordinate, so those bytes are
    /// 2^255-1, i.e. 18 mod p: a perfectly valid full-order point.
    #[test]
    fn pubkey_di_ordine_basso_rifiutata() {
        let alice = identita(17);
        let degeneri: [[u8; 32]; 7] = [
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            hex!("0100000000000000000000000000000000000000000000000000000000000000"),
            hex!("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800"),
            hex!("5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157"),
            hex!("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
            hex!("eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"),
        ];

        for bytes in degeneri {
            let peer = PublicKey::from_bytes(bytes);
            assert!(
                matches!(seal(&alice, &peer, b"x", 1_700_000_000, &mut rng(7)), Err(Error::Crypto)),
                "pubkey degenere accettata: {bytes:02x?}"
            );
        }
    }

    /// The timestamp survives the round trip and is authenticated: altering it
    /// means altering the ciphertext, which the tag catches.
    #[test]
    fn timestamp_autenticato_e_recuperato() {
        let alice = identita(20);
        let bob = identita(21);
        let quando = 1_735_689_600i64; // 2025-01-01

        let testo = seal(&alice, &bob.public(), b"con data", quando, &mut rng(11)).unwrap();
        let aperto = apri(&bob, &testo).unwrap();
        assert_eq!(aperto.as_bytes(), b"con data");
        assert_eq!(aperto.sent_at_unix(), quando);
    }

    /// The timestamp lengthens the blob by exactly 8 bytes, not by a
    /// variable-length field that would shift lengths depending on content.
    #[test]
    fn il_timestamp_costa_otto_byte() {
        let alice = identita(22);
        let bob = identita(23);

        let corto = seal(&alice, &bob.public(), b"", 0, &mut rng(12)).unwrap();
        let payload = corto.strip_prefix(SENTINEL).unwrap();
        let body = crate::encoding::decode(payload).unwrap();
        let atteso = crate::format::MESSAGE_PREFIX_LEN
            + crate::keys::KEY_LEN
            + NONCE_LEN
            + TIMESTAMP_LEN
            + TAG_LEN;
        assert_eq!(body.len(), atteso);
    }

    /// An absurd timestamp is not an error: nobody can prove the sender's clock
    /// was right, and rejecting messages on a strange date would make the
    /// system unusable for anyone with the wrong time on their phone.
    #[test]
    fn timestamp_assurdo_non_e_un_errore() {
        let alice = identita(24);
        let bob = identita(25);

        for quando in [i64::MIN, -1, 0, i64::MAX] {
            let testo = seal(&alice, &bob.public(), b"x", quando, &mut rng(13)).unwrap();
            assert_eq!(apri(&bob, &testo).unwrap().sent_at_unix(), quando);
        }
    }

    /// Regression anchor: fixed identities and nonce must always produce the
    /// same string. If it breaks, the wire format or the key derivation (i.e.
    /// compatibility) changed, not the code.
    #[test]
    fn kat_baseline() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let bob = Identity::from_secret_bytes([0x22; 32]).unwrap();
        let testo = seal(&alice, &bob.public(), b"kat", 1_700_000_000, &mut rng(0)).unwrap();
        assert_eq!(testo, KAT_BASELINE);
        assert_eq!(apri(&bob, KAT_BASELINE).unwrap().as_bytes(), b"kat");
    }

    /// Regression anchors for the **group** format (decision K).
    ///
    /// They were added after a change to the slot derivation domain (a real
    /// compatibility break) passed the whole suite unnoticed. They pin:
    ///
    /// - the **exact string**: framing, field order, slot and payload key
    ///   derivation, and also the slot shuffle, which is deterministic with a
    ///   fixed RNG and part of the format;
    /// - that **every recipient** reopens their slot;
    /// - that **the sender** reopens it too, from their own slot (K2).
    ///
    /// If one of these breaks, it is **not a refactor**: it is a format change,
    /// to be handled as such (a new version, not a change to version 2).
    #[test]
    fn kat_gruppo() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let bob = Identity::from_secret_bytes([0x22; 32]).unwrap();
        let carla = Identity::from_secret_bytes([0x33; 32]).unwrap();

        let blob = gruppo(&alice, &[bob.public(), carla.public()], b"kat", 0);
        assert_eq!(blob, KAT_GRUPPO);

        for chi in [&bob, &carla] {
            assert_eq!(
                apri_gruppo(KAT_GRUPPO, chi, &alice.public()).unwrap().as_bytes(),
                b"kat",
            );
        }
        // The sender rereads from their own slot.
        assert_eq!(
            apri_gruppo(KAT_GRUPPO, &alice, &alice.public()).unwrap().as_bytes(),
            b"kat",
        );
    }

    /// A group with a single recipient: two slots in total, the recipient's and
    /// the sender's. Pins the boundary case of `n_slot`, a byte that alone
    /// decides how much is read.
    #[test]
    fn kat_gruppo_minimo() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let bob = Identity::from_secret_bytes([0x22; 32]).unwrap();

        let blob = gruppo(&alice, &[bob.public()], b"kat", 0);
        assert_eq!(blob, KAT_GRUPPO_MINIMO);
        assert_eq!(
            apri_gruppo(KAT_GRUPPO_MINIMO, &bob, &alice.public()).unwrap().as_bytes(),
            b"kat",
        );
    }

    const KAT_GRUPPO: &str = "kc/yeyyyy4qekw7rqfim56orfye4tjzftohccp68mx4mamgmdazf6dp7r3hn751jab9zdcrwp5keqhxefeawrqc8b7spg3qh3cgyx64bytog9n76nrpz3h4zqdw36gqdg3jk4yzhqydhz8pwectbtqxepfpa49ydurmbz5fis5te598mdookzaba9dn8g833t5tbdb64o1chazw8558z1rj5thzcwko6s1bfsoqc6dsnb6o8zmcugrueotfdbgb9dn7p88wwgfukpgsnhkrhziceebd9u7cp6hau5ebr6imotc4z5kuq6f4d9mix66udth1c6wjdfbd6dsp5izcxpbr7f3oxgcutytop1jk86uit6tnk1wzk5cy";
    const KAT_GRUPPO_MINIMO: &str = "kc/yeyyyyajxjmm6o5uq3pp1snuac9job74zmcwuz8r8344h3o6mhnoqjhsybeiq1rpqh1qyx7a5bfdq41dzd4bkgfbdubaxpujymzssqr4ditw3st1hrswoje8h1bgo5dhiypi9yesze1614jeu5whtnheag3x9b1szbqwdabbzu8z7z456ppu543sina5bp6cweu3pf3kahztf3kzf63cni9kdcnjcfyeyadurk9mqnys1quodb7q7afxoceggnj4phw8c3o4dm4y3yrffsuznkd7athmbs5dwxsgtcy";

    const KAT_BASELINE: &str = "kc/yryyyym5j4ejzxu993nce3pnrybz4arqhpcjxwa69f3xy95wtrsmb739np5mtafpwdau5rnymiiqkwhgzwwm5wo3znoe55e4w7jg53deymgkw548czgbcg9oe759w8g6shbp8mx46g5y";
}
