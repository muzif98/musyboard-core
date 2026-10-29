//! Encrypted files: photos, voice notes, anything (decision G).
//!
//! ## Why not through text
//!
//! z-base-32 inflates by 1.6×: a 500 KB photo would become 800 KB of
//! characters, out of scale for any chat field. An encrypted file therefore
//! travels as a **binary attachment**, handed to the chat by the share sheet,
//! not by the keyboard (which cannot attach files).
//!
//! ## What is inside the ciphertext
//!
//! The file name and type are **inside**, not in the attachment name:
//!
//! ```text
//! timestamp(8, LE) | name_len(2, LE) | name | mime_len(2, LE) | mime | content
//! ```
//!
//! The timestamp is added by [`crate::baseline`], as for messages; the rest
//! belongs to this module.
//!
//! In clear, a name like `IMG_20260810_marks-birthday.jpg` would tell the
//! platform almost everything encryption is meant to hide. Outside there is
//! only a neutral name with the `.kc` extension (decision G3): it says the
//! file is encrypted, and nothing else.
//!
//! ## Accepted residual, and not a small one
//!
//! An attachment that opens with nothing is a much stronger marker than a
//! text blob, and its **size** says much more than the length of a text.
//! Accepted because the observed alternative is worse: without this path,
//! photos are sent anyway, in clear, in the same conversation.

use zeroize::Zeroizing;

use crate::baseline;
use crate::error::{Error, Result};
use crate::format::{self, ParsedEnvelope};
use crate::keys::{Identity, PublicKey};

/// Cap on the length of name and type. They are metadata, not content; beyond
/// this they become a channel for smuggling data into a field nobody looks at.
const MAX_META_LEN: usize = 512;

/// Size of each of the two length fields.
const LEN_FIELD: usize = 2;

/// Name and type of a file, from the encrypted part.
///
/// **No `Debug`**, by the same rule that keeps private keys out of logs: these
/// fields come from **inside** the ciphertext, so they are plaintext. A file
/// name is the most telling metadata there is (decision G3 drops it on the way
/// out for this reason), and a derived `Debug` would be enough to make it
/// reappear in a panic message or a log line.
#[derive(Clone, PartialEq, Eq)]
pub struct FileMeta {
    /// Original name. **Treat as hostile**: it comes from the sender, and
    /// whoever saves the file must sanitise it (it may contain `../`, a path
    /// separator, or five hundred characters).
    pub name: String,
    /// MIME type declared by the sender. Used to choose how to show it, and
    /// worth exactly the sender's word: `image/jpeg` does not guarantee an
    /// image inside.
    pub mime: String,
}

/// Name and type are wiped from memory when the struct is dropped.
///
/// `String` alone does not zeroize: it leaves the allocation on the heap until
/// reused. Done here rather than with `Zeroizing<String>` fields, which every
/// front-end would have to unwrap for the same guarantee.
impl Drop for FileMeta {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.name.zeroize();
        self.mime.zeroize();
    }
}

/// A decrypted file.
pub struct DecryptedFile {
    pub meta: FileMeta,
    /// Zeroized on drop, like all plaintext in this crate.
    pub content: Zeroizing<Vec<u8>>,
    /// Authenticated but **not verifiable**: nobody can prove the sender's
    /// clock was right. Shown, never used for decisions.
    pub sent_at_unix: i64,
}

/// Encrypts a file for `recipient`.
///
/// The recipient is explicit, never inferred (decision G4): sending a file to
/// the wrong person cannot be undone.
pub fn seal_file<R: rand_core::RngCore + rand_core::CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    meta: &FileMeta,
    content: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let name = meta.name.as_bytes();
    let mime = meta.mime.as_bytes();
    if name.len() > MAX_META_LEN || mime.len() > MAX_META_LEN {
        return Err(Error::Format("nome o tipo del file troppo lunghi"));
    }
    let name_len = u16::try_from(name.len()).map_err(|_| Error::Format("nome troppo lungo"))?;
    let mime_len = u16::try_from(mime.len()).map_err(|_| Error::Format("tipo troppo lungo"))?;

    let capacity = LEN_FIELD
        .saturating_mul(2)
        .saturating_add(name.len())
        .saturating_add(mime.len())
        .saturating_add(content.len());
    let mut inner = Zeroizing::new(Vec::with_capacity(capacity));
    inner.extend_from_slice(&name_len.to_le_bytes());
    inner.extend_from_slice(name);
    inner.extend_from_slice(&mime_len.to_le_bytes());
    inner.extend_from_slice(mime);
    inner.extend_from_slice(content);

    baseline::seal_file(sender, recipient, &inner, now_unix, rng)
}

/// Like [`seal_file`], with the forward secrecy chain.
///
/// `prekey_destinatario` is the latest temporary key that contact sent us: if
/// present, full forward secrecy; if missing, fall back to the ephemeral
/// sender, which is still better than static-static and **starts** the chain
/// by carrying ours.
///
/// Attachments share the per-contact state of messages: same conversation,
/// same person, and two chains would mean twice the keys to keep and twice
/// the chances of not dropping them.
#[allow(clippy::too_many_arguments)]
pub fn seal_file_forward<R: rand_core::RngCore + rand_core::CryptoRng>(
    sender: &Identity,
    recipient: &PublicKey,
    prekey_destinatario: Option<&PublicKey>,
    mia_prekey: &PublicKey,
    meta: &FileMeta,
    content: &[u8],
    now_unix: i64,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let inner = componi(meta, content)?;
    match prekey_destinatario {
        Some(loro) => baseline::seal_file_forward(
            sender, recipient, loro, mia_prekey, &inner, now_unix, rng,
        ),
        None => {
            baseline::seal_file_ephemeral(sender, recipient, mia_prekey, &inner, now_unix, rng)
        }
    }
}

/// Name, type and content in one block, with length checks.
fn componi(meta: &FileMeta, content: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let name = meta.name.as_bytes();
    let mime = meta.mime.as_bytes();
    if name.len() > MAX_META_LEN || mime.len() > MAX_META_LEN {
        return Err(Error::Format("nome o tipo del file troppo lunghi"));
    }
    let name_len = u16::try_from(name.len()).map_err(|_| Error::Format("nome troppo lungo"))?;
    let mime_len = u16::try_from(mime.len()).map_err(|_| Error::Format("tipo troppo lungo"))?;
    let capacity = LEN_FIELD
        .saturating_mul(2)
        .saturating_add(name.len())
        .saturating_add(mime.len())
        .saturating_add(content.len());
    let mut inner = Zeroizing::new(Vec::with_capacity(capacity));
    inner.extend_from_slice(&name_len.to_le_bytes());
    inner.extend_from_slice(name);
    inner.extend_from_slice(&mime_len.to_le_bytes());
    inner.extend_from_slice(mime);
    inner.extend_from_slice(content);
    Ok(inner)
}

/// Reads an attachment envelope without decrypting it.
///
/// Lets the recipient learn **who** sent it before opening it: the sender's
/// public key is in the clear header, as in messages.
pub fn parse_file(bytes: &[u8]) -> Result<ParsedEnvelope<'_>> {
    format::parse_file(bytes)
}

/// Inverse of [`seal_file`].
pub fn open_file(
    recipient: &Identity,
    sender_pub: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<DecryptedFile> {
    monta(baseline::open_file(recipient, sender_pub, parsed)?)
}

/// Opens an ephemeral-sender attachment **assuming** `candidato` sent it.
/// Also returns their next temporary key.
pub fn open_file_ephemeral(
    recipient: &Identity,
    candidato: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, DecryptedFile)> {
    let (prekey, plaintext) = baseline::open_file_ephemeral(recipient, candidato, parsed)?;
    Ok((prekey, monta(plaintext)?))
}

/// Opens a fully forward-secret attachment with one of our temporary keys.
pub fn open_file_forward(
    mia_prekey: &crate::keys::EphemeralSecret,
    candidato: &PublicKey,
    destinatario: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<(PublicKey, DecryptedFile)> {
    let (prekey, plaintext) =
        baseline::open_file_forward(mia_prekey, candidato, destinatario, parsed)?;
    Ok((prekey, monta(plaintext)?))
}

/// Reopens an attachment **we sent**, trying `recipient` as the recipient.
/// Only works without the chain, as for messages.
pub fn open_file_as_sender(
    sender: &Identity,
    recipient: &PublicKey,
    parsed: &ParsedEnvelope<'_>,
) -> Result<DecryptedFile> {
    monta(baseline::open_file_as_sender(sender, recipient, parsed)?)
}

fn monta(plaintext: crate::baseline::Plaintext) -> Result<DecryptedFile> {
    let (meta, content) = split_inner(plaintext.as_bytes())?;
    Ok(DecryptedFile {
        meta,
        content: Zeroizing::new(content),
        sent_at_unix: plaintext.sent_at_unix(),
    })
}

/// Splits metadata and content.
///
/// Everything read here is already **authenticated** (the AEAD said yes), so
/// it cannot have been tampered with in transit. It can still be absurd,
/// because the sender may have written anything: every length is checked
/// against what remains instead of being trusted.
fn split_inner(inner: &[u8]) -> Result<(FileMeta, Vec<u8>)> {
    let (name, rest) = take_field(inner)?;
    let (mime, content) = take_field(rest)?;
    let meta = FileMeta {
        name: String::from_utf8(name).map_err(|_| Error::Format("nome non e' UTF-8"))?,
        mime: String::from_utf8(mime).map_err(|_| Error::Format("tipo non e' UTF-8"))?,
    };
    Ok((meta, content.to_vec()))
}

/// `split_at` rather than `split_at_checked`, which is stable only since Rust
/// 1.80 while the crate declares 1.75. The length is checked **before** every
/// split, so neither can go out of range.
fn take_field(bytes: &[u8]) -> Result<(Vec<u8>, &[u8])> {
    if bytes.len() < LEN_FIELD {
        return Err(Error::Format("allegato troncato"));
    }
    let (len_bytes, rest) = bytes.split_at(LEN_FIELD);
    let len = usize::from(u16::from_le_bytes([
        *len_bytes.first().ok_or(Error::Format("allegato troncato"))?,
        *len_bytes.get(1).ok_or(Error::Format("allegato troncato"))?,
    ]));
    if len > MAX_META_LEN {
        return Err(Error::Format("metadato del file troppo lungo"));
    }
    if rest.len() < len {
        return Err(Error::Format("allegato troncato"));
    }
    let (field, tail) = rest.split_at(len);
    Ok((field.to_vec(), tail))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    fn identita(seed: u8) -> Identity {
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([seed; 32]);
        Identity::generate(&mut rng).unwrap()
    }

    fn meta() -> FileMeta {
        FileMeta {
            name: "compleanno di marco.jpg".to_owned(),
            mime: "image/jpeg".to_owned(),
        }
    }

    #[test]
    fn round_trip() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let content = vec![0xABu8; 5000];

        let blob = seal_file(&alice, &bob.public(), &meta(), &content, 1_700_000_000, &mut rng)
            .unwrap();
        let parsed = parse_file(&blob).unwrap();
        let out = open_file(&bob, &alice.public(), &parsed).unwrap();

        // Field by field rather than `assert_eq!` on the struct: `FileMeta`
        // has no `Debug` on purpose.
        assert_eq!(out.meta.name, meta().name);
        assert_eq!(out.meta.mime, meta().mime);
        assert_eq!(out.content.as_slice(), content.as_slice());
        assert_eq!(out.sent_at_unix, 1_700_000_000);
    }

    /// The name travels inside the ciphertext: no trace of it outside.
    #[test]
    fn il_nome_non_e_in_chiaro() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"x", 1, &mut rng).unwrap();
        assert!(!blob
            .windows(6)
            .any(|w| w == b"marco." || w == b"image/"));
    }

    /// `kind` is in the AAD: a file does not open as a message even with the
    /// right key, and a message does not open as a file.
    #[test]
    fn un_file_non_e_un_messaggio() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"contenuto", 1, &mut rng).unwrap();
        let parsed = parse_file(&blob).unwrap();
        assert!(matches!(
            baseline::open(&bob, &alice.public(), &parsed),
            Err(Error::Crypto)
        ));
    }

    /// An attachment that is not ours must not look like a decryption error:
    /// it is a file of another type, and is reported as such.
    #[test]
    fn un_messaggio_non_e_un_allegato() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let testo = baseline::seal(&alice, &bob.public(), b"ciao", 1, &mut rng).unwrap();
        let body = crate::encoding::decode(testo.trim_start_matches(format::SENTINEL)).unwrap();
        assert!(matches!(parse_file(&body), Err(Error::Format(_))));
    }

    #[test]
    fn ogni_bit_flip_e_intercettato() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"contenuto", 1, &mut rng).unwrap();
        for i in 0..blob.len() {
            let mut corrotto = blob.clone();
            corrotto[i] ^= 0x01;
            let aperto = parse_file(&corrotto)
                .and_then(|p| open_file(&bob, &alice.public(), &p));
            assert!(aperto.is_err(), "il bit {i} e' passato inosservato");
        }
    }

    #[test]
    fn troncato_non_si_apre() {
        let alice = identita(1);
        let bob = identita(2);
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([9; 32]);
        let blob = seal_file(&alice, &bob.public(), &meta(), b"contenuto", 1, &mut rng).unwrap();
        for len in 0..blob.len() {
            let aperto = parse_file(&blob[..len])
                .and_then(|p| open_file(&bob, &alice.public(), &p));
            assert!(aperto.is_err(), "troncato a {len} si e' aperto");
        }
    }
}
