//! Identity backup: the private key and the keyring, encrypted with a
//! passphrase, in a form that can leave the device.
//!
//! # Why Android Keystore is not enough
//!
//! On the phone the secret is protected by a non-exportable Keystore key.
//! That is exactly right there, and exactly why a backup cannot use it: a
//! file encrypted with a key that never leaves the device can never be opened
//! on another device. Protection here depends **only** on what the user
//! knows; a backup with a weak passphrase is a weak backup.
//!
//! # What this module exists to prevent
//!
//! Without a backup, whoever changes phone or clears the app data loses the
//! identity, and every contact sees a key change: the same signal that
//! indicates an impersonation attempt.
//!
//! # Format
//!
//! ```text
//! version(1) | salt(16) | m_cost(4 BE) | t_cost(4 BE) | p_cost(1) |
//! nonce(24) | ciphertext( secret(32) || keyring ) + tag(16)
//! ```
//!
//! The header travels **in clear** (version, salt and parameters are needed
//! to redo the derivation) but is entirely authenticated data of the AEAD, so
//! it cannot be modified. Otherwise the attack would be immediate: rewrite the
//! parameters to `m=8, t=1`, the file still opens with the same passphrase,
//! and guessing becomes thousands of times cheaper, without the victim ever
//! noticing.

use crate::error::{Error, Result};
use crate::keys::Identity;
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

/// Version of the backup container. Independent of the message format: the
/// two formats have separate lifecycles.
const VERSION: u8 = 1;

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const KEY_LEN: usize = 32;
const TAG_LEN: usize = 16;
const SECRET_LEN: usize = 32;

/// Clear header: version, salt and the three Argon2 parameters.
const HEADER_LEN: usize = 1 + SALT_LEN + 4 + 4 + 1;

/// Memory cost in KiB: 64 MiB.
///
/// This decides how much a passphrase guess costs, and is also what can make
/// the operation fail on a cheap phone. 64 MiB makes each guess expensive
/// even on GPUs (where memory is the bottleneck) without killing a device with
/// 2 GB of RAM.
///
/// Not frozen: it is stored in the file, so raising it later does not break
/// existing backups, which reopen with the parameters they were written with.
const M_COST: u32 = 65_536;

/// Number of passes.
const T_COST: u32 = 3;

/// Parallelism. One: phones have few, busy cores, and raising it helps the
/// attacker (who has many) more than the defender.
const P_COST: u32 = 1;

/// Domain separation: the key derived here must never coincide with any other
/// key in the project, even if the same passphrase were reused elsewhere.
const AD: &[u8] = b"keyboard-cipher/v1/backup";

/// Contents of an opened backup.
///
/// **Does not implement `Debug`**, and must not: it contains the private key
/// in clear, and a `{:?}` in a log would write it to disk.
///
/// Both fields are zeroized on drop: the secret because it is the private
/// key, the keyring because it is the list of people one talks to.
pub struct Backup {
    /// The 32 bytes of the identity secret.
    pub secret: Zeroizing<[u8; SECRET_LEN]>,
    /// The serialised keyring, opaque to this module.
    pub keyring: Zeroizing<Vec<u8>>,
}

/// Encrypts identity and keyring with a passphrase.
///
/// `keyring` is opaque bytes: its serialisation belongs to the implementer,
/// not to this module.
///
/// # Errors
///
/// [`Error::Format`] if the passphrase is empty (see below).
///
/// [`Error::Crypto`] if derivation or encryption fails. The caller cannot
/// tell which, on purpose.
///
/// # The empty passphrase is rejected here, not in the UI
///
/// Argon2 accepts an empty passphrase without complaint, producing a file
/// **that looks like an encrypted backup** and opens for anyone who presses
/// enter. That failure does not look like a failure. The check lives in the
/// core rather than in each front-end, so that it cannot be missing from one.
///
/// **`import` does not reject it**, on purpose: a backup made by an earlier
/// version, when empty passphrases were accepted, must stay openable.
/// Rejecting it on read would protect nobody (the file is already out) and
/// would lock the owner out of their data.
///
/// This is not a strength check: "empty" is the only case the core can judge
/// without inventing a policy. Minimum length is up to the UI.
pub fn export<R: RngCore + CryptoRng>(
    identity: &Identity,
    keyring: &[u8],
    passphrase: &[u8],
    rng: &mut R,
) -> Result<Vec<u8>> {
    if passphrase.is_empty() {
        return Err(Error::Format("passphrase vuota"));
    }
    let mut salt = [0u8; SALT_LEN];
    rng.fill_bytes(&mut salt);
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let header = header_bytes(&salt, M_COST, T_COST, P_COST);
    let key = derive(passphrase, &salt, M_COST, T_COST, P_COST)?;

    // The plaintext is secret(32) || keyring. It lives in a Zeroizing buffer
    // because it holds the raw private key.
    let mut plaintext = Zeroizing::new(Vec::with_capacity(
        SECRET_LEN.saturating_add(keyring.len()),
    ));
    plaintext.extend_from_slice(identity.secret_bytes().as_ref());
    plaintext.extend_from_slice(keyring);

    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto)?;
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_slice(),
                aad: &header,
            },
        )
        .map_err(|_| Error::Crypto)?;

    let mut out = Vec::with_capacity(
        HEADER_LEN
            .saturating_add(NONCE_LEN)
            .saturating_add(ciphertext.len()),
    );
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Opens a backup.
///
/// # Errors
///
/// - [`Error::Format`] if the file is too short or malformed;
/// - [`Error::UnsupportedVersion`] for a future version, so the user reads
///   "update the app" rather than "wrong passphrase";
/// - [`Error::Crypto`] for everything else, **wrong passphrase included**.
///   "Wrong passphrase" and "tampered file" cannot be distinguished with
///   authenticated encryption, and must not be: it would be an oracle for
///   whoever is guessing.
pub fn import(blob: &[u8], passphrase: &[u8]) -> Result<Backup> {
    let minimo = HEADER_LEN
        .saturating_add(NONCE_LEN)
        .saturating_add(SECRET_LEN)
        .saturating_add(TAG_LEN);
    if blob.len() < minimo {
        return Err(Error::Format("backup troppo corto"));
    }
    let header = blob.get(..HEADER_LEN).ok_or(Error::Format("intestazione"))?;

    let versione = *header.first().ok_or(Error::Format("versione"))?;
    if versione != VERSION {
        return Err(Error::UnsupportedVersion(versione));
    }

    let salt: [u8; SALT_LEN] = header
        .get(1..1 + SALT_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("salt"))?;
    let m_cost = be_u32(header, 1 + SALT_LEN)?;
    let t_cost = be_u32(header, 1 + SALT_LEN + 4)?;
    let p_cost = u32::from(*header.get(1 + SALT_LEN + 8).ok_or(Error::Format("p_cost"))?);

    // A file can request arbitrary parameters and Argon2 would honour them. A
    // 4 GiB m_cost is not a cryptographic attack, but in Rust an allocation
    // failure aborts, and this runs inside the keyboard process: a crafted file
    // would kill the keyboard of whoever opens it.
    //
    // 256 MiB is four times what we write: room to raise costs later without
    // making old files unreadable, and no room to kill the process.
    if m_cost > 262_144 || t_cost > 8 || p_cost == 0 || p_cost > 4 {
        return Err(Error::Format("parametri di derivazione fuori scala"));
    }

    let nonce: [u8; NONCE_LEN] = blob
        .get(HEADER_LEN..HEADER_LEN + NONCE_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("nonce"))?;
    let ciphertext = blob
        .get(HEADER_LEN + NONCE_LEN..)
        .ok_or(Error::Format("ciphertext"))?;

    let key = derive(passphrase, &salt, m_cost, t_cost, p_cost)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| Error::Crypto)?;
    let plaintext = Zeroizing::new(
        cipher
            .decrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: ciphertext,
                    aad: header,
                },
            )
            .map_err(|_| Error::Crypto)?,
    );

    let secret: [u8; SECRET_LEN] = plaintext
        .get(..SECRET_LEN)
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("segreto"))?;
    // Goes through the identity constructor. It cannot fail today (any 32
    // bytes are a valid X25519 secret after clamping; low-order checks concern
    // the peer's PUBLIC key), but if the constructor ever gains validation,
    // the backup inherits it.
    Identity::from_secret_bytes(secret)?;

    let keyring = plaintext
        .get(SECRET_LEN..)
        .ok_or(Error::Format("portachiavi"))?
        .to_vec();

    Ok(Backup {
        secret: Zeroizing::new(secret),
        keyring: Zeroizing::new(keyring),
    })
}

fn header_bytes(salt: &[u8; SALT_LEN], m: u32, t: u32, p: u32) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.push(VERSION);
    header.extend_from_slice(salt);
    header.extend_from_slice(&m.to_be_bytes());
    header.extend_from_slice(&t.to_be_bytes());
    // `try_from` rather than `as`: with `p` above 255 the cast would write a
    // value different from the one used to derive, producing a backup that
    // looks valid and can never be opened.
    header.push(u8::try_from(p).unwrap_or(u8::MAX));
    header
}

fn be_u32(buf: &[u8], at: usize) -> Result<u32> {
    let quattro: [u8; 4] = buf
        .get(at..at.saturating_add(4))
        .and_then(|s| s.try_into().ok())
        .ok_or(Error::Format("intero a 32 bit"))?;
    Ok(u32::from_be_bytes(quattro))
}

fn derive(
    passphrase: &[u8],
    salt: &[u8; SALT_LEN],
    m: u32,
    t: u32,
    p: u32,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(m, t, p, Some(KEY_LEN)).map_err(|_| Error::Crypto)?;
    // The domain constant is passed as Argon2's "secret" (a pepper). It is not
    // secret (it is in the source); it only guarantees this derivation never
    // coincides with another one using the same passphrase and salt.
    let argon = Argon2::new_with_secret(AD, Algorithm::Argon2id, Version::V0x13, params)
        .map_err(|_| Error::Crypto)?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(passphrase, salt, key.as_mut())
        .map_err(|_| Error::Crypto)?;
    Ok(key)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    // Tests use MINIMAL parameters: the real ones cost 64 MiB and tens of
    // milliseconds per derivation, which would make the suite too slow to run
    // on every change. Parameters are stored in the file, so this shortcut
    // does not misrepresent the format.
    fn export_veloce(identity: &Identity, keyring: &[u8], pass: &[u8], seed: u8) -> Vec<u8> {
        let mut rng = ChaCha20Rng::from_seed([seed; 32]);
        let mut salt = [0u8; SALT_LEN];
        rng.fill_bytes(&mut salt);
        let mut nonce = [0u8; NONCE_LEN];
        rng.fill_bytes(&mut nonce);
        let header = header_bytes(&salt, 8, 1, 1);
        let key = derive(pass, &salt, 8, 1, 1).unwrap();
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(identity.secret_bytes().as_ref());
        plaintext.extend_from_slice(keyring);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_ref()).unwrap();
        let ct = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &header,
                },
            )
            .unwrap();
        let mut out = header;
        out.extend_from_slice(&nonce);
        out.extend_from_slice(&ct);
        out
    }

    /// `Backup` does not implement `Debug`, so `unwrap()` does not compile:
    /// the same rule that keeps private keys out of logs.
    fn apri(blob: &[u8], pass: &[u8]) -> Backup {
        match import(blob, pass) {
            Ok(b) => b,
            Err(_) => panic!("il backup doveva aprirsi"),
        }
    }

    fn identita(seed: u8) -> Identity {
        Identity::from_secret_bytes([seed; 32]).unwrap()
    }

    #[test]
    fn una_passphrase_vuota_non_produce_un_backup() {
        let id = identita(9);
        let mut rng = ChaCha20Rng::from_seed([0; 32]);
        // Argon2 would accept it silently, and the resulting file would be
        // indistinguishable from a real backup and open for anyone.
        let esito = export(&id, b"portachiavi", b"", &mut rng);
        assert!(matches!(esito, Err(Error::Format(_))));
    }

    #[test]
    fn un_backup_vecchio_a_passphrase_vuota_si_apre_ancora() {
        // The asymmetry with the test above is intended, and this test exists
        // so that nobody "fixes" it by adding the same check to `import`. An
        // existing file is already out there: rejecting it on read would only
        // lock the owner out.
        let id = identita(9);
        let blob = export_veloce(&id, b"portachiavi", b"", 4);
        let aperto = apri(&blob, b"");
        assert_eq!(aperto.keyring.as_slice(), b"portachiavi");
    }

    #[test]
    fn andata_e_ritorno() {
        let id = identita(7);
        let keyring = b"portachiavi finto".as_slice();
        let blob = export_veloce(&id, keyring, b"passphrase corretta", 1);

        let aperto = apri(&blob, b"passphrase corretta");
        assert_eq!(aperto.secret.as_ref(), id.secret_bytes().as_ref());
        assert_eq!(aperto.keyring.as_slice(), keyring);
    }

    #[test]
    fn passphrase_sbagliata_e_manomissione_danno_lo_stesso_errore() {
        let id = identita(9);
        let blob = export_veloce(&id, b"kr", b"giusta", 2);

        let per_passphrase = match import(&blob, b"sbagliata") {
            Err(e) => e,
            Ok(_) => panic!("non doveva aprirsi"),
        };
        let mut corrotto = blob.clone();
        let ultimo = corrotto.len() - 1;
        corrotto[ultimo] ^= 1;
        let per_manomissione = match import(&corrotto, b"giusta") {
            Err(e) => e,
            Ok(_) => panic!("non doveva aprirsi"),
        };

        // They must be indistinguishable: an error saying "right passphrase,
        // broken file" would also tell a guesser that the passphrase was right.
        assert!(matches!(per_passphrase, Error::Crypto));
        assert!(matches!(per_manomissione, Error::Crypto));
    }

    #[test]
    fn i_parametri_sono_autenticati() {
        let id = identita(3);
        let mut blob = export_veloce(&id, b"kr", b"pass", 4);
        // Lowering the derivation cost is the obvious attack: the file would
        // still open and guesses would be much cheaper. m=16 instead of the 8 it
        // was written with: it only has to be DIFFERENT.
        blob[1 + SALT_LEN..1 + SALT_LEN + 4].copy_from_slice(&16u32.to_be_bytes());
        assert!(import(&blob, b"pass").is_err());
    }

    #[test]
    fn versione_futura_non_dice_passphrase_sbagliata() {
        let id = identita(5);
        let mut blob = export_veloce(&id, b"kr", b"pass", 6);
        blob[0] = 2;
        assert!(matches!(
            import(&blob, b"pass"),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn parametri_assurdi_rifiutati_senza_provarci() {
        let id = identita(11);
        let mut blob = export_veloce(&id, b"kr", b"pass", 8);
        // 4 GiB memory cost: not a cryptographic attack, a way to kill the
        // process of whoever opens the file.
        blob[1 + SALT_LEN..1 + SALT_LEN + 4].copy_from_slice(&4_194_304u32.to_be_bytes());
        assert!(matches!(import(&blob, b"pass"), Err(Error::Format(_))));
    }

    #[test]
    fn troncato() {
        let id = identita(13);
        let blob = export_veloce(&id, b"kr", b"pass", 10);
        for taglio in [0, 1, HEADER_LEN, HEADER_LEN + NONCE_LEN] {
            assert!(import(&blob[..taglio], b"pass").is_err());
        }
    }

    #[test]
    fn portachiavi_vuoto() {
        // Common case: exporting before ever talking to anyone.
        let id = identita(15);
        let blob = export_veloce(&id, b"", b"pass", 12);
        let aperto = apri(&blob, b"pass");
        assert!(aperto.keyring.is_empty());
        assert_eq!(aperto.secret.as_ref(), id.secret_bytes().as_ref());
    }

    #[test]
    fn export_vero_usa_i_parametri_veri() {
        // One test with production parameters: checks that the chosen cost is
        // sustainable and that the full round trip works.
        let mut rng = ChaCha20Rng::from_seed([21; 32]);
        let id = identita(17);
        let blob = export(&id, b"portachiavi", b"una passphrase lunga", &mut rng).unwrap();
        assert_eq!(blob[0], VERSION);
        assert_eq!(be_u32(&blob, 1 + SALT_LEN).unwrap(), M_COST);
        let aperto = apri(&blob, b"una passphrase lunga");
        assert_eq!(aperto.secret.as_ref(), id.secret_bytes().as_ref());
        assert_eq!(aperto.keyring.as_slice(), b"portachiavi");
    }

    #[test]
    fn due_export_dello_stesso_segreto_sono_diversi() {
        // Salt and nonce are random: two backups of the same identity must not
        // be comparable.
        let id = identita(19);
        let a = export_veloce(&id, b"kr", b"pass", 30);
        let b = export_veloce(&id, b"kr", b"pass", 31);
        assert_ne!(a, b);
    }


}
