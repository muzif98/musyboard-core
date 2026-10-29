//! In-memory keyring, with serialisation for persistence on the Java side.
//!
//! The core works against the [`Keyring`] trait; real storage is outside. Here
//! the keyring lives in memory and is exported/imported as `byte[]`: the JVM
//! encrypts it with an Android Keystore key and writes it to disk.
//!
//! Why not call into Java on every access: those would be JNI upcalls inside
//! the decryption path, with the JVM able to throw in the middle of a crypto
//! operation. Better one block, loaded at start and saved again when it
//! changes.
//!
//! This blob's format is NOT the wire format: it is local storage and may
//! change between app versions without breaking anything.

use zeroize::Zeroizing;
use keyboard_cipher_core::error::{Error, Result};
use keyboard_cipher_core::keys::{PrekeyRecord, 
    Fingerprint, Keyring, LabelOutcome, PeerRecord, PinOutcome, PrekeyStore, PublicKey, KEY_LEN,
    MAX_PREKEY_MIE,
};

/// Storage version written. Version 2 added the forward secrecy chain at the
/// end of each record; 3 and 4 append further fields.
///
/// **The latest is written and every older one is read.** Someone updating the
/// app has an older keyring on disk: rejecting it would wipe everyone's
/// contacts and re-pin every key at the next message, i.e. silently accept any
/// MITM, which is exactly what the error on corrupted blobs exists to prevent.
const STORAGE_VERSION: u8 = 4;
const STORAGE_VERSION_SENZA_CATENA: u8 = 1;
/// Version 3 had our epoch but not the PEER's, which was still mixed with the
/// rotating prekey (see `PrekeyStore::epoche_loro`), and lacked the two dates
/// that prevent going backwards. Still read: that state restarts without the
/// peer's epoch and dates, and the core's fallbacks recover it.
const STORAGE_VERSION_SENZA_EPOCA_LORO: u8 = 3;
/// Version 2 had the chain but no epoch: the epoch lived INSIDE the chain, the
/// bug version 3 fixes. Still read; that state restarts without an epoch and
/// the fallback in `api.rs` finds it among old prekeys.
const STORAGE_VERSION_SENZA_EPOCA: u8 = 2;
/// pubkey + first_seen(i64) + verified(u8) + label length(u16)
const RECORD_LEN: usize = KEY_LEN + 8 + 1 + 2;
/// A label is a name chosen by the user, not a free network field.
const MAX_LABEL_LEN: usize = 256;

#[derive(Default)]
pub struct MemoryKeyring {
    peers: Vec<PeerRecord>,
    /// Holds temporary PRIVATE keys. The JVM encrypts this blob with an Android
    /// Keystore key before it touches the disk, the same protection as the
    /// identity, and it is needed: while these keys exist, the messages that
    /// used them can be reopened.
    prekey: PrekeyStore,
}

impl MemoryKeyring {
    pub fn new() -> Self {
        Self::default()
    }

    /// Serialises for persistence on the Java side. **Contains private keys**:
    /// see [`Self::export_pubblico`] for the variant to give to code that only
    /// shows names.
    pub fn export(&self) -> Vec<u8> {
        let mut out = self.scrivi_peers();
        self.scrivi_catena(&mut out);
        out
    }

    /// The contact list only: public key, date, verified flag, label.
    ///
    /// Exists because the contacts screen does not need the prekeys, which are
    /// PRIVATE keys; serving it the persistence blob would copy them into a
    /// JVM `byte[]` that nobody zeroizes.
    ///
    /// Backward compatible by construction: the Java reader (`PeerList`) reads
    /// up to the last peer and **ignores the tail**. Here the tail is simply
    /// absent. The version stays `STORAGE_VERSION`: this is not a different
    /// format, it is the same one truncated.
    pub fn export_pubblico(&self) -> Vec<u8> {
        self.scrivi_peers()
    }

    fn scrivi_peers(&self) -> Vec<u8> {
        let capacity = self
            .peers
            .len()
            .saturating_mul(RECORD_LEN)
            .saturating_add(5);
        let mut out = Vec::with_capacity(capacity);
        out.push(STORAGE_VERSION);
        let count = u32::try_from(self.peers.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count.to_le_bytes());
        for record in &self.peers {
            out.extend_from_slice(record.public.as_bytes());
            out.extend_from_slice(&record.first_seen_unix.to_le_bytes());
            out.push(u8::from(record.verified));
            let etichetta = record.label.as_deref().unwrap_or("").as_bytes();
            let len = u16::try_from(etichetta.len()).unwrap_or(0);
            out.extend_from_slice(&len.to_le_bytes());
            if len != 0 {
                out.extend_from_slice(etichetta);
            }
        }
        out
    }

    fn scrivi_catena(&self, out: &mut Vec<u8>) {
        let catena = self.prekey.dump();
        let quante = u32::try_from(catena.len()).unwrap_or(0);
        out.extend_from_slice(&quante.to_le_bytes());
        for record in catena.iter().take(quante as usize) {
            let chi = &record.peer;
            let loro = &record.sua_prekey;
            let mie = &record.mie;
            let epoca = &record.mia_epoca;
            out.extend_from_slice(chi.as_bytes());
            match loro {
                Some(k) => {
                    out.push(1);
                    out.extend_from_slice(k.as_bytes());
                }
                // A contact we wrote to first has no key of theirs yet.
                None => out.push(0),
            }
            let quante_mie = u8::try_from(mie.len()).unwrap_or(0);
            out.push(quante_mie);
            for segreto in mie.iter().take(usize::from(quante_mie)) {
                out.extend_from_slice(&**segreto);
            }
            // The epoch at the end of the record, with its presence byte: a
            // contact can have it without prekeys and vice versa.
            match epoca {
                Some(k) => {
                    out.push(1);
                    out.extend_from_slice(&**k);
                }
                None => out.push(0),
            }
            // Since version 4: the PEER's epoch and the two dates, appended at
            // the end of the record like every earlier addition.
            match &record.sua_epoca {
                Some(k) => {
                    out.push(1);
                    out.extend_from_slice(k.as_bytes());
                }
                None => out.push(0),
            }
            out.extend_from_slice(&record.visto_a.to_le_bytes());
            out.extend_from_slice(&record.rogo_a.to_le_bytes());
        }
    }

    /// Rebuilds from a blob produced by [`Self::export`].
    ///
    /// A corrupted blob is an error, not a silent loss: if the keyring does not
    /// load, the user must know. Silently starting from scratch would re-pin
    /// every key at the next message, i.e. accept any MITM without asking.
    pub fn import(bytes: &[u8]) -> Result<Self> {
        let mut cursor = bytes.iter().copied();
        let version = cursor.next().ok_or(Error::Keyring)?;
        if version != STORAGE_VERSION
            && version != STORAGE_VERSION_SENZA_EPOCA_LORO
            && version != STORAGE_VERSION_SENZA_EPOCA
            && version != STORAGE_VERSION_SENZA_CATENA
        {
            return Err(Error::Keyring);
        }

        let mut count_bytes = [0u8; 4];
        for slot in count_bytes.iter_mut() {
            *slot = cursor.next().ok_or(Error::Keyring)?;
        }
        let count = usize::try_from(u32::from_le_bytes(count_bytes)).map_err(|_| Error::Keyring)?;

        let mut peers = Vec::with_capacity(count.min(1024));
        for _ in 0..count {
            let mut key = [0u8; KEY_LEN];
            for slot in key.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let mut seen = [0u8; 8];
            for slot in seen.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let verified = cursor.next().ok_or(Error::Keyring)?;

            let mut len_bytes = [0u8; 2];
            for slot in len_bytes.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let len = usize::from(u16::from_le_bytes(len_bytes));
            if len > MAX_LABEL_LEN {
                return Err(Error::Keyring);
            }
            let mut etichetta = Vec::with_capacity(len);
            for _ in 0..len {
                etichetta.push(cursor.next().ok_or(Error::Keyring)?);
            }
            // A label that is not valid UTF-8 is corrupted storage, not an odd
            // name: better reject than show replacement characters instead of a
            // contact's name.
            let label = if len == 0 {
                None
            } else {
                Some(String::from_utf8(etichetta).map_err(|_| Error::Keyring)?)
            };

            peers.push(PeerRecord {
                public: PublicKey::from_bytes(key),
                label,
                first_seen_unix: i64::from_le_bytes(seen),
                verified: verified != 0,
            });
        }
        let mut prekey = PrekeyStore::default();
        if version == STORAGE_VERSION
            || version == STORAGE_VERSION_SENZA_EPOCA_LORO
            || version == STORAGE_VERSION_SENZA_EPOCA
        {
            let mut quante_bytes = [0u8; 4];
            for slot in quante_bytes.iter_mut() {
                *slot = cursor.next().ok_or(Error::Keyring)?;
            }
            let quante =
                usize::try_from(u32::from_le_bytes(quante_bytes)).map_err(|_| Error::Keyring)?;
            for _ in 0..quante {
                let chi = PublicKey::from_bytes(prendi_chiave(&mut cursor)?);
                let loro = match cursor.next().ok_or(Error::Keyring)? {
                    0 => None,
                    1 => Some(PublicKey::from_bytes(prendi_chiave(&mut cursor)?)),
                    _ => return Err(Error::Keyring),
                };
                let quante_mie = usize::from(cursor.next().ok_or(Error::Keyring)?);
                if quante_mie > MAX_PREKEY_MIE {
                    return Err(Error::Keyring);
                }
                let mut mie = Vec::with_capacity(quante_mie);
                for _ in 0..quante_mie {
                    mie.push(Zeroizing::new(prendi_chiave(&mut cursor)?));
                }
                // Only from version 3: in version 2 the record ended here.
                let epoca = if version != STORAGE_VERSION_SENZA_EPOCA {
                    match cursor.next().ok_or(Error::Keyring)? {
                        0 => None,
                        1 => Some(prendi_chiave(&mut cursor)?),
                        _ => return Err(Error::Keyring),
                    }
                } else {
                    None
                };
                // From version 4: the peer's epoch and dates.
                let (sua_epoca, visto_a, rogo_a) = if version == STORAGE_VERSION {
                    let sua = match cursor.next().ok_or(Error::Keyring)? {
                        0 => None,
                        1 => Some(PublicKey::from_bytes(prendi_chiave(&mut cursor)?)),
                        _ => return Err(Error::Keyring),
                    };
                    (sua, prendi_i64(&mut cursor)?, prendi_i64(&mut cursor)?)
                } else {
                    (None, i64::MIN, i64::MIN)
                };
                prekey.restore(PrekeyRecord {
                    peer: chi,
                    sua_prekey: loro,
                    mie,
                    mia_epoca: epoca.map(Zeroizing::new),
                    sua_epoca,
                    visto_a,
                    rogo_a,
                });
            }
        }
        if cursor.next().is_some() {
            return Err(Error::Keyring);
        }
        Ok(Self { peers, prekey })
    }

    #[cfg(test)]
    fn catena(&self) -> &PrekeyStore {
        &self.prekey
    }

    fn find(&self, peer: &PublicKey) -> Option<&PeerRecord> {
        self.peers.iter().find(|record| &record.public == peer)
    }
}

impl Keyring for MemoryKeyring {
    fn peers(&self) -> Result<Vec<PublicKey>> {
        Ok(self.peers.iter().map(|p| p.public.clone()).collect())
    }

    fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
        // `retain` rather than `position` + `remove`: the latter removed only
        // **the first** match, and if the same key appeared twice the contact
        // would come back after the user deleted it. Duplicates should not
        // exist, but the list may come from an imported blob (a backup, a file)
        // this code did not build. A promise like "forget this contact" must be
        // kept here.
        let prima = self.peers.len();
        self.peers.retain(|p| &p.public != peer);
        if self.peers.len() == prima {
            return Ok(false);
        }
        // The temporary keys too: keeping them after the user deleted the
        // contact would be the opposite of what they asked.
        self.prekey.forget(peer);
        Ok(true)
    }

    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome> {
        if self.find(peer).is_some() {
            return Ok(PinOutcome::AlreadyPinned);
        }
        self.peers.push(PeerRecord {
            public: peer.clone(),
            label: None,
            first_seen_unix: now_unix,
            verified: false,
        });
        Ok(PinOutcome::Pinned)
    }

    fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome> {
        if label.is_empty() || label.len() > MAX_LABEL_LEN {
            return Err(Error::Format("etichetta vuota o troppo lunga"));
        }
        if let Some(altro) = self
            .peers
            .iter()
            .find(|record| record.label.as_deref() == Some(label) && &record.public != peer)
        {
            return Ok(LabelOutcome::Conflict {
                existing: altro.public.clone(),
                existing_fingerprint: Fingerprint::of(&altro.public),
                incoming_fingerprint: Fingerprint::of(peer),
            });
        }
        match self
            .peers
            .iter_mut()
            .find(|record| &record.public == peer)
        {
            Some(record) => {
                record.label = Some(label.to_owned());
                Ok(LabelOutcome::Assigned)
            }
            None => Err(Error::UnknownPeer),
        }
    }

    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()> {
        let etichetta = self
            .find(old)
            .and_then(|record| record.label.clone());
        self.peers.retain(|record| &record.public != old);
        self.peers.retain(|record| &record.public != new);
        self.peers.push(PeerRecord {
            public: new.clone(),
            label: etichetta,
            first_seen_unix: now_unix,
            // A new key has not been verified out of band.
            verified: false,
        });
        Ok(())
    }

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>> {
        Ok(self.find(peer).cloned())
    }

    fn peer_prekey(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
        Ok(self.prekey.peer_prekey(peer))
    }

    fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) -> Result<()> {
        self.prekey.set_peer_prekey(peer, prekey);
        Ok(())
    }

    fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<Zeroizing<[u8; KEY_LEN]>>> {
        Ok(self.prekey.my_prekeys(peer))
    }

    fn my_epoch(&self, peer: &PublicKey) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        Ok(self.prekey.my_epoch(peer))
    }

    fn peer_epoch(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
        Ok(self.prekey.peer_epoch(peer))
    }

    fn set_peer_epoch(&mut self, peer: &PublicKey, epoca: &PublicKey) -> Result<()> {
        self.prekey.set_peer_epoch(peer, epoca);
        Ok(())
    }

    fn seen_at(&self, peer: &PublicKey) -> Result<i64> {
        Ok(self.prekey.seen_at(peer))
    }

    fn set_seen_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()> {
        self.prekey.set_seen_at(peer, quando);
        Ok(())
    }

    fn burned_at(&self, peer: &PublicKey) -> Result<i64> {
        Ok(self.prekey.burned_at(peer))
    }

    fn set_burned_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()> {
        self.prekey.set_burned_at(peer, quando);
        Ok(())
    }

    fn forget_my_prekey(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) -> Result<()> {
        self.prekey.forget_my_prekey(peer, secret);
        Ok(())
    }

    fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.set_my_epoch(peer, secret);
        Ok(())
    }

    fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.push_my_prekey(peer, secret);
        Ok(())
    }

    fn drop_my_prekeys_older_than(
        &mut self,
        peer: &PublicKey,
        secret: &[u8; KEY_LEN],
    ) -> Result<()> {
        self.prekey.drop_my_prekeys_older_than(peer, secret);
        Ok(())
    }

    fn burn_conversation(&mut self, peer: &PublicKey) -> Result<()> {
        self.prekey.burn(peer);
        Ok(())
    }

    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        match self
            .peers
            .iter_mut()
            .find(|record| &record.public == peer)
        {
            Some(record) => {
                record.verified = true;
                Ok(())
            }
            None => Err(Error::UnknownPeer),
        }
    }
}

/// Eight bytes, little endian. Like [`prendi_chiave`]: if they run out, the file
/// is truncated and that is reported, rather than reading zeros.
fn prendi_i64(cursor: &mut impl Iterator<Item = u8>) -> Result<i64> {
    let mut bytes = [0u8; 8];
    for slot in bytes.iter_mut() {
        *slot = cursor.next().ok_or(Error::Keyring)?;
    }
    Ok(i64::from_le_bytes(bytes))
}

fn prendi_chiave(cursor: &mut impl Iterator<Item = u8>) -> Result<[u8; KEY_LEN]> {
    let mut chiave = [0u8; KEY_LEN];
    for slot in chiave.iter_mut() {
        *slot = cursor.next().ok_or(Error::Keyring)?;
    }
    Ok(chiave)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    /// Assertions compare bare arrays: `Zeroizing` would only get in the way.
    fn nude(v: Vec<Zeroizing<[u8; KEY_LEN]>>) -> Vec<[u8; KEY_LEN]> {
        v.into_iter().map(|k| *k).collect()
    }

    fn key(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; KEY_LEN])
    }

    /// The contact list for the contacts screen must not include private
    /// prekeys.
    #[test]
    fn elenco_pubblico_non_contiene_prekey() {
        const SEGRETO: [u8; KEY_LEN] = [0xAB; KEY_LEN];
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();
        keyring.push_my_prekey(&key(1), SEGRETO).unwrap();

        let completo = keyring.export();
        let pubblico = keyring.export_pubblico();

        // Precondition: if the secret were not even in the full blob, its
        // absence from the other would prove nothing.
        assert!(
            completo.windows(KEY_LEN).any(|f| f == SEGRETO),
            "il blob di persistenza deve contenere la prekey",
        );
        assert!(
            !pubblico.windows(KEY_LEN).any(|f| f == SEGRETO),
            "la prekey PRIVATA non deve uscire verso la UI",
        );

        // A prefix, not a "similar format": that is what keeps the truncation
        // compatible with the Java reader, which ignores the tail. `get` rather
        // than direct slicing: `clippy --all-targets -D warnings` applies to
        // tests too.
        assert_eq!(
            Some(&pubblico[..]),
            completo.get(..pubblico.len()),
            "il blob pubblico deve essere un prefisso di quello completo",
        );

        // And the list must stay useful: the names are still there.
        assert!(pubblico.windows(5).any(|f| f == b"Marco"));
    }

    /// The epoch survives the round trip to disk, and state written by the
    /// previous version still reads.
    #[test]
    fn l_epoca_sopravvive_al_disco_e_la_2_si_rilegge() {
        const EPOCA: [u8; KEY_LEN] = [0xEE; KEY_LEN];
        const PREKEY: [u8; KEY_LEN] = [0x11; KEY_LEN];
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.push_my_prekey(&key(1), PREKEY).unwrap();
        keyring.set_my_epoch(&key(1), EPOCA).unwrap();
        // The peer's epoch too, otherwise the record would end with just the
        // presence byte and the truncation arithmetic below would test a format
        // that does not exist.
        keyring.set_peer_epoch(&key(1), &key(9)).unwrap();

        let riletto = MemoryKeyring::import(&keyring.export()).unwrap();
        assert_eq!(riletto.my_epoch(&key(1)).unwrap().map(|k| *k), Some(EPOCA));
        assert_eq!(nude(riletto.my_prekeys(&key(1)).unwrap()), vec![PREKEY]);

        // A contact with only an epoch, no prekeys: someone using burnable mode
        // only. Without the dedicated pass in `dump` their state would not reach
        // the disk.
        let mut solo_epoca = MemoryKeyring::new();
        solo_epoca.tofu_pin(&key(2), 100).unwrap();
        solo_epoca.set_my_epoch(&key(2), EPOCA).unwrap();
        let riletto = MemoryKeyring::import(&solo_epoca.export()).unwrap();
        assert_eq!(riletto.my_epoch(&key(2)).unwrap().map(|k| *k), Some(EPOCA));

        // Older versions still read. They are built by removing from the END of
        // the record the fields added later (the only place every version added
        // something) and lowering the version byte. If a field were ever added in
        // the middle, this test would stop building valid blobs and say so.
        let completo = keyring.export();

        // Format 3: without the peer's epoch (1 + 32) and the two dates (8 + 8).
        let coda_v4 = 1 + KEY_LEN + 8 + 8;
        let mut v3 = completo
            .get(..completo.len().saturating_sub(coda_v4))
            .unwrap_or_default()
            .to_vec();
        if let Some(primo) = v3.first_mut() {
            *primo = STORAGE_VERSION_SENZA_EPOCA_LORO;
        }
        let riletto = MemoryKeyring::import(&v3).unwrap();
        assert_eq!(riletto.my_epoch(&key(1)).unwrap().map(|k| *k), Some(EPOCA));
        assert_eq!(riletto.peer_epoch(&key(1)).unwrap(), None);
        assert_eq!(nude(riletto.my_prekeys(&key(1)).unwrap()), vec![PREKEY]);

        // Format 2: also without our epoch (1 + 32).
        let mut v2 = v3
            .get(..v3.len().saturating_sub(1 + KEY_LEN))
            .unwrap_or_default()
            .to_vec();
        if let Some(primo) = v2.first_mut() {
            *primo = STORAGE_VERSION_SENZA_EPOCA;
        }
        let riletto = MemoryKeyring::import(&v2).unwrap();
        assert_eq!(riletto.my_epoch(&key(1)).unwrap().map(|k| *k), None);
        assert_eq!(nude(riletto.my_prekeys(&key(1)).unwrap()), vec![PREKEY]);
    }

    /// The peer's epoch and the two dates survive the round trip to disk.
    #[test]
    fn epoca_del_peer_e_date_sopravvivono_al_disco() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.set_peer_epoch(&key(1), &key(9)).unwrap();
        keyring.set_seen_at(&key(1), 1_700_000_000).unwrap();
        keyring.set_burned_at(&key(1), 1_700_000_500).unwrap();

        let riletto = MemoryKeyring::import(&keyring.export()).unwrap();
        assert_eq!(riletto.peer_epoch(&key(1)).unwrap(), Some(key(9)));
        assert_eq!(riletto.seen_at(&key(1)).unwrap(), 1_700_000_000);
        assert_eq!(riletto.burned_at(&key(1)).unwrap(), 1_700_000_500);
    }

    #[test]
    fn round_trip_vuoto() {
        let vuoto = MemoryKeyring::new();
        let ricostruito = MemoryKeyring::import(&vuoto.export()).unwrap();
        assert!(ricostruito.peers.is_empty());
    }

    #[test]
    fn round_trip_con_peer() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.tofu_pin(&key(2), 200).unwrap();
        keyring.assign_label(&key(2), "Marco è qui ✓").unwrap();
        keyring.mark_verified(&key(2)).unwrap();

        let ricostruito = MemoryKeyring::import(&keyring.export()).unwrap();
        assert_eq!(ricostruito.peers.len(), 2);
        assert!(!ricostruito.get(&key(1)).unwrap().unwrap().verified);
        let secondo = ricostruito.get(&key(2)).unwrap().unwrap();
        assert!(secondo.verified);
        assert_eq!(secondo.first_seen_unix, 200);
        // Non-ASCII UTF-8 must survive the round trip.
        assert_eq!(secondo.label.as_deref(), Some("Marco è qui ✓"));
    }

    /// Someone updating the app has a version 1 keyring on disk. It must still
    /// load: rejecting it would wipe everyone's contacts, and the next message
    /// would re-pin every key without asking.
    #[test]
    fn un_keyring_di_prima_si_carica_ancora() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();

        // A version 1 blob is a version 2 blob without the chain tail.
        let mut vecchio = keyring.export();
        let taglio = vecchio.len().checked_sub(4).unwrap();
        vecchio.truncate(taglio);
        *vecchio.first_mut().unwrap() = 1;

        let riletto = MemoryKeyring::import(&vecchio).unwrap();
        assert_eq!(
            riletto.get(&key(1)).unwrap().unwrap().label.as_deref(),
            Some("Marco")
        );
        assert!(riletto.peer_prekey(&key(1)).unwrap().is_none());
    }

    /// The chain must survive the round trip **in order**: the order decides
    /// which messages in flight remain openable.
    #[test]
    fn la_catena_sopravvive_al_round_trip() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 100).unwrap();
        keyring.tofu_pin(&key(2), 200).unwrap();
        keyring.set_peer_prekey(&key(1), &key(50)).unwrap();
        keyring.push_my_prekey(&key(1), [10; KEY_LEN]).unwrap();
        keyring.push_my_prekey(&key(1), [11; KEY_LEN]).unwrap();
        // A contact we wrote to first: no key of theirs.
        keyring.push_my_prekey(&key(2), [20; KEY_LEN]).unwrap();

        let riletto = MemoryKeyring::import(&keyring.export()).unwrap();
        assert_eq!(riletto.peer_prekey(&key(1)).unwrap(), Some(key(50)));
        assert_eq!(
            nude(riletto.my_prekeys(&key(1)).unwrap()),
            vec![[11; KEY_LEN], [10; KEY_LEN]]
        );
        assert_eq!(riletto.peer_prekey(&key(2)).unwrap(), None);
        assert_eq!(nude(riletto.my_prekeys(&key(2)).unwrap()), vec![[20; KEY_LEN]]);
        assert_eq!(riletto.catena().dump().len(), 2);
    }

    /// Forgetting a contact also removes their temporary keys, which would
    /// otherwise stay in the blob saved to disk.
    #[test]
    fn dimenticare_svuota_anche_la_catena() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.set_peer_prekey(&key(1), &key(50)).unwrap();
        keyring.push_my_prekey(&key(1), [10; KEY_LEN]).unwrap();

        assert!(keyring.forget(&key(1)).unwrap());
        assert!(keyring.catena().dump().is_empty());
        let riletto = MemoryKeyring::import(&keyring.export()).unwrap();
        assert!(nude(riletto.my_prekeys(&key(1)).unwrap()).is_empty());
    }

    /// A corrupted blob must fail, not degrade to an empty keyring.
    #[test]
    fn blob_corrotto_e_un_errore() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.set_peer_prekey(&key(1), &key(50)).unwrap();
        keyring.push_my_prekey(&key(1), [10; KEY_LEN]).unwrap();
        let buono = keyring.export();

        for taglio in 1..buono.len() {
            let corto = buono.get(..taglio).unwrap();
            assert!(
                MemoryKeyring::import(corto).is_err(),
                "troncamento a {taglio} accettato"
            );
        }

        let mut lungo = buono.clone();
        lungo.push(0);
        assert!(MemoryKeyring::import(&lungo).is_err());

        let mut versione_sbagliata = buono;
        if let Some(first) = versione_sbagliata.first_mut() {
            *first = 99;
        }
        assert!(MemoryKeyring::import(&versione_sbagliata).is_err());
    }

    #[test]
    fn niente_panic_su_input_arbitrario() {
        for len in 0..200usize {
            let spazzatura: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(31)) as u8).collect();
            let _ = MemoryKeyring::import(&spazzatura);
        }
    }

    #[test]
    fn etichetta_duplicata_e_un_conflitto() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.tofu_pin(&key(2), 2).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();

        let esito = keyring.assign_label(&key(2), "Marco").unwrap();
        assert!(matches!(esito, LabelOutcome::Conflict { .. }));
        // Nothing changed.
        assert_eq!(
            keyring.get(&key(1)).unwrap().unwrap().label.as_deref(),
            Some("Marco")
        );
        assert!(keyring.get(&key(2)).unwrap().unwrap().label.is_none());
    }

    #[test]
    fn la_conferma_sposta_etichetta_e_azzera_la_verifica() {
        let mut keyring = MemoryKeyring::new();
        keyring.tofu_pin(&key(1), 1).unwrap();
        keyring.assign_label(&key(1), "Marco").unwrap();
        keyring.mark_verified(&key(1)).unwrap();

        keyring.replace_pinned(&key(1), &key(2), 10).unwrap();
        let record = keyring.get(&key(2)).unwrap().unwrap();
        assert_eq!(record.label.as_deref(), Some("Marco"));
        assert!(!record.verified, "la verifica non si eredita");
        assert!(keyring.get(&key(1)).unwrap().is_none());
    }
}
