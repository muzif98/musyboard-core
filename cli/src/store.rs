//! On-disk state: identity and keyring.
//!
//! ## The format is its own
//!
//! It does not match the phone's, and must not. This binary is a **different
//! party**: its own identity, its own contacts, and it exchanges only `kc/…`
//! blobs with Android. The two state files never meet, so aligning them would
//! be work for a compatibility nobody uses.
//!
//! ## The secret is stored in clear
//!
//! On the phone the private key is wrapped by Android Keystore. Here there is
//! nothing equivalent: the file is protected only by Unix permissions (`0600`).
//!
//! A choice, not an oversight: this is a testing tool, and asking for a
//! passphrase on every command would get in the way of exactly that use. The
//! consequence is stated in `--help` too: **this identity is not worth as much
//! as the phone's.** Do not use it for real conversations.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use keyboard_cipher_core::encoding;
use keyboard_cipher_core::keys::{PrekeyRecord, 
    Fingerprint, Identity, Keyring, LabelOutcome, PeerRecord, PinOutcome, PrekeyStore, PublicKey,
    KEY_LEN,
};
use keyboard_cipher_core::{Error, Result};
use zeroize::Zeroizing;

const MAGIC: &str = "keyboard-cipher-cli 1";

/// Where the state lives. `KC_HOME` takes precedence, so several identities can
/// be kept side by side, which is exactly what testing a key conflict needs
/// without deleting one's own.
pub fn state_path() -> PathBuf {
    if let Ok(dir) = std::env::var("KC_HOME") {
        return PathBuf::from(dir).join("state");
    }
    // Windows has neither XDG nor HOME: without this the file would end up in
    // the current directory, i.e. somewhere different depending on where the
    // program is started, and the identity would seem to vanish.
    if let Ok(dir) = std::env::var("APPDATA") {
        return PathBuf::from(dir).join("keyboard-cipher").join("state");
    }
    let base = std::env::var("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            PathBuf::from(std::env::var("HOME").unwrap_or_else(|_| ".".to_owned()))
                .join(".local")
                .join("share")
        });
    base.join("keyboard-cipher").join("state")
}

/// Concrete keyring: an in-memory list, saved by the caller.
///
/// Records keep insertion order and must not be reordered: commands accept the
/// index shown by `kc contacts`, and a list that reorders itself would apply an
/// operation meant for one contact to another.
#[derive(Default)]
pub struct FileKeyring {
    peers: Vec<PeerRecord>,
    /// The forward secrecy chain. The logic is in the core; only the disk round
    /// trip lives here.
    pub(crate) prekey: PrekeyStore,
}

impl FileKeyring {
    pub fn peers(&self) -> &[PeerRecord] {
        &self.peers
    }

    fn position(&self, peer: &PublicKey) -> Option<usize> {
        self.peers.iter().position(|p| &p.public == peer)
    }

    /// See [`Keyring::forget`]. Also a method of its own because the app uses it
    /// without building a `Session`.
    ///
    /// **Consequence to tell whoever does it:** the pin is lost. The next
    /// message from that person appears as an unseen sender and is silently
    /// re-pinned, reopening the attack window the pin was closing, and any
    /// "compared in person" is lost too. Deleting a contact is not like deleting
    /// a line from an address book.
    pub fn remove(&mut self, peer: &PublicKey) -> bool {
        // `retain` rather than `position` + `remove`: the latter removed only
        // **the first** match, and a key present twice would make the contact
        // reappear after deletion. The list comes from a text file on disk, so a
        // duplicate is realistic: one line pasted twice by hand.
        let prima = self.peers.len();
        self.peers.retain(|p| &p.public != peer);
        if self.peers.len() == prima {
            return false;
        }
        // Temporary keys towards them too: keeping them on disk after the user
        // deleted the contact would be the opposite of what they asked.
        self.prekey.forget(peer);
        true
    }
}

impl Keyring for FileKeyring {
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

    fn my_epoch(&self, peer: &PublicKey) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>> {
        Ok(self.prekey.my_epoch(peer))
    }

    fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()> {
        self.prekey.set_my_epoch(peer, secret);
        Ok(())
    }

    fn peers(&self) -> Result<Vec<PublicKey>> {
        Ok(self.peers.iter().map(|p| p.public.clone()).collect())
    }

    fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
        Ok(self.remove(peer))
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

    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome> {
        if self.position(peer).is_some() {
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
        // Look for a conflict BEFORE touching anything: on conflict nothing
        // changes, and the old key keeps the name until explicit confirmation.
        if let Some(other) = self
            .peers
            .iter()
            .find(|p| p.label.as_deref() == Some(label) && &p.public != peer)
        {
            return Ok(LabelOutcome::Conflict {
                existing: other.public.clone(),
                existing_fingerprint: Fingerprint::of(&other.public),
                incoming_fingerprint: Fingerprint::of(peer),
            });
        }
        let index = self.position(peer).ok_or(Error::UnknownPeer)?;
        match self.peers.get_mut(index) {
            Some(record) => {
                record.label = Some(label.to_owned());
                Ok(LabelOutcome::Assigned)
            }
            None => Err(Error::Keyring),
        }
    }

    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()> {
        let old_index = self.position(old).ok_or(Error::UnknownPeer)?;
        let label = match self.peers.get(old_index) {
            Some(record) => record.label.clone(),
            None => return Err(Error::Keyring),
        };
        if let Some(record) = self.peers.get_mut(old_index) {
            record.label = None;
        }
        match self.position(new) {
            Some(index) => {
                if let Some(record) = self.peers.get_mut(index) {
                    record.label = label;
                    // A new key has not been compared out of band, by
                    // definition.
                    record.verified = false;
                }
            }
            None => self.peers.push(PeerRecord {
                public: new.clone(),
                label,
                first_seen_unix: now_unix,
                verified: false,
            }),
        }
        Ok(())
    }

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>> {
        Ok(self.position(peer).and_then(|i| self.peers.get(i)).cloned())
    }

    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        let index = self.position(peer).ok_or(Error::UnknownPeer)?;
        match self.peers.get_mut(index) {
            Some(record) => {
                record.verified = true;
                Ok(())
            }
            None => Err(Error::Keyring),
        }
    }
}

/// All the state: who I am, and whom I know.
///
/// The secret is kept next to the identity because `Identity` does not return
/// it, rightly: a private key that anyone holding the object can read back ends
/// up in a log. Here it is only needed to write it back to disk.
pub struct State {
    pub identity: Identity,
    pub keyring: FileKeyring,
    secret: Zeroizing<[u8; KEY_LEN]>,
}

impl State {
    /// Copy of the secret bytes, to keep before [`Identity`] moves into a
    /// `Session`, which takes ownership.
    pub fn secret_bytes(&self) -> [u8; KEY_LEN] {
        *self.secret
    }

    pub fn create(secret: [u8; KEY_LEN]) -> Result<Self> {
        Ok(Self {
            identity: Identity::from_secret_bytes(secret)?,
            keyring: FileKeyring::default(),
            secret: Zeroizing::new(secret),
        })
    }

    pub fn load(path: &Path) -> io::Result<Option<Self>> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        Ok(parse(&text))
    }

}

/// Writes identity and contacts.
///
/// A free function rather than a method: after an operation the identity and
/// the keyring live inside a `Session`, so there is no `State` left to call a
/// method on. The two parts are passed separately because that is where they
/// are at that point.
pub fn save(path: &Path, secret: &[u8; KEY_LEN], keyring: &FileKeyring) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut out = String::from(MAGIC);
    out.push('\n');
    out.push_str("secret ");
    out.push_str(&encoding::encode(secret));
    out.push('\n');
    for peer in keyring.peers() {
        out.push_str("peer ");
        out.push_str(&encoding::encode(peer.public.as_bytes()));
        out.push(' ');
        out.push_str(&peer.first_seen_unix.to_string());
        out.push(' ');
        out.push(if peer.verified { '1' } else { '0' });
        out.push(' ');
        out.push_str(peer.label.as_deref().unwrap_or(""));
        out.push('\n');
    }
    // `chain` lines come AFTER the `peer` lines, not inside them: an older binary
    // ignores them (the parser skips unknown lines) and keeps working without
    // full forward secrecy, instead of rejecting the file and losing the
    // identity.
    //
    // This is private material in clear, like the identity secret above: same
    // file, same permissions, same caveat.
    for record in keyring.prekey.dump() {
        let chi = &record.peer;
        let loro = &record.sua_prekey;
        let mie = &record.mie;
        let epoca = &record.mia_epoca;
        // Separate lines for the peer's epoch and the two dates, as for ours: an
        // old reader skips unknown lines, while an extra column on a known line
        // would be read as a prekey.
        if let Some(k) = &record.sua_epoca {
            out.push_str("peerepoch ");
            out.push_str(&encoding::encode(chi.as_bytes()));
            out.push(' ');
            out.push_str(&encoding::encode(k.as_bytes()));
            out.push('\n');
        }
        if record.visto_a != i64::MIN || record.rogo_a != i64::MIN {
            out.push_str("seen ");
            out.push_str(&encoding::encode(chi.as_bytes()));
            out.push(' ');
            out.push_str(&record.visto_a.to_string());
            out.push(' ');
            out.push_str(&record.rogo_a.to_string());
            out.push('\n');
        }
        // A separate line, not a column at the end of `chain`: an old reader
        // would read an extra column as a prekey, use the epoch as a chain key
        // and drop it at the first read.
        if let Some(k) = epoca {
            out.push_str("epoch ");
            out.push_str(&encoding::encode(chi.as_bytes()));
            out.push(' ');
            out.push_str(&encoding::encode(&k[..]));
            out.push('\n');
        }
        out.push_str("chain ");
        out.push_str(&encoding::encode(chi.as_bytes()));
        out.push(' ');
        out.push_str(&match loro {
            Some(k) => encoding::encode(k.as_bytes()),
            // A contact we wrote to first has no key of theirs yet: the dash
            // keeps the column position.
            None => "-".to_owned(),
        });
        for segreto in mie.iter() {
            out.push(' ');
            out.push_str(&encoding::encode(&**segreto));
        }
        out.push('\n');
    }
    // Atomic write: a state file truncated halfway is a lost identity, and there
    // is no backup behind it.
    let tmp = path.with_extension("tmp");
    fs::write(&tmp, out)?;
    restrict(&tmp)?;
    fs::rename(&tmp, path)?;
    restrict(path)
}

/// Owner only. Contains a private key in clear.
#[cfg(unix)]
fn restrict(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// An unreadable file becomes `None`, i.e. "no identity".
///
/// Looks permissive and is not: callers never regenerate on their own (see
/// `main`). A local failure must not become indistinguishable from an attack.
fn chiave(testo: &str) -> Option<PublicKey> {
    let bytes = encoding::decode(testo).ok()?;
    let bytes: [u8; KEY_LEN] = bytes.as_slice().try_into().ok()?;
    Some(PublicKey::from_bytes(bytes))
}

fn segreto_da(testo: &str) -> Option<[u8; KEY_LEN]> {
    let bytes = encoding::decode(testo).ok()?;
    bytes.as_slice().try_into().ok()
}

fn parse(text: &str) -> Option<State> {
    let mut lines = text.lines();
    if lines.next()? != MAGIC {
        return None;
    }
    let mut secret: Option<[u8; KEY_LEN]> = None;
    let mut keyring = FileKeyring::default();
    for line in lines {
        let mut parts = line.splitn(2, ' ');
        match (parts.next(), parts.next()) {
            (Some("secret"), Some(rest)) => {
                let bytes = encoding::decode(rest.trim()).ok()?;
                secret = Some(bytes.as_slice().try_into().ok()?);
            }
            (Some("peer"), Some(rest)) => {
                let mut fields = rest.splitn(4, ' ');
                let public = encoding::decode(fields.next()?).ok()?;
                let public: [u8; KEY_LEN] = public.as_slice().try_into().ok()?;
                let first_seen_unix = fields.next()?.parse().ok()?;
                let verified = fields.next()? == "1";
                let label = fields.next().unwrap_or("").trim();
                keyring.peers.push(PeerRecord {
                    public: PublicKey::from_bytes(public),
                    label: if label.is_empty() {
                        None
                    } else {
                        Some(label.to_owned())
                    },
                    first_seen_unix,
                    verified,
                });
            }
            // A broken line here costs that contact's chain, not the identity: no
            // `?`, which would leave `parse` with `None` and lose everything. At
            // worst the next message to that person restarts at half forward
            // secrecy, as on first contact.
            (Some("chain"), Some(rest)) => {
                let mut campi = rest.split(' ');
                if let Some(chi) = campi.next().and_then(chiave) {
                    let loro = match campi.next() {
                        Some("-") | None => None,
                        Some(testo) => chiave(testo),
                    };
                    let mie: Vec<[u8; KEY_LEN]> = campi.filter_map(segreto_da).collect();
                    // The epoch comes from its own line, which may come before or
                    // after this one: not touched here.
                    keyring.prekey.restore(PrekeyRecord {
                        peer: chi,
                        sua_prekey: loro,
                        mie: mie.into_iter().map(Zeroizing::new).collect(),
                        // The other lines arrive separately, before or after this
                        // one: not touched here.
                        mia_epoca: None,
                        sua_epoca: None,
                        visto_a: i64::MIN,
                        rogo_a: i64::MIN,
                    });
                }
            }
            // Line introduced when the epoch stopped living inside the chain.
            // Older state does not have it and restarts without; the core's
            // fallback finds it among old prekeys.
            (Some("epoch"), Some(rest)) => {
                let mut campi = rest.split(' ');
                if let (Some(chi), Some(k)) = (
                    campi.next().and_then(chiave),
                    campi.next().and_then(segreto_da),
                ) {
                    keyring.prekey.set_my_epoch(&chi, k);
                }
            }
            // The PEER's epoch: its own line, added when it stopped living in the
            // rotating prekey. Older state does not have it, and the core's
            // fallback finds it in the prekey.
            (Some("peerepoch"), Some(rest)) => {
                let mut campi = rest.split(' ');
                if let (Some(chi), Some(k)) = (
                    campi.next().and_then(chiave),
                    campi.next().and_then(chiave),
                ) {
                    keyring.prekey.set_peer_epoch(&chi, &k);
                }
            }
            // The two dates that prevent going backwards: the last material
            // accepted from them and the last burn honoured.
            (Some("seen"), Some(rest)) => {
                let mut campi = rest.split(' ');
                if let Some(chi) = campi.next().and_then(chiave) {
                    if let Some(q) = campi.next().and_then(|s| s.parse::<i64>().ok()) {
                        if q != i64::MIN {
                            keyring.prekey.set_seen_at(&chi, q);
                        }
                    }
                    if let Some(q) = campi.next().and_then(|s| s.parse::<i64>().ok()) {
                        if q != i64::MIN {
                            keyring.prekey.set_burned_at(&chi, q);
                        }
                    }
                }
            }
            _ => {}
        }
    }
    let secret = secret?;
    Some(State {
        identity: Identity::from_secret_bytes(secret).ok()?,
        keyring,
        secret: Zeroizing::new(secret),
    })
}

#[cfg(test)]
// The bans apply to production code: in a test, a panic is how failure is
// reported.
#[allow(clippy::unwrap_used, clippy::panic, clippy::indexing_slicing)]
mod tests {
    use super::*;

    /// Assertions compare bare arrays: `Zeroizing` would only get in the way.
    fn nude(v: Vec<Zeroizing<[u8; KEY_LEN]>>) -> Vec<[u8; KEY_LEN]> {
        v.into_iter().map(|k| *k).collect()
    }

    fn secret() -> [u8; KEY_LEN] {
        [7u8; KEY_LEN]
    }

    fn peer(n: u8) -> PublicKey {
        PublicKey::from_bytes([n; KEY_LEN])
    }

    #[test]
    fn round_trip_con_contatti() {
        let dir = std::env::temp_dir().join(format!("kc-test-{}", std::process::id()));
        let path = dir.join("state");
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 111).unwrap();
        keyring.tofu_pin(&peer(2), 222).unwrap();
        keyring.assign_label(&peer(1), "nome con spazi").unwrap();
        keyring.mark_verified(&peer(2)).unwrap();

        save(&path, &secret(), &keyring).unwrap();
        let loaded = State::load(&path).unwrap().unwrap();

        assert_eq!(loaded.secret_bytes(), secret());
        let peers = loaded.keyring.peers();
        assert_eq!(peers.len(), 2);
        // The label may contain spaces: it is the last field of the line on
        // purpose, and a format that split it would rename contacts.
        assert_eq!(peers[0].label.as_deref(), Some("nome con spazi"));
        assert_eq!(peers[0].first_seen_unix, 111);
        assert!(!peers[0].verified);
        assert_eq!(peers[1].label, None);
        assert!(peers[1].verified);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A restart must not kill messages in flight: temporary keys must survive
    /// the round trip to disk, **in order**.
    #[test]
    fn la_catena_sopravvive_al_riavvio() {
        let dir = std::env::temp_dir().join(format!("kc-chain-{}", std::process::id()));
        let path = dir.join("state");
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 111).unwrap();
        keyring.tofu_pin(&peer(2), 222).unwrap();
        keyring.set_peer_prekey(&peer(1), &peer(50)).unwrap();
        keyring.push_my_prekey(&peer(1), [10; KEY_LEN]).unwrap();
        keyring.push_my_prekey(&peer(1), [11; KEY_LEN]).unwrap();
        // A contact we wrote to first: no key of theirs.
        keyring.push_my_prekey(&peer(2), [20; KEY_LEN]).unwrap();

        save(&path, &secret(), &keyring).unwrap();
        let loaded = State::load(&path).unwrap().unwrap();

        assert_eq!(loaded.keyring.peer_prekey(&peer(1)).unwrap(), Some(peer(50)));
        assert_eq!(
            nude(loaded.keyring.my_prekeys(&peer(1)).unwrap()),
            vec![[11; KEY_LEN], [10; KEY_LEN]]
        );
        assert_eq!(loaded.keyring.peer_prekey(&peer(2)).unwrap(), None);
        assert_eq!(
            nude(loaded.keyring.my_prekeys(&peer(2)).unwrap()),
            vec![[20; KEY_LEN]]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An unreadable `chain` line costs that contact's chain, not the identity:
    /// the file still loads.
    #[test]
    fn una_catena_corrotta_non_fa_sparire_l_identita() {
        let testo = format!(
            "{MAGIC}\nsecret {}\nchain ??? -\n",
            encoding::encode(&secret())
        );
        let stato = parse(&testo).unwrap();
        assert_eq!(stato.secret_bytes(), secret());
    }

    #[test]
    fn file_estraneo_non_e_uno_stato() {
        assert!(parse("tutt'altro\nsecret aaaa\n").is_none());
    }

    /// No secret, no identity, and half a state is worse than none: loading it
    /// would give a valid keyring attached to a key that does not exist.
    #[test]
    fn stato_senza_segreto_non_si_carica() {
        assert!(parse(&format!("{MAGIC}\npeer ybnd 1 0 tizio\n")).is_none());
    }

    #[test]
    fn dimenticare_un_contatto_lo_toglie_e_lascia_gli_altri() {
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 1).unwrap();
        keyring.tofu_pin(&peer(2), 2).unwrap();
        keyring.assign_label(&peer(2), "marco").unwrap();

        assert!(keyring.remove(&peer(1)));
        // Twice is not an error: the second time only says it was not there.
        assert!(!keyring.remove(&peer(1)));
        assert_eq!(keyring.peers().len(), 1);
        assert_eq!(keyring.peers()[0].label.as_deref(), Some("marco"));
    }

    #[test]
    fn etichetta_gia_in_uso_e_un_conflitto_e_non_cambia_niente() {
        let mut keyring = FileKeyring::default();
        keyring.tofu_pin(&peer(1), 1).unwrap();
        keyring.tofu_pin(&peer(2), 2).unwrap();
        keyring.assign_label(&peer(1), "marco").unwrap();

        match keyring.assign_label(&peer(2), "marco").unwrap() {
            LabelOutcome::Conflict { existing, .. } => assert_eq!(existing, peer(1)),
            LabelOutcome::Assigned => panic!("doveva essere un conflitto"),
        }
        // The point of the conflict: the old key keeps the name.
        assert_eq!(keyring.peers()[0].label.as_deref(), Some("marco"));
        assert_eq!(keyring.peers()[1].label, None);
    }
}
