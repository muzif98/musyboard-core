//! Identity, keys, TOFU keyring.

use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as XPublicKey, StaticSecret};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};

/// Length of an X25519 key, public or private.
pub const KEY_LEN: usize = 32;

/// X25519 public key. Safe to show and serialise.
///
/// Opaque wrapper over the raw 32 bytes: the crypto crate's type does not leak
/// into the public API, so replacing the crate is not a breaking change.
///
/// There is deliberately no validation here: X25519 accepts any 32 bytes. The
/// check that matters is on the RESULT of the exchange: a low-order public key
/// yields an all-zero shared secret, the same for everyone. It is rejected
/// after the Diffie-Hellman, not here.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey([u8; KEY_LEN]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; KEY_LEN] {
        &self.0
    }
}

/// X25519 private key. Never `Debug`/`Display`/`Serialize`: the absence of
/// those impls is deliberate. `StaticSecret` zeroizes itself on drop.
///
/// At rest it is stored encrypted; the storage key lives in Android Keystore,
/// outside this crate.
pub struct SecretKey(StaticSecret);

/// Our identity: the long-term key pair. One only, valid for every recipient;
/// there is no per-contact key.
pub struct Identity {
    secret: SecretKey,
    public: PublicKey,
}

impl Identity {
    /// Generates a new identity from the given RNG.
    ///
    /// The RNG is a parameter, not a global, so tests are deterministic and
    /// vectors reproducible. In production the caller passes the OS CSPRNG;
    /// never an in-app seeded PRNG.
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Result<Self> {
        let secret = StaticSecret::random_from_rng(rng);
        Ok(Self::from_static_secret(secret))
    }

    /// Rebuilds an identity from persisted key material.
    pub fn from_secret_bytes(bytes: [u8; KEY_LEN]) -> Result<Self> {
        Ok(Self::from_static_secret(StaticSecret::from(bytes)))
    }

    fn from_static_secret(secret: StaticSecret) -> Self {
        let public = PublicKey::from_bytes(XPublicKey::from(&secret).to_bytes());
        Self {
            secret: SecretKey(secret),
            public,
        }
    }

    /// The raw secret bytes, for the encrypted backup **only**.
    ///
    /// `pub(crate)`, not `pub`: outside this crate there is no way to extract
    /// the private key from an `Identity`. Whoever persists it received it at
    /// generation time; from then on it never leaves.
    ///
    /// The only caller is [`crate::backup`], which encrypts it with a
    /// passphrase before it touches anything else.
    pub(crate) fn secret_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.secret.0.to_bytes())
    }

    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint::of(&self.public)
    }

    /// X25519 shared secret with `peer`.
    ///
    /// Crate-internal: the crypto crate's type must not appear in the public
    /// API, and the check below must not be skippable by a caller doing its
    /// own DH.
    ///
    /// REJECTS low-order points. A low-order public key yields an all-zero
    /// shared secret, identical for ANYONE who uses it: whoever sends it as
    /// `sender_pub` gets an AEAD key that anybody can derive. X25519 does not
    /// prevent this by itself, so the check is made on the result, and this is
    /// the only place it can live.
    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.secret.0.diffie_hellman(&XPublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return Err(Error::Crypto);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// Ephemeral key pair: lives for the time it takes to encrypt one message,
/// then disappears.
///
/// The secret never leaves this type and is zeroized on drop. That is what
/// makes the message unreadable even to someone who later obtains the
/// sender's stable key.
pub struct Ephemeral {
    secret: SecretKey,
    public: PublicKey,
}

impl Ephemeral {
    pub fn generate<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut bytes = [0u8; KEY_LEN];
        rng.fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        // The seed is no longer needed: `StaticSecret` made its own copy.
        bytes.zeroize();
        let public = PublicKey(XPublicKey::from(&secret).to_bytes());
        Ok(Self {
            secret: SecretKey(secret),
            public,
        })
    }

    pub fn public(&self) -> PublicKey {
        self.public.clone()
    }

    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.secret.0.diffie_hellman(&XPublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return Err(Error::Crypto);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// The private part of a temporary key, kept for as long as it is needed.
///
/// Separate from [`Ephemeral`] because the two uses are opposite: the sender's
/// ephemeral key is dropped **immediately**, while the recipient keeps this one
/// until reading, and drops it once read. That act produces forward secrecy.
pub struct EphemeralSecret(SecretKey);

impl EphemeralSecret {
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self(SecretKey(StaticSecret::from(bytes)))
    }

    pub fn public(&self) -> PublicKey {
        PublicKey(XPublicKey::from(&self.0 .0).to_bytes())
    }

    /// The bytes, so that the key can be **persisted**. This is the only place
    /// where a private key leaves the crate, and only for temporary keys: the
    /// identity key has nothing similar, on purpose.
    pub fn to_bytes(&self) -> Zeroizing<[u8; KEY_LEN]> {
        Zeroizing::new(self.0 .0.to_bytes())
    }

    pub(crate) fn diffie_hellman(&self, peer: &PublicKey) -> Result<Zeroizing<[u8; KEY_LEN]>> {
        let shared = self.0 .0.diffie_hellman(&XPublicKey::from(*peer.as_bytes()));
        if !shared.was_contributory() {
            return Err(Error::Crypto);
        }
        Ok(Zeroizing::new(shared.to_bytes()))
    }
}

/// Domain separation for the fingerprint. Frozen.
const FINGERPRINT_DOMAIN: &[u8] = b"keyboard-cipher/v1/fingerprint";

/// 120 bits, i.e. 24 z-base-32 characters in 6 groups of 4.
pub const FINGERPRINT_LEN: usize = 15;

/// Stable fingerprint of a public key, for manual out-of-band verification.
///
/// Domain-separated SHA-256, truncated to 120 bits, rendered in z-base-32 in
/// groups of 4. **Frozen**: it is what two people read aloud or compare on
/// screen, and changing it would invalidate every verification already done.
///
/// 120 rather than 96 bits: second-preimage resistance (the binding property)
/// is already ample at 96, but collision resistance is half the length, and 48
/// bits are within reach of GPUs. No flow depends on collisions today, since
/// pinning stores the full key, but the format is permanent. See `DESIGN.md`,
/// decision D.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Fingerprint([u8; FINGERPRINT_LEN]);

impl Fingerprint {
    pub fn of(public: &PublicKey) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(FINGERPRINT_DOMAIN);
        hasher.update(public.as_bytes());
        let digest = hasher.finalize();

        let mut out = [0u8; FINGERPRINT_LEN];
        // SHA-256 yields 32 bytes and FINGERPRINT_LEN is 15: the slice exists.
        if let Some(head) = digest.get(..FINGERPRINT_LEN) {
            out.copy_from_slice(head);
        }
        Self(out)
    }

    /// Display form: 24 characters in 6 groups of 4. The groups make visual
    /// comparison possible.
    pub fn display(&self) -> String {
        let encoded = crate::encoding::encode(&self.0);
        let mut out = String::with_capacity(encoded.len().saturating_add(5));
        for (i, c) in encoded.chars().enumerate() {
            if i != 0 && i.checked_rem(4) == Some(0) {
                out.push(' ');
            }
            out.push(c);
        }
        out
    }
}

/// TOFU record for a peer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PeerRecord {
    pub public: PublicKey,
    /// Name given by the user. **This is the contact identity**: without it,
    /// two different keys are just two different peers and "Mark's key
    /// changed" cannot be expressed.
    ///
    /// `None` until the user decides: the system cannot know who an unseen key
    /// belongs to.
    pub label: Option<String>,
    /// For audit and UX only. No security role.
    pub first_seen_unix: i64,
    /// `true` if the user compared the fingerprint out of band.
    pub verified: bool,
}

/// Outcome of a pin attempt.
///
/// There is deliberately no conflict case: when an unseen key arrives, the
/// system cannot know whether it is a new contact or a known one with a new
/// phone. Only the user knows. Conflicts therefore live in [`LabelOutcome`],
/// when the user assigns a name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PinOutcome {
    /// Never seen before: pinned now, without a label.
    Pinned,
    /// Already present with the same key: nothing to do.
    AlreadyPinned,
}

/// Outcome of assigning a label to a key.
///
/// A conflict is NOT an `Err`: it is a legitimate state that needs a user
/// decision, so it must reach the UI without going through the error channel.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LabelOutcome {
    /// The label is free, or already belongs to this key.
    Assigned,
    /// **This is Signal's "safety number changed".** The label already belongs
    /// to another key: either the contact reinstalled, or someone is in the
    /// middle. Show both fingerprints and ask for explicit confirmation. Until
    /// then the old key keeps the label and nothing is overwritten.
    Conflict {
        existing: PublicKey,
        existing_fingerprint: Fingerprint,
        incoming_fingerprint: Fingerprint,
    },
}

/// How many of our temporary keys are kept per contact.
///
/// **Not a security knob: it is how many messages in a row you can send
/// before the other side replies.** The replier uses the latest key it has
/// *seen*, not the latest that exists; if newer ones were already dropped,
/// the reply cannot be opened.
///
/// Raising it **does not cost forward secrecy**: one of our temporary keys
/// only opens messages encrypted to it, and on reading, everything older than
/// the key used is dropped. Surplus keys are keys no message ever used. The cap
/// only stops state from growing towards a contact who never replies (64 keys
/// are 2 KB per contact).
///
/// 64 rather than 32 because long messages are split into up to twelve parts,
/// each consuming a key: with 32, three long messages in a row filled the
/// window.
///
/// Not much more than 64, because the cap is also the cost of **reading**: a
/// forward-secret message is opened by trying contact × our key, two
/// Diffie-Hellman operations each (see `baseline::apri_avanti`). The worst
/// case, a blob that opens with nothing, costs contacts × this number × 2 DH.
pub const MAX_PREKEY_MIE: usize = 64;

/// How many temporary keys survive a read regardless.
///
/// Opening a message drops our keys older than the one it used. Without a
/// minimum, **opening a message destroyed every older unread message from the
/// same person**: two messages encrypted to two different keys, the second
/// opened first, and the first never opens again. With copy-paste, reading out
/// of order is the norm.
///
/// Cost, stated in full: the eight most recent keys are no longer dropped on
/// reading, so a seized phone opens up to eight more messages. A real but
/// bounded weakening of forward secrecy: a fixed number, not a growing window,
/// and it slides away as new keys are generated. See `DESIGN.md`, decision I.
pub const CODA_MINIMA: usize = 8;

/// A row of [`PrekeyStore::dump`].
///
/// A struct rather than a tuple: two `Option<PublicKey>` fields with opposite
/// meanings (the rotating prekey and the epoch key) would be silently swapped
/// by a positional mistake.
pub struct PrekeyRecord {
    pub peer: PublicKey,
    /// Their rotating prekey (forward secrecy chain).
    pub sua_prekey: Option<PublicKey>,
    /// Our prekeys, newest first.
    pub mie: Vec<Zeroizing<[u8; KEY_LEN]>>,
    /// Our epoch key towards them. Private.
    pub mia_epoca: Option<Zeroizing<[u8; KEY_LEN]>>,
    /// Their epoch key towards us. Public.
    pub sua_epoca: Option<PublicKey>,
    /// See `PrekeyStore::seen_at`.
    pub visto_a: i64,
    /// See `PrekeyStore::burned_at`.
    pub rogo_a: i64,
}

/// Per-contact state of the forward secrecy chain.
///
/// It lives in the core, which does no I/O, because it is **just a data
/// structure**: callers store it however they like. All [`Keyring`]
/// implementations (phone, command line, tests) need exactly the same logic,
/// and separate copies would be separate ways of getting wrong the part that
/// decides whether an old message reopens.
///
/// `Vec` rather than `HashMap`: [`PublicKey`] deliberately does not implement
/// `Hash`.
#[derive(Default)]
pub struct PrekeyStore {
    /// The latest temporary key the peer sent us. Public.
    loro: Vec<(PublicKey, PublicKey)>,
    /// Ours, private, newest first. Zeroized when dropped.
    mie: Vec<(PublicKey, Vec<Zeroizing<[u8; KEY_LEN]>>)>,
    /// Our epoch key per contact (decision J). Private.
    ///
    /// **Kept here and not in `mie`.** The chain exists to rotate and be
    /// dropped (`push_my_prekey` inserts at the front, `drop_my_prekeys_older_than`
    /// truncates on every read), while the epoch exists precisely because it
    /// does NOT rotate. When they shared a list, reading a forward-secret
    /// message dropped the epoch and the burnable conversation became
    /// unreadable without anyone burning it.
    epoche: Vec<(PublicKey, Zeroizing<[u8; KEY_LEN]>)>,
    /// The PEER's epoch key. Public.
    ///
    /// The symmetric half of the field above. `loro` holds the chain's rotating
    /// prekey; storing the epoch there too made a sender with forward secrecy
    /// on encrypt to the epoch as if it were a prekey, and the recipient could
    /// never open it. This happens whenever two people have the switch set
    /// differently.
    epoche_loro: Vec<(PublicKey, PublicKey)>,
    /// When we last accepted material from that contact, by the WRITER's
    /// clock.
    ///
    /// Prevents going backwards. A blob is valid forever, so rereading an old
    /// message used to reinstall the key of that time (after a burn, the
    /// other side's destroyed pre-burn epoch), and our messages silently
    /// became unreadable to them.
    ///
    /// This does not judge the other clock (decision C forbids that): it
    /// compares against what we already accepted from THEM.
    visto_a: Vec<(PublicKey, i64)>,
    /// When we last honoured a burn from that contact.
    ///
    /// A burn blob can be pasted again months later and destroy a conversation
    /// that restarted in the meantime. Rejecting by absolute date is ruled out;
    /// refusing to **redo** something already done is not.
    rogo_a: Vec<(PublicKey, i64)>,
}

impl PrekeyStore {
    pub fn peer_prekey(&self, peer: &PublicKey) -> Option<PublicKey> {
        self.loro
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, k)| k.clone())
    }

    pub fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) {
        match self.loro.iter_mut().find(|(p, _)| p == peer) {
            Some((_, k)) => *k = prekey.clone(),
            None => self.loro.push((peer.clone(), prekey.clone())),
        }
    }

    /// Temporary keys are returned inside `Zeroizing`, not as bare arrays:
    /// `dump()` calls this for every contact on every save, so unprotected
    /// copies would put every temporary key on the heap at each write.
    pub fn my_prekeys(&self, peer: &PublicKey) -> Vec<Zeroizing<[u8; KEY_LEN]>> {
        self.mie
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    }

    pub fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) {
        match self.mie.iter_mut().find(|(p, _)| p == peer) {
            Some((_, v)) => {
                v.insert(0, Zeroizing::new(secret));
                // `truncate` drops the surplus keys, which zeroize on drop.
                v.truncate(MAX_PREKEY_MIE);
            }
            None => self.mie.push((peer.clone(), vec![Zeroizing::new(secret)])),
        }
    }

    /// See [`Keyring::drop_my_prekeys_older_than`]. If the given key is no
    /// longer present nothing is dropped: it already fell out, and treating
    /// "not found" as "drop them all" would also delete the newer ones.
    ///
    /// **Never goes below [`CODA_MINIMA`]**; see that constant.
    pub fn drop_my_prekeys_older_than(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) {
        if let Some((_, v)) = self.mie.iter_mut().find(|(p, _)| p == peer) {
            if let Some(i) = v.iter().position(|s| &**s == secret) {
                v.truncate(i.saturating_add(1).max(CODA_MINIMA));
            }
        }
    }

    /// **Burns** the conversation with a contact: our keys and theirs go. The
    /// contact and their identity stay; only the ability to read what was
    /// exchanged disappears.
    ///
    /// Same effect on keys as [`Self::forget`], with a different intent; the
    /// two names stay distinct because users do them for opposite reasons.
    pub fn burn(&mut self, peer: &PublicKey) {
        self.forget(peer);
    }

    /// The contact's epoch key, if they sent us one.
    pub fn peer_epoch(&self, peer: &PublicKey) -> Option<PublicKey> {
        self.epoche_loro
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, k)| k.clone())
    }

    pub fn set_peer_epoch(&mut self, peer: &PublicKey, epoca: &PublicKey) {
        match self.epoche_loro.iter_mut().find(|(p, _)| p == peer) {
            Some((_, k)) => *k = epoca.clone(),
            None => self.epoche_loro.push((peer.clone(), epoca.clone())),
        }
    }

    pub fn seen_at(&self, peer: &PublicKey) -> i64 {
        self.visto_a
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, q)| *q)
            .unwrap_or(i64::MIN)
    }

    pub fn set_seen_at(&mut self, peer: &PublicKey, quando: i64) {
        match self.visto_a.iter_mut().find(|(p, _)| p == peer) {
            Some((_, q)) => *q = quando.max(*q),
            None => self.visto_a.push((peer.clone(), quando)),
        }
    }

    pub fn burned_at(&self, peer: &PublicKey) -> i64 {
        self.rogo_a
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, q)| *q)
            .unwrap_or(i64::MIN)
    }

    pub fn set_burned_at(&mut self, peer: &PublicKey, quando: i64) {
        match self.rogo_a.iter_mut().find(|(p, _)| p == peer) {
            Some((_, q)) => *q = quando.max(*q),
            None => self.rogo_a.push((peer.clone(), quando)),
        }
    }

    /// Removes one secret from the chain without touching the rest.
    ///
    /// Used when an old prekey is **adopted as the epoch**: from then on it is
    /// something else, and leaving it in the chain too would make it live in
    /// two places, with `drop_my_prekeys_older_than` touching only one, so a
    /// secret that forward secrecy declares destroyed would stay on disk.
    pub fn forget_my_prekey(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) {
        if let Some((_, v)) = self.mie.iter_mut().find(|(p, _)| p == peer) {
            v.retain(|s| &**s != secret);
        }
    }

    /// Our epoch key towards that contact, if any.
    pub fn my_epoch(&self, peer: &PublicKey) -> Option<Zeroizing<[u8; KEY_LEN]>> {
        self.epoche
            .iter()
            .find(|(p, _)| p == peer)
            .map(|(_, k)| k.clone())
    }

    /// Keeps ONE per contact: a second would be a second history. Overwriting
    /// is therefore right, but callers must only do it when none exists yet,
    /// otherwise the epoch rotates and the history breaks anyway.
    pub fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) {
        match self.epoche.iter_mut().find(|(p, _)| p == peer) {
            Some((_, k)) => *k = Zeroizing::new(secret),
            None => self.epoche.push((peer.clone(), Zeroizing::new(secret))),
        }
    }

    /// Callers that forget a contact must call this: otherwise the temporary
    /// private keys towards that person would stay on disk after the user
    /// asked to delete them.
    pub fn forget(&mut self, peer: &PublicKey) {
        self.loro.retain(|(p, _)| p != peer);
        self.mie.retain(|(p, _)| p != peer);
        // The epoch goes with the rest: it is conversation state, and
        // forgetting a contact or burning the conversation must leave the same
        // void. If it survived, `burn` would promise to make unreadable what
        // would stay readable.
        self.epoche.retain(|(p, _)| p != peer);
        self.epoche_loro.retain(|(p, _)| p != peer);
        // `visto_a` and `rogo_a` are NOT reset: they are the defences against
        // going backwards, and resetting them here would let a reposted burn
        // through right after a burn (which goes through this function). They
        // are monotonic counters, not conversation state.
    }

    /// For whoever writes the state to disk.
    pub fn dump(&self) -> Vec<PrekeyRecord> {
        // A contact can appear in any one of the lists and not in the others,
        // so first collect all peers, then fill each row.
        let mut peers: Vec<PublicKey> = Vec::new();
        for chiave in self
            .loro
            .iter()
            .map(|(p, _)| p)
            .chain(self.mie.iter().map(|(p, _)| p))
            .chain(self.epoche.iter().map(|(p, _)| p))
            .chain(self.epoche_loro.iter().map(|(p, _)| p))
            .chain(self.visto_a.iter().map(|(p, _)| p))
            .chain(self.rogo_a.iter().map(|(p, _)| p))
        {
            if !peers.iter().any(|p| p == chiave) {
                peers.push(chiave.clone());
            }
        }
        peers
            .into_iter()
            .map(|peer| PrekeyRecord {
                sua_prekey: self.peer_prekey(&peer),
                mie: self.my_prekeys(&peer),
                mia_epoca: self.my_epoch(&peer),
                sua_epoca: self.peer_epoch(&peer),
                visto_a: self.seen_at(&peer),
                rogo_a: self.burned_at(&peer),
                peer,
            })
            .collect()
    }

    /// For whoever reads it back. Our keys must be passed newest first, in the
    /// order [`Self::dump`] returned them: the order is significant, it decides
    /// what drops out.
    pub fn restore(&mut self, record: PrekeyRecord) {
        let PrekeyRecord {
            peer,
            sua_prekey: loro,
            mie,
            mia_epoca: epoca,
            sua_epoca,
            visto_a,
            rogo_a,
        } = record;
        let peer = &peer;
        if let Some(k) = sua_epoca {
            self.set_peer_epoch(peer, &k);
        }
        if visto_a != i64::MIN {
            self.set_seen_at(peer, visto_a);
        }
        if rogo_a != i64::MIN {
            self.set_burned_at(peer, rogo_a);
        }
        if let Some(k) = epoca {
            self.set_my_epoch(peer, *k);
        }
        if let Some(k) = loro {
            self.set_peer_prekey(peer, &k);
        }
        if !mie.is_empty() {
            let mut v: Vec<Zeroizing<[u8; KEY_LEN]>> = mie;
            v.truncate(MAX_PREKEY_MIE);
            match self.mie.iter_mut().find(|(p, _)| p == peer) {
                Some((_, dentro)) => *dentro = v,
                None => self.mie.push((peer.clone(), v)),
            }
        }
    }
}

/// TOFU keyring. Encrypted storage lives outside the core; this is only the
/// abstraction the core works against.
///
/// Object-safe on purpose (used as `dyn Keyring` on Android): no
/// `-> impl Iterator` in the methods.
pub trait Keyring {
    /// Records the peer if new, without a label.
    fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome>;

    /// Assigns a name to an already pinned key.
    ///
    /// This is where TOFU becomes able to say "Mark's key changed": if the
    /// label belongs to another key, returns [`LabelOutcome::Conflict`] and
    /// **changes nothing**.
    fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome>;

    /// Moves label and contact identity from the old key to the new one, after
    /// EXPLICIT user confirmation. The only place where a pin can be
    /// overwritten. Never call it automatically after a
    /// [`LabelOutcome::Conflict`].
    ///
    /// `verified` is NOT inherited: a new key has, by definition, not been
    /// verified out of band.
    fn replace_pinned(&mut self, old: &PublicKey, new: &PublicKey, now_unix: i64) -> Result<()>;

    /// Forgets a peer. `Ok(true)` if it was there.
    ///
    /// Not needed by the keyboard flow, but by the contact list, which could
    /// otherwise only grow.
    ///
    /// **Callers must warn the user first:** the pin is lost, and the next
    /// message from that person appears as an unseen sender and is silently
    /// re-pinned. That is indistinguishable from someone impersonating them,
    /// i.e. it reopens exactly the window the pin was closing.
    fn forget(&mut self, peer: &PublicKey) -> Result<bool>;

    /// The latest temporary key the peer sent us, used to write to them.
    /// `None` until they send one.
    fn peer_prekey(&self, peer: &PublicKey) -> Result<Option<PublicKey>>;

    fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) -> Result<()>;

    /// Our still-valid temporary keys towards that peer, newest first. Highly
    /// sensitive, and they must be persisted: otherwise a restart would make
    /// messages already in flight unreadable.
    fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<Zeroizing<[u8; KEY_LEN]>>>;

    /// Adds one of our temporary keys, keeping only the latest few.
    fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()>;

    /// Our epoch key towards that contact (decision J), if any.
    ///
    /// **Not a prekey, and not stored with them**: the chain rotates and is
    /// dropped, the epoch exists because it does not rotate.
    fn my_epoch(&self, peer: &PublicKey) -> Result<Option<Zeroizing<[u8; KEY_LEN]>>>;

    /// The contact's epoch key, used to write to them in burnable mode.
    ///
    /// **Not their prekey**: one rotates and is dropped, the other does not.
    fn peer_epoch(&self, peer: &PublicKey) -> Result<Option<PublicKey>>;

    fn set_peer_epoch(&mut self, peer: &PublicKey, epoca: &PublicKey) -> Result<()>;

    /// Since when we accept material from that contact. See
    /// `PrekeyStore::seen_at`: prevents going backwards by rereading an old
    /// blob.
    fn seen_at(&self, peer: &PublicKey) -> Result<i64>;

    fn set_seen_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()>;

    /// When we last honoured a burn from that contact, so as not to redo one.
    fn burned_at(&self, peer: &PublicKey) -> Result<i64>;

    fn set_burned_at(&mut self, peer: &PublicKey, quando: i64) -> Result<()>;

    /// Removes from the chain a secret adopted as the epoch, so it does not
    /// live in two places.
    fn forget_my_prekey(&mut self, peer: &PublicKey, secret: &[u8; KEY_LEN]) -> Result<()>;

    /// Sets our epoch key towards that contact. Callers must only do this when
    /// none exists yet: overwriting it is the same as not having it.
    fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; KEY_LEN]) -> Result<()>;

    /// Drops our temporary keys older than the given one.
    ///
    /// **This is the act that produces forward secrecy**: as long as those keys
    /// exist, the messages that used them remain openable. Only older keys are
    /// dropped, so two messages sent with the same key stay readable even when
    /// they arrive out of order.
    fn drop_my_prekeys_older_than(
        &mut self,
        peer: &PublicKey,
        secret: &[u8; KEY_LEN],
    ) -> Result<()>;

    /// Drops **all** conversation state with that peer: our temporary keys and
    /// theirs. The pin and the name stay.
    ///
    /// This is decision J. Afterwards, messages exchanged with that person no
    /// longer reopen on this side, and the next one sent starts with a new key.
    fn burn_conversation(&mut self, peer: &PublicKey) -> Result<()>;

    /// The pinned keys, for callers that must try them all.
    ///
    /// Needed for ephemeral-sender messages: the recipient does not know who
    /// wrote and finds out by trying. Returns a `Vec` rather than an iterator
    /// because the trait must stay object-safe.
    fn peers(&self) -> Result<Vec<PublicKey>>;

    fn get(&self, peer: &PublicKey) -> Result<Option<PeerRecord>>;

    /// Marks a peer as verified out of band (fingerprint compared).
    fn mark_verified(&mut self, peer: &PublicKey) -> Result<()>;
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

    fn peer(n: u8) -> PublicKey {
        PublicKey::from_bytes([n; KEY_LEN])
    }

    /// The normal case: I send two messages in a row, the other side opens the
    /// second, and the first must stay openable.
    #[test]
    fn buttare_il_vecchio_non_e_buttare_tutto() {
        let mut store = PrekeyStore::default();
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.push_my_prekey(&peer(1), [11; KEY_LEN]);
        store.push_my_prekey(&peer(1), [12; KEY_LEN]);

        // Newest first: the order in which opening is attempted.
        assert_eq!(*store.my_prekeys(&peer(1))[0], [12; KEY_LEN]);

        // A message encrypted with the second-newest key arrives. With only
        // three keys nothing drops: below CODA_MINIMA nothing is ever cut.
        store.drop_my_prekeys_older_than(&peer(1), &[11; KEY_LEN]);
        assert_eq!(
            nude(store.my_prekeys(&peer(1))),
            vec![[12; KEY_LEN], [11; KEY_LEN], [10; KEY_LEN]]
        );

        // Beyond the minimum the cut applies again: fill the list and use a key
        // far enough back.
        for i in 13..30u8 {
            store.push_my_prekey(&peer(1), [i; KEY_LEN]);
        }
        store.drop_my_prekeys_older_than(&peer(1), &[25; KEY_LEN]);
        // Exactly CODA_MINIMA remain: the one used plus the newer ones, up to
        // eight. The older ones are gone.
        let rimaste = nude(store.my_prekeys(&peer(1)));
        assert_eq!(rimaste.len(), CODA_MINIMA);
        assert_eq!(rimaste.first(), Some(&[29; KEY_LEN]));
        assert!(rimaste.contains(&[25; KEY_LEN]));
        assert!(!rimaste.contains(&[10; KEY_LEN]));
    }

    /// If the given key already dropped out, nothing is dropped: treating "not
    /// found" as "drop them all" would kill messages in flight.
    #[test]
    fn una_chiave_gia_caduta_non_ne_trascina_altre() {
        let mut store = PrekeyStore::default();
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.drop_my_prekeys_older_than(&peer(1), &[99; KEY_LEN]);
        assert_eq!(nude(store.my_prekeys(&peer(1))), vec![[10; KEY_LEN]]);
    }

    /// The cap exists only so that state does not grow without bound towards
    /// someone who never replies.
    #[test]
    fn la_finestra_non_diventa_un_archivio() {
        let mut store = PrekeyStore::default();
        let quante = u8::try_from(MAX_PREKEY_MIE).unwrap().saturating_add(8);
        for i in 0..quante {
            store.push_my_prekey(&peer(1), [i; KEY_LEN]);
        }
        assert_eq!(store.my_prekeys(&peer(1)).len(), MAX_PREKEY_MIE);
        // The newest stays first: the order in which keys are tried.
        assert_eq!(
            store.my_prekeys(&peer(1))[0],
            Zeroizing::new([quante.saturating_sub(1); KEY_LEN])
        );
    }

    /// Forgetting a contact must also remove our private keys towards them;
    /// otherwise they stay on disk after the user deleted the contact.
    #[test]
    fn dimenticare_porta_via_anche_le_chiavi() {
        let mut store = PrekeyStore::default();
        store.set_peer_prekey(&peer(1), &peer(50));
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.set_peer_prekey(&peer(2), &peer(51));

        store.forget(&peer(1));
        assert!(store.peer_prekey(&peer(1)).is_none());
        assert!(store.my_prekeys(&peer(1)).is_empty());
        assert_eq!(store.peer_prekey(&peer(2)), Some(peer(51)));
    }

    /// A restart must not make messages in flight unreadable: the order
    /// survives, and the order decides what drops out.
    #[test]
    fn lo_stato_sopravvive_al_giro_su_disco() {
        let mut store = PrekeyStore::default();
        store.set_peer_prekey(&peer(1), &peer(50));
        store.push_my_prekey(&peer(1), [10; KEY_LEN]);
        store.push_my_prekey(&peer(1), [11; KEY_LEN]);
        // A contact who wrote to us but whom we have not answered yet: their
        // key, none of ours.
        store.set_peer_prekey(&peer(2), &peer(51));
        // And one we wrote to first: ours only.
        store.push_my_prekey(&peer(3), [30; KEY_LEN]);

        let mut riletto = PrekeyStore::default();
        for record in store.dump() {
            riletto.restore(record);
        }

        assert_eq!(riletto.peer_prekey(&peer(1)), Some(peer(50)));
        assert_eq!(
            nude(riletto.my_prekeys(&peer(1))),
            vec![[11; KEY_LEN], [10; KEY_LEN]]
        );
        assert_eq!(riletto.peer_prekey(&peer(2)), Some(peer(51)));
        assert!(riletto.my_prekeys(&peer(2)).is_empty());
        assert!(riletto.peer_prekey(&peer(3)).is_none());
        assert_eq!(nude(riletto.my_prekeys(&peer(3))), vec![[30; KEY_LEN]]);
    }

}
