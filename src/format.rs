//! Wire format of a message.
//!
//! There are two kinds of text blob, distinguished by a `kind` byte INSIDE the
//! body:
//!
//! ```text
//! SENTINEL || z-base-32( body )
//!
//! body = version(1) || kind(1) || payload
//!
//! kind = Message:
//!     tier(1) || flags(1)
//!  || [ sender_pub(32) if flags & SENDER_PUB ]
//!  || nonce(24)
//!  || ciphertext(n + 16)      // includes the Poly1305 tag
//!
//! kind = IdentityCard:
//!     flags(1) || public(32) || checksum(4)
//! ```
//!
//! The discriminant is in the body, not in the sentinel, on purpose: from the
//! outside the two kinds are indistinguishable. A dedicated sentinel for
//! identity cards would be a clear-text marker of "this user is adding a new
//! contact", exactly the kind of signal mass scanning collects for free.
//!
//! Overhead of a message with `sender_pub`: 76 bytes + plaintext, about 1.6×
//! after z-base-32.

use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha256};

use crate::encoding;
use crate::error::{Error, Result};
use crate::keys::{PublicKey, KEY_LEN};

/// Version byte, first byte of the body. A released version is never modified;
/// a new one is added.
pub const PROTOCOL_VERSION: u8 = 1;

/// Group message (decision K). **A version, not a new `kind` and not a flag
/// bit**: an older installation must say "update the app", not "corrupted
/// message", and only the version byte yields `UnsupportedVersion` before any
/// other check.
pub const GROUP_VERSION: u8 = 2;

/// Wrapped content key (32) plus tag (16).
pub const SLOT_LEN: usize = KEY_LEN + TAG_LEN;

/// Eight recipients plus the sender's own slot, which lets the sender reread
/// the message: the ephemeral key is dropped after sending.
pub const MAX_SLOT: usize = 9;

/// Recognition prefix, necessarily in clear: it identifies arbitrary clipboard
/// text as one of our blobs BEFORE decryption.
///
/// A cosmetic pseudo-link: social plausibility for a human eye, no security
/// property. Never clickable, never a real domain, never a network request.
///
/// TECHNICAL CONSTRAINT: chat linkifiers must not recognise it, otherwise the
/// platform unfurls it server-side and sends the blob to a third party.
/// Linkifiers match `scheme://`, `www.` and `label.tld` with TLDs from the IANA
/// list; none of the three is here. Do not introduce dots.
///
/// The slash is not in the z-base-32 alphabet, so it is an unambiguous
/// separator.
///
/// It does NOT contain the version, which lives only in the first byte of the
/// body. As a result, a blob from a future version is still RECOGNISED as ours
/// and yields `UnsupportedVersion` ("update the app") instead of `NotOurBlob`
/// ("this text is not encrypted").
pub const SENTINEL: &str = "kc/";

/// Below this length, alphabet characters after the sentinel are almost
/// certainly a coincidence in normal text, not a truncated blob. Prevents text
/// that happens to contain `kc/` and a few letters from being classified as
/// "ours but broken".
const MIN_PAYLOAD_CHARS: usize = 16;

/// Range into which the body length of an identity card is brought with random
/// padding.
///
/// Without it a card would ALWAYS have the same length (39 bytes, 68
/// characters) while the shortest message has 127: a single length rule would
/// isolate all identity cards in all traffic, which is exactly the marker that
/// putting `kind` inside the body was meant to avoid.
///
/// The range covers the lengths of messages with 0 to 200 bytes of plaintext.
/// Accepted residual: over many samples the distributions remain
/// distinguishable (cards are uniform, messages follow text lengths). It
/// defends against a cheap rule applied to all traffic, not against statistics
/// on a chosen user.
const CARD_MIN_BODY: usize = 76;
const CARD_MAX_BODY: usize = 276;

/// XChaCha20-Poly1305 nonce.
pub const NONCE_LEN: usize = 24;
/// Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Truncated checksum of an identity card.
pub const CHECKSUM_LEN: usize = 4;

/// Domain separation of the checksum. Frozen.
const CHECKSUM_DOMAIN: &[u8] = b"keyboard-cipher/v1/identity-card";

/// Fixed part of a message: version + kind + tier + flags.
pub const MESSAGE_PREFIX_LEN: usize = 4;
/// Fixed part of an identity card: version + kind + flags.
pub const CARD_PREFIX_LEN: usize = 3;

/// Blob kind.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Kind {
    /// Encrypted message.
    Message = 0,
    /// Identity card: "this is my public key". Neither encrypted nor
    /// authenticated (it cannot be: it is the first contact). It only carries a
    /// public key in a form the keyboard recognises.
    IdentityCard = 1,
    /// Encrypted file: photo, audio, anything. It does **not** travel as text
    /// (z-base-32 would inflate it by 1.6×) but as raw bytes in an attachment.
    /// The rest of the envelope is identical to a message, so there is a single
    /// parser and `kind` is already in the AAD: a file cannot pass for a
    /// message, nor vice versa.
    File = 2,
    /// **Burn request** (decision J): "destroy the epoch key we write to each
    /// other with".
    ///
    /// Carries no text. It travels encrypted like everything else, so only
    /// someone who really has that conversation can request it, but it **cannot
    /// be enforced**: the recipient's app has to honour it.
    Burn = 3,
}

impl Kind {
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Kind::Message),
            1 => Ok(Kind::IdentityCard),
            2 => Ok(Kind::File),
            3 => Ok(Kind::Burn),
            _ => Err(Error::Format("kind sconosciuto")),
        }
    }
}

/// Protection level. The marker travels in clear (needed for dispatch before
/// decryption) AND is in the AAD: an active attacker altering it to force a
/// downgrade makes authentication fail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Tier {
    /// Static-static X25519 + XChaCha20-Poly1305. The only one implemented.
    Baseline = 0,
    /// Forward secrecy tier. RESERVED: parsed, execution returns
    /// [`Error::TierUnsupported`].
    ForwardSecret = 1,
    // **2 is reserved for a hybrid post-quantum exchange** (decision L). It is
    // not a variant because no code produces it yet; `from_byte` defends the
    // number by answering "update the app" instead of "corrupted" on an
    // unknown tier.
}

impl Tier {
    /// An unknown tier is [`Error::TierUnsupported`], **not** [`Error::Format`].
    ///
    /// The difference is what the user reads: `Format` is shown with the same
    /// sentence as a damaged blob, `TierUnsupported` as "update the app". A
    /// message from a future version is not damaged, only newer than the
    /// reader. This is what makes the `tier` byte a real reserved slot.
    ///
    /// Accepted price: a genuinely corrupted blob whose tier byte lands on an
    /// undefined value says "update the app" instead of "damaged". That is the
    /// right direction to be wrong in.
    ///
    /// For **known** tiers the two levels stay distinct: `ForwardSecret` parses
    /// without complaint and is rejected at execution. "I cannot read it" and
    /// "I cannot run it" remain different.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Tier::Baseline),
            1 => Ok(Tier::ForwardSecret),
            _ => Err(Error::TierUnsupported),
        }
    }
}

/// Presence bits for optional fields.
///
/// They make the format evolvable without breaking it: the static scheme puts
/// the sender's public key in clear, while ephemeral schemes do not, and then
/// `sender_pub` simply is not there.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Flags(pub u8);

impl Flags {
    pub const NONE: Flags = Flags(0);
    /// The body contains `sender_pub` in clear.
    pub const SENDER_PUB: Flags = Flags(0b0000_0001);
    /// The key in the header is **ephemeral**, not the sender's identity.
    ///
    /// The recipient no longer knows who wrote before decrypting, and finds out
    /// by trying their contacts. The AEAD key derives from two exchanges, the
    /// ephemeral one and the one with the sender's stable key, so a successful
    /// decryption **proves** who wrote, without a signature.
    ///
    /// Removes linkability: without `sender_pub` in clear, two messages from
    /// the same sender cannot be linked by looking at traffic. It is also half
    /// forward secrecy: whoever later obtains the SENDER's key cannot open
    /// earlier messages, because the ephemeral key was dropped. Whoever obtains
    /// the recipient's key still can; that is what [`Flags::PREKEY`] adds.
    pub const EPHEMERAL: Flags = Flags(0b0000_0010);
    /// The message also uses a **temporary key of the recipient**.
    ///
    /// Full forward secrecy: once the recipient drops that key, nobody can
    /// open the message, not even them. Always together with
    /// [`Flags::EPHEMERAL`] for the forward-secrecy scheme.
    pub const PREKEY: Flags = Flags(0b0000_0100);
    /// The ciphertext **carries** the sender's epoch key.
    ///
    /// Distinct from [`Flags::PREKEY`], which says the opposite: *using* the
    /// recipient's key. They must be separate because the first message of an
    /// epoch conversation carries its own key without being able to use the
    /// other's (it does not have it yet); without the distinction that message
    /// would have to be ephemeral, i.e. not rereadable by its author, which is
    /// exactly the case decision J exists for.
    ///
    /// Ephemeral schemes carry a key anyway, and there this bit stays **off**:
    /// such blobs already exist, and declaring it now would make them
    /// unreadable.
    pub const EPOCH_OFFER: Flags = Flags(0b0000_1000);
    /// Bits defined in version 1. Everything else must be zero.
    pub const KNOWN: Flags = Flags(0b0000_1111);

    pub fn contains(self, other: Flags) -> bool {
        self.0 & other.0 == other.0
    }

    fn has_unknown_bits(self) -> bool {
        self.0 & !Self::KNOWN.0 != 0
    }
}

/// What the public key in the header is, if present.
///
/// One type instead of a key plus a flag: with two fields one could write
/// "ephemeral" without a key, or a key without saying what it is. Here those
/// states cannot be expressed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    /// No key in clear. No current scheme produces it; it stays representable
    /// for a future tier.
    Assente,
    /// The sender's key, in clear. Needed for the first TOFU contact, and makes
    /// messages from the same sender linkable (accepted residual).
    Mittente(PublicKey),
    /// An **ephemeral** key, dropped by the sender right after sending.
    ///
    /// The recipient finds out who wrote by trying their contacts. The AEAD
    /// key comes from two exchanges, the ephemeral one and the one with the
    /// sender's stable key, so a successful decryption **proves** who it was.
    Effimera(PublicKey),
    /// Sender ephemeral key **plus** use of a temporary key of the recipient:
    /// full forward secrecy.
    ///
    /// Both exchanges go through the recipient's temporary key. Once it is
    /// dropped, the message is unreadable to anyone, including the recipient:
    /// **no history**, the price accepted with decision I.
    EffimeraConPrekey(PublicKey),
    /// The sender's key in clear, and the ciphertext carries **our** epoch key
    /// without using theirs: the first message of an epoch conversation, or
    /// the first after a burn.
    ///
    /// Encrypted to the recipient's identity, like the static scheme, so
    /// readable by both sides, which is the point of decision J.
    MittenteConEpoca(PublicKey),
    /// The sender's key in clear **plus** use of the recipient's epoch key:
    /// **decision J**, the burnable conversation.
    ///
    /// The difference from [`Origin::EffimeraConPrekey`] is what is missing:
    /// no ephemeral key. That is what makes the message rereadable, also by its
    /// author, who can redo the same derivation, so history exists.
    ///
    /// Confidentiality then comes from an act rather than from time: while the
    /// two epoch keys exist the message can be read; once they are destroyed it
    /// cannot, by either side.
    MittenteConPrekey(PublicKey),
}

impl Origin {
    pub fn is_ephemeral(&self) -> bool {
        matches!(self, Origin::Effimera(_) | Origin::EffimeraConPrekey(_))
    }

    pub fn uses_prekey(&self) -> bool {
        matches!(
            self,
            Origin::EffimeraConPrekey(_) | Origin::MittenteConPrekey(_)
        )
    }

    /// Epoch scheme: sender key in clear, encrypted to the recipient's epoch
    /// key. Rereadable as long as those keys exist.
    pub fn uses_epoch(&self) -> bool {
        matches!(self, Origin::MittenteConPrekey(_))
    }

    /// The ciphertext carries the sender's epoch key **and declares it**.
    /// Ephemeral schemes carry one anyway, without the bit.
    pub fn offers_epoch(&self) -> bool {
        matches!(
            self,
            Origin::MittenteConEpoca(_) | Origin::MittenteConPrekey(_)
        )
    }

    /// First message of an epoch conversation: carries our key but does not
    /// use theirs, because we do not have it yet.
    pub fn is_epoch_bootstrap(&self) -> bool {
        matches!(self, Origin::MittenteConEpoca(_))
    }

    /// The key to put in the body, if any.
    pub fn key(&self) -> Option<&PublicKey> {
        match self {
            Origin::Assente => None,
            Origin::Mittente(k)
            | Origin::Effimera(k)
            | Origin::EffimeraConPrekey(k)
            | Origin::MittenteConEpoca(k)
            | Origin::MittenteConPrekey(k) => Some(k),
        }
    }
}

/// Clear-text header of a message. Everything here is visible to whoever
/// intercepts it: keep it minimal.
///
/// `flags` is not a field but a function of `origin`: two sources of truth
/// for the same fact would make it possible to build an inconsistent header,
/// which fails authentication opaquely.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub tier: Tier,
    pub origin: Origin,
    pub nonce: [u8; NONCE_LEN],
}

impl Header {
    pub fn flags(&self) -> Flags {
        match self.origin {
            Origin::Assente => Flags::NONE,
            Origin::Mittente(_) => Flags::SENDER_PUB,
            Origin::Effimera(_) => Flags(Flags::SENDER_PUB.0 | Flags::EPHEMERAL.0),
            Origin::EffimeraConPrekey(_) => {
                Flags(Flags::SENDER_PUB.0 | Flags::EPHEMERAL.0 | Flags::PREKEY.0)
            }
            Origin::MittenteConEpoca(_) => Flags(Flags::SENDER_PUB.0 | Flags::EPOCH_OFFER.0),
            Origin::MittenteConPrekey(_) => {
                Flags(Flags::SENDER_PUB.0 | Flags::PREKEY.0 | Flags::EPOCH_OFFER.0)
            }
        }
    }

    /// The sender's key, if the header declares it as such. `None` for an
    /// ephemeral key: it does not say who wrote, and treating it as an identity
    /// would pin a single-use key in the keyring.
    pub fn sender_pub(&self) -> Option<&PublicKey> {
        match &self.origin {
            // In the epoch scheme the key is the sender's, as in the static
            // case: it is the ephemeral key that does not identify the writer.
            Origin::Mittente(k) | Origin::MittenteConEpoca(k) | Origin::MittenteConPrekey(k) => {
                Some(k)
            }
            _ => None,
        }
    }
}

/// Parsed message, before decryption. Borrows the ciphertext from the caller's
/// buffer instead of copying it.
#[derive(Debug)]
pub struct ParsedEnvelope<'a> {
    pub header: Header,
    /// Includes the trailing Poly1305 tag.
    pub ciphertext: &'a [u8],
}

/// Parsed identity card.
#[derive(Debug, PartialEq, Eq)]
pub struct IdentityCard {
    pub public: PublicKey,
}

/// Result of [`parse`]: the caller must handle every case.
#[derive(Debug)]
pub enum ParsedBlob<'a> {
    Message(ParsedEnvelope<'a>),
    IdentityCard(IdentityCard),
    /// A request to burn the conversation (decision J). Same envelope as a
    /// message; only `kind` differs, and it is in the AAD, so it cannot be
    /// swapped with a normal message.
    Burn(ParsedEnvelope<'a>),
    /// A group message (decision K, `version = 2`).
    Group(ParsedGroup<'a>),
}

/// A parsed group message.
///
/// Slots stay a block of bytes rather than a `Vec` of structs: readers try
/// them one by one and have nothing to extract until one works.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedGroup<'a> {
    pub header: Header,
    /// `n * SLOT_LEN` bytes. The count follows from the length.
    pub slots: &'a [u8],
    /// Includes the trailing Poly1305 tag.
    pub ciphertext: &'a [u8],
}

impl ParsedGroup<'_> {
    pub fn slot_count(&self) -> usize {
        self.slots.len() / SLOT_LEN
    }

    pub fn slot(&self, i: usize) -> Option<&[u8]> {
        let inizio = i.checked_mul(SLOT_LEN)?;
        let fine = inizio.checked_add(SLOT_LEN)?;
        self.slots.get(inizio..fine)
    }
}

/// Authenticated but unencrypted data (the AEAD's AAD).
///
/// Binds header, kind and tier to the ciphertext: tampering with them makes
/// authentication fail. `kind` is included so a message cannot be
/// reinterpreted as a blob of a different kind. `sender_pub` is included even
/// though its value is already bound implicitly by the key derivation: making
/// it explicit costs nothing and does not leave the binding to an indirect
/// argument.
pub fn build_aad(kind: Kind, header: &Header) -> Vec<u8> {
    let mut aad = Vec::with_capacity(4 + KEY_LEN);
    aad.push(PROTOCOL_VERSION);
    aad.push(kind as u8);
    aad.push(header.tier as u8);
    aad.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        aad.extend_from_slice(chiave.as_bytes());
    }
    aad
}

/// AAD of a group message.
///
/// On top of what version 1 binds, it binds **the slot count** and, when a
/// slot is being sealed or opened, **its index**. They prevent different
/// attacks:
///
/// - without the index, slots could be **reordered** (a moved slot still
///   opens, because its key does not depend on the position);
/// - without the count, one could be **removed**, and the mutilated blob would
///   look as if it had been created without that recipient.
///
/// `indice` is `None` for the payload AAD, which belongs to no slot.
///
/// `impronta_slot` is passed **only** for the payload AAD, and binds the text
/// to the slot block as it is. Without it, overwriting one person's slot with
/// a copy of another's kept count, length and shape intact, and the blob
/// stayed readable for everyone else: someone in the middle could **exclude a
/// single person** silently. Now such a substitution breaks the payload for
/// EVERYONE: corruption is still possible (an active attacker can always do
/// that), but it becomes an evident failure rather than targeted, silent
/// censorship.
///
/// Not needed for the slots: when they are sealed the block does not exist
/// yet, and each is already bound to its index.
pub fn build_group_aad(
    kind: Kind,
    header: &Header,
    n_slot: u8,
    indice: Option<u8>,
    impronta_slot: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(6 + KEY_LEN + 32);
    aad.push(GROUP_VERSION);
    aad.push(kind as u8);
    aad.push(header.tier as u8);
    aad.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        aad.extend_from_slice(chiave.as_bytes());
    }
    aad.push(n_slot);
    // Payload and slots must never share an AAD: `0xFF` is not a valid index
    // (the cap is MAX_SLOT), so it separates the two cases without a type byte.
    aad.push(indice.unwrap_or(0xFF));
    if let Some(impronta) = impronta_slot {
        aad.extend_from_slice(impronta);
    }
    aad
}

/// Hash of the slot block, binding it to the payload. See
/// [`build_group_aad`].
pub fn impronta_slot(slots: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(slots);
    hasher.finalize().into()
}

/// Serialises a group message.
///
/// `slots` is the already concatenated block in random order: shuffling is
/// the builder's job, not this function's (there is no RNG here).
pub fn serialize_group(header: &Header, slots: &[u8], ciphertext: &[u8]) -> Result<String> {
    // Enforce the contract instead of trusting it. A block whose length is not
    // a multiple of SLOT_LEN would leave stray bytes in the ciphertext, and
    // above 255 slots the count would be written as zero, producing a blob our
    // own parser rejects. A caller error must be an `Err`, not a broken blob.
    if slots.is_empty() || slots.len() % SLOT_LEN != 0 {
        return Err(Error::Format("blocco di slot malformato"));
    }
    let n_slot = slots.len() / SLOT_LEN;
    if !(2..=MAX_SLOT).contains(&n_slot) {
        return Err(Error::Format("numero di slot fuori dai limiti"));
    }
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(1)
        .saturating_add(slots.len())
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(GROUP_VERSION);
    body.push(Kind::Message as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.push(u8::try_from(n_slot).map_err(|_| Error::Format("troppi slot"))?);
    body.extend_from_slice(slots);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    Ok(out)
}

/// Serialises a message with the sentinel in front, ready for the chat.
pub fn serialize_message(header: &Header, ciphertext: &[u8]) -> String {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::Message as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Serialises an identity card, with random padding at the end.
///
/// The padding is not decorative: without it every card would have the same
/// length and could be isolated with a regex over all traffic (see
/// [`CARD_MIN_BODY`]). That is also why this function needs an RNG while its
/// message counterpart does not.
///
/// Padding bytes are not covered by the checksum and mean nothing: altering
/// them does not change the key carried. As a consequence a card has NO unique
/// textual form, unlike a message. Intended: the variability is the point.
pub fn serialize_identity_card<R: RngCore + CryptoRng>(public: &PublicKey, rng: &mut R) -> String {
    let base = CARD_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(CHECKSUM_LEN);
    let span = CARD_MAX_BODY
        .saturating_sub(CARD_MIN_BODY)
        .saturating_add(1);
    let offset = usize::try_from(rng.next_u32())
        .unwrap_or(0)
        .checked_rem(span)
        .unwrap_or(0);
    let target = CARD_MIN_BODY.saturating_add(offset);
    let pad_len = target.saturating_sub(base);

    let mut body = Vec::with_capacity(target);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::IdentityCard as u8);
    body.push(Flags::NONE.0);
    body.extend_from_slice(public.as_bytes());
    body.extend_from_slice(&identity_card_checksum(public));

    let mut pad = vec![0u8; pad_len];
    rng.fill_bytes(&mut pad);
    body.extend_from_slice(&pad);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Truncated checksum of an identity card.
///
/// Not authentication, and does not claim to be: a card can be replaced in
/// transit, which is precisely the risk TOFU accepts. It protects against
/// CORRUPTION: a card truncated or altered in transport would otherwise be
/// pinned as a valid key, and every later message to that contact would fail
/// opaquely. Four bytes catch it, at the cost of seven characters.
pub fn identity_card_checksum(public: &PublicKey) -> [u8; CHECKSUM_LEN] {
    let mut hasher = Sha256::new();
    hasher.update(CHECKSUM_DOMAIN);
    hasher.update(public.as_bytes());
    let digest = hasher.finalize();

    let mut out = [0u8; CHECKSUM_LEN];
    // `digest` is 32 bytes and CHECKSUM_LEN is 4: the slice always exists.
    if let Some(head) = digest.get(..CHECKSUM_LEN) {
        out.copy_from_slice(head);
    }
    out
}

/// Tells whether the text *looks like* it contains one of our blobs, without
/// decoding it.
///
/// Used for one thing only: deciding whether to offer "decrypt". It checks the
/// sentinel and the minimum length of the alphabet run that follows, and
/// stops there.
///
/// **Not a check.** `true` does not mean the blob is intact, or for us, or of
/// the right version: `kc/` followed by enough garbage is enough. Fine for
/// deciding UI; wrong for skipping checks downstream.
///
/// A separate function because the Android caller must be able to ask
/// **without side effects**: [`parse`] has none, but the next step (decrypting)
/// pins peers in the keyring, and a "looks like ours" function must have no way
/// to get there.
#[must_use]
pub fn looks_like_blob(text: &str) -> bool {
    extract_payload(text).is_some()
}

/// Checks the sentinel, decodes, checks version and kind, extracts the fields.
/// Does NOT decrypt.
///
/// Returns [`Error::NotOurBlob`] if there is no sentinel: the common case for
/// arbitrary clipboard text, not a failure.
///
/// `out` is the buffer the decoded body lands in: the envelope borrows the
/// ciphertext from it instead of copying, so the result lives as long as the
/// buffer, not the text.
pub fn parse<'a>(text: &str, out: &'a mut Vec<u8>) -> Result<ParsedBlob<'a>> {
    let payload = extract_payload(text).ok_or(Error::NotOurBlob)?;
    *out = encoding::decode(payload)?;

    let mut cursor = Cursor::new(out);
    let version = cursor.take_u8()?;
    if version != PROTOCOL_VERSION && version != GROUP_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    let kind = Kind::from_byte(cursor.take_u8()?)?;

    if version == GROUP_VERSION {
        // Only messages have a group form. Group burns or cards do not exist,
        // and accepting them would mean a code path nobody produces or tests.
        return match kind {
            Kind::Message => parse_group(cursor).map(ParsedBlob::Group),
            _ => Err(Error::Format("questo tipo non ha una forma di gruppo")),
        };
    }

    match kind {
        Kind::Message => parse_message(cursor).map(ParsedBlob::Message),
        Kind::IdentityCard => parse_identity_card(cursor).map(ParsedBlob::IdentityCard),
        // A file never arrives this way: it is an attachment, not text. Someone
        // could still encode one in z-base-32 and paste it; better to say the
        // blob is not of this kind than to attempt a decryption that the AAD
        // would fail as "crypto".
        Kind::Burn => parse_message(cursor).map(ParsedBlob::Burn),
        Kind::File => Err(Error::Format("un file non si incolla come testo")),
    }
}

/// Serialises a burn request. From the outside it is indistinguishable from a
/// message: same sentinel, same shape, length in the same range. A dedicated
/// sentinel would tell scanners "two people are deleting a conversation here".
pub fn serialize_burn(header: &Header, ciphertext: &[u8]) -> String {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::Burn as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);

    let mut out = String::from(SENTINEL);
    out.push_str(&encoding::encode(&body));
    out
}

/// Serialises a file: same body as a message, **without** sentinel and
/// without z-base-32.
///
/// No marker at the start of any kind. A magic number would only help file
/// scanners recognise it: the first two bytes (version and `kind`) are enough
/// for whoever actually opens it, and announce nothing to whoever only looks.
pub fn serialize_file(header: &Header, ciphertext: &[u8]) -> Vec<u8> {
    let capacity = MESSAGE_PREFIX_LEN
        .saturating_add(KEY_LEN)
        .saturating_add(NONCE_LEN)
        .saturating_add(ciphertext.len());
    let mut body = Vec::with_capacity(capacity);
    body.push(PROTOCOL_VERSION);
    body.push(Kind::File as u8);
    body.push(header.tier as u8);
    body.push(header.flags().0);
    if let Some(chiave) = header.origin.key() {
        body.extend_from_slice(chiave.as_bytes());
    }
    body.extend_from_slice(&header.nonce);
    body.extend_from_slice(ciphertext);
    body
}

/// Inverse of [`serialize_file`].
///
/// As for messages, `Ok` says **nothing** about the integrity of the content:
/// the ciphertext has variable length and truncating it yields a well-formed
/// file. The tag catches that at decryption.
pub fn parse_file(bytes: &[u8]) -> Result<ParsedEnvelope<'_>> {
    let mut cursor = Cursor::new(bytes);
    let version = cursor.take_u8()?;
    if version != PROTOCOL_VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    match Kind::from_byte(cursor.take_u8()?)? {
        Kind::File => parse_message(cursor),
        // Not a file. Not a content format error either: it is a blob of
        // another kind that came through the wrong door.
        _ => Err(Error::Format("questo allegato non e' un file cifrato")),
    }
}

/// Isolates the blob inside the surrounding text.
///
/// Does not require the sentinel at the start nor the blob to run to the end.
/// Real input paths do not guarantee it: clipboard and share sheet often add a
/// trailing newline, and manual selection often includes a "look: " prefix.
/// Requiring an exact string would fail in the most common case, and with the
/// wrong error: a valid blob with a trailing `\n` is not "foreign", it is ours.
///
/// The payload is the maximal run of alphabet characters after the sentinel;
/// the first foreign byte ends it. Below [`MIN_PAYLOAD_CHARS`] it is treated as
/// a coincidence in normal text, not a blob.
fn extract_payload(text: &str) -> Option<&str> {
    // Try **every** occurrence of the sentinel, not only the first: a truncated
    // quote above the real message, or a hand-written "kc/" in an explanation,
    // must not hide a complete blob further on. The first VALID occurrence is
    // taken (the first thing of ours met while reading), not the longest.
    //
    // `match_indices` rather than a manual `find` loop: it returns positions
    // that are character boundaries by construction, whereas advancing one
    // byte in UTF-8 text is not.
    for (start, _) in text.match_indices(SENTINEL) {
        let Some(dopo) = start
            .checked_add(SENTINEL.len())
            .and_then(|inizio| text.get(inizio..))
        else {
            continue;
        };
        let end = dopo
            .bytes()
            .position(|b| !encoding::is_alphabet_byte(b))
            .unwrap_or(dopo.len());
        let Some(payload) = dopo.get(..end) else {
            continue;
        };
        if payload.len() >= MIN_PAYLOAD_CHARS {
            return Some(payload);
        }
    }
    None
}

fn parse_message<'a>(mut cursor: Cursor<'a>) -> Result<ParsedEnvelope<'a>> {
    let tier = Tier::from_byte(cursor.take_u8()?)?;
    let flags = Flags(cursor.take_u8()?);
    if flags.has_unknown_bits() {
        return Err(Error::Format("flag non definiti in questa versione"));
    }

    // The nature of the key follows from the flags, and the bits are not
    // independent: "ephemeral" without "key present" is an inconsistent
    // header, rejected here rather than producing an `Origin` that does not
    // describe the body. A format error is diagnosable; an AEAD failure is not.
    let ha_chiave = flags.contains(Flags::SENDER_PUB);
    let effimera = flags.contains(Flags::EPHEMERAL);
    let prekey = flags.contains(Flags::PREKEY);
    let offre = flags.contains(Flags::EPOCH_OFFER);
    if !ha_chiave && (effimera || prekey || offre) {
        return Err(Error::Format("effimera senza chiave"));
    }
    // Using the other side's epoch key without carrying our own would stall
    // the conversation at the next message: they would have nothing to write
    // to. Inconsistent in the same way as "ephemeral without a key".
    if prekey && !effimera && !offre {
        return Err(Error::Format("usa un'epoca senza offrirne una"));
    }
    // In ephemeral schemes the key travels anyway and the bit stays off:
    // setting it would be a second source of truth for the same fact.
    if effimera && offre {
        return Err(Error::Format("un'effimera porta gia' la propria chiave"));
    }
    // "Prekey without ephemeral" is valid since decision J: it is the epoch
    // scheme, where the absence of the ephemeral key is what makes the message
    // rereadable.
    let origin = if !ha_chiave {
        Origin::Assente
    } else {
        let mut bytes = [0u8; KEY_LEN];
        bytes.copy_from_slice(cursor.take(KEY_LEN)?);
        let chiave = PublicKey::from_bytes(bytes);
        match (effimera, prekey, offre) {
            (false, false, false) => Origin::Mittente(chiave),
            (false, false, true) => Origin::MittenteConEpoca(chiave),
            (false, true, _) => Origin::MittenteConPrekey(chiave),
            (true, false, _) => Origin::Effimera(chiave),
            (true, true, _) => Origin::EffimeraConPrekey(chiave),
        }
    };

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(cursor.take(NONCE_LEN)?);

    let ciphertext = cursor.rest();
    // Below the tag length there is not even an empty message.
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Format("ciphertext piu' corto del tag"));
    }

    Ok(ParsedEnvelope {
        header: Header { tier, origin, nonce },
        ciphertext,
    })
}

/// Parses a group message (`version = 2`).
///
/// The header is that of version 1 and is read with the same rules: the group
/// form appends fields, it does not change what was there.
fn parse_group<'a>(mut cursor: Cursor<'a>) -> Result<ParsedGroup<'a>> {
    let tier = Tier::from_byte(cursor.take_u8()?)?;
    let flags = Flags(cursor.take_u8()?);
    if flags.has_unknown_bits() {
        return Err(Error::Format("flag non definiti in questa versione"));
    }
    // A group has one shape only: sender ephemeral key, no prekeys. Groups have
    // no forward secrecy by decision (K1), so chain bits would mean nothing
    // here, and accepting them would allow a header claiming a property the
    // format does not have.
    if !flags.contains(Flags::SENDER_PUB)
        || !flags.contains(Flags::EPHEMERAL)
        || flags.contains(Flags::PREKEY)
        || flags.contains(Flags::EPOCH_OFFER)
    {
        return Err(Error::Format("un gruppo vuole la sola effimera"));
    }

    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(cursor.take(KEY_LEN)?);
    let origin = Origin::Effimera(PublicKey::from_bytes(bytes));

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(cursor.take(NONCE_LEN)?);

    let n_slot = usize::from(cursor.take_u8()?);
    // **Fewer than two slots is not a group.** The sender always has a slot of
    // their own (K2), so a legitimate group has at least two. A one-slot blob
    // can only come from a modified client, and would serve one purpose: to
    // pose as a one-to-one message while being a `version = 2` blob without
    // forward secrecy.
    if n_slot < 2 {
        return Err(Error::Format("un gruppo vuole almeno due slot"));
    }
    if n_slot > MAX_SLOT {
        return Err(Error::Format("troppi destinatari"));
    }
    // `take` fails if the bytes are not all there: the declared count and the
    // real length must match, otherwise a truncated blob would look like a
    // smaller group.
    let slots = cursor.take(n_slot.saturating_mul(SLOT_LEN))?;

    let ciphertext = cursor.rest();
    if ciphertext.len() < TAG_LEN {
        return Err(Error::Format("ciphertext piu' corto del tag"));
    }

    Ok(ParsedGroup {
        header: Header { tier, origin, nonce },
        slots,
        ciphertext,
    })
}

fn parse_identity_card(mut cursor: Cursor<'_>) -> Result<IdentityCard> {
    let flags = Flags(cursor.take_u8()?);
    // No flags are defined for cards in version 1.
    if flags != Flags::NONE {
        return Err(Error::Format("flag non definiti per identity card"));
    }

    let mut bytes = [0u8; KEY_LEN];
    bytes.copy_from_slice(cursor.take(KEY_LEN)?);
    let public = PublicKey::from_bytes(bytes);

    let checksum = cursor.take(CHECKSUM_LEN)?;
    // What remains is padding and is ignored: the extra bytes are the feature
    // (they keep cards from all having the same length), not a defect.
    //
    // Not a constant-time comparison, on purpose: there is no secret involved,
    // the card is entirely public.
    if checksum != identity_card_checksum(&public) {
        return Err(Error::Format("checksum della identity card non torna"));
    }

    Ok(IdentityCard { public })
}

/// Sequential reader that cannot panic: reading past the end is a format
/// error, never an out-of-bounds index.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(n)
            .ok_or(Error::Format("lunghezza fuori scala"))?;
        let slice = self
            .buf
            .get(self.pos..end)
            .ok_or(Error::Format("body troncato"))?;
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self) -> Result<u8> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(Error::Format("body troncato"))
    }

    fn rest(&self) -> &'a [u8] {
        self.buf.get(self.pos..).unwrap_or(&[])
    }
}

#[cfg(test)]
// In tests `unwrap` and `panic!` are intended: an unexpected result must fail
// loudly. The bans apply to production code.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    #[test]
    fn looks_like_blob_riconosce_senza_promettere() {
        // Sentinel plus enough alphabet characters: enough.
        assert!(looks_like_blob("kc/ybndrfg8ejkmcpqx"));
        // Tolerates context, like parse: real inputs are never clean.
        assert!(looks_like_blob("guarda: kc/ybndrfg8ejkmcpqx\n"));

        // No sentinel.
        assert!(!looks_like_blob("un messaggio qualunque"));
        // Sentinel, but the tail is too short to be a blob.
        assert!(!looks_like_blob("kc/ybnd"));
        // Sentinel followed by characters outside the alphabet.
        assert!(!looks_like_blob("kc/MAIUSCOLE"));

        // NOT a check: garbage of sufficient length passes. Intended (it only
        // decides whether to offer "decrypt"), and this test exists so nobody
        // mistakes it for validation.
        assert!(looks_like_blob("kc/yyyyyyyyyyyyyyyyyyyy"));
    }

    fn pubkey(seed: u8) -> PublicKey {
        PublicKey::from_bytes([seed; KEY_LEN])
    }

    fn header(sender: Option<PublicKey>) -> Header {
        Header {
            tier: Tier::Baseline,
            origin: match sender {
                Some(k) => Origin::Mittente(k),
                None => Origin::Assente,
            },
            nonce: [7u8; NONCE_LEN],
        }
    }

    fn ciphertext() -> Vec<u8> {
        (0..40u8).collect()
    }

    fn card_body_len() -> usize {
        CARD_PREFIX_LEN + KEY_LEN + CHECKSUM_LEN
    }

    #[test]
    fn round_trip_messaggio_con_sender_pub() {
        let h = header(Some(pubkey(0xAB)));
        let ct = ciphertext();
        let text = serialize_message(&h, &ct);

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = parse(&text, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert_eq!(parsed.header, h);
        assert_eq!(parsed.ciphertext, &ct[..]);
    }

    #[test]
    fn round_trip_messaggio_senza_sender_pub() {
        let h = header(None);
        let ct = ciphertext();
        let text = serialize_message(&h, &ct);

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = parse(&text, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert_eq!(parsed.header, h);
        assert_eq!(parsed.header.flags(), Flags::NONE);
        assert_eq!(parsed.ciphertext, &ct[..]);
    }

    #[test]
    fn round_trip_identity_card() {
        let key = pubkey(0x5C);
        let text = serialize_identity_card(&key, &mut rng(1));

        let mut buf = Vec::new();
        let ParsedBlob::IdentityCard(card) = parse(&text, &mut buf).unwrap() else {
            panic!("attesa una identity card");
        };
        assert_eq!(card.public, key);
    }

    /// The finding that motivated padding: without it every card was exactly
    /// 68 characters and the shortest message 127, so one length rule isolated
    /// all identity cards.
    ///
    /// Checks that (a) cards no longer have a fixed length and (b) their range
    /// falls inside that of messages.
    #[test]
    fn le_card_non_hanno_lunghezza_fissa() {
        let key = pubkey(0x77);
        let mut r = rng(2);
        let mut lunghezze = std::collections::BTreeSet::new();
        for _ in 0..200 {
            lunghezze.insert(serialize_identity_card(&key, &mut r).len());
        }
        assert!(
            lunghezze.len() > 50,
            "solo {} lunghezze distinte: il riempimento non sta variando",
            lunghezze.len()
        );

        let msg_corto = serialize_message(&header(Some(pubkey(1))), &[0u8; TAG_LEN]).len();
        let msg_lungo = serialize_message(&header(Some(pubkey(1))), &[0u8; 200 + TAG_LEN]).len();
        let (min, max) = (
            *lunghezze.iter().next().unwrap(),
            *lunghezze.iter().next_back().unwrap(),
        );
        assert!(
            min >= msg_corto && max <= msg_lungo,
            "card in {min}..{max}, messaggi in {msg_corto}..{msg_lungo}: gli intervalli non si sovrappongono"
        );
    }

    #[test]
    fn i_due_tipi_non_si_confondono() {
        let mut buf = Vec::new();
        let msg = serialize_message(&header(Some(pubkey(1))), &ciphertext());
        assert!(matches!(
            parse(&msg, &mut buf).unwrap(),
            ParsedBlob::Message(_)
        ));

        let card = serialize_identity_card(&pubkey(1), &mut rng(3));
        assert!(matches!(
            parse(&card, &mut buf).unwrap(),
            ParsedBlob::IdentityCard(_)
        ));
    }

    #[test]
    fn testo_qualunque_non_e_nostro() {
        let mut buf = Vec::new();
        for testo in [
            "",
            "ciao",
            "https://esempio.it/x",
            "KC/1/yyyyyyyyyyyyyyyyyyyy",
            "guarda qui kc/ e poi basta",
        ] {
            assert!(
                matches!(parse(testo, &mut buf), Err(Error::NotOurBlob)),
                "non riconosciuto come estraneo: {testo}"
            );
        }
    }

    /// Text from real input paths is never clean: clipboard and share sheet add
    /// a newline, manual selection drags context along. A valid blob inside all
    /// that stays valid.
    #[test]
    fn tollera_spazi_e_contesto() {
        let h = header(Some(pubkey(0x3D)));
        let ct = ciphertext();
        let blob = serialize_message(&h, &ct);

        for testo in [
            format!("{blob}\n"),
            format!("{blob}\r\n"),
            format!("{blob} "),
            format!("  {blob}  "),
            format!("guarda: {blob}"),
            format!("{blob} che ne dici?"),
            format!("[14:32] Marco:\n{blob}\n\n"),
            // A false start before the real one: a truncated quote above the
            // message must not hide the blob.
            format!("kc/ ecco quello di prima:\n{blob}"),
            format!("> kc/ybndrf\n{blob}"),
            format!("kc/\n{blob}\n"),
        ] {
            let mut buf = Vec::new();
            let ParsedBlob::Message(parsed) = parse(&testo, &mut buf).unwrap_or_else(|e| {
                panic!("rifiutato con {e:?}: {testo:?}");
            }) else {
                panic!("atteso un messaggio");
            };
            assert_eq!(parsed.ciphertext, &ct[..]);
        }
    }

    /// A truncated blob is still OURS: it may be broken, but must never become
    /// "this text is not encrypted". The UI builds two very different messages
    /// on that distinction, and a cut tail is the most common way a paste goes
    /// wrong.
    ///
    /// It is NOT asserted to be an error: cutting the tail of a message
    /// shortens the ciphertext and yields a still well-formed blob. The
    /// Poly1305 tag notices, not the parser.
    #[test]
    fn blob_troncato_resta_riconoscibile() {
        let blob = serialize_message(&header(Some(pubkey(2))), &ciphertext());

        for taglio in 1..=8usize {
            let tagliato = blob.get(..blob.len().saturating_sub(taglio)).unwrap();
            let mut buf = Vec::new();
            assert!(
                !matches!(parse(tagliato, &mut buf), Err(Error::NotOurBlob)),
                "taglio di {taglio} caratteri: classificato come non nostro"
            );
        }
    }

    /// With no version in the sentinel, a blob from a future version is
    /// recognised as ours: the user must read "update the app", not "this text
    /// is not encrypted".
    ///
    /// Version 3 rather than 2: 2 is the group message.
    #[test]
    fn versione_futura_riconosciuta_come_nostra() {
        let mut body = vec![3u8, Kind::Message as u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(
            parse(&text, &mut buf),
            Err(Error::UnsupportedVersion(3))
        ));
    }

    #[test]
    fn tier_riservato_si_parsa_il_rifiuto_arriva_dopo() {
        // The parser accepts ForwardSecret without complaint: `baseline` must
        // return TierUnsupported. Mixing the two levels would make "cannot
        // read" indistinguishable from "cannot run".
        let h = Header {
            tier: Tier::ForwardSecret,
            ..header(Some(pubkey(3)))
        };
        let text = serialize_message(&h, &ciphertext());

        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = parse(&text, &mut buf).unwrap() else {
            panic!("atteso un messaggio");
        };
        assert_eq!(parsed.header.tier, Tier::ForwardSecret);
    }

    /// Unknown `kind` and unknown `tier` give **different** errors, on purpose.
    ///
    /// An unknown `kind` is a malformed blob: kinds are closed, with no reserved
    /// space. `Format` is right.
    ///
    /// An unknown `tier` is the one slot of the format explicitly kept free for
    /// a future scheme (decision L). The reader is not looking at a damaged blob
    /// but at a newer message, and the right sentence is "update the app":
    /// `TierUnsupported`.
    #[test]
    fn kind_e_tier_sconosciuti() {
        let mut buf = Vec::new();

        let mut body = vec![PROTOCOL_VERSION, 42u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));

        let mut body = vec![PROTOCOL_VERSION, Kind::Message as u8, 42u8, 0u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));
        assert!(matches!(parse(&text, &mut buf), Err(Error::TierUnsupported)));
    }

    /// Tier **2** is reserved for the hybrid exchange, and this test defends
    /// the reservation.
    ///
    /// It does not test a scheme that does not exist: it checks that a message
    /// using it one day is rejected **with the right message**. This is the
    /// only testable part of the reservation, and the one that could not be
    /// added later.
    #[test]
    fn il_tier_ibrido_dice_aggiorna_non_corrotto() {
        let mut buf = Vec::new();
        let mut body = vec![PROTOCOL_VERSION, Kind::Message as u8, 2u8, 0u8];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));
        assert!(matches!(parse(&text, &mut buf), Err(Error::TierUnsupported)));
    }

    #[test]
    fn flag_non_definiti_rifiutati() {
        let mut body = vec![PROTOCOL_VERSION, Kind::Message as u8, 0u8, 0b1000_0000];
        body.extend_from_slice(&[0u8; 64]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    /// Mandatory negative test: flags inconsistent with length. SENDER_PUB is
    /// set but the body has no room for the 32 bytes.
    #[test]
    fn flag_sender_pub_incoerente_con_la_lunghezza() {
        let mut body = vec![
            PROTOCOL_VERSION,
            Kind::Message as u8,
            Tier::Baseline as u8,
            Flags::SENDER_PUB.0,
        ];
        // Fewer than the 32 key bytes, let alone nonce and ciphertext.
        body.extend_from_slice(&[0u8; 20]);
        let text = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    #[test]
    fn ciphertext_piu_corto_del_tag() {
        let h = header(Some(pubkey(9)));
        let text = serialize_message(&h, &[0u8; TAG_LEN - 1]);

        let mut buf = Vec::new();
        assert!(matches!(parse(&text, &mut buf), Err(Error::Format(_))));
    }

    /// Flipping each bit of the SIGNIFICANT part of a card, one at a time, must
    /// never produce a card.
    ///
    /// The assertion is "no card comes out", not "the result is an error":
    /// flipping a `kind` bit turns the card into a syntactically valid message,
    /// which is harmless (no wrong key gets pinned). Pinning a corrupted key is
    /// exactly what the checksum exists to prevent.
    ///
    /// Padding is excluded on purpose: it is not covered by the checksum and
    /// altering it must change nothing (next test).
    #[test]
    fn nessun_bit_flip_produce_una_card() {
        let key = pubkey(0x11);
        let text = serialize_identity_card(&key, &mut rng(4));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let originale = encoding::decode(payload).unwrap();

        for i in 0..card_body_len() {
            for bit in 0..8u8 {
                let mut body = originale.clone();
                let Some(slot) = body.get_mut(i) else { continue };
                *slot ^= 1 << bit;

                let mutato = format!("{SENTINEL}{}", encoding::encode(&body));
                let mut buf = Vec::new();
                assert!(
                    !matches!(parse(&mutato, &mut buf), Ok(ParsedBlob::IdentityCard(_))),
                    "bit {bit} del byte {i} passato inosservato"
                );
            }
        }
    }

    #[test]
    fn il_riempimento_non_influenza_la_chiave() {
        let key = pubkey(0x12);
        let text = serialize_identity_card(&key, &mut rng(5));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let mut body = encoding::decode(payload).unwrap();
        assert!(body.len() > card_body_len(), "questa card non ha riempimento");

        for i in card_body_len()..body.len() {
            let Some(slot) = body.get_mut(i) else { continue };
            *slot ^= 0xFF;
        }
        let mutato = format!("{SENTINEL}{}", encoding::encode(&body));

        let mut buf = Vec::new();
        let ParsedBlob::IdentityCard(card) = parse(&mutato, &mut buf).unwrap() else {
            panic!("attesa una identity card");
        };
        assert_eq!(card.public, key);
    }

    #[test]
    fn troncamento_card_sotto_la_parte_significativa() {
        let text = serialize_identity_card(&pubkey(0x22), &mut rng(6));
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let body = encoding::decode(payload).unwrap();

        for len in 0..card_body_len() {
            let troncato = body.get(..len).unwrap();
            let text = format!("{SENTINEL}{}", encoding::encode(troncato));
            let mut buf = Vec::new();
            assert!(
                !matches!(parse(&text, &mut buf), Ok(ParsedBlob::IdentityCard(_))),
                "troncamento a {len} byte accettato come card"
            );
        }
    }

    /// A message has a variable-length ciphertext, which imposes a limit worth
    /// understanding: **the parser cannot tell that a ciphertext was
    /// truncated.**
    ///
    /// Cutting the last bytes yields a well-formed message with a shorter
    /// ciphertext. No length field contradicts it, and adding one would not
    /// help: it would be in clear and an attacker would adjust it along with the
    /// rest. The Poly1305 tag catches it at decryption; `parse` returning `Ok`
    /// says nothing about integrity.
    #[test]
    fn troncamento_messaggio_rifiutato_fino_al_tag() {
        let text = serialize_message(&header(Some(pubkey(4))), &ciphertext());
        let payload = text.strip_prefix(SENTINEL).unwrap();
        let body = encoding::decode(payload).unwrap();

        let soglia = MESSAGE_PREFIX_LEN + KEY_LEN + NONCE_LEN + TAG_LEN;

        for len in 0..body.len() {
            let troncato = body.get(..len).unwrap();
            let text = format!("{SENTINEL}{}", encoding::encode(troncato));
            let mut buf = Vec::new();
            let esito = parse(&text, &mut buf);

            if len < soglia {
                assert!(esito.is_err(), "troncamento a {len} byte accettato");
            } else {
                assert!(esito.is_ok(), "troncamento a {len} byte rifiutato");
            }
        }
    }

    /// The version is not among the cases: it is not a free field of `Header`
    /// but the crate constant, so a header with an inconsistent version cannot
    /// be built.
    #[test]
    fn aad_cambia_con_ogni_campo() {
        let base = header(Some(pubkey(0x33)));
        let riferimento = build_aad(Kind::Message, &base);

        assert_ne!(build_aad(Kind::IdentityCard, &base), riferimento);

        let altro_tier = Header {
            tier: Tier::ForwardSecret,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altro_tier), riferimento);

        let altro_sender = Header {
            origin: Origin::Mittente(pubkey(0x44)),
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &altro_sender), riferimento);

        let senza_sender = Header {
            origin: Origin::Assente,
            ..base.clone()
        };
        assert_ne!(build_aad(Kind::Message, &senza_sender), riferimento);
    }

    /// The AAD does not cover the nonce, on purpose: the nonce is already an
    /// input of the AEAD, so altering it makes authentication fail without
    /// authenticating it a second time.
    #[test]
    fn aad_non_copre_il_nonce() {
        let base = header(Some(pubkey(0x55)));
        let altro_nonce = Header {
            nonce: [9u8; NONCE_LEN],
            ..base.clone()
        };
        assert_eq!(
            build_aad(Kind::Message, &altro_nonce),
            build_aad(Kind::Message, &base)
        );
    }

    /// Regression anchor for the format, not an external authority: pins the
    /// exact string produced from known inputs. If it breaks, the wire format
    /// (i.e. compatibility) changed, not the code.
    #[test]
    fn kat_formato() {
        let h = Header {
            tier: Tier::Baseline,
            origin: Origin::Mittente(PublicKey::from_bytes([0x42; KEY_LEN])),
            nonce: [0x24; NONCE_LEN],
        };
        let ct: Vec<u8> = (0..32u8).collect();
        assert_eq!(serialize_message(&h, &ct), KAT_MESSAGGIO);

        let card = serialize_identity_card(&PublicKey::from_bytes([0x42; KEY_LEN]), &mut rng(0));
        assert_eq!(card, KAT_IDENTITY_CARD);
    }

    const KAT_MESSAGGIO: &str = "kc/yryyyyknejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nee1nejbrro1nejbrro1nejbrro1nejbrro1nejbryyyoryarywdyqnyjbefoadeqbhebnrounoktcfaadrpbs8y7daxo";
    const KAT_IDENTITY_CARD: &str = "kc/yryoyo1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nejbrro1nk9yhjwfy6r63yon7pm1i8bi7fn67rgpawng64gieg5zh3n5zbzd7wok3xteiq1rpqh1qyx7a5bfdq41dzd4bkgfbdubaxpujsmzgmbw9y9u5hikt8b7jtqwzxt314nyp3c81uenehp1s1rsgkc9df5u47ww5qemsuuurho6iqr35y7ga88kud5e9fbeoi64fiuoow84mxfgs6mejwduggjo";
}
