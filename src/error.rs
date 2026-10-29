//! The single public error type of the crate. No panics.

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("formato non valido: {0}")]
    Format(&'static str),

    #[error("versione di protocollo non supportata: {0}")]
    UnsupportedVersion(u8),

    /// The text is not a blob of this system. A NORMAL outcome, not a
    /// failure: the keyboard uses it to decide whether to offer "decrypt" on
    /// arbitrary clipboard text.
    #[error("sentinel non riconosciuto: il testo non e' un blob di questo sistema")]
    NotOurBlob,

    #[error("decodifica z-base-32 fallita")]
    Decode,

    /// DELIBERATELY opaque. Never distinguish "invalid tag" from "wrong key"
    /// from "corrupted nonce" towards the caller: that would be a channel that
    /// helps an attacker. One error for every AEAD failure. Do not add more
    /// specific variants to improve diagnostics.
    #[error("decifratura/autenticazione fallita")]
    Crypto,

    /// The operation needs an already pinned peer and the message declares a
    /// sender that is not in the keyring.
    #[error("peer sconosciuto per questa operazione")]
    UnknownPeer,

    /// The blob uses a tier this build cannot execute: "update the app".
    #[error("tier non supportato dalla build corrente")]
    TierUnsupported,

    /// The blob declares OUR key as sender: we wrote it, and only the
    /// recipient can open it.
    ///
    /// This does **not** break the opacity of [`Error::Crypto`]: the decision
    /// is made before any decryption attempt, from a clear-text header field
    /// that anyone can read. Someone crafting a blob with our public key learns
    /// nothing they did not put there.
    ///
    /// It exists because the case is common (send a message, then copy it
    /// again), and reporting it as a crypto failure makes expected behaviour
    /// look broken.
    #[error("questo messaggio l'hai scritto tu: puo' aprirlo solo il destinatario")]
    OwnMessage,

    /// Like [`Error::OwnMessage`], with a different cause that the user
    /// message must reflect.
    ///
    /// [`Error::OwnMessage`] applies where reopening goes through
    /// **identities** (baseline scheme, epoch bootstrap, attachments): there,
    /// failing for every contact means only one thing, the recipient is no
    /// longer in the keyring.
    ///
    /// This one applies where reopening needs a **recipient-side** key: a
    /// non-bootstrap epoch message reopens only with the epoch key it was
    /// sealed to. That key is one per contact and gets overwritten (rotated,
    /// or replaced by a prekey when the contact has forward secrecy on). The
    /// contact is still there; the key is not. A burned conversation ends here
    /// too.
    ///
    /// Not a leak through [`Error::Crypto`]: the decision is made from
    /// clear-text header fields ("the sender is me", "the scheme is epoch")
    /// before any decryption attempt, and says nothing about why an AEAD
    /// failed.
    #[error("questo messaggio l'hai scritto tu, e la chiave verso cui era cifrato non c'e' piu'")]
    OwnMessageKeyGone,

    /// [`crate::keys::Keyring`] is implemented outside the core (encrypted
    /// storage on Android); its failures surface here without details.
    #[error("errore del keyring")]
    Keyring,
}

pub type Result<T> = core::result::Result<T, Error>;
