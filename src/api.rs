//! The surface the JNI layer calls (Rust/JVM boundary).
//!
//! The JNI crate depends on this one and holds the `extern` symbols; there are
//! none here. The JVM only sends and receives plaintext and ciphertext; private
//! keys and the keyring stay on this side of the boundary.
//!
//! Rule for secrets: return `byte[]` to the JVM, never `String`. A
//! `java.lang.String` is immutable and cannot be zeroized, so plaintext put
//! into one stays on the heap until GC. That is why these types expose
//! [`Plaintext`] rather than `String`.
//!
//! # Why the current recipient is per app
//!
//! A keyboard does not know who you are talking to: `EditorInfo` gives the
//! app's package, not the conversation, and there is no API for it. The only
//! thing that could tell is an accessibility service reading the screen, which
//! is excluded: it would destroy the premise of the project.
//!
//! So the recipient is established by approximation, in this order:
//!
//!   1. implicitly, by decrypting: whoever reads a message and then replies
//!      (almost everyone, almost always) never chooses anything, having chosen
//!      by reading;
//!   2. by memory, remembering the last peer used in THAT app: someone with one
//!      contact per app never touches anything;
//!   3. explicitly, from the toolbar, for several contacts in the same app.
//!
//! The third is the fallback: if users need it often, the first two are not
//! working. What is NEVER done is guessing: encrypting for the wrong person is
//! the worst possible failure, so with no peer the result is
//! [`Error::UnknownPeer`] and the user is asked.

use std::collections::HashMap;

use rand_core::{CryptoRng, RngCore};

use crate::baseline::{self, Plaintext};
use crate::file::{self, DecryptedFile, FileMeta};
use crate::error::{Error, Result};
use crate::format::{self, ParsedBlob};
use crate::keys::{self, Fingerprint, Identity, Keyring, LabelOutcome, PinOutcome, PublicKey};

/// Live state of the core, owned by the JNI layer for the session.
pub struct Session<K: Keyring> {
    identity: Identity,
    keyring: K,
    /// Current recipient per Android package (`com.whatsapp`, ...).
    /// Deliberately NOT persisted here: it is session state, and storage lives
    /// outside the core.
    current_peer: HashMap<String, PublicKey>,
}

/// TOFU state of the sender of a message just decrypted. Drives what the UI
/// shows: a successful decryption does not imply the sender is the expected
/// one.
#[derive(Debug, PartialEq, Eq)]
pub enum SenderStatus {
    /// Never-seen key: pinned now, **without a label**. The UI should ask the
    /// user who it is; that is where a key change comes to light, because
    /// assigning a label already in use yields [`LabelOutcome::Conflict`].
    New,
    /// Already pinned key. `label` is `None` if the user never named it.
    Known {
        label: Option<String>,
        verified: bool,
    },
}

/// Result of a successful decryption.
pub struct DecryptedMessage {
    /// Who built the message.
    ///
    /// **For a group (`destinatari > 1`) this is NOT the author of the text**,
    /// and the UI must respect that (decision K6). Opening a slot proves its
    /// builder knew `DH(sender, recipient)`, so the field is not false, only
    /// insufficient: the payload is encrypted with a key every member has, and
    /// any of them can rewrite it keeping the original slots.
    ///
    /// It tells who you are talking to, not who wrote the text.
    pub sender: PublicKey,
    pub sender_status: SenderStatus,
    pub plaintext: Plaintext,
    /// This message came from a **group**.
    ///
    /// An explicit flag rather than a threshold on the count: deducing it from
    /// `destinatari > 1` let a one-slot blob pass as a one-to-one message while
    /// being a `version = 2` blob without forward secrecy. The parser now
    /// rejects groups under two slots, but the flag stays: deducing a fact from
    /// a threshold is fragile.
    pub gruppo: bool,
    /// How many slots the blob had, i.e. how many people could read it, sender
    /// included. **`0` when [gruppo] is false**.
    pub destinatari: usize,
}

/// Why one of our epoch messages did not reopen.
///
/// The user's question is "where did my contact go?". There are three real
/// causes, told apart with what is already known, without extra decryption
/// attempts:
///
///  - **no contacts at all**: then indeed there is nobody to try;
///  - **bootstrap**: the first message of a conversation reopens with the
///    identities alone, which do not change or expire. If it fails for every
///    contact, the recipient is not among them;
///  - **everything else**: it reopened with the recipient's epoch key, which is
///    one per contact and gets overwritten, or deleted by a burn. The contact
///    is still there; the key of that time is not.
fn perche_non_si_riapre(bootstrap: bool, contatti: usize) -> Error {
    if contatti == 0 || bootstrap {
        Error::OwnMessage
    } else {
        Error::OwnMessageKeyGone
    }
}

/// A new secret for a temporary key.
fn nuovo_segreto<R: RngCore + CryptoRng>(rng: &mut R) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    rng.fill_bytes(&mut bytes);
    bytes
}

/// A decrypted attachment, with the TOFU state of its sender.
pub struct IncomingFile {
    /// Who sent it, **or**, when `nostro` is true, whom we sent it to. One
    /// field because it is always "the other person"; `nostro` tells how to
    /// label it.
    pub sender: PublicKey,
    pub sender_status: SenderStatus,
    pub file: DecryptedFile,
    /// We sent it and reopened it. Only without forward secrecy.
    pub nostro: bool,
}

/// What the incoming text turned out to be.
pub enum IncomingItem {
    Message(DecryptedMessage),
    /// One of **our** messages, reopened. Happens when copying what one just
    /// sent, and is presented as such: there is no sender to show, there is a
    /// recipient.
    ///
    /// Only without forward secrecy. With the chain on, the key no longer
    /// exists and there is nothing to reopen, for anyone.
    OwnMessage {
        recipient: PublicKey,
        recipient_label: Option<String>,
        plaintext: Plaintext,
    },
    /// The other side asked to burn, and we did: the keys that read that
    /// conversation no longer exist on this side. There is no text to show.
    ///
    /// `sent_at_unix` is the time the SENDER wrote inside the ciphertext:
    /// authenticated, not verifiable, and to be **shown**, never used for
    /// decisions (decision C). A burn blob stays valid forever and can be
    /// pasted again later to destroy a conversation that restarted in the
    /// meantime; that cannot be prevented without rejecting by date, but it can
    /// be made VISIBLE: a request from August arriving in November stands out
    /// if the date is on screen.
    Burned {
        peer: PublicKey,
        sent_at_unix: i64,
    },
    /// Our own identity card, reopened. Nothing is pinned: see the branch that
    /// produces it.
    OwnIdentityCard { fingerprint: Fingerprint },
    /// An identity card: no message to show, only a key to pin. The UI shows
    /// the fingerprint and the pin outcome.
    IdentityCard {
        peer: PublicKey,
        fingerprint: Fingerprint,
        outcome: PinOutcome,
    },
}

impl<K: Keyring> Session<K> {
    pub fn new(identity: Identity, keyring: K) -> Self {
        Self {
            identity,
            keyring,
            current_peer: HashMap::new(),
        }
    }

    /// Identity card blob to insert into the text field.
    ///
    /// It does not go through the clipboard: the keyboard writes it straight
    /// into the field it is serving (`commitText`) and the user presses send.
    /// Inserting is native for an IME, reading is not.
    ///
    /// The key is ONE, the same for every recipient: there is no per-contact
    /// card. The RNG is needed for the padding that keeps cards from all having
    /// the same length.
    pub fn identity_card<R: RngCore + CryptoRng>(&self, rng: &mut R) -> String {
        format::serialize_identity_card(&self.identity.public(), rng)
    }

    pub fn my_fingerprint(&self) -> Fingerprint {
        self.identity.fingerprint()
    }

    /// Read-only access to the keyring, for persisting or displaying it.
    /// Mutation only goes through [`Session`] methods, so pins cannot be
    /// modified bypassing the TOFU rules.
    pub fn keyring(&self) -> &K {
        &self.keyring
    }

    /// The session identity, for the encrypted backup.
    ///
    /// Exposing it opens no hole: outside the crate an [`Identity`] does not
    /// let the private key be extracted (the raw-bytes accessor is
    /// `pub(crate)` with a single caller, [`crate::backup`]).
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    /// Recognises and handles arbitrary incoming text.
    ///
    /// Transport-neutral on purpose: the four ways a blob can reach the
    /// keyboard (clipboard, `ACTION_PROCESS_TEXT`, share sheet, input field)
    /// all deliver the same string, and the core must not know which one.
    ///
    /// Returns [`Error::NotOurBlob`] if there is no sentinel: a normal outcome,
    /// the case for the vast majority of texts. The keyboard uses it to decide
    /// whether to show "decrypt".
    ///
    /// `now_unix` is injected because the core does not read the system clock.
    pub fn handle_incoming_text(
        &mut self,
        app_package: &str,
        text: &str,
        now_unix: i64,
    ) -> Result<IncomingItem> {
        let mut buf = Vec::new();
        match format::parse(text, &mut buf)? {
            // A burn is recognised by its kind, which is in the AAD: it is not a
            // disguised message, and a message cannot become one.
            ParsedBlob::Burn(parsed) => {
                let (peer, sent_at_unix) = self.mittente_di_un_rogo(&parsed)?;
                // A burn already honoured is not redone. A blob stays valid
                // forever: whoever saw it pass in the chat could paste it again
                // months later and destroy the conversation restarted meanwhile.
                //
                // This is not a judgement on the date (decision C forbids that):
                // it refuses to **redo** something already done, comparing with
                // what we already honoured from them. The answer is `Crypto`:
                // anything else would tell the reposter the blob was good.
                //
                // The comparison uses the **smaller** of the declared date and
                // ours, as in `ricorda_prekey` and `ricorda_epoca_del_peer`. A
                // burn request dated in the future would otherwise push
                // `burned_at` years ahead and **every later burn from that
                // person would be rejected**, silently. Capping at `now_unix`
                // keeps the replay defence intact (an old blob has an old date
                // anyway) while an absurd date can no longer disable the feature.
                let quando = sent_at_unix.min(now_unix);
                if quando <= self.keyring.burned_at(&peer)? {
                    return Err(Error::Crypto);
                }
                self.keyring.set_burned_at(&peer, quando)?;
                self.keyring.burn_conversation(&peer)?;
                Ok(IncomingItem::Burned { peer, sent_at_unix })
            }
            ParsedBlob::Message(parsed)
                if parsed.header.origin.uses_epoch()
                    || parsed.header.origin.is_epoch_bootstrap() =>
            {
                let (peer, plaintext, nostro) = self.apri_a_epoca(&parsed, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), peer.clone());
                if nostro {
                    let recipient_label = self.keyring.get(&peer)?.and_then(|r| r.label);
                    return Ok(IncomingItem::OwnMessage {
                        recipient: peer,
                        recipient_label,
                        plaintext,
                    });
                }
                let sender_status = self.pin_and_classify(&peer, now_unix)?;
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender: peer,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::Message(parsed) if parsed.header.origin.uses_prekey() => {
                let (sender, plaintext) = self.prova_con_le_prekey(&parsed, now_unix)?;
                let sender_status = self.pin_and_classify(&sender, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), sender.clone());
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::Message(parsed) if parsed.header.origin.is_ephemeral() => {
                // Ephemeral sender: the writer is not declared and is found by
                // trying. The first key that opens the message IS the sender,
                // because the derivation needs their private key.
                let (sender, prekey, plaintext) = self.prova_i_contatti(&parsed)?;
                // From here on we can reply with full forward secrecy: the chain
                // has started.
                self.ricorda_prekey(&sender, &prekey, plaintext.sent_at_unix(), now_unix)?;
                let sender_status = self.pin_and_classify(&sender, now_unix)?;
                self.current_peer
                    .insert(app_package.to_owned(), sender.clone());
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::Message(parsed) => {
                let sender = parsed
                    .header
                    .sender_pub()
                    .cloned()
                    .ok_or(Error::Format("messaggio senza pubkey del mittente"))?;

                // We wrote it: reopen by trying our contacts as RECIPIENTS, the
                // one thing the header does not say. Recognised from a clear
                // field before any decryption attempt, so it is not inferred
                // from an AEAD failure and does not affect the opacity of
                // `Crypto`.
                if sender == self.identity.public() {
                    return self.riapri_un_mio_messaggio(app_package, &parsed);
                }

                // CRITICAL ORDER: decrypt BEFORE touching the keyring.
                //
                // A successful decryption proves the writer really holds the
                // private key of `sender` and that the message was for us.
                // Pinning first would let anyone fill the keyring with invented
                // peers, or trigger a false conflict on a real contact by
                // sending garbage under some key: the UI would show "Mark's key
                // changed" at a stranger's command.
                let plaintext = baseline::open(&self.identity, &sender, &parsed)?;

                let sender_status = self.pin_and_classify(&sender, now_unix)?;

                // The sender just read becomes the recipient for this app: this
                // makes the dominant case (read, then reply) automatic.
                self.current_peer
                    .insert(app_package.to_owned(), sender.clone());

                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: false,
                    destinatari: 0,
                    sender,
                    sender_status,
                    plaintext,
                }))
            }
            // Group messages (decision K). Kept as an explicit branch with an
            // error-free path rather than `unreachable!()`: an unexpected blob
            // must produce a message, not kill the process.
            ParsedBlob::Group(parsed) => {
                let (mittente, plaintext) = self.apri_di_gruppo(&parsed)?;
                // If our own key opened it, we are rereading our own message:
                // **nothing is pinned**. Without this guard `tofu_pin` added
                // the user to their own contacts, and the UI got "unknown
                // sender" on a message they wrote. The static path catches its
                // own sender before decrypting, the epoch path uses the
                // `nostro` flag; groups needed the same guard.
                let sender_status = if mittente == self.identity.public() {
                    // Not `New`, which would ask "who is this?" about one's own
                    // words. Group authors are not shown anyway (K6).
                    SenderStatus::Known {
                        label: None,
                        verified: false,
                    }
                } else {
                    self.pin_and_classify(&mittente, now_unix)?
                };
                // **The current recipient is not changed**, on purpose. "Decrypting
                // establishes who you are talking to" holds between two people;
                // here the other end is a group, and choosing the sender alone
                // would send the reply privately to them, inside the chat where
                // everyone else expects it. The writer chooses the group.
                Ok(IncomingItem::Message(DecryptedMessage {
                    gruppo: true,
                    destinatari: parsed.slot_count(),
                    sender: mittente,
                    sender_status,
                    plaintext,
                }))
            }
            ParsedBlob::IdentityCard(card) => {
                // Pin the key, and NOTHING ELSE.
                //
                // In particular the current recipient is not changed, however
                // convenient. An identity card is not authenticated (it is the
                // first contact by construction), so anyone can craft one with
                // their own key and get it to the victim. If decrypting it were
                // enough to become the recipient, a stranger would decide whom
                // the victim encrypts for. Implicit selection is authorised only
                // by a SUCCESSFUL decryption of a message, which proves the
                // writer holds the declared key. A card proves nothing, so it
                // decides nothing: choosing the recipient takes an explicit user
                // action (`set_current_peer`).
                //
                // Our own card is not pinned either: reopening it used to create
                // a contact that is oneself, a name one could even encrypt to. Not
                // a security hole (the key is ours already) but an address book
                // that lies. It is reported separately from "already known",
                // which would be true and useless.
                if card.public == self.identity.public() {
                    return Ok(IncomingItem::OwnIdentityCard {
                        fingerprint: Fingerprint::of(&card.public),
                    });
                }
                let outcome = self.keyring.tofu_pin(&card.public, now_unix)?;
                Ok(IncomingItem::IdentityCard {
                    fingerprint: Fingerprint::of(&card.public),
                    peer: card.public,
                    outcome,
                })
            }
        }
    }

    /// Pins the sender and translates the outcome into a display state.
    fn pin_and_classify(&mut self, sender: &PublicKey, now_unix: i64) -> Result<SenderStatus> {
        match self.keyring.tofu_pin(sender, now_unix)? {
            PinOutcome::Pinned => Ok(SenderStatus::New),
            PinOutcome::AlreadyPinned => {
                let record = self.keyring.get(sender)?;
                Ok(SenderStatus::Known {
                    label: record.as_ref().and_then(|r| r.label.clone()),
                    verified: record.map(|r| r.verified).unwrap_or(false),
                })
            }
        }
    }

    /// Assigns a name to a key: the point where TOFU becomes able to say
    /// "Mark's key changed".
    ///
    /// On [`LabelOutcome::Conflict`] nothing changes: the UI shows both
    /// fingerprints and, only if the user confirms, calls
    /// [`Self::confirm_key_change`].
    pub fn assign_label(&mut self, peer: &PublicKey, label: &str) -> Result<LabelOutcome> {
        self.keyring.assign_label(peer, label)
    }

    /// Encrypts a text for the current recipient of the given app.
    ///
    /// Returns [`Error::UnknownPeer`] if that app has no recipient: the UI must
    /// ask, never guess.
    pub fn encrypt_for_app<R: RngCore + CryptoRng>(
        &mut self,
        app_package: &str,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        self.encrypt_for_app_with(app_package, plaintext, now_unix, rng, false)
    }

    /// Like [`Self::encrypt_for_app`], choosing whether to use the ephemeral
    /// sender.
    ///
    /// The choice belongs to the caller, not the core, because it is about
    /// **compatibility**, not cryptography: an older version cannot open an
    /// ephemeral-sender message. The core does not know the recipient's
    /// version, and guessing would produce unreadable messages.
    pub fn encrypt_for_app_with<R: RngCore + CryptoRng>(
        &mut self,
        app_package: &str,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
        effimero: bool,
    ) -> Result<String> {
        let peer = self
            .current_peer
            .get(app_package)
            .ok_or(Error::UnknownPeer)?
            .clone();
        if !effimero {
            return self.cifra_a_epoca(&peer, plaintext, now_unix, rng);
        }

        // With a temporary key of the recipient we get full forward secrecy;
        // without one (first message, or no reply yet) we fall back to half,
        // which still protects what we send. Not a forceable downgrade: it
        // depends on what THEY sent us, not on what a message declares.
        match self.keyring.peer_prekey(&peer)?.filter(|k| self.identity.diffie_hellman(k).is_ok()) {
            Some(sua_prekey) => {
                let mia = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
                let blob = baseline::seal_forward(
                    &self.identity,
                    &peer,
                    &sua_prekey,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                // Stored AFTER encrypting: if encryption failed we would have
                // saved a useless key.
                self.keyring.push_my_prekey(&peer, *mia.to_bytes())?;
                Ok(blob)
            }
            None => {
                // The fallback carries a temporary key of ours too: that is what
                // STARTS the chain. Without it the recipient would never get a
                // prekey of ours and full forward secrecy would never begin.
                let mia = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
                let blob = baseline::seal_ephemeral(
                    &self.identity,
                    &peer,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                self.keyring.push_my_prekey(&peer, *mia.to_bytes())?;
                Ok(blob)
            }
        }
    }

    /// Encrypts a file for an **explicitly chosen** peer (decision G4).
    ///
    /// No `app_package` and no implicit recipient: this path starts from a
    /// screen, not from the keyboard, and a file sent to the wrong person
    /// cannot be withdrawn.
    ///
    /// The peer must already be in the keyring: no encrypting to a never-seen
    /// key, as in [`Self::set_current_peer`].
    pub fn encrypt_file<R: RngCore + CryptoRng>(
        &self,
        peer: &PublicKey,
        meta: &FileMeta,
        content: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<Vec<u8>> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        file::seal_file(&self.identity, peer, meta, content, now_unix, rng)
    }

    /// [`Self::encrypt_file`] with the forward secrecy chain.
    ///
    /// An attachment without the chain is a bigger hole than a message without
    /// it: a photo is worth more than a line of text, and stays on the
    /// recipient's phone. With `forward = false` it falls back to static-static,
    /// for recipients on an older version.
    ///
    /// **Uses the same state as messages**: same conversation, same person.
    pub fn encrypt_file_with<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        meta: &FileMeta,
        content: &[u8],
        now_unix: i64,
        rng: &mut R,
        forward: bool,
    ) -> Result<Vec<u8>> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        if !forward {
            return file::seal_file(&self.identity, peer, meta, content, now_unix, rng);
        }
        // The `filter` is not redundant with `ricorda_prekey`: state saved by an
        // older version may already contain an unusable key, and then the only
        // sensible thing is to fall back rather than be unable to write to that
        // person.
        let sua = self
            .keyring
            .peer_prekey(peer)?
            .filter(|k| self.identity.diffie_hellman(k).is_ok());
        let mia = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
        let blob = file::seal_file_forward(
            &self.identity,
            peer,
            sua.as_ref(),
            &mia.public(),
            meta,
            content,
            now_unix,
            rng,
        )?;
        // After encrypting: if it failed, we would have saved a useless key.
        self.keyring.push_my_prekey(peer, *mia.to_bytes())?;
        Ok(blob)
    }

    /// Opens a received attachment.
    ///
    /// Same critical order as messages: **decrypt before touching the
    /// keyring**. Pinning first would let anyone fill the keyring by sending an
    /// arbitrary attachment.
    ///
    /// Unlike a message it **chooses no recipient**: there is no originating
    /// app to attribute it to, and guessing could make the next message go to
    /// the wrong person.
    pub fn handle_incoming_file(&mut self, bytes: &[u8], now_unix: i64) -> Result<IncomingFile> {
        let parsed = file::parse_file(bytes)?;

        // As for messages: with an ephemeral sender the file does not say who
        // sent it, and that is found by trying contacts. Senders outside the
        // keyring stay unknown, on purpose.
        let (sender, decrypted) = if parsed.header.origin.uses_prekey() {
            self.prova_le_prekey_sul_file(&parsed, now_unix)?
        } else if parsed.header.origin.is_ephemeral() {
            let (chi, prekey, aperto) = self.prova_i_contatti_sul_file(&parsed)?;
            self.ricorda_prekey(&chi, &prekey, aperto.sent_at_unix, now_unix)?;
            (chi, aperto)
        } else {
            let sender = parsed
                .header
                .sender_pub()
                .cloned()
                .ok_or(Error::Format("allegato senza pubkey del mittente"))?;
            // We sent it: reopen by trying contacts as recipients, as for a
            // message.
            if sender == self.identity.public() {
                for candidato in self.keyring.peers()? {
                    let Ok(aperto) =
                        file::open_file_as_sender(&self.identity, &candidato, &parsed)
                    else {
                        continue;
                    };
                    let sender_status = self.pin_and_classify(&candidato, now_unix)?;
                    return Ok(IncomingFile {
                        sender: candidato,
                        sender_status,
                        file: aperto,
                        nostro: true,
                    });
                }
                return Err(Error::OwnMessage);
            }
            let aperto = file::open_file(&self.identity, &sender, &parsed)?;
            (sender, aperto)
        };
        let sender_status = self.pin_and_classify(&sender, now_unix)?;

        Ok(IncomingFile {
            sender,
            sender_status,
            file: decrypted,
            nostro: false,
        })
    }

    /// Reopens one of our messages by trying contacts as recipients.
    ///
    /// **Pins nothing:** the sender is us. It does move the app's current
    /// recipient, by the usual rule: whoever rereads what they sent to Mark is
    /// looking at the conversation with Mark.
    ///
    /// If all fail, [`Error::OwnMessage`]: we know it is ours because it says
    /// so, but the recipient is no longer among the contacts.
    fn riapri_un_mio_messaggio(
        &mut self,
        app_package: &str,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<IncomingItem> {
        for candidato in self.keyring.peers()? {
            let Ok(plaintext) = baseline::open_as_sender(&self.identity, &candidato, parsed) else {
                continue;
            };
            let recipient_label = self
                .keyring
                .get(&candidato)?
                .and_then(|record| record.label);
            self.current_peer
                .insert(app_package.to_owned(), candidato.clone());
            return Ok(IncomingItem::OwnMessage {
                recipient: candidato,
                recipient_label,
                plaintext,
            });
        }
        Err(Error::OwnMessage)
    }

    /// Encrypts **with an epoch** (decision J): the conversation stays readable
    /// until it is burned.
    ///
    /// Two cases, depending only on what we already have:
    ///
    /// - if the contact already sent us their epoch key, encrypt to it. The
    ///   message is rereadable by both and dies for both when the two keys are
    ///   destroyed;
    /// - otherwise (first message, or right after a burn) use the epoch
    ///   bootstrap, which **carries our epoch key** without needing theirs. This
    ///   is how the conversation restarts after a burn without a handshake or a
    ///   return channel.
    fn cifra_a_epoca<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        let mia = self.mia_epoca(peer, rng)?;
        // The contact's EPOCH key, not their prekey. They used to share a field,
        // and with forward secrecy on at the other side we ended up encrypting to
        // a key whose private half they look for among their prekeys.
        match self.epoca_del_peer(peer)? {
            Some(sua) => {
                let (header, ciphertext) = baseline::seal_epoch(
                    &self.identity,
                    &sua,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                Ok(format::serialize_message(&header, &ciphertext))
            }
            None => {
                let (header, ciphertext) = baseline::seal_epoch_bootstrap(
                    &self.identity,
                    peer,
                    &mia.public(),
                    plaintext,
                    now_unix,
                    rng,
                )?;
                Ok(format::serialize_message(&header, &ciphertext))
            }
        }
    }

    /// Our epoch key towards that contact, created if missing.
    ///
    /// **Not renewed on every message**: that is the only mechanical
    /// difference from the chain, and what makes history exist. It changes only
    /// on a burn.
    fn mia_epoca<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        rng: &mut R,
    ) -> Result<keys::EphemeralSecret> {
        // This used to take `my_prekeys(peer).first()`, the newest of the CHAIN:
        // the epoch then changed whenever the chain advanced, and reading a
        // forward-secret message dropped it altogether, making the burnable
        // conversation unreadable with nobody burning it. Probe:
        // `leggere_un_messaggio_non_brucia_l_epoca`.
        if let Some(segreto) = self.keyring.my_epoch(peer)? {
            return Ok(keys::EphemeralSecret::from_bytes(*segreto));
        }
        let nuova = keys::EphemeralSecret::from_bytes(nuovo_segreto(rng));
        self.keyring.set_my_epoch(peer, *nuova.to_bytes())?;
        Ok(nuova)
    }

    /// **Burns the conversation** with a contact (decision J).
    ///
    /// Two different things:
    ///
    /// 1. **final on this side**: the keys that read that conversation are
    ///    destroyed and do not come back;
    /// 2. **a request on the other side**. The returned blob must be delivered
    ///    to the other person; if their app honours it, it destroys theirs. It
    ///    cannot be enforced, and this function does not promise otherwise.
    ///
    /// The blob is produced **before** destroying: afterwards the key to
    /// encrypt it would be gone.
    pub fn burn_conversation<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        let richiesta = self.cifra_richiesta_di_rogo(peer, now_unix, rng)?;
        self.keyring.burn_conversation(peer)?;
        Ok(richiesta)
    }

    fn cifra_richiesta_di_rogo<R: RngCore + CryptoRng>(
        &mut self,
        peer: &PublicKey,
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        let mia = self.mia_epoca(peer, rng)?;
        let sua = self.epoca_del_peer(peer)?;
        // Without an epoch key of theirs there is nothing to burn on their side,
        // but the request is sent anyway, encrypted to their identity, so it
        // works even if they already burned first.
        let (header, ciphertext) = match sua {
            Some(sua) => baseline::seal_burn_epoch(
                &self.identity,
                &sua,
                &mia.public(),
                now_unix,
                rng,
            )?,
            None => baseline::seal_burn_static(&self.identity, peer, &mia.public(), now_unix, rng)?,
        };
        Ok(format::serialize_burn(&header, &ciphertext))
    }

    /// Records the **prekey** a contact sent us, **after checking it**.
    ///
    /// A low-order X25519 key yields an all-zero shared secret, which the
    /// library rejects: stored in the keyring, it would make every future
    /// message to that contact fail, permanently and opaquely. The prekey
    /// travels inside the ciphertext, so only that contact can send one; still,
    /// rejecting it on entry costs one line. The previous one is kept and the
    /// conversation continues.
    ///
    /// `quando` is the writer's clock, from inside the ciphertext. Material
    /// older than what we already accepted from THEM is discarded: a blob stays
    /// valid forever, and rereading an old one used to reinstall the key of
    /// that time (after a burn, the epoch they had destroyed).
    ///
    /// **`adesso` is our clock, and it is needed**: a date in the future would
    /// push `seen_at` years ahead and from then on **everything** would be
    /// discarded. The comparison uses the smaller of the two. `seen_at` is
    /// shared with [`Self::ricorda_epoca_del_peer`], so poisoning it here would
    /// poison epochs too.
    fn ricorda_prekey(
        &mut self,
        peer: &PublicKey,
        prekey: &PublicKey,
        quando: i64,
        adesso: i64,
    ) -> Result<()> {
        if self.identity.diffie_hellman(prekey).is_err() {
            return Ok(());
        }
        let quando = quando.min(adesso);
        if quando < self.keyring.seen_at(peer)? {
            return Ok(());
        }
        self.keyring.set_seen_at(peer, quando)?;
        self.keyring.set_peer_prekey(peer, prekey)
    }

    /// The contact's epoch key, falling back to state saved before it had a
    /// field of its own.
    ///
    /// The fallback does not guess: the stored prekey is a key the contact
    /// really sent us, and before the separation it was **also** the only place
    /// their epoch ended up. It phases out by itself when they send a new one.
    fn epoca_del_peer(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
        if let Some(epoca) = self.keyring.peer_epoch(peer)? {
            if self.identity.diffie_hellman(&epoca).is_ok() {
                return Ok(Some(epoca));
            }
        }
        Ok(self
            .keyring
            .peer_prekey(peer)?
            .filter(|k| self.identity.diffie_hellman(k).is_ok()))
    }

    /// Records the contact's **epoch key**, in its own field (one rotates and is
    /// dropped, the other does not; mixed, a sender with forward secrecy on
    /// encrypted to the epoch as if it were a prekey).
    ///
    /// `quando` is the timestamp **declared by the sender**; `adesso` is ours.
    /// The comparison with `seen_at` prevents going backwards: an old reposted
    /// blob must not revive an epoch the sender already changed. But relying on
    /// the writer's clock alone (decision C: authenticated, not verifiable) let
    /// a single message dated in the future (a phone with the wrong time) push
    /// `seen_at` years ahead; from then on **every** new epoch was silently
    /// discarded and the sender's messages stopped opening.
    ///
    /// Taking the smaller of the two keeps the backward defence (an old blob has
    /// an old date anyway) while a future date is cut down to when we actually
    /// received it.
    fn ricorda_epoca_del_peer(
        &mut self,
        peer: &PublicKey,
        epoca: &PublicKey,
        quando: i64,
        adesso: i64,
    ) -> Result<()> {
        if self.identity.diffie_hellman(epoca).is_err() {
            return Ok(());
        }
        let quando = quando.min(adesso);
        if quando < self.keyring.seen_at(peer)? {
            return Ok(());
        }
        self.keyring.set_seen_at(peer, quando)?;
        self.keyring.set_peer_epoch(peer, epoca)
    }

    /// Opens an epoch message. The third value says whether we wrote it.
    ///
    /// The sender's key is in clear, so there is no need to try contacts: only
    /// the right epoch key is needed, and if it was burned there is nothing
    /// left to do.
    fn apri_a_epoca(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
        adesso: i64,
    ) -> Result<(PublicKey, Plaintext, bool)> {
        let mittente = parsed
            .header
            .sender_pub()
            .cloned()
            .ok_or(Error::Format("messaggio a epoca senza mittente"))?;

        let bootstrap = parsed.header.origin.is_epoch_bootstrap();

        // We wrote it: reopen with the recipient's epoch key we kept, or with
        // their identity if it was the first message. Burning removes this
        // possibility too, which is half the point.
        if mittente == self.identity.public() {
            let mut contatti = 0usize;
            for candidato in self.keyring.peers()? {
                contatti = contatti.saturating_add(1);
                let aperto = if bootstrap {
                    baseline::open_epoch_bootstrap_as_sender(&self.identity, &candidato, parsed)
                } else {
                    let Some(sua) = self.epoca_del_peer(&candidato)? else {
                        continue;
                    };
                    baseline::open_epoch_as_sender(&self.identity, &sua, parsed)
                };
                if let Ok((_, plaintext)) = aperto {
                    return Ok((candidato, plaintext, true));
                }
            }
            return Err(perche_non_si_riapre(bootstrap, contatti));
        }

        // The first message of a conversation is encrypted to our identity: no
        // epoch key of ours is needed, which is why the conversation can
        // restart after a burn without resending identity cards.
        if bootstrap {
            let (sua_epoca, plaintext) =
                baseline::open_epoch_bootstrap(&self.identity, &mittente, parsed)?;
            self.ricorda_epoca_del_peer(&mittente, &sua_epoca, plaintext.sent_at_unix(), adesso)?;
            return Ok((mittente, plaintext, false));
        }

        // Our epoch, from its own field. **Nothing is dropped**: history must
        // remain here, the one operational difference from the chain.
        if let Some(segreto) = self.keyring.my_epoch(&mittente)? {
            let mia = keys::EphemeralSecret::from_bytes(*segreto);
            if let Ok((sua_epoca, plaintext)) = baseline::open_epoch(&mia, &mittente, parsed) {
                self.ricorda_epoca_del_peer(&mittente, &sua_epoca, plaintext.sent_at_unix(), adesso)?;
                return Ok((mittente, plaintext, false));
            }
        }

        // Fallback for state saved BEFORE the epoch had its own field, when it
        // lived in the chain. Without it, updating the app would make ongoing
        // burnable conversations unreadable. It does not guess which prekey was
        // the epoch: it tries them. It phases out as old prekeys drop.
        for segreto in self.keyring.my_prekeys(&mittente)? {
            let mia = keys::EphemeralSecret::from_bytes(*segreto);
            let Ok((sua_epoca, plaintext)) = baseline::open_epoch(&mia, &mittente, parsed) else {
                continue;
            };
            // Adopt it as the epoch and remove it from the chain, so it lives in
            // ONE place (otherwise `drop_my_prekeys_older_than` would touch one
            // copy, and a secret declared destroyed would stay on disk).
            //
            // **Only if there is no epoch yet.** This fallback migrates state
            // saved before the epoch had its own field, where by definition
            // there is none. Without the guard, an old reposted blob encrypted to
            // a prekey still in the chain could fail the normal path, end up
            // here, and silently replace the current epoch with one months old
            // (`set_my_epoch` overwrites). Same family as the other
            // self-poisoning bugs (see `DESIGN.md`).
            //
            // The message is still read: opening it does no harm, adopting it
            // would.
            if self.keyring.my_epoch(&mittente)?.is_none() {
                self.keyring.set_my_epoch(&mittente, *segreto)?;
                self.keyring.forget_my_prekey(&mittente, &segreto)?;
            }
            self.ricorda_epoca_del_peer(&mittente, &sua_epoca, plaintext.sent_at_unix(), adesso)?;
            return Ok((mittente, plaintext, false));
        }
        Err(Error::Crypto)
    }

    /// Opens a group message by trying pinned contacts.
    ///
    /// The header only carries the ephemeral key, so the writer is not recorded
    /// anywhere: as for ephemeral messages, readers try, and **the sender must
    /// already be a contact**. Without their identity the slot key cannot even
    /// be derived.
    ///
    /// Our own identity is among the candidates, last: that is how one rereads
    /// one's own messages. Last because receiving is the common case.
    fn apri_di_gruppo(
        &mut self,
        parsed: &crate::format::ParsedGroup<'_>,
    ) -> Result<(PublicKey, Plaintext)> {
        for candidato in self.keyring.peers()? {
            if let Ok(aperto) = baseline::open_group(&self.identity, &candidato, parsed) {
                return Ok((candidato, aperto));
            }
        }
        let mio = self.identity.public();
        if let Ok(aperto) = baseline::open_group(&self.identity, &mio, parsed) {
            return Ok((mio, aperto));
        }
        Err(Error::Crypto)
    }

    /// Encrypts for several recipients (decision K).
    ///
    /// The caller always chooses the recipients explicitly and in full: there
    /// is no "current group" established by reading, as between two people. A
    /// message sent to the wrong group cannot be withdrawn, and the wrong
    /// recipients would be many.
    ///
    /// **No forward secrecy**, by decision: whoever shows the result must say
    /// so.
    pub fn encrypt_group<R: RngCore + CryptoRng>(
        &mut self,
        destinatari: &[PublicKey],
        plaintext: &[u8],
        now_unix: i64,
        rng: &mut R,
    ) -> Result<String> {
        // Only pinned contacts: for a never-seen key one could not even know
        // whether it is the right person, and in a group the mistake multiplies.
        for chiave in destinatari {
            if self.keyring.get(chiave)?.is_none() {
                return Err(Error::UnknownPeer);
            }
        }
        let (header, slots, ciphertext) =
            baseline::seal_group(&self.identity, destinatari, plaintext, now_unix, rng)?;
        crate::format::serialize_group(&header, &slots, &ciphertext)
    }

    /// Who asked for the burn. Found by **decrypting**: otherwise anyone could
    /// delete other people's conversations by sending a random blob.
    fn mittente_di_un_rogo(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<(PublicKey, i64)> {
        if parsed.header.origin.uses_epoch() {
            let mittente = parsed
                .header
                .sender_pub()
                .cloned()
                .ok_or(Error::Format("rogo senza mittente"))?;
            // Our epoch, from its own field. The chain fallback is for state
            // saved before the separation: without it, a burn arriving after the
            // update would not open, and a destruction request would be lost
            // silently.
            if let Some(segreto) = self.keyring.my_epoch(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, aperto)) = baseline::open_burn_epoch(&mia, &mittente, parsed) {
                    return Ok((mittente, aperto.sent_at_unix()));
                }
            }
            for segreto in self.keyring.my_prekeys(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, aperto)) = baseline::open_burn_epoch(&mia, &mittente, parsed) {
                    return Ok((mittente, aperto.sent_at_unix()));
                }
            }
            return Err(Error::Crypto);
        }
        // A burn sent by someone without an epoch key of ours is encrypted to our
        // identity: it happens when we had already burned.
        let mittente = parsed
            .header
            .sender_pub()
            .cloned()
            .ok_or(Error::Format("rogo senza mittente"))?;
        // Decrypt BEFORE looking at the keyring, and do not distinguish
        // failures. With the opposite order (`UnknownPeer` for an unpinned
        // sender, `Crypto` for a blob that does not open), sending any burn with
        // a candidate public key revealed whether that person is among the
        // victim's contacts: the membership oracle the threat model forbids.
        // Decrypting is also the only proof that the requester holds that key.
        let (_, aperto) = baseline::open_burn_static(&self.identity, &mittente, parsed)
            .map_err(|_| Error::Crypto)?;
        if self.keyring.get(&mittente)?.is_none() {
            return Err(Error::Crypto);
        }
        Ok((mittente, aperto.sent_at_unix()))
    }

    /// [`Self::prova_i_contatti`] for attachments.
    fn prova_i_contatti_sul_file(
        &self,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<(PublicKey, PublicKey, file::DecryptedFile)> {
        for candidato in self.keyring.peers()? {
            if let Ok((prekey, aperto)) =
                file::open_file_ephemeral(&self.identity, &candidato, parsed)
            {
                return Ok((candidato, prekey, aperto));
            }
        }
        Err(Error::Crypto)
    }

    /// [`Self::prova_con_le_prekey`] for attachments: same chain, same dropping
    /// of old keys.
    fn prova_le_prekey_sul_file(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
        adesso: i64,
    ) -> Result<(PublicKey, file::DecryptedFile)> {
        let mio = self.identity.public();
        for candidato in self.keyring.peers()? {
            for segreto in self.keyring.my_prekeys(&candidato)? {
                let prekey = keys::EphemeralSecret::from_bytes(*segreto);
                let Ok((prossima, aperto)) =
                    file::open_file_forward(&prekey, &candidato, &mio, parsed)
                else {
                    continue;
                };
                self.ricorda_prekey(&candidato, &prossima, aperto.sent_at_unix, adesso)?;
                self.keyring
                    .drop_my_prekeys_older_than(&candidato, &segreto)?;
                return Ok((candidato, aperto));
            }
        }
        Err(Error::Crypto)
    }

    /// Forgets a peer and stops using it as a recipient.
    ///
    /// Dropping the second part would be a silent failure: the contact would
    /// disappear from the list while encryption continued to that key, because
    /// the current recipient is a separate map.
    pub fn forget_peer(&mut self, peer: &PublicKey) -> Result<bool> {
        let c_era = self.keyring.forget(peer)?;
        self.current_peer.retain(|_, corrente| corrente != peer);
        Ok(c_era)
    }

    /// Tries to open an ephemeral-sender message with each contact.
    ///
    /// One decryption per contact; with a few dozen contacts it is not
    /// noticeable. Senders outside the keyring are not recognised, on purpose:
    /// an unknown sender must send an identity card first.
    ///
    /// If all fail, the error is [`Error::Crypto`] like any other: "none of my
    /// contacts" is not distinguished from "corrupted", because that would tell
    /// an attacker something about the keyring.
    fn prova_i_contatti(
        &self,
        parsed: &crate::format::ParsedEnvelope<'_>,
    ) -> Result<(PublicKey, PublicKey, Plaintext)> {
        for candidato in self.keyring.peers()? {
            if let Ok((prekey, plaintext)) =
                baseline::open_ephemeral(&self.identity, &candidato, parsed)
            {
                return Ok((candidato, prekey, plaintext));
            }
        }
        Err(Error::Crypto)
    }

    /// Like [`Self::prova_i_contatti`], for fully forward-secret messages:
    /// contacts are tried **for each** of our temporary keys.
    ///
    /// On success two things happen, the two that move the chain forward: the
    /// sender's next key is recorded, and our keys older than the one just used
    /// are dropped (down to [`keys::CODA_MINIMA`]).
    fn prova_con_le_prekey(
        &mut self,
        parsed: &crate::format::ParsedEnvelope<'_>,
        adesso: i64,
    ) -> Result<(PublicKey, Plaintext)> {
        let mio = self.identity.public();
        for candidato in self.keyring.peers()? {
            for segreto in self.keyring.my_prekeys(&candidato)? {
                let prekey = keys::EphemeralSecret::from_bytes(*segreto);
                let Ok((prossima, plaintext)) =
                    baseline::open_forward(&prekey, &candidato, &mio, parsed)
                else {
                    continue;
                };
                self.ricorda_prekey(&candidato, &prossima, plaintext.sent_at_unix(), adesso)?;
                self.keyring
                    .drop_my_prekeys_older_than(&candidato, &segreto)?;
                return Ok((candidato, plaintext));
            }
        }
        Err(Error::Crypto)
    }

    /// Opens a message **without touching the keyring**, to read an archive.
    ///
    /// Not a convenience: a chat export contains anything, including messages
    /// from other conversations or forged ones, and pinning keys while reading a
    /// file would fill the keyring unnoticed, or show a false "Mark's key
    /// changed".
    ///
    /// Read only: no pin, no recipient chosen, no state modified.
    pub fn open_archived(&self, text: &str) -> Result<(PublicKey, Plaintext)> {
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(text, &mut buf)? else {
            return Err(Error::Format("non e' un messaggio"));
        };
        // Epoch scheme: readable while the keys exist, and reading an archive
        // does not touch them.
        if parsed.header.origin.uses_epoch() || parsed.header.origin.is_epoch_bootstrap() {
            let bootstrap = parsed.header.origin.is_epoch_bootstrap();
            let mittente = parsed
                .header
                .sender_pub()
                .cloned()
                .ok_or(Error::Format("messaggio a epoca senza mittente"))?;
            if mittente == self.identity.public() {
                let mut contatti = 0usize;
                for candidato in self.keyring.peers()? {
                    contatti = contatti.saturating_add(1);
                    let aperto = if bootstrap {
                        baseline::open_epoch_bootstrap_as_sender(&self.identity, &candidato, &parsed)
                    } else {
                        let Some(sua) = self.epoca_del_peer(&candidato)? else {
                            continue;
                        };
                        baseline::open_epoch_as_sender(&self.identity, &sua, &parsed)
                    };
                    if let Ok((_, plaintext)) = aperto {
                        return Ok((candidato, plaintext));
                    }
                }
                return Err(perche_non_si_riapre(bootstrap, contatti));
            }
            if bootstrap {
                let (_, plaintext) =
                    baseline::open_epoch_bootstrap(&self.identity, &mittente, &parsed)?;
                return Ok((mittente, plaintext));
            }
            // Our epoch, from its own field. Without this, the same blob opened
            // from the keyboard but gave `Error::Crypto` from the archive, i.e.
            // **history** (the one thing bought by giving up forward secrecy)
            // could not be rebuilt for received messages.
            if let Some(segreto) = self.keyring.my_epoch(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, plaintext)) = baseline::open_epoch(&mia, &mittente, &parsed) {
                    return Ok((mittente, plaintext));
                }
            }
            // Fallback for state saved before the separation, as on the read
            // path.
            for segreto in self.keyring.my_prekeys(&mittente)? {
                let mia = keys::EphemeralSecret::from_bytes(*segreto);
                if let Ok((_, plaintext)) = baseline::open_epoch(&mia, &mittente, &parsed) {
                    return Ok((mittente, plaintext));
                }
            }
            return Err(Error::Crypto);
        }
        if parsed.header.origin.uses_prekey() {
            // Keys still alive can be used: they are ours. Only what the chain
            // already dropped is gone, which is exactly the property.
            //
            // **Does not advance the chain.** Reading an archive is not receiving
            // a message: dropping old keys would kill messages still in flight,
            // and recording the sender's next key from a file would let anyone
            // who sends us an export hijack the next conversation.
            let mio = self.identity.public();
            for candidato in self.keyring.peers()? {
                for segreto in self.keyring.my_prekeys(&candidato)? {
                    let prekey = keys::EphemeralSecret::from_bytes(*segreto);
                    if let Ok((_, plaintext)) =
                        baseline::open_forward(&prekey, &candidato, &mio, &parsed)
                    {
                        return Ok((candidato, plaintext));
                    }
                }
            }
            return Err(Error::Crypto);
        }
        if parsed.header.origin.is_ephemeral() {
            let (mittente, _, plaintext) = self.prova_i_contatti(&parsed)?;
            return Ok((mittente, plaintext));
        }
        let sender = parsed
            .header
            .sender_pub()
            .cloned()
            .ok_or(Error::Format("messaggio senza pubkey del mittente"))?;
        // In a chat export half the messages are OURS. Without this branch,
        // rebuilding would only show what we received.
        if sender == self.identity.public() {
            for candidato in self.keyring.peers()? {
                if let Ok(plaintext) =
                    baseline::open_as_sender(&self.identity, &candidato, &parsed)
                {
                    return Ok((candidato, plaintext));
                }
            }
            return Err(Error::OwnMessage);
        }
        let plaintext = baseline::open(&self.identity, &sender, &parsed)?;
        Ok((sender, plaintext))
    }

    pub fn current_peer(&self, app_package: &str) -> Option<&PublicKey> {
        self.current_peer.get(app_package)
    }

    /// Explicit choice from the toolbar. The peer must already be in the
    /// keyring: no encrypting to a key that was never pinned.
    pub fn set_current_peer(&mut self, app_package: &str, peer: &PublicKey) -> Result<()> {
        if self.keyring.get(peer)?.is_none() {
            return Err(Error::UnknownPeer);
        }
        self.current_peer
            .insert(app_package.to_owned(), peer.clone());
        Ok(())
    }

    /// Explicit user confirmation after a [`SenderStatus::Conflict`] or a
    /// [`PinOutcome::Conflict`]. The only path that overwrites a pin. Never
    /// called automatically.
    pub fn confirm_key_change(
        &mut self,
        old: &PublicKey,
        new: &PublicKey,
        now_unix: i64,
    ) -> Result<()> {
        self.keyring.replace_pinned(old, new, now_unix)?;
        // The current recipient pointed to the old key: update it everywhere,
        // or the next reply would be encrypted to a key the user just declared
        // superseded.
        for peer in self.current_peer.values_mut() {
            if peer == old {
                *peer = new.clone();
            }
        }
        Ok(())
    }

    /// Marks a peer as verified after the user compared the fingerprint out of
    /// band. The only thing that closes first-contact MITM, which TOFU alone
    /// does not.
    pub fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
        self.keyring.mark_verified(peer)
    }
}

#[cfg(test)]
// In tests `unwrap` and `panic!` are intended.
#[allow(clippy::unwrap_used, clippy::panic, clippy::arithmetic_side_effects)]
mod tests {
    use super::*;
    use crate::keys::{LabelOutcome, PeerRecord};
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    /// In-memory keyring. Real storage lives outside the crate; this only has
    /// to honour the contract.
    #[derive(Default)]
    struct KeyringInMemoria {
        peers: Vec<PeerRecord>,
        prekey: crate::keys::PrekeyStore,
    }

    impl Keyring for KeyringInMemoria {
        fn peer_prekey(&self, peer: &PublicKey) -> Result<Option<PublicKey>> {
            Ok(self.prekey.peer_prekey(peer))
        }

        fn set_peer_prekey(&mut self, peer: &PublicKey, prekey: &PublicKey) -> Result<()> {
            self.prekey.set_peer_prekey(peer, prekey);
            Ok(())
        }

        fn my_prekeys(&self, peer: &PublicKey) -> Result<Vec<zeroize::Zeroizing<[u8; 32]>>> {
            Ok(self.prekey.my_prekeys(peer))
        }

        fn my_epoch(&self, peer: &PublicKey) -> Result<Option<zeroize::Zeroizing<[u8; 32]>>> {
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

        fn forget_my_prekey(&mut self, peer: &PublicKey, secret: &[u8; 32]) -> Result<()> {
            self.prekey.forget_my_prekey(peer, secret);
            Ok(())
        }

        fn set_my_epoch(&mut self, peer: &PublicKey, secret: [u8; 32]) -> Result<()> {
            self.prekey.set_my_epoch(peer, secret);
            Ok(())
        }

        fn push_my_prekey(&mut self, peer: &PublicKey, secret: [u8; 32]) -> Result<()> {
            self.prekey.push_my_prekey(peer, secret);
            Ok(())
        }

        fn drop_my_prekeys_older_than(
            &mut self,
            peer: &PublicKey,
            secret: &[u8; 32],
        ) -> Result<()> {
            self.prekey.drop_my_prekeys_older_than(peer, secret);
            Ok(())
        }

        fn burn_conversation(&mut self, peer: &PublicKey) -> Result<()> {
            self.prekey.burn(peer);
            Ok(())
        }

        fn peers(&self) -> Result<Vec<PublicKey>> {
            Ok(self.peers.iter().map(|p| p.public.clone()).collect())
        }

        fn forget(&mut self, peer: &PublicKey) -> Result<bool> {
            match self.peers.iter().position(|p| &p.public == peer) {
                Some(i) => {
                    self.peers.remove(i);
                    self.prekey.forget(peer);
                    Ok(true)
                }
                None => Ok(false),
            }
        }

        fn tofu_pin(&mut self, peer: &PublicKey, now_unix: i64) -> Result<PinOutcome> {
            if self.peers.iter().any(|r| &r.public == peer) {
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
            if let Some(altro) = self
                .peers
                .iter()
                .find(|r| r.label.as_deref() == Some(label) && &r.public != peer)
            {
                return Ok(LabelOutcome::Conflict {
                    existing: altro.public.clone(),
                    existing_fingerprint: Fingerprint::of(&altro.public),
                    incoming_fingerprint: Fingerprint::of(peer),
                });
            }
            match self.peers.iter_mut().find(|r| &r.public == peer) {
                Some(record) => {
                    record.label = Some(label.to_owned());
                    Ok(LabelOutcome::Assigned)
                }
                None => Err(Error::UnknownPeer),
            }
        }

        fn replace_pinned(
            &mut self,
            old: &PublicKey,
            new: &PublicKey,
            now_unix: i64,
        ) -> Result<()> {
            let etichetta = self
                .peers
                .iter()
                .find(|r| &r.public == old)
                .and_then(|r| r.label.clone());
            self.peers.retain(|r| &r.public != old);
            self.peers.retain(|r| &r.public != new);
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
            Ok(self.peers.iter().find(|r| &r.public == peer).cloned())
        }

        fn mark_verified(&mut self, peer: &PublicKey) -> Result<()> {
            match self.peers.iter_mut().find(|r| &r.public == peer) {
                Some(record) => {
                    record.verified = true;
                    Ok(())
                }
                None => Err(Error::UnknownPeer),
            }
        }
    }

    fn rng(seed: u8) -> ChaCha20Rng {
        ChaCha20Rng::from_seed([seed; 32])
    }

    fn sessione(seed: u8) -> Session<KeyringInMemoria> {
        Session::new(
            Identity::from_secret_bytes([seed; 32]).unwrap(),
            KeyringInMemoria::default(),
        )
    }

    const WHATSAPP: &str = "com.whatsapp";
    const SIGNAL: &str = "org.thoughtcrime.securesms";

    #[test]
    fn testo_normale_non_e_nostro() {
        let mut bob = sessione(2);
        for testo in ["", "ciao come stai", "https://esempio.it"] {
            assert!(matches!(
                bob.handle_incoming_text(WHATSAPP, testo, 0),
                Err(Error::NotOurBlob)
            ));
        }
    }

    #[test]
    fn messaggio_da_peer_nuovo_lo_fissa() {
        let alice = sessione(1);
        let mut bob = sessione(2);

        let blob = crate::baseline::seal(
            &Identity::from_secret_bytes([1; 32]).unwrap(),
            &bob.identity.public(),
            b"primo contatto",
            1_700_000_000,
            &mut rng(9),
        )
        .unwrap();

        let IncomingItem::Message(msg) = bob.handle_incoming_text(WHATSAPP, &blob, 100).unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(msg.sender_status, SenderStatus::New);
        assert_eq!(msg.plaintext.as_bytes(), b"primo contatto");
        assert_eq!(msg.sender, alice.identity.public());

        // The sender became the current recipient for that app.
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));
    }

    #[test]
    fn secondo_messaggio_dallo_stesso_peer_e_noto() {
        let mut bob = sessione(2);
        let alice_id = Identity::from_secret_bytes([1; 32]).unwrap();

        for _ in 0..2 {
            let blob =
                crate::baseline::seal(&alice_id, &bob.identity.public(), b"x", 1_700_000_000, &mut rng(9)).unwrap();
            let _ = bob.handle_incoming_text(WHATSAPP, &blob, 100).unwrap();
        }

        let blob =
            crate::baseline::seal(&alice_id, &bob.identity.public(), b"y", 1_700_000_000, &mut rng(8)).unwrap();
        let IncomingItem::Message(msg) = bob.handle_incoming_text(WHATSAPP, &blob, 200).unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(
            msg.sender_status,
            SenderStatus::Known {
                label: None,
                verified: false
            }
        );
    }

    /// The recipient is per app, not global: one contact per app means never
    /// touching anything, and reading in one app must not move the other.
    #[test]
    fn il_destinatario_e_per_app() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let carol = Identity::from_secret_bytes([3; 32]).unwrap();

        let da_alice =
            crate::baseline::seal(&alice, &bob.identity.public(), b"a", 1_700_000_000, &mut rng(1)).unwrap();
        let da_carol =
            crate::baseline::seal(&carol, &bob.identity.public(), b"c", 1_700_000_000, &mut rng(2)).unwrap();

        bob.handle_incoming_text(WHATSAPP, &da_alice, 1).unwrap();
        bob.handle_incoming_text(SIGNAL, &da_carol, 2).unwrap();

        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.public()));
        assert_eq!(bob.current_peer(SIGNAL), Some(&carol.public()));
    }

    /// Within one app the last sender read wins. This rule makes the common case
    /// automatic and is the one that can surprise, so it is pinned here.
    #[test]
    fn nella_stessa_app_vince_l_ultimo_letto() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let carol = Identity::from_secret_bytes([3; 32]).unwrap();

        let da_alice =
            crate::baseline::seal(&alice, &bob.identity.public(), b"a", 1_700_000_000, &mut rng(1)).unwrap();
        let da_carol =
            crate::baseline::seal(&carol, &bob.identity.public(), b"c", 1_700_000_000, &mut rng(2)).unwrap();

        bob.handle_incoming_text(WHATSAPP, &da_alice, 1).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.public()));
        bob.handle_incoming_text(WHATSAPP, &da_carol, 2).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&carol.public()));
    }

    /// Full round trip of a group, from the level that will really use it.
    #[test]
    fn un_gruppo_si_apre_da_tutti_e_dice_quanti_erano() {
        let mut alice = sessione(1);
        let mut babbo = sessione(2);
        let mut mamma = sessione(3);
        let chiave_alice = alice.identity.public();
        let chiave_babbo = babbo.identity.public();
        let chiave_mamma = mamma.identity.public();

        // They know each other: groups are not sent to, nor opened from,
        // unpinned keys.
        alice.keyring.tofu_pin(&chiave_babbo, 1).unwrap();
        alice.keyring.tofu_pin(&chiave_mamma, 1).unwrap();
        babbo.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        mamma.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        let blob = alice
            .encrypt_group(
                &[chiave_babbo.clone(), chiave_mamma.clone()],
                b"ci vediamo domenica",
                50,
                &mut rng(4),
            )
            .unwrap();

        for chi in [&mut babbo, &mut mamma] {
            let IncomingItem::Message(messaggio) =
                chi.handle_incoming_text(WHATSAPP, &blob, 51).unwrap()
            else {
                panic!("atteso un messaggio")
            };
            assert_eq!(messaggio.plaintext.as_bytes(), b"ci vediamo domenica");
            assert_eq!(messaggio.sender, chiave_alice);
            // Three slots: dad, mum and Alice. Lets the UI say that a group
            // message has no forward secrecy.
            assert!(messaggio.gruppo);
            assert_eq!(messaggio.destinatari, 3);
        }

        // Alice rereads her own.
        let IncomingItem::Message(riletto) =
            alice.handle_incoming_text(WHATSAPP, &blob, 52).unwrap()
        else {
            panic!("atteso un messaggio")
        };
        assert_eq!(riletto.plaintext.as_bytes(), b"ci vediamo domenica");

        // THE LINE THAT MATTERS: reading a group message does NOT select the
        // sender as recipient. Otherwise the reply would go privately to them,
        // inside the chat where everyone expects it.
        assert_eq!(babbo.current_peer(WHATSAPP), None);
    }

    /// The same blob must open from the keyboard AND from the archive: history
    /// is the one thing bought by giving up forward secrecy, and it is useless
    /// if only half can be rebuilt.
    #[test]
    fn l_archivio_apre_quel_che_apre_la_tastiera() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_bob = bob.identity.public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Burnable opening, so Bob learns Alice's epoch and replies to it.
        let apertura = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &apertura, 11).unwrap();
        let risposta = bob
            .encrypt_for_app_with(WHATSAPP, b"ci sono", 12, &mut rng(2), false)
            .unwrap();

        // From the keyboard it opens.
        alice.handle_incoming_text(WHATSAPP, &risposta, 13).unwrap();
        // And from the archive too (it used to give Error::Crypto).
        let (chi, aperto) = alice.open_archived(&risposta).unwrap();
        assert_eq!(chi, chiave_bob);
        assert_eq!(aperto.as_bytes(), b"ci sono");
    }

    /// Rereading one's own group message must not add the user to their own
    /// contacts.
    #[test]
    fn rileggere_un_proprio_gruppo_non_fissa_se_stessi() {
        let mut alice = sessione(1);
        let babbo = sessione(2).identity.public();
        alice.keyring.tofu_pin(&babbo, 1).unwrap();
        let quanti_prima = alice.keyring.peers().unwrap().len();

        let blob = alice
            .encrypt_group(&[babbo], b"ciao a tutti", 50, &mut rng(6))
            .unwrap();
        let IncomingItem::Message(riletto) =
            alice.handle_incoming_text(WHATSAPP, &blob, 51).unwrap()
        else {
            panic!("atteso un messaggio")
        };

        assert_eq!(riletto.plaintext.as_bytes(), b"ciao a tutti");
        assert!(riletto.gruppo);
        assert_eq!(riletto.sender, alice.identity.public());
        // THE LINE THAT MATTERS: the address book did not grow.
        assert_eq!(alice.keyring.peers().unwrap().len(), quanti_prima);
        // And no "who is this?" about one's own words.
        assert!(matches!(riletto.sender_status, SenderStatus::Known { .. }));
    }

    /// Reported case, and two messages are enough.
    ///
    /// She sends two, encrypted to two different prekeys of the recipient. He
    /// opens the second first. Before the minimum tail, the first (never
    /// opened) became unreadable forever. Reading out of order is the norm with
    /// copy-paste.
    #[test]
    fn due_messaggi_letti_fuori_ordine_si_aprono_tutti_e_due() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Bob writes twice: two prekeys of his, the second newer.
        let b1 = bob
            .encrypt_for_app_with("app", b"uno", 10, &mut rng(1), true)
            .unwrap();
        let b2 = bob
            .encrypt_for_app_with("app", b"due", 11, &mut rng(2), true)
            .unwrap();

        // Alice reads the first and replies with the prekey she just saw.
        alice.handle_incoming_text("app", &b1, 12).unwrap();
        let a1 = alice
            .encrypt_for_app_with("app", b"rispondo a uno", 13, &mut rng(3), true)
            .unwrap();

        // Then reads the second and replies again, with a newer one.
        alice.handle_incoming_text("app", &b2, 14).unwrap();
        let a2 = alice
            .encrypt_for_app_with("app", b"rispondo a due", 15, &mut rng(4), true)
            .unwrap();

        // Bob opens the SECOND reply first.
        assert!(bob.handle_incoming_text("app", &a2, 16).is_ok());

        // Then the first, which arrived earlier and is still there.
        let esito = bob.handle_incoming_text("app", &a1, 17);
        assert!(esito.is_ok(), "la prima risposta non si apre: {:?}", esito.err());
    }

    /// A single message with the clock ahead poisons state **forever**.
    ///
    /// `ricorda_epoca_del_peer` rejects epochs older than `seen_at`, and
    /// `seen_at` came from the timestamp **declared by the sender** (decision
    /// C: authenticated, not verifiable). One message dated in the future (a
    /// phone with the wrong time) and every new epoch was silently ignored.
    #[test]
    fn un_orologio_avanti_non_blocca_le_epoche_future() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Bob writes with a wrong clock: he claims it is 2050.
        let futuro = 2_500_000_000;
        let sballato = bob
            .encrypt_for_app_with("app", b"ciao", futuro, &mut rng(1), false)
            .unwrap();
        alice.handle_incoming_text("app", &sballato, 100).unwrap();

        // Bob fixes his clock and burns the conversation: new epoch.
        bob.burn_conversation(&ka, 150, &mut rng(9)).unwrap();
        let corretto = bob
            .encrypt_for_app_with("app", b"di nuovo", 200, &mut rng(2), false)
            .unwrap();
        alice.handle_incoming_text("app", &corretto, 201).unwrap();

        // Alice must have learned the new epoch: otherwise she encrypts to the
        // burned one and Bob opens nothing.
        let risposta = alice
            .encrypt_for_app_with("app", b"eccomi", 202, &mut rng(3), false)
            .unwrap();
        let esito = bob.handle_incoming_text("app", &risposta, 203);
        assert!(esito.is_ok(), "Bob non apre la risposta: {:?}", esito.err());
    }

    /// The counterweight of the test above: **an old reposted blob does not
    /// bring the epoch back**.
    ///
    /// This is the defence the comparison with `seen_at` exists for, and the
    /// clock fix must not have removed it: an old message has an old date
    /// either way, so it is still discarded.
    #[test]
    fn un_messaggio_vecchio_ripubblicato_non_riporta_indietro_l_epoca() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // A message Bob sent long ago, which Alice keeps aside.
        let vecchio = bob
            .encrypt_for_app_with("app", b"antico", 100, &mut rng(1), false)
            .unwrap();

        // Bob changes epoch and writes again; Alice reads and learns the new one.
        bob.burn_conversation(&ka, 150, &mut rng(9)).unwrap();
        let nuovo = bob
            .encrypt_for_app_with("app", b"recente", 200, &mut rng(2), false)
            .unwrap();
        alice.handle_incoming_text("app", &nuovo, 201).unwrap();

        // Now someone reposts the old one. Alice opens it (it is a valid blob)
        // but must NOT go back to that epoch.
        let _ = alice.handle_incoming_text("app", &vecchio, 300);

        // The proof: her reply must still open.
        let risposta = alice
            .encrypt_for_app_with("app", b"eccomi", 301, &mut rng(3), false)
            .unwrap();
        let esito = bob.handle_incoming_text("app", &risposta, 302);
        assert!(
            esito.is_ok(),
            "l'epoca e' tornata indietro: {:?}",
            esito.err()
        );
    }

    /// A burn request dated in the future must not **disable future burns**.
    ///
    /// Third case of the same family (`burned_at`, like `seen_at`) and the
    /// worst: the only destructive operation of the system would stop working
    /// silently.
    #[test]
    fn un_rogo_datato_nel_futuro_non_blocca_i_roghi_dopo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();

        // Bob burns with a wrong clock.
        let futuro = 2_500_000_000;
        let primo = bob.burn_conversation(&ka, futuro, &mut rng(1)).unwrap();
        assert!(matches!(
            alice.handle_incoming_text("app", &primo, 100),
            Ok(IncomingItem::Burned { .. })
        ));

        // Bob fixes the clock and burns again, later. It must be honoured.
        let secondo = bob.burn_conversation(&ka, 200, &mut rng(2)).unwrap();
        assert!(
            matches!(
                alice.handle_incoming_text("app", &secondo, 201),
                Ok(IncomingItem::Burned { .. })
            ),
            "il secondo rogo e' stato rifiutato: la funzione era disattivata"
        );
    }

    /// The same poisoning, through the **prekey** path.
    ///
    /// `seen_at` is shared by `ricorda_prekey` and `ricorda_epoca_del_peer`, so
    /// fixing only the latter would have achieved nothing.
    #[test]
    fn un_orologio_avanti_sulla_catena_non_avvelena_le_epoche() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let ka = alice.identity.public();
        let kb = bob.identity.public();
        alice.keyring.tofu_pin(&kb, 1).unwrap();
        bob.keyring.tofu_pin(&ka, 1).unwrap();
        alice.set_current_peer("app", &kb).unwrap();
        bob.set_current_peer("app", &ka).unwrap();

        // Bob writes WITH the chain and a wrong clock: goes through
        // `ricorda_prekey`, the other door to `seen_at`.
        let futuro = 2_500_000_000;
        let sballato = bob
            .encrypt_for_app_with("app", b"ciao", futuro, &mut rng(1), true)
            .unwrap();
        alice.handle_incoming_text("app", &sballato, 100).unwrap();

        // Then changes epoch and writes without the chain, at the right time.
        bob.burn_conversation(&ka, 150, &mut rng(9)).unwrap();
        let corretto = bob
            .encrypt_for_app_with("app", b"di nuovo", 200, &mut rng(2), false)
            .unwrap();
        alice.handle_incoming_text("app", &corretto, 201).unwrap();

        let risposta = alice
            .encrypt_for_app_with("app", b"eccomi", 202, &mut rng(3), false)
            .unwrap();
        let esito = bob.handle_incoming_text("app", &risposta, 203);
        assert!(esito.is_ok(), "Bob non apre la risposta: {:?}", esito.err());
    }

    /// The other half of K1 condition 1: sending and opening a group message
    /// must not touch the state one-to-one forward secrecy depends on. If
    /// someone ever tried to give groups forward secrecy by reusing existing
    /// prekeys (the path K1 rules out), this test would notice the chain move.
    #[test]
    fn un_gruppo_non_tocca_la_catena_a_due() {
        let mut alice = sessione(1);
        let mut babbo = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_babbo = babbo.identity.public();
        alice.keyring.tofu_pin(&chiave_babbo, 1).unwrap();
        babbo.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        // First build real one-to-one state: a message with the chain on puts a
        // prekey in the sender's keyring.
        alice.set_current_peer("app", &chiave_babbo).unwrap();
        let a_due = alice
            .encrypt_for_app_with("app", b"a due", 10, &mut rng(1), true)
            .unwrap();
        babbo.handle_incoming_text("app", &a_due, 11).unwrap();

        let prima_alice = alice.keyring.my_prekeys(&chiave_babbo).unwrap();
        let prima_babbo = babbo.keyring.my_prekeys(&chiave_alice).unwrap();
        let epoca_prima = alice.keyring.my_epoch(&chiave_babbo).unwrap();
        assert!(!prima_alice.is_empty(), "lo stato a due deve esistere");

        // Now the group, between the same people.
        let blob = alice
            .encrypt_group(
                std::slice::from_ref(&chiave_babbo),
                b"di gruppo",
                20,
                &mut rng(2),
            )
            .unwrap();
        babbo.handle_incoming_text("app", &blob, 21).unwrap();

        assert_eq!(
            alice.keyring.my_prekeys(&chiave_babbo).unwrap(),
            prima_alice,
            "cifrare un gruppo ha mosso la catena di chi manda"
        );
        assert_eq!(
            babbo.keyring.my_prekeys(&chiave_alice).unwrap(),
            prima_babbo,
            "aprire un gruppo ha mosso la catena di chi legge"
        );
        assert_eq!(
            alice.keyring.my_epoch(&chiave_babbo).unwrap(),
            epoca_prima,
            "il gruppo ha toccato la chiave d'epoca"
        );
    }

    /// A one-slot group used to pass as a one-to-one message: a `version = 2`
    /// blob without forward secrecy looking like one that has it.
    #[test]
    fn un_gruppo_da_uno_slot_non_esiste() {
        let mut alice = sessione(1);
        let mia = alice.identity.public();
        alice.keyring.tofu_pin(&mia, 1).unwrap();
        // Only recipient: herself. After deduplication one slot would remain.
        assert!(alice
            .encrypt_group(&[mia], b"ciao", 1, &mut rng(7))
            .is_err());
    }

    #[test]
    fn un_gruppo_verso_uno_sconosciuto_non_parte() {
        let mut alice = sessione(1);
        let estraneo = sessione(9).identity.public();
        assert!(matches!(
            alice.encrypt_group(&[estraneo], b"ciao", 1, &mut rng(5)),
            Err(Error::UnknownPeer)
        ));
    }

    /// PROBE. Two people with the switch set differently (one keeps it on, the
    /// default; the other turns it off for history) must be able to write to
    /// each other both ways.
    ///
    /// Previously the contact's epoch ended up in the same field as their
    /// prekey, and a sender with forward secrecy on encrypted to it as if it were
    /// a prekey: every reply was lost forever with `Error::Crypto`.
    #[test]
    fn interruttori_diversi_si_parlano_lo_stesso() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_bob = bob.identity.public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Alice keeps forward secrecy OFF: she wants history.
        // Bob keeps it ON, the default.
        for giro in 0..3i64 {
            let da_alice = alice
                .encrypt_for_app_with(WHATSAPP, b"da alice", 100 + giro, &mut rng(1), false)
                .unwrap();
            let IncomingItem::Message(letto) =
                bob.handle_incoming_text(WHATSAPP, &da_alice, 101 + giro).unwrap()
            else {
                panic!("Bob non ha letto il messaggio di Alice al giro {giro}")
            };
            assert_eq!(letto.plaintext.as_bytes(), b"da alice");

            let da_bob = bob
                .encrypt_for_app_with(WHATSAPP, b"da bob", 102 + giro, &mut rng(2), true)
                .unwrap();
            // THE LINE THAT MATTERS: this used to give Error::Crypto every time.
            let esito = alice.handle_incoming_text(WHATSAPP, &da_bob, 103 + giro);
            let IncomingItem::Message(risposta) = esito.unwrap() else {
                panic!("Alice non ha letto la risposta di Bob al giro {giro}")
            };
            assert_eq!(risposta.plaintext.as_bytes(), b"da bob");
        }
    }

    /// PROBE. A burn already honoured is not redone: the blob stays valid
    /// forever, and whoever saw it could paste it again to destroy the
    /// conversation restarted meanwhile.
    #[test]
    fn un_rogo_ripubblicato_non_brucia_di_nuovo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity.public();
        let chiave_bob = bob.identity.public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        let apertura = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &apertura, 11).unwrap();

        let richiesta = alice.burn_conversation(&chiave_bob, 12, &mut rng(7)).unwrap();
        // The first time it is honoured.
        let esito = bob.handle_incoming_text(WHATSAPP, &richiesta, 13).unwrap();
        assert!(matches!(esito, IncomingItem::Burned { .. }));

        // The conversation restarts.
        let nuova = alice
            .encrypt_for_app_with(WHATSAPP, b"ricominciamo", 20, &mut rng(3), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &nuova, 21).unwrap();

        // The same burn blob, pasted again: it must NOT burn the new
        // conversation.
        assert!(bob.handle_incoming_text(WHATSAPP, &richiesta, 22).is_err());
        // And the new conversation holds: it still reads.
        assert!(bob.open_archived(&nuova).is_ok());
    }

    /// PROBE (decision J). The epoch must not rotate: that is what makes history
    /// exist. If it lives in the same list as the forward secrecy chain, reading
    /// a message drops it, and the conversation becomes unreadable with nobody
    /// burning it.
    #[test]
    fn leggere_un_messaggio_non_brucia_l_epoca() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_bob = bob.identity.public();
        let chiave_alice = alice.identity.public();
        // They already know each other: first contact is not what is tested.
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // 1. Alice opens in burnable mode: her epoch is created and offered.
        let apertura = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &apertura, 11).unwrap();

        // 2. Bob replies burnable, encrypting to Alice's epoch.
        let verso_epoca = bob
            .encrypt_for_app_with(WHATSAPP, b"prima risposta", 12, &mut rng(2), false)
            .unwrap();

        // 3. Meanwhile they exchange a fully forward-secret message.
        let effimero = alice
            .encrypt_for_app_with(WHATSAPP, b"effimero", 13, &mut rng(3), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &effimero, 14).unwrap();
        let risposta_effimera = bob
            .encrypt_for_app_with(WHATSAPP, b"risposta effimera", 15, &mut rng(4), true)
            .unwrap();
        alice
            .handle_incoming_text(WHATSAPP, &risposta_effimera, 16)
            .unwrap();

        // 4. THE LINE THAT MATTERS. Nobody burned anything: Bob's burnable
        //    message must still open.
        let esito = alice.handle_incoming_text(WHATSAPP, &verso_epoca, 17);
        assert!(
            esito.is_ok(),
            "l'epoca e' stata buttata leggendo un altro messaggio: {:?}",
            esito.err(),
        );
    }

    /// Reopening one's own identity card used to create a contact that is
    /// oneself: an address book that lies about whom one is encrypting for.
    #[test]
    fn la_propria_card_non_diventa_un_contatto() {
        let mut alice = sessione(1);
        let card = alice.identity_card(&mut rng(7));

        let esito = alice.handle_incoming_text(WHATSAPP, &card, 50).unwrap();
        let IncomingItem::OwnIdentityCard { fingerprint } = esito else {
            panic!("attesa la propria card, non un contatto");
        };
        assert_eq!(fingerprint, alice.my_fingerprint());

        // The line that matters: the address book did not grow. Recognising it
        // and pinning it anyway would be the same bug with a nicer message.
        assert!(alice.keyring.peers().unwrap().is_empty());
        // And nothing was selected as recipient.
        assert_eq!(alice.current_peer(WHATSAPP), None);
    }

    #[test]
    fn identity_card_fissa_la_chiave_ma_non_sceglie_il_destinatario() {
        let alice = sessione(1);
        let mut bob = sessione(2);

        let card = alice.identity_card(&mut rng(7));
        let IncomingItem::IdentityCard {
            peer,
            fingerprint,
            outcome,
        } = bob.handle_incoming_text(WHATSAPP, &card, 50).unwrap()
        else {
            panic!("attesa una identity card");
        };

        assert_eq!(peer, alice.identity.public());
        assert_eq!(fingerprint, alice.my_fingerprint());
        assert!(matches!(outcome, PinOutcome::Pinned));

        // THE LINE THAT MATTERS. A card is not authenticated: anyone can craft
        // one with their own key and get it to the victim. If decrypting it were
        // enough to become the recipient, a stranger would decide whom the
        // victim encrypts for.
        assert_eq!(bob.current_peer(WHATSAPP), None);
    }

    /// A stranger must not be able to hijack an established conversation by
    /// sending their own identity card.
    #[test]
    fn una_card_non_dirotta_il_destinatario_gia_scelto() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let estraneo = sessione(9);

        // Bob and Alice already talk: Bob read a message from Alice, and that
        // successful decryption is what authorises automatic recipient choice.
        alice.keyring.tofu_pin(&bob.identity.public(), 5).unwrap();
        alice
            .set_current_peer(WHATSAPP, &bob.identity.public())
            .unwrap();
        let msg = alice
            .encrypt_for_app(WHATSAPP, b"ciao", 10, &mut rng(3))
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &msg, 11).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));

        // A stranger's card arrives and Bob decrypts it.
        let card = estraneo.identity_card(&mut rng(8));
        bob.handle_incoming_text(WHATSAPP, &card, 12).unwrap();

        // The recipient must still be Alice.
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.identity.public()));
    }

    /// The full bootstrap cycle: Alice introduces herself, Bob pins her,
    /// CHOOSES to reply to her, and Alice reads.
    ///
    /// That choice is a user action, not automatic: a card is not
    /// authenticated, so it cannot decide whom to encrypt for. From then on
    /// automation applies, because Alice establishes the recipient by
    /// decrypting a real message.
    #[test]
    fn bootstrap_completo() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);

        let card = alice.identity_card(&mut rng(7));
        bob.handle_incoming_text(WHATSAPP, &card, 1).unwrap();

        // The explicit action the card does not perform on its behalf.
        bob.set_current_peer(WHATSAPP, &alice.identity.public())
            .unwrap();

        let risposta = bob
            .encrypt_for_app(WHATSAPP, b"ricevuto", 1_700_000_000, &mut rng(4))
            .unwrap();

        let IncomingItem::Message(msg) = alice
            .handle_incoming_text(WHATSAPP, &risposta, 2)
            .unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(msg.plaintext.as_bytes(), b"ricevuto");
        assert_eq!(msg.sender_status, SenderStatus::New);
        // And now Alice also knows whom to reply to, without choosing anything.
        assert_eq!(alice.current_peer(WHATSAPP), Some(&bob.identity.public()));
    }

    /// The chain: the first message starts at half strength and already carries
    /// the key that makes the next one full.
    #[test]
    fn la_catena_parte_col_primo_messaggio() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();

        // They know each other: without it an ephemeral sender is not
        // recognisable.
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        // First message: Alice has no temporary key of Bob's, so she falls back
        // to half forward secrecy, but already carries her own.
        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        assert!(
            bob.keyring.peer_prekey(&chiave_alice).unwrap().is_some(),
            "il primo messaggio deve far partire la catena"
        );

        // Bob's reply uses that key: full forward secrecy.
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"risposta", 12, &mut rng(8), true)
            .unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&due, &mut buf).unwrap() else {
            panic!()
        };
        let piena = parsed.header.origin.uses_prekey();
        assert!(piena, "la risposta doveva essere a forward secrecy piena");

        let letto = alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();
        let IncomingItem::Message(messaggio) = letto else {
            panic!("doveva essere un messaggio")
        };
        assert_eq!(messaggio.plaintext.as_bytes(), b"risposta");
        assert_eq!(messaggio.sender, chiave_bob);
    }

    /// An attachment must have the same chain as a message: a photo is worth
    /// more than a line of text, and stays on the recipient's phone.
    #[test]
    fn anche_gli_allegati_hanno_la_catena() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        let meta = crate::file::FileMeta {
            name: "foto.jpg".to_owned(),
            mime: "image/jpeg".to_owned(),
        };

        // First attachment: no key of Bob's, so ephemeral sender, but it already
        // carries her own and the chain starts.
        let uno = alice
            .encrypt_file_with(&chiave_bob, &meta, b"contenuto", 10, &mut rng(9), true)
            .unwrap();
        let letto = bob.handle_incoming_file(&uno, 11).unwrap();
        assert_eq!(letto.sender, chiave_alice);
        assert_eq!(letto.file.meta.name, "foto.jpg");
        assert_eq!(&*letto.file.content, b"contenuto");
        assert!(
            bob.keyring.peer_prekey(&chiave_alice).unwrap().is_some(),
            "anche un allegato deve far partire la catena"
        );

        // Bob's reply uses that key: full forward secrecy.
        let due = bob
            .encrypt_file_with(&chiave_alice, &meta, b"risposta", 12, &mut rng(8), true)
            .unwrap();
        let piena = crate::file::parse_file(&due).unwrap().header.origin.uses_prekey();
        assert!(piena, "il secondo allegato doveva essere a forward secrecy piena");

        let letto = alice.handle_incoming_file(&due, 13).unwrap();
        assert_eq!(letto.sender, chiave_bob);
        assert_eq!(&*letto.file.content, b"risposta");
    }

    /// An attachment must not be rereadable as a message: `kind` is in the AAD
    /// also in ephemeral-sender schemes.
    #[test]
    fn un_allegato_non_e_un_messaggio_nemmeno_con_la_catena() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();

        let meta = crate::file::FileMeta {
            name: "a".to_owned(),
            mime: "b".to_owned(),
        };
        let allegato = alice
            .encrypt_file_with(&chiave_bob, &meta, b"segreto", 10, &mut rng(9), true)
            .unwrap();

        // Same body, served again as a message: the AAD does not match.
        let come_messaggio = {
            let parsed = crate::file::parse_file(&allegato).unwrap();
            format::serialize_message(&parsed.header, parsed.ciphertext)
        };
        assert!(bob.handle_incoming_text(WHATSAPP, &come_messaggio, 11).is_err());
    }

    /// Copying one's own message again happens, and must not look like a
    /// failure.
    #[test]
    fn un_mio_messaggio_si_riapre_solo_senza_catena() {
        let mut alice = sessione(1);
        let bob = sessione(2);
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        // Without forward secrecy it reopens: the ECDH secret is symmetric, and
        // the recipient is found by trying contacts.
        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(9), false)
            .unwrap();
        let letto = alice.handle_incoming_text(WHATSAPP, &mio, 11).unwrap();
        let IncomingItem::OwnMessage {
            recipient,
            plaintext,
            ..
        } = letto
        else {
            panic!("doveva essere un messaggio nostro")
        };
        assert_eq!(recipient, chiave_bob);
        assert_eq!(plaintext.as_bytes(), b"ciao");

        // With forward secrecy our key does NOT exist, by construction: it stays
        // an opaque failure, as it should. If this test ever returned OwnMessage,
        // the sender identity would have become visible in the header.
        let effimero = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 12, &mut rng(8), true)
            .unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &effimero, 13),
            Err(Error::Crypto)
        ));
    }

    /// **The prekey window against split messages.**
    ///
    /// Since the keyboard splits long messages into parts encrypted one by
    /// one, "how many messages in a row" no longer equals "how many keys": one
    /// long message uses up to twelve. With the old cap of 32, three long
    /// messages in a row filled the window and the other side's reply could no
    /// longer be opened.
    ///
    /// The test sends 36 messages without a reply, then lets the other side read
    /// **only the first**: its reply uses the key seen there, the oldest of all.
    #[test]
    fn tre_messaggi_spezzati_di_fila_non_chiudono_la_finestra() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        let mut prima: Option<String> = None;
        for i in 0..36u8 {
            let parte = alice
                .encrypt_for_app_with(
                    WHATSAPP,
                    b"una parte",
                    10 + i64::from(i),
                    &mut rng(i),
                    true,
                )
                .unwrap();
            if prima.is_none() {
                prima = Some(parte);
            }
        }

        // Bob reads the first part and replies: his reply is encrypted to the key
        // Alice announced there.
        let prima = prima.unwrap();
        bob.handle_incoming_text(WHATSAPP, &prima, 100).unwrap();
        let risposta = bob
            .encrypt_for_app_with(WHATSAPP, b"ricevuto", 101, &mut rng(99), true)
            .unwrap();

        let letto = alice.handle_incoming_text(WHATSAPP, &risposta, 102).unwrap();
        let IncomingItem::Message(m) = letto else {
            panic!("la risposta doveva aprirsi: la chiave era ancora nella finestra")
        };
        assert_eq!(m.plaintext.as_bytes(), b"ricevuto");
    }

    /// **The reported case** behind [`Error::OwnMessageKeyGone`].
    ///
    /// The writer has forward secrecy off, the recipient on. The message goes
    /// to the recipient's **prekey** ([`Session::epoca_del_peer`] falls back to
    /// it when there is no epoch key), and that prekey advances with each
    /// message they send. Two replies later the writer rereads and it no longer
    /// opens. That is expected; the bug was the message, which said "that
    /// contact is no longer in your list" while the contact was right there.
    #[test]
    fn un_mio_messaggio_verso_una_prechiave_avanzata_non_incolpa_la_rubrica() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Bob writes first WITH forward secrecy: Alice records his prekey, the
        // only ephemeral key of Bob's she knows.
        let da_bob = bob
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(9), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &da_bob, 11).unwrap();

        // Alice replies WITHOUT: she encrypts with an epoch, and the recipient's
        // epoch is Bob's prekey, because he never sent a real epoch.
        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"la mia risposta", 12, &mut rng(8), false)
            .unwrap();
        // Just written, it still rereads: the key is the current one.
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 13),
            Ok(IncomingItem::OwnMessage { .. })
        ));
        assert!(bob.handle_incoming_text(WHATSAPP, &mio, 14).is_ok());

        // Bob replies again and his chain advances: Alice records the new prekey
        // in place of the one she encrypted to.
        let ancora_bob = bob
            .encrypt_for_app_with(WHATSAPP, b"e ancora", 15, &mut rng(7), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &ancora_bob, 16).unwrap();

        // From now on Alice's message does not reopen, and must say so for what
        // it is: the contact is still there.
        assert!(
            alice.keyring.get(&chiave_bob).unwrap().is_some(),
            "il contatto non e' stato toccato da niente"
        );
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 17),
            Err(Error::OwnMessageKeyGone)
        ));
        // And the same answer from the archive, which has its own path.
        assert!(matches!(
            alice.open_archived(&mio),
            Err(Error::OwnMessageKeyGone)
        ));
    }

    /// The other half: where the address book **is** the cause, the message
    /// must not change. An opening message reopens with identities alone, which
    /// neither expire nor advance: if it fails for every contact, the recipient
    /// really is not among them.
    #[test]
    fn un_mio_messaggio_di_apertura_incolpa_la_rubrica_e_ha_ragione() {
        let mut alice = sessione(1);
        let bob = sessione(2);
        let carol = sessione(3);
        let chiave_bob = bob.identity().public();
        let chiave_carol = carol.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        // First message of the conversation: bootstrap, encrypted to Bob's
        // identity.
        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"apriamo", 10, &mut rng(9), false)
            .unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 11),
            Ok(IncomingItem::OwnMessage { .. })
        ));

        // Alice forgets Bob and keeps Carol: the address book is not empty, but
        // whoever could open it is gone.
        assert!(alice.forget_peer(&chiave_bob).unwrap());
        alice.keyring.tofu_pin(&chiave_carol, 12).unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &mio, 13),
            Err(Error::OwnMessage)
        ));
    }

    /// Half of an exported chat was written by us: if it stayed closed,
    /// rebuilding would show a one-sided conversation.
    #[test]
    fn l_archivio_riapre_anche_i_miei_messaggi() {
        let mut alice = sessione(1);
        let bob = sessione(2);
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        let mio = alice
            .encrypt_for_app_with(WHATSAPP, b"scritto da me", 10, &mut rng(9), false)
            .unwrap();
        let (chi, testo) = alice.open_archived(&mio).unwrap();
        // "Who" is the recipient: in a two-person conversation that is what puts
        // the message in the right column.
        assert_eq!(chi, chiave_bob);
        assert_eq!(testo.as_bytes(), b"scritto da me");
    }

    /// Several messages in a row before the other side replies is the norm in
    /// chat. The replier uses the latest key **they have seen**: if newer ones
    /// were already dropped, the reply does not open. With a window of 3, four
    /// messages were enough.
    #[test]
    fn molti_messaggi_di_fila_non_rompono_la_risposta() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Alice writes many times in a row, well beyond the old window.
        let mut mandati = Vec::new();
        for i in 0..20u8 {
            mandati.push(
                alice
                    .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(i), true)
                    .unwrap(),
            );
        }
        // Bob reads only the FIRST; the others are still unread.
        let primo = mandati.first().unwrap();
        bob.handle_incoming_text(WHATSAPP, primo, 11).unwrap();
        // And replies.
        let risposta = bob
            .encrypt_for_app_with(WHATSAPP, b"risposta", 12, &mut rng(99), true)
            .unwrap();

        let letto = alice.handle_incoming_text(WHATSAPP, &risposta, 13).unwrap();
        let IncomingItem::Message(messaggio) = letto else {
            panic!("doveva essere un messaggio")
        };
        assert_eq!(messaggio.plaintext.as_bytes(), b"risposta");
    }

    /// An unusable temporary key must not be able to silence a conversation:
    /// fall back, do not stop being able to write.
    #[test]
    fn una_prekey_inservibile_non_ci_zittisce() {
        let mut alice = sessione(1);
        let chiave_bob = sessione(2).identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        // Low-order point: DH with it yields an all-zero secret.
        let veleno = PublicKey::from_bytes([0u8; 32]);
        alice.keyring.set_peer_prekey(&chiave_bob, &veleno).unwrap();

        // A contact must not be able to stop us writing to them.
        let blob = alice
            .encrypt_for_app_with(WHATSAPP, b"ciao", 10, &mut rng(1), true)
            .unwrap();
        // It fell back to the half scheme, not the poisoned chain.
        let mut buf = Vec::new();
        let ParsedBlob::Message(parsed) = format::parse(&blob, &mut buf).unwrap() else {
            panic!()
        };
        assert!(!parsed.header.origin.uses_prekey());

        // And an unusable incoming prekey never enters the keyring.
        let mut carla = sessione(3);
        let chiave_carla = carla.identity().public();
        alice.keyring.tofu_pin(&chiave_carla, 1).unwrap();
        carla.keyring.tofu_pin(&alice.identity().public(), 1).unwrap();
        carla.set_current_peer(WHATSAPP, &alice.identity().public()).unwrap();
        alice.ricorda_prekey(&chiave_carla, &veleno, 1, 1).unwrap();
        assert!(alice.keyring.peer_prekey(&chiave_carla).unwrap().is_none());
    }

    /// One of our attachments rereads like one of our messages: without the
    /// chain it is possible, and a difference between the two would be
    /// inexplicable.
    #[test]
    fn anche_un_allegato_mio_si_riapre() {
        let mut alice = sessione(1);
        let chiave_bob = sessione(2).identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        let meta = crate::file::FileMeta {
            name: "a.jpg".to_owned(),
            mime: "image/jpeg".to_owned(),
        };
        let mio = alice
            .encrypt_file_with(&chiave_bob, &meta, b"foto", 10, &mut rng(1), false)
            .unwrap();
        let letto = alice.handle_incoming_file(&mio, 11).unwrap();
        assert!(letto.nostro, "e' un allegato nostro, non ricevuto");
        assert_eq!(letto.sender, chiave_bob, "il peer e' il destinatario");
        assert_eq!(&*letto.file.content, b"foto");

        // With the chain on it stays closed, as for messages.
        let con_catena = alice
            .encrypt_file_with(&chiave_bob, &meta, b"foto", 12, &mut rng(2), true)
            .unwrap();
        assert!(alice.handle_incoming_file(&con_catena, 13).is_err());
    }

    /// **Forgetting a contact deletes nothing**, and that is better written in a
    /// test than discovered by chance.
    ///
    /// Without the chain, the reading key is not stored anywhere: it is
    /// **recomputed** from our identity and the sender's public key, which
    /// travels in clear inside the message. Removing the pin removes the name,
    /// not the ability to read. Hence a "burn this conversation" feature
    /// **cannot** be built on the keyring alone (see decision J).
    #[test]
    fn dimenticare_un_contatto_non_cancella_i_suoi_messaggi() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // Bob writes to Alice without forward secrecy.
        let messaggio = bob
            .encrypt_for_app_with(WHATSAPP, b"vecchio segreto", 10, &mut rng(1), false)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &messaggio, 11).unwrap();

        // Alice forgets Bob: pin gone, temporary keys gone.
        assert!(alice.forget_peer(&chiave_bob).unwrap());

        // It reopens anyway: the key is recomputed, not stored.
        let (chi, testo) = alice.open_archived(&messaggio).unwrap();
        assert_eq!(chi, chiave_bob);
        assert_eq!(testo.as_bytes(), b"vecchio segreto");
    }

    /// **Decision J.** Without the chain the conversation can be reread, by both
    /// sides, until it is burned; burning makes it disappear for both.
    #[test]
    fn bruciare_rende_illeggibile_da_tutte_e_due_le_parti() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // First message: no epoch key of the other side, so bootstrap. It must
        // still be rereadable: that is the point of the decision.
        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        assert!(matches!(
            alice.handle_incoming_text(WHATSAPP, &uno, 11),
            Ok(IncomingItem::OwnMessage { .. })
        ));

        // Reply: Bob now has Alice's epoch key and uses it.
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"secondo", 12, &mut rng(8), false)
            .unwrap();
        let mut buf = Vec::new();
        let ParsedBlob::Message(p) = format::parse(&due, &mut buf).unwrap() else {
            panic!()
        };
        let a_epoca = p.header.origin.uses_epoch();
        assert!(a_epoca, "la risposta doveva usare la chiave d'epoca");

        alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();
        // And it rereads as many times as wanted: here history exists.
        alice.handle_incoming_text(WHATSAPP, &due, 14).unwrap();
        assert!(bob.open_archived(&due).is_ok(), "Bob rilegge cio' che ha scritto");

        // Alice burns. On this side it is final, immediately.
        let richiesta = alice.burn_conversation(&chiave_bob, 15, &mut rng(7)).unwrap();
        assert!(alice.handle_incoming_text(WHATSAPP, &due, 16).is_err());

        // Bob receives the request and honours it: it disappears on his side too.
        let esito = bob.handle_incoming_text(WHATSAPP, &richiesta, 17).unwrap();
        let IncomingItem::Burned { peer, .. } = esito else {
            panic!("doveva essere un rogo")
        };
        assert_eq!(peer, chiave_alice);
        assert!(bob.open_archived(&due).is_err(), "il messaggio a epoca e' morto");

        // **RESIDUAL, stated plainly:** the opening message does NOT burn, for
        // either side. It is encrypted to Bob's identity, because when it was
        // sent nothing else was shared yet, and the identity survives a burn by
        // definition. Not fixable within this scheme: it would take an epoch key
        // in the identity card, so that an opening message is no longer needed.
        assert!(bob.open_archived(&uno).is_ok(), "il residuo, documentato");
        assert!(alice.open_archived(&uno).is_ok(), "vale anche per chi scrive");

        // The contact stays: the conversation is burned, not the person.
        assert!(bob.keyring.get(&chiave_alice).unwrap().is_some());

        // And one can start over without resending any identity card: the
        // first message restarts from the bootstrap.
        let tre = bob
            .encrypt_for_app_with(WHATSAPP, b"ricominciamo", 18, &mut rng(6), false)
            .unwrap();
        let letto = alice.handle_incoming_text(WHATSAPP, &tre, 19).unwrap();
        let IncomingItem::Message(m) = letto else {
            panic!("doveva essere un messaggio")
        };
        assert_eq!(m.plaintext.as_bytes(), b"ricominciamo");
    }

    /// A burn cannot be sent on someone else's behalf: whoever does not have the
    /// conversation cannot delete it.
    #[test]
    fn un_estraneo_non_puo_bruciare_le_conversazioni_altrui() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let mut mallory = sessione(3);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();

        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), false)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();

        // Mallory knows Bob and tries to burn his conversation.
        mallory.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        let falso = mallory.burn_conversation(&chiave_bob, 12, &mut rng(5)).unwrap();
        assert!(bob.handle_incoming_text(WHATSAPP, &falso, 13).is_err());

        // The conversation with Alice is intact.
        assert!(bob.open_archived(&uno).is_ok());
    }

    /// Reading an archive must not advance the chain: otherwise opening an old
    /// conversation would kill messages still in flight, and an export received
    /// from anyone could hijack the next conversation.
    #[test]
    fn leggere_un_archivio_non_muove_la_catena() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"secondo", 12, &mut rng(8), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();
        let tre = alice
            .encrypt_for_app_with(WHATSAPP, b"terzo", 14, &mut rng(7), true)
            .unwrap();

        // Bob has not read it yet: the key is still there, so the archive opens
        // it.
        let prima = bob.keyring.my_prekeys(&chiave_alice).unwrap();
        let (chi, testo) = bob.open_archived(&tre).unwrap();
        assert_eq!(chi, chiave_alice);
        assert_eq!(testo.as_bytes(), b"terzo");

        // And after reading it from the archive nothing changed.
        assert_eq!(bob.keyring.my_prekeys(&chiave_alice).unwrap(), prima);
        assert!(bob.handle_incoming_text(WHATSAPP, &tre, 15).is_ok());
    }

    /// **The accepted price:** once the chain has advanced *enough*, old
    /// messages no longer reopen, not even for their recipient.
    ///
    /// "Enough" is [`keys::CODA_MINIMA`]: the eight newest keys survive a read,
    /// so within that window a message reopens. Beyond it, it dies as before.
    #[test]
    fn la_cronologia_non_si_rilegge() {
        let mut alice = sessione(1);
        let mut bob = sessione(2);
        let chiave_alice = alice.identity().public();
        let chiave_bob = bob.identity().public();
        alice.keyring.tofu_pin(&chiave_bob, 1).unwrap();
        bob.keyring.tofu_pin(&chiave_alice, 1).unwrap();
        alice.set_current_peer(WHATSAPP, &chiave_bob).unwrap();
        bob.set_current_peer(WHATSAPP, &chiave_alice).unwrap();

        // They take turns until the chain has started on both sides.
        let uno = alice
            .encrypt_for_app_with(WHATSAPP, b"primo", 10, &mut rng(9), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &uno, 11).unwrap();
        let due = bob
            .encrypt_for_app_with(WHATSAPP, b"secondo", 12, &mut rng(8), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &due, 13).unwrap();

        // Alice replies: she uses Bob's prekey, and Bob drops his older keys on
        // reading it.
        let tre = alice
            .encrypt_for_app_with(WHATSAPP, b"terzo", 14, &mut rng(7), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &tre, 15).unwrap();
        let quattro = bob
            .encrypt_for_app_with(WHATSAPP, b"quarto", 16, &mut rng(6), true)
            .unwrap();
        alice.handle_incoming_text(WHATSAPP, &quattro, 17).unwrap();
        let cinque = alice
            .encrypt_for_app_with(WHATSAPP, b"quinto", 18, &mut rng(5), true)
            .unwrap();
        bob.handle_incoming_text(WHATSAPP, &cinque, 19).unwrap();

        // Within the minimum tail the third still reopens: that is the window,
        // on purpose.
        assert!(bob.handle_incoming_text(WHATSAPP, &tre, 20).is_ok());

        // But the window slides, and **Bob** slides it: the keys involved are
        // his, and a new one is born with every message he sends.
        let mut ultimo = String::new();
        for i in 0..(crate::keys::CODA_MINIMA + 2) {
            let n = i64::try_from(i).unwrap();
            ultimo = bob
                .encrypt_for_app_with(WHATSAPP, b"ancora", 30 + n, &mut rng(7), true)
                .unwrap();
        }
        // Alice reads the last one, learning the newest key, and replies with it.
        alice.handle_incoming_text(WHATSAPP, &ultimo, 50).unwrap();
        let recente = alice
            .encrypt_for_app_with(WHATSAPP, b"con la nuova", 51, &mut rng(8), true)
            .unwrap();
        // Reading it, Bob keeps the used key plus the seven after it: the key of
        // the third message is now too far back and drops.
        bob.handle_incoming_text(WHATSAPP, &recente, 52).unwrap();

        // Now it is dead, as before.
        assert!(
            bob.handle_incoming_text(WHATSAPP, &tre, 60).is_err(),
            "la catena e' avanzata oltre la coda: quel messaggio doveva morire"
        );
    }

    #[test]
    fn senza_destinatario_non_si_indovina() {
        let mut bob = sessione(2);
        assert!(matches!(
            bob.encrypt_for_app(WHATSAPP, b"per chi?", 1_700_000_000, &mut rng(1)),
            Err(Error::UnknownPeer)
        ));
    }

    #[test]
    fn destinatario_esplicito_solo_se_gia_noto() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();

        // Never seen: cannot be selected.
        assert!(matches!(
            bob.set_current_peer(WHATSAPP, &alice.public()),
            Err(Error::UnknownPeer)
        ));

        bob.keyring.tofu_pin(&alice.public(), 0).unwrap();
        bob.set_current_peer(WHATSAPP, &alice.public()).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&alice.public()));
    }

    /// A message that does not decrypt must leave NO trace in the keyring.
    ///
    /// That is why decryption comes before pinning: otherwise anyone could fill
    /// the keyring with invented peers by sending garbage, or show the user a
    /// false "key changed".
    #[test]
    fn messaggio_non_decifrabile_non_tocca_il_keyring() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let carol_pub = Identity::from_secret_bytes([3; 32]).unwrap().public();

        // A message from Alice to Carol: Bob cannot open it.
        let blob = crate::baseline::seal(&alice, &carol_pub, b"non per bob", 1_700_000_000, &mut rng(5)).unwrap();

        assert!(matches!(
            bob.handle_incoming_text(WHATSAPP, &blob, 1),
            Err(Error::Crypto)
        ));
        assert!(bob.keyring.get(&alice.public()).unwrap().is_none());
        assert_eq!(bob.current_peer(WHATSAPP), None);
    }

    #[test]
    fn tier_riservato_non_e_un_errore_crypto() {
        let mut bob = sessione(2);
        let alice = Identity::from_secret_bytes([1; 32]).unwrap();
        let blob =
            crate::baseline::seal(&alice, &bob.identity.public(), b"x", 1_700_000_000, &mut rng(6)).unwrap();

        // Raise the tier byte to ForwardSecret.
        let payload = blob.strip_prefix(format::SENTINEL).unwrap();
        let mut body = crate::encoding::decode(payload).unwrap();
        *body.get_mut(2).unwrap() = format::Tier::ForwardSecret as u8;
        let manomesso = format!("{}{}", format::SENTINEL, crate::encoding::encode(&body));

        assert!(matches!(
            bob.handle_incoming_text(WHATSAPP, &manomesso, 1),
            Err(Error::TierUnsupported)
        ));
    }

    #[test]
    fn conferma_del_cambio_chiave_sposta_anche_il_destinatario() {
        let mut bob = sessione(2);
        let vecchia = Identity::from_secret_bytes([1; 32]).unwrap().public();
        let nuova = Identity::from_secret_bytes([4; 32]).unwrap().public();

        bob.keyring.tofu_pin(&vecchia, 0).unwrap();
        bob.set_current_peer(WHATSAPP, &vecchia).unwrap();

        bob.confirm_key_change(&vecchia, &nuova, 10).unwrap();
        assert_eq!(bob.current_peer(WHATSAPP), Some(&nuova));
        assert!(bob.keyring.get(&vecchia).unwrap().is_none());
    }

    #[test]
    fn verifica_fuori_banda() {
        let mut bob = sessione(2);
        let alice_id = Identity::from_secret_bytes([1; 32]).unwrap();

        let blob =
            crate::baseline::seal(&alice_id, &bob.identity.public(), b"x", 1_700_000_000, &mut rng(9)).unwrap();
        bob.handle_incoming_text(WHATSAPP, &blob, 1).unwrap();
        bob.mark_verified(&alice_id.public()).unwrap();

        let blob2 =
            crate::baseline::seal(&alice_id, &bob.identity.public(), b"y", 1_700_000_000, &mut rng(8)).unwrap();
        let IncomingItem::Message(msg) = bob.handle_incoming_text(WHATSAPP, &blob2, 2).unwrap()
        else {
            panic!("atteso un messaggio");
        };
        assert_eq!(
            msg.sender_status,
            SenderStatus::Known {
                label: None,
                verified: true
            }
        );
    }

    /// The label is the contact identity, and assigning it is when TOFU becomes
    /// able to say "Mark's key changed". Before this choice the conflict could
    /// not be expressed: two different keys were simply two different peers.
    #[test]
    fn etichetta_duplicata_e_un_conflitto() {
        let mut bob = sessione(2);
        let marco = Identity::from_secret_bytes([1; 32]).unwrap().public();
        let finto_marco = Identity::from_secret_bytes([9; 32]).unwrap().public();

        bob.keyring.tofu_pin(&marco, 1).unwrap();
        bob.keyring.tofu_pin(&finto_marco, 2).unwrap();

        assert_eq!(bob.assign_label(&marco, "Marco").unwrap(), LabelOutcome::Assigned);

        let esito = bob.assign_label(&finto_marco, "Marco").unwrap();
        let LabelOutcome::Conflict {
            existing,
            existing_fingerprint,
            incoming_fingerprint,
        } = esito
        else {
            panic!("atteso un conflitto");
        };
        assert_eq!(existing, marco);
        assert_eq!(existing_fingerprint, Fingerprint::of(&marco));
        assert_eq!(incoming_fingerprint, Fingerprint::of(&finto_marco));

        // Nothing changed: the old key still has the name.
        assert_eq!(
            bob.keyring.get(&marco).unwrap().unwrap().label.as_deref(),
            Some("Marco")
        );
        assert!(bob.keyring.get(&finto_marco).unwrap().unwrap().label.is_none());
    }

    #[test]
    fn rietichettare_la_stessa_chiave_non_e_un_conflitto() {
        let mut bob = sessione(2);
        let marco = Identity::from_secret_bytes([1; 32]).unwrap().public();
        bob.keyring.tofu_pin(&marco, 1).unwrap();

        assert_eq!(bob.assign_label(&marco, "Marco").unwrap(), LabelOutcome::Assigned);
        assert_eq!(bob.assign_label(&marco, "Marco").unwrap(), LabelOutcome::Assigned);
        assert_eq!(
            bob.assign_label(&marco, "Marco R.").unwrap(),
            LabelOutcome::Assigned
        );
    }

    /// Confirming moves the name to the new key and does NOT inherit
    /// verification: a new key has not been compared out of band.
    #[test]
    fn la_conferma_sposta_etichetta_e_azzera_la_verifica() {
        let mut bob = sessione(2);
        let vecchia = Identity::from_secret_bytes([1; 32]).unwrap().public();
        let nuova = Identity::from_secret_bytes([9; 32]).unwrap().public();

        bob.keyring.tofu_pin(&vecchia, 1).unwrap();
        bob.assign_label(&vecchia, "Marco").unwrap();
        bob.mark_verified(&vecchia).unwrap();
        bob.set_current_peer(WHATSAPP, &vecchia).unwrap();

        bob.confirm_key_change(&vecchia, &nuova, 10).unwrap();

        let record = bob.keyring.get(&nuova).unwrap().unwrap();
        assert_eq!(record.label.as_deref(), Some("Marco"));
        assert!(!record.verified, "la verifica non si eredita");
        assert!(bob.keyring.get(&vecchia).unwrap().is_none());
        assert_eq!(bob.current_peer(WHATSAPP), Some(&nuova));
    }

    /// The fingerprint is stable forever: 24 characters in 6 groups of 4. If
    /// this test changes, every verification users already did is invalid.
    #[test]
    fn kat_fingerprint() {
        let alice = Identity::from_secret_bytes([0x11; 32]).unwrap();
        let mostrato = alice.fingerprint().display();

        assert_eq!(mostrato.len(), 29, "24 caratteri + 5 spazi");
        assert_eq!(mostrato.split(' ').count(), 6);
        assert!(mostrato.split(' ').all(|g| g.len() == 4));
        assert_eq!(mostrato, KAT_FINGERPRINT);
    }

    const KAT_FINGERPRINT: &str = "st8b 8gnj bz97 raos onxs ugao";
}
