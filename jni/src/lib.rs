//! JNI bridge between `keyboard-cipher-core` and the Android JVM.
//!
//! All the `unsafe` of the project lives here, and there is not much: the
//! `extern "system"` symbols the JVM calls. The core stays
//! `#![forbid(unsafe_code)]`, which is the whole reason the two crates are
//! separate.
//!
//! # Boundary rules
//!
//! - **Secrets cross as `byte[]`, never as `String`.** A `java.lang.String` is
//!   immutable: it cannot be zeroized and stays on the heap until GC. The
//!   Kotlin caller zeroizes the array as soon as it is done.
//! - **The private key never crosses** after initialisation. It stays in Rust;
//!   the JVM only handles incoming plaintext and outgoing blobs.
//! - **No panic may cross the boundary.** Unwinding out of an `extern`
//!   function is undefined behaviour, not a clean crash. Every entry point is
//!   wrapped in `catch_unwind`. The core should not panic (it denies `panic`,
//!   `unwrap_used`, `indexing_slicing`, `arithmetic_side_effects`), but
//!   "should not" is not enough when the alternative is UB.
//! - **A crypto failure is a single code.** The core does not distinguish
//!   causes on purpose; this layer must not reintroduce the distinction.
//!
//! # Why the state is global rather than a handle
//!
//! The idiomatic alternative would return a `Box::into_raw` to the JVM as a
//! `jlong`. Here it is dangerous: Android destroys and recreates the
//! `InputMethodService` freely, and a handle that outlives a lifecycle is a
//! use-after-free handed to the caller. There is exactly ONE identity per
//! device, so a singleton is also the honest model.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::{Mutex, OnceLock};

use jni::objects::{JByteArray, JClass, JIntArray, JObject, JString};
use jni::sys::{jboolean, jbyteArray, jint, jlong, jstring};
use jni::JNIEnv;
use rand_core::OsRng;
use zeroize::Zeroizing;

use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::file::FileMeta;
use keyboard_cipher_core::error::Error;
use keyboard_cipher_core::keys::{Identity, Keyring, LabelOutcome, PinOutcome, PublicKey, KEY_LEN};

mod keyring;
use keyring::MemoryKeyring;

/// Codes returned to the JVM. Stable: Kotlin `when`s on them.
mod code {
    use super::jint;
    pub const OK: jint = 0;
    /// Not one of our blobs. A NORMAL outcome, not an error.
    pub const NOT_OUR_BLOB: jint = 1;
    pub const FORMAT: jint = 2;
    pub const UNSUPPORTED_VERSION: jint = 3;
    pub const DECODE: jint = 4;
    /// Any crypto failure. No details, by construction.
    pub const CRYPTO: jint = 5;
    pub const UNKNOWN_PEER: jint = 6;
    pub const TIER_UNSUPPORTED: jint = 7;
    pub const KEYRING: jint = 8;
    /// Session not initialised, JNI error, or caught panic.
    pub const INTERNAL: jint = 9;
    /// We wrote it: only the recipient can open it. A NORMAL outcome (copying
    /// one's own message again).
    ///
    /// Here the cause is precise: the recipient is no longer in the keyring.
    pub const OWN_MESSAGE: jint = 10;
    /// We wrote it and the recipient is still there, but the recipient-side key
    /// it was encrypted to has been replaced or burned. As NORMAL as the
    /// previous one; only the user message changes.
    pub const OWN_MESSAGE_KEY_GONE: jint = 11;

    /// Outcomes of `handleIncomingText` when the code is OK.
    pub const ITEM_MESSAGE: jint = 0;
    pub const ITEM_IDENTITY_CARD: jint = 1;
    /// Encrypted attachment. See `nativeDecryptFile`.
    pub const ITEM_FILE: jint = 2;
    /// One of our messages, reopened. `senderKey` and the label are the
    /// RECIPIENT's: there is no sender to show.
    pub const ITEM_OWN_MESSAGE: jint = 3;
    /// One of our attachments, reopened. As above: the peer is the recipient.
    pub const ITEM_OWN_FILE: jint = 4;
    /// The other side asked to burn the conversation, and we did. No text.
    pub const ITEM_BURNED: jint = 5;
    /// Our own identity card, reopened: no contact was pinned.
    pub const ITEM_OWN_IDENTITY_CARD: jint = 6;

    /// Outcomes of `nativeBlobShape`. They describe the ENVELOPE, not the
    /// outcome.
    pub const SHAPE_UNKNOWN: jint = 0;
    pub const SHAPE_MESSAGE: jint = 1;
    /// A message that used the chain: only for these is "it opens once only" a
    /// true explanation.
    pub const SHAPE_MESSAGE_FS: jint = 2;
    pub const SHAPE_GROUP: jint = 3;
    pub const SHAPE_CARD: jint = 4;
    pub const SHAPE_BURN: jint = 5;
    /// Sender ephemeral key, no recipient temporary key: the first message with
    /// forward secrecy on. The recipient can reopen it at will; the author never.
    pub const SHAPE_MESSAGE_EPHEMERAL: jint = 6;
    /// Epoch scheme (decision J): rereadable by both while the epoch keys exist.
    /// It fails to open if the conversation was burned, not because "it opens
    /// once only".
    pub const SHAPE_MESSAGE_EPOCH: jint = 7;

    /// Outcomes of `assignLabel`.
    pub const LABEL_ASSIGNED: jint = 0;
    /// The label already belongs to another key: "safety number changed".
    pub const LABEL_CONFLICT: jint = 1;
}

fn code_of(error: &Error) -> jint {
    match error {
        Error::NotOurBlob => code::NOT_OUR_BLOB,
        Error::Format(_) => code::FORMAT,
        Error::UnsupportedVersion(_) => code::UNSUPPORTED_VERSION,
        Error::Decode => code::DECODE,
        Error::Crypto => code::CRYPTO,
        Error::UnknownPeer => code::UNKNOWN_PEER,
        Error::TierUnsupported => code::TIER_UNSUPPORTED,
        Error::OwnMessage => code::OWN_MESSAGE,
        Error::OwnMessageKeyGone => code::OWN_MESSAGE_KEY_GONE,
        Error::Keyring => code::KEYRING,
    }
}

/// The single process-wide state.
static SESSION: OnceLock<Mutex<Option<Session<MemoryKeyring>>>> = OnceLock::new();

fn session_slot() -> &'static Mutex<Option<Session<MemoryKeyring>>> {
    SESSION.get_or_init(|| Mutex::new(None))
}

/// Runs `body` with the session, if initialised.
///
/// A mutex poisoned by an earlier panic is recovered rather than propagated: at
/// that point the damage is done, and returning an error is more useful than
/// making the keyboard unusable until restart.
fn with_session<T, F>(body: F) -> Result<T, jint>
where
    F: FnOnce(&mut Session<MemoryKeyring>) -> Result<T, Error>,
{
    let mut guard = match session_slot().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    let session = guard.as_mut().ok_or(code::INTERNAL)?;
    body(session).map_err(|error| code_of(&error))
}

/// Barrier against unwinding into the JVM.
fn guard<T, F: FnOnce() -> T>(fallback: T, body: F) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or(fallback)
}

/// Clears a pending Java exception; must be called on EVERY failed JNI call.
///
/// When a JNI call fails (out of memory while allocating a string, an array
/// too large), the JVM **arms an exception on the thread** and leaves it
/// there; the return value is only the second copy of the news. Returning
/// `null` without clearing it closes nothing: the exception fires at the next
/// Java call, **far from here**, on code that did nothing wrong, and meanwhile
/// further JNI calls are undefined behaviour.
///
/// So the bridge clears it immediately and reports the failure **only**
/// through the return value, the one channel this boundary declares. This
/// applies to reads too: `get_string` and `convert_byte_array` arm an
/// exception just like `new_string`.
///
/// If `exception_clear` itself fails there is nothing lower to report to; the
/// return value still says the operation failed.
fn spegni_eccezione(env: &JNIEnv) {
    let _ = env.exception_clear();
}

fn read_string(env: &mut JNIEnv, value: &JString) -> Result<String, jint> {
    env.get_string(value).map(|s| s.into()).map_err(|_| {
        spegni_eccezione(env);
        code::INTERNAL
    })
}

fn new_string(env: &JNIEnv, value: &str) -> jstring {
    match env.new_string(value) {
        Ok(s) => s.into_raw(),
        Err(_) => {
            spegni_eccezione(env);
            std::ptr::null_mut()
        }
    }
}

fn new_byte_array(env: &JNIEnv, value: &[u8]) -> jbyteArray {
    match env.byte_array_from_slice(value) {
        Ok(array) => array.into_raw(),
        Err(_) => {
            spegni_eccezione(env);
            std::ptr::null_mut()
        }
    }
}

/// Like `read_bytes`, for data that must not stay in memory: private keys,
/// passphrases, plaintext of messages and attachments.
///
/// The only difference is `Zeroizing`, and two functions exist rather than a
/// parameter so that the return type **says** whether the input is a secret.
/// With `Zeroizing` the guarantee lives in `Drop`, so it holds for every exit
/// path, including early returns added later.
///
/// **It only covers the Rust copy.** The one inside the Java array stays alive
/// and must be zeroized by the caller; this is written on the signatures that
/// receive secrets.
fn read_secret_bytes(env: &mut JNIEnv, value: &JByteArray) -> Result<Zeroizing<Vec<u8>>, jint> {
    read_bytes(env, value).map(Zeroizing::new)
}

/// Stores the failure reason in the output array, if the caller passed one.
///
/// For functions that return a reference: `null` is all they can say, and it
/// lumps every cause together. A caller that wants to know **why** passes an
/// `int[1]`; one that does not passes `null` and pays nothing.
///
/// An output parameter rather than a "last error" to query afterwards: a last
/// error is global state, and with several threads calling the bridge it might
/// not be one's own.
///
/// If the write fails nothing is done: the `null` return already says the
/// operation failed, and an error while reporting an error must not become a
/// second failure. `spegni_eccezione` is there because a too-short array arms
/// an exception that must be cleared at once.
fn motivo(env: &mut JNIEnv, out: &JIntArray, codice: jint) {
    if out.is_null() {
        return;
    }
    if env.set_int_array_region(out, 0, &[codice]).is_err() {
        spegni_eccezione(env);
    }
}

fn read_bytes(env: &mut JNIEnv, value: &JByteArray) -> Result<Vec<u8>, jint> {
    env.convert_byte_array(value).map_err(|_| {
        spegni_eccezione(env);
        code::INTERNAL
    })
}

fn read_key(env: &mut JNIEnv, value: &JByteArray) -> Result<PublicKey, jint> {
    let bytes = read_bytes(env, value)?;
    let mut key = [0u8; KEY_LEN];
    if bytes.len() != KEY_LEN {
        return Err(code::FORMAT);
    }
    key.copy_from_slice(&bytes);
    Ok(PublicKey::from_bytes(key))
}

// ============================================================================
// Identity lifecycle
// ============================================================================

/// Generates a new identity and returns the 32 secret bytes, which the JVM must
/// encrypt with Android Keystore and persist.
///
/// This is the ONLY moment the private key crosses the boundary. The caller
/// zeroizes the array right after handing it to storage.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeGenerateSecret(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        use rand_core::RngCore;

        // OsRng: OS entropy. Never an in-app seeded PRNG.
        //
        // `Zeroizing` rather than manual `zeroize()` calls: zeroization lives in
        // `Drop` and survives new exit paths.
        let mut secret = Zeroizing::new([0u8; KEY_LEN]);
        OsRng.fill_bytes(&mut *secret);
        // Check that the bytes yield a valid identity before handing them to
        // storage: a secret that does not reload would be a permanent, silent
        // failure.
        if Identity::from_secret_bytes(*secret).is_err() {
            return std::ptr::null_mut();
        }
        new_byte_array(&env, &*secret)
    })
}

/// Initialises the session with a persisted secret and an exported keyring.
/// `keyringBlob` may be empty on first start.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeInit(
    mut env: JNIEnv,
    _class: JClass,
    secret: JByteArray,
    keyring_blob: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        // Secret and keyring blob are both key material: the first is the
        // identity, the second holds every contact's temporary and epoch keys.
        // This runs at every process start.
        let bytes = match read_secret_bytes(&mut env, &secret) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        if bytes.len() != KEY_LEN {
            return code::FORMAT;
        }
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(&bytes);
        let identity = match Identity::from_secret_bytes(*key) {
            Ok(identity) => identity,
            Err(error) => return code_of(&error),
        };

        let blob = match read_secret_bytes(&mut env, &keyring_blob) {
            Ok(blob) => blob,
            Err(codice) => return codice,
        };
        let keyring = if blob.is_empty() {
            MemoryKeyring::new()
        } else {
            match MemoryKeyring::import(&blob) {
                Ok(keyring) => keyring,
                Err(error) => return code_of(&error),
            }
        };

        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(Session::new(identity, keyring));
        code::OK
    })
}

// ============================================================================
// Operations
// ============================================================================

/// Forgets a peer.
///
/// The caller must already have warned the user: the pin is lost, and the next
/// message from that person will be silently pinned again as if new,
/// indistinguishable from someone impersonating them.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeForgetPeer(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let Ok(chiave) = read_key(&mut env, &peer) else {
            return code::FORMAT;
        };
        // Through Session rather than the keyring: forgetting must also remove
        // the peer from current recipients, otherwise it disappears from the
        // list while encryption continues to that key.
        match with_session(|session| session.forget_peer(&chiave)) {
            Ok(_) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// The name of the recipient for this app, shown in the keyboard.
///
/// The label if any, otherwise the fingerprint: two unnamed contacts can only
/// be told apart by it. `null` if there is no recipient, which is information,
/// not an error.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeCurrentPeerName(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let Ok(package) = read_string(&mut env, &app_package) else {
            return std::ptr::null_mut();
        };
        let nome = with_session(|session| {
            let Some(peer) = session.current_peer(&package) else {
                return Ok(None);
            };
            let etichetta = Keyring::get(session.keyring(), peer)?
                .and_then(|record| record.label)
                .unwrap_or_else(|| keyboard_cipher_core::keys::Fingerprint::of(peer).display());
            Ok(Some(etichetta))
        });
        match nome {
            Ok(Some(nome)) => new_string(&env, nome.as_str()),
            _ => std::ptr::null_mut(),
        }
    })
}

/// Is there a recipient for this app?
///
/// Lets the keyboard tell "I don't know whom to encrypt for" from "encryption
/// failed": the user resolves them differently, and without this question both
/// look like a key that does nothing.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeHasCurrentPeer(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
) -> jboolean {
    guard(0, || {
        let Ok(package) = read_string(&mut env, &app_package) else {
            return 0;
        };
        let presente = with_session(|session| Ok(session.current_peer(&package).is_some()));
        jboolean::from(presente.unwrap_or(false))
    })
}

/// Encrypts a file for an explicitly chosen peer.
///
/// The content crosses as `byte[]` and the caller zeroizes it once delivered.
///
/// No implicit recipient (decision G4): this path starts from a screen, not
/// from the keyboard, and a file sent to the wrong person cannot be withdrawn.
///
/// With a non-zero `forward` it **modifies the keyring**, like
/// `nativeEncryptForApp`: the caller must persist immediately.
///
/// `errorOut` is an optional `int[1]` (pass `null` to skip it) that receives
/// the reason when the result is `null`: `UNKNOWN_PEER` (the recipient was
/// forgotten after choosing the file), `FORMAT` (the file does not fit), or an
/// internal failure. At least one of these the user can fix.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptFile(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
    name: JString,
    mime: JString,
    content: JByteArray,
    now_unix: jlong,
    forward: jboolean,
    error_out: JIntArray,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let chiave = match read_key(&mut env, &peer) {
            Ok(chiave) => chiave,
            Err(codice) => {
                motivo(&mut env, &error_out, codice);
                return std::ptr::null_mut();
            }
        };
        let Ok(nome) = read_string(&mut env, &name) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return std::ptr::null_mut();
        };
        let Ok(tipo) = read_string(&mut env, &mime) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return std::ptr::null_mut();
        };
        // File content is plaintext like message text, and much more of it: up
        // to the cap of decision G6.
        let Ok(bytes) = read_secret_bytes(&mut env, &content) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return std::ptr::null_mut();
        };
        let meta = FileMeta { name: nome, mime: tipo };
        let esito = with_session(|session| {
            session.encrypt_file_with(&chiave, &meta, &bytes, now_unix, &mut OsRng, forward != 0)
        });
        match esito {
            Ok(blob) => new_byte_array(&env, &blob),
            Err(codice) => {
                motivo(&mut env, &error_out, codice);
                std::ptr::null_mut()
            }
        }
    })
}

/// Opens a received attachment and fills `result`.
///
/// As for messages, the core decrypts **before** touching the keyring: a
/// successful decryption proves the sender holds the declared private key.
///
/// **Opening also modifies the keyring, so persist immediately here too.**
/// Three distinct reasons, each leaving different damage if the process died
/// before saving:
///
/// - a never-seen sender is **pinned** (TOFU). Not persisted, it would be
///   silently pinned again next time, so a key change would never be noticed;
/// - opening a forward-secret message **drops** our older temporary keys
///   (decision I: reading drops, not replying). Not persisted, the dropped keys
///   come back on restart and the property the switch promises is gone;
/// - a burn (decision J) **destroys** the epoch key. Not persisted, the burned
///   conversation comes back on restart after the user was told it was over.
///
/// # The plaintext put into `result`
///
/// The text field is a `byte[]`, not a `String`, as always. The bridge cannot
/// zeroize it (it belongs to the caller), so **the caller zeroizes it as soon
/// as it has been shown or saved**. This is the one place in this file where a
/// secret travels towards the JVM rather than towards the core.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeDecryptFile(
    mut env: JNIEnv,
    _class: JClass,
    blob: JByteArray,
    now_unix: jlong,
    result: JObject,
) -> jint {
    guard(code::INTERNAL, || {
        let bytes = match read_bytes(&mut env, &blob) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let esito = with_session(|session| session.handle_incoming_file(&bytes, now_unix));
        let incoming = match esito {
            Ok(incoming) => incoming,
            Err(codice) => return codice,
        };

        let (etichetta, verificato) = match &incoming.sender_status {
            SenderStatus::New => (None, false),
            SenderStatus::Known { label, verified } => (label.clone(), *verified),
        };
        let genere = if incoming.nostro {
            code::ITEM_OWN_FILE
        } else {
            code::ITEM_FILE
        };
        if env
            .set_field(&result, "kind", "I", genere.into())
            .is_err()
            || env
                .set_field(&result, "verified", "I", jint::from(verificato).into())
                .is_err()
        {
            return code::INTERNAL;
        }
        let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&incoming.sender);
        if !fill_strings(&mut env, &result, &fingerprint.display(), etichetta.as_deref()) {
            return code::INTERNAL;
        }
        if env
            .set_field(
                &result,
                "sentAtUnix",
                "J",
                jni::objects::JValue::Long(incoming.file.sent_at_unix),
            )
            .is_err()
        {
            return code::INTERNAL;
        }
        let Ok(chiave) = env.byte_array_from_slice(incoming.sender.as_bytes()) else {
            return code::INTERNAL;
        };
        if env
            .set_field(&result, "senderKey", "[B", (&chiave).into())
            .is_err()
        {
            return code::INTERNAL;
        }
        // Name and type come from the sender: authenticated, not trustworthy.
        // Whoever uses them to save must sanitise them (`../`, path
        // separators).
        let Ok(nome) = env.new_string(&incoming.file.meta.name) else {
            return code::INTERNAL;
        };
        let Ok(tipo) = env.new_string(&incoming.file.meta.mime) else {
            return code::INTERNAL;
        };
        if env
            .set_field(&result, "fileName", "Ljava/lang/String;", (&nome).into())
            .is_err()
            || env
                .set_field(&result, "fileMime", "Ljava/lang/String;", (&tipo).into())
                .is_err()
        {
            return code::INTERNAL;
        }
        let Ok(contenuto) = env.byte_array_from_slice(&incoming.file.content) else {
            return code::INTERNAL;
        };
        if env
            .set_field(&result, "fileContent", "[B", (&contenuto).into())
            .is_err()
        {
            return code::INTERNAL;
        }
        code::OK
    })
}

/// Identity card blob to insert into the field with `commitText`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeIdentityCard(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        match with_session(|session| Ok(session.identity_card(&mut OsRng))) {
            Ok(card) => new_string(&env, &card),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Fingerprint of our identity, already formatted for the UI.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeMyFingerprint(
    env: JNIEnv,
    _class: JClass,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        match with_session(|session| Ok(session.my_fingerprint().display())) {
            Ok(fingerprint) => new_string(&env, &fingerprint),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Exports identity and keyring encrypted with a passphrase.
///
/// The passphrase arrives as `byte[]`, **not** `String`; the caller zeroizes
/// the array when done.
///
/// Returns the backup blob, or `null`. The `null` covers every failure, on
/// purpose: there is nothing useful for the caller to distinguish here.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeExportBackup(
    mut env: JNIEnv,
    _class: JClass,
    passphrase: JByteArray,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let pass = match read_secret_bytes(&mut env, &passphrase) {
            Ok(bytes) => bytes,
            Err(_) => return std::ptr::null_mut(),
        };
        let esito = with_session(|session| {
            // The exported keyring is key material too, not only the
            // passphrase: it holds every contact's temporary and epoch keys.
            let keyring = Zeroizing::new(session.keyring().export());
            keyboard_cipher_core::backup::export(
                session.identity(),
                &keyring,
                &pass,
                &mut OsRng,
            )
        });
        match esito {
            Ok(blob) => new_byte_array(&env, &blob),
            Err(_) => std::ptr::null_mut(),
        }
    })
}

/// Opens a backup and **replaces** the current identity and keyring.
///
/// Destructive: from here on the previous identity is unreachable from this
/// session. The caller must already have asked the user for confirmation and
/// must persist the result immediately; otherwise, if the process dies, the old
/// identity is on disk and the new one in memory.
///
/// The 32 secret bytes are written to `secretOut`, which the caller allocates
/// and zeroizes as soon as it has encrypted it for storage. There is no way to
/// get the secret out without someone holding it: the choice is between this
/// and no backups.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeImportBackup(
    mut env: JNIEnv,
    _class: JClass,
    blob: JByteArray,
    passphrase: JByteArray,
    secret_out: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let dati = match read_bytes(&mut env, &blob) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let pass = match read_secret_bytes(&mut env, &passphrase) {
            Ok(bytes) => bytes,
            Err(codice) => return codice,
        };
        let aperto = match keyboard_cipher_core::backup::import(&dati, &pass) {
            Ok(aperto) => aperto,
            Err(error) => return code_of(&error),
        };

        let identity = match Identity::from_secret_bytes(*aperto.secret) {
            Ok(identity) => identity,
            Err(error) => return code_of(&error),
        };
        let keyring = if aperto.keyring.is_empty() {
            MemoryKeyring::new()
        } else {
            match MemoryKeyring::import(&aperto.keyring) {
                Ok(keyring) => keyring,
                Err(error) => return code_of(&error),
            }
        };

        // The secret is written BEFORE replacing the session: if writing to the
        // array fails, better leave everything as it was than have a live
        // identity in memory and no way to persist it. The length is checked
        // first: a shorter array would arm a pending JNI exception.
        if env.get_array_length(&secret_out).unwrap_or(0) != KEY_LEN as jint {
            return code::FORMAT;
        }
        // Zeroizing: a copy of the 32 private key bytes, which would otherwise
        // stay on the heap until the allocation is reused.
        let temporaneo = zeroize::Zeroizing::new(
            aperto.secret.iter().map(|b| *b as i8).collect::<Vec<i8>>(),
        );
        if env
            .set_byte_array_region(&secret_out, 0, &temporaneo)
            .is_err()
        {
            return code::INTERNAL;
        }

        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        *guard = Some(Session::new(identity, keyring));
        code::OK
    })
}

/// Tells whether the text *looks like* it contains one of our blobs. No
/// decryption, no keyring access, no side effects.
///
/// For the UI: deciding whether to show a hint or offer "decrypt". NOT a
/// check: `true` says neither that the blob is intact nor that it is for us.
///
/// Unlike every other entry point it does NOT need an initialised session: it
/// only looks at the shape of the text, so it can be called before the
/// identity exists.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeLooksLikeOurBlob(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> jboolean {
    guard(0, || {
        let testo = match read_string(&mut env, &text) {
            Ok(testo) => testo,
            Err(_) => return 0,
        };
        u8::from(keyboard_cipher_core::format::looks_like_blob(&testo))
    })
}

/// The **shape** of this blob, without decrypting it.
///
/// Looks only at what travels in clear (version, kind, flag bits) and does not
/// touch the keyring, like `nativeLooksLikeOurBlob`. No session needed.
///
/// # Why it is not an oracle
///
/// An AEAD failure stays an opaque `Error::Crypto`, and this function does not
/// change that: it says neither **whether** a blob opens nor why it did not. It
/// says what is written on the envelope, which anyone intercepting the message
/// reads anyway. Callers use it **after** a failure, to pick a true sentence
/// instead of listing guesses (e.g. "it opens once only" is false for a blob
/// that never used forward secrecy, and for groups).
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeBlobShape(
    mut env: JNIEnv,
    _class: JClass,
    text: JString,
) -> jint {
    guard(code::SHAPE_UNKNOWN, || {
        let Ok(testo) = read_string(&mut env, &text) else {
            return code::SHAPE_UNKNOWN;
        };
        let mut buf = Vec::new();
        match keyboard_cipher_core::format::parse(&testo, &mut buf) {
            Ok(keyboard_cipher_core::format::ParsedBlob::Message(parsed)) => {
                forma_del_messaggio(&parsed.header.origin)
            }
            Ok(keyboard_cipher_core::format::ParsedBlob::Group(_)) => code::SHAPE_GROUP,
            Ok(keyboard_cipher_core::format::ParsedBlob::IdentityCard(_)) => code::SHAPE_CARD,
            Ok(keyboard_cipher_core::format::ParsedBlob::Burn(_)) => code::SHAPE_BURN,
            Err(_) => code::SHAPE_UNKNOWN,
        }
    })
}

/// The shape of a one-to-one message, from the origin declared on the envelope.
///
/// It looks at the origin, not just the `PREKEY` bit: that bit is carried by
/// **two** opposite schemes. With an ephemeral key it is the chain, which opens
/// once only; without, it is the epoch scheme, rereadable until burned.
fn forma_del_messaggio(origin: &keyboard_cipher_core::format::Origin) -> jint {
    use keyboard_cipher_core::format::Origin;
    match origin {
        Origin::EffimeraConPrekey(_) => code::SHAPE_MESSAGE_FS,
        Origin::Effimera(_) => code::SHAPE_MESSAGE_EPHEMERAL,
        Origin::MittenteConPrekey(_) => code::SHAPE_MESSAGE_EPOCH,
        Origin::Assente | Origin::Mittente(_) | Origin::MittenteConEpoca(_) => {
            code::SHAPE_MESSAGE
        }
    }
}

/// Encrypts for the app's current recipient. `null` if there is none.
///
/// With a non-zero `forward` it **modifies the keyring** (it stores a new
/// temporary key). The caller must export and persist it immediately, or the
/// reply will be encrypted to a key that no longer exists.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptForApp(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    plaintext: JByteArray,
    now_unix: jlong,
    forward: jboolean,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let nullo: jstring = std::ptr::null_mut();
        let Ok(package) = read_string(&mut env, &app_package) else {
            return nullo;
        };
        let Ok(bytes) = read_secret_bytes(&mut env, &plaintext) else {
            return nullo;
        };

        let esito = with_session(|session| {
            session.encrypt_for_app_with(&package, &bytes, now_unix, &mut OsRng, forward != 0)
        });
        match esito {
            Ok(blob) => new_string(&env, &blob),
            Err(_) => nullo,
        }
    })
}

/// Encrypts for several recipients (decision K).
///
/// Keys arrive **concatenated** in one `byte[]`, 32 bytes each, rather than as
/// `byte[][]`: an array of arrays through JNI needs a local reference per row
/// and a loop to release them, i.e. more `unsafe` code for the same data. The
/// count follows from the length; a length that is not a multiple of 32 is a
/// caller error.
///
/// **No forward secrecy**, by decision: whoever shows the result must tell the
/// user.
///
/// `errorOut` is an optional `int[1]` receiving the reason when the result is
/// `null`. Mostly for `UNKNOWN_PEER`: a saved group keeps its members' keys,
/// and a member may have been forgotten since. It is the one failure the user
/// can fix alone.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeEncryptGroup(
    mut env: JNIEnv,
    _class: JClass,
    peers: JByteArray,
    plaintext: JByteArray,
    now_unix: jlong,
    error_out: JIntArray,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let nullo: jstring = std::ptr::null_mut();
        let Ok(chiavi) = read_bytes(&mut env, &peers) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return nullo;
        };
        if chiavi.is_empty() || chiavi.len() % KEY_LEN != 0 {
            motivo(&mut env, &error_out, code::FORMAT);
            return nullo;
        }
        let destinatari: Vec<keyboard_cipher_core::keys::PublicKey> = chiavi
            .chunks_exact(KEY_LEN)
            .map(|pezzo| {
                let mut bytes = [0u8; KEY_LEN];
                bytes.copy_from_slice(pezzo);
                keyboard_cipher_core::keys::PublicKey::from_bytes(bytes)
            })
            .collect();

        let Ok(bytes) = read_secret_bytes(&mut env, &plaintext) else {
            motivo(&mut env, &error_out, code::INTERNAL);
            return nullo;
        };
        let esito = with_session(|session| {
            session.encrypt_group(&destinatari, &bytes, now_unix, &mut OsRng)
        });
        match esito {
            Ok(blob) => new_string(&env, &blob),
            Err(codice) => {
                motivo(&mut env, &error_out, codice);
                nullo
            }
        }
    })
}

/// Single entry point for all four ways a blob can arrive (clipboard,
/// `ACTION_PROCESS_TEXT`, share sheet, input field).
///
/// Fills the `result` object passed by the caller instead of building one:
/// constructing objects from JNI requires resolving class and constructor
/// signature at runtime, and every mistake becomes an exception thrown in the
/// middle of a crypto operation. Filling fields of an object allocated on the
/// Java side is duller and much harder to get wrong.
///
/// **Not a read: it modifies the keyring, and the caller persists
/// immediately.** It pins never-seen senders, drops our temporary keys older
/// than the one used, and on a burn destroys the epoch key (see
/// `nativeDecryptFile` for the consequences of not persisting).
///
/// The opened text arrives in `result` as `byte[]`, and **the caller zeroizes
/// it** once shown.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeHandleIncomingText(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    text: JString,
    now_unix: jlong,
    result: JObject,
) -> jint {
    guard(code::INTERNAL, || {
        let package = match read_string(&mut env, &app_package) {
            Ok(package) => package,
            Err(codice) => return codice,
        };
        let testo = match read_string(&mut env, &text) {
            Ok(testo) => testo,
            Err(codice) => return codice,
        };

        let esito = with_session(|session| session.handle_incoming_text(&package, &testo, now_unix));
        let item = match esito {
            Ok(item) => item,
            Err(codice) => return codice,
        };

        let mut set_int = |campo: &str, valore: jint| {
            env.set_field(&result, campo, "I", valore.into()).is_ok()
        };

        match item {
            IncomingItem::Message(message) => {
                let (etichetta, verificato) = match &message.sender_status {
                    SenderStatus::New => (None, false),
                    SenderStatus::Known { label, verified } => (label.clone(), *verified),
                };

                if !set_int("kind", code::ITEM_MESSAGE)
                    || !set_int("verified", jint::from(verificato))
                    // How many people could read it, sender included. Lets the UI
                    // say that a group message has NO forward secrecy (decision
                    // K1). An explicit flag, not a threshold on the count.
                    || !set_int("isGroup", jint::from(message.gruppo))
                    || !set_int(
                        "recipientCount",
                        jint::try_from(message.destinatari).unwrap_or(0),
                    )
                {
                    return code::INTERNAL;
                }
                let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&message.sender);
                if !fill_strings(
                    &mut env,
                    &result,
                    &fingerprint.display(),
                    etichetta.as_deref(),
                ) {
                    return code::INTERNAL;
                }
                // Composition date declared by the sender. Authenticated but NOT
                // verifiable: it helps the user notice a reposted blob, it
                // decides nothing automatically.
                if env
                    .set_field(
                        &result,
                        "sentAtUnix",
                        "J",
                        jni::objects::JValue::Long(message.plaintext.sent_at_unix()),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                // The public key lets the caller label the sender or select it
                // as recipient.
                let Ok(chiave) = env.byte_array_from_slice(message.sender.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                // The plaintext leaves as byte[]: never String.
                let Ok(array) = env.byte_array_from_slice(message.plaintext.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "plaintext", "[B", (&array).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::Burned { peer, sent_at_unix } => {
                if !set_int("kind", code::ITEM_BURNED) || !set_int("verified", 0) {
                    return code::INTERNAL;
                }
                // The date of the request. A burn blob stays valid forever and
                // can be pasted again months later; rejecting it by date is ruled
                // out by decision C, but showing the date makes replay visible.
                if env
                    .set_field(
                        &result,
                        "sentAtUnix",
                        "J",
                        jni::objects::JValue::Long(sent_at_unix),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&peer);
                let etichetta = session_label(&peer).unwrap_or_default();
                if !fill_strings(&mut env, &result, &fingerprint.display(), etichetta.as_deref()) {
                    return code::INTERNAL;
                }
                let Ok(chiave) = env.byte_array_from_slice(peer.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::OwnMessage {
                recipient,
                recipient_label,
                plaintext,
            } => {
                // Same fields as a message, but the peer is the recipient. The
                // caller already knows from `kind` how to present it.
                if !set_int("kind", code::ITEM_OWN_MESSAGE) || !set_int("verified", 0) {
                    return code::INTERNAL;
                }
                let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&recipient);
                if !fill_strings(
                    &mut env,
                    &result,
                    &fingerprint.display(),
                    recipient_label.as_deref(),
                ) {
                    return code::INTERNAL;
                }
                if env
                    .set_field(
                        &result,
                        "sentAtUnix",
                        "J",
                        jni::objects::JValue::Long(plaintext.sent_at_unix()),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                let Ok(chiave) = env.byte_array_from_slice(recipient.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                let Ok(array) = env.byte_array_from_slice(plaintext.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "plaintext", "[B", (&array).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::IdentityCard {
                peer,
                fingerprint,
                outcome,
            } => {
                let nuovo = matches!(outcome, PinOutcome::Pinned);
                // `verified` stays 0. It means "compared in person", the system's
                // only anti-MITM signal: setting it because the key was already
                // pinned would let anyone obtain it by sending the same card
                // twice.
                if !set_int("kind", code::ITEM_IDENTITY_CARD)
                    || !set_int("alreadyPinned", jint::from(!nuovo))
                    || !set_int("verified", 0)
                {
                    return code::INTERNAL;
                }
                // The label is needed: this branch says "you already have this
                // key", and without the saved name the sentence is true but
                // useless.
                let etichetta = session_label(&peer).unwrap_or_default();
                if !fill_strings(
                    &mut env,
                    &result,
                    &fingerprint.display(),
                    etichetta.as_deref(),
                ) {
                    return code::INTERNAL;
                }
                let Ok(chiave) = env.byte_array_from_slice(peer.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "senderKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            IncomingItem::OwnIdentityCard { fingerprint } => {
                // No `senderKey`: there is no peer, and filling it with our own
                // key would invite treating it as a contact.
                if !set_int("kind", code::ITEM_OWN_IDENTITY_CARD)
                    || !set_int("alreadyPinned", 0)
                    || !set_int("verified", 0)
                {
                    return code::INTERNAL;
                }
                if !fill_strings(&mut env, &result, &fingerprint.display(), None) {
                    return code::INTERNAL;
                }
                code::OK
            }
        }
    })
}

/// Fills the string fields of the result: the sender's fingerprint and, if
/// any, the label the user gave them.
fn fill_strings(
    env: &mut JNIEnv,
    result: &JObject,
    sender: &str,
    label: Option<&str>,
) -> bool {
    let Ok(sender_obj) = env.new_string(sender) else {
        return false;
    };
    if env
        .set_field(
            result,
            "senderFingerprint",
            "Ljava/lang/String;",
            (&sender_obj).into(),
        )
        .is_err()
    {
        return false;
    }
    if let Some(label) = label {
        let Ok(label_obj) = env.new_string(label) else {
            return false;
        };
        if env
            .set_field(
                result,
                "senderLabel",
                "Ljava/lang/String;",
                (&label_obj).into(),
            )
            .is_err()
        {
            return false;
        }
    }
    true
}

/// Explicit recipient selection from the toolbar.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeSetCurrentPeer(
    mut env: JNIEnv,
    _class: JClass,
    app_package: JString,
    peer: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let package = match read_string(&mut env, &app_package) {
            Ok(package) => package,
            Err(codice) => return codice,
        };
        let key = match read_key(&mut env, &peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        match with_session(|session| session.set_current_peer(&package, &key)) {
            Ok(()) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Replaces a pin after EXPLICIT user confirmation. Never called automatically
/// after a conflict.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeConfirmKeyChange(
    mut env: JNIEnv,
    _class: JClass,
    old_peer: JByteArray,
    new_peer: JByteArray,
    now_unix: jlong,
) -> jint {
    guard(code::INTERNAL, || {
        let old = match read_key(&mut env, &old_peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        let new = match read_key(&mut env, &new_peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        match with_session(|session| session.confirm_key_change(&old, &new, now_unix)) {
            Ok(()) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Marks a peer as verified out of band (fingerprint compared).
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeMarkVerified(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
) -> jint {
    guard(code::INTERNAL, || {
        let key = match read_key(&mut env, &peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        match with_session(|session| session.mark_verified(&key)) {
            Ok(()) => code::OK,
            Err(codice) => codice,
        }
    })
}

/// Exports the keyring for the JVM to encrypt and persist.
///
/// **Contains PRIVATE keys**: the forward secrecy chain prekeys are at the end
/// of the blob. This blob must be encrypted before it touches the disk, and must
/// not be handed to anything that only needs names (use `export_pubblico` for
/// that).
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeExportKeyring(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_mut() {
            Some(session) => new_byte_array(&env, &session.keyring().export()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Peer name. Takes the session lock again instead of reusing the caller's:
/// this is not inside a crypto operation, so the cost is nil and the code stays
/// readable.
fn session_label(
    peer: &keyboard_cipher_core::keys::PublicKey,
) -> keyboard_cipher_core::Result<Option<String>> {
    let mut guard = match session_slot().lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    };
    match guard.as_mut() {
        Some(session) => Ok(session.keyring().get(peer)?.and_then(|r| r.label)),
        None => Ok(None),
    }
}

/// **Burns the conversation** with a peer (decision J).
///
/// Returns the blob to deliver to the other person, or `null`. On this side the
/// effect has already happened when the function returns: **the caller must
/// persist immediately**, otherwise a dying process leaves the keys on disk.
///
/// On the other side it is a request, not a command: the recipient's app must
/// honour it. Do not present it as guaranteed deletion.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeBurnConversation(
    env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
    now_unix: jlong,
) -> jstring {
    guard(std::ptr::null_mut(), || {
        let mut env = env;
        let nullo: jstring = std::ptr::null_mut();
        let Ok(chiave) = read_key(&mut env, &peer) else {
            return nullo;
        };
        let esito =
            with_session(|session| session.burn_conversation(&chiave, now_unix, &mut OsRng));
        match esito {
            // If the string cannot be built, the burn HAS ALREADY HAPPENED: the
            // keys are destroyed. Returning `null` would tell the caller "failed"
            // about an irreversible operation that worked.
            //
            // So three outcomes, not two: `null` = not burned, empty string =
            // burned with no request to deliver, non-empty string = all done.
            // This is mirrored on the Kotlin side.
            Ok(blob) => {
                let costruita = new_string(&env, &blob);
                if costruita.is_null() {
                    new_string(&env, "")
                } else {
                    costruita
                }
            }
            Err(_) => nullo,
        }
    })
}

/// List of known peers for the contacts UI, in the **same format** as
/// `nativeExportKeyring`.
///
/// Reusing the storage format for the UI has a cost: `PeerList.parse` on the
/// Kotlin side is a second reader of this format, and changing it breaks that
/// reader without anything here noticing. If this format changes, that file
/// must be updated too.
///
/// **No private key leaves here.** This uses `export_pubblico`, which stops
/// before the chain; serving the persistence blob would copy private prekeys
/// into a JVM `byte[]` that nobody zeroizes, just to read names. If more data is
/// ever needed here, add it to `export_pubblico`.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeListPeers(
    env: JNIEnv,
    _class: JClass,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
        let mut guard = match session_slot().lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        match guard.as_mut() {
            Some(session) => new_byte_array(&env, &session.keyring().export_pubblico()),
            None => std::ptr::null_mut(),
        }
    })
}

/// Fingerprint of any public key, already formatted.
///
/// The peer need not be in the keyring: also used to show the incoming key
/// during a conflict, which by definition is not pinned.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeFingerprintOf(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
) -> jstring {
    guard(std::ptr::null_mut(), || match read_key(&mut env, &peer) {
        Ok(key) => {
            let fingerprint = keyboard_cipher_core::keys::Fingerprint::of(&key);
            new_string(&env, &fingerprint.display())
        }
        Err(_) => std::ptr::null_mut(),
    })
}

/// Assigns a name to an already pinned key.
///
/// This is where TOFU becomes able to say "Mark's key changed": without a
/// contact identity independent of the key, two different keys would just be
/// two different peers.
///
/// On conflict it changes NOTHING and fills `result` with the two fingerprints
/// to show. Only if the user confirms is `nativeConfirmKeyChange` called; never
/// automatically.
#[unsafe(no_mangle)]
pub extern "system" fn Java_helium314_keyboard_cipher_CipherCore_nativeAssignLabel(
    mut env: JNIEnv,
    _class: JClass,
    peer: JByteArray,
    label: JString,
    result: JObject,
) -> jint {
    guard(code::INTERNAL, || {
        let key = match read_key(&mut env, &peer) {
            Ok(key) => key,
            Err(codice) => return codice,
        };
        let nome = match read_string(&mut env, &label) {
            Ok(nome) => nome,
            Err(codice) => return codice,
        };

        let esito = with_session(|session| session.assign_label(&key, &nome));
        let esito = match esito {
            Ok(esito) => esito,
            Err(codice) => return codice,
        };

        match esito {
            LabelOutcome::Assigned => {
                if env
                    .set_field(&result, "kind", "I", code::LABEL_ASSIGNED.into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
            LabelOutcome::Conflict {
                existing,
                existing_fingerprint,
                incoming_fingerprint,
            } => {
                if env
                    .set_field(&result, "kind", "I", code::LABEL_CONFLICT.into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                if !fill_strings(&mut env, &result, &incoming_fingerprint.display(), None) {
                    return code::INTERNAL;
                }
                let Ok(esistente) = env.new_string(existing_fingerprint.display()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(
                        &result,
                        "existingFingerprint",
                        "Ljava/lang/String;",
                        (&esistente).into(),
                    )
                    .is_err()
                {
                    return code::INTERNAL;
                }
                // The already labelled key is needed by `nativeConfirmKeyChange`.
                let Ok(chiave) = env.byte_array_from_slice(existing.as_bytes()) else {
                    return code::INTERNAL;
                };
                if env
                    .set_field(&result, "existingKey", "[B", (&chiave).into())
                    .is_err()
                {
                    return code::INTERNAL;
                }
                code::OK
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use keyboard_cipher_core::format::Origin;
    use keyboard_cipher_core::keys::PublicKey;

    /// The `PREKEY` bit is used by two opposite schemes, the chain and the
    /// epoch. The shape must tell them apart, or a message with forward secrecy
    /// off is explained as one that had it on.
    #[test]
    fn la_forma_separa_catena_epoca_ed_effimera() {
        let k = PublicKey::from_bytes([7u8; 32]);
        assert_eq!(forma_del_messaggio(&Origin::EffimeraConPrekey(k.clone())), code::SHAPE_MESSAGE_FS);
        assert_eq!(forma_del_messaggio(&Origin::MittenteConPrekey(k.clone())), code::SHAPE_MESSAGE_EPOCH);
        assert_eq!(forma_del_messaggio(&Origin::Effimera(k.clone())), code::SHAPE_MESSAGE_EPHEMERAL);
        assert_eq!(forma_del_messaggio(&Origin::Mittente(k.clone())), code::SHAPE_MESSAGE);
        assert_eq!(forma_del_messaggio(&Origin::MittenteConEpoca(k)), code::SHAPE_MESSAGE);
        assert_eq!(forma_del_messaggio(&Origin::Assente), code::SHAPE_MESSAGE);
    }
}
