//! `kc`: the other party, from the command line.
//!
//! Used to test the keyboard **alone**. With the phone only, you can encrypt to
//! yourself, which tests the encrypt/decrypt round trip and nothing that needs
//! two distinct identities: identity cards, first contact, key change, label
//! conflict, wrong recipient. Those are also the paths where failures do the
//! most damage.
//!
//! Typical use with a chat's "saved messages": `kc card` prints the identity
//! card, you paste it into the chat and decrypt it on the phone; from then on
//! the two sides write to each other, every blob going through the clipboard.
//!
//! No network I/O, no talking to the phone: the only channel between the two
//! parties is you copying and pasting.

mod store;

use std::io::Read;

use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::file::FileMeta;
use keyboard_cipher_core::format::SENTINEL;
use keyboard_cipher_core::keys::{Fingerprint, Keyring, LabelOutcome, PinOutcome, PublicKey};
use rand_core::{OsRng, RngCore};
use store::{FileKeyring, State};

const APP: &str = "cli";

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("kc: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("help");
    let rest: &[String] = args.get(1..).unwrap_or(&[]);

    match command {
        "init" => cmd_init(rest),
        "id" => cmd_id(),
        "card" => cmd_card(),
        "contacts" => cmd_contacts(),
        "name" => cmd_name(rest),
        "verify" => cmd_verify(rest),
        "encrypt" => cmd_encrypt(rest),
        "decrypt" => cmd_decrypt(rest),
        "burn" => cmd_burn(rest),
        "sealfile" => cmd_sealfile(rest),
        "openfile" => cmd_openfile(rest),
        "archive" => cmd_archive(rest),
        "help" | "--help" | "-h" => {
            print!("{USAGE}");
            Ok(())
        }
        other => Err(format!("comando sconosciuto: {other}\n\n{USAGE}")),
    }
}

const USAGE: &str = "\
kc — l'altra parte di keyboard-cipher, per provare la tastiera da soli.

  kc init [--force]        crea l'identita'
  kc id                    fingerprint e percorso dello stato
  kc card                  la propria presentazione, da incollare in chat
  kc contacts              elenco dei contatti
  kc name <chi> <nome>     attribuisce un nome a una chiave
  kc verify <chi>          segna il fingerprint come confrontato di persona
  kc encrypt --to <chi> [testo]   cifra (se manca il testo, legge da stdin)
                                  --no-fs: senza forward secrecy, rileggibile
  kc decrypt [blob]        decifra un messaggio o fissa una presentazione
  kc burn <chi>            brucia la conversazione: non si rilegge piu'
  kc sealfile --to <chi> <file>    cifra un file, scrive <file>.kc (--no-fs)
  kc openfile <file.kc> [dove]     apre un allegato cifrato
  kc archive <esportazione>        decifra tutti i messaggi di una chat esportata

<chi> e' un nome, un indice di `kc contacts`, o l'inizio di un fingerprint.

La forward secrecy e' accesa: ogni messaggio porta una chiave nuova e leggere
una risposta butta le vecchie. Chi ti sequestra il telefono domani non apre i
messaggi di oggi — e non li apri piu' nemmeno tu. Con `--no-fs` restano
rileggibili, e `kc archive` funziona.

Lo stato sta in $KC_HOME oppure in ~/.local/share/keyboard-cipher/state, con
permessi 0600. La chiave privata e' in chiaro: sul telefono la protegge Android
Keystore, qui non c'e' niente di equivalente. E' uno strumento per provare —
questa identita' non vale quanto quella del telefono.
";

// ---------------------------------------------------------------------------

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn load() -> Result<State, String> {
    let path = store::state_path();
    match State::load(&path).map_err(|e| format!("stato illeggibile ({}): {e}", path.display()))? {
        Some(state) => Ok(state),
        None => Err(format!(
            "nessuna identita' in {}. Creala con `kc init`.",
            path.display()
        )),
    }
}

// ---------------------------------------------------------------------------

fn cmd_init(args: &[String]) -> Result<(), String> {
    let path = store::state_path();
    let force = args.iter().any(|a| a == "--force");
    let existing = State::load(&path).map_err(|e| format!("stato illeggibile: {e}"))?;
    if existing.is_some() && !force {
        return Err(format!(
            "esiste gia' un'identita' in {}. `--force` la sostituisce, e i \
             messaggi ricevuti finora non saranno piu' decifrabili.",
            path.display()
        ));
    }

    // OsRng: OS entropy. Never an in-app seeded PRNG.
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    // Build the identity before writing: a secret that does not reload would be
    // an unusable state created silently.
    let state = State::create(secret).map_err(|e| format!("segreto non valido: {e}"))?;
    store::save(&path, &secret, &state.keyring)
        .map_err(|e| format!("non riesco a scrivere {}: {e}", path.display()))?;
    println!("identita' creata: {}", state.identity.fingerprint().display());
    println!("stato: {}", path.display());
    Ok(())
}

fn cmd_id() -> Result<(), String> {
    let state = load()?;
    println!("fingerprint: {}", state.identity.fingerprint().display());
    println!("stato:       {}", store::state_path().display());
    println!("contatti:    {}", state.keyring.peers().len());
    Ok(())
}

fn cmd_card() -> Result<(), String> {
    let state = load()?;
    let session = Session::new(state.identity, state.keyring);
    println!("{}", session.identity_card(&mut OsRng));
    Ok(())
}

fn cmd_contacts() -> Result<(), String> {
    let state = load()?;
    if state.keyring.peers().is_empty() {
        println!("nessun contatto. Decifra una presentazione con `kc decrypt`.");
        return Ok(());
    }
    for (i, peer) in state.keyring.peers().iter().enumerate() {
        let name = peer.label.as_deref().unwrap_or("(senza nome)");
        let mark = if peer.verified { " ✓" } else { "" };
        println!(
            "{i}. {name}{mark}\n   {}",
            Fingerprint::of(&peer.public).display()
        );
    }
    Ok(())
}

fn cmd_name(args: &[String]) -> Result<(), String> {
    let who = args.first().ok_or("manca <chi>. Vedi `kc help`.")?;
    let label = args.get(1).ok_or("manca il nome. Vedi `kc help`.")?;
    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;
    let mut session = Session::new(state.identity, state.keyring);
    let outcome = session
        .assign_label(&peer, label)
        .map_err(|e| format!("{e}"))?;
    match outcome {
        LabelOutcome::Assigned => {
            persist(&secret, &session)?;
            println!("ora si chiama {label}.");
        }
        // Not an error: a state that needs a decision. Nothing changes here, and
        // the old key keeps the name.
        LabelOutcome::Conflict {
            existing_fingerprint,
            incoming_fingerprint,
            ..
        } => {
            println!("«{label}» appartiene gia' a un'altra chiave. Non ho cambiato nulla.");
            println!("  quella che ha il nome: {}", existing_fingerprint.display());
            println!("  quella nuova:          {}", incoming_fingerprint.display());
            println!(
                "\nSe {label} ha cambiato telefono e' normale. Se non lo sa,\n\
                 qualcuno si sta interponendo: confrontate il codice di persona."
            );
        }
    }
    Ok(())
}

fn cmd_verify(args: &[String]) -> Result<(), String> {
    let who = args.first().ok_or("manca <chi>. Vedi `kc help`.")?;
    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;
    let mut session = Session::new(state.identity, state.keyring);
    session.mark_verified(&peer).map_err(|e| format!("{e}"))?;
    persist(&secret, &session)?;
    println!("segnato come verificato di persona.");
    Ok(())
}

/// Peer name for on-screen messages, or "(senza nome)".
fn state_label<K: keyboard_cipher_core::keys::Keyring>(
    session: &Session<K>,
    peer: &keyboard_cipher_core::keys::PublicKey,
) -> String {
    session
        .keyring()
        .get(peer)
        .ok()
        .flatten()
        .and_then(|r| r.label)
        .unwrap_or_else(|| "(senza nome)".to_owned())
}

/// Burns the conversation with a contact (decision J).
///
/// **Final on this side**: the keys that read it disappear. The printed blob
/// must be delivered to the other person: if their app honours it, it destroys
/// theirs. It cannot be enforced, and is not presented as if it could.
fn cmd_burn(args: &[String]) -> Result<(), String> {
    let who = args.first().ok_or("manca <chi>. Vedi `kc help`.")?;
    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;
    let mut session = Session::new(state.identity, state.keyring);
    let richiesta = session
        .burn_conversation(&peer, now_unix(), &mut OsRng)
        .map_err(|e| format!("{e}"))?;
    // To disk immediately: if the process died now, the keys would still be
    // there and the burn would not have happened.
    persist(&secret, &session)?;
    eprintln!("bruciata da questo lato. Manda all'altro la riga qui sotto:");
    println!("{richiesta}");
    Ok(())
}

/// Encrypts a message.
///
/// **Forward secrecy on by default**, as on the phone: every message carries a
/// new temporary key, and reading the reply drops the old ones. The price is
/// that messages cannot be reopened; `--no-fs` is for those who do not want to
/// pay it, for example to keep a conversation rereadable with `kc archive`.
fn cmd_encrypt(args: &[String]) -> Result<(), String> {
    let mut who: Option<&str> = None;
    let mut text: Vec<&str> = Vec::new();
    let mut forward = true;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            "--to" | "-t" => {
                who = args.get(i.saturating_add(1)).map(String::as_str);
                i = i.saturating_add(2);
            }
            "--no-fs" => {
                forward = false;
                i = i.saturating_add(1);
            }
            other => {
                text.push(other);
                i = i.saturating_add(1);
            }
        }
    }
    let who = who.ok_or("manca --to <chi>. Vedi `kc help`.")?;
    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;

    let plaintext = if text.is_empty() {
        read_stdin()?
    } else {
        text.join(" ")
    };
    if plaintext.trim().is_empty() {
        return Err("niente da cifrare".to_owned());
    }

    let mut session = Session::new(state.identity, state.keyring);
    session
        .set_current_peer(APP, &peer)
        .map_err(|e| format!("{e}"))?;
    let blob = session
        .encrypt_for_app_with(APP, plaintext.as_bytes(), now_unix(), &mut OsRng, forward)
        .map_err(|e| format!("{e}"))?;
    // Without this forward secrecy would not work at all: encrypting generates a
    // new temporary key, and if it is not saved the reply arrives encrypted to a
    // key that no longer exists.
    persist(&secret, &session)?;
    println!("{blob}");
    Ok(())
}

fn cmd_decrypt(args: &[String]) -> Result<(), String> {
    let input = if args.is_empty() {
        read_stdin()?
    } else {
        args.join(" ")
    };
    let state = load()?;
    let secret = state.secret_bytes();
    let mut session = Session::new(state.identity, state.keyring);
    // Decrypt BEFORE touching the keyring, guaranteed by the core: a successful
    // decryption proves the writer holds the declared private key. Pinning first
    // would let anyone fill the keyring with invented peers.
    let item = session
        .handle_incoming_text(APP, &input, now_unix())
        .map_err(|e| format!("{e}"))?;
    match item {
        IncomingItem::Burned { peer, sent_at_unix } => {
            persist(&secret, &session)?;
            let chi = state_label(&session, &peer);
            println!("bruciata:  la conversazione con {chi} non si rilegge piu'.");
            println!("chiave:    {}", Fingerprint::of(&peer).display());
            // The date of the request. Read it: a burn arriving months after it
            // was composed is a reposted blob, not a new request, and by then the
            // conversation is already destroyed.
            println!("richiesta: composta a {sent_at_unix} (unix)");
            println!();
            println!("Il contatto resta. Il prossimo messaggio riparte da capo.");
        }
        // We wrote it: there is no sender to show here, there is a recipient,
        // and calling it sender would be false.
        IncomingItem::OwnMessage {
            recipient,
            recipient_label,
            plaintext,
        } => {
            persist(&secret, &session)?;
            println!(
                "a:        {}",
                recipient_label.unwrap_or_else(|| "(senza nome)".to_owned())
            );
            println!("chiave:   {}", Fingerprint::of(&recipient).display());
            println!(
                "scritto:  {} (l'hai scritto tu)",
                format_unix(plaintext.sent_at_unix())
            );
            println!("nota:     si riapre perche' la forward secrecy era spenta.");
            println!();
            match std::str::from_utf8(plaintext.as_bytes()) {
                Ok(text) => println!("{text}"),
                Err(_) => println!("(il messaggio non e' testo UTF-8)"),
            }
        }
        IncomingItem::Message(message) => {
            let who = match &message.sender_status {
                SenderStatus::New => "mittente mai visto, ora fissato".to_owned(),
                SenderStatus::Known { label, verified } => {
                    let name = label.clone().unwrap_or_else(|| "(senza nome)".to_owned());
                    if *verified {
                        format!("{name} ✓")
                    } else {
                        name
                    }
                }
            };
            persist(&secret, &session)?;
            println!("da:       {who}");
            println!("chiave:   {}", Fingerprint::of(&message.sender).display());
            // Authenticated but NOT verifiable: nobody can prove the sender's
            // clock was right. Shown, never used to decide anything.
            println!(
                "scritto:  {} (secondo il mittente)",
                format_unix(message.plaintext.sent_at_unix())
            );
            println!();
            match std::str::from_utf8(message.plaintext.as_bytes()) {
                Ok(text) => println!("{text}"),
                Err(_) => println!("(il messaggio non e' testo UTF-8)"),
            }
        }
        IncomingItem::OwnIdentityCard { fingerprint } => {
            // No `persist`: nothing was pinned, and saving here would mislead the
            // reader of the code.
            println!("Questa e' la TUA chiave, non quella di un contatto.");
            println!("{}", fingerprint.display());
            println!("\nNon e' stato aggiunto nessun contatto.");
        }
        IncomingItem::IdentityCard {
            fingerprint,
            outcome,
            ..
        } => {
            persist(&secret, &session)?;
            match outcome {
                PinOutcome::Pinned => println!("nuovo contatto, chiave fissata."),
                PinOutcome::AlreadyPinned => println!("chiave gia' nota."),
            }
            println!("{}", fingerprint.display());
            println!("\nConfronta il codice di persona, poi dagli un nome con `kc name`.");
        }
    }
    Ok(())
}

/// Encrypts a file. The result is **binary**, not text: z-base-32 would inflate
/// by 1.6× something that is attached, not pasted.
///
/// Name and type of the file go **inside** the ciphertext; outside there is a
/// neutral name. In clear, a name like `marks-birthday.jpg.kc` would by itself
/// tell almost everything.
fn cmd_sealfile(args: &[String]) -> Result<(), String> {
    let mut who: Option<&str> = None;
    let mut percorso: Option<&str> = None;
    let mut forward = true;
    let mut i = 0;
    while let Some(arg) = args.get(i) {
        match arg.as_str() {
            "--to" | "-t" => {
                who = args.get(i.saturating_add(1)).map(String::as_str);
                i = i.saturating_add(2);
            }
            "--no-fs" => {
                forward = false;
                i = i.saturating_add(1);
            }
            altro => {
                percorso = Some(altro);
                i = i.saturating_add(1);
            }
        }
    }
    let who = who.ok_or("manca --to <chi>. Vedi `kc help`.")?;
    let percorso = percorso.ok_or("manca il file da cifrare.")?;
    let contenuto = std::fs::read(percorso).map_err(|e| format!("{percorso}: {e}"))?;

    let state = load()?;
    let secret = state.secret_bytes();
    let peer = resolve(&state.keyring, who)?;
    let nome = std::path::Path::new(percorso)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "allegato".to_owned());
    let meta = FileMeta {
        name: nome,
        // The type is declared, not guessed: there is no type table here, and
        // inventing one would be worse than saying "unknown".
        mime: "application/octet-stream".to_owned(),
    };
    let mut session = Session::new(state.identity, state.keyring);
    let blob = session
        .encrypt_file_with(&peer, &meta, &contenuto, now_unix(), &mut OsRng, forward)
        .map_err(|e| format!("{e}"))?;
    // The temporary key just generated must be saved before the attachment
    // exists on disk: the other side will reply to it.
    persist(&secret, &session)?;

    let uscita = format!("{percorso}.kc");
    std::fs::write(&uscita, &blob).map_err(|e| format!("{uscita}: {e}"))?;
    println!("{uscita} ({} byte)", blob.len());
    Ok(())
}

/// Opens an encrypted attachment. Without `dove`, writes next to the file with
/// the original name, which is inside the ciphertext.
fn cmd_openfile(args: &[String]) -> Result<(), String> {
    let percorso = args.first().ok_or("manca il file da aprire.")?;
    let blob = std::fs::read(percorso).map_err(|e| format!("{percorso}: {e}"))?;
    let state = load()?;
    let secret = state.secret_bytes();
    let mut session = Session::new(state.identity, state.keyring);
    let incoming = session
        .handle_incoming_file(&blob, now_unix())
        .map_err(|e| format!("{e}"))?;

    let chi = match &incoming.sender_status {
        SenderStatus::New => "mittente mai visto, ora fissato".to_owned(),
        SenderStatus::Known { label, verified } => {
            let nome = label.clone().unwrap_or_else(|| "(senza nome)".to_owned());
            if *verified { format!("{nome} ✓") } else { nome }
        }
    };
    persist(&secret, &session)?;

    // The name comes from the sender: authenticated, not trustworthy. Only the
    // last path segment is kept, so a name with `../` or a separator cannot
    // write outside the chosen folder.
    let nome_pulito = incoming
        .file
        .meta
        .name
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("allegato")
        .to_owned();
    let destinazione = match args.get(1) {
        Some(dove) => std::path::PathBuf::from(dove),
        None => std::path::Path::new(percorso)
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .join(&nome_pulito),
    };
    std::fs::write(&destinazione, &incoming.file.content)
        .map_err(|e| format!("{}: {e}", destinazione.display()))?;

    if incoming.nostro {
        println!("a:        {chi}");
    } else {
        println!("da:       {chi}");
    }
    println!("chiave:   {}", Fingerprint::of(&incoming.sender).display());
    let quando = format_unix(incoming.file.sent_at_unix);
    if incoming.nostro {
        println!("scritto:  {quando} (l'hai mandato tu)");
    } else {
        println!("scritto:  {quando} (secondo il mittente)");
    }
    println!("nome:     {} ({})", incoming.file.meta.name, incoming.file.meta.mime);
    println!("salvato:  {}", destinazione.display());
    Ok(())
}

// ---------------------------------------------------------------------------

/// Decrypts all of our messages found inside any file.
///
/// For **chat exports**: messaging apps export HTML or JSON where messages are
/// text, so all the blobs are there. The export format is not parsed (it would
/// change with every app update): the sentinel is searched for wherever it
/// appears, exactly as the keyboard does inside arbitrary text.
///
/// **Works while forward secrecy is off.** With it on, the keys of old messages
/// no longer exist, and an export is dead bytes even for its author: the
/// declared price of that choice.
///
/// Does not touch the keyring and pins nobody: an archive can contain anything,
/// and pinning keys while reading a file would fill the keyring unnoticed.
fn cmd_archive(args: &[String]) -> Result<(), String> {
    let percorso = args.first().ok_or("manca il file esportato.")?;
    let testo = std::fs::read_to_string(percorso).map_err(|e| format!("{percorso}: {e}"))?;

    let state = load()?;
    let session = Session::new(state.identity, state.keyring);

    let mut trovati = 0usize;
    let mut aperti = 0usize;
    let mut resto = testo.as_str();
    while let Some(inizio) = resto.find(SENTINEL) {
        let dopo = resto.get(inizio..).unwrap_or("");
        // The blob ends at the first character outside the alphabet: the same
        // rule as recognition inside arbitrary text.
        let fine = dopo
            .char_indices()
            .position(|(i, c)| i >= SENTINEL.len() && !c.is_ascii_alphanumeric())
            .unwrap_or(dopo.len());
        let blob = dopo.get(..fine).unwrap_or("");
        resto = dopo.get(fine.max(SENTINEL.len())..).unwrap_or("");
        trovati = trovati.saturating_add(1);

        // `Session::open_archived` does not touch the keyring: here we only want
        // to read, not to recognise who writes.
        match session.open_archived(blob) {
            Ok((mittente, plaintext)) => {
                aperti = aperti.saturating_add(1);
                let nome = Keyring::get(session.keyring(), &mittente)
                    .ok()
                    .flatten()
                    .and_then(|r| r.label)
                    .unwrap_or_else(|| Fingerprint::of(&mittente).display());
                println!(
                    "[{}] {}: {}",
                    format_unix(plaintext.sent_at_unix()),
                    nome,
                    String::from_utf8_lossy(plaintext.as_bytes())
                );
            }
            // A blob that does not open is not a command error: it may belong to
            // another conversation, another recipient, or a key that no longer
            // exists.
            Err(_) => println!("[non decifrabile]"),
        }
    }
    eprintln!("\n{aperti} messaggi aperti su {trovati} trovati.");
    Ok(())
}

/// Human-readable date, in UTC.
///
/// Hand-written rather than pulling in a date dependency for one line.
///
/// UTC rather than local time, on purpose: the timestamp is **authenticated but
/// not verifiable**, so showing it in the reader's time zone would suggest a
/// precision that is not there.
///
/// `allow(arithmetic_side_effects)`: this is Hinnant's civil-from-days
/// algorithm on values bounded by `ts` (an `i64` of seconds); none of the
/// operations can overflow for representable dates.
#[allow(clippy::arithmetic_side_effects)]
fn format_unix(ts: i64) -> String {
    let days = ts.div_euclid(86_400);
    let secs = ts.rem_euclid(86_400);
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{day:02}/{month:02}/{year} {:02}:{:02} UTC",
        secs / 3_600,
        (secs % 3_600) / 60
    )
}

/// Saves the state after an operation that touched the keyring.
///
/// Takes the secret because by now the identity is inside the `Session`, which
/// owns it, and `Identity` does not return its own private key, as it should
/// not. The caller copied it beforehand.
fn persist(secret: &[u8; 32], session: &Session<FileKeyring>) -> Result<(), String> {
    let path = store::state_path();
    store::save(&path, secret, session.keyring())
        .map_err(|e| format!("non riesco a scrivere {}: {e}", path.display()))
}

/// Finds a peer from a name, an index from `kc contacts`, or the start of a
/// fingerprint (spaces may be omitted).
fn resolve(keyring: &FileKeyring, who: &str) -> Result<PublicKey, String> {
    let peers = keyring.peers();
    if let Some(peer) = peers.iter().find(|p| p.label.as_deref() == Some(who)) {
        return Ok(peer.public.clone());
    }
    if let Ok(index) = who.parse::<usize>() {
        if let Some(peer) = peers.get(index) {
            return Ok(peer.public.clone());
        }
    }
    let needle: String = who.chars().filter(|c| !c.is_whitespace()).collect();
    if !needle.is_empty() {
        let matching: Vec<&keyboard_cipher_core::keys::PeerRecord> = peers
            .iter()
            .filter(|p| {
                Fingerprint::of(&p.public)
                    .display()
                    .replace(' ', "")
                    .starts_with(&needle)
            })
            .collect();
        match matching.as_slice() {
            [single] => return Ok(single.public.clone()),
            [] => {}
            // Never guess: encrypting for the wrong person is the worst failure
            // this system can produce.
            _ => return Err(format!("«{who}» corrisponde a piu' contatti")),
        }
    }
    Err(format!(
        "«{who}» non e' un contatto. Vedi `kc contacts`."
    ))
}

fn read_stdin() -> Result<String, String> {
    let mut buffer = String::new();
    std::io::stdin()
        .read_to_string(&mut buffer)
        .map_err(|e| format!("non riesco a leggere da stdin: {e}"))?;
    Ok(buffer)
}
