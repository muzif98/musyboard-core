//! Desktop app: encrypts and decrypts the keyboard's messages.
//!
//! ## Purpose
//!
//! On the phone the keyboard encrypts inside the chat. On a computer there is
//! no keyboard that can do that, so there needs to be a place to paste a blob
//! to read it and to write a message to encrypt it. This is that place, and it
//! is also a **real second identity**: phone and computer are two different
//! people for the system, with two different keys.
//!
//! ## What it shares with `kc`
//!
//! The **same state file**, through the same module. Two implementations of one
//! format would be two sources of truth, and the first time they diverged the
//! identity would be lost. The app and the command line work on the same
//! identity and contacts.
//!
//! ## What it does NOT do, by choice
//!
//! It does not talk to the phone: the only channel between the two parties is
//! whoever copies and pastes. No network, no pairing, nothing to configure.
//!
//! *Declared limit:* the private key is stored in clear in the state file,
//! protected only by filesystem permissions. On the phone it is wrapped by
//! Android Keystore; there is nothing equivalent here, and asking for a
//! passphrase at every start would get in the way of the app's purpose. It is a
//! tool, not an identity to rely on as much as the phone's.

use eframe::egui;
use keyboard_cipher_cli::store::{self, FileKeyring, State};
use keyboard_cipher_core::api::{IncomingItem, SenderStatus, Session};
use keyboard_cipher_core::format::SENTINEL;
use keyboard_cipher_core::keys::{Fingerprint, LabelOutcome, PinOutcome, PublicKey};
use rand_core::OsRng;

/// App name for the core. On the phone the recipient is per application; here
/// there is only one, and the recipient is chosen by hand each time.
const APP: &str = "gui";

fn main() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([760.0, 620.0])
            .with_min_inner_size([520.0, 420.0])
            .with_title("Tastiera cifrata"),
        ..Default::default()
    };
    eframe::run_native(
        "Tastiera cifrata",
        options,
        Box::new(|_cc| Ok(Box::new(App::new()))),
    )
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Scheda {
    Scrivi,
    Leggi,
    Contatti,
    Archivio,
}

struct Contatto {
    chiave: PublicKey,
    nome: Option<String>,
    fingerprint: String,
    verificato: bool,
}

struct App {
    /// `None` until an identity exists: it is created from the app.
    identita: Option<String>,
    contatti: Vec<Contatto>,
    scheda: Scheda,

    destinatario: Option<usize>,
    messaggio: String,
    incollato: String,
    letto: Option<Letto>,

    /// Last result to show. `errore` only decides the colour: the text already
    /// says what happened.
    avviso: Option<(String, bool)>,
    nuovo_nome: String,
    conflitto: Option<Conflitto>,
    /// Contact about to be forgotten, awaiting confirmation.
    da_dimenticare: Option<usize>,

    /// Forward secrecy: a new temporary key on every message, old ones dropped
    /// when a reply arrives. On by default, as on the phone. Turning it off is
    /// for those who want to reread: with it on, "rebuild chat" reopens nothing,
    /// by construction.
    forward_secrecy: bool,

    /// Watch the clipboard to notice messages copied elsewhere.
    sorveglia_appunti: bool,
    /// Keep the window on top: read without leaving the chat.
    sempre_sopra: bool,
    appunti: Option<arboard::Clipboard>,
    /// The last content already examined, to avoid redoing the work every frame.
    ultimo_appunto: String,

    /// The conversation rebuilt from an export.
    archivio: Vec<RigaArchivio>,
    archivio_da: Option<String>,
    archivio_trovati: usize,
}

/// A message rebuilt from a chat export.
struct RigaArchivio {
    quando: String,
    chi: String,
    testo: String,
    /// `false` when the blob was there but did not open: it may belong to
    /// another conversation, another recipient, or a key that no longer exists.
    aperto: bool,
}

struct Letto {
    /// Who wrote it, **or** whom we wrote to, if `nostro`.
    mittente: String,
    fingerprint: String,
    verificato: bool,
    quando: String,
    testo: String,
    /// We wrote it and reopened it: only possible without forward secrecy, and
    /// it must be said, otherwise "from: Mark" on our own message would be false.
    nostro: bool,
}

/// Two keys claiming the same name. **Not an error**: a state that needs a
/// decision, and nothing changes until the user decides.
struct Conflitto {
    nome: String,
    vecchia: PublicKey,
    nuova: PublicKey,
    fingerprint_vecchia: String,
    fingerprint_nuova: String,
}

impl App {
    fn new() -> Self {
        let mut app = Self {
            identita: None,
            contatti: Vec::new(),
            scheda: Scheda::Scrivi,
            destinatario: None,
            messaggio: String::new(),
            incollato: String::new(),
            letto: None,
            avviso: None,
            nuovo_nome: String::new(),
            conflitto: None,
            da_dimenticare: None,
            forward_secrecy: true,
            sorveglia_appunti: true,
            sempre_sopra: false,
            appunti: arboard::Clipboard::new().ok(),
            ultimo_appunto: String::new(),
            archivio: Vec::new(),
            archivio_da: None,
            archivio_trovati: 0,
        };
        app.ricarica();
        app
    }

    /// Reloads everything from disk.
    ///
    /// Reloaded on every operation instead of keeping a live copy: the file is
    /// small, and `kc` may have changed it meanwhile. An in-memory copy that
    /// diverges from disk is the quickest way to overwrite a contact just added
    /// from the other side.
    fn ricarica(&mut self) {
        let percorso = store::state_path();
        let stato = match State::load(&percorso) {
            Ok(Some(stato)) => stato,
            Ok(None) => {
                self.identita = None;
                self.contatti.clear();
                return;
            }
            Err(e) => {
                self.avviso = Some((format!("stato illeggibile: {e}"), true));
                return;
            }
        };
        self.identita = Some(stato.identity.fingerprint().display());
        self.contatti = stato
            .keyring
            .peers()
            .iter()
            .map(|p| Contatto {
                chiave: p.public.clone(),
                nome: p.label.clone(),
                fingerprint: Fingerprint::of(&p.public).display(),
                verificato: p.verified,
            })
            .collect();
        if self.destinatario.is_some_and(|i| i >= self.contatti.len()) {
            self.destinatario = None;
        }
    }

    fn stato(&mut self) -> Option<State> {
        match State::load(&store::state_path()) {
            Ok(Some(stato)) => Some(stato),
            Ok(None) => {
                self.avviso = Some(("Nessuna identita': creala prima.".to_owned(), true));
                None
            }
            Err(e) => {
                self.avviso = Some((format!("stato illeggibile: {e}"), true));
                None
            }
        }
    }

    fn salva(&mut self, secret: &[u8; 32], keyring: &FileKeyring) {
        if let Err(e) = store::save(&store::state_path(), secret, keyring) {
            self.avviso = Some((format!("non riesco a scrivere lo stato: {e}"), true));
        }
    }

    fn crea_identita(&mut self) {
        use rand_core::RngCore;
        let mut secret = [0u8; 32];
        OsRng.fill_bytes(&mut secret);
        // Build the identity before writing: a secret that does not reload would
        // be an unusable state created silently.
        match State::create(secret) {
            Ok(stato) => {
                self.salva(&secret, &stato.keyring);
                self.ricarica();
                self.avviso = Some(("Identita' creata.".to_owned(), false));
            }
            Err(e) => self.avviso = Some((format!("segreto non valido: {e}"), true)),
        }
    }

    fn presentazione(&mut self, ctx: &egui::Context) {
        let Some(stato) = self.stato() else { return };
        let session = Session::new(stato.identity, stato.keyring);
        let card = session.identity_card(&mut OsRng);
        ctx.copy_text(card);
        self.avviso = Some((
            "Presentazione copiata: incollala nella chat.".to_owned(),
            false,
        ));
    }

    fn cifra(&mut self, ctx: &egui::Context) {
        let Some(indice) = self.destinatario else {
            self.avviso = Some(("Scegli prima a chi stai scrivendo.".to_owned(), true));
            return;
        };
        let Some(contatto) = self.contatti.get(indice) else {
            self.avviso = Some(("Contatto non piu' valido.".to_owned(), true));
            return;
        };
        if self.messaggio.trim().is_empty() {
            self.avviso = Some(("Niente da cifrare.".to_owned(), true));
            return;
        }
        let chiave = contatto.chiave.clone();
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        if let Err(e) = session.set_current_peer(APP, &chiave) {
            self.avviso = Some((format!("{e}"), true));
            return;
        }
        match session.encrypt_for_app_with(
            APP,
            self.messaggio.as_bytes(),
            adesso(),
            &mut OsRng,
            self.forward_secrecy,
        ) {
            Ok(blob) => {
                // To disk immediately: with forward secrecy on, encrypting
                // generates a new temporary key, and not saving it means the
                // reply cannot be opened.
                self.salva(&secret, session.keyring());
                ctx.copy_text(blob);
                self.messaggio.clear();
                self.avviso = Some((
                    "Messaggio cifrato e copiato: incollalo nella chat.".to_owned(),
                    false,
                ));
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }

    fn decifra(&mut self) {
        if self.incollato.trim().is_empty() {
            self.avviso = Some(("Incolla prima un messaggio.".to_owned(), true));
            return;
        }
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        // The core decrypts BEFORE touching the keyring: a successful decryption
        // proves the writer holds the declared private key.
        match session.handle_incoming_text(APP, &self.incollato, adesso()) {
            Ok(IncomingItem::Message(messaggio)) => {
                let (nome, verificato) = match &messaggio.sender_status {
                    SenderStatus::New => ("mittente mai visto, ora fissato".to_owned(), false),
                    SenderStatus::Known { label, verified } => (
                        label.clone().unwrap_or_else(|| "(senza nome)".to_owned()),
                        *verified,
                    ),
                };
                let testo = String::from_utf8_lossy(messaggio.plaintext.as_bytes()).into_owned();
                self.letto = Some(Letto {
                    mittente: nome,
                    fingerprint: Fingerprint::of(&messaggio.sender).display(),
                    verificato,
                    quando: data(messaggio.plaintext.sent_at_unix()),
                    testo,
                    nostro: false,
                });
                self.salva(&secret, session.keyring());
                self.incollato.clear();
                self.ricarica();
                self.avviso = None;
            }
            Ok(IncomingItem::Burned { peer, sent_at_unix }) => {
                let nome = self
                    .contatti
                    .iter()
                    .find(|c| c.chiave == peer)
                    .map(etichetta)
                    .unwrap_or_else(|| "quel contatto".to_owned());
                self.salva(&secret, session.keyring());
                self.letto = None;
                self.incollato.clear();
                self.ricarica();
                // The request date is in the notice, and it matters: a burn
                // composed months ago and arriving now is a reposted blob, not a
                // new request. Rejecting it by date is ruled out by decision C;
                // showing it is the remaining defence.
                self.avviso = Some((
                    format!(
                        "Conversazione con {nome} bruciata: non si rilegge piu'. \
                         Richiesta composta il {}. \
                         Il contatto resta, il prossimo messaggio riparte da capo.",
                        data(sent_at_unix)
                    ),
                    false,
                ));
            }
            Ok(IncomingItem::OwnMessage {
                recipient,
                recipient_label,
                plaintext,
            }) => {
                let testo = String::from_utf8_lossy(plaintext.as_bytes()).into_owned();
                self.letto = Some(Letto {
                    mittente: recipient_label.unwrap_or_else(|| "(senza nome)".to_owned()),
                    fingerprint: Fingerprint::of(&recipient).display(),
                    // No tick: on our own message there is no identity to verify.
                    verificato: false,
                    quando: data(plaintext.sent_at_unix()),
                    testo,
                    nostro: true,
                });
                self.salva(&secret, session.keyring());
                self.incollato.clear();
                self.ricarica();
                self.avviso = None;
            }
            Ok(IncomingItem::OwnIdentityCard { fingerprint }) => {
                // No save and no switch to Contacts: there is no new contact to
                // show.
                self.incollato.clear();
                self.avviso = Some((
                    format!(
                        "Questa e' la TUA chiave ({}), non quella di un contatto: \
                         non e' stato aggiunto niente.",
                        fingerprint.display()
                    ),
                    true,
                ));
            }
            Ok(IncomingItem::IdentityCard {
                fingerprint,
                outcome,
                ..
            }) => {
                self.salva(&secret, session.keyring());
                self.incollato.clear();
                self.ricarica();
                self.scheda = Scheda::Contatti;
                let cosa = match outcome {
                    PinOutcome::Pinned => "Nuovo contatto, chiave memorizzata",
                    PinOutcome::AlreadyPinned => "Chiave gia' nota",
                };
                self.avviso = Some((
                    format!("{cosa}: {}. Confrontalo di persona.", fingerprint.display()),
                    false,
                ));
            }
            Err(e) => {
                self.letto = None;
                self.avviso = Some((format!("{e}"), true));
            }
        }
    }

    fn rinomina(&mut self, indice: usize) {
        let Some(contatto) = self.contatti.get(indice) else { return };
        let chiave = contatto.chiave.clone();
        let nome = self.nuovo_nome.trim().to_owned();
        if nome.is_empty() {
            self.avviso = Some(("Scrivi un nome.".to_owned(), true));
            return;
        }
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        match session.assign_label(&chiave, &nome) {
            Ok(LabelOutcome::Assigned) => {
                self.salva(&secret, session.keyring());
                self.nuovo_nome.clear();
                self.ricarica();
                self.avviso = Some((format!("Ora si chiama {nome}."), false));
            }
            // Signal's "safety number changed". Nothing changes until the user
            // decides: the old key keeps the name.
            Ok(LabelOutcome::Conflict {
                existing,
                existing_fingerprint,
                incoming_fingerprint,
            }) => {
                self.conflitto = Some(Conflitto {
                    nome,
                    vecchia: existing,
                    nuova: chiave,
                    fingerprint_vecchia: existing_fingerprint.display(),
                    fingerprint_nuova: incoming_fingerprint.display(),
                });
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }

    fn conferma_conflitto(&mut self) {
        let Some(conflitto) = self.conflitto.take() else { return };
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        match session.confirm_key_change(&conflitto.vecchia, &conflitto.nuova, adesso()) {
            Ok(()) => {
                self.salva(&secret, session.keyring());
                self.ricarica();
                self.avviso = Some((
                    format!(
                        "{} ora e' la chiave nuova. La verifica di persona e' stata azzerata.",
                        conflitto.nome
                    ),
                    false,
                ));
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }

    /// Forgets a contact, after confirmation.
    ///
    /// The confirmation is not politeness: deleting a contact **loses the
    /// pin**, and the next message from that person will be silently re-pinned
    /// as if new, reopening the window the pin was closing and losing "compared
    /// in person". The user must know beforehand.
    fn dimentica(&mut self, indice: usize) {
        let Some(contatto) = self.contatti.get(indice) else { return };
        let chiave = contatto.chiave.clone();
        let nome = contatto
            .nome
            .clone()
            .unwrap_or_else(|| contatto.fingerprint.clone());
        let Some(mut stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        if !stato.keyring.remove(&chiave) {
            self.avviso = Some(("Quel contatto non c'e' piu'.".to_owned(), true));
            return;
        }
        self.salva(&secret, &stato.keyring);
        self.destinatario = None;
        self.ricarica();
        self.avviso = Some((format!("{nome} dimenticato."), false));
    }

    fn verifica(&mut self, indice: usize) {
        let Some(contatto) = self.contatti.get(indice) else { return };
        let chiave = contatto.chiave.clone();
        let Some(stato) = self.stato() else { return };
        let secret = stato.secret_bytes();
        let mut session = Session::new(stato.identity, stato.keyring);
        match session.mark_verified(&chiave) {
            Ok(()) => {
                self.salva(&secret, session.keyring());
                self.ricarica();
                self.avviso = Some(("Segnato come confrontato di persona.".to_owned(), false));
            }
            Err(e) => self.avviso = Some((format!("{e}"), true)),
        }
    }
}

impl App {
    /// Rebuilds a conversation from a chat export.
    ///
    /// The export format is not parsed (each messaging app has its own, and it
    /// changes with every update). The **sentinel** is searched wherever it
    /// appears, exactly as the keyboard does inside arbitrary text, so any
    /// format works, including future ones, as long as messages are text.
    ///
    /// **Does not touch the keyring.** An archive can contain anything,
    /// including forged messages: pinning keys while reading a file would fill
    /// the contacts unnoticed, or show a false "Mark's key changed".
    fn ricostruisci(&mut self, percorso: std::path::PathBuf) {
        let Ok(testo) = std::fs::read_to_string(&percorso) else {
            self.avviso = Some((
                "Non riesco a leggere quel file. Se e' un archivio compresso, \
                 estrailo prima."
                    .to_owned(),
                true,
            ));
            return;
        };
        let Some(stato) = self.stato() else { return };
        let session = Session::new(stato.identity, stato.keyring);

        self.archivio.clear();
        self.archivio_trovati = 0;
        let mut resto = testo.as_str();
        while let Some(inizio) = resto.find(SENTINEL) {
            let dopo = resto.get(inizio..).unwrap_or("");
            let fine = dopo
                .char_indices()
                .position(|(i, c)| i >= SENTINEL.len() && !c.is_ascii_alphanumeric())
                .unwrap_or(dopo.len());
            let blob = dopo.get(..fine).unwrap_or("");
            resto = dopo.get(fine.max(SENTINEL.len())..).unwrap_or("");
            self.archivio_trovati += 1;

            match session.open_archived(blob) {
                Ok((mittente, plaintext)) => {
                    let nome = keyboard_cipher_core::keys::Keyring::get(session.keyring(), &mittente)
                        .ok()
                        .flatten()
                        .and_then(|r| r.label)
                        .unwrap_or_else(|| Fingerprint::of(&mittente).display());
                    self.archivio.push(RigaArchivio {
                        quando: data(plaintext.sent_at_unix()),
                        chi: nome,
                        testo: String::from_utf8_lossy(plaintext.as_bytes()).into_owned(),
                        aperto: true,
                    });
                }
                Err(_) => self.archivio.push(RigaArchivio {
                    quando: String::new(),
                    chi: String::new(),
                    testo: "(non decifrabile)".to_owned(),
                    aperto: false,
                }),
            }
        }
        self.archivio_da = percorso
            .file_name()
            .map(|n| n.to_string_lossy().into_owned());
        self.avviso = None;
    }

    /// Checks whether one of our messages appeared on the clipboard.
    ///
    /// Removes the last manual step: copy the message in the chat app and this
    /// app has already opened it.
    ///
    /// **What it looks at and what it does not.** It only looks for the
    /// sentinel. Everything else is discarded without further reading, without
    /// being saved and without leaving this function: copying a password does
    /// nothing here and leaves nothing behind. It is still a clipboard read
    /// while the app is open, so it can be turned off, with the checkbox right
    /// next to it.
    fn guarda_appunti(&mut self, ctx: &egui::Context) {
        if !self.sorveglia_appunti {
            return;
        }
        let Some(appunti) = self.appunti.as_mut() else { return };
        let Ok(testo) = appunti.get_text() else { return };
        if testo == self.ultimo_appunto {
            return;
        }
        self.ultimo_appunto = testo.clone();
        if !testo.contains(SENTINEL) {
            return;
        }
        self.incollato = testo;
        self.scheda = Scheda::Leggi;
        self.decifra();
        // The window brings itself to the front: whoever just copied is looking
        // at the chat, not this app.
        //
        // Only brought to the front: the plaintext does **not** go back to the
        // clipboard and does not end up in the chat app's field. That field
        // belongs to the app, and writing plaintext there would hand it over,
        // exactly what this system exists to avoid; one careless send would
        // deliver it in clear.
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.guarda_appunti(ctx);
        ctx.send_viewport_cmd(egui::ViewportCommand::WindowLevel(if self.sempre_sopra {
            egui::WindowLevel::AlwaysOnTop
        } else {
            egui::WindowLevel::Normal
        }));
        // Without this the app only repaints when touched, and would notice the
        // clipboard only on the next mouse movement.
        ctx.request_repaint_after(std::time::Duration::from_millis(700));
        egui::TopBottomPanel::top("intestazione").show(ctx, |ui| {
            ui.add_space(8.0);
            match self.identita.clone() {
                Some(fingerprint) => {
                    ui.horizontal_wrapped(|ui| {
                        ui.label("La tua chiave:");
                        ui.monospace(&fingerprint);
                        if ui.button("Copia la presentazione").clicked() {
                            self.presentazione(ctx);
                        }
                    });
                    ui.small(
                        "Leggi questo codice a voce a chi vuoi contattare: se combacia, \
                         nessuno si e' interposto.",
                    );
                }
                None => {
                    ui.label("Non hai ancora un'identita' su questo computer.");
                    if ui.button("Crea l'identita'").clicked() {
                        self.crea_identita();
                    }
                }
            }
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.selectable_value(&mut self.scheda, Scheda::Scrivi, "Scrivi");
                ui.selectable_value(&mut self.scheda, Scheda::Leggi, "Leggi");
                ui.selectable_value(&mut self.scheda, Scheda::Contatti, "Contatti");
                ui.selectable_value(&mut self.scheda, Scheda::Archivio, "Archivio");
            });
            ui.add_space(4.0);
        });

        if let Some((testo, errore)) = self.avviso.clone() {
            egui::TopBottomPanel::bottom("avviso").show(ctx, |ui| {
                ui.add_space(6.0);
                let colore = if errore {
                    egui::Color32::from_rgb(200, 80, 80)
                } else {
                    egui::Color32::from_rgb(90, 150, 90)
                };
                ui.colored_label(colore, testo);
                ui.add_space(6.0);
            });
        }

        egui::CentralPanel::default().show(ctx, |ui| match self.scheda {
            Scheda::Scrivi => self.scheda_scrivi(ui, ctx),
            Scheda::Leggi => self.scheda_leggi(ui),
            Scheda::Contatti => self.scheda_contatti(ui),
            Scheda::Archivio => self.scheda_archivio(ui),
        });

        self.finestra_conflitto(ctx);
        self.finestra_dimentica(ctx);
    }
}

impl App {
    fn scheda_scrivi(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        if self.contatti.is_empty() {
            ui.label(
                "Nessun contatto. Fatti mandare la presentazione di qualcuno e incollala \
                 in «Leggi», oppure manda la tua con il pulsante qui sopra.",
            );
            return;
        }
        ui.horizontal(|ui| {
            ui.label("A chi scrivi:");
            let scelto = self
                .destinatario
                .and_then(|i| self.contatti.get(i))
                .map(etichetta)
                .unwrap_or_else(|| "— scegli —".to_owned());
            egui::ComboBox::from_id_salt("destinatario")
                .selected_text(scelto)
                .show_ui(ui, |ui| {
                    for (i, contatto) in self.contatti.iter().enumerate() {
                        ui.selectable_value(&mut self.destinatario, Some(i), etichetta(contatto));
                    }
                });
        });
        ui.add_space(8.0);
        ui.add(
            egui::TextEdit::multiline(&mut self.messaggio)
                .desired_rows(10)
                .desired_width(f32::INFINITY)
                .hint_text("Scrivi qui il messaggio in chiaro"),
        );
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            if ui.button("Cifra e copia").clicked() {
                self.cifra(ctx);
            }
            ui.add_space(16.0);
            ui.checkbox(&mut self.forward_secrecy, "Forward secrecy")
                .on_hover_text(
                    "Ogni messaggio porta una chiave nuova, e leggere una risposta butta le \
                     vecchie. Chi ti prende il computer domani non apre i messaggi di oggi — \
                     e non li apri piu' nemmeno tu: con questa accesa «Ricostruisci chat» \
                     non riapre niente.",
                );
        });
    }

    fn scheda_leggi(&mut self, ui: &mut egui::Ui) {
        ui.label("Incolla qui il messaggio ricevuto:");
        let campo = ui.add(
            egui::TextEdit::multiline(&mut self.incollato)
                .desired_rows(5)
                .desired_width(f32::INFINITY)
                .hint_text("kc/…"),
        );
        // If what you pasted is one of our messages, it decrypts by itself.
        // Recognition is the keyboard's (the sentinel) and does not touch the
        // keyring: if it is not ours, nothing happens.
        if campo.changed() && self.incollato.contains(SENTINEL) {
            self.decifra();
        }
        ui.add_space(8.0);
        if ui.button("Decifra").clicked() {
            self.decifra();
        }
        ui.add_space(4.0);
        ui.checkbox(
            &mut self.sorveglia_appunti,
            "Apri da solo i messaggi che copio",
        )
        .on_hover_text(
            "Guarda negli appunti mentre l'app e' aperta, e cerca soltanto i \
             messaggi di questa tastiera. Tutto il resto viene scartato senza \
             essere salvato.",
        );
        ui.checkbox(&mut self.sempre_sopra, "Tieni la finestra sopra le altre")
            .on_hover_text(
                "Per leggere senza uscire dalla chat. Il messaggio decifrato \
                 resta qui: non torna negli appunti e non entra nel campo di \
                 scrittura dell'app, dove un invio distratto lo rispedirebbe in \
                 chiaro.",
            );
        if let Some(letto) = &self.letto {
            ui.add_space(12.0);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(if letto.nostro { "A:" } else { "Da:" });
                ui.strong(&letto.mittente);
                if letto.verificato {
                    ui.label("✓ confrontato di persona");
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("Chiave:");
                ui.monospace(&letto.fingerprint);
            });
            // Authenticated but NOT verifiable: nobody can prove the sender's
            // clock was right. Shown, never used to decide anything.
            if letto.nostro {
                ui.small(format!("Scritto il {} — l'hai scritto tu", letto.quando));
                ui.small(
                    "Si riapre perche' la forward secrecy era spenta: con quella accesa \
                     non sarebbe possibile, nemmeno per te.",
                );
            } else {
                ui.small(format!("Scritto il {} (secondo il mittente)", letto.quando));
            }
            ui.add_space(8.0);
            ui.group(|ui| {
                ui.add(
                    egui::Label::new(egui::RichText::new(&letto.testo).size(15.0)).wrap(),
                );
            });
        }
    }

    fn scheda_contatti(&mut self, ui: &mut egui::Ui) {
        if self.contatti.is_empty() {
            ui.label("Nessun contatto ancora.");
            return;
        }
        let mut da_rinominare: Option<usize> = None;
        let mut da_verificare: Option<usize> = None;
        let mut da_dimenticare: Option<usize> = None;
        egui::ScrollArea::vertical().show(ui, |ui| {
            for (i, contatto) in self.contatti.iter().enumerate() {
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(contatto.nome.clone().unwrap_or_else(|| "(senza nome)".into()));
                        if contatto.verificato {
                            ui.label("✓");
                        }
                    });
                    ui.monospace(&contatto.fingerprint);
                    ui.horizontal(|ui| {
                        if ui.button("Dai un nome").clicked() {
                            da_rinominare = Some(i);
                        }
                        if ui.button("Ho confrontato di persona").clicked() {
                            da_verificare = Some(i);
                        }
                        if ui.button("Dimentica").clicked() {
                            da_dimenticare = Some(i);
                        }
                    });
                });
            }
        });
        ui.add_space(8.0);
        ui.horizontal(|ui| {
            ui.label("Nome:");
            ui.text_edit_singleline(&mut self.nuovo_nome);
        });
        if let Some(i) = da_rinominare {
            self.rinomina(i);
        }
        if let Some(i) = da_verificare {
            self.verifica(i);
        }
        if let Some(i) = da_dimenticare {
            self.da_dimenticare = Some(i);
        }
    }

    /// Confirmation before forgetting, with the consequence spelled out.
    fn finestra_dimentica(&mut self, ctx: &egui::Context) {
        let Some(indice) = self.da_dimenticare else { return };
        let Some(contatto) = self.contatti.get(indice) else {
            self.da_dimenticare = None;
            return;
        };
        let nome = contatto
            .nome
            .clone()
            .unwrap_or_else(|| "(senza nome)".to_owned());
        let fingerprint = contatto.fingerprint.clone();
        let mut conferma = false;
        let mut annulla = false;
        egui::Window::new("Dimenticare questo contatto?")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.strong(&nome);
                ui.monospace(&fingerprint);
                ui.add_space(8.0);
                ui.label(
                    "Perdi il collegamento fra questa chiave e questa persona. Il prossimo \
                     messaggio che ti manda ricomparira' come mittente mai visto e verra' \
                     memorizzato di nuovo senza dire niente: e' la stessa cosa che vedresti \
                     se qualcuno si stesse spacciando per lei.",
                );
                ui.add_space(4.0);
                ui.small(
                    "Si perde anche «confrontato di persona», e per riaverlo bisogna \
                     riconfrontare il codice.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Annulla").clicked() {
                        annulla = true;
                    }
                    if ui.button("Dimentica").clicked() {
                        conferma = true;
                    }
                });
            });
        if annulla {
            self.da_dimenticare = None;
        }
        if conferma {
            self.da_dimenticare = None;
            self.dimentica(indice);
        }
    }

    fn scheda_archivio(&mut self, ui: &mut egui::Ui) {
        ui.label(
            "Apri l'esportazione di una conversazione — Telegram, Signal, WhatsApp, \
             Instagram: qualunque formato, purche' i messaggi ci siano come testo.",
        );
        ui.add_space(8.0);
        if ui.button("Ricostruisci una chat…").clicked() {
            if let Some(percorso) = rfd::FileDialog::new()
                .add_filter("Esportazioni", &["html", "json", "txt", "htm", "csv", "md"])
                .add_filter("Qualunque file", &["*"])
                .pick_file()
            {
                self.ricostruisci(percorso);
            }
        }
        if let Some(da) = &self.archivio_da {
            ui.add_space(8.0);
            let aperti = self.archivio.iter().filter(|r| r.aperto).count();
            ui.label(format!(
                "{da}: {aperti} messaggi aperti su {} trovati.",
                self.archivio_trovati
            ));
            ui.add_space(4.0);
            // With forward secrecy on, the keys of old messages no longer exist,
            // the declared price of that choice: say so here, rather than let it
            // look like a failure.
            if aperti < self.archivio_trovati {
                ui.small(
                    "Quelli non decifrabili possono essere di un'altra conversazione, \
                     diretti a qualcun altro, oppure cifrati con forward secrecy: in \
                     quel caso la chiave non esiste piu' e non tornera'.",
                );
            }
            ui.separator();
            egui::ScrollArea::vertical().show(ui, |ui| {
                for riga in &self.archivio {
                    if riga.aperto {
                        ui.horizontal_wrapped(|ui| {
                            ui.small(&riga.quando);
                            ui.strong(&riga.chi);
                        });
                        ui.add(egui::Label::new(&riga.testo).wrap());
                    } else {
                        ui.weak(&riga.testo);
                    }
                    ui.add_space(6.0);
                }
            });
        }
    }

    /// The screen that decides whether someone is in the middle.
    ///
    /// The two codes are **one above the other** on purpose: it is the only
    /// moment the user can notice an attack, and they must be able to compare
    /// them without switching windows.
    fn finestra_conflitto(&mut self, ctx: &egui::Context) {
        let Some(conflitto) = &self.conflitto else { return };
        let nome = conflitto.nome.clone();
        let vecchia = conflitto.fingerprint_vecchia.clone();
        let nuova = conflitto.fingerprint_nuova.clone();
        let mut conferma = false;
        let mut annulla = false;
        egui::Window::new("Quel nome e' gia' di un'altra chiave")
            .collapsible(false)
            .resizable(false)
            .show(ctx, |ui| {
                ui.label(format!(
                    "«{nome}» appartiene gia' a una chiave diversa. Non ho cambiato niente."
                ));
                ui.add_space(8.0);
                ui.label("Quella che ha il nome:");
                ui.monospace(&vecchia);
                ui.label("Quella nuova:");
                ui.monospace(&nuova);
                ui.add_space(8.0);
                ui.small(
                    "Se ha cambiato telefono e' normale. Se non lo sa, qualcuno si sta \
                     interponendo: confrontate il codice di persona prima di confermare.",
                );
                ui.add_space(8.0);
                ui.horizontal(|ui| {
                    if ui.button("Annulla").clicked() {
                        annulla = true;
                    }
                    if ui.button("E' lui, sposta il nome").clicked() {
                        conferma = true;
                    }
                });
            });
        if annulla {
            self.conflitto = None;
        }
        if conferma {
            self.conferma_conflitto();
        }
    }
}

fn etichetta(contatto: &Contatto) -> String {
    match &contatto.nome {
        Some(nome) if contatto.verificato => format!("{nome} ✓"),
        Some(nome) => nome.clone(),
        None => format!("(senza nome) {}", contatto.fingerprint),
    }
}

fn adesso() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Human-readable date in UTC, using Hinnant's civil-from-days algorithm.
///
/// UTC rather than local time, on purpose: the timestamp is authenticated but
/// **not verifiable**, and showing it in the reader's time zone would suggest a
/// precision that is not there.
fn data(ts: i64) -> String {
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
