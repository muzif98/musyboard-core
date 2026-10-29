//! `format::parse` on arbitrary text.
//!
//! The parser is the part exposed to completely hostile input: it receives
//! whatever passes through the clipboard. It must never panic, with or without
//! the right sentinel.
//!
//! Half of the inputs are prefixed with the sentinel, otherwise the fuzzer would
//! spend almost all its time on the NotOurBlob branch without reaching the real
//! parsing.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keyboard_cipher_core::format::{self, ParsedBlob, SENTINEL};

fuzz_target!(|data: &[u8]| {
    let Some((selettore, resto)) = data.split_first() else {
        return;
    };
    let Ok(testo) = std::str::from_utf8(resto) else {
        return;
    };

    let candidato = if selettore % 2 == 0 {
        format!("{SENTINEL}{testo}")
    } else {
        testo.to_owned()
    };

    let mut buf = Vec::new();
    if let Ok(blob) = format::parse(&candidato, &mut buf) {
        // If it parses, the fields must be consistent with what the format
        // promises: flags are a FUNCTION of the origin, not a field, and the
        // ciphertext is never shorter than the tag.
        if let ParsedBlob::Message(envelope) = blob {
            assert!(envelope.ciphertext.len() >= format::TAG_LEN);
            let origine = &envelope.header.origin;
            // Impossible combinations must not come out of `parse`: "ephemeral
            // without a key" and similar are inconsistent headers, which fail
            // authentication opaquely, the hardest way to diagnose.
            assert!(!(origine.is_ephemeral() && origine.key().is_none()));
            assert!(!(origine.uses_prekey() && !origine.is_ephemeral()));
            // Flags must be rebuildable from the origin: the invariant that
            // guarantees there is no second source of truth.
            let f = envelope.header.flags().0;
            assert_eq!(f & 0b1 != 0, origine.key().is_some());
            assert_eq!(f & 0b10 != 0, origine.is_ephemeral());
            assert_eq!(f & 0b100 != 0, origine.uses_prekey());
        }
    }
});
