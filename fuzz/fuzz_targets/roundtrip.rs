//! Structured round trip: builds VALID blobs from arbitrary input, then
//! corrupts them.
//!
//! The other two targets rarely reach a well-formed blob, because the fuzzer
//! would have to guess the encoding. Here valid blobs are produced by
//! construction, so fuzzing works on the deep branches of the parser rather
//! than on immediate rejections.

#![no_main]

use libfuzzer_sys::fuzz_target;

use keyboard_cipher_core::encoding;
use keyboard_cipher_core::format::{self, Header, Origin, ParsedBlob, Tier, NONCE_LEN, SENTINEL};
use keyboard_cipher_core::keys::{PublicKey, KEY_LEN};

fuzz_target!(|data: &[u8]| {
    let Some((controllo, corpo)) = data.split_first() else {
        return;
    };
    let controllo = *controllo;

    let mut chiave = [0u8; KEY_LEN];
    let mut nonce = [0u8; NONCE_LEN];
    for (slot, byte) in chiave.iter_mut().zip(corpo.iter()) {
        *slot = *byte;
    }
    for (slot, byte) in nonce.iter_mut().zip(corpo.iter().rev()) {
        *slot = *byte;
    }

    let header = Header {
        tier: if controllo & 0b10 == 0 {
            Tier::Baseline
        } else {
            Tier::ForwardSecret
        },
        // All origins, so the round trip also covers the ephemeral-sender
        // schemes.
        origin: match controllo % 6 {
            0 => Origin::Assente,
            1 => Origin::Mittente(PublicKey::from_bytes(chiave)),
            2 => Origin::Effimera(PublicKey::from_bytes(chiave)),
            3 => Origin::EffimeraConPrekey(PublicKey::from_bytes(chiave)),
            4 => Origin::MittenteConEpoca(PublicKey::from_bytes(chiave)),
            _ => Origin::MittenteConPrekey(PublicKey::from_bytes(chiave)),
        },
        nonce,
    };

    // A ciphertext of valid length built from the input.
    let mut ciphertext = vec![0u8; format::TAG_LEN];
    ciphertext.extend_from_slice(corpo);

    // One bit of the control byte selects the GROUP form (version 2), so the
    // group parser is fuzzed too: this is the only target that builds valid
    // blobs and reaches the deep branches.
    let gruppo = controllo & 0b100 != 0;
    let testo = if gruppo {
        // A group needs the ephemeral origin only and at least two slots: build
        // a block of valid length filled with the input. Slot contents need not
        // open: this tests the PARSER, not the cryptography.
        let quanti = 2 + usize::from(controllo) % (format::MAX_SLOT - 1);
        let mut slots = vec![0u8; quanti * format::SLOT_LEN];
        for (slot, byte) in slots.iter_mut().zip(corpo.iter().cycle()) {
            *slot = *byte;
        }
        let header_gruppo = Header {
            tier: header.tier,
            origin: Origin::Effimera(PublicKey::from_bytes(chiave)),
            nonce,
        };
        match format::serialize_group(&header_gruppo, &slots, &ciphertext) {
            Ok(testo) => {
                let mut buf = Vec::new();
                match format::parse(&testo, &mut buf) {
                    Ok(ParsedBlob::Group(g)) => {
                        assert_eq!(g.header, header_gruppo);
                        assert_eq!(g.slot_count(), quanti);
                        assert_eq!(g.ciphertext, &ciphertext[..]);
                    }
                    // The reserved tier is rejected after parsing the shape: a
                    // legitimate outcome, not a failed round trip.
                    Ok(_) | Err(_) if header_gruppo.tier != Tier::Baseline => {}
                    altro => {
                        panic!("un gruppo appena serializzato non ri-parsa: {:?}", altro.is_ok())
                    }
                }
                testo
            }
            Err(_) => return,
        }
    } else {
        let testo = format::serialize_message(&header, &ciphertext);
        // A freshly produced blob must always re-parse identically.
        let mut buf = Vec::new();
        match format::parse(&testo, &mut buf) {
            Ok(ParsedBlob::Message(envelope)) => {
                assert_eq!(envelope.header, header);
                assert_eq!(envelope.ciphertext, &ciphertext[..]);
            }
            altro => panic!("un blob appena serializzato non ri-parsa: {:?}", altro.is_ok()),
        }
        testo
    };

    // Now corrupt it: whatever the mutation, parse must not panic.
    let payload = testo.strip_prefix(SENTINEL).unwrap_or(&testo);
    if let Ok(mut body) = encoding::decode(payload) {
        let indice = usize::from(controllo) % body.len().max(1);
        if let Some(slot) = body.get_mut(indice) {
            *slot ^= controllo | 1;
        }
        let mutato = format!("{SENTINEL}{}", encoding::encode(&body));
        let mut buf2 = Vec::new();
        let _ = format::parse(&mutato, &mut buf2);

        // And truncated at every length.
        for taglio in [1usize, 3, 7, 16, 40] {
            if let Some(corto) = body.get(..body.len().saturating_sub(taglio)) {
                let testo = format!("{SENTINEL}{}", encoding::encode(corto));
                let mut buf3 = Vec::new();
                let _ = format::parse(&testo, &mut buf3);
            }
        }
    }
});
