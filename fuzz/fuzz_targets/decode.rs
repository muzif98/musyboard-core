//! `encoding::decode` on arbitrary input.
//!
//! Two invariants:
//!   1. it never panics, whatever the input;
//!   2. canonicity: if it decodes, re-encoding the result must reproduce the
//!      input string exactly. Otherwise one blob would have several textual
//!      forms, and two identical messages might not compare equal as strings.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(testo) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(byte) = keyboard_cipher_core::encoding::decode(testo) {
        assert_eq!(
            keyboard_cipher_core::encoding::encode(&byte),
            testo,
            "decodifica non canonica"
        );
    }
});
