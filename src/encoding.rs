//! z-base-32 (Zooko): the surface encoding.
//!
//! Chosen because it survives keyboard autocorrect and human reading:
//! lowercase only, no punctuation, no visually ambiguous characters.
//!
//! The original specification is BIT-oriented and can encode sub-octet
//! quantities. Only the byte-aligned case is needed here, so the API takes and
//! returns whole bytes: the last character carries zero padding bits, and
//! decoding requires them to be zero (see [`decode`]).

use crate::error::{Error, Result};

/// The z-base-32 alphabet. The order is NOT that of RFC 4648 base32: the most
/// legible symbols take the most frequent positions. Do not reorder.
pub const ALPHABET: &[u8; 32] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// Marker for "not in the alphabet" in the reverse table.
const INVALID: u8 = 0xFF;

/// Decoding table, built from the alphabet at compile time so the two
/// directions cannot diverge.
// `i` is bounded to 0..32 and ALPHABET has 32 elements; the `table` index is a
// widened u8 and `table` has 256 entries. Evaluation happens at compile time,
// so an out-of-bounds index would fail to compile, not panic at runtime.
#[allow(clippy::indexing_slicing)]
const DECODE_TABLE: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut i = 0usize;
    while i < 32 {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// Encoded length in characters of `bytes` bytes: `ceil(bytes * 8 / 5)`.
///
/// Saturates instead of overflowing: such an input cannot exist in memory,
/// but the function stays total.
const fn encoded_len(bytes: usize) -> usize {
    match bytes.checked_mul(8) {
        Some(bits) => match bits.checked_add(4) {
            Some(padded) => padded / 5,
            None => usize::MAX,
        },
        None => usize::MAX,
    }
}

/// A string of `n` characters encodes whole bytes only if `n` is exactly the
/// length produced by some number of bytes.
///
/// This rejects strings with a trailing character that carries no data: 3
/// characters would encode 1 byte plus 7 bits of nothing, and 1 byte is
/// written with 2 characters. Without this check, several distinct strings
/// would decode to the same blob.
const fn is_canonical_len(n: usize) -> bool {
    match n.checked_mul(5) {
        Some(bits) => encoded_len(bits / 8) == n,
        None => false,
    }
}

pub fn encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(encoded_len(bytes.len()));
    // MSB-first accumulator. It holds at most 4 leftover + 8 new = 12 bits, so
    // u16 is enough and the shift never loses bits.
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;

    for &byte in bytes {
        acc = (acc << 8) | u16::from(byte);
        bits = bits.saturating_add(8);
        while bits >= 5 {
            bits = bits.saturating_sub(5);
            out.push(symbol((acc >> bits) as u8));
        }
    }
    if bits > 0 {
        // Zero padding bits at the end.
        out.push(symbol((acc << (5u8.saturating_sub(bits))) as u8));
    }
    out
}

/// Strict decoding: exactly one valid encoding for every input.
///
/// Rejects, all with [`Error::Decode`]:
///   - characters outside the alphabet, uppercase included;
///   - lengths that cannot come from whole bytes;
///   - non-zero trailing padding bits.
///
/// Without this strictness one blob would have several textual forms, and two
/// identical messages might not compare equal as strings.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    let raw = s.as_bytes();
    if !is_canonical_len(raw.len()) {
        return Err(Error::Decode);
    }

    let mut out = Vec::with_capacity(raw.len().saturating_mul(5) / 8);
    let mut acc: u16 = 0;
    let mut bits: u8 = 0;

    for &c in raw {
        let value = value_of(c)?;
        acc = (acc << 5) | u16::from(value);
        bits = bits.saturating_add(5);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push((acc >> bits) as u8);
        }
    }

    // Leftover bits are padding and must be zero.
    let residual_mask = (1u16 << bits).saturating_sub(1);
    if acc & residual_mask != 0 {
        return Err(Error::Decode);
    }
    Ok(out)
}

/// Symbol for a 5-bit value.
fn symbol(value: u8) -> char {
    let index = usize::from(value & 0x1F);
    // `index` < 32 because of the mask, and ALPHABET has 32 elements.
    #[allow(clippy::indexing_slicing)]
    char::from(ALPHABET[index])
}

/// Is the byte in the z-base-32 alphabet?
///
/// Used to isolate a blob inside arbitrary text: the alphabet is all ASCII, so
/// stopping at the first foreign byte always lands on a character boundary.
pub fn is_alphabet_byte(b: u8) -> bool {
    value_of(b).is_ok()
}

/// 5-bit value of a character, or [`Error::Decode`] if outside the alphabet.
fn value_of(c: u8) -> Result<u8> {
    // `c` is a u8 and DECODE_TABLE has 256 entries: always in range.
    #[allow(clippy::indexing_slicing)]
    let value = DECODE_TABLE[usize::from(c)];
    if value == INVALID {
        Err(Error::Decode)
    } else {
        Ok(value)
    }
}

#[cfg(test)]
// In tests `unwrap` is intended: an unexpected `Err` must fail loudly. The ban
// applies to production code.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// The alphabet is copied from the specification. If this test changes,
    /// the wire format changed, not the code.
    #[test]
    fn alfabeto_della_specifica() {
        assert_eq!(ALPHABET, b"ybndrfg8ejkmcpqxot1uwisza345h769");
    }

    /// Vectors from the EXAMPLES table of the z-base-32 specification.
    ///
    /// The table has ten rows but only these two are byte-aligned (24 bits);
    /// the others encode sub-octet quantities (1, 2, 10, 20, 30 bits) that this
    /// API does not express.
    ///
    /// The 30-bit row is also wrong in the specification itself: its base32
    /// column has 7 characters where 30 bits need 6, and its z-base-32 value
    /// ("6im5sd") does not match its own base-2 column, which gives "6im54d".
    /// It is not usable as a vector in any form.
    #[test]
    fn vettori_della_specifica() {
        // 24 bit: 111100001011111111000111
        assert_eq!(encode(&[0xF0, 0xBF, 0xC7]), "6n9hq");
        assert_eq!(decode("6n9hq").unwrap(), vec![0xF0, 0xBF, 0xC7]);

        // 24 bit: 110101000111101000000100
        assert_eq!(encode(&[0xD4, 0x7A, 0x04]), "4t7ye");
        assert_eq!(decode("4t7ye").unwrap(), vec![0xD4, 0x7A, 0x04]);
    }

    #[test]
    fn vuoto() {
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("").unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn round_trip_ogni_lunghezza() {
        for len in 0..=64usize {
            let input: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(37) ^ 0xA5) as u8).collect();
            let encoded = encode(&input);
            assert_eq!(encoded.len(), encoded_len(len), "lunghezza attesa, len={len}");
            assert_eq!(decode(&encoded).unwrap(), input, "round-trip, len={len}");
        }
    }

    /// Differential testing against an independent implementation, for all the
    /// lengths the specification does not cover.
    #[test]
    fn concorde_con_implementazione_indipendente() {
        for len in 0..=64usize {
            let input: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(101) ^ 0x3C) as u8).collect();
            let nostro = encode(&input);
            let loro = zbase32::encode_full_bytes(&input);
            assert_eq!(nostro, loro, "encode diverge, len={len}");
            // Decode their output too, not only ours: a self round-trip would not
            // rule out two symmetric bugs.
            assert_eq!(decode(&loro).unwrap(), input, "decode diverge, len={len}");
        }
    }

    #[test]
    fn rifiuta_maiuscole() {
        // "6N9HQ" looks the same to a human but is not canonical.
        assert!(matches!(decode("6N9HQ"), Err(Error::Decode)));
    }

    #[test]
    fn rifiuta_caratteri_fuori_alfabeto() {
        // 'l', 'v', '0', '2' are excluded from the alphabet because they can be
        // confused with '1', 'u', 'o', 'z'.
        for bad in ["6n9hl", "6n9hv", "6n9h0", "6n9h2", "6n9h ", "6n9h/"] {
            assert!(matches!(decode(bad), Err(Error::Decode)), "accettato: {bad}");
        }
    }

    #[test]
    fn rifiuta_lunghezze_non_canoniche() {
        // 1 and 3 characters cannot come from whole bytes: 1 byte -> 2
        // characters, 2 bytes -> 4.
        for bad in ["y", "yyy", "yyyyyy", "yyyyyyyyy"] {
            assert!(matches!(decode(bad), Err(Error::Decode)), "accettato: {bad}");
        }
    }

    #[test]
    fn rifiuta_bit_di_riempimento_non_nulli() {
        // [0x00] -> "yy": two characters, 10 bits, 2 of them padding.
        assert_eq!(encode(&[0x00]), "yy");
        // 'b' = 1 sets a padding bit. It would decode to the same byte 0x00,
        // which is exactly the malleability to exclude.
        assert!(matches!(decode("yb"), Err(Error::Decode)));
        assert_eq!(decode("yy").unwrap(), vec![0x00]);
    }

    /// Canonicity proven exhaustively, not by sampling.
    ///
    /// For every possible string of 2 and 4 alphabet characters: either
    /// decoding fails, or re-encoding the result gives back exactly the same
    /// string. No two distinct strings decode to the same blob.
    ///
    /// The counts are the independent check: 2 characters encode exactly 1
    /// byte, so exactly 256 of 32^2 strings must pass; 4 characters encode 2
    /// bytes, so 65_536 of 32^4. Without the padding-bit check, all would pass.
    #[test]
    fn canonicita_esaustiva() {
        for (chars, attesi) in [(2usize, 256usize), (4, 65_536)] {
            let mut passate = 0usize;
            let mut buf = vec![0u8; chars];
            for n in 0..32usize.pow(chars as u32) {
                let mut rest = n;
                for slot in buf.iter_mut() {
                    *slot = ALPHABET.get(rest % 32).copied().unwrap_or(b'y');
                    rest /= 32;
                }
                let s = std::str::from_utf8(&buf).unwrap();
                if let Ok(decoded) = decode(s) {
                    assert_eq!(encode(&decoded), s, "codifica non canonica: {s}");
                    passate += 1;
                }
            }
            assert_eq!(passate, attesi, "stringhe accettate a {chars} caratteri");
        }
    }

    #[test]
    fn nessun_panic_su_input_arbitrario() {
        // Includes multi-byte UTF-8, where len() in bytes differs from the
        // number of characters: it must fail, not panic.
        for s in ["", "y", "!!!!", "6n9hq6n9hq", "ààà", "\u{1F600}", "6n9hq\0"] {
            let _ = decode(s);
        }
    }
}
