//! keyboard-cipher core: encryption and message format for MusyBoard.
//!
//! Design decisions are recorded in `DESIGN.md`. In short:
//!   - Baseline: X25519 + XChaCha20-Poly1305 + HKDF-SHA-256.
//!   - Identity: TOFU, with the sender's public key in clear **only** in the
//!     static schemes.
//!   - Forward secrecy inside the baseline tier, signalled by flag bits: a
//!     single-use sender key per message plus a temporary recipient key that
//!     travels inside the ciphertext. The property comes from discarding old
//!     keys, not from encrypting.
//!   - Surface encoding: z-base-32.
//!   - Version byte first, tier inside the AAD (no downgrade).
//!   - The forward-secrecy **tier** is a reserved slot in the format, not
//!     implemented; not to be confused with the forward secrecy above.
//!
//! Threat model: platform-side mass scanning, not a targeted adversary.
//!
//! This crate does no I/O. Randomness and time are injected by the caller;
//! without that, test vectors for the format could not be written.

#![forbid(unsafe_code)]
#![deny(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

pub mod api;
pub mod backup;
pub mod baseline;
pub mod encoding;
pub mod error;
pub mod file;
pub mod format;
pub mod keys;

pub use error::{Error, Result};
