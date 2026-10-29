//! The reusable part of `kc`: on-disk state and the keyring.
//!
//! A library because the windowed app and the command line must read and write
//! the **same** file. Two implementations of one format would be two sources of
//! truth, and the first time they diverged the user would lose the identity,
//! i.e. the ability to decrypt anything received.

pub mod store;
