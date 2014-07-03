#![crate_id = "tweetnacl#tweetnacl"]
#![crate_type = "lib"]
#![desc = "TODO: write me"]
#![comment = "TODO: write me"]
#![license = "MIT"]

#![feature(globs)]
// #[deny(missing_doc)]

//! `tweetnacl` is an opinionated Rust language interface to the
//! already opinionated NaCl project.
//!
//! It provides several useful abstractions around NaCl's primitives,
//! but also exposes direct bindings to the C library (via the `bindings`
//! module).
//!
//! ## Primitives
//!
//! The following cryptographic primitives are used with this library.
//!
//! Module        | Primitive
//! ------------- | -------------
//! auth          | HMAC-SHA-512/256
//! cryptobox     | Curve25519/Salsa20/Poly1305
//! hash          | SHA-512
//! secretbox     | Salsa20/Poly1305
//! sign          | Ed25519
//! stream        | Salsa20

extern crate libc;

pub mod auth;

/// Exposes the crypto_box functionality of NaCl.
pub mod cryptobox;

/// Exposes the crypto_hash functionality of NaCl.
pub mod hash;

/// Exposes the crypto_secretbox functionality of NaCl.
pub mod secretbox;

/// Exposes the crypto_sign functionality of NaCl.
pub mod sign;

/// Exposes the crypto_stream functionality of NaCl.
pub mod stream;

/// Exposes direct Rust bindings to the C NaCl interface.
#[allow(dead_code)]
pub mod bindings;