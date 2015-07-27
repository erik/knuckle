#![crate_name = "knuckle"]
#![crate_type = "lib"]

#![feature(slice_bytes, vec_push_all)]
//#![deny(missing_doc)]

//! `knuckle` is an opinionated Rust language interface to the
//! already opinionated NaCl project.
//!
//! Specifically, knuckle uses `tweetnacl`, a minimal implementation
//! of NaCl that's implemented as a standalone C file. Theoretically, the
//! backend could be trivially switched to either full NaCl or the
//! derivative `libsodium` project.
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
//! cryptobox     | Curve25519/Salsa20/Poly1305
//! hash          | SHA-512
//! secretbox     | Salsa20/Poly1305
//! sign          | Ed25519
//! stream        | Salsa20

extern crate libc;

pub use bindings::*;

/// Exposes direct Rust bindings to the C NaCl interface.
#[allow(dead_code)]
pub mod bindings;

/// Provides authenticated asymmetric key cryptography operations.
pub mod cryptobox;

/// Simple interface to strong cryptographic hash function.
pub mod hash;

/// Provides authenticated symmetric key cryptography operations.
pub mod secretbox;

/// Provides simple interface to generate and validate digital signatures.
pub mod sign;

/// Exposes the crypto_stream functionality of NaCl. (Not yet written)
pub mod stream;

/// Useful common functions for this library.
pub mod util;
