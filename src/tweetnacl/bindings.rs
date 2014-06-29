//!
//! This module contains direct FFI calls to the NaCl library. The
//! Rust interface available in other crates in this package is much
//! easier to use, but this is conceviably necessary.
//!
//! See the [NaCl documentation](http://nacl.cr.yp.to/) for usage
//! information.
//!
//! (TODO: change this).
//!
//! For now, the relevant constants (`crypto_hash_BYTES`, etc.) are
//! available in the relevant Rust modules as statics.

use libc::*;

#[link(name = "tweetnacl", kind = "static")]
extern "C" {
    // --- Utilities ---

    /// Fill an array with secure random numbers.
    pub fn randombytes(ptr: *mut c_uchar, sz: u64);

    /// Perform scalar multiplication using Curve 25519's field.
    pub fn crypto_scalarmult(result: *mut c_uchar,
                             n: *const c_uchar,
                             p: *const c_uchar) -> c_int;
    /// Perform scalar multiplication against the Curve 25519 base point.
    pub fn crypto_scalarmult_base(result: *mut c_uchar, n: *const c_uchar) -> c_int;

    // --- Crypto box ---

    /// Generate public and private keys for use with `crypto_box`.
    pub fn crypto_box_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;

    /// Sign and encrypt a message using asymmetric encryption.
    pub fn crypto_box(cipher: *mut c_uchar,
                      msg: *const c_uchar,
                      len: c_ulonglong,
                      nonce: *const c_uchar,
                      pk: *const c_uchar,
                      sk: *const c_uchar) -> c_int;

    /// Verify and decrypt a message generated with `crypto_box`.
    pub fn crypto_box_open(msg: *mut c_uchar,
                           cipher: *const c_uchar,
                           len: c_ulonglong,
                           nonce: *const c_uchar,
                           pk: *const c_uchar,
                           sk: *const c_uchar) -> c_int;

    // --- Secret box ---

    /// Symmetrically encrypt a message using a shared secret key.
    pub fn crypto_secretbox(cipher: *mut c_uchar,
                            msg: *const c_uchar,
                            len: c_ulonglong,
                            nonce: *const c_uchar,
                            k: *const c_uchar) -> c_int;

    /// Decrypt a message encryped with `crypto_secretbox`.
    pub fn crypto_secretbox_open(msg: *mut c_uchar,
                                 cipher: *const c_uchar,
                                 len: c_ulonglong,
                                 nonce: *const c_uchar,
                                 k: *const c_uchar) -> c_int;

    // --- Sign ---

    /// Generate signing keys to use with `crypto_sign`.
    pub fn crypto_sign_keypair(pk: *mut c_uchar,
                               sk: *mut c_uchar) -> c_int;

    /// Sign a message using a given secret key.
    pub fn crypto_sign(smsg: *mut c_uchar,
                       smsg_len: *mut c_ulonglong,
                       msg: *const c_uchar,
                       msg_len: c_ulonglong,
                       sk: *const c_uchar) -> c_int;

    /// Verify the validity of an asymmetrially signed message.
    pub fn crypto_sign_open(msg: *mut c_uchar,
                            msg_len: *mut c_ulonglong,
                            smsg: *const c_uchar,
                            smsg_len: c_ulonglong,
                            pk: *const c_uchar) -> c_int;

    // --- Hash ---
    /// Hash.
    pub fn crypto_hash(hash: *mut c_uchar,
                       msg: *const c_uchar,
                       len: u64) -> c_int;
}
