use libc::*;

/// Rust bindings to C tweetnacl library.

extern "C" {
    // --- Utilities ---
    pub fn randombytes(ptr: *mut c_uchar, sz: u64);

    // --- Crypto box ---
    pub fn crypto_box_keypair(pk: *mut c_uchar, sk: *mut c_uchar) -> c_int;

    pub fn crypto_box(cipher: *mut c_uchar,
                      msg: *c_uchar,
                      len: c_ulonglong,
                      nonce: *c_uchar,
                      pk: *c_uchar,
                      sk: *c_uchar) -> c_int;

    pub fn crypto_box_open(msg: *mut c_uchar,
                           cipher: *c_uchar,
                           len: c_ulonglong,
                           nonce: *c_uchar,
                           pk: *c_uchar,
                           sk: *c_uchar) -> c_int;

    // --- Secret box ---
    pub fn crypto_secretbox(cipher: *mut c_uchar,
                            msg: *c_uchar,
                            len: c_ulonglong,
                            nonce: *c_uchar,
                            k: *c_uchar) -> c_int;

    pub fn crypto_secretbox_open(msg: *mut c_uchar,
                                 cipher: *c_uchar,
                                 len: c_ulonglong,
                                 nonce: *c_uchar,
                                 k: *c_uchar) -> c_int;

}
