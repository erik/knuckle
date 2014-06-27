use libc::*;

/// Rust bindings to C tweetnacl library.

#[link(name = "tweetnacl", kind = "static")]
extern "C" {
    // --- Utilities ---
    pub fn randombytes(ptr: *mut c_uchar, sz: u64);

    pub fn crypto_scalarmult(result: *mut c_uchar,
                             n: *c_uchar,
                             p: *c_uchar) -> c_int;

    pub fn crypto_scalarmult_base(result: *mut c_uchar, n: *c_uchar) -> c_int;

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

    // --- Sign ---
    pub fn crypto_sign_keypair(pk: *mut c_uchar,
                               sk: *mut c_uchar) -> c_int;

    pub fn crypto_sign(smsg: *mut c_uchar,
                       smsg_len: *mut c_ulonglong,
                       msg: *c_uchar,
                       msg_len: c_ulonglong,
                       sk: *c_uchar) -> c_int;

    pub fn crypto_sign_open(msg: *mut c_uchar,
                            msg_len: *mut c_ulonglong,
                            smsg: *c_uchar,
                            smsg_len: c_ulonglong,
                            pk: *c_uchar) -> c_int;

    // --- Hash ---
    pub fn crypto_hash(hash: *mut c_uchar,
                       msg: *c_uchar,
                       len: u64) -> c_int;
}
