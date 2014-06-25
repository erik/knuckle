use libc;

/// Rust bindings to C tweetnacl library.

extern "C" {


    // --- Utilities ---
    pub fn randombytes(ptr: *mut libc::c_uchar, sz: u64);


    // --- Crypto box ---
    pub fn crypto_box_keypair(pk: *mut libc::c_uchar, sk: *mut libc::c_uchar) -> libc::c_int;
    pub fn crypto_box(cipher: *mut libc::c_uchar,
                      msg: *libc::c_uchar,
                      len: libc::c_ulonglong,
                      nonce: *libc::c_uchar,
                      pk: *libc::c_uchar,
                      sk: *libc::c_uchar);
    pub fn crypto_box_open(msg: *mut libc::c_uchar,
                           cipher: *libc::c_uchar,
                           len: libc::c_ulonglong,
                           nonce: *libc::c_uchar,
                           pk: *libc::c_uchar,
                           sk: *libc::c_uchar);


}
