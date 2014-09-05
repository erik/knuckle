//!
//! TODO: Write me

pub static KEY_BYTES: uint = 32;
// static NONCE_BYTES: uint = 8;

pub type SecretKey = [u8, ..KEY_BYTES];

pub struct Stream {
    pub sk: SecretKey
}

impl Stream {
    pub fn new(sk: SecretKey) -> Stream {
        Stream { sk: sk }
    }

    // TODO: write me
}
