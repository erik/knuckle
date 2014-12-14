//!
//! TODO: Write me

pub const KEY_BYTES: uint = 32;
// const NONCE_BYTES: uint = 8;

pub type SecretKey = [u8, ..KEY_BYTES];

#[deriving(Copy)]
pub struct Stream {
    pub sk: SecretKey
}

impl Stream {
    pub fn new(sk: SecretKey) -> Stream {
        Stream { sk: sk }
    }

    // TODO: write me
}
