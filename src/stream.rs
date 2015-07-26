//!
//! TODO: Write me

pub const KEY_BYTES: usize = 32;
// const NONCE_BYTES: usize = 8;

pub type SecretKey = [u8; KEY_BYTES];

#[derive(Copy, Clone)]
pub struct Stream {
    pub sk: SecretKey
}

impl Stream {
    pub fn new(sk: SecretKey) -> Stream {
        Stream { sk: sk }
    }

    // TODO: write me
}
