use bindings::*;

static KEY_BYTES: uint = 32;
static NONCE_BYTES: uint = 24;

pub type SecretKey = [u8, ..KEY_BYTES];

pub struct SecretBox {
    pub sk: SecretKey
}

impl SecretBox {
    pub fn new(sk: SecretKey) -> SecretBox {
        SecretBox { sk: sk }
    }

    pub fn encrypt(&self, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        unsafe {
            let mut nonce: Vec<u8> = Vec::with_capacity(NONCE_BYTES);
            let mut cipher: Vec<u8> = Vec::with_capacity(msg.len());

            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);
            nonce.set_len(NONCE_BYTES);

            crypto_secretbox(cipher.as_mut_ptr(),
                             msg.as_ptr(),
                             msg.len() as u64,
                             nonce.as_ptr(),
                             self.sk.as_ptr());
            cipher.set_len(msg.len());

            (cipher, nonce)
        }
    }

    pub fn decrypt(&self, cipher: &[u8], nonce: &[u8, ..NONCE_BYTES]) -> Vec<u8> {
        unsafe {
            let mut msg: Vec<u8> = Vec::with_capacity(cipher.len());

            crypto_secretbox_open(msg.as_mut_ptr(),
                                  cipher.as_ptr(),
                                  cipher.len() as u64,
                                  nonce.as_ptr(),
                                  self.sk.as_ptr());
            msg.set_len(cipher.len());

            msg
        }
    }
}
