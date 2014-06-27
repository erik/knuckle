use bindings::*;
use std::slice::bytes::copy_memory;

static KEY_BYTES: uint = 32;
static NONCE_BYTES: uint = 24;
static ZERO_BYTES: uint = 32;


pub struct SecretKey ([u8, ..KEY_BYTES]);

impl SecretKey {
    pub fn from_str(str: &str) -> SecretKey {
        SecretKey::from_slice(str.as_bytes())
    }

    pub fn from_slice(slice: &[u8]) -> SecretKey {
        assert!(slice.len() <= KEY_BYTES);

        let mut sized = [0u8, ..KEY_BYTES];
        copy_memory(sized, slice);

        SecretKey(sized)
    }
}

pub struct SecretBox {
    sk: SecretKey
}

impl SecretBox {
    pub fn new(sk: SecretKey) -> SecretBox {
        SecretBox { sk: sk }
    }

    pub fn encrypt(&self, msg: &[u8]) -> (Vec<u8>, Vec<u8>) {
        unsafe {
            let mut stretched: Vec<u8> = Vec::from_elem(ZERO_BYTES, 0u8);
            stretched.push_all(msg);

            let mut nonce = Vec::from_elem(NONCE_BYTES, 0u8);
            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);

            let SecretKey(sk) = self.sk;

            let mut cipher = Vec::from_elem(stretched.len(), 0u8);

            match crypto_secretbox(cipher.as_mut_ptr(),
                                   stretched.as_ptr(),
                                   stretched.len() as u64,
                                   nonce.as_ptr(),
                                   sk.as_ptr()) {
                0 => (cipher, nonce),
                _ => fail!("crypto_secretbox failed")
            }
        }
    }

    pub fn decrypt(&self, cipher: &[u8], nonce: &[u8]) -> Vec<u8> {
        unsafe {
            let mut msg = Vec::from_elem(cipher.len(), 0u8);
            let SecretKey(sk) = self.sk;

            match crypto_secretbox_open(msg.as_mut_ptr(),
                                        cipher.as_ptr(),
                                        cipher.len() as u64,
                                        nonce.as_ptr(),
                                        sk.as_ptr()) {
                0 => Vec::from_slice(msg.slice(ZERO_BYTES, msg.len())),
                _ => fail!("crypto_secretbox_open failed")
            }
        }
    }
}


#[test]
fn test_secretbox_sanity() {
    for i in range(0 as uint, 256) {
        let msg = Vec::from_elem(i, i as u8);

        let sb = SecretBox::new(SecretKey::from_str("some passkey"));
        let (encr, nonce) = sb.encrypt(msg.as_slice());

        println!("enc:\t{}\nnonce:\t{}", encr, nonce);

        let decr = sb.decrypt(encr.as_slice(), nonce.as_slice());

        println!("dec:\t{}", decr);

        assert!(decr == msg);
    }
}
