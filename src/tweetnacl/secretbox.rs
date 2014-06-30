//! The `secretbox` module symmetrically encrypts given plaintext and
//! then uses a one time authenticator to ensure tamper-resistance.
//!
//! In other words, this uses an encrypt-then-MAC scheme.
//!
//! TODO: document me.

use bindings::*;
use std::slice::bytes::copy_memory;

/// Size of shared secret key used for symmetric encryption.
pub static KEY_BYTES: uint = 32;
/// Size of the nonce value.
pub static NONCE_BYTES: uint = 24;
/// Size of the zero padding applied to each message.
pub static ZERO_BYTES: uint = 32;

/// Shared secret key. Must be `<= KEY_BYTES` bytes long.
pub struct SecretKey ([u8, ..KEY_BYTES]);

impl SecretKey {
    /// Generate a secret key from the bytes of a given string.
    pub fn from_str(str: &str) -> SecretKey {
        SecretKey::from_slice(str.as_bytes())
    }

    /// Generate a secret key from a slice (turn a slice into a sized slice).
    pub fn from_slice(slice: &[u8]) -> SecretKey {
        assert!(slice.len() <= KEY_BYTES);

        let mut sized = [0u8, ..KEY_BYTES];
        copy_memory(sized, slice);

        SecretKey(sized)
    }
}


/// Encapsulates both the nonce value and cipher text returned by `encrypt`.
pub struct SecretMsg {
    pub nonce: [u8, ..NONCE_BYTES],
    pub cipher: Vec<u8>
}


/// TODO: Document me
pub struct SecretBox {
    sk: SecretKey
}


impl SecretBox {
    /// Create a new SecretBox with the provided key
    pub fn new(sk: SecretKey) -> SecretBox {
        SecretBox { sk: sk }
    }

    /// Using this box's secret key, symmetrically encrypt the given message.
    ///
    /// A random nonce value will be securely generated and returned
    /// as part of the response.
    pub fn encrypt(&self, msg: &[u8]) -> SecretMsg {
        unsafe {
            let mut stretched: Vec<u8> = Vec::from_elem(ZERO_BYTES, 0u8);
            stretched.push_all(msg);

            let mut nonce = [0u8, ..NONCE_BYTES];
            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);

            let SecretKey(sk) = self.sk;

            let mut cipher = Vec::from_elem(stretched.len(), 0u8);

            // TODO: Better error handling
            match crypto_secretbox(cipher.as_mut_ptr(),
                                   stretched.as_ptr(),
                                   stretched.len() as u64,
                                   nonce.as_ptr(),
                                   sk.as_ptr()) {
                0 => SecretMsg { nonce: nonce, cipher: cipher },
                _ => fail!("crypto_secretbox failed")
            }
        }
    }

    /// Using this box's secret key, decrypt the given ciphertext into
    /// plain text.
    pub fn decrypt(&self, msg: &SecretMsg) -> Vec<u8> {
        let &SecretMsg { ref nonce, ref cipher } = msg;

        unsafe {
            let mut msg = Vec::from_elem(cipher.len(), 0u8);
            let SecretKey(sk) = self.sk;

            // TODO: Error handling, this can fail in non-fatal ways
            //       (MAC validation fails etc.)
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
    for i in range(0 as uint, 16) {
        let msg = Vec::from_elem(i * 4, i as u8);

        let sb = SecretBox::new(SecretKey::from_str("some secret key"));
        let SecretMsg { nonce, mut cipher } = sb.encrypt(msg.as_slice());

        println!("enc:\t{}\nnonce:\t{}", cipher, Vec::from_slice(nonce));

        let decr = sb.decrypt(&SecretMsg { nonce: nonce, cipher: cipher });

        println!("dec:\t{}", decr);

        assert!(decr == msg);
    }
}

#[test]
fn test_secretbox_uniqueness() {
    let msg = Vec::from_elem(128, 0x53u8);

    let box1 = SecretBox::new(SecretKey::from_str("1"));
    let box2 = SecretBox::new(SecretKey::from_str(""));

    let SecretMsg { nonce: n1, cipher: c1 } = box1.encrypt(msg.as_slice());
    let SecretMsg { nonce: n2, cipher: c2 } = box2.encrypt(msg.as_slice());

    assert!(n1 != n2);
    assert!(c1 != c2);
    assert!(c1 != msg);
    assert!(c2 != msg);
}
