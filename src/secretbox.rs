//!
//! Exposes the crypto_secretbox functionality of NaCl.
//!
//! The `secretbox` module symmetrically encrypts given plaintext and
//! then uses a one time authenticator to ensure tamper-resistance.
//!
//! In other words, this uses an encrypt-then-MAC scheme.
//!
//! ## Usage
//!
//! ```rust{.example}
//! use knuckle::secretbox::{SecretKey, SecretMsg};
//!
//! let key = SecretKey::from_str("some secret key");
//! let enc: SecretMsg = key.encrypt("my secret msg".as_bytes());
//!
//! // ...
//!
//! let decr_opt = key.decrypt(&enc);
//! println!("decrypted: {}", decr_opt.unwrap());
//! ```

use bindings::*;
use std::slice::bytes::copy_memory;

/// Size of shared secret key used for symmetric encryption.
pub const KEY_BYTES: uint = 32;
/// Size of the nonce value.
pub const NONCE_BYTES: uint = 24;
/// Size of the zero padding applied to each message.
pub const ZERO_BYTES: uint = 32;


/// Encapsulates both the nonce value and cipher text returned by `encrypt`.
pub struct SecretMsg {
    /// Nonce value used for this ciphertext.
    pub nonce: [u8, ..NONCE_BYTES],
    pub cipher: Vec<u8>
}

impl SecretMsg {
    pub fn from_bytes(bytes: &[u8]) -> Option<SecretMsg> {
        if bytes.len() <= NONCE_BYTES + ZERO_BYTES {
            return None
        }

        let mut nonce = [0u8, ..NONCE_BYTES];
        let cipher = bytes.slice_from(NONCE_BYTES);

        copy_memory(&mut nonce, bytes.slice(0, NONCE_BYTES));

        Some(SecretMsg { nonce: nonce, cipher: cipher.to_vec() })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = self.nonce.to_vec();
        buf.push_all(self.cipher.as_slice());

        buf
    }
}


/// Shared secret key. Must be `<= KEY_BYTES` bytes long.
///
/// This struct wraps access to encrypting and decrypting messages.
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
        copy_memory(&mut sized, slice);

        SecretKey(sized)
    }

    /// Using this secret key, symmetrically encrypt the given message.
    ///
    /// A random nonce value will be securely generated and returned
    /// as part of the response.
    pub fn encrypt(&self, msg: &[u8]) -> SecretMsg {
        let mut stretched: Vec<u8> = Vec::from_elem(ZERO_BYTES, 0u8);
        stretched.push_all(msg);

        let mut nonce = [0u8, ..NONCE_BYTES];
        let mut cipher = Vec::from_elem(stretched.len(), 0u8);
        let &SecretKey(sk) = self;

        unsafe {
            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);

            // TODO: Better error handling
            match crypto_secretbox(cipher.as_mut_ptr(),
                                   stretched.as_ptr(),
                                   stretched.len() as u64,
                                   nonce.as_ptr(),
                                   sk.as_ptr()) {
                0 => SecretMsg { nonce: nonce, cipher: cipher },
                _ => panic!("crypto_secretbox failed")
            }
        }
    }

    /// Using this box's secret key, decrypt the given ciphertext into
    /// plain text.
    ///
    /// If the cipher text fails to conform to the MAC (message was
    /// tampered with or corrupted), then None will be returned instead.
    pub fn decrypt(&self, msg: &SecretMsg) -> Option<Vec<u8>> {
        let &SecretKey(sk) = self;
        let mut plaintext = Vec::from_elem(msg.cipher.len(), 0u8);

        unsafe {
            match crypto_secretbox_open(plaintext.as_mut_ptr(),
                                        msg.cipher.as_ptr(),
                                        msg.cipher.len() as u64,
                                        msg.nonce.as_ptr(),
                                        sk.as_ptr()) {
                0 => Some(plaintext.slice(ZERO_BYTES, plaintext.len()).to_vec()),
                -2 => None,
                _ => panic!("crypto_secretbox_open failed")
            }
        }
    }
}


#[test]
fn test_secretbox_sanity() {
    for i in range(0 as uint, 16) {
        let msg = Vec::from_elem(i * 4, i as u8);

        let key = SecretKey::from_str("some secret key");
        let SecretMsg { nonce, cipher } = key.encrypt(msg.as_slice());

        println!("enc:\t{}\nnonce:\t{}", cipher, nonce.to_vec());

        let decr_opt = key.decrypt(&SecretMsg { nonce: nonce, cipher: cipher });

        assert!(decr_opt.is_some());

        let decr = decr_opt.unwrap();
        println!("dec:\t{}", decr);

        assert!(msg == decr);
    }
}

#[test]
fn test_secretbox_uniqueness() {
    let msg = Vec::from_elem(128, 0x53u8);

    let key1 = SecretKey::from_str("1");
    let key2 = SecretKey::from_str("");

    let SecretMsg { nonce: n1, cipher: c1 } = key1.encrypt(msg.as_slice());
    let SecretMsg { nonce: n2, cipher: c2 } = key2.encrypt(msg.as_slice());

    assert!(n1 != n2);
    assert!(c1 != c2);
    assert!(c1 != msg);
    assert!(c2 != msg);
}

#[test]
fn test_secretbox_mac_sanity() {

    let msg = Vec::from_elem(0xff, 0xff as u8);

    let key = SecretKey::from_str("some secret key");

    let SecretMsg { nonce, cipher } = key.encrypt(msg.as_slice());

    let mut ciphers = [cipher.clone(), cipher.clone(), cipher.clone()];

    // tamper with the cipher text in various ways
    ciphers[0u].push(0u8);
    ciphers[1u].pop();

    let last = ciphers[2u].pop().unwrap();
    ciphers[2u].push(last + 1);

    for c in ciphers.iter() {
        let decr = key.decrypt(&SecretMsg { nonce: nonce, cipher: c.clone() });

        println!("cipher:\t{}\ndecr:\t{}", c, decr);
        assert!(decr.is_none());
    }

}

#[test]
fn test_secretbox_secretmsg() {
    let msg = b"some message";
    let key = SecretKey::from_str("some secret key");
    let encr = key.encrypt(msg);

    let secret_msg= encr.as_bytes();
    let re_encr = SecretMsg::from_bytes(secret_msg.as_slice());

    assert!(re_encr.is_some());

    let decr_opt = key.decrypt(&re_encr.unwrap());

    assert!(decr_opt.is_some());
    assert!(decr_opt.unwrap().as_slice() == msg);
}

#[test]
fn test_secretkey_tamper_resistance() {
    let msg = b"some message";
    let key = SecretKey::from_str("some secret key");
    let encr = key.encrypt(msg);
    let mut tampered_msg = encr.cipher.clone();

    // Start past the end of the nonce padding
    for i in range(16, tampered_msg.len()) {
        tampered_msg[i] = tampered_msg[i] ^ 0xFF;

        let tampered = SecretMsg { nonce: encr.nonce, cipher: tampered_msg.clone() };
        let plaintext = key.decrypt(&tampered);

        println!("msg:\t{}\ntampered:\t{}\nplaintext:\t{}", msg, tampered.cipher, plaintext);
        assert!(plaintext.is_none());
    }
}
