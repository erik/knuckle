//!
//! Exposes the crypto_box functionality of NaCl.
//!
//!
//! TODO: Document me
//!
//! ## Usage
//! ```rust{.example}
//! use knuckle::cryptobox::{CryptoBox, Keypair};
//!
//! let key1 = Keypair::new();
//! let key2 = Keypair::new();
//!
//! let box1 = CryptoBox::from_key_pair(key1.sk, key2.pk);
//! let box2 = CryptoBox::from_key_pair(key2.sk, key1.pk);
//!
//! let msg = b"my secret message";
//!
//! let boxed = box1.encrypt(msg);
//!
//! let plain = box2.decrypt(boxed);
//! assert!(plain.unwrap() == Vec::from_slice(msg));
//! ```

use bindings::*;
use std::slice::bytes::copy_memory;

/// Size of zero padding used in encrypted messages.
pub static ZERO_BYTES: uint = 32;
/// Size of encrypted message's nonce value.
pub static NONCE_BYTES: uint = 24;
/// Size of public key.
pub static PUBLICKEY_BYTES: uint = 32;
/// Size of secret key.
pub static SECRETKEY_BYTES: uint = 32;

/// A secret key used by CryptoBox
pub struct SecretKey ([u8, ..SECRETKEY_BYTES]);

/// A public key used by CryptoBox
pub struct PublicKey ([u8, ..PUBLICKEY_BYTES]);

impl PublicKey {
    /// Generate a public key matching a given secret key.
    pub fn from_secret_key(key: SecretKey) -> PublicKey {
        let mut pk = [0u8, ..PUBLICKEY_BYTES];
        let SecretKey(sk) = key;

        unsafe { crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr()); }

        PublicKey(pk)
    }
}

impl SecretKey {
    /// Generate a random new secret key.
    pub fn new() -> SecretKey {
        let mut sk = [0u8, ..SECRETKEY_BYTES];

        unsafe { randombytes(sk.as_mut_ptr(), SECRETKEY_BYTES as u64); }

        SecretKey(sk)
    }
}

/// A asymmetric keypair containing matching public and private keys.
pub struct Keypair {
    /// Public key
    pub pk: PublicKey,
    /// Private key
    pub sk: SecretKey
}

impl Keypair {
    /// Generate a random matching public and private key.
    pub fn new() -> Keypair {
        let mut pk = [0u8, ..PUBLICKEY_BYTES];
        let mut sk = [0u8, ..SECRETKEY_BYTES];

        unsafe {
            crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            Keypair { pk: PublicKey(pk), sk: SecretKey(sk) }
        }
    }
}

pub struct BoxedMsg {
    pub nonce: [u8, ..NONCE_BYTES],
    pub cipher: Vec<u8>
}

impl BoxedMsg {
    pub fn from_bytes(bytes: &[u8]) -> Option<BoxedMsg> {
        if bytes.len() <= NONCE_BYTES + ZERO_BYTES {
            return None
        }

        let mut nonce = [0u8, ..NONCE_BYTES];
        let cipher = bytes.slice_from(NONCE_BYTES);

        copy_memory(nonce, bytes.slice(0, NONCE_BYTES));

        Some(BoxedMsg { nonce: nonce, cipher: Vec::from_slice(cipher) })
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::from_slice(self.nonce);
        buf.push_all(self.cipher.as_slice());

        buf
    }
}

/// TODO: document me
pub struct CryptoBox {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl CryptoBox {

    /// Generate a new CryptoBox using an existing keypair.

    pub fn from_key_pair(send_key: SecretKey, recv_key: PublicKey) -> CryptoBox {
        CryptoBox { sk: send_key, pk: recv_key }
    }

    /// Sign a message using this box's secret key and encrypt the
    /// message to the given recipient's PublicKey.
    pub fn encrypt(&self, msg: &[u8]) -> BoxedMsg {
        let mut stretched = Vec::from_elem(ZERO_BYTES, 0u8);
        stretched.push_all(msg);

        let SecretKey(sk) = self.sk;
        let PublicKey(pk) = self.pk;

        let mut nonce = [0u8, ..NONCE_BYTES];
        let mut cipher = Vec::from_elem(stretched.len(), 0u8);

        unsafe {
            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);

            match crypto_box(cipher.as_mut_ptr(),
                             stretched.as_ptr(),
                             stretched.len() as u64,
                             nonce.as_ptr(),
                             pk.as_ptr(),
                             sk.as_ptr()) {
                0 => BoxedMsg { nonce: nonce, cipher: cipher },
                _ => fail!("crypto_box failed")
            }
        }
    }

    pub fn decrypt(&self, box_msg: BoxedMsg) -> Option<Vec<u8>> {
        let BoxedMsg { nonce, cipher } = box_msg;

        let mut msg = Vec::from_elem(cipher.len(), 0u8);

        let SecretKey(sk) = self.sk;
        let PublicKey(pk) = self.pk;

        unsafe {
            match crypto_box_open(msg.as_mut_ptr(),
                                  cipher.as_ptr(),
                                  cipher.len() as u64,
                                  nonce.as_ptr(),
                                  pk.as_ptr(),
                                  sk.as_ptr()) {
                0 => Some(Vec::from_slice(msg.slice(ZERO_BYTES, msg.len()))),
                -2 => None,
                _ => fail!("crypto_box_open failed")
            }
        }
    }
}


#[test]
fn test_cryptobox_sanity() {
    for i in range(0 as uint, 16) {
        let key1 = Keypair::new();
        let key2 = Keypair::new();

        let box1 = CryptoBox::from_key_pair(key1.sk, key2.pk);
        let box2 = CryptoBox::from_key_pair(key2.sk, key1.pk);

        let msg = Vec::from_elem(i * 4, i as u8);

        let boxed = box1.encrypt(msg.as_slice());

        print!("enc:\t{}\nnonce:\t{}\n", boxed.cipher, Vec::from_slice(boxed.nonce));

        let plain_opt = box2.decrypt(boxed);

        assert!(plain_opt.is_some());

        let plain = plain_opt.unwrap();

        print!("plain:\t{}\n", plain);
        print!("msg:\t{}\n", msg);

        assert!(msg == plain);
    }
}


#[test]
fn test_cryptobox_pubkey_from_keypair() {
    for _ in range(0i, 16) {
        let key = Keypair::new();
        let pubkey = PublicKey::from_secret_key(key.sk);

        let PublicKey(k1) = pubkey;
        let PublicKey(k2) = key.pk;

        assert!(k1 == k2);
    }
}

#[test]
fn test_cryptobox_pubkey_from_seckey() {
    for _ in range(0i, 16) {
        let key = SecretKey::new();
        let pk = PublicKey::from_secret_key(key);

        let msg = b"secret message";

        let cbox = CryptoBox::from_key_pair(key, pk);
        let boxed = cbox.encrypt(msg);
        let plain_opt = cbox.decrypt(boxed);

        assert!(plain_opt.is_some());

        let plain = plain_opt.unwrap();

        print!("plain:\t{}\n", plain);
        print!("msg:\t{}\n", msg);

        assert!(plain == Vec::from_slice(msg));
    }
}

#[test]
fn test_cryptobox_mac_sanity() {
    for _ in range(0i, 16) {
        let kp1 = Keypair::new();
        let kp2 = Keypair::new();

        let cbox = CryptoBox::from_key_pair(kp1.sk, kp1.pk);

        for t in vec![(kp1.sk, kp2.pk),
                      (kp2.sk, kp1.pk),
                      (kp2.sk, kp2.pk)].iter() {
            let msg = b"secret message";
            let boxed = cbox.encrypt(msg);

            let &(sk, pk) = t;
            let dbox = CryptoBox::from_key_pair(sk, pk);

            let plain_opt = dbox.decrypt(boxed);
            assert!(plain_opt.is_none());
        }
    }
}

#[test]
fn test_cryptobox_boxedmsg() {
    let kp = Keypair::new();
    let cb = CryptoBox::from_key_pair(kp.sk, kp.pk);

    let msg = b"some message";
    let boxed = cb.encrypt(msg);

    let bytes = boxed.as_bytes();
    let reboxed = BoxedMsg::from_bytes(bytes.as_slice());

    assert!(reboxed.is_some());

    let plain_opt = cb.decrypt(reboxed.unwrap());

    assert!(plain_opt.is_some());
    assert!(plain_opt.unwrap().as_slice() == msg);
}
