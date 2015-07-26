//!
//! Exposes the crypto_box functionality of NaCl.
//!
//! The `cryptobox` module allows simple access to asymmetric (i.e. public key /
//! private key) encryption, including message authentication to ensure message
//! validity.
//!
//! A `CryptoBox` is the black box interface for encrypting and decrypting
//! messages from and to a specific recipient.
//!
//! **CAREFUL:** safely transporting and verifying public keys is still a
//! difficult problem. The exact solution depends on your use case, but don't just
//! send over a public key in the clear and assume it will be safe.
//!
//! ## Usage
//! ```rust{.example}
//! use knuckle::cryptobox::{CryptoBox, Keypair};
//!
//! // For this example, pretend that key1 / box1 exist on some other computer
//! // than key2 / box2.
//!
//! // Generate two independent sets of keypairs
//! let key1 = Keypair::new();
//! let key2 = Keypair::new();
//!
//! // Create a black box for handling messages between the keypairs.
//! let box1 = CryptoBox::from_key_pair(key1.sk, key2.pk);
//! let box2 = CryptoBox::from_key_pair(key2.sk, key1.pk);
//!
//! let msg = b"my secret message";
//!
//! // Encrypt `msg` so that only the owner of `key2` can decrypt it.
//! let boxed = box1.encrypt(msg);
//!
//! // Decrypt the encrypted message using `key2`'s secret key.
//! let plain = box2.decrypt(boxed);
//! assert!(plain.unwrap() == msg.to_vec());
//! ```

use bindings::*;
use std::iter::repeat;
use std::slice::bytes::copy_memory;

/// Size of zero padding used in encrypted messages.
pub const ZERO_BYTES: usize = 32;
/// Size of encrypted message's nonce value.
pub const NONCE_BYTES: usize = 24;
/// Size of public key.
pub const PUBLICKEY_BYTES: usize = 32;
/// Size of secret key.
pub const SECRETKEY_BYTES: usize = 32;

/// A secret key used by CryptoBox
#[derive(Copy, Clone)]
pub struct SecretKey ([u8; SECRETKEY_BYTES]);

/// A public key used by CryptoBox
#[derive(Copy, Clone)]
pub struct PublicKey ([u8; PUBLICKEY_BYTES]);

impl PublicKey {
    /// Generate a public key matching a given secret key.
    pub fn from_secret_key(key: SecretKey) -> PublicKey {
        let mut pk = [0u8; PUBLICKEY_BYTES];
        let SecretKey(sk) = key;

        unsafe { crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr()); }

        PublicKey(pk)
    }
}

impl SecretKey {
    /// Generate a random new secret key. This is done simply by grabbing the
    /// appropriate number of random bytes.
    pub fn new() -> SecretKey {
        let mut sk = [0u8; SECRETKEY_BYTES];

        unsafe { randombytes(sk.as_mut_ptr(), SECRETKEY_BYTES as u64); }

        SecretKey(sk)
    }
}

/// A asymmetric keypair containing matching public and private keys.
#[derive(Copy, Clone)]
pub struct Keypair {
    /// Public key
    pub pk: PublicKey,
    /// Private key
    pub sk: SecretKey
}

impl Keypair {
    /// Generate a random matching public and private key.
    pub fn new() -> Keypair {
        let mut pk = [0u8; PUBLICKEY_BYTES];
        let mut sk = [0u8; SECRETKEY_BYTES];

        unsafe {
            crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            Keypair { pk: PublicKey(pk), sk: SecretKey(sk) }
        }
    }
}

///Struct representing the encrypted contents of a message.
pub struct BoxedMsg {
    /// Nonce value used for this encrypted message
    pub nonce: [u8; NONCE_BYTES],
    /// The ciphertext value of the encrypted plaintext
    pub cipher: Vec<u8>
}

impl BoxedMsg {
    /// Serialize a BoxedMsg into bytes, use `BoxedMsg::from_bytes` to deserialize.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut buf = self.nonce.to_vec();
        buf.push_all(&self.cipher);

        buf
    }

    /// Deserialize a BoxedMsg instance out of its byte representation
    pub fn from_bytes(bytes: &[u8]) -> Option<BoxedMsg> {
        if bytes.len() <= NONCE_BYTES + ZERO_BYTES {
            return None
        }

        let mut nonce = [0u8; NONCE_BYTES];
        let cipher = &bytes[NONCE_BYTES..];

        copy_memory(&bytes[0 .. NONCE_BYTES], &mut nonce);

        Some(BoxedMsg { nonce: nonce, cipher: cipher.to_vec() })
    }
}

/// Struct enabling bidirectional asymmetrically encrypted communication
/// between two parties.
#[derive(Copy, Clone)]
pub struct CryptoBox {
    /// Key used to decrypt messages passed to this CryptoBox. Sender must have
    /// the matching public key.
    pub sk: SecretKey,
    /// Key used to encrypt messages to some other party.
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
        let mut stretched = [0u8; ZERO_BYTES].to_vec();
        stretched.push_all(msg);

        let SecretKey(sk) = self.sk;
        let PublicKey(pk) = self.pk;

        let mut nonce = [0u8; NONCE_BYTES];
        let mut cipher: Vec<u8> = repeat(0u8).take(stretched.len()).collect();

        unsafe {
            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);

            match crypto_box(cipher.as_mut_ptr(),
                             stretched.as_ptr(),
                             stretched.len() as u64,
                             nonce.as_ptr(),
                             pk.as_ptr(),
                             sk.as_ptr()) {
                0 => BoxedMsg { nonce: nonce, cipher: cipher },
                _ => panic!("crypto_box failed")
            }
        }
    }

    /// Given an encrypted message, attempt to decrypt the content, returning
    /// None if the message was unable to be decrypted (indicating tampered message
    /// or a bad public / secret key match).
    pub fn decrypt(&self, box_msg: BoxedMsg) -> Option<Vec<u8>> {
        let BoxedMsg { nonce, cipher } = box_msg;

        let mut msg: Vec<u8> = repeat(0u8).take(cipher.len()).collect();

        let SecretKey(sk) = self.sk;
        let PublicKey(pk) = self.pk;

        unsafe {
            match crypto_box_open(msg.as_mut_ptr(),
                                  cipher.as_ptr(),
                                  cipher.len() as u64,
                                  nonce.as_ptr(),
                                  pk.as_ptr(),
                                  sk.as_ptr()) {
                0 => Some((&msg[ZERO_BYTES .. msg.len()]).to_vec()),
                -2 => None,
                _ => panic!("crypto_box_open failed")
            }
        }
    }
}


#[test]
fn test_cryptobox_sanity() {
    for i in 0..16 {
        let key1 = Keypair::new();
        let key2 = Keypair::new();

        let box1 = CryptoBox::from_key_pair(key1.sk, key2.pk);
        let box2 = CryptoBox::from_key_pair(key2.sk, key1.pk);

        let msg: Vec<u8> = repeat(i as u8).take(i * 4).collect();

        let boxed = box1.encrypt(&msg);

        print!("enc:\t{:?}\nnonce:\t{:?}\n", boxed.cipher, boxed.nonce.to_vec());

        let plain_opt = box2.decrypt(boxed);

        assert!(plain_opt.is_some());

        let plain = plain_opt.unwrap();

        print!("plain:\t{:?}\n", plain);
        print!("msg:\t{:?}\n", msg);

        assert!(msg == plain);
    }
}


#[test]
fn test_cryptobox_pubkey_from_keypair() {
    for _ in 0..16 {
        let key = Keypair::new();
        let pubkey = PublicKey::from_secret_key(key.sk);

        let PublicKey(k1) = pubkey;
        let PublicKey(k2) = key.pk;

        assert!(k1 == k2);
    }
}

#[test]
fn test_cryptobox_pubkey_from_seckey() {
    for _ in 0..16 {
        let key = SecretKey::new();
        let pk = PublicKey::from_secret_key(key);

        let msg = b"secret message";

        let cbox = CryptoBox::from_key_pair(key, pk);
        let boxed = cbox.encrypt(msg);
        let plain_opt = cbox.decrypt(boxed);

        assert!(plain_opt.is_some());

        let plain = plain_opt.unwrap();

        print!("plain:\t{:?}\n", plain);
        print!("msg:\t{:?}\n", msg);

        assert!(plain == msg.to_vec());
    }
}

#[test]
fn test_cryptobox_mac_sanity() {
    for _ in 0..16 {
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
    let reboxed = BoxedMsg::from_bytes(&bytes);

    assert!(reboxed.is_some());

    let plain_opt = cb.decrypt(reboxed.unwrap());

    assert!(plain_opt.is_some());
    assert!(plain_opt.unwrap() == msg);
}

#[test]
fn test_cryptobox_tamper_resistance() {
    let kp = Keypair::new();
    let cb = CryptoBox::from_key_pair(kp.sk, kp.pk);
    let msg = b"something";

    let boxed = cb.encrypt(msg);
    let mut tampered_msg = boxed.cipher.clone();

    // Start past the end of the nonce padding
    for i in 16..tampered_msg.len() {
        tampered_msg[i] = tampered_msg[i] ^ 0xFF;

        let tampered_boxed = BoxedMsg { nonce: boxed.nonce, cipher: tampered_msg.clone() };
        let plaintext = cb.decrypt(tampered_boxed);

        println!("msg:\t{:?}\ntampered:\t{:?}\nplaintext:\t{:?}", msg, tampered_msg, plaintext);
        assert!(plaintext.is_none());
    }
}
