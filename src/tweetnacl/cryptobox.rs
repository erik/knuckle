//!
//! These are black boxes to perform authenticated asymmetric
//! cryptography.
//!
//! TODO: Document me
//!
//! ## Usage
//! ```rust{.example}
//! use tweetnacl::cryptobox::CryptoBox;
//!
//! let box1 = CryptoBox::new();
//! let box2 = CryptoBox::new();
//!
//! let msg = "my secret message";
//!
//! let (cipher, nonce) = box1.encrypt(msg.as_bytes(), box2.keypair.pk);
//!
//! let plain = box2.decrypt(cipher.as_slice(), nonce.as_slice(), box1.keypair.pk);
//! assert!(plain == Vec::from_slice(msg.as_bytes()));
//! ```

use bindings::*;

/// Size of zero padding used in encrypted messages.
pub static ZERO_BYTES: uint = 32;
/// Size of encrypted message's nonce value.
pub static NONCE_BYTES: uint = 24;
/// Size of public key.
pub static PUBLICKEY_BYTES: uint = 32;
/// Size of secret key.
pub static SECRETKEY_BYTES: uint = 32;

/// TODO: document me
pub struct CryptoBox {
    pub keypair: Keypair,
}

/// A secret key used by CryptoBox
pub struct SecretKey ([u8, ..SECRETKEY_BYTES]);

/// A public key used by CryptoBox
pub struct PublicKey ([u8, ..PUBLICKEY_BYTES]);

impl PublicKey {
    /// Generate a public key matching a given secret key.
    pub fn from_secret_key(key: SecretKey) -> PublicKey {
        unsafe {
            let mut pk = [0u8, ..PUBLICKEY_BYTES];
            let SecretKey(sk) = key;

            crypto_scalarmult_base(pk.as_mut_ptr(), sk.as_ptr());

            PublicKey(pk)
        }
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
        unsafe {
            let mut pk = [0u8, ..PUBLICKEY_BYTES];
            let mut sk = [0u8, ..SECRETKEY_BYTES];

            crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            Keypair { pk: PublicKey(pk), sk: SecretKey(sk) }
        }
    }
}

impl CryptoBox {
    /// Generate a new CryptoBox using a random keypair
    pub fn new() -> CryptoBox {
        CryptoBox { keypair: Keypair::new() }
    }

    /// Generate a new CryptoBox using an existing keypair.
    pub fn new_with_key(key: Keypair) -> CryptoBox {
        CryptoBox { keypair: key }
    }

    /// Sign a message using this box's secret key and encrypt the
    /// message to the given recipient's PublicKey.
    pub fn encrypt(&self, msg: &[u8], recvKey: PublicKey) -> (Vec<u8>, Vec<u8>) {
        unsafe {
            let mut stretched = Vec::from_elem(ZERO_BYTES, 0u8);
            stretched.push_all(msg);

            let SecretKey(sk) = self.keypair.sk;
            let PublicKey(pk) = recvKey;

            let mut nonce = Vec::from_elem(NONCE_BYTES, 0u8);
            randombytes(nonce.as_mut_ptr(), NONCE_BYTES as u64);

            let mut cipher = Vec::from_elem(stretched.len(), 0u8);
            match crypto_box(cipher.as_mut_ptr(),
                             stretched.as_ptr(),
                             stretched.len() as u64,
                             nonce.as_ptr(),
                             pk.as_ptr(),
                             sk.as_ptr()) {
                0 => (cipher, nonce),
                _ => fail!("crypto_box failed")
            }
        }
    }

    pub fn decrypt(&self, cipher: &[u8], nonce: &[u8], sendKey: PublicKey) -> Vec<u8> {
        unsafe {
            let mut msg = Vec::from_elem(cipher.len(), 0u8);

            let SecretKey(sk) = self.keypair.sk;
            let PublicKey(pk) = sendKey;

            // TODO: error handling.
            match crypto_box_open(msg.as_mut_ptr(),
                                  cipher.as_ptr(),
                                  cipher.len() as u64,
                                  nonce.as_ptr(),
                                  pk.as_ptr(),
                                  sk.as_ptr()) {
                0 => Vec::from_slice(msg.slice(ZERO_BYTES, msg.len())),
                _ => fail!("crypto_box_open failed")
            }
        }
    }
}


#[test]
fn test_cryptobox_sanity() {
    for i in range(0 as uint, 16) {
        let box1 = CryptoBox::new();
        let box2 = CryptoBox::new();

        let msg = Vec::from_elem(i * 4, i as u8);

        let (cipher, nonce) = box1.encrypt(msg.as_slice(), box2.keypair.pk);

        print!("enc:\t{}\nnonce:\t{}\n", cipher, nonce);

        let plain = box2.decrypt(cipher.as_slice(), nonce.as_slice(), box1.keypair.pk);

        print!("plain:\t{}\n", plain);
        print!("msg:\t{}\n", msg);

        assert!(msg == plain);
    }
}


#[test]
fn test_cryptobox_pubkey_from_seckey() {
    for _ in range(0i, 16) {
        let key = Keypair::new();
        let pubkey = PublicKey::from_secret_key(key.sk);

        let PublicKey(k1) = pubkey;
        let PublicKey(k2) = key.pk;

        assert!(k1 == k2);
    }
}
