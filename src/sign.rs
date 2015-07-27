//!
//! Exposes the crypto_sign functionality of NaCl.
//!
//! ## Usage
//!
//! ```rust{.example}
//! use knuckle::sign::Keypair;
//!
//! let key = Keypair::new();
//! let msg = b"some important message";
//!
//! let signed = key.sign(msg);
//!
//! // ...
//!
//! let plain_opt = signed.verify();
//! assert!(plain_opt.is_some());
//! assert!(plain_opt.unwrap() == msg);
//! ```

use bindings::*;

use std::slice::bytes::copy_memory;

/// Number of bytes in the sign public key
pub const PUBKEY_BYTES: usize = 32;
/// Number of bytes in the sign private key
pub const SECKEY_BYTES: usize = 64;
/// Bytes of padding used in each signed message
pub const SIGN_BYTES: usize = 64;

/// Key used to verify the validity of signed messages.
#[derive(Copy, Clone)]
pub struct PublicKey ([u8; PUBKEY_BYTES]);

/// Secret key used to generate valid message signatures.
#[derive(Copy)]
pub struct SecretKey ([u8; SECKEY_BYTES]);

impl Clone for SecretKey {
    fn clone(&self) -> SecretKey {
        *self
    }
}

/// Encapsulates the verification key and signed message.
pub struct SignedMsg {
    /// Public key matching the key used to sign this message.
    pub pk: PublicKey,
    /// Cryptographically signed message, containing both signature and message.
    pub signed: Vec<u8>
}

impl SignedMsg {
    /// Verify the validity of a given signed message against this public key.
    pub fn verify(&self) -> Option<Vec<u8>> {
        let PublicKey(pk) = self.pk;

        let mut msg = Vec::with_capacity(self.signed.len());
        let mut msg_len = 0u64;

        unsafe {
            match crypto_sign_open(msg.as_mut_ptr(),
                                   &mut msg_len,
                                   self.signed.as_ptr(),
                                   self.signed.len() as u64,
                                   pk.as_ptr()) {
                -3 => None,
                0  => {
                    msg.set_len(msg_len as usize);
                    Some(msg)
                },
                _  => panic!("Impossible things happened")
            }
        }
    }

    /// Serialize the `SignedMsg` into bytes. Response will contain both the
    /// public key to verify the message as well as the signed message itself.
    ///
    /// **IMPORTANT**: THIS SHOULD NOT BE USED TO TRANSFER THE PUBLIC KEY. It is
    /// only included for convenience. Make sure the client checking the signature
    /// has some secure source for receiving the correct verification key.
    pub fn as_bytes(&self) -> Vec<u8> {
        let PublicKey(pk) = self.pk;
        let mut buf = pk.to_vec();

        buf.push_all(&self.signed);

        buf
    }

    /// Construct a SignedMsg from the form serialized by `as_bytes`.
    ///
    /// **IMPORTANT**: The same warning in the documentation for `as_bytes`
    /// applies here. Don't blindly trust keys!
    pub fn from_bytes(msg: &[u8]) -> Option<SignedMsg> {
        if msg.len() < PUBKEY_BYTES + SIGN_BYTES {
            return None;
        }

        let mut pk = [0u8; PUBKEY_BYTES];
        let signed = &msg[PUBKEY_BYTES..];

        copy_memory(&msg[0 .. PUBKEY_BYTES], &mut pk);

        Some(SignedMsg { pk: PublicKey(pk), signed: signed.to_vec() })
    }
}

/// Struct representing a signing key pair, used to create signed messages.
#[derive(Copy, Clone)]
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl Keypair {
    /// Securely generate a random new signing keypair
    pub fn new() -> Keypair {
        let mut pk = [0u8; PUBKEY_BYTES];
        let mut sk = [0u8; SECKEY_BYTES];

        unsafe {
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }

        Keypair { pk: PublicKey(pk), sk: SecretKey(sk) }
    }

    /// Sign a given message with this keypair's signing key.
    pub fn sign(&self, msg: &[u8]) -> SignedMsg {
        let mut signed = Vec::with_capacity(msg.len() + SIGN_BYTES);
        let mut signed_len: u64 = 0;

        let SecretKey(sk) = self.sk;
        let PublicKey(pk) = self.pk;

        unsafe {
            crypto_sign(signed.as_mut_ptr(),
                        &mut signed_len,
                        msg.as_ptr(),
                        msg.len() as u64,
                        sk.as_ptr());

            signed.set_len(signed_len as usize);
        }

        SignedMsg { pk: PublicKey(pk), signed: signed }
    }
}


#[test]
fn test_sign_sanity() {
    use std::iter::repeat;

    for i in 1..16 {
        let keypair = Keypair::new();
        let msg: Vec<u8> = repeat(i as u8).take(i * 4).collect();

        let SecretKey(sk) = keypair.sk;
        let PublicKey(pk) = keypair.pk;

        println!("sk: {:?}\npk: {:?}", &sk[..], &pk[..]);

        let sig = keypair.sign(&msg);
        let desig = sig.verify();

        println!("msg:\t{:?}\nsig:\t{:?}\ndesig:\t{:?}", msg, sig.signed, desig);

        assert!(desig.is_some());
        assert!(desig.unwrap() == msg);
    }
}


#[test]
fn test_sign_fail_sanity() {
    let key1 = Keypair::new();
    let key2 = Keypair::new();

    let msg = b"some message";

    let sig = key1.sign(msg);

    let altered_sig = SignedMsg { pk: key2.pk, signed: sig.signed.clone() };
    let desig = altered_sig.verify();

    println!("msg:\t{:?}\nsig:\t{:?}\ndesig:\t{:?}", msg, sig.signed, desig);

    assert!(desig.is_none());
}

#[test]
fn test_sign_tamper_resistance() {
    let keypair = Keypair::new();
    let msg = b"something";

    let sig = keypair.sign(msg);
    let mut tampered_msg = sig.signed.clone();

    // Try tampering each of the different bytes of the signed message
    for i in 0..tampered_msg.len() {
        tampered_msg[i] = tampered_msg[i] ^ 0xFF;

        let tampered_sig = SignedMsg { pk: keypair.pk, signed: tampered_msg.clone() };
        let design = tampered_sig.verify();

        println!("msg:\t{:?}\nsig:\t{:?}\ndesig:\t{:?}", msg, sig.signed, design);
        assert!(design.is_none());
    }
}

#[test]
fn test_sign_serialization() {
    let keypair = Keypair::new();
    let msg = b"my message";

    let signed = keypair.sign(msg);
    let serialized = signed.as_bytes();
    let deserialized = SignedMsg::from_bytes(&serialized);

    assert!(deserialized.is_some());

    let validated_msg = deserialized.unwrap().verify();

    assert!(validated_msg.is_some());
    assert!(validated_msg.unwrap() == msg);
}
