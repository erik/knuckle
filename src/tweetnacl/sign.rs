//!
//!
//! TODO: document me

use bindings::*;

/// Number of bytes in the sign public key
pub static PUBKEY_BYTES: uint = 32;
/// Number of bytes in the sign private key
pub static SECKEY_BYTES: uint = 64;
/// Bytes of padding used in each signed message
pub static SIGN_BYTES: uint = 64;

pub struct PublicKey ([u8, ..PUBKEY_BYTES]);
pub struct SecretKey ([u8, ..SECKEY_BYTES]);

/// Encapsulates the verification key and signed message.
pub struct SignedMsg {
    pub pk: PublicKey,
    pub signed: Vec<u8>
}

impl SignedMsg {
    /// Verify the validity of a given signed message against this public key.
    pub fn verify(&self) -> Option<Vec<u8>> {
        let PublicKey(pk) = self.pk;

        let mut msg: Vec<u8> = Vec::from_elem(self.signed.len(), 0u8);
        let mut msg_len: u64 = 0;

        unsafe {
            match crypto_sign_open(msg.as_mut_ptr(),
                                   &mut msg_len,
                                   self.signed.as_ptr(),
                                   self.signed.len() as u64,
                                   pk.as_ptr()) {
                -3 => None,
                0  => {
                    msg.set_len(msg_len as uint);
                    Some(msg)
                },
                _  => fail!("Impossible things happened")
            }
        }
    }
}

/// Matching secret / public keys.
pub struct Keypair {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl Keypair {
    /// Securely generate a random new signing keypair
    pub fn new() -> Keypair {
        let mut pk = [0u8, ..PUBKEY_BYTES];
        let mut sk = [0u8, ..SECKEY_BYTES];

        unsafe {
            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());
        }

        Keypair { pk: PublicKey(pk), sk: SecretKey(sk) }
    }

    /// Sign a given message with this keypair's secret key.
    pub fn sign(&self, msg: &[u8]) -> SignedMsg {
        let mut signed: Vec<u8> = Vec::from_elem(msg.len() + SIGN_BYTES, 0u8);
        let mut signed_len: u64 = 0;

        let SecretKey(sk) = self.sk;

        unsafe {
            crypto_sign(signed.as_mut_ptr(),
                        &mut signed_len,
                        msg.as_ptr(),
                        msg.len() as u64,
                        sk.as_ptr());

            signed.set_len(signed_len as uint);
        }

        SignedMsg { pk: self.pk, signed: signed }
    }
}


#[test]
fn test_sign_sanity() {
    for i in range(1 as uint, 16) {
        let keypair = Keypair::new();
        let msg = Vec::from_elem(i * 4, i as u8);

        let SecretKey(sk) = keypair.sk;
        let PublicKey(pk) = keypair.pk;

        println!("sk: {}\npk: {}", sk.as_slice(), pk.as_slice());

        let sig = keypair.sign(msg.as_slice());
        let desig = sig.verify();

        println!("msg:\t{}\nsig:\t{}\ndesig:\t{}", msg, sig.signed, desig);

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

    println!("msg:\t{}\nsig:\t{}\ndesig:\t{}", msg, sig.signed, desig);

    assert!(desig.is_none());
}
