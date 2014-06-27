use bindings::*;

static PUBKEY_BYTES: uint = 32;
static SECKEY_BYTES: uint = 64;
static SIGN_BYTES: uint = 64;

pub struct SecretKey ([u8, ..SECKEY_BYTES]);
pub struct PublicKey ([u8, ..PUBKEY_BYTES]);

pub struct SignKey {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl SignKey {
    pub fn new() -> SignKey {
        unsafe {
            let mut pk = [0u8, ..PUBKEY_BYTES];
            let mut sk = [0u8, ..SECKEY_BYTES];

            crypto_sign_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            SignKey { pk: PublicKey(pk), sk: SecretKey(sk) }
        }

    }
}

pub struct Signer {
    pub keypair: SignKey
}

impl Signer {
    pub fn new() -> Signer {
        Signer { keypair: SignKey::new() }
    }

    pub fn new_with_key(key: SignKey) -> Signer {
        Signer { keypair: key }
    }

    pub fn sign(&self, msg: &[u8]) -> Vec<u8> {
        unsafe {
            let mut signed: Vec<u8> = Vec::from_elem(msg.len() + SIGN_BYTES, 0u8);
            let mut signed_len: u64 = 0;

            let SecretKey(sk) = self.keypair.sk;

            crypto_sign(signed.as_mut_ptr(),
                        &mut signed_len,
                        msg.as_ptr(),
                        msg.len() as u64,
                        sk.as_ptr());

            signed.set_len(signed_len as uint);
            signed
        }
    }

    pub fn verify(&self, smsg: &[u8], pk: PublicKey) -> Option<Vec<u8>> {
        unsafe {
            let mut msg: Vec<u8> = Vec::from_elem(smsg.len(), 0u8);
            let mut msg_len: u64 = 0;

            let PublicKey(pk) = pk;

            match crypto_sign_open(msg.as_mut_ptr(),
                                   &mut msg_len,
                                   smsg.as_ptr(),
                                   smsg.len() as u64,
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


#[test]
fn test_sign_sanity() {
    for i in range(1 as uint, 16) {
        let signer = Signer::new();
        let msg = Vec::from_elem(i * 4, i as u8);

        let SecretKey(sk) = signer.keypair.sk;
        let PublicKey(pk) = signer.keypair.pk;

        println!("sk: {}\npk: {}", sk.as_slice(), pk.as_slice());

        let sig = signer.sign(msg.as_slice());
        let desig = signer.verify(sig.as_slice(), signer.keypair.pk);

        println!("msg:\t{}\nsig:\t{}\ndesig:\t{}", msg, sig, desig);

        assert!(desig.is_some());
        assert!(desig.unwrap() == msg);
    }
}
