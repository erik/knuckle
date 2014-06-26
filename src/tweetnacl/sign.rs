use bindings::*;

static PUBKEY_BYTES: uint = 32;
static SECKEY_BYTES: uint = 64;
static SIGN_BYTES: uint = 64;

pub type SecretKey = [u8, ..SECKEY_BYTES];
pub type PublicKey = [u8, ..PUBKEY_BYTES];

pub struct SignKey {
    pub sk: SecretKey,
    pub pk: PublicKey
}

impl SignKey {
    pub fn new() -> SignKey {
        unsafe {
            let mut pk = [0u8, ..PUBKEY_BYTES];
            let mut sk = [0u8, ..SECKEY_BYTES];

            crypto_box_keypair(pk.as_mut_ptr(), sk.as_mut_ptr());

            SignKey { pk: pk, sk: sk }
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
            let mut signed: Vec<u8> = Vec::with_capacity(msg.len() + SIGN_BYTES);
            let mut signed_len: u64 = 0;

            crypto_sign(signed.as_mut_ptr(),
                        &mut signed_len,
                        msg.as_ptr(),
                        msg.len() as u64,
                        self.keypair.sk.as_ptr());

            signed
        }
    }

    pub fn verify(&self, smsg: &[u8], pk: PublicKey) -> Option<Vec<u8>> {
        unsafe {
            let mut msg: Vec<u8> = Vec::with_capacity(smsg.len());
            let mut msg_len: u64 = 0;

            match crypto_sign_open(msg.as_mut_ptr(),
                                   &mut msg_len,
                                   smsg.as_ptr(),
                                   smsg.len() as u64,
                                   pk.as_ptr()) {
                -1 => None,
                0  => Some(msg),
                _  => fail!("Impossible things happened")
            }
        }
    }
}
