use bindings::*;

static ZERO_BYTES: uint = 32;
static NONCE_BYTES: uint = 24;
static PUBLICKEY_BYTES: uint = 32;
static SECRETKEY_BYTES: uint = 32;

pub struct CryptoBox {
    pub keypair: Keypair,
}

pub struct SecretKey ([u8, ..SECRETKEY_BYTES]);
pub struct PublicKey ([u8, ..PUBLICKEY_BYTES]);

pub struct Keypair {
    pub pk: PublicKey,
    pub sk: SecretKey
}

impl Keypair {
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
    pub fn new() -> CryptoBox {
        CryptoBox { keypair: Keypair::new() }
    }

    pub fn new_with_key(key: Keypair) -> CryptoBox {
        CryptoBox { keypair: key }
    }

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
