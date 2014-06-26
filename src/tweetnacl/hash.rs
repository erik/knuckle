use bindings::*;

static HASH_BYTES: uint = 64;


pub fn hash(msg: &[u8]) -> Vec<u8> {
    unsafe {
        let mut hash: Vec<u8> = Vec::with_capacity(HASH_BYTES);

        crypto_hash(hash.as_mut_ptr(), msg.as_ptr(), msg.len() as u64);

        hash
    }
}
