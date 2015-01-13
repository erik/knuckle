//!
//! This module contains any other useful utilities which don't fit
//! elsewhere in the library.

use bindings::randombytes;

use std::iter::repeat;

/// Return a vector of the specified length containing securely
/// generated random bytes.
pub fn random_bytes(len: u64) -> Vec<u8> {
    let mut vec: Vec<u8> = repeat(0u8).take(len as usize).collect();

    unsafe {
        randombytes(vec.as_mut_ptr(), len);
    }

    vec
}


#[test]
fn test_randombytes_sanity() {
    let v1 = random_bytes(16);
    let v2 = random_bytes(16);

    assert!(v1 != v2);
    assert!(v1 != [0u8; 16].to_vec());
}
