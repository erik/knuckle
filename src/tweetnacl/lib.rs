#![crate_id = "tweetnacl#tweetnacl"]
#![crate_type = "lib"]
#![desc = "TODO: write me"]
#![comment = "TODO: write me"]
#![license = "mit"]

#![feature(globs)]
//#![deny(missing_doc)]

//! Documentation goes here.

extern crate libc;

pub mod cryptobox;
pub mod secretbox;
pub mod stream;
pub mod sign;
pub mod hash;
pub mod auth;

#[allow(dead_code)]
mod bindings;
