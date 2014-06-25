#![crate_id = ""]
#![feature(globs)]
//#![deny(missing_doc)]

//! Documentation goes here.

extern crate libc;
extern crate rlibc;

pub mod cryptobox;
pub mod secretbox;

mod bindings;
