#![feature(fs, path, process, core)]

use std::fs::PathExt;
use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env!("OUT_DIR");

    println!("cargo:rustc-flags=-L {} -l tweetnacl:static", out_dir);

    if Path::new(format!("{}/libtweetnacl.a", out_dir).as_slice()).exists() {
        println!("Nothing to do...");
        return;
    }

    Command::new("cc")
        .arg("src/lib/tweetnacl.c")
        .arg("-c")
        .arg("-fPIC")
        .arg("-Isrc/lib/")
        .arg("-o")
        .arg(format!("{}/tweetnacl.o", out_dir).as_slice())
        .status()
        .unwrap();

    Command::new("ar")
        .arg("rcs")
        .arg("libtweetnacl.a")
        .arg("tweetnacl.o")
        .current_dir(Path::new(out_dir))
        .status()
        .unwrap();
}
