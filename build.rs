use std::path::Path;
use std::process::Command;

fn main() {
    let out_dir = env!("OUT_DIR");

    Command::new("cc")
        .arg("src/lib/tweetnacl.c")
        .arg("-c")
        .arg("-fPIC")
        .arg("-Isrc/lib/")
        .arg("-o")
        .arg(format!("{}/tweetnacl.o", out_dir))
        .status()
        .unwrap();

    Command::new("ar")
        .arg("rcs")
        .arg("libtweetnacl.a")
        .arg("tweetnacl.o")
        .current_dir(Path::new(out_dir))
        .status()
        .unwrap();

    println!("cargo:rustc-link-search=native={}", out_dir);
    println!("cargo:rustc-link-lib=static=tweetnacl");
}
