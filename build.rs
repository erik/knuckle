use std::io::fs::PathExtensions;
use std::path::Path;
use std::io::Command;


fn main() {
    let out_dir = env!("OUT_DIR");

    println!("cargo:rustc-flags=-L {} -l tweetnacl:static", out_dir);

    if Path::new(format!("{}/libtweetnacl.a", out_dir)).exists() {
        println!("Nothing to do...");
        return;
    }

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
        .cwd(&Path::new(out_dir))
        .status()
        .unwrap();
}
