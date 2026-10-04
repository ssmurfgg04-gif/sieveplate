// Full scan: report vmlinuz + modules.* files.
use std::io::Read;

fn main() {
    let path = std::env::args().nth(1).expect("path to .pkg.tar.zst");
    let f = std::fs::File::open(path).unwrap();
    let dz = zstd::Decoder::new(f).unwrap();
    let mut tar = tar::Archive::new(dz);
    let mut total = 0u64;
    for entry in tar.entries().unwrap() {
        let e = entry.unwrap();
        let p = e.path().unwrap().to_string_lossy().to_string();
        total += 1;
        if p.contains("vmlinuz") || (p.contains("modules.") && !p.contains(".ko")) {
            println!("{p}\t{}", e.header().size().unwrap_or(0));
        }
    }
    println!("TOTAL ENTRIES: {total}");
}
