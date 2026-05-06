use std::path::PathBuf;

fn main() {
    let out_dir = PathBuf::from("./generated");

    swift_bridge_build::parse_bridges(vec![PathBuf::from("src/lib.rs")])
        .write_all_concatenated(out_dir, env!("CARGO_PKG_NAME"));
}
