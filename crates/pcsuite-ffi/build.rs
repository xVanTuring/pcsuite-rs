// Generates the Swift + C glue for the `#[swift_bridge::bridge]` module in src/lib.rs.
// Output lands in `generated/` (checked into the repo so Xcode can reference it
// without running cargo first):
//   generated/SwiftBridgeCore.{swift,h}
//   generated/pcsuite-ffi/pcsuite-ffi.{swift,h}
use std::path::PathBuf;

fn main() {
    let bridges = vec!["src/lib.rs"];
    for path in &bridges {
        println!("cargo:rerun-if-changed={path}");
    }
    let out_dir = PathBuf::from("generated");
    swift_bridge_build::parse_bridges(bridges).write_all_concatenated(out_dir, "pcsuite-ffi");
}
