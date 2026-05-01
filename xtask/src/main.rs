use std::env;
use std::process::Command;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let cmd = args.first().map(|s| s.as_str()).unwrap_or("help");

    match cmd {
        "build-ios" => build_ios(),
        "build-android" => build_android(),
        "build-desktop" => build_desktop(),
        "generate-headers" => generate_headers(),
        _ => {
            eprintln!("Usage: cargo xtask <command>");
            eprintln!("Commands:");
            eprintln!("  build-ios          Build xcframework for iOS/macOS");
            eprintln!("  build-android      Build .so for Android NDK targets");
            eprintln!("  build-desktop      Build shared/static lib for host platform");
            eprintln!("  generate-headers   Generate C header via cbindgen");
        }
    }
}

fn run(cmd: &str, args: &[&str]) {
    let status = Command::new(cmd)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to run {cmd}: {e}"));
    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn build_ios() {
    let targets = [
        "aarch64-apple-ios",
        "aarch64-apple-ios-sim",
        "x86_64-apple-ios",
        "aarch64-apple-darwin",
        "x86_64-apple-darwin",
    ];

    for target in &targets {
        eprintln!("Building pack-protocol-ffi for {target}...");
        run("cargo", &["build", "--release", "-p", "pack-protocol-ffi", "--target", target]);
    }

    eprintln!("iOS targets built. Create xcframework with xcodebuild -create-xcframework.");
    eprintln!("Libs at: target/<target>/release/libpack_protocol_ffi.a");
}

fn build_android() {
    let targets = [
        "aarch64-linux-android",
        "armv7-linux-androideabi",
        "x86_64-linux-android",
        "i686-linux-android",
    ];

    for target in &targets {
        eprintln!("Building pack-protocol-jni for {target}...");
        run("cargo", &["build", "--release", "-p", "pack-protocol-jni", "--target", target]);
    }

    eprintln!("Android targets built.");
    eprintln!("Libs at: target/<target>/release/libpack_protocol_jni.so");
    eprintln!("Copy into jniLibs/<abi>/ for AAR packaging.");
}

fn build_desktop() {
    eprintln!("Building pack-protocol-ffi for host...");
    run("cargo", &["build", "--release", "-p", "pack-protocol-ffi"]);
    eprintln!("Desktop build complete.");
}

fn generate_headers() {
    eprintln!("Generating C headers...");
    run("cargo", &["build", "-p", "pack-protocol-ffi"]);
    eprintln!("Header written to: crates/pack-protocol-ffi/include/pack_protocol.h");
}
