fn main() {
    // The release asset this build updates itself from.
    println!(
        "cargo:rustc-env=TUYO_SIGNER_TARGET={}",
        std::env::var("TARGET").unwrap()
    );
    println!("cargo:rerun-if-env-changed=TUYO_SIGNER_UPDATE_PUBLIC_KEY");
    println!("cargo:rerun-if-env-changed=TUYO_SIGNER_APPLE_TEAM_ID");
}
