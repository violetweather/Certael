fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        // Node provides the N-API symbols when the addon is loaded. macOS must
        // therefore defer resolving them until runtime instead of requiring a
        // Node library during the cdylib link step.
        println!("cargo:rustc-link-arg=-Wl,-undefined,dynamic_lookup");
    }
}
