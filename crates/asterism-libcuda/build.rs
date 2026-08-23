fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        // CUDA applications request DT_SONAME libcuda.so.1. The versioned
        // packaging filename is deliberately not the ABI identity.
        println!("cargo:rustc-link-arg=-Wl,-soname,libcuda.so.1");
        // Give exported driver entrypoints a default ELF symbol version.
        // This is supported by GNU ld and lld and lets both version-aware
        // and legacy loaders resolve the same audited entrypoints.
        println!("cargo:rustc-link-arg=-Wl,--default-symver");
    }
}
