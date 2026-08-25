fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("linux") {
        // CUDA applications request DT_SONAME libcuda.so.1. The versioned
        // packaging filename is deliberately not the ABI identity.
        println!("cargo:rustc-link-arg=-Wl,-soname,libcuda.so.1");
        // CUDA Driver ABI generations are distinct exported C names such as
        // cuMemAlloc and cuMemAlloc_v2, not ELF symbol versions. Keep those
        // audited names unversioned: GNU ld's --default-symver is unsupported
        // by rust-lld and would invent a loader contract CUDA does not require.
    }
}
