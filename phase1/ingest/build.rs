fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    // Protobuf generation needs a compiler but should not require a system package.
    unsafe {
        std::env::set_var("PROTOC", protoc);
    }
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(&["../proto/telemetry.proto"], &["../proto"])?;
    println!("cargo:rerun-if-changed=../proto/telemetry.proto");
    Ok(())
}
