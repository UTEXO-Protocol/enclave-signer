fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gRPC service — generates tonic server trait + prost message types.
    // parentadapter.proto imports signer/signer.proto, so we include ../proto/ as root.
    let out_dir = std::path::PathBuf::from(std::env::var("OUT_DIR")?);
    tonic_build::configure()
        .file_descriptor_set_path(out_dir.join("tricorn_descriptor.bin"))
        .compile_protos(&["../proto/parentadapter.proto"], &["../proto/"])?;

    // Enclave wire protocol — prost-only (no gRPC, just message types)
    prost_build::compile_protos(
        &["../proto/enclave.proto", "../proto/enriched-payload.proto"],
        &["../proto/"],
    )?;

    Ok(())
}
