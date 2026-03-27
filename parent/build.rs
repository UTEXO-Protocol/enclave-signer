fn main() -> Result<(), Box<dyn std::error::Error>> {
    // gRPC service — generates tonic server trait + prost message types
    tonic_build::compile_protos("../proto/parentadapter.proto")?;

    // Enclave wire protocol — prost-only (no gRPC, just message types)
    prost_build::compile_protos(
        &["../proto/enclave.proto", "../proto/enriched-payload.proto"],
        &["../proto/"],
    )?;

    Ok(())
}
