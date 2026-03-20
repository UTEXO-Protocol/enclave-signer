fn main() -> Result<(), Box<dyn std::error::Error>> {
    prost_build::compile_protos(
        &[
            "../proto/enclave.proto",
            "../proto/enriched-payload.proto",
        ],
        &["../proto/"],
    )?;
    Ok(())
}
