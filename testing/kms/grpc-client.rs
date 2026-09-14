//! Testing-branch-only driver for the real parent gRPC process.
//! Signature verification is performed by the enclave TCP E2E client; the
//! runner compares that verified signature with the result of this route.

#[cfg(not(debug_assertions))]
compile_error!("kms-e2e-grpc-client is local testing tooling and must not be built in release");

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use tonic::transport::Endpoint;
use utexo_bridge_parent::enriched;
use utexo_bridge_parent::grpc_proto::parent_service_client::ParentServiceClient;
use utexo_bridge_parent::grpc_proto::{sign_request, SignRequest};
use utexo_bridge_parent::signer::{DataType, SignRequest as CommonSignRequest};

#[derive(Parser)]
struct Cli {
    #[arg(long, default_value = "http://127.0.0.1:50051")]
    addr: String,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Sign the provided unsigned EIP-1559 transaction through the parent.
    Sign { unsigned_tx: String },
}

async fn run(cli: Cli) -> Result<Vec<u8>> {
    // Local testing must never accidentally target a deployed signer.
    let socket = cli
        .addr
        .strip_prefix("http://")
        .context("local E2E gRPC address must use http://127.0.0.1:PORT")?
        .trim_end_matches('/')
        .parse::<std::net::SocketAddr>()
        .context("invalid local gRPC socket address")?;
    if !socket.ip().is_loopback() {
        bail!("the local E2E gRPC driver requires a loopback address");
    }
    let endpoint = Endpoint::from_shared(cli.addr)?
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(90));
    let mut client = ParentServiceClient::new(endpoint.connect().await?);
    match cli.command {
        Command::Sign { unsigned_tx } => {
            let unsigned_tx = hex::decode(unsigned_tx.strip_prefix("0x").unwrap_or(&unsigned_tx))?;
            let response = client
                .sign(SignRequest {
                    common: Some(CommonSignRequest {
                        src_network_id: 0,
                        dst_network_id: 1,
                        data_type: DataType::EvmGasTx as i32,
                    }),
                    source: None,
                    data: Some(sign_request::Data::EvmData(enriched::EnrichedEvmPayload {
                        unsigned_tx,
                        chain_id: 1,
                        ..Default::default()
                    })),
                })
                .await?
                .into_inner();
            if response.signer_network_id != 1 || response.signature.len() != 65 {
                bail!("unexpected parent gRPC signature response");
            }
            Ok(response.signature)
        }
    }
}

#[tokio::main]
async fn main() {
    match run(Cli::parse()).await {
        Ok(signature) => println!(
            "{{\"ok\":true,\"signature\":\"{}\"}}",
            hex::encode(signature)
        ),
        Err(error) => {
            eprintln!("local gRPC client: {error:#}");
            println!("{{\"ok\":false,\"error\":\"grpc_client_failed\"}}");
            std::process::exit(1);
        }
    }
}
