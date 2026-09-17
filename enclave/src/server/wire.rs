//! The connection loop: read one framed request, dispatch it, write one
//! framed response, close. One request per connection, by design.

use std::io::{Read, Write};

use super::context::ServerContext;
use super::dispatch::dispatch;
use crate::error::Result;
use crate::framing;
use crate::proto::EnclaveRequest;

/// Handle a single connection: read one request, dispatch, write one response, close.
pub fn handle_connection(stream: impl Read + Write, ctx: &ServerContext) {
    if let Err(e) = process_connection(stream, ctx) {
        tracing::error!("connection error: {}", e);
    }
}

fn process_connection(mut stream: impl Read + Write, ctx: &ServerContext) -> Result<()> {
    tracing::debug!("reading request");
    let request: EnclaveRequest = framing::read_message(&mut stream)?;

    let response = dispatch(request, ctx);

    framing::write_message(&mut stream, &response)?;
    tracing::debug!("response written");
    Ok(())
}
