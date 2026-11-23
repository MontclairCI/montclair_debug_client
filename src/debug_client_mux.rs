use http::Request;
use http::StatusCode;
use http_body_util::BodyExt;
use montclair_protocol::channel::FnChannelAcceptor;
use tokio_util::sync::CancellationToken;

use montclair_api::id::AccountId;
use montclair_api::id::DebugSessionId;
use montclair_api::id::UserId;
use montclair_protocol::http::DebugClientResponse;
use montclair_protocol::http::PROTOCOL_MONTCLAIR_DEBUG;
use montclair_protocol::mux::Mux;
use montclair_protocol::mux::MuxHandle;
use montclair_tracing::TError;

#[derive(Debug, thiserror::Error)]
#[error("DebugSubcommandMuxHandleError: {0}")]
struct DebugSubcommandMuxHandleError(String);

#[tracing::instrument(skip_all)]
pub async fn debug_client_mux_handle(
    client_shutdown: CancellationToken,
    server_domain: &str,
    user_id: &UserId,
    secret: &str,
    account_id: &AccountId,
    debug_session_id: &DebugSessionId,
) -> Result<MuxHandle, TError> {
    eprintln!("{server_domain}");
    let server_stream = {
        let stream = tokio::net::TcpStream::connect(server_domain).await?;
        stream.set_nodelay(true)?;
        hyper_util::rt::TokioIo::new(stream)
    };

    let (mut send_request, connection) =
        hyper::client::conn::http1::handshake(server_stream).await?;

    tokio::spawn(async move {
        if let Err(e) = connection.with_upgrades().await {
            eprintln!("Connection error: {:?}", e);
        }
    });

    let request = Request::builder()
        .method("POST")
        .uri("/cli_connect_debug_client")
        .header(http::header::HOST, server_domain)
        .header(http::header::CONNECTION, "Upgrade")
        .header(http::header::UPGRADE, PROTOCOL_MONTCLAIR_DEBUG)
        .header("x-montclair-user-id", user_id.as_str())
        .header("x-montclair-personal-access-token-secret", secret)
        .header("x-montclair-account-id", account_id.as_str())
        .header("x-montclair-debug-session-id", debug_session_id.as_str())
        .body(http_body_util::Empty::<bytes::Bytes>::new())?;

    let response = send_request.send_request(request).await?;

    match response.status() {
        StatusCode::SWITCHING_PROTOCOLS => {}
        StatusCode::BAD_REQUEST => {
            let body_bytes = response.collect().await?.to_bytes();
            let e = serde_json::from_slice::<DebugClientResponse>(&body_bytes)?.error;
            let e = DebugSubcommandMuxHandleError(format!("Client error: {e}"));
            return Err(e.into());
        }
        StatusCode::INTERNAL_SERVER_ERROR => {
            let body_bytes = response.collect().await?.to_bytes();
            let e = serde_json::from_slice::<DebugClientResponse>(&body_bytes)?.error;
            let e = DebugSubcommandMuxHandleError(format!("Server error: {e}"));
            return Err(e.into());
        }
        code => {
            let e = DebugSubcommandMuxHandleError(format!("Unexpected status code: {code}"));
            return Err(e.into());
        }
    }

    let (read_half, write_half) = {
        let hyper_upgraded_stream = hyper::upgrade::on(response).await?;
        let tokio_stream = hyper_util::rt::TokioIo::new(hyper_upgraded_stream);
        tokio::io::split(tokio_stream)
    };

    let channel_acceptor = FnChannelAcceptor::new(move |channel_id, channel_type| {
        panic!(
            "Client received request to open channel [{}] of type {:?}",
            channel_id, channel_type
        );
    });

    let (_join_handle, mux_handle) =
        Mux::spawn(read_half, write_half, channel_acceptor, client_shutdown);

    Ok(mux_handle)
}
