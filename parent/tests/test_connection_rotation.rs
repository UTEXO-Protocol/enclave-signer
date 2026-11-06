//! Tests connection rotation and drain deadlines over TCP.

use std::{
    convert::Infallible,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Duration,
};

use http::{Request, Response};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::{mpsc, Notify},
    time::timeout,
};
use tokio_stream::StreamExt;
use tonic::{
    body::Body,
    transport::{
        server::{Connected, TcpConnectInfo},
        Channel, Endpoint, Server,
    },
};
use tower::ServiceExt;
use utexo_bridge_parent::transport_security::{LimitedIncoming, LimitedSocket};

struct ObservedSocket {
    stream: LimitedSocket,
    peer: SocketAddr,
    closed: mpsc::UnboundedSender<SocketAddr>,
}

impl Drop for ObservedSocket {
    fn drop(&mut self) {
        let _ = self.closed.send(self.peer);
    }
}

impl Connected for ObservedSocket {
    type ConnectInfo = TcpConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.stream.connect_info()
    }
}

impl AsyncRead for ObservedSocket {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for ObservedSocket {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

async fn server(
    age: Duration,
    grace: Option<Duration>,
    release: Arc<Notify>,
) -> (
    Channel,
    mpsc::UnboundedReceiver<SocketAddr>,
    mpsc::UnboundedReceiver<SocketAddr>,
) {
    let mut incoming = LimitedIncoming::bind("127.0.0.1:0".parse().unwrap(), 8)
        .await
        .unwrap();
    let addr = incoming.local_addr().unwrap();
    if let Some(grace) = grace {
        incoming = incoming.with_max_connection_duration(age + grace);
    }
    let (seen_tx, seen) = mpsc::unbounded_channel();
    let (closed_tx, closed) = mpsc::unbounded_channel();
    let incoming = incoming.map(move |stream| {
        stream.map(|stream| {
            let peer = stream.connect_info().remote_addr().unwrap();
            ObservedSocket {
                stream,
                peer,
                closed: closed_tx.clone(),
            }
        })
    });
    let service = tower::service_fn(move |req: Request<Body>| {
        let release = release.clone();
        let peer = req
            .extensions()
            .get::<TcpConnectInfo>()
            .unwrap()
            .remote_addr()
            .unwrap();
        seen_tx.send(peer).unwrap();

        async move {
            if req.uri().path() == "/rotation/slow" {
                release.notified().await;
            }
            Ok::<_, Infallible>(
                Response::builder()
                    .header("content-type", "application/grpc")
                    .header("grpc-status", "0")
                    .body(Body::empty())
                    .unwrap(),
            )
        }
    });
    let server = Server::builder().max_connection_age(age);
    tokio::spawn(async move {
        server.serve_with_incoming(service, incoming).await.unwrap();
    });

    let channel = Endpoint::from_shared(format!("http://{addr}"))
        .unwrap()
        .connect()
        .await
        .unwrap();
    (channel, seen, closed)
}

#[tokio::test]
async fn connection_deadline_starts_after_acceptance_and_cannot_be_reset() {
    let duration = Duration::from_millis(200);
    let mut incoming = LimitedIncoming::bind("127.0.0.1:0".parse().unwrap(), 1)
        .await
        .unwrap()
        .with_max_connection_duration(duration);
    let _peer = TcpStream::connect(incoming.local_addr().unwrap())
        .await
        .unwrap();
    let mut socket = incoming.next().await.unwrap().unwrap();
    let mut byte = [0];

    // TLS handshakes read the socket before tonic requests connection metadata.
    assert!(timeout(duration * 2, socket.read(&mut byte)).await.is_err());
    socket.connect_info();
    tokio::time::sleep(duration * 2).await;
    socket.connect_info();
    let error = timeout(duration / 2, socket.read(&mut byte))
        .await
        .expect("repeated metadata access must not extend the deadline")
        .unwrap_err();
    assert_eq!(error.kind(), std::io::ErrorKind::TimedOut);
}

fn request(path: &'static str) -> Request<Body> {
    Request::builder().uri(path).body(Body::empty()).unwrap()
}

#[tokio::test]
async fn rotation_opens_a_new_socket_while_the_original_rpc_finishes() {
    let release = Arc::new(Notify::new());
    let (channel, mut seen, mut closed) = server(
        Duration::from_millis(300),
        Some(Duration::from_secs(3)),
        release.clone(),
    )
    .await;
    let first = tokio::spawn(channel.clone().oneshot(request("/rotation/slow")));
    let old_peer = timeout(Duration::from_secs(2), seen.recv())
        .await
        .unwrap()
        .unwrap();

    tokio::time::sleep(Duration::from_millis(500)).await;
    timeout(Duration::from_secs(2), async {
        // tonic's Channel can return an error for the first call after GOAWAY.
        // Retry the probe, but require the pending RPC to finish without a retry.
        if channel
            .clone()
            .oneshot(request("/rotation/fast"))
            .await
            .is_err()
        {
            channel
                .clone()
                .oneshot(request("/rotation/fast"))
                .await
                .unwrap();
        }
    })
    .await
    .unwrap();
    let new_peer = seen.recv().await.unwrap();

    assert_ne!(
        old_peer, new_peer,
        "GOAWAY must move new RPCs to a new socket before the grace expires"
    );
    assert!(
        !first.is_finished(),
        "the old RPC must still be waiting on its original socket"
    );
    assert!(
        closed.try_recv().is_err(),
        "the old socket must remain open while its RPC is active"
    );

    release.notify_one();
    timeout(Duration::from_secs(2), first)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), closed.recv())
            .await
            .unwrap()
            .unwrap(),
        old_peer
    );
}

#[tokio::test]
async fn an_idle_connection_closes_at_its_age_without_waiting_for_grace() {
    let (channel, mut seen, mut closed) = server(
        Duration::from_millis(300),
        Some(Duration::from_secs(3)),
        Arc::new(Notify::new()),
    )
    .await;
    channel
        .clone()
        .oneshot(request("/rotation/fast"))
        .await
        .unwrap();
    let peer = seen.recv().await.unwrap();

    assert_eq!(
        timeout(Duration::from_secs(2), closed.recv())
            .await
            .unwrap()
            .unwrap(),
        peer
    );
}

#[tokio::test]
async fn grace_force_closes_a_stream_that_does_not_finish() {
    let (channel, mut seen, mut closed) = server(
        Duration::from_millis(200),
        Some(Duration::from_millis(300)),
        Arc::new(Notify::new()),
    )
    .await;
    let call = tokio::spawn(channel.oneshot(request("/rotation/slow")));
    let peer = seen.recv().await.unwrap();

    let result = timeout(Duration::from_secs(2), call)
        .await
        .unwrap()
        .unwrap();
    assert!(
        result.is_err(),
        "the grace deadline must terminate the stuck stream"
    );
    assert_eq!(
        timeout(Duration::from_secs(2), closed.recv())
            .await
            .unwrap()
            .unwrap(),
        peer
    );
}

#[tokio::test]
async fn an_age_without_a_grace_keeps_the_original_stream_alive() {
    let release = Arc::new(Notify::new());
    let (channel, mut seen, _) = server(Duration::from_millis(200), None, release.clone()).await;
    let call = tokio::spawn(channel.oneshot(request("/rotation/slow")));
    seen.recv().await.unwrap();

    tokio::time::sleep(Duration::from_millis(400)).await;
    release.notify_one();
    timeout(Duration::from_secs(2), call)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
