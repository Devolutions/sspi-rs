use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::Duration;

use dpapi::client::{ConnectionOptions, WebAppAuth};
use dpapi::{Error, LocalStream, Result, Transport};
use dpapi_ws::prepare_ws_request_for_gateway_webapp;
use futures_util::{AsyncRead, AsyncWrite};
use gloo_net::websocket;
use gloo_net::websocket::futures::WebSocket;
use url::Url;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + 'static {}

type ErasedReadWrite = Box<dyn AsyncReadWrite>;

pub struct FuturesStream<S> {
    stream: S,
}

impl<S> FuturesStream<S> {
    fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> LocalStream for FuturesStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; length];
        self.read_buf(&mut buf).await?;
        Ok(buf)
    }

    async fn read_buf(&mut self, mut buf: &mut [u8]) -> Result<()> {
        use futures_util::AsyncReadExt as _;

        while !buf.is_empty() {
            let bytes_read = Box::pin(async { self.stream.read(buf).await }).await?;
            buf = &mut buf[bytes_read..];

            if bytes_read == 0 {
                return Err(Error::Io(ErrorKind::UnexpectedEof.into()));
            }
        }

        Ok(())
    }

    async fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        use futures_util::AsyncWriteExt as _;

        Box::pin(async {
            self.stream.write_all(buf).await?;
            self.stream.flush().await?;

            Ok(())
        })
        .await
    }
}

#[derive(Debug)]
pub struct WasmTransport;

impl WasmTransport {
    /// Connects to the RPC server via the Devolutions Gateway tunneled connection.
    async fn ws_connect(
        ws_request: &Url,
        web_app_auth: &WebAppAuth,
        destination: &SocketAddr,
    ) -> Result<FuturesStream<ErasedReadWrite>> {
        let ws_request = prepare_ws_request_for_gateway_webapp(ws_request, web_app_auth, destination).await?;

        let ws = WebSocket::open(ws_request.as_str()).map_err(|e| Error::TransportConnection(e.to_string()))?;

        // NOTE: ideally, when the WebSocket can’t be opened, the above call should fail with details on why is that
        // (e.g., the proxy hostname could not be resolved, proxy service is not running), but errors are never
        // bubbled up in practice, so instead we poll the WebSocket state until we know its connected (i.e., the
        // WebSocket handshake is a success and user data can be exchanged).
        loop {
            match ws.state() {
                websocket::State::Closing | websocket::State::Closed => {
                    return Err(Error::TransportConnection(format!(
                        "Failed to connect to {ws_request} (WebSocket is `{:?}`)",
                        ws.state()
                    )));
                }
                websocket::State::Connecting => {
                    trace!("WebSocket is connecting to proxy at {ws_request}...");
                    gloo_timers::future::sleep(Duration::from_millis(50)).await;
                }
                websocket::State::Open => {
                    debug!("WebSocket connected to {ws_request} with success");
                    break;
                }
            }
        }

        Ok(FuturesStream::new(Box::new(ws) as ErasedReadWrite))
    }
}

impl Transport for WasmTransport {
    type Stream = FuturesStream<ErasedReadWrite>;

    async fn connect(connection_options: &ConnectionOptions) -> Result<Self::Stream> {
        match connection_options {
            ConnectionOptions::Tcp(_) => Err(Error::UnsupportedTransport(
                "tcp is not supported for wasm32 target".to_string(),
            )),
            ConnectionOptions::WebSocketTunnel {
                websocket_url,
                web_app_auth,
                destination,
            } => Self::ws_connect(websocket_url, web_app_auth, destination).await,
        }
    }
}
