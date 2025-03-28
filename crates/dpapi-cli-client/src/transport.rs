use dpapi::client::{ConnectionOptions, WebAppAuth};
use dpapi::{Error, LocalStream, Result, Transport};
use dpapi_ws::prepare_ws_request_for_gateway_webapp;
use std::io::ErrorKind;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite;
use tokio_tungstenite::tungstenite::Bytes;
use url::Url;

pub trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin {}

impl<T> AsyncReadWrite for T where T: AsyncRead + AsyncWrite + Unpin + 'static {}

pub type ErasedReadWrite = Box<dyn AsyncReadWrite>;

pub struct TokioStream<S> {
    stream: S,
}

impl<S> TokioStream<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> LocalStream for TokioStream<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    async fn read_exact(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; length];
        self.read_buf(&mut buf).await?;
        Ok(buf)
    }

    async fn read_buf(&mut self, mut buf: &mut [u8]) -> Result<()> {
        use tokio::io::AsyncReadExt as _;

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
        use tokio::io::AsyncWriteExt as _;

        Box::pin(async {
            self.stream.write_all(buf).await?;
            self.stream.flush().await?;

            Ok(())
        })
        .await
    }
}

#[derive(Debug)]
pub struct NativeTransport;

impl NativeTransport {
    /// Connects to the RPC server via the Devolutions Gateway tunneled connection.
    async fn ws_connect(
        ws_request: &Url,
        web_app_auth: &WebAppAuth,
        destination: &SocketAddr,
    ) -> Result<TokioStream<ErasedReadWrite>> {
        let ws_request = prepare_ws_request_for_gateway_webapp(ws_request, web_app_auth, destination).await?;

        let (ws, _) = tokio_tungstenite::connect_async(ws_request.as_str())
            .await
            .map_err(|e| Error::TransportConnection(e.to_string()))?;

        {
            use futures_util::{future, SinkExt as _, StreamExt as _};

            let ws_compat = ws
                .filter_map(|item| {
                    future::ready(
                        item.map(|msg| match msg {
                            tungstenite::Message::Text(data) => {
                                Some(transport::WsReadMsg::Payload(data.as_bytes().to_vec()))
                            }
                            tungstenite::Message::Binary(data) => Some(transport::WsReadMsg::Payload(data.to_vec())),
                            tungstenite::Message::Ping(_) | tungstenite::Message::Pong(_) => None,
                            tungstenite::Message::Close(_) => Some(transport::WsReadMsg::Close),
                            tungstenite::Message::Frame(_) => {
                                unreachable!("raw frames are never returned when reading")
                            }
                        })
                        .transpose(),
                    )
                })
                .with(|item: Vec<u8>| {
                    future::ready(Ok::<_, tungstenite::Error>(tungstenite::Message::Binary(Bytes::from(
                        item,
                    ))))
                });

            Ok(TokioStream::new(
                Box::new(transport::WsStream::new(ws_compat)) as ErasedReadWrite
            ))
        }
    }
}

impl Transport for NativeTransport {
    type Stream = TokioStream<ErasedReadWrite>;

    async fn connect(connection_options: &ConnectionOptions) -> Result<Self::Stream> {
        match connection_options {
            ConnectionOptions::Tcp(addr) => {
                let stream = TokioStream::new(Box::new(TcpStream::connect(addr).await?) as ErasedReadWrite);
                Ok(stream)
            }
            ConnectionOptions::WebSocketTunnel {
                websocket_url,
                web_app_auth,
                destination,
            } => Self::ws_connect(websocket_url, web_app_auth, destination).await,
        }
    }
}
