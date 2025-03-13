use bytes::{BufMut, BytesMut};
use std::io::{ErrorKind as IoErrorKind, Read, Write};
use std::net::TcpStream;
use tungstenite::stream::MaybeTlsStream;
use tungstenite::{Bytes, Message, WebSocket};

use crate::{Error, Result};

pub trait ReadWrite: Read + Write {}

impl<T> ReadWrite for T where T: Read + Write + 'static {}

pub type Stream = Box<dyn ReadWrite>;

/// A wrapper around stream that provides convenient read and write functions.
pub struct StreamWrapper<S> {
    stream: S,
}

impl<S> StreamWrapper<S> {
    pub fn new(stream: S) -> Self {
        Self { stream }
    }
}

impl<S> StreamWrapper<S>
where
    S: Read,
{
    /// Reads an exact number of bytes from the stream and returns buffer as `Vec`.
    pub fn read_exact(&mut self, length: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0; length];
        self.read_buf(&mut buf)?;
        Ok(buf)
    }

    /// Read a data from the stream until it fully fills the buffer.
    pub fn read_buf(&mut self, mut buf: &mut [u8]) -> Result<()> {
        while !buf.is_empty() {
            let bytes_read = self.stream.read(buf)?;
            buf = &mut buf[bytes_read..];

            if bytes_read == 0 {
                return Err(Error::Io(IoErrorKind::UnexpectedEof.into()));
            }
        }

        Ok(())
    }
}

impl<S> StreamWrapper<S>
where
    S: Write,
{
    /// Writes an entire buffer and flushes the stream.
    pub fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        self.stream.write_all(buf)?;
        self.stream.flush()?;

        Ok(())
    }
}

/// A WebSocket stream wrapper that implements the `Read` and `Write` traits from `std`.
pub struct WebSocketWrapper {
    inner: WebSocket<MaybeTlsStream<TcpStream>>,
    buf: BytesMut,
}

impl WebSocketWrapper {
    pub fn new(inner: WebSocket<MaybeTlsStream<TcpStream>>) -> Self {
        Self {
            inner,
            buf: BytesMut::new(),
        }
    }
}

impl Read for WebSocketWrapper {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.buf.len() >= buf.len() {
                buf.copy_from_slice(&self.buf.split_to(buf.len()));
                return Ok(buf.len());
            }

            let message = self
                .inner
                .read()
                .map_err(|err| std::io::Error::new(std::io::ErrorKind::Other, err.to_string()))?;

            match message {
                Message::Binary(data) => {
                    self.buf.put(data);
                }
                Message::Text(data) => self.buf.put(data.as_ref()),
                _ => return Ok(0),
            }
        }
    }
}

impl Write for WebSocketWrapper {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.inner.send(Message::Binary(Bytes::from(buf.to_vec()))).unwrap();
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
