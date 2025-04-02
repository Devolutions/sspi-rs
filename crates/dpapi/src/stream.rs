use crate::{ConnectionOptions, Result};

/// Represents a transport for communicating with the target server.
pub trait Transport {
    type Stream: LocalStream;

    /// Connects to the target server.
    fn connect(connection_options: &ConnectionOptions) -> impl std::future::Future<Output = Result<Self::Stream>>;
}

pub trait LocalStream {
    /// Reads an exact number of bytes from the stream and returns buffer as `Vec`.
    fn read_exact(&mut self, length: usize) -> impl std::future::Future<Output = Result<Vec<u8>>>;

    /// Read a data from the stream until it fully fills the buffer.
    fn read_buf(&mut self, buf: &mut [u8]) -> impl std::future::Future<Output = Result<()>>;

    /// Writes an entire buffer and flushes the stream.
    fn write_all(&mut self, buf: &[u8]) -> impl std::future::Future<Output = Result<()>>;
}
