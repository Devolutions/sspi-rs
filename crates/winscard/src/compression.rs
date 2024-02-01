use alloc::format;
use alloc::vec::Vec;

use flate2::{Compress, Compression, FlushCompress, Status};

use crate::{Error, ErrorKind, WinScardResult};

// This function compresses the user-der-encoded certificate using the Zlib algorithm from the flate2 crate.
// We need to compress the certificate before storing it in the smart card cache.
// The resulting array slice corresponds to the compressed certificate in the buffer.
pub fn compress_cert<'c>(cert: &'_ [u8], buff: &'c mut Vec<u8>) -> WinScardResult<&'c [u8]> {
    let mut data_to_compress = cert;
    let mut total_written = 0;

    let mut compressor = Compress::new(Compression::fast(), /* zlib header */ true);

    loop {
        let read_before = compressor.total_in() as usize;
        let written_before = compressor.total_out() as usize;

        let status = compressor
            .compress(data_to_compress, &mut buff[total_written..], FlushCompress::Finish)
            .map_err(|err| {
                Error::new(
                    ErrorKind::InternalError,
                    format!("can not compress sc certificate: {:?}", err),
                )
            })?;

        let read_after = compressor.total_in() as usize;
        let written_after = compressor.total_out() as usize;

        let read_len = read_after - read_before;
        let written_len = written_after - written_before;

        total_written += written_len;
        data_to_compress = &data_to_compress[read_len..];

        match status {
            Status::BufError => {
                // This case should never happen because usually, buff len is equal to the uncompressed data len.
                // But we check it just in case.
                let len = buff.len();
                buff.resize(len * 2, 0);
            }
            Status::StreamEnd => break,
            Status::Ok => {}
        }
    }

    Ok(&buff[0..total_written])
}
