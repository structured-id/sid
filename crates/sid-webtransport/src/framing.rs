// SPDX-License-Identifier: AGPL-3.0-only
use thiserror::Error;
use wtransport::RecvStream;
use wtransport::SendStream;

/// Maximum frame size: 4 MiB. Prevents OOM from malicious length prefix.
const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum FrameError {
    #[error("stream closed before frame header")]
    UnexpectedEof,
    #[error("frame too large: {0} bytes (max {MAX_FRAME_SIZE})")]
    TooLarge(u32),
    #[error("transport error: {0}")]
    Transport(#[from] wtransport::error::StreamReadError),
    #[error("transport write error: {0}")]
    Write(#[from] wtransport::error::StreamWriteError),
}

/// Read one length-prefixed frame from a WebTransport receive stream.
///
/// Wire format: `[4 bytes big-endian length][payload]`
pub async fn read_frame(stream: &mut RecvStream) -> Result<Vec<u8>, FrameError> {
    // Read 4-byte length prefix
    let mut len_buf = [0u8; 4];
    read_exact(stream, &mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf);

    if len > MAX_FRAME_SIZE {
        return Err(FrameError::TooLarge(len));
    }

    // Read payload
    let mut payload = vec![0u8; len as usize];
    read_exact(stream, &mut payload).await?;

    Ok(payload)
}

/// Write one length-prefixed frame to a WebTransport send stream.
pub async fn write_frame(stream: &mut SendStream, payload: &[u8]) -> Result<(), FrameError> {
    let len = payload.len() as u32;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(payload).await?;
    Ok(())
}

/// Read exactly `buf.len()` bytes from the stream.
async fn read_exact(stream: &mut RecvStream, buf: &mut [u8]) -> Result<(), FrameError> {
    let mut offset = 0;
    while offset < buf.len() {
        match stream.read(&mut buf[offset..]).await? {
            Some(n) => offset += n,
            None => return Err(FrameError::UnexpectedEof),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_max_frame_guard() {
        // Ensure the constant is reasonable
        assert_eq!(MAX_FRAME_SIZE, 4 * 1024 * 1024);
    }
}
