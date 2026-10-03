//! hyper's I/O traits over tokio streams (hyper-util would bring a crate
//! for these forty lines).

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub struct Io<T>(pub T);

impl<T: AsyncRead + Unpin> hyper::rt::Read for Io<T> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, mut buf: hyper::rt::ReadBufCursor<'_>) -> Poll<io::Result<()>> {
        // SAFETY: tokio's ReadBuf only writes initialised bytes into the
        // uninitialised tail, and we advance by exactly what was filled.
        let filled = unsafe {
            let mut rb = ReadBuf::uninit(buf.as_mut());
            match Pin::new(&mut self.0).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) => rb.filled().len(),
                other => return other,
            }
        };
        unsafe { buf.advance(filled) };
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite + Unpin> hyper::rt::Write for Io<T> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}
