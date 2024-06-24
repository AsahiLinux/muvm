use bytes::Bytes;
use futures_util::sink::SinkExt as _;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_stream::StreamExt as _;
use tokio_util::codec::{Framed, LengthDelimitedCodec};

use crate::error::Result;
use crate::request::Request;
use crate::response::Response;

pub struct Server<T> {
    transport: Framed<T, LengthDelimitedCodec>,
}

impl<T> Server<T>
where
    T: AsyncRead + AsyncWrite,
{
    pub fn new(io: T) -> Self {
        Self {
            transport: Framed::new(io, LengthDelimitedCodec::new()),
        }
    }
}

impl<T> Server<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub async fn read_request(&mut self) -> Result<Request> {
        let frame = self
            .transport
            .next()
            .await
            .ok_or_else(|| crate::Error::Io(std::io::Error::other("unexpected end of stream")))?
            .map_err(crate::Error::Io)?;
        let request = serde_json::from_slice(&frame[..]).map_err(crate::Error::Json)?;
        Ok(request)
    }

    pub async fn write_response(&mut self, response: Response) -> Result<()> {
        let frame = Bytes::from(format!("{response}"));
        self.transport.send(frame).await.map_err(crate::Error::Io)?;
        Ok(())
    }
}
