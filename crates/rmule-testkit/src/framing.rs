//! Shared TCP frame pump for the fakes: pull one decoded packet, buffering
//! across reads and keeping trailing bytes for the next call (frames on a
//! shared session can coalesce).

use rmule_primitives::Packet;
use tokio::io::{AsyncRead, AsyncReadExt};

pub(crate) async fn next_packet<R: AsyncRead + Unpin>(
    stream: &mut R,
    buf: &mut Vec<u8>,
) -> Option<Packet> {
    loop {
        if let Ok((packet, consumed)) = Packet::decode(buf) {
            buf.drain(..consumed);
            return Some(packet);
        }
        let mut tmp = [0u8; 4096];
        let n = stream.read(&mut tmp).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&tmp[..n]);
    }
}
