use std::io;

use anyhow::{Context, Result, bail};
use bytes::{BufMut, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[derive(Debug, Clone)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

pub async fn read_packet(stream: &mut TcpStream, max_packet_size: usize) -> io::Result<Vec<u8>> {
    let packet_len = read_varint_async(stream).await?;
    if packet_len <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet length must be positive",
        ));
    }
    let packet_len = packet_len as usize;
    if packet_len > max_packet_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "packet too large",
        ));
    }
    let mut buf = vec![0u8; packet_len];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

pub async fn write_packet(stream: &mut TcpStream, payload: &[u8]) -> io::Result<()> {
    let mut header = BytesMut::with_capacity(5);
    write_varint(payload.len() as i32, &mut header);
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    Ok(())
}

pub fn parse_packet_id(payload: &[u8]) -> Result<(i32, usize)> {
    parse_varint(payload).context("failed to decode packet id")
}

pub fn parse_handshake(payload: &[u8]) -> Result<Handshake> {
    let (packet_id, mut offset) = parse_varint(payload).context("missing handshake packet id")?;
    if packet_id != 0 {
        bail!("expected handshake packet id 0, got {packet_id}");
    }

    let (protocol_version, read) =
        parse_varint(&payload[offset..]).context("missing protocol version")?;
    offset += read;

    let (server_address, read) =
        parse_mc_string(&payload[offset..]).context("missing server address")?;
    offset += read;

    if payload.len() < offset + 2 {
        bail!("missing server port");
    }
    let server_port = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
    offset += 2;

    let (next_state, _read) = parse_varint(&payload[offset..]).context("missing next state")?;

    Ok(Handshake {
        protocol_version,
        server_address,
        server_port,
        next_state,
    })
}

pub fn parse_login_start_username(payload: &[u8]) -> Result<Option<String>> {
    let (packet_id, mut offset) = parse_varint(payload).context("missing login packet id")?;
    if packet_id != 0 {
        return Ok(None);
    }
    let (username, read) = parse_mc_string(&payload[offset..]).context("missing username")?;
    offset += read;
    if offset > payload.len() {
        bail!("invalid login payload");
    }
    Ok(Some(username))
}

pub fn build_login_disconnect(message: &str) -> Vec<u8> {
    let chat_json = serde_json::json!({ "text": message }).to_string();
    let mut payload = BytesMut::with_capacity(chat_json.len() + 8);
    write_varint(0, &mut payload);
    write_mc_string(&chat_json, &mut payload);
    payload.to_vec()
}

pub fn build_status_response(json: &str) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(json.len() + 8);
    write_varint(0, &mut payload);
    write_mc_string(json, &mut payload);
    payload.to_vec()
}

pub fn build_status_ping_response(ping_payload: i64) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(1 + 8);
    write_varint(1, &mut payload);
    payload.put_i64(ping_payload);
    payload.to_vec()
}

pub fn build_status_request() -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(1);
    write_varint(0, &mut payload);
    payload.to_vec()
}

pub fn build_handshake_packet(
    protocol_version: i32,
    host: &str,
    port: u16,
    next_state: i32,
) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(host.len() + 16);
    write_varint(0, &mut payload);
    write_varint(protocol_version, &mut payload);
    write_mc_string(host, &mut payload);
    payload.put_u16(port);
    write_varint(next_state, &mut payload);
    payload.to_vec()
}

pub fn write_varint(mut value: i32, buf: &mut BytesMut) {
    loop {
        if (value & !0x7F) == 0 {
            buf.put_u8(value as u8);
            return;
        }
        buf.put_u8(((value & 0x7F) | 0x80) as u8);
        value = ((value as u32) >> 7) as i32;
    }
}

pub fn parse_varint(input: &[u8]) -> Result<(i32, usize)> {
    let mut num_read = 0usize;
    let mut result = 0i32;

    loop {
        if num_read >= input.len() {
            bail!("incomplete varint");
        }
        let byte = input[num_read];
        let value = (byte & 0x7F) as i32;
        result |= value << (7 * num_read);
        num_read += 1;
        if num_read > 5 {
            bail!("varint too big");
        }
        if (byte & 0x80) == 0 {
            break;
        }
    }

    Ok((result, num_read))
}

fn parse_mc_string(input: &[u8]) -> Result<(String, usize)> {
    let (len, read) = parse_varint(input).context("bad string len varint")?;
    if len < 0 {
        bail!("negative string len");
    }
    let len = len as usize;
    let start = read;
    let end = start + len;
    if input.len() < end {
        bail!("string payload truncated");
    }
    let s = std::str::from_utf8(&input[start..end]).context("string is not utf8")?;
    Ok((s.to_string(), read + len))
}

fn write_mc_string(value: &str, buf: &mut BytesMut) {
    write_varint(value.len() as i32, buf);
    buf.put_slice(value.as_bytes());
}

async fn read_varint_async(stream: &mut TcpStream) -> io::Result<i32> {
    let mut num_read = 0u32;
    let mut result = 0i32;

    loop {
        let byte = stream.read_u8().await?;
        let value = (byte & 0x7F) as i32;
        result |= value << (7 * num_read);
        num_read += 1;
        if num_read > 5 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "varint too large",
            ));
        }
        if (byte & 0x80) == 0 {
            break;
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let mut buf = BytesMut::new();
        write_varint(767, &mut buf);
        let (decoded, read) = parse_varint(&buf).expect("must decode");
        assert_eq!(decoded, 767);
        assert_eq!(read, buf.len());
    }

    #[test]
    fn handshake_parser_works() {
        let payload = build_handshake_packet(767, "localhost", 25565, 2);
        let hs = parse_handshake(&payload).expect("handshake parses");
        assert_eq!(hs.protocol_version, 767);
        assert_eq!(hs.server_address, "localhost");
        assert_eq!(hs.server_port, 25565);
        assert_eq!(hs.next_state, 2);
    }
}
