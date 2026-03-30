use std::io;
use std::io::{Read, Write};

use anyhow::{Context, Result, bail};
use bytes::{BufMut, BytesMut};
use flate2::Compression;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Handshake {
    pub protocol_version: i32,
    pub server_address: String,
    pub server_port: u16,
    pub next_state: i32,
}

#[derive(Debug, Clone)]
pub struct LoginPluginRequest {
    pub message_id: i32,
    pub channel: String,
    pub data: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct EncryptionResponse {
    pub shared_secret: Vec<u8>,
    pub verify_token: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct VelocityProperty {
    pub name: String,
    pub value: String,
    pub signature: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct LoginPluginResponse {
    pub message_id: i32,
    pub success: bool,
    pub data: Option<Vec<u8>>,
}

#[cfg(test)]
#[derive(Debug, Clone)]
pub struct VelocityForwardingPayload {
    pub version: i32,
    pub client_ip: String,
    pub uuid_bytes: [u8; 16],
    pub username: String,
    pub properties: Vec<VelocityProperty>,
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

pub fn build_login_start_packet(username: &str) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(username.len() + 8);
    write_varint(0, &mut payload);
    write_mc_string(username, &mut payload);
    payload.to_vec()
}

pub fn build_login_disconnect(message: &str) -> Vec<u8> {
    let chat_json = serde_json::json!({ "text": message }).to_string();
    let mut payload = BytesMut::with_capacity(chat_json.len() + 8);
    write_varint(0, &mut payload);
    write_mc_string(&chat_json, &mut payload);
    payload.to_vec()
}

pub fn build_encryption_request(
    server_id: &str,
    public_key_der: &[u8],
    verify_token: &[u8],
) -> Vec<u8> {
    let mut payload =
        BytesMut::with_capacity(server_id.len() + public_key_der.len() + verify_token.len() + 16);
    write_varint(0x01, &mut payload);
    write_mc_string(server_id, &mut payload);
    write_byte_array(public_key_der, &mut payload);
    write_byte_array(verify_token, &mut payload);
    payload.put_u8(1); // should authenticate
    payload.to_vec()
}

pub fn parse_encryption_response(payload: &[u8]) -> Result<Option<EncryptionResponse>> {
    let (packet_id, mut offset) = parse_varint(payload).context("missing packet id")?;
    if packet_id != 0x01 {
        return Ok(None);
    }

    let (shared_secret, read) =
        parse_byte_array(&payload[offset..]).context("missing encrypted shared secret")?;
    offset += read;
    if offset >= payload.len() {
        bail!("missing encrypted verify token");
    }

    let remaining = &payload[offset..];
    if let Ok((verify_token, read)) = parse_byte_array(remaining)
        && read == remaining.len()
    {
        return Ok(Some(EncryptionResponse {
            shared_secret,
            verify_token,
        }));
    }

    let has_verify_token = remaining[0] != 0;
    offset += 1;
    if !has_verify_token {
        bail!("encryption response without verify token is not supported");
    }

    let (verify_token, _read) =
        parse_byte_array(&payload[offset..]).context("missing encrypted verify token")?;
    Ok(Some(EncryptionResponse {
        shared_secret,
        verify_token,
    }))
}

#[cfg(test)]
pub fn build_login_plugin_request(message_id: i32, channel: &str, data: &[u8]) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(channel.len() + data.len() + 16);
    write_varint(0x04, &mut payload);
    write_varint(message_id, &mut payload);
    write_mc_string(channel, &mut payload);
    payload.put_slice(data);
    payload.to_vec()
}

pub fn parse_login_plugin_request(payload: &[u8]) -> Result<Option<LoginPluginRequest>> {
    let (packet_id, mut offset) = parse_varint(payload).context("missing packet id")?;
    if packet_id != 0x04 {
        return Ok(None);
    }
    let (message_id, read) = parse_varint(&payload[offset..]).context("missing message id")?;
    offset += read;
    let (channel, read) = parse_mc_string(&payload[offset..]).context("missing channel")?;
    offset += read;
    let data = payload[offset..].to_vec();
    Ok(Some(LoginPluginRequest {
        message_id,
        channel,
        data,
    }))
}

pub fn build_login_plugin_response(message_id: i32, success: bool, data: Option<&[u8]>) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(data.map(|d| d.len()).unwrap_or(0) + 16);
    write_varint(0x02, &mut payload);
    write_varint(message_id, &mut payload);
    payload.put_u8(if success { 1 } else { 0 });
    if success && let Some(data) = data {
        payload.put_slice(data);
    }
    payload.to_vec()
}

pub fn parse_set_compression_threshold(payload: &[u8]) -> Result<Option<i32>> {
    let (packet_id, offset) = parse_varint(payload).context("missing packet id")?;
    if packet_id != 0x03 {
        return Ok(None);
    }
    let (threshold, _read) =
        parse_varint(&payload[offset..]).context("missing compression threshold")?;
    Ok(Some(threshold))
}

pub fn decode_login_packet_from_backend(
    raw_payload: &[u8],
    compression_enabled: bool,
) -> Result<Vec<u8>> {
    if !compression_enabled {
        return Ok(raw_payload.to_vec());
    }

    let (data_length, read) =
        parse_varint(raw_payload).context("missing compressed frame data length")?;
    if data_length < 0 {
        bail!("negative compressed frame data length");
    }

    if data_length == 0 {
        return Ok(raw_payload[read..].to_vec());
    }

    let compressed = &raw_payload[read..];
    let mut decoder = ZlibDecoder::new(compressed);
    let mut decompressed = Vec::with_capacity(data_length as usize);
    decoder
        .read_to_end(&mut decompressed)
        .context("failed to decompress login packet")?;
    if decompressed.len() != data_length as usize {
        bail!(
            "decompressed size mismatch: expected {}, got {}",
            data_length,
            decompressed.len()
        );
    }
    Ok(decompressed)
}

pub fn encode_login_packet_for_backend(
    payload: &[u8],
    compression_threshold: Option<i32>,
) -> Result<Vec<u8>> {
    let Some(threshold) = compression_threshold else {
        return Ok(payload.to_vec());
    };

    if threshold < 0 {
        return Ok(payload.to_vec());
    }
    let threshold = threshold as usize;

    if payload.len() < threshold {
        let mut out = BytesMut::with_capacity(payload.len() + 5);
        write_varint(0, &mut out);
        out.put_slice(payload);
        return Ok(out.to_vec());
    }

    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder
        .write_all(payload)
        .context("failed to compress login packet")?;
    let compressed = encoder.finish().context("failed to finalize compression")?;
    let mut out = BytesMut::with_capacity(compressed.len() + 5);
    write_varint(payload.len() as i32, &mut out);
    out.put_slice(&compressed);
    Ok(out.to_vec())
}

#[cfg(test)]
pub fn parse_login_plugin_response(payload: &[u8]) -> Result<Option<LoginPluginResponse>> {
    let (packet_id, mut offset) = parse_varint(payload).context("missing packet id")?;
    if packet_id != 0x02 {
        return Ok(None);
    }
    let (message_id, read) = parse_varint(&payload[offset..]).context("missing message id")?;
    offset += read;
    if payload.len() <= offset {
        bail!("missing success flag");
    }
    let success = payload[offset] != 0;
    offset += 1;
    let data = if success {
        Some(payload[offset..].to_vec())
    } else {
        None
    };
    Ok(Some(LoginPluginResponse {
        message_id,
        success,
        data,
    }))
}

pub fn build_velocity_modern_forwarding_payload(
    client_ip: &str,
    uuid_bytes: [u8; 16],
    username: &str,
    properties: &[VelocityProperty],
) -> Vec<u8> {
    let mut payload = BytesMut::with_capacity(client_ip.len() + username.len() + 64);
    write_varint(1, &mut payload);
    write_mc_string(client_ip, &mut payload);
    payload.put_slice(&uuid_bytes);
    write_mc_string(username, &mut payload);
    write_varint(properties.len() as i32, &mut payload);
    for property in properties {
        write_mc_string(&property.name, &mut payload);
        write_mc_string(&property.value, &mut payload);
        payload.put_u8(property.signature.is_some() as u8);
        if let Some(signature) = &property.signature {
            write_mc_string(signature, &mut payload);
        }
    }
    payload.to_vec()
}

pub fn offline_uuid(username: &str) -> [u8; 16] {
    let source = format!("OfflinePlayer:{username}");
    *Uuid::new_v3(&Uuid::NAMESPACE_DNS, source.as_bytes()).as_bytes()
}

#[cfg(test)]
pub fn parse_velocity_modern_forwarding_payload(
    payload: &[u8],
) -> Result<VelocityForwardingPayload> {
    let (version, mut offset) = parse_varint(payload).context("missing velocity version")?;
    let (client_ip, read) = parse_mc_string(&payload[offset..]).context("missing client ip")?;
    offset += read;
    if payload.len() < offset + 16 {
        bail!("missing uuid bytes");
    }
    let mut uuid_bytes = [0u8; 16];
    uuid_bytes.copy_from_slice(&payload[offset..offset + 16]);
    offset += 16;
    let (username, read) = parse_mc_string(&payload[offset..]).context("missing username")?;
    offset += read;
    let (properties_count, read) =
        parse_varint(&payload[offset..]).context("missing properties count")?;
    offset += read;
    if properties_count < 0 {
        bail!("negative properties count");
    }
    let mut properties = Vec::with_capacity(properties_count as usize);
    for _ in 0..properties_count {
        let (name, read) = parse_mc_string(&payload[offset..]).context("missing property name")?;
        offset += read;
        let (value, read) =
            parse_mc_string(&payload[offset..]).context("missing property value")?;
        offset += read;
        if payload.len() <= offset {
            bail!("missing property signature flag");
        }
        let has_signature = payload[offset] != 0;
        offset += 1;
        let signature = if has_signature {
            let (signature, read) =
                parse_mc_string(&payload[offset..]).context("missing property signature")?;
            offset += read;
            Some(signature)
        } else {
            None
        };
        properties.push(VelocityProperty {
            name,
            value,
            signature,
        });
    }
    Ok(VelocityForwardingPayload {
        version,
        client_ip,
        uuid_bytes,
        username,
        properties,
    })
}

pub fn sign_hmac_sha256(secret: &str, payload: &[u8]) -> Result<[u8; 32]> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid hmac key"))?;
    mac.update(payload);
    let raw = mac.finalize().into_bytes();
    let mut signature = [0u8; 32];
    signature.copy_from_slice(raw.as_slice());
    Ok(signature)
}

pub fn build_signed_velocity_forwarding_data(secret: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let signature = sign_hmac_sha256(secret, payload)?;
    let mut out = Vec::with_capacity(32 + payload.len());
    out.extend_from_slice(&signature);
    out.extend_from_slice(payload);
    Ok(out)
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

pub fn build_respawn_packet(protocol: u32) -> Vec<u8> {
    if protocol != 774 {
        return Vec::new();
    }

    let mut payload = BytesMut::with_capacity(128);
    write_varint(0x47, &mut payload);
    write_mc_string("minecraft:overworld", &mut payload); // dimension_type
    write_mc_string("minecraft:overworld", &mut payload); // dimension_name
    payload.put_i64(0); // hashed_seed
    payload.put_u8(0); // gamemode (survival)
    payload.put_i8(-1); // previous gamemode
    payload.put_u8(0); // is_debug
    payload.put_u8(0); // is_flat
    payload.put_u8(0); // has_death_location
    write_varint(0, &mut payload); // portal_cooldown
    write_varint(64, &mut payload); // sea_level
    payload.to_vec()
}

pub fn build_play_plugin_message_packet(
    protocol: u32,
    clientbound: bool,
    channel: &str,
    data: &[u8],
) -> Option<Vec<u8>> {
    let packet_id = match (protocol, clientbound) {
        // 1.21.11 (protocol 774): ClientboundCustomPayloadPacket / ServerboundCustomPayloadPacket
        (774, true) => 0x18,
        (774, false) => 0x15,
        _ => return None,
    };
    let mut payload = BytesMut::with_capacity(channel.len() + data.len() + 16);
    write_varint(packet_id, &mut payload);
    write_mc_string(channel, &mut payload);
    payload.put_slice(data);
    Some(payload.to_vec())
}

pub fn build_play_system_chat_packet(
    protocol: u32,
    message: &str,
    is_action_bar: bool,
) -> Option<Vec<u8>> {
    let packet_id = match protocol {
        // 1.21.11 (protocol 774): ClientboundSystemChatPacket
        774 => 0x77,
        _ => return None,
    };

    let mut payload = BytesMut::with_capacity(message.len() + 32);
    write_varint(packet_id, &mut payload);
    write_anonymous_nbt_text_component(message, &mut payload);
    payload.put_u8(u8::from(is_action_bar));
    Some(payload.to_vec())
}

pub fn parse_play_plugin_message_packet(
    payload: &[u8],
    protocol: u32,
    clientbound: bool,
) -> Result<Option<(String, usize)>> {
    let expected_id = match (protocol, clientbound) {
        (774, true) => 0x18,
        (774, false) => 0x15,
        _ => return Ok(None),
    };
    let (packet_id, mut offset) = parse_varint(payload).context("missing packet id")?;
    if packet_id != expected_id {
        return Ok(None);
    }
    let (channel, read) = parse_mc_string(&payload[offset..]).context("missing channel")?;
    offset += read;
    Ok(Some((channel, offset)))
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

fn write_anonymous_nbt_text_component(text: &str, buf: &mut BytesMut) {
    // anonymousNbt compound: { text: "<message>" }
    buf.put_u8(0x0A); // TAG_Compound (unnamed)

    buf.put_u8(0x08); // TAG_String
    buf.put_u16(4); // key length: "text"
    buf.put_slice(b"text");

    let text_len = text.len().min(u16::MAX as usize);
    buf.put_u16(text_len as u16);
    buf.put_slice(&text.as_bytes()[..text_len]);

    buf.put_u8(0x00); // TAG_End
}

fn parse_byte_array(input: &[u8]) -> Result<(Vec<u8>, usize)> {
    let (len, read) = parse_varint(input).context("bad byte array len varint")?;
    if len < 0 {
        bail!("negative byte array len");
    }
    let len = len as usize;
    let start = read;
    let end = start + len;
    if input.len() < end {
        bail!("byte array payload truncated");
    }
    Ok((input[start..end].to_vec(), read + len))
}

fn write_byte_array(value: &[u8], buf: &mut BytesMut) {
    write_varint(value.len() as i32, buf);
    buf.put_slice(value);
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

    #[test]
    fn velocity_payload_signing_roundtrip() {
        let payload = build_velocity_modern_forwarding_payload(
            "127.0.0.1",
            offline_uuid("Player"),
            "Player",
            &[],
        );
        let signed = build_signed_velocity_forwarding_data("secret", &payload).expect("signing");
        assert_eq!(signed.len(), payload.len() + 32);
        let parsed = parse_velocity_modern_forwarding_payload(&signed[32..]).expect("parse");
        assert_eq!(parsed.version, 1);
        assert_eq!(parsed.client_ip, "127.0.0.1");
        assert_eq!(parsed.uuid_bytes, offline_uuid("Player"));
        assert_eq!(parsed.username, "Player");
        assert!(parsed.properties.is_empty());
    }

    #[test]
    fn compressed_login_frame_roundtrip() {
        let mut inner = BytesMut::new();
        write_varint(0x02, &mut inner);
        write_mc_string("ok", &mut inner);
        let wrapped = encode_login_packet_for_backend(&inner, Some(1)).expect("encode");
        let decoded = decode_login_packet_from_backend(&wrapped, true).expect("decode");
        assert_eq!(decoded, inner.to_vec());
    }

    #[test]
    fn system_chat_packet_has_expected_id_and_flag() {
        let packet = build_play_system_chat_packet(774, "Hello", false).expect("packet");
        let (packet_id, offset) = parse_varint(&packet).expect("packet id");
        assert_eq!(packet_id, 0x77);
        assert_eq!(packet.last().copied(), Some(0));
        assert!(offset < packet.len());
    }
}
