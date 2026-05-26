//! MySQL wire protocol v4.1 — packet codec, handshake, command dispatch.

use bytes::{Buf, BufMut, Bytes, BytesMut};

// ── Packet framing ─────────────────────────────────────────────────────────

/// Decode one MySQL packet from `buf`. Returns (payload, seq) or None if
/// not enough data yet.
pub fn decode_packet(buf: &mut BytesMut) -> Option<(Bytes, u8)> {
    if buf.len() < 4 { return None; }
    let len = u24_le(&buf[0..3]) as usize;
    if buf.len() < 4 + len { return None; }
    buf.advance(3);
    let seq = buf[0];
    buf.advance(1);
    Some((buf.split_to(len).freeze(), seq))
}

/// Encode a payload as a MySQL packet with sequence number `seq`.
pub fn encode_packet(payload: &[u8], seq: u8) -> Bytes {
    let mut out = BytesMut::with_capacity(4 + payload.len());
    let len = payload.len() as u32;
    out.put_u8((len & 0xff) as u8);
    out.put_u8(((len >> 8) & 0xff) as u8);
    out.put_u8(((len >> 16) & 0xff) as u8);
    out.put_u8(seq);
    out.put_slice(payload);
    out.freeze()
}

// ── Handshake ──────────────────────────────────────────────────────────────

pub const CAPABILITY_LONG_PASSWORD: u32       = 1;
pub const CAPABILITY_PROTOCOL_41: u32         = 512;
pub const CAPABILITY_SECURE_CONNECTION: u32   = 32768;
pub const CAPABILITY_PLUGIN_AUTH: u32         = 1 << 19;
pub const CAPABILITY_CONNECT_WITH_DB: u32     = 8;

/// Build a server greeting (HandshakeV10).
pub fn server_greeting(server_id: u32, auth_data: &[u8; 20]) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(10); // protocol version
    out.put_slice(b"8.0.32-RunAlexDB\0"); // server version string
    out.put_u32_le(server_id);
    out.put_slice(&auth_data[..8]);
    out.put_u8(0); // filler

    let caps: u32 = CAPABILITY_LONG_PASSWORD
        | CAPABILITY_PROTOCOL_41
        | CAPABILITY_SECURE_CONNECTION
        | CAPABILITY_PLUGIN_AUTH;
    out.put_u16_le((caps & 0xffff) as u16);
    out.put_u8(0x21); // charset utf8mb4
    out.put_u16_le(2); // status flags: autocommit
    out.put_u16_le((caps >> 16) as u16);
    out.put_u8(21); // auth_plugin_data_len
    out.put_bytes(0, 10); // reserved
    out.put_slice(&auth_data[8..]); // scramble part 2
    out.put_u8(0);
    out.put_slice(b"mysql_native_password\0");

    out.freeze()
}

// ── Commands ───────────────────────────────────────────────────────────────

#[derive(Debug)]
pub enum Command {
    Query(String),
    Ping,
    Quit,
    InitDb(String),
    FieldList(String),
    Unknown(u8),
}

pub fn parse_command(payload: &[u8]) -> Command {
    if payload.is_empty() { return Command::Unknown(0); }
    match payload[0] {
        0x01 => Command::Quit,
        0x02 => Command::InitDb(String::from_utf8_lossy(&payload[1..]).into_owned()),
        0x03 => Command::Query(String::from_utf8_lossy(&payload[1..]).into_owned()),
        0x04 => Command::FieldList(String::from_utf8_lossy(&payload[1..]).into_owned()),
        0x0e => Command::Ping,
        other => Command::Unknown(other),
    }
}

// ── Response builders ──────────────────────────────────────────────────────

/// OK packet
pub fn ok_packet(affected: u64, last_insert_id: u64) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(0x00);
    put_lenenc(&mut out, affected);
    put_lenenc(&mut out, last_insert_id);
    out.put_u16_le(2); // status: autocommit
    out.put_u16_le(0); // warnings
    out.freeze()
}

/// ERR packet
pub fn err_packet(code: u16, msg: &str) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(0xff);
    out.put_u16_le(code);
    out.put_slice(b"#HY000");
    out.put_slice(msg.as_bytes());
    out.freeze()
}

/// EOF packet (protocol 4.1)
pub fn eof_packet() -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(0xfe);
    out.put_u16_le(0); // warnings
    out.put_u16_le(2); // status
    out.freeze()
}

// ── Result set encoding ────────────────────────────────────────────────────

/// Column definition packet
pub fn column_def(schema: &str, table: &str, name: &str, col_type: u8, flags: u16) -> Bytes {
    let mut out = BytesMut::new();
    put_lenenc_str(&mut out, "def"); // catalog
    put_lenenc_str(&mut out, schema);
    put_lenenc_str(&mut out, table);
    put_lenenc_str(&mut out, table); // org_table
    put_lenenc_str(&mut out, name);
    put_lenenc_str(&mut out, name); // org_name
    out.put_u8(0x0c); // length of fixed fields
    out.put_u16_le(0x21); // charset utf8mb4
    out.put_u32_le(255); // max column length
    out.put_u8(col_type);
    out.put_u16_le(flags);
    out.put_u8(0); // decimals
    out.put_u16_le(0); // filler
    out.freeze()
}

/// Text row packet
pub fn text_row(values: &[Option<&str>]) -> Bytes {
    let mut out = BytesMut::new();
    for v in values {
        match v {
            None => out.put_u8(0xfb), // NULL
            Some(s) => put_lenenc_str(&mut out, s),
        }
    }
    out.freeze()
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn u24_le(b: &[u8]) -> u32 {
    b[0] as u32 | ((b[1] as u32) << 8) | ((b[2] as u32) << 16)
}

fn put_lenenc(out: &mut BytesMut, v: u64) {
    if v < 251 {
        out.put_u8(v as u8);
    } else if v < 65536 {
        out.put_u8(0xfc);
        out.put_u16_le(v as u16);
    } else if v < 16_777_216 {
        out.put_u8(0xfd);
        out.put_u8((v & 0xff) as u8);
        out.put_u8(((v >> 8) & 0xff) as u8);
        out.put_u8(((v >> 16) & 0xff) as u8);
    } else {
        out.put_u8(0xfe);
        out.put_u64_le(v);
    }
}

fn put_lenenc_str(out: &mut BytesMut, s: &str) {
    put_lenenc(out, s.len() as u64);
    out.put_slice(s.as_bytes());
}
