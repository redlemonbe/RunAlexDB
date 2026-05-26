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
pub const CAPABILITY_SSL: u32                 = 1 << 11; // CLIENT_SSL

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

/// Build a server greeting advertising TLS support (CLIENT_SSL capability).
pub fn server_greeting_tls(server_id: u32, auth_data: &[u8; 20]) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(10);
    out.put_slice(b"8.0.32-RunAlexDB\0");
    out.put_u32_le(server_id);
    out.put_slice(&auth_data[..8]);
    out.put_u8(0);

    let caps: u32 = CAPABILITY_LONG_PASSWORD
        | CAPABILITY_PROTOCOL_41
        | CAPABILITY_SECURE_CONNECTION
        | CAPABILITY_PLUGIN_AUTH
        | CAPABILITY_SSL;
    out.put_u16_le((caps & 0xffff) as u16);
    out.put_u8(0x21);
    out.put_u16_le(2);
    out.put_u16_le((caps >> 16) as u16);
    out.put_u8(21);
    out.put_bytes(0, 10);
    out.put_slice(&auth_data[8..]);
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
    StmtPrepare(String),
    /// stmt_id is set; params vec is empty — server.rs re-parses from raw payload.
    StmtExecute(u32),
    StmtClose(u32),
    StmtReset(u32),
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
        0x16 => Command::StmtPrepare(String::from_utf8_lossy(&payload[1..]).into_owned()),
        0x17 => {
            if payload.len() >= 5 {
                let id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Command::StmtExecute(id)
            } else { Command::Unknown(0x17) }
        }
        0x19 => {
            if payload.len() >= 5 {
                let id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Command::StmtClose(id)
            } else { Command::Unknown(0x19) }
        }
        0x1a => {
            if payload.len() >= 5 {
                let id = u32::from_le_bytes([payload[1], payload[2], payload[3], payload[4]]);
                Command::StmtReset(id)
            } else { Command::Unknown(0x1a) }
        }
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

// ── Prepared statement packets ──────────────────────────────────────────────

pub fn stmt_prepare_ok(stmt_id: u32, num_params: u16, num_columns: u16) -> Bytes {
    let mut out = BytesMut::new();
    out.put_u8(0x00);
    out.put_u32_le(stmt_id);
    out.put_u16_le(num_columns);
    out.put_u16_le(num_params);
    out.put_u8(0);
    out.put_u16_le(0);
    out.freeze()
}

/// Binary result-set row (for COM_STMT_EXECUTE responses).
pub fn binary_row(values: &[Option<&str>]) -> Bytes {
    let n = values.len();
    let null_bitmap_len = (n + 7 + 2) / 8;
    let mut null_bitmap = vec![0u8; null_bitmap_len];
    for (i, v) in values.iter().enumerate() {
        if v.is_none() {
            let bit = i + 2;
            null_bitmap[bit / 8] |= 1 << (bit % 8);
        }
    }
    let mut out = BytesMut::new();
    out.put_u8(0x00);
    out.put_slice(&null_bitmap);
    for v in values {
        if let Some(s) = v {
            put_lenenc_str(&mut out, s);
        }
    }
    out.freeze()
}

/// Parse the binary parameter values from a COM_STMT_EXECUTE payload.
/// Returns Vec<Option<String>>: None = SQL NULL.
pub fn parse_execute_params(payload: &[u8], num_params: u16) -> Vec<Option<String>> {
    let n = num_params as usize;
    if n == 0 || payload.len() < 10 { return vec![]; }
    // null bitmap starts at offset 10, length = ceil(n/8)
    let bitmap_len = (n + 7) / 8;
    if payload.len() < 10 + bitmap_len { return vec![None; n]; }
    let null_bitmap = &payload[10..10 + bitmap_len];
    let mut pos = 10 + bitmap_len;

    let new_bound = if pos < payload.len() { payload[pos] } else { 0 };
    pos += 1;

    let mut types = vec![(0xfd_u8, false); n];
    if new_bound == 1 && pos + n * 2 <= payload.len() {
        for t in types.iter_mut() {
            t.0 = payload[pos];
            t.1 = payload[pos + 1] != 0;
            pos += 2;
        }
    }

    let mut result = Vec::with_capacity(n);
    for i in 0..n {
        let is_null = (null_bitmap[i / 8] >> (i % 8)) & 1 == 1;
        if is_null { result.push(None); continue; }
        let val = read_binary_param(payload, &mut pos, types[i].0);
        result.push(Some(val));
    }
    result
}

fn read_binary_param(payload: &[u8], pos: &mut usize, type_byte: u8) -> String {
    if *pos >= payload.len() { return String::new(); }
    match type_byte {
        0x01 => { // TINY
            let v = payload[*pos] as i8; *pos += 1; v.to_string()
        }
        0x02 | 0x82 => { // SHORT
            if *pos + 2 > payload.len() { return String::new(); }
            let v = i16::from_le_bytes([payload[*pos], payload[*pos+1]]); *pos += 2; v.to_string()
        }
        0x03 | 0x09 => { // LONG / INT24
            if *pos + 4 > payload.len() { return String::new(); }
            let v = i32::from_le_bytes(payload[*pos..*pos+4].try_into().unwrap_or_default()); *pos += 4; v.to_string()
        }
        0x04 => { // FLOAT
            if *pos + 4 > payload.len() { return String::new(); }
            let v = f32::from_le_bytes(payload[*pos..*pos+4].try_into().unwrap_or_default()); *pos += 4; format!("{v}")
        }
        0x05 => { // DOUBLE
            if *pos + 8 > payload.len() { return String::new(); }
            let v = f64::from_le_bytes(payload[*pos..*pos+8].try_into().unwrap_or_default()); *pos += 8; format!("{v}")
        }
        0x08 => { // LONGLONG
            if *pos + 8 > payload.len() { return String::new(); }
            let v = i64::from_le_bytes(payload[*pos..*pos+8].try_into().unwrap_or_default()); *pos += 8; v.to_string()
        }
        0x0a | 0x0e => read_binary_date(payload, pos),
        0x07 | 0x0b | 0x0c => read_binary_datetime(payload, pos),
        _ => read_lenenc_bytes_as_str(payload, pos),
    }
}

fn read_lenenc_bytes_as_str(payload: &[u8], pos: &mut usize) -> String {
    if *pos >= payload.len() { return String::new(); }
    let (len, inc): (usize, usize) = match payload[*pos] {
        0xfb => { *pos += 1; return String::new(); }
        0xfc => {
            if *pos + 2 >= payload.len() { return String::new(); }
            (u16::from_le_bytes([payload[*pos+1], payload[*pos+2]]) as usize, 3)
        }
        0xfd => {
            if *pos + 3 >= payload.len() { return String::new(); }
            let l = (payload[*pos+1] as usize) | ((payload[*pos+2] as usize) << 8) | ((payload[*pos+3] as usize) << 16);
            (l, 4)
        }
        n => (n as usize, 1),
    };
    *pos += inc;
    if *pos + len > payload.len() { return String::new(); }
    let s = String::from_utf8_lossy(&payload[*pos..*pos+len]).into_owned();
    *pos += len;
    s
}

fn read_binary_date(payload: &[u8], pos: &mut usize) -> String {
    if *pos >= payload.len() { return "0000-00-00".to_owned(); }
    let len = payload[*pos] as usize; *pos += 1;
    if len < 4 || *pos + 4 > payload.len() { *pos += len; return "0000-00-00".to_owned(); }
    let y = u16::from_le_bytes([payload[*pos], payload[*pos+1]]);
    let m = payload[*pos+2]; let d = payload[*pos+3];
    *pos += len;
    format!("{y:04}-{m:02}-{d:02}")
}

fn read_binary_datetime(payload: &[u8], pos: &mut usize) -> String {
    if *pos >= payload.len() { return "0000-00-00 00:00:00".to_owned(); }
    let len = payload[*pos] as usize; *pos += 1;
    if len < 4 || *pos + len > payload.len() { *pos += len; return "0000-00-00 00:00:00".to_owned(); }
    let y = u16::from_le_bytes([payload[*pos], payload[*pos+1]]);
    let mo = payload[*pos+2]; let d = payload[*pos+3];
    let (h, mi, s) = if len >= 7 { (payload[*pos+4], payload[*pos+5], payload[*pos+6]) } else { (0,0,0) };
    *pos += len;
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
}

// ── Inline writers — zero-alloc batch protocol encoding ────────────────────
//
// Each function writes directly into a caller-owned BytesMut.
// Pattern: reserve 4-byte header placeholder, write payload, back-fill header.
// Combined with build_result_into() this reduces N+4 write_all() calls
// (one per packet) to a single write_all() for the entire result set.

use crate::engine::QueryResult;

/// Write a framed MySQL packet header + payload into buf (no intermediate alloc).
#[inline(always)]
pub fn write_packet_into(out: &mut BytesMut, payload: &[u8], seq: u8) {
    let len = payload.len() as u32;
    out.put_u8((len & 0xff) as u8);
    out.put_u8(((len >> 8) & 0xff) as u8);
    out.put_u8(((len >> 16) & 0xff) as u8);
    out.put_u8(seq);
    out.put_slice(payload);
}

/// Write a 9-byte EOF packet (protocol 4.1) directly into buf.
#[inline(always)]
pub fn write_eof_into(out: &mut BytesMut, seq: u8) {
    out.put_slice(&[0x05, 0x00, 0x00, seq, 0xfe, 0x00, 0x00, 0x02, 0x00]);
}

/// Write a column definition packet directly into buf.
pub fn write_col_def_into(out: &mut BytesMut, name: &str, col_type: u8, seq: u8) {
    let hdr_pos = out.len();
    out.put_bytes(0, 4); // placeholder
    put_lenenc_str(out, "def");
    put_lenenc_str(out, "");
    put_lenenc_str(out, "");
    put_lenenc_str(out, "");
    put_lenenc_str(out, name);
    put_lenenc_str(out, name); // org_name
    out.put_u8(0x0c);
    out.put_u16_le(0x21);
    out.put_u32_le(255);
    out.put_u8(col_type);
    out.put_u16_le(0);
    out.put_u8(0);
    out.put_u16_le(0);
    let pl = out.len() - hdr_pos - 4;
    out[hdr_pos]   = (pl & 0xff) as u8;
    out[hdr_pos+1] = ((pl >> 8) & 0xff) as u8;
    out[hdr_pos+2] = ((pl >> 16) & 0xff) as u8;
    out[hdr_pos+3] = seq;
}

/// Write a text-mode result row directly into buf.
pub fn write_text_row_into(out: &mut BytesMut, row: &[Option<String>], seq: u8) {
    let hdr_pos = out.len();
    out.put_bytes(0, 4);
    for v in row {
        match v {
            None    => out.put_u8(0xfb),
            Some(s) => { put_lenenc(out, s.len() as u64); out.put_slice(s.as_bytes()); }
        }
    }
    let pl = out.len() - hdr_pos - 4;
    out[hdr_pos]   = (pl & 0xff) as u8;
    out[hdr_pos+1] = ((pl >> 8) & 0xff) as u8;
    out[hdr_pos+2] = ((pl >> 16) & 0xff) as u8;
    out[hdr_pos+3] = seq;
}

/// Write a binary-mode result row (COM_STMT_EXECUTE) directly into buf.
pub fn write_binary_row_into(out: &mut BytesMut, row: &[Option<String>], seq: u8) {
    let n = row.len();
    let null_bitmap_len = (n + 7 + 2) / 8;
    let mut null_bitmap = vec![0u8; null_bitmap_len];
    for (i, v) in row.iter().enumerate() {
        if v.is_none() {
            let bit = i + 2;
            null_bitmap[bit / 8] |= 1 << (bit % 8);
        }
    }
    let hdr_pos = out.len();
    out.put_bytes(0, 4);
    out.put_u8(0x00);
    out.put_slice(&null_bitmap);
    for v in row {
        if let Some(s) = v {
            put_lenenc(out, s.len() as u64);
            out.put_slice(s.as_bytes());
        }
    }
    let pl = out.len() - hdr_pos - 4;
    out[hdr_pos]   = (pl & 0xff) as u8;
    out[hdr_pos+1] = ((pl >> 8) & 0xff) as u8;
    out[hdr_pos+2] = ((pl >> 16) & 0xff) as u8;
    out[hdr_pos+3] = seq;
}

/// Serialize an entire QueryResult into buf as one contiguous block of MySQL packets.
/// Caller issues a single write_all() syscall instead of N+4 per result set.
pub fn build_result_into(buf: &mut BytesMut, result: &QueryResult, seq: u8) {
    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            let p = ok_packet(*affected, *last_insert_id);
            write_packet_into(buf, &p, seq);
        }
        QueryResult::Err { code, message } => {
            let p = err_packet(*code, message);
            write_packet_into(buf, &p, seq);
        }
        QueryResult::Rows { columns, rows } => {
            let n_cols = columns.len();
            let mut s = seq;
            buf.reserve(256 + n_cols * 40 + rows.len().saturating_mul(4 + n_cols * 20));
            write_packet_into(buf, &[n_cols as u8], s); s = s.wrapping_add(1);
            for col in columns { write_col_def_into(buf, col, 0xfd, s); s = s.wrapping_add(1); }
            write_eof_into(buf, s); s = s.wrapping_add(1);
            for row in rows { write_text_row_into(buf, row, s); s = s.wrapping_add(1); }
            write_eof_into(buf, s);
        }
        QueryResult::ValueRows { columns, rows } => {
            build_value_result_into(buf, columns, rows, seq);
        }
    }
}

/// Same as build_result_into but uses binary row encoding (COM_STMT_EXECUTE).
pub fn build_binary_result_into(buf: &mut BytesMut, result: &QueryResult, seq: u8) {
    match result {
        QueryResult::Ok { affected, last_insert_id } => {
            let p = ok_packet(*affected, *last_insert_id);
            write_packet_into(buf, &p, seq);
        }
        QueryResult::Err { code, message } => {
            let p = err_packet(*code, message);
            write_packet_into(buf, &p, seq);
        }
        QueryResult::Rows { columns, rows } => {
            let n_cols = columns.len();
            let mut s = seq;
            buf.reserve(256 + n_cols * 40 + rows.len().saturating_mul(4 + n_cols * 20));
            write_packet_into(buf, &[n_cols as u8], s); s = s.wrapping_add(1);
            for col in columns { write_col_def_into(buf, col, 0xfd, s); s = s.wrapping_add(1); }
            write_eof_into(buf, s); s = s.wrapping_add(1);
            for row in rows { write_binary_row_into(buf, row, s); s = s.wrapping_add(1); }
            write_eof_into(buf, s);
        }
        QueryResult::ValueRows { columns, rows } => {
            // For binary protocol, use text encoding (stmt_execute with VARCHAR columns)
            build_value_result_into(buf, columns, rows, seq);
        }
    }
}

// ── ValueRows encoding — zero heap allocation per row ─────────────────────
//
// Integer values are formatted as ASCII on a stack buffer (no String alloc).
// Text values are written as raw bytes from the stored String.

/// Write a single i64 as ASCII decimal directly into buf.
/// Uses stdlib fmt::Display (lookup-table optimized) via a custom fmt::Write wrapper.
/// Zero heap allocation: the formatted digits go straight into the BytesMut.
#[inline]
fn write_i64_digits(out: &mut BytesMut, n: i64) {
    use std::fmt::Write as FmtWrite;
    // Wrapper: routes fmt output directly into our BytesMut (no intermediate String).
    struct Sink<'a>(&'a mut BytesMut, usize); // field 1: buf, field 2: bytes_written
    impl FmtWrite for Sink<'_> {
        #[inline(always)]
        fn write_str(&mut self, s: &str) -> std::fmt::Result {
            self.0.put_slice(s.as_bytes());
            self.1 += s.len();
            Ok(())
        }
    }
    // Reserve 1 byte for the lenenc prefix (all i64 decimals fit in 1-byte lenenc ≤ 250)
    let lenenc_pos = out.len();
    out.put_u8(0); // placeholder
    let mut sink = Sink(out, 0);
    let _ = write!(sink, "{}", n);
    let written = sink.1;
    // Backfill lenenc (i64 max = 19 digits — always fits in 1-byte lenenc < 251)
    out[lenenc_pos] = written as u8;
}

/// Write a Value directly into buf (text-mode MySQL encoding, no String conversion).
#[inline]
fn write_value_text(out: &mut BytesMut, v: &crate::engine::Value) {
    use crate::engine::Value;
    match v {
        Value::Null       => out.put_u8(0xfb),
        Value::Int(n)     => write_i64_digits(out, *n),
        Value::Float(f)   => {
            // floats still need formatting — use a stack string via itoa-style
            let s = format!("{f}");
            put_lenenc(out, s.len() as u64);
            out.put_slice(s.as_bytes());
        }
        Value::Text(s)    => { put_lenenc(out, s.len() as u64); out.put_slice(s.as_bytes()); }
        Value::Bytes(b)   => {
            let h = hex::encode(b);
            put_lenenc(out, h.len() as u64);
            out.put_slice(h.as_bytes());
        }
    }
}

/// Write a ValueRows result row directly into buf — no String intermediate.
pub fn write_value_row_into(out: &mut BytesMut, row: &[crate::engine::Value], seq: u8) {
    let hdr_pos = out.len();
    out.put_bytes(0, 4);
    for v in row { write_value_text(out, v); }
    let pl = out.len() - hdr_pos - 4;
    out[hdr_pos]   = (pl & 0xff) as u8;
    out[hdr_pos+1] = ((pl >> 8) & 0xff) as u8;
    out[hdr_pos+2] = ((pl >> 16) & 0xff) as u8;
    out[hdr_pos+3] = seq;
}

/// Build a ValueRows result into buf (zero allocation per row for Int values).
pub fn build_value_result_into(buf: &mut BytesMut, columns: &[String], rows: &[Vec<crate::engine::Value>], seq: u8) {
    let n_cols = columns.len();
    let mut s = seq;
    buf.reserve(256 + n_cols * 40 + rows.len().saturating_mul(4 + n_cols * 12));
    write_packet_into(buf, &[n_cols as u8], s); s = s.wrapping_add(1);
    for col in columns { write_col_def_into(buf, col, 0xfd, s); s = s.wrapping_add(1); }
    write_eof_into(buf, s); s = s.wrapping_add(1);
    for row in rows { write_value_row_into(buf, row, s); s = s.wrapping_add(1); }
    write_eof_into(buf, s);
}
