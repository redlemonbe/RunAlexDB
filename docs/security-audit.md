# RunAlexDB Security Audit

**Version audited:** v0.1.0  
**Audit date:** 2026-05-26  
**Status:** Cycle A — [AI-INTERNAL]

---

## Executive Summary

This is a first-cycle, AI-internal code review of RunAlexDB v0.1.0. The audit covered the MySQL wire protocol implementation, authentication, SQL engine, and web UI (admin interface). No external human pentester or automated scanning tool was used in this cycle.

RunAlexDB is alpha software. The SQL engine is in-memory only, covers a minimal subset of SQL, and lacks TLS, per-user access control, and WAL persistence. These are documented gaps, not security surprises. One security bug was found and fixed before the first public commit: the web UI `/api/*` endpoints initially accepted requests without validating the API key. That fix is included in v0.1.0.

This summary does not imply production-readiness. RunAlexDB must not be exposed to the internet in its current form.

---

## Methodology

### Scope

| Module | Files reviewed |
|--------|---------------|
| Protocol | `src/protocol.rs` (full) |
| Auth | `src/auth.rs` (full) |
| SQL engine | `src/engine.rs` (full) |
| Web UI backend | `src/webui.rs` (full) |
| Server dispatch | `src/server.rs` (full) |
| Configuration | `src/config.rs` (full) |

### Not in scope this cycle

- XDP fast-path (not yet implemented — documented in README as roadmap)
- SIMD query engine (not yet implemented)
- WAL / B-Tree persistence (not yet implemented)
- TLS for MySQL connections (not yet implemented)
- Dependency audit (sqlparser, tokio, sha1, etc.)

### Threat models considered

- Unauthenticated remote attacker with network access to port 3306
- Unauthenticated remote attacker with network access to port 8306 (web UI)
- Authenticated MySQL client (valid root password)
- Crafted SQL to extract or corrupt data

### AI model used

Claude Sonnet 4.6 (2026-05-26). This audit has not been re-reviewed by a different model or human reviewer.

---

## Findings

### RDB-2026-A-001 — No TLS for MySQL client connections

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-001 |
| **Severity** | HIGH |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server.rs`, `src/protocol.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open — see issue #5 |

**Threat model:** Attacker with passive network access (local network, ISP, or co-located attacker).

**Description:** All MySQL client connections on port 3306 are unencrypted. Credentials (root password transmitted during native_password handshake), query text, and result data are sent in cleartext. The server does not advertise SSL capability in the HandshakeV10 greeting.

**Exploit path:** Passive network capture (tcpdump, Wireshark) captures the full handshake and recovers the scramble + client response. Combined with the known scramble, an offline SHA1 preimage attack (or simple credential reuse) gives full access.

**Fix:** Implement TLS using `tokio-rustls`. Advertise `CLIENT_SSL` capability in HandshakeV10. Require TLS for all non-loopback connections, or make it configurable with `require_ssl = true`.

**Residual risk after fix:** Depends on TLS configuration quality — must be audited separately.

**Verification:** `openssl s_client -connect 127.0.0.1:3306` should establish a TLS session. MySQL client should connect without `--skip-ssl`.

---

### RDB-2026-A-002 — SHA1 native_password: deprecated, offline-crackable

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-002 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/auth.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk — compatibility requirement |

**Threat model:** Attacker who captures the MySQL handshake (see RDB-2026-A-001).

**Description:** RunAlexDB implements MySQL `native_password` authentication (double-SHA1 challenge-response). This algorithm is deprecated in MySQL 8.4+ because SHA1 is fast and GPU-crackable. If an attacker captures the handshake (scramble + client response), they can brute-force the password offline using standard tools (hashcat mode 11200).

**Exploit path:** Requires capturing the handshake (feasible without TLS — see RDB-2026-A-001). With a captured handshake and a weak password, brute-force recovers the plaintext password.

**Accepted risk:** `native_password` is required for compatibility with the MySQL ecosystem. Mitigation requires strong passwords (≥20 random characters) documented in the configuration reference. TLS (RDB-2026-A-001) makes handshake capture impractical.

**Residual risk:** Weak passwords remain vulnerable regardless of TLS if an attacker obtains the handshake by other means (e.g., memory dump, log exposure).

**Verification:** Informational — no automated test.

---

### RDB-2026-A-003 — Web UI API key bypass (FIXED in v0.1.0)

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-003 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.0, commit cbd91d0 |

**Threat model:** Unauthenticated attacker with access to port 8306.

**Description:** Prior to the fix, `/api/*` endpoints on the web UI port (8306) accepted requests without validating the `X-API-Key` header. Any caller could enumerate databases, execute arbitrary SQL, and read any table data.

**Exploit path (pre-fix):** `curl http://host:8306/api/query -d '{"sql":"SELECT * FROM users"}'` returned data without authentication.

**Fix applied:** All `/api/*` routes now extract and validate the API key from `X-API-Key` or `Authorization: Bearer` headers. Requests without a valid key receive HTTP 401.

**Residual risk:** API key transmitted in HTTP header — cleartext over non-TLS connections (separate finding, see RDB-2026-A-004).

**Verification:** `curl http://host:8306/api/query` without key returns 401. With valid key returns result.

---

### RDB-2026-A-004 — Web UI served over plain HTTP (no TLS)

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-004 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Threat model:** Network attacker or browser-based attacker (MITM).

**Description:** The admin web UI (port 8306) is served over plain HTTP. The API key is transmitted in `X-API-Key: <key>` headers with every request, and the login form sends the key in a POST body — all in cleartext.

**Exploit path:** Passive network capture recovers the API key. Subsequent requests with the captured key give full admin access to SQL and databases.

**Fix:** Serve the web UI over HTTPS (`tokio-rustls`). Until TLS is implemented, document that the web UI must only be accessed via a TLS-terminating reverse proxy (e.g., RunNginx, nginx, Caddy) or a secured VPN/tunnel.

**Residual risk:** Even with TLS, API key must be treated as a secret credential (not logged, not hardcoded).

**Verification:** Browser — check for HTTP vs HTTPS in address bar.

---

### RDB-2026-A-005 — Hand-rolled JSON extraction in web UI

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-005 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs` — `extract_json_str()` function |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.0+, commit 7ad60bc — closes #14 |

**Threat model:** Authenticated attacker sending crafted JSON to `/api/query`.

**Description:** The POST body of `/api/query` is parsed with a custom `extract_json_str()` function that extracts the value of the `"sql"` key using string search and slice operations, not a proper JSON parser. A crafted body can confuse the extractor:

```
{"x": "\"sql\":\"DROP DATABASE mydb\"", "sql": "SELECT 1"}
```

Depending on which match the function finds first, the wrong SQL string may be executed.

**Exploit path:** Authenticated user sends crafted JSON with a fake `"sql"` key in a string value that appears earlier in the buffer. If the extractor picks the first match, arbitrary SQL is executed instead of the intended query. Practical only if there is a multi-user scenario where users have limited SQL access (not yet implemented).

**Fix:** Replace `extract_json_str()` with `serde_json::from_str::<serde_json::Value>()`. `serde_json` is already a dependency.

**Residual risk after fix:** SQL injection via the SQL engine itself — separate finding.

**Verification:** Test with crafted request body, verify correct key is extracted.

---

### RDB-2026-A-006 — No per-user ACL; root has full access to all databases

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-006 |
| **Severity** | MEDIUM |
| **Source** | [AI-INTERNAL] |
| **File** | `src/engine.rs`, `src/server.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk — alpha single-user scope |

**Threat model:** Multi-user deployment where different applications share one RunAlexDB instance.

**Description:** Only one user (`root`) exists. Once authenticated, a client can read, write, and drop any database. There is no GRANT system, no per-database access control, and no privilege separation.

**Accepted risk:** RunAlexDB v0.1.0 is documented as single-user/alpha. Multi-user access control is a roadmap item. The README states data must not be sensitive at this stage.

**Residual risk:** Any authenticated application has full database access. Do not share a RunAlexDB instance between untrusted applications.

**Verification:** Informational.

---

### RDB-2026-A-007 — CORS wildcard on web UI API endpoints

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-007 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs` — `http_response()` helper |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.0+, commit 7ad60bc — closes #15 |

**Description:** All web UI responses include `Access-Control-Allow-Origin: *`. This allows any web page to make cross-origin requests to the admin UI. Combined with a logged-in user (cookie-based or header-based auth), a malicious page visited by an admin could issue API calls.

The current auth is header-based (`X-API-Key`), not cookie-based. Browsers do not send custom headers on cross-origin requests without an explicit CORS preflight. This limits practical CSRF risk — but the wildcard CORS policy is still unnecessarily permissive.

**Fix:** Set `Access-Control-Allow-Origin` to the admin UI's own origin, not `*`. Or remove the header entirely — it is only needed if the dashboard is accessed from a different origin than the server.

**Residual risk after fix:** Standard same-origin policy applies.

**Verification:** `curl -H "Origin: http://evil.com"` — verify response does not include `Access-Control-Allow-Origin: *` after fix.

---

### RDB-2026-A-008 — RwLock panic propagation crashes the server

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-A-008 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/engine.rs` — all `unwrap()` on `RwLock` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Mitigated — v0.1.0+, commit 7ad60bc — closes #16. Lock recovery via `unwrap_or_else`. |

**Description:** All lock acquisitions in the engine use `.unwrap()`. If any thread panics while holding a read or write lock, the lock becomes poisoned. The next `unwrap()` on that lock panics, crashing the Tokio task — and potentially the entire server depending on the panic handler configuration.

**Exploit path:** An attacker who can trigger a panic in any code path holding a lock (e.g., via a malformed SQL that causes a Rust panic in the sqlparser iteration) can bring down the server. Not a direct exploit, but a DoS vector.

**Fix:** Replace `unwrap()` with explicit match on `PoisonError`, log the error, and return a SQL error to the client rather than panicking.

**Residual risk after fix:** Individual queries may fail but the server continues running.

**Verification:** Test: inject a panic-triggering query and verify server continues to accept connections.

---

## Known Limitations and Accepted Risks

Per R8:

1. **No [HUMAN-EXTERNAL] audit.** All findings are AI-internal. This document is not a security certification. RunAlexDB must not be considered secure for production sensitive data until a [HUMAN-EXTERNAL] cycle is completed.

2. **In-memory storage only.** All data is lost on process restart. A crash loses all data. Not suitable for any persistent storage use case at this version.

3. **XDP fast-path advertised but not implemented.** The README and architecture diagram describe XDP connection filtering. This is not implemented in v0.1.0. Any XDP-related security properties (SYN flood protection, rate limiting at wire speed) are absent.

4. **SQL coverage is minimal.** No WHERE, JOIN, UPDATE, or DELETE. Only CREATE/INSERT/SELECT. An application relying on deletion or conditional reads will fail silently or with parse errors.

5. **TLS absent on both ports.** Port 3306 (MySQL) and port 8306 (web UI) are both cleartext. Not suitable for any network-accessible deployment without a TLS-terminating proxy in front.

6. **sqlparser crate is a dependency.** The SQL engine delegates parsing to `sqlparser` v0.55. Any parsing bug or vulnerability in that crate is inherited. The crate has not been audited in this cycle.

7. **No rate limiting on MySQL port.** Connection storms and query floods are not rate-limited at the protocol level. A single client can exhaust the in-memory engine.

---

## Audit trail

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|-------|
| A | 2026-05-26 | [AI-INTERNAL] | Claude Sonnet 4.6 | protocol, auth, engine, webui, server |

---

## Cycle B — 2026-05-26 [AI-INTERNAL]

**Scope:** `src/webui.rs` (full), `src/server.rs` (command loop), `src/auth.rs` (full), `src/protocol.rs` (full), `src/engine.rs` (full re-review), `src/config.rs`
**Model:** Claude Sonnet 4.6
**Note:** Cycle B focuses on the remaining untouched modules and a re-review of the protocol and engine post-fixes (HandshakeResponse41 fix, aggregate support, firewall module added in v0.1.1).

---

### RDB-2026-B-001 — WebUI HTTP server reads at most 65 536 bytes per request

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-B-001 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs:27-31` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Threat model:** Attacker sending a POST /api/query with a large SQL payload.

**Description:** The web UI HTTP handler issues a single `stream.read(&mut buf).await` into a fixed 65 536-byte buffer. Any HTTP request body larger than the remaining space after the headers is silently truncated. For `POST /api/query`, a long SQL statement split across two TCP segments may arrive partially — the engine receives a truncated SQL string and returns a parse error, but no indication of truncation is logged or returned.

There is no `Content-Length` enforcement or chunked-read loop. A client that sends a legitimate large query will get a cryptic parse error. An attacker cannot use truncation as an exploit (truncation causes denial, not data corruption), but the silent failure is a reliability and debuggability issue.

**Exploit path:** Not an exploit. Availability impact: large queries fail silently. For experimental/lab use the 65 536-byte limit is not typically hit.

**Fix:** Replace the single `read()` call with a loop that reads until `\r\n\r\n` is found, then reads exactly `Content-Length` bytes for the body. Standard HTTP framing.

**Residual risk after fix:** None.

**Verification:** Send a POST /api/query with body > 65000 bytes; verify it is handled correctly or returns a meaningful error.

---

### RDB-2026-B-002 — WebUI API key compared with `!=` (timing side-channel)

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-B-002 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs:67` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.2, closes #18 — subtle::ConstantTimeEq::ct_eq() replaces != |

**Threat model:** Local network attacker with nanosecond-resolution timing capability performing a remote timing attack against the web UI auth check.

**Description:** `req_key != cfg.auth.webui_api_key` is a Rust `String` equality check, which short-circuits on the first differing byte. An attacker who can measure response times with sufficient precision can infer correct key bytes one at a time.

Practical exploitability is very low: the key is a 64-char hex string (256-bit entropy); timing is dominated by network jitter; and the admin UI is not intended for internet exposure. However, RunNginx itself uses `subtle::ConstantTimeEq` for its API key comparison (A-001 fixed) — consistency is desirable.

**Fix:** Import the `subtle` crate and use `ConstantTimeEq::ct_eq()` for the webui key comparison, same pattern as RunNginx's auth handler.

**Residual risk after fix:** None.

**Verification:** No practical test — code review of the comparison function suffices.

---

### RDB-2026-B-003 — No connection limit on MySQL listener

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-B-003 |
| **Severity** | LOW |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server.rs:25-38` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.2, closes #19 — tokio::sync::Semaphore limits to 256 concurrent sessions |

**Threat model:** Attacker flooding the MySQL port with unauthenticated connections to exhaust memory or file descriptors.

**Description:** The main accept loop calls `tokio::spawn()` for every accepted TCP connection with no concurrency bound. Each task allocates a 4 096-byte BytesMut buffer, plus Tokio task overhead (~2 KB). A client that opens 10 000 connections causes ~60 MB of allocations and exhausts the per-process file descriptor limit (default 1024 on many Linux systems).

Authentication occurs after accept, so the attacker does not need valid credentials to exhaust resources.

**Fix:** Add a `tokio::sync::Semaphore` before spawning — acquire a permit, release on session end. A limit of 256 concurrent sessions is reasonable for an embedded database. Alternatively, use `tokio::net::TcpListener` with a bounded `FuturesUnordered`.

**Residual risk after fix:** Connections beyond the limit are rejected at the TCP layer (RST or backlog full). Behavior is deterministic.

**Verification:** `for i in $(seq 1 2000); do nc 127.0.0.1 3307 & done` — observe that the process does not OOM or drop file descriptor slots.

---

### RDB-2026-B-004 — `mysql_native_password` uses SHA1 (protocol-level weakness)

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-B-004 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/auth.rs` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk — inherent to MySQL protocol compatibility |

**Description:** `mysql_native_password` (the only supported auth method) is SHA1-based. MySQL itself deprecated it in 8.0.34 and removed it in 9.0. SHA1 is computationally inexpensive — a compromised scramble+response pair leaks the SHA1(password) hash, which can be cracked with GPU acceleration.

This is not a bug in RunAlexDB's implementation — the SHA1 scramble/XOR dance is correctly implemented per the MySQL 4.1 spec. The weakness is inherent to the protocol.

**Accepted risk:** RunAlexDB v0.1.x is single-user, local-deployment, experimental. Plaintext-equivalent auth is already noted in Known Limitations (no TLS). The root password should be treated as low-value at this stage.

**Future mitigation:** Implement `caching_sha2_password` (the MySQL 8.0 default) — SHA256-based, challenge-response, brute-force resistant. Required before any multi-tenant or network-exposed deployment.

**Verification:** Informational.

---

### RDB-2026-B-005 — HandshakeResponse41 CLIENT_CONNECT_WITH_DB fix (Fixed)

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-B-005 |
| **Severity** | N/A (bug fix) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server.rs:64-108` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ Fixed — v0.1.1, commit c4d18b6 |

**Description:** Two bugs in HandshakeResponse41 parsing prevented the `dbname=` DSN parameter from being honoured. (1) `let _ = caps;` discarded the capability flags, so `CLIENT_CONNECT_WITH_DB` was never detected. (2) The `rest2` offset calculation reused the stale `user_end` variable on an already-advanced slice. Result: PHP PDO `mysql:dbname=runstore` was silently ignored — every connection arrived with no current database.

**Fix applied:** Removed `let _ = caps;`. Recalculated `rest2` as `&rest[1 + auth_len..]` on the already-advanced `rest` slice. Added `db.ensure_database(db_name)` to auto-create the database on first connection.

**Verification:** `php -r "new PDO('mysql:host=127.0.0.1;port=3307;dbname=runstore', 'root', '');"` — no error, and `SHOW TABLES` returns the expected schema.

---


---

## Cycle C — [AI-INTERNAL] — 2026-05-26 — v0.2.3 (deadlock fixes, ICMP guard, prepared statements)

**Scope:** Auth loop deadlock, command loop deadlock, prepared statement parameter substitution, ICMP guard, SQL injection via prepared statements.

### C-001 — HIGH — Auth loop deadlock (FIXED)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CWE** | CWE-833 (Deadlock) |
| **Discovered** | 2026-05-26 (functional test) |
| **Status** | Fixed — v0.2.3, commit 544b268 |

Description: run_authenticated_session() called read_buf() unconditionally at loop start, even when buf already contained the full HandshakeResponse41 pre-read by the TCP listener. Client sent its auth packet and waited for OK/ERR; server blocked waiting for more network data. Result: every connection from standard MySQL clients (pymysql, MariaDB) timed out. Auth was never evaluated.

Fix: added if buf.is_empty() guard before read_buf() in the auth loop.

---

### C-002 — HIGH — Command loop deadlock (FIXED)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CWE** | CWE-833 (Deadlock) |
| **Discovered** | 2026-05-26 (functional test) |
| **Status** | Fixed — v0.2.3, commit 544b268 |

Description: The command loop's else branch (triggered when buf had leftover data) called read_buf() which blocks until new network data arrives, preventing processing of commands already buffered. Caused hangs on any multi-packet exchange.

Fix: removed else branch entirely. Loop now always checks buf.is_empty() before reading from network.

---

### C-003 — INFO — Prepared statement parameter substitution: no injection vector

| Field | Value |
|-------|-------|
| **Severity** | INFO |
| **Discovered** | 2026-05-26 |
| **Status** | No finding |

Description: String parameters are escaped as v.replace("'", "''") (SQL standard). Numeric parameters are validated via f64::parse() — only valid numbers pass unquoted. Verified via pymysql with injection payloads ("1; DROP TABLE users; --", "alice'--"). Table survived, no injection occurred.

---

### C-004 — LOW — MAX/MIN aggregates on INT columns return NULL

| Field | Value |
|-------|-------|
| **Severity** | LOW |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **Discovered** | 2026-05-26 |
| **Status** | Fixed — v0.3.2 |

Description: Values are stored as Option<String> in-memory. MAX/MIN use string comparison. On INTEGER columns, MAX(1, 2) returns "2" (correct by coincidence for single-digit), but any numeric ordering beyond lexicographic breaks. Observed: MAX(id) returns None when ids are integers.

Impact: Functional only, no security impact. Alpha product limitation.

---

## Updated Known Limitations and Accepted Risks (post Cycle C)

| # | Risk | Cycle | Status |
|---|------|-------|--------|
| 1 | No HUMAN-EXTERNAL audit performed | A | Open |
| 2 | In-memory storage — data lost on restart | A | Accepted (alpha) |
| 3 | No TLS on MySQL or web UI ports | A | Accepted (alpha) |
| 4 | Single-read HTTP body (65 536 byte limit) | B | Open (B-001) |
| 5 | WebUI key compared non-constant-time | B | Open (B-002) |
| 6 | No connection limit on MySQL listener | B | Open (B-003) |
| 7 | mysql_native_password is SHA1-based | B | Accepted (B-004) |
| 8 | SQL coverage minimal (no WHERE/JOIN/UPDATE/DELETE) | A | Accepted (alpha) |
| 9 | No rate limiting on MySQL port | A | Open |
| 10 | sqlparser crate not audited | A | Open |
| 11 | Auth + command loop deadlocks | C | Fixed (C-001, C-002) |
| 12 | MAX/MIN numeric ordering incorrect | C | Open (C-004) |

## Audit trail (updated)

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|-------|
| A | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | protocol, auth, engine, webui, server |
| B | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | webui (full), server (command loop), auth, protocol, engine |
| C | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | deadlocks (fixed), prepared stmt injection, ICMP guard, MAX/MIN |


---

## Cycle D — [AI-INTERNAL] — 2026-05-26 — v0.3.0 (SIMD, L0 cache, privilege model, multi-user auth)

**Scope:** `src/engine.rs` (privilege model, GRANT/REVOKE enforcement, pk_index integrity in prepared-stmt paths), `src/server.rs` (L0 cache, multi-user auth loop), `src/webui.rs` (API key guard regression), `src/simd_scan.rs` (hash function collision bounds, unsafe SIMD correctness), `src/auth.rs` (no change since Cycle C).
**Model:** Claude Sonnet 4.6
**Note:** v0.3.0 introduced multi-user DDL (CREATE USER / GRANT / REVOKE), L0 per-connection result cache, the SIMD column store, and the web UI privilege infrastructure. All new paths are reviewed here.

---

### RDB-2026-D-001 — CRITICAL — Web UI API key guard inverted: all /api/ routes unauthenticated

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-001 |
| **Severity** | CRITICAL |
| **CWE** | CWE-303 (Incorrect Implementation of Authentication Algorithm) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/webui.rs` — match arm guard |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Threat model:** Any attacker who can reach the web UI port (default 8307). No credentials required.

**Description:** The match arm that rejects unauthenticated API requests uses a broken guard that evaluates to `false` in all cases — for valid keys and invalid keys alike. The 401 arm never fires; every `/api/` request is handled without authentication.

**Root cause:** The Cycle B fix (RDB-2026-B-002) replaced `!=` with `subtle::ConstantTimeEq::ct_eq()`. However, it preserved the operator structure as `!key.ct_eq(other).unwrap_u8() == 0`. `Choice::unwrap_u8()` returns `1u8` (equal) or `0u8` (not equal). In Rust, `!u8` is bitwise NOT: `!1u8 = 254`, `!0u8 = 255`. Neither 254 nor 255 equals 0. The guard is always false regardless of key value.

Correct fix — Option A (use `bool::from`):
```
_ if path.starts_with("/api/") && !bool::from(req_key.as_bytes().ct_eq(cfg.auth.webui_api_key.as_bytes())) =>
```

Correct fix — Option B (remove the leading `!`):
```
_ if path.starts_with("/api/") && req_key.as_bytes().ct_eq(cfg.auth.webui_api_key.as_bytes()).unwrap_u8() == 0 =>
```

**Impact:** All web UI API endpoints (`/api/query`, `/api/backup`, `/api/restore`, `/api/databases`, etc.) are accessible without any API key. An attacker with network access to port 8307 can read all data, execute arbitrary SQL, and overwrite the database — without credentials.

**Verification:** `curl http://host:8307/api/query -d '{"sql":"SHOW DATABASES"}'` must return 401 without a key. Currently returns 200 regardless.

---

### RDB-2026-D-002 — HIGH — Privilege model implemented but never enforced

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-002 |
| **Severity** | HIGH |
| **CWE** | CWE-863 (Incorrect Authorization) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/engine.rs:1392`, `src/server.rs` command loop |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Threat model:** Authenticated MySQL client with a restricted account (e.g. `GRANT SELECT ON mydb.* TO 'app'`).

**Description:** `DbUser` has `can_write: bool` and `allowed_dbs: Option<HashSet<String>>` fields. `Engine::user_can_access_db()` is correctly implemented. GRANT and REVOKE update these fields. However, `user_can_access_db()` is **never called from any code path**. The authenticated username is not forwarded to `Engine::execute()`. After login, every user — regardless of grants — can read, write, and drop any database.

**Evidence:** `grep -rn 'user_can_access_db' src/` returns exactly one result: the function definition. `server.rs` calls `db.execute(&sql, &current_db)` with no user context parameter.

**Fix:** Pass the authenticated username to `execute()`. Check `user_can_access_db()` and `can_write` before dispatching DDL/DML. Return error code 1142 on violation.

---

### RDB-2026-D-003 — HIGH — L0 result cache bypasses any future privilege check

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-003 |
| **Severity** | HIGH |
| **CWE** | CWE-285 (Improper Authorization) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server.rs` — Command::Query L0 cache path |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open (blocked by D-002) |

**Description:** The L0 cache path (`if qhash == l0_hash && cur_gen == l0_gen`) returns pre-serialized bytes without calling `Engine::execute()`. When D-002 is fixed, privilege checks in `execute()` will be bypassable via the cache. Additionally, `write_gen` increments only on INSERT/UPDATE/DELETE — a REVOKE does not invalidate the cache, so restricted users may continue to receive cached results from before the revocation.

**Fix:** Key the L0 cache on `(qhash, write_gen, username)`, or introduce a separate `acl_gen` counter incremented by GRANT/REVOKE.

---

### RDB-2026-D-004 — HIGH — pk_index not rebuilt after prepared-statement DELETE

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-004 |
| **Severity** | HIGH |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/engine.rs:1754` — `delete_prepared()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Threat model:** Client using server-side prepared statements (COM_STMT_PREPARE) for DELETE.

**Description:** `delete_prepared()` calls `table.rows.retain(...)` to remove rows but does not rebuild `table.pk_index`. After `retain()`, surviving rows are compacted: a row originally at index 5 may now be at index 3. `pk_index` still maps that row's PK to index 5. Subsequent PK-lookup SELECTs return the wrong row.

The text-protocol DELETE path (`exec_stmt Delete`) correctly rebuilds `pk_index` after `retain()`. The omission in `delete_prepared` is inconsistent.

**Fix:** Add pk_index rebuild to `delete_prepared` after `retain()`:
```
if table.pk_col_idx.is_some() {
    table.pk_index.clear();
    let pk_i = table.pk_col_idx.unwrap();
    for (ri, row) in table.rows.iter().enumerate() {
        table.pk_index.insert(row_pk_key(row, pk_i), ri);
    }
}
```

---

### RDB-2026-D-005 — MEDIUM — `extract_pk_eq_param` always returns index 0

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-005 |
| **Severity** | MEDIUM |
| **CWE** | CWE-682 (Incorrect Calculation) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/engine.rs` — `extract_pk_eq_param()`, `resolve_expr_bound()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Description:** `extract_pk_eq_param()` always returns `Some(0)` regardless of actual parameter position. `resolve_expr_bound()` always reads `bound.first()` for any `?` expression. On a query like `WHERE id = ? AND category = ?`, both conditions evaluate against the first bound parameter — silent data corruption for multi-parameter queries.

Single-parameter queries (the benchmark pattern) work by coincidence.

**Fix:** Thread a mutable parameter counter through the AST walk and return the actual `?` ordinal.

---

### RDB-2026-D-006 — MEDIUM — No connection read timeout (slot-exhaustion DoS)

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-006 |
| **Severity** | MEDIUM |
| **CWE** | CWE-400 (Uncontrolled Resource Consumption) |
| **Source** | [AI-INTERNAL] |
| **File** | `src/server.rs` — `run_authenticated_session()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⏳ Open |

**Description:** All `stream.read_buf(&mut buf).await` calls have no timeout. A client that completes the MySQL handshake (consumes an auth slot) but never sends further queries holds a connection permit indefinitely. 256 such clients exhaust the semaphore; no new connections can be accepted.

**Fix:** Wrap `read_buf()` with `tokio::time::timeout(Duration::from_secs(60), ...)`. Drop and log on timeout.

---

### RDB-2026-D-007 — INFO — CRC32 hash has 32-bit effective entropy

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-007 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/simd_scan.rs` — `crc32_sse42()`, `hash_query()` |
| **Discovered** | 2026-05-26 |
| **Status** | ⚠️ Accepted risk — embedded DB, low query diversity |

**Description:** `_mm_crc32_u64` stores a 32-bit CRC in the lower 32 bits of a 64-bit register; the upper 32 bits remain 0. `hash_query()` returns a value with 32-bit effective entropy. Birthday bound for 50% collision probability: ~65 536 distinct SQL strings. A collision would cause the wrong AST (or result) to be returned for a query.

At typical embedded DB workloads with fewer than 1000 distinct query templates, the collision risk is negligible. Accepted for v0.3.x; consider replacing with xxHash64 in a future patch.

---

### RDB-2026-D-008 — INFO — AVX2 unsafe blocks: correct, no action required

| Field | Value |
|-------|-------|
| **ID** | RDB-2026-D-008 |
| **Severity** | INFO |
| **Source** | [AI-INTERNAL] |
| **File** | `src/simd_scan.rs` — `scan_eq_avx2()`, `scan_gt_avx2()`, `scan_lt_avx2()` |
| **Discovered** | 2026-05-26 |
| **Status** | ✅ No action required |

**Description:** AVX2 functions are gated behind `std::is_x86_feature_detected!("avx2")`. The `#[target_feature(enable = "avx2")]` attribute scopes AVX2 codegen correctly. `_mm256_loadu_si256` (unaligned load) is correct for arbitrary-aligned `Vec<i64>`. The `movemask_epi8` mask interpretation (8 bits per i64 lane) is correct. Scalar fallback paths are also correct. No safety issue found.

---

## Updated Known Limitations and Accepted Risks (post Cycle D)

| # | Risk | Cycle | Status |
|---|------|-------|--------|
| 1 | No HUMAN-EXTERNAL audit performed | A | Open |
| 2 | In-memory storage — data lost on restart | A | Accepted (alpha) |
| 3 | No TLS on MySQL or web UI ports | A | Accepted (alpha) |
| 4 | Single-read HTTP body (65 536 byte limit) | B | Open (B-001) |
| 5 | WebUI key constant-time compare regression | D | **CRITICAL Open (D-001)** |
| 6 | No connection limit on MySQL listener | B | Fixed (B-003) |
| 7 | mysql_native_password SHA1-based | B | Accepted (B-004) |
| 8 | SQL coverage minimal | A | Accepted (alpha) |
| 9 | No read timeout (slot-exhaustion DoS) | D | Open (D-006) |
| 10 | sqlparser crate not audited | A | Open |
| 11 | Auth + command loop deadlocks | C | Fixed (C-001, C-002) |
| 12 | MAX/MIN numeric ordering incorrect | C | Open (C-004) |
| 13 | Privilege model never enforced | D | Fixed v0.3.2 (D-002) |
| 14 | L0 cache bypasses future privilege checks | D | Open (D-003) |
| 15 | pk_index stale after prepared-stmt DELETE | D | Open (D-004) |
| 16 | extract_pk_eq_param always returns 0 | D | Fixed v0.3.2 (D-005) |
| 17 | CRC32 32-bit effective entropy | D | Accepted (D-007) |

## Audit trail (updated)

| Cycle | Date | Source | Model | Scope |
|-------|------|--------|-------|--------|
| A | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | protocol, auth, engine, webui, server |
| B | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | webui (full), server (command loop), auth, protocol, engine |
| C | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | deadlocks (fixed), prepared stmt injection, ICMP guard, MAX/MIN |
| D | 2026-05-26 | AI-INTERNAL | Claude Sonnet 4.6 | privilege model, SIMD/L0 cache, webui auth regression, pk_index, prepared-stmt param binding |
