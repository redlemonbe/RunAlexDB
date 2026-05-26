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
| **Status** | ⏳ Open |

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
| **Status** | ⏳ Open |

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
| **Status** | ⏳ Open |

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
