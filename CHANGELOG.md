# Changelog — RunAlexDB

## [0.1.4] — 2026-05-26

### Added

- **INFORMATION_SCHEMA.TABLES**: returns table list with schema, name, type, engine, and row count. Compatible with DBeaver, phpMyAdmin, Adminer, MySQL Workbench.
- **INFORMATION_SCHEMA.COLUMNS**: returns column list with name, position, type, nullability, and key info. Used by ORM tools for schema introspection.
- **INFORMATION_SCHEMA.SCHEMATA**: returns database list.
- **SHOW VARIABLES / SHOW SESSION VARIABLES**: returns common MySQL variables (charset, max_allowed_packet, timeouts, sql_mode) — satisfies client connection handshakes.
- **SHOW STATUS / SHOW GLOBAL STATUS**: returns basic status (Uptime, Threads_connected).
- **SET / BEGIN / COMMIT / ROLLBACK**: silently accepted and return OK — allows applications using transaction wrappers to connect without errors.

---

## [0.1.3] — 2026-05-26

### Added

- **WHERE clause**: Full expression evaluator — `=`, `!=`, `<`, `<=`, `>`, `>=`, `AND`, `OR`, `NOT`, `IS NULL`, `IS NOT NULL`, `LIKE` (% and _ wildcards), `BETWEEN`, `IN (...)`.
- **Column projection**: `SELECT col1, col2 FROM table` — previously only `SELECT *` was supported. Alias supported: `SELECT col AS alias`.
- **ORDER BY**: `ORDER BY col [ASC|DESC]`. Numeric columns sorted numerically.
- **LIMIT / OFFSET**: `SELECT ... LIMIT n OFFSET m`.
- **UPDATE**: `UPDATE table SET col = val [WHERE ...]` — returns affected row count.
- **DELETE**: `DELETE FROM table [WHERE ...]` — returns affected row count.

### Fixed

- Aggregate match patterns corrected to string literals (`"COUNT"`, `"MAX"`, `"MIN"`, `"SUM"`) — bare identifiers caused COUNT to always match first regardless of function name.
- Aggregates respect WHERE filter when present.

---

## [0.1.2] — 2026-05-26

### Security

- **B-002 fixed**: WebUI API key comparison now uses `subtle::ConstantTimeEq::ct_eq()` — prevents timing side-channel — closes #18.
- **B-003 fixed**: MySQL listener bounded to 256 concurrent sessions via `tokio::sync::Semaphore` — prevents connection-storm DoS — closes #19.

### Fixed

- Aggregate function match patterns changed from bare identifiers to string literals (`"COUNT"`, `"MAX"`, `"MIN"`, `"SUM"`).

---

## [0.1.1] — 2026-05-26

### Added

- **Firewall auto-management**: RunAlexDB opens `mysql_port` and `webui_port` at startup and closes them on shutdown. Detects and uses ufw, nftables, or iptables automatically. Rules are tagged (`# runalexdb` or configurable via `firewall_tag`). Config keys: `firewall_manage`, `firewall_backend`, `firewall_tag`.
- **Aggregate functions**: `COUNT(*)`, `MAX(col)`, `MIN(col)`, `SUM(col)` now return correct single-row results. Previously aggregate-only projections returned raw rows.
- **install.sh**: One-command installer — downloads binary, creates system user, writes default config with generated credentials, installs and starts systemd unit.

### Fixed

- **`CLIENT_CONNECT_WITH_DB` not parsed** (closes #18): Two bugs in `HandshakeResponse41` parsing prevented `dbname=` in the DSN from being honoured. (1) `let _ = caps;` discarded capability flags — `CLIENT_CONNECT_WITH_DB` was never detected. (2) The `rest2` offset calculation reused a stale variable on an already-advanced slice. Result: every PHP PDO connection with `mysql:dbname=X` arrived with no selected database.
- **`ensure_database()` auto-creates database on first connect** (closes #19): If the database named in the handshake does not exist in the engine, it is created automatically. Prevents "Unknown database" errors after a daemon restart when the application seeded data in a previous run.

---

## [0.1.0] — 2026-05-26

### Initial release

- MySQL wire protocol v4.1 — HandshakeV10 greeting, `mysql_native_password` auth, COM_QUERY/COM_PING/COM_QUIT/COM_INIT_DB dispatch
- In-memory SQL engine — `CREATE DATABASE`, `CREATE TABLE`, `INSERT INTO`, `SELECT`, `SHOW DATABASES`, `SHOW TABLES`, `USE db`
- Admin web UI on configurable port (default 8306) — SQL console, database browser, system info
- REST API — `GET /api/system`, `GET /api/databases`, `POST /api/query`
- Security fixes: serde_json request parsing, CORS wildcard removed, RwLock poison recovery, server-side API key validation on all /api/* routes
- CI: 4 release targets — x86_64/aarch64 × gnu/musl
