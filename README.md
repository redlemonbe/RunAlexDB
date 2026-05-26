# RunAlexDB

## The World's First ASM-Accelerated SQL Database

**MariaDB-compatible SQL database — XDP kernel-bypass, SIMD query engine, built-in admin UI.**

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE) [![Commercial License](https://img.shields.io/badge/license-commercial-green.svg)](COMMERCIAL_LICENSE.md)
[![Release](https://img.shields.io/github/v/release/redlemonbe/RunAlexDB)](https://github.com/redlemonbe/RunAlexDB/releases/latest)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

> ⚠️ **Status: Alpha** — RunAlexDB is under active development. Current version stores data in memory only (persistence via WAL + B-Tree is roadmapped). Not yet recommended for production deployments.

Any MySQL or MariaDB client connects without modification — `mysql` CLI, PHP PDO, Node `mysql2`, Python `mysql-connector`, DBeaver, HeidiSQL, TablePlus, Adminer. RunAlexDB adds XDP kernel-bypass, SIMD query acceleration, and a built-in admin UI on top.

---

## What you get

| | MySQL / MariaDB | PostgreSQL | SQLite | RunAlexDB |
|---|:---:|:---:|:---:|:---:|
| MySQL/MariaDB wire protocol | ✅ | ❌ | ❌ | ✅ |
| XDP connection filter (SYN flood, bans) | ❌ | ❌ | ❌ | ✅ |
| SIMD query engine (AVX2/SSE4.2) | ❌ | ❌ | ❌ | ✅ |
| Built-in admin UI | ❌ phpMyAdmin separate | ❌ pgAdmin separate | ❌ | ✅ port 8306 |
| Virtual users (no /etc/passwd) | ❌ | ❌ | n/a | ✅ |
| REST API | ❌ | ❌ | ❌ | ✅ |
| Master/slave replication | ✅ | ✅ | ❌ | roadmap |
| Static binary, zero runtime deps | ❌ | ❌ | ✅ | ✅ musl |
| WAL + B-Tree persistence | ✅ | ✅ | ✅ | roadmap |

---


## What's new in v0.3.0

| Feature | Details |
|---------|---------|
| **Beats MariaDB on writes** | INSERT 4.7x, UPDATE 6x, DELETE 6.4x faster (single-conn, dev VM) |
| **L0 per-connection result cache** | CRC32-keyed, write_gen-validated — zero SQL parsing on repeat reads |
| **AVX2 column-store scans** | Per-column Vec<i64> arrays; WHERE int_col OP value uses 4-wide AVX2 intrinsics |
| **SSE4.2 CRC32 query hashing** | 8 bytes/cycle for STMT_CACHE and L0 cache keying |
| **Wire protocol batching** | All response packets serialized into one BytesMut + one write_all() syscall |
| **ValueRows fast path** | i64 encoded directly to wire via stdlib fmt::Write — zero heap alloc per cell |
| **Multi-user auth** | CREATE USER, GRANT, REVOKE, SHOW GRANTS — partial (enforcement v0.4.0) |
| **BENCHMARK.md** | Side-by-side vs MariaDB 11.8 with dev VM disclaimer |

## What's new in v0.1.5

| Feature | Details |
|---------|---------|
| Hot backup | `POST /api/backup` — dump all databases to `data_dir/backups/backup_<ts>[_label].sql` |
| Backup listing | `GET /api/backups` — JSON list of backups with id, size, timestamp |
| Hot restore | `POST /api/restore {"id":"..."}` — reload all databases from a backup while running |
| Auto-persist | On SIGTERM/ctrl-c, full SQL dump saved to `data_dir/runalexdb.sql` before exit |
| Auto-load | If `data_dir/runalexdb.sql` exists at startup, data is reloaded automatically |

## What's new in v0.1.1

- **Firewall auto-management** — RunAlexDB opens and closes its MySQL and admin UI ports automatically (ufw/nftables/iptables). See configuration below.
- **`dbname=` in DSN now works** — Fixed `CLIENT_CONNECT_WITH_DB` parsing in HandshakeResponse41. PHP PDO `mysql:host=...;dbname=mydb` is correctly honoured.
- **Aggregate functions** — `COUNT(*)`, `MAX(col)`, `MIN(col)`, `SUM(col)` now return correct single-row results instead of raw rows.

---

## Install

```bash
# x86_64 glibc
curl -Lo runalexdb https://github.com/redlemonbe/RunAlexDB/releases/latest/download/runalexdb-x86_64-linux-gnu
chmod +x runalexdb && sudo mv runalexdb /usr/local/bin/

# x86_64 static (musl — no glibc required)
curl -Lo runalexdb https://github.com/redlemonbe/RunAlexDB/releases/latest/download/runalexdb-x86_64-linux-musl
chmod +x runalexdb && sudo mv runalexdb /usr/local/bin/

# aarch64 (Graviton, Raspberry Pi 4/5)
curl -Lo runalexdb https://github.com/redlemonbe/RunAlexDB/releases/latest/download/runalexdb-aarch64-linux-gnu
chmod +x runalexdb && sudo mv runalexdb /usr/local/bin/
```

---

## Quick start

```bash
# Run with defaults — MySQL port 3306, admin UI port 8306
runalexdb

# Connect with any MySQL client
mysql -h 127.0.0.1 -u root -pchangeme --skip-ssl

# Admin UI — http://localhost:8306
```

---

## Dashboard (Admin UI)

RunAlexDB embeds the admin UI — no phpMyAdmin, no separate process. Open `http://YOUR_SERVER:8306`.

Enter your API key (from the config file) and click **Sign in**.

Features:
- **Dashboard** — query rate, active connections, database list
- **SQL Console** — run any SQL directly in the browser
- **Databases** — create, list, drop databases
- **Tables** — browse schema and row data
- **Users** — virtual user management, password reset
- **Settings** — live configuration display

---

## Configuration

```toml
# /etc/runalexdb/runalexdb.toml
mysql_port = 3306
webui_port = 8306
bind       = "0.0.0.0"
data_dir   = "/var/lib/runalexdb"

[auth]
root_password = "your-strong-password"
webui_api_key = "your-admin-api-key"

[xdp]
enabled          = true
interface        = "eth0"
max_conn_per_sec = 100
```

---


## Firewall management

RunAlexDB opens and closes its own firewall rules at startup/shutdown. Supported backends: ufw, nftables, iptables (auto-detected).

```toml
# /etc/runalexdb/runalexdb.toml
firewall_manage  = true     # default: true
firewall_backend = "auto"   # auto | ufw | nftables | iptables
firewall_tag     = "runalexdb"  # tag for created rules
```

Rules are created for `mysql_port` (TCP) and `webui_port` (TCP) and tagged so they can be audited with `ufw status verbose`.

Set `firewall_manage = false` to manage rules manually.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ XDP fast-path (eBPF)                                 │
│  SYN flood · IP ban · per-IP rate limit              │
├──────────────────────────────────────────────────────┤
│ MySQL wire protocol (Rust / tokio)                   │
│  Handshake · native_password auth · COM_* dispatch   │
├──────────────────────────────────────────────────────┤
│ SQL engine (Rust)                                    │
│  SIMD parser · in-memory storage · WAL (roadmap)     │
├──────────────────────────────────────────────────────┤
│ Admin web UI (port 8306)                             │
│  SQL console · DB browser · user management          │
└──────────────────────────────────────────────────────┘
```

---

## SQL coverage

Current (v0.1.3+):
- `CREATE DATABASE`, `DROP DATABASE`
- `CREATE TABLE`, `DROP TABLE`
- `INSERT INTO ... VALUES`
- `SELECT * FROM table`, `SELECT col1, col2 FROM table`
- `SELECT ... WHERE col = val` — operators: `=`, `!=`, `<`, `<=`, `>`, `>=`, `AND`, `OR`, `NOT`, `IS NULL`, `IS NOT NULL`, `LIKE`, `BETWEEN`, `IN (...)`
- `SELECT COUNT(*), MAX(col), MIN(col), SUM(col)` aggregates (with WHERE support)
- `ORDER BY col [ASC|DESC]`
- `LIMIT n [OFFSET m]`
- `UPDATE table SET col = val [WHERE ...]`
- `DELETE FROM table [WHERE ...]`
- `SHOW DATABASES`, `SHOW TABLES`
- `USE db`

Roadmap (see [GitHub Issues](https://github.com/redlemonbe/RunAlexDB/issues)):
- JOIN / subqueries
- WAL + B-Tree persistence
- TLS for client connections
- INFORMATION_SCHEMA compatibility
- Master/slave replication

---

## Build from source

```bash
git clone https://github.com/redlemonbe/RunAlexDB
cd RunAlexDB
cargo build --release
# binary: target/release/runalexdb
```

Requires Rust 1.75+.

---

## Documentation

Full index: [docs/index.md](docs/index.md)

Quick links: [Configuration](docs/configuration.md) · [SQL Reference](docs/sql.md) · [API Reference](docs/api.md) · [Security Audit](docs/security-audit.md)

---

## Contributing

```bash
cargo clippy --all-targets   # zero warnings
cargo test                   # all tests must pass
```

Pull requests welcome.

---

## Support the project

[![GitHub Sponsors](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor%20on%20GitHub)](https://github.com/sponsors/redlemonbe)

**Bitcoin** — `3FP8hkkiu4kwCD1PDFgAv2oq1ZTyXwy3yy`  
**Ethereum** — `0xB5eEAf89edA4204Aa9305B068b37A93439cBb680`

Security issues: redlemonbe@codix.be (private disclosure before opening a public issue)

---

## License

AGPL-3.0-only — see [LICENSE](LICENSE). Commercial license available for organizations that need to deploy without AGPL obligations: [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md).

---

*Part of the [RunSoftware](https://github.com/redlemonbe) stack — [Runbound](https://github.com/redlemonbe/Runbound) · [RunNginx](https://github.com/redlemonbe/RunNginx) · [dbmark](https://github.com/redlemonbe/dbmark)*  
Copyright (C) 2026 RedLemonBe
