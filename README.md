# RunAlexDB

High-performance SQL database — MySQL/MariaDB wire protocol, XDP fast-path, SIMD query engine.  
Drop-in MariaDB replacement. Built-in admin UI. Static binary. No dependencies.

[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)
[![Release](https://img.shields.io/github/v/release/redlemonbe/RunAlexDB)](https://github.com/redlemonbe/RunAlexDB/releases/latest)

> **Part of the [RunSoftware](https://github.com/redlemonbe) ecosystem.**  
> Native integration with [RunNginx](https://github.com/redlemonbe/RunNginx) and [Runbound](https://github.com/redlemonbe/Runbound).

---

## Features

- **100% MySQL/MariaDB wire protocol** — any MySQL client, ORM, or tool connects without modification
- **XDP fast-path** — eBPF/XDP connection filter: SYN flood, rate limiting, IP banning at wire speed
- **SIMD query engine** — AVX2/SSE4.2 for string comparison, CRC32c for index hashing
- **Built-in admin UI** — SQL console, database browser, user management (port 8306)
- **No system accounts** — virtual users, no /etc/passwd entries
- **Static binary** — single file, no runtime dependencies, runs anywhere

---

## Quick start

```bash
# Install
curl -Lo runalexdb https://github.com/redlemonbe/RunAlexDB/releases/latest/download/runalexdb-x86_64-linux-gnu
chmod +x runalexdb && sudo mv runalexdb /usr/local/bin/

# Run with defaults (MySQL port 3306, admin UI port 8306)
runalexdb

# Connect with any MySQL client
mysql -h 127.0.0.1 -u root -pchangeme --skip-ssl

# Admin UI
open http://localhost:8306
```

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
enabled         = true
interface       = "eth0"
max_conn_per_sec = 100
```

---

## Compatibility

RunAlexDB implements the MySQL 4.1 wire protocol.  
Works with: `mysql` CLI, MariaDB CLI, Python `mysql-connector`, PHP `PDO_MYSQL`, Node `mysql2`, Go `go-sql-driver`, `JDBC`, DBeaver, HeidiSQL, TablePlus, Adminer.

---

## Architecture

```
┌──────────────────────────────────────────────────────┐
│ XDP fast-path (eBPF)                                 │
│  SYN flood · IP ban · per-IP rate limit              │
├──────────────────────────────────────────────────────┤
│ MySQL wire protocol (Rust / tokio)                   │
│  Handshake · Auth (native_password) · COM_* dispatch │
├──────────────────────────────────────────────────────┤
│ SQL engine (Rust)                                    │
│  sqlparser · B-Tree storage · MVCC · WAL             │
├──────────────────────────────────────────────────────┤
│ Admin web UI (port 8306)                             │
│  SQL console · DB browser · user management          │
└──────────────────────────────────────────────────────┘
```

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

## Contributing

`cargo clippy --all-targets` — zero warnings  
`cargo test` — all tests must pass

---

## Support

[![Sponsor](https://img.shields.io/github/sponsors/redlemonbe?style=flat&logo=github&label=Sponsor)](https://github.com/sponsors/redlemonbe)

**Bitcoin** — `3FP8hkkiu4kwCD1PDFgAv2oq1ZTyXwy3yy`  
**Ethereum** — `0xB5eEAf89edA4204Aa9305B068b37A93439cBb680`

Security issues: redlemonbe@codix.be (private disclosure before opening a public issue)

---

## License

AGPL-3.0-only — see [LICENSE](LICENSE)

Any use of RunAlexDB as part of a network service requires making the full source code
available to users of that service, under the same license.

*Part of the RunSoftware stack — [RunNginx](https://github.com/redlemonbe/RunNginx) · [Runbound](https://github.com/redlemonbe/Runbound) · [dnsmark](https://github.com/redlemonbe/dnsmark) · [httpmark](https://github.com/redlemonbe/httpmark)*  
Copyright (C) 2026 RedLemonBe
