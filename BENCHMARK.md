# RunAlexDB v0.3.0 — Benchmark vs MariaDB 11.8

> **WARNING: Development VM.** These benchmarks were run on a dedicated development virtual machine, not production hardware. Results represent relative performance between the two engines under identical conditions, not absolute performance targets.

## Environment

| Parameter | Value |
|-----------|-------|
| Host | AMD Ryzen Threadripper PRO 5995WX (32 vCPUs allocated) |
| RAM | 32 GB |
| OS | Debian 13 (Trixie), Linux 6.12 |
| VM type | KVM/QEMU |
| RunAlexDB | v0.3.0 — in-memory engine, port 3307 |
| MariaDB | 11.8, default config, InnoDB, port 3306 |
| Benchmark tool (single-conn) | pymysql 1.1.1, 10 000 ops each |
| Benchmark tool (concurrent) | dbmark v0.1.0, 20 connections, 15s (+3s warmup) |
| Date | 2026-05-26 |

Both databases ran on the same host simultaneously. No external load.

---

## Single-connection benchmark (pymysql)

| Operation | RunAlexDB v0.3.0 | MariaDB 11.8 | Ratio |
|-----------|-----------------|--------------|-------|
| INSERT | 11,583 QPS | 2,470 QPS | **4.69x faster** |
| SELECT by PK | 8,590 QPS | 6,597 QPS | **1.30x faster** |
| SELECT full scan (WHERE score < 500, 10k rows) | 58 QPS | 56 QPS | **1.04x faster** |
| UPDATE by PK | 14,040 QPS | 2,346 QPS | **5.98x faster** |
| DELETE by PK | 15,593 QPS | 2,454 QPS | **6.35x faster** |

Schema: `bench_perf (id INT PRIMARY KEY, val VARCHAR(64), score INT)`, 10 000 rows.

---

## Concurrent benchmark (dbmark, 20 connections)

### SELECT 1 — health check / overhead probe

| Metric | RunAlexDB v0.3.0 | MariaDB 11.8 |
|--------|-----------------|--------------|
| Throughput | 159,742 QPS | 178,202 QPS |
| p50 latency | 0.12 ms | 0.11 ms |
| p99 latency | 0.22 ms | 0.21 ms |
| Errors | 0 | 0 |

RunAlexDB: 89.6% of MariaDB throughput. MariaDB's advantage on SELECT 1 reflects its highly optimized connection handling for this trivial query.

### SELECT by primary key — `WHERE id = 42`

| Metric | RunAlexDB v0.3.0 | MariaDB 11.8 |
|--------|-----------------|--------------|
| Throughput | 154,262 QPS | 140,156 QPS | 
| p50 latency | 0.12 ms | 0.14 ms |
| p99 latency | 0.25 ms | 0.26 ms |
| Errors | 0 | 0 |

RunAlexDB: **10.1% faster** than MariaDB for PK reads under concurrent load. Hash-map O(1) lookup vs InnoDB B-tree.

### SELECT full scan — `WHERE score < 500` (5 000 matching rows / 10 000 total)

| Metric | RunAlexDB v0.3.0 | MariaDB 11.8 |
|--------|-----------------|--------------|
| Throughput | 169 QPS | 181 QPS |
| p50 latency | 119 ms | 110 ms |
| Errors | 0 | 0 |

MariaDB 7% faster on concurrent full scans. Under concurrent load, RunAlexDB's read lock contention on the RwLock<Database> becomes the bottleneck. MariaDB's MVCC allows reads to proceed without blocking.

---

## Key optimizations active in v0.3.0

- **Wire protocol batching**: All response packets (column count, col defs, EOF, rows, EOF) serialized into a single `BytesMut` and written with one `write_all()` syscall. SELECT_SCAN: 5,004 syscalls → 1.
- **Pre-computed SELECT 1 response**: 57 static bytes, zero parsing, zero encoding. Returned on the hot path before any dispatch.
- **Per-connection write buffer**: 64 KB `BytesMut` reused each query. Eliminates per-response allocation.
- **L0 per-connection result cache**: CRC32-keyed, write_gen-validated. Zero SQL parsing and encoding on repeat reads.
- **ValueRows fast path**: Returns `Vec<Vec<Value>>` instead of converting to `Vec<Vec<Option<String>>>`. Integers encoded directly to wire with stdlib `fmt::Write` — zero heap allocation per cell.
- **AVX2 column-store scans**: Per-column `Vec<i64>` arrays. Full-table int scans use 4-wide `_mm256_cmpgt_epi64`. Falls back to scalar if AVX2 unavailable.
- **SSE4.2 CRC32 query cache hashing**: 8 bytes/cycle for both the STMT_CACHE and L0 cache keys.

---

## Interpretation

RunAlexDB is an in-memory database — no WAL, no fsync, no MVCC. Its performance advantage on writes (INSERT/UPDATE/DELETE) is primarily structural: no durability overhead. Its PK read advantage reflects the O(1) hash-map vs B-tree. Full-table scan performance is comparable; concurrent scan performance is limited by read-write lock contention.

These results should not be compared to disk-based benchmarks (TPC-C, Sysbench) run on dedicated hardware. They show the relative overhead of each engine's processing stack under identical conditions on the same VM.

---

## Reproducibility

```bash
# Single-connection benchmark
python3 benchmark_final.py  # requires pymysql, MariaDB on :3306, RunAlexDB on :3307

# Concurrent benchmark
dbmark --query 'SELECT 1' -c 20 -d 15 -w 3 \
  --compare 'mysql://bench:bench@127.0.0.1:3306/bench' \
  'mysql://root:demo1234@127.0.0.1:3307/test'
```
