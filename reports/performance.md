# LLMFirewall Comprehensive Performance Benchmark Report

- **Benchmark Timestamp:** `2026-10-26T23:05:08.949808+00:00`
- **Python Version:** `3.12.1`
- **Platform / Architecture:** `macOS-27.0.1-arm64-arm-64bit (arm64)`
- **Logical CPUs:** `8`

## 1. End-to-End Scanning Latency (Cold vs Warm-Cache)

> [!IMPORTANT]
> Cache-hit latency is isolated as a dedicated microbenchmark and is NEVER conflated with general request latency.

| Evaluation Mode | Sample Count | P50 Latency | P95 Latency | P99 Latency | Mean Latency | Throughput |
|---|---|---|---|---|---|---|
| **Cold End-to-End Scanning (No Cache)** | 100 | `0.1725 ms` | `0.1841 ms` | `0.2114 ms` | `0.177 ms` | `5650.73 req/s` |
| **Warm-Cache Scanning (ScanCache Hit)** | 200 | `0.0367 ms` | `0.0382 ms` | `0.0461 ms` | `0.0372 ms` | `26911.26 req/s` |

## 2. Individual Detector Execution Times

| Detector | Iterations | P50 Latency | P95 Latency | P99 Latency | Throughput |
|---|---|---|---|---|---|
| `prompt_injection` | 150 | `0.0646 ms` | `0.0656 ms` | `0.0684 ms` | `15426.23 ops/s` |
| `pii` | 150 | `0.0377 ms` | `0.0383 ms` | `0.0404 ms` | `26417.98 ops/s` |
| `secrets` | 150 | `0.0294 ms` | `0.0296 ms` | `0.0299 ms` | `34049.3 ops/s` |

## 3. Full Detector Pipeline

- **Iterations:** 200
- **P50 Latency:** `0.1253 ms`
- **P95 Latency:** `0.1311 ms`
- **P99 Latency:** `0.1535 ms`
- **Throughput:** `7757.96 req/s`

## 4. Multi-Threaded Concurrency Scaling

| Worker Threads | Total Requests | Wall-Clock Time | P50 Latency | P95 Latency | Aggregate Throughput | Error Rate |
|---|---|---|---|---|---|---|
| `1 workers` | 200 | `0.0274 s` | `0.1293 ms` | `0.1352 ms` | `7305.0 req/s` | `0.0%` |
| `2 workers` | 200 | `0.0274 s` | `0.1292 ms` | `0.1376 ms` | `7300.95 req/s` | `0.0%` |
| `4 workers` | 200 | `0.0323 s` | `0.1529 ms` | `1.6622 ms` | `6188.19 req/s` | `0.0%` |
| `8 workers` | 200 | `0.0287 s` | `0.1331 ms` | `0.1524 ms` | `6974.39 req/s` | `0.0%` |

## 5. Payload Size Scaling

| Payload Size | Bytes | P50 Latency | P95 Latency | Request Throughput | Data Throughput |
|---|---|---|---|---|---|
| `small_100B` | 95 B | `0.1344 ms` | `0.1432 ms` | `7353.57 req/s` | `0.67 MB/s` |
| `medium_1KB` | 1000 B | `0.7198 ms` | `0.7304 ms` | `1386.23 req/s` | `1.32 MB/s` |
| `large_10KB` | 10000 B | `6.5046 ms` | `6.7536 ms` | `152.95 req/s` | `1.46 MB/s` |
| `oversized_50KB` | 50000 B | `32.283 ms` | `32.7972 ms` | `30.92 req/s` | `1.47 MB/s` |

## 6. Token Boundary & Streaming Guard (`StreamingTextGuard`)

- **Streams Evaluated:** 10
- **Total Chunks Processed:** 10
- **Per-Chunk P50 Latency:** `0.0001 ms`
- **Per-Chunk P95 Latency:** `0.0006 ms`
- **Chunk Throughput:** `5569.35 chunks/s`
- **Streaming Error Rate:** `0.0%`

## 7. Tool and RAG Security Paths

| Target Pipeline | Iterations | P50 Latency | P95 Latency | Throughput |
|---|---|---|---|---|
| **Tool Call Inspection (`check_tool_call`)** | 100 | `0.1044 ms` | `0.1125 ms` | `9135.83 ops/s` |
| **RAG Context Filtering (`filter_and_secure`)** | 100 | `0.3684 ms` | `0.403 ms` | `2663.42 ops/s` |

## 8. Memory Footprint and Heap Allocation

- **Baseline Heap Memory:** `0.037 MB`
- **Peak Heap Memory (under load):** `1.566 MB`
- **Net Heap Delta (200 reqs):** `1.524 MB`
- **Estimated Growth per 1,000 Requests:** `7.622 MB`
