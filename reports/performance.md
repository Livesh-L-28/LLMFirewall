# Performance Benchmark Report

- **Benchmark Iterations:** 500
- **Sub-millisecond Runtime Overhead Verified:** `YES (<1ms)`
- **Added Latency (P50):** `0.0234 ms`

## Latency Comparison

| Metric | Without LLMFirewall | With LLMFirewall |
|---|---|---|
| **P50 Latency** | `0.0001 ms` | `0.0235 ms` |
| **P95 Latency** | `0.0001 ms` | `0.0486 ms` |
| **P99 Latency** | `0.0002 ms` | `0.1291 ms` |
| **Mean Latency** | `0.0001 ms` | `0.0276 ms` |
