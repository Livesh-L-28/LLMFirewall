# Performance Benchmark Report

- **Benchmark Iterations:** 500
- **Sub-millisecond Runtime Overhead Verified:** `YES (<1ms)`
- **Added Latency (P50):** `0.0222 ms`

## Latency Comparison

| Metric | Without LLMFirewall | With LLMFirewall |
|---|---|---|
| **P50 Latency** | `0.0001 ms` | `0.0223 ms` |
| **P95 Latency** | `0.0001 ms` | `0.0263 ms` |
| **P99 Latency** | `0.0001 ms` | `0.059 ms` |
| **Mean Latency** | `0.0001 ms` | `0.0235 ms` |
