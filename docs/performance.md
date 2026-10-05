# Performance & Caching Architecture

LLMFirewall Core v1.1.0 integrates a high-performance **in-memory caching layer** (`ScanCache`) and **precompiled pattern cache** (`RegexCache`) designed for high-throughput, low-latency AI inference gateways.

---

## 1. Design & Security Principles

Caching in a security enforcement engine requires strict cryptographic guarantees to prevent **cache poisoning, stale decisions, and unauthorized security bypasses**:

1. **Deterministic Cryptographic Key Binding**:
   - Cache keys are generated via SHA-256 over:
     $$\text{Key} = \text{SHA256}(\text{direction} \parallel \text{policy\_checksum} \parallel \text{detector\_suite\_id} \parallel \text{sanitized\_context\_json} \parallel \text{normalized\_text})$$
2. **Ephemeral Context Isolation**:
   - Dynamic per-turn fields like `request_id`, `trace_id`, `timestamp`, `nonce`, and `span_id` are strictly stripped from the cache key computation.
   - When a cache hit occurs, a fresh `ScanResult` clone is generated with the caller's unique `request_id` and fresh timestamp, preserving precise SIEM audit logs.
3. **Automatic Policy & Detector Invalidation**:
   - Any update to policy rules (which alters `policy.get_checksum()`) or addition/removal of detectors immediately results in new cache keys, rendering old evaluations completely obsolete without requiring manual cache flushes.
4. **Bounded LRU Eviction & Monotonic TTL**:
   - Enforces strict upper bounds on memory footprint (default 5,000 entries).
   - Oldest entries are evicted first upon saturation. Expired entries past TTL (default 1800s) are automatically cleared.
5. **Thread Safety**:
   - Fully synchronized using reentrant locks (`threading.RLock`) for concurrent ASGI / web server worker threads.

---

## 2. Empirical Benchmark Results

Measured on macOS ARM64 using `examples/benchmark_performance.py`:

| Execution Mode | Average Latency | Throughput | Speedup | Cache Hit Ratio |
|---|---|---|---|---|
| **Cold Scan** (No Cache) | 309.02 μs (0.31 ms) | ~3,236 req/sec | Baseline | 0.0% |
| **Warm ScanCache Hit** | **38.11 μs (0.038 ms)** | **~26,143 req/sec** | **8.1x faster** | **99.9%** |

---

## 3. Configuration & Usage

### Basic Initialization

`ScanCache` is enabled by default in `Firewall`:

```python
from llmfirewall import Firewall

# Standard initialization with built-in cache
fw = Firewall(
    enable_cache=True,
    cache_size=5000,      # Maximum cached entries
    cache_ttl=1800.0,     # Time-to-live in seconds (30 minutes)
)

# First call: runs full detector suite and stores result
res1 = fw.scan_prompt("Summarize annual report.")

# Subsequent identical call: sub-millisecond cache hit!
res2 = fw.scan_prompt("Summarize annual report.")
assert res2.metadata.get("cached") is True
```

### Per-Request Cache Bypass

To force full re-execution without cache lookup:

```python
# Bypass cache for sensitive real-time security auditing
res = fw.scan_prompt("Audit this prompt", context={"no_cache": True})
```

### Cache Operational Telemetry

Inspect real-time cache performance:

```python
metrics = fw.cache.get_metrics()
print(f"Total Lookups: {metrics.total_lookups}")
print(f"Hits: {metrics.hits}, Misses: {metrics.misses}")
print(f"Hit Ratio: {metrics.hit_ratio * 100:.2f}%")
print(f"Evictions: {metrics.evictions}, Expirations: {metrics.expirations}")
```

### Precompiled Regex Cache

`RegexCache` provides thread-safe LRU caching of regular expressions across detectors:

```python
from llmfirewall.cache import compile_regex

# Precompiles pattern or reuses existing compiled pattern
pattern = compile_regex(r"sk-[A-Za-z0-9]{32,64}")
```
