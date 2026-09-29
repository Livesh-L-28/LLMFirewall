"""Performance benchmarks for Phase 28: AI Supply-Chain & Model Security."""

import os
import tempfile
import time

from llmfirewall import (
    DependencyScanner,
    Firewall,
    ModelArtifact,
    ModelVerifier,
    SecuritySnapshot,
    compute_streaming_hash,
    hash_configuration,
)


def benchmark_streaming_hashing():
    print("--- 1. Model Artifact Streaming Hashing Benchmark ---")
    chunk_sizes = [1 * 1024 * 1024, 10 * 1024 * 1024, 50 * 1024 * 1024]  # 1MB, 10MB, 50MB
    for size in chunk_sizes:
        with tempfile.NamedTemporaryFile(delete=False) as f:
            f.write(b"0" * size)
            f.flush()
            temp_path = f.name

        try:
            start = time.perf_counter()
            digest = compute_streaming_hash(temp_path, algorithm="sha256")
            duration = time.perf_counter() - start
            mb_per_sec = (size / (1024 * 1024)) / duration
            print(f"Hashed {size / (1024*1024):.1f} MB in {duration * 1000:.2f} ms ({mb_per_sec:.2f} MB/s) [digest={digest[:8]}...]")
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


def benchmark_dependency_inventory():
    print("\n--- 2. Offline Dependency Inventory Scan Benchmark ---")
    scanner = DependencyScanner()
    start = time.perf_counter()
    deps = scanner.scan_environment()
    duration = time.perf_counter() - start
    print(f"Scanned {len(deps)} installed packages in {duration * 1000:.2f} ms")


def benchmark_security_snapshot_generation():
    print("\n--- 3. AI Security Snapshot Generation Benchmark ---")
    fw = Firewall()
    start = time.perf_counter()
    snapshot = fw.create_security_snapshot(application_version="1.0.0")
    duration = time.perf_counter() - start
    print(f"Generated complete SecuritySnapshot (fingerprint={snapshot.snapshot_hash[:8]}...) in {duration * 1000:.2f} ms")


def benchmark_config_hashing_and_drift():
    print("\n--- 4. Configuration Hashing & Drift Detection Benchmark ---")
    config_dict = {f"param_{i}": i * 1.5 for i in range(500)}
    start = time.perf_counter()
    for _ in range(100):
        hash_configuration(config_dict)
    duration = time.perf_counter() - start
    print(f"Hashed 100 500-key config dictionaries in {duration * 1000:.2f} ms ({duration / 100 * 1000:.3f} ms/op)")


if __name__ == "__main__":
    print("=========================================================")
    print("LLMFirewall Phase 28: Supply-Chain & Model Security Benchmark")
    print("=========================================================")
    benchmark_streaming_hashing()
    benchmark_dependency_inventory()
    benchmark_security_snapshot_generation()
    benchmark_config_hashing_and_drift()
    print("=========================================================")
