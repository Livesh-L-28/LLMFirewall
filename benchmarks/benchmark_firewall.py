"""Comprehensive benchmark suite measuring all LLMFirewall components."""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

BENCHMARKS_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = BENCHMARKS_DIR.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from fastapi import FastAPI
from fastapi.testclient import TestClient

from llmfirewall import (
    Action,
    AuditConfig,
    AuditLogger,
    DetectorConfig,
    Firewall,
    FirewallConfig,
    PIIConfig,
    PolicyConfig,
    PolicyRule,
    PromptInjectionConfig,
    RedactionConfig,
    RiskConfig,
    SecretConfig,
    Severity,
    ThreatType,
)
from llmfirewall.detectors.pii.detector import PIIDetector
from llmfirewall.detectors.prompt_injection.detector import PromptInjectionDetector
from llmfirewall.detectors.secrets.detector import SecretDetector
from llmfirewall.integrations.fastapi import FirewallMiddleware
from llmfirewall.policy.engine import PolicyEngine
from llmfirewall.policy.redactor import SafeRedactor
from llmfirewall.risk.engine import RiskEngine

from benchmarks.utils import (
    get_system_environment,
    measure_latency_and_throughput,
    measure_memory_peak,
)

BENCHMARKS_DIR = Path(__file__).parent
DATASETS_DIR = BENCHMARKS_DIR / "datasets"


def load_dataset_text(filename: str) -> str:
    with open(DATASETS_DIR / filename, "r", encoding="utf-8") as f:
        return f.read()


def run_all_benchmarks() -> Dict[str, Any]:
    print("=" * 70)
    print(" LLMFirewall Performance Benchmarking Suite")
    print("=" * 70)

    env = get_system_environment()
    print(f"Python      : {env['python_version']} ({env['platform']})")
    print(f"Hardware    : {env['processor']} | Logical CPUs: {env['cpu_count_logical']}")
    print(f"Memory Total: {env['total_memory_gb']} GB")
    print("=" * 70)

    small_text = load_dataset_text("small.txt")
    med_text = load_dataset_text("medium.txt")
    large_text = load_dataset_text("large.txt")

    results: Dict[str, Any] = {
        "environment": env,
        "detectors": {},
        "detector_combinations": {},
        "firewall_full": {},
        "input_size_scaling": {},
        "risk_engine": {},
        "policy_engine": {},
        "redaction": {},
        "audit_overhead": {},
        "configuration": {},
        "object_reuse": {},
        "memory": {},
        "fastapi": {},
        "cli": {},
    }

    # -------------------------------------------------------------
    # 1. Individual Detector Benchmarks
    # -------------------------------------------------------------
    print("\n[1/12] Benchmarking Individual Detectors...")
    pi_detector = PromptInjectionDetector()
    pii_detector = PIIDetector()
    sec_detector = SecretDetector()

    sizes = [("small", small_text), ("medium", med_text), ("large", large_text)]

    for size_name, text in sizes:
        p_bytes = len(text.encode("utf-8"))

        s_pi, ops_pi, mb_pi = measure_latency_and_throughput(lambda: pi_detector.detect(text), iterations=150, payload_bytes=p_bytes)
        s_pii, ops_pii, mb_pii = measure_latency_and_throughput(lambda: pii_detector.detect(text), iterations=150, payload_bytes=p_bytes)
        s_sec, ops_sec, mb_sec = measure_latency_and_throughput(lambda: sec_detector.detect(text), iterations=150, payload_bytes=p_bytes)

        results["detectors"][f"prompt_injection_{size_name}"] = {"stats": s_pi, "ops_sec": ops_pi, "mb_sec": mb_pi}
        results["detectors"][f"pii_{size_name}"] = {"stats": s_pii, "ops_sec": ops_pii, "mb_sec": mb_pii}
        results["detectors"][f"secrets_{size_name}"] = {"stats": s_sec, "ops_sec": ops_sec, "mb_sec": mb_sec}

        print(f"  • {size_name.upper():<6} ({p_bytes:>5} B) | PI: {s_pi['median']}ms | PII: {s_pii['median']}ms | Sec: {s_sec['median']}ms")

    # -------------------------------------------------------------
    # 2. Detector Combinations
    # -------------------------------------------------------------
    print("\n[2/12] Benchmarking Detector Combinations (Medium Text)...")
    combos = [
        ("pi_only", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=True), pii=PIIConfig(enabled=False), secrets=SecretConfig(enabled=False))),
        ("pii_only", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=False), pii=PIIConfig(enabled=True), secrets=SecretConfig(enabled=False))),
        ("secrets_only", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=False), pii=PIIConfig(enabled=False), secrets=SecretConfig(enabled=True))),
        ("pi_and_pii", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=True), pii=PIIConfig(enabled=True), secrets=SecretConfig(enabled=False))),
        ("pi_and_secrets", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=True), pii=PIIConfig(enabled=False), secrets=SecretConfig(enabled=True))),
        ("pii_and_secrets", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=False), pii=PIIConfig(enabled=True), secrets=SecretConfig(enabled=True))),
        ("all_detectors", DetectorConfig(prompt_injection=PromptInjectionConfig(enabled=True), pii=PIIConfig(enabled=True), secrets=SecretConfig(enabled=True))),
    ]
    for combo_name, det_cfg in combos:
        fw = Firewall(config=FirewallConfig(detectors=det_cfg))
        s, ops, _ = measure_latency_and_throughput(lambda: fw.check(med_text), iterations=150)
        results["detector_combinations"][combo_name] = {"stats": s, "ops_sec": ops}
        print(f"  • {combo_name:<18} | Median: {s['median']:>6.3f} ms | p95: {s['p95']:>6.3f} ms | {ops:>7.1f} req/s")

    # -------------------------------------------------------------
    # 3. Full Firewall Pipeline
    # -------------------------------------------------------------
    print("\n[3/12] Benchmarking Full Firewall Orchestrator...")
    fw_default = Firewall()
    with open(DATASETS_DIR / "security_cases.json", "r") as f:
        security_cases = json.load(f)

    for case in security_cases:
        c_name = case["name"]
        c_text = case["text"]
        s, ops, _ = measure_latency_and_throughput(lambda: fw_default.check(c_text), iterations=200)
        results["firewall_full"][c_name] = {"stats": s, "ops_sec": ops}
        print(f"  • Case: {c_name:<26} | Median: {s['median']:>6.3f} ms | p99: {s['p99']:>6.3f} ms | {ops:>7.1f} req/s")

    # -------------------------------------------------------------
    # 4. Input-Size Scaling
    # -------------------------------------------------------------
    print("\n[4/12] Measuring Scaling vs Input Size...")
    scaling_sizes = [100, 500, 1000, 5000, 10000, 25000, 50000]
    for n_bytes in scaling_sizes:
        sub_text = (med_text * ((n_bytes // len(med_text)) + 1))[:n_bytes]
        actual_bytes = len(sub_text.encode("utf-8"))
        s, ops, mb_sec = measure_latency_and_throughput(lambda: fw_default.check(sub_text), iterations=100, payload_bytes=actual_bytes)
        results["input_size_scaling"][f"{n_bytes}B"] = {"bytes": actual_bytes, "stats": s, "ops_sec": ops, "mb_sec": mb_sec}
        print(f"  • {actual_bytes:>5} Bytes | Median: {s['median']:>6.3f} ms | p95: {s['p95']:>6.3f} ms | {mb_sec:>6.2f} MB/s")

    # -------------------------------------------------------------
    # 5. Risk Engine Standalone
    # -------------------------------------------------------------
    print("\n[5/12] Benchmarking Risk Engine...")
    risk_eng = RiskEngine()
    from llmfirewall.core.models import Finding
    from llmfirewall.detectors.collection import FindingCollection

    findings_counts = [0, 1, 5, 20, 100]
    for count in findings_counts:
        sample_findings = [
            Finding(
                detector_name="mock",
                threat_type=ThreatType.PROMPT_INJECTION,
                description="mock",
                severity=Severity.HIGH,
                confidence=0.9,
            ) for _ in range(count)
        ]
        fc = FindingCollection(findings=sample_findings)
        s, ops, _ = measure_latency_and_throughput(lambda: risk_eng.evaluate(fc), iterations=500)
        results["risk_engine"][f"{count}_findings"] = {"stats": s, "ops_sec": ops}
        print(f"  • {count:>3} findings | Median: {s['median']:>6.4f} ms | p99: {s['p99']:>6.4f} ms | {ops:>9.1f} ops/s")

    # -------------------------------------------------------------
    # 6. Policy Engine Standalone
    # -------------------------------------------------------------
    print("\n[6/12] Benchmarking Policy Engine...")
    pol_eng = PolicyEngine()
    from llmfirewall.core.models import RiskScore

    mock_rs = RiskScore(score=0.75, max_severity=Severity.HIGH)
    s_pol, ops_pol, _ = measure_latency_and_throughput(
        lambda: pol_eng.decide(text="prompt", findings=sample_findings[:3], risk_score=mock_rs),
        iterations=500,
    )
    results["policy_engine"] = {"stats": s_pol, "ops_sec": ops_pol}
    print(f"  • Policy Evaluation | Median: {s_pol['median']:>6.4f} ms | p99: {s_pol['p99']:>6.4f} ms | {ops_pol:>9.1f} ops/s")

    # -------------------------------------------------------------
    # 7. Redaction Engine
    # -------------------------------------------------------------
    print("\n[7/12] Benchmarking Redaction Engine...")
    redactor = SafeRedactor()
    pii_matches = pii_detector.detect("Emails: a@corp.com, b@corp.com, c@corp.com, d@corp.com, e@corp.com")
    text_to_redact = "Emails: a@corp.com, b@corp.com, c@corp.com, d@corp.com, e@corp.com"

    s_red, ops_red, _ = measure_latency_and_throughput(
        lambda: redactor.redact(text_to_redact, pii_matches),
        iterations=500,
    )
    results["redaction"] = {"stats": s_red, "ops_sec": ops_red}
    print(f"  • Redaction (5 matches) | Median: {s_red['median']:>6.4f} ms | p99: {s_red['p99']:>6.4f} ms | {ops_red:>9.1f} ops/s")

    # -------------------------------------------------------------
    # -------------------------------------------------------------
    # 8. Audit Logging Overhead
    # -------------------------------------------------------------
    print("\n[8/13] Benchmarking Audit Logging Overhead...")
    fw_no_audit = Firewall()
    null_sink = open(os.devnull, "w")
    fw_with_audit = Firewall(audit_logger=AuditLogger(sink=null_sink))

    s_no_aud, ops_no_aud, _ = measure_latency_and_throughput(lambda: fw_no_audit.check(small_text), iterations=300)
    s_aud, ops_aud, _ = measure_latency_and_throughput(lambda: fw_with_audit.check(small_text), iterations=300)

    audit_overhead_ms = round(s_aud["median"] - s_no_aud["median"], 4)
    results["audit_overhead"] = {
        "disabled": s_no_aud,
        "enabled": s_aud,
        "delta_median_ms": audit_overhead_ms,
    }
    print(f"  • Audit Disabled: {s_no_aud['median']:.3f} ms | Audit Enabled: {s_aud['median']:.3f} ms | Delta: +{audit_overhead_ms:.3f} ms")

    # -------------------------------------------------------------
    # 8b. Telemetry Overhead (Phase 19)
    # -------------------------------------------------------------
    print("\n[8b/13] Benchmarking Telemetry Overhead...")
    from llmfirewall.telemetry import InMemoryTelemetrySink
    fw_with_telem = Firewall(telemetry_sink=InMemoryTelemetrySink(enable_events=True, enable_metrics=True))

    s_telem, ops_telem, _ = measure_latency_and_throughput(lambda: fw_with_telem.check(small_text), iterations=300)
    telem_overhead_ms = round(s_telem["median"] - s_no_aud["median"], 4)
    results["telemetry_overhead"] = {
        "disabled": s_no_aud,
        "enabled": s_telem,
        "delta_median_ms": telem_overhead_ms,
    }
    print(f"  • Telemetry Disabled: {s_no_aud['median']:.3f} ms | Telemetry Enabled: {s_telem['median']:.3f} ms | Delta: +{telem_overhead_ms:.3f} ms")

    # -------------------------------------------------------------
    # 9. Configuration Lookup Overhead
    # -------------------------------------------------------------
    print("\n[9/12] Benchmarking Configuration Lookup Overhead...")
    cfg_custom = FirewallConfig(
        detectors=DetectorConfig(prompt_injection=PromptInjectionConfig(rules=["instruction_override"])),
        risk=RiskConfig(low_threshold=0.10),
    )
    fw_custom = Firewall(config=cfg_custom)

    s_def_cfg, _, _ = measure_latency_and_throughput(lambda: fw_default.check(small_text), iterations=300)
    s_cust_cfg, _, _ = measure_latency_and_throughput(lambda: fw_custom.check(small_text), iterations=300)

    cfg_delta = round(s_cust_cfg["median"] - s_def_cfg["median"], 4)
    results["configuration"] = {
        "default": s_def_cfg,
        "custom": s_cust_cfg,
        "delta_ms": cfg_delta,
    }
    print(f"  • Default Config: {s_def_cfg['median']:.3f} ms | Custom Config: {s_cust_cfg['median']:.3f} ms")

    # -------------------------------------------------------------
    # 10. Object Reuse vs Re-instantiation
    # -------------------------------------------------------------
    print("\n[10/12] Benchmarking Object Reuse vs Creation...")
    s_reuse, ops_reuse, _ = measure_latency_and_throughput(lambda: fw_default.check(small_text), iterations=300)

    def fresh_instantiation_scan():
        fw = Firewall()
        return fw.check(small_text)

    s_create, ops_create, _ = measure_latency_and_throughput(fresh_instantiation_scan, iterations=300)
    creation_overhead_ms = round(s_create["median"] - s_reuse["median"], 4)
    results["object_reuse"] = {
        "reuse_instance": s_reuse,
        "fresh_instance_per_req": s_create,
        "creation_cost_ms": creation_overhead_ms,
    }
    print(f"  • Reused Instance: {s_reuse['median']:.3f} ms ({ops_reuse:.1f} req/s)")
    print(f"  • Fresh Instance : {s_create['median']:.3f} ms ({ops_create:.1f} req/s)")
    print(f"  • Instantiation Cost: +{creation_overhead_ms:.3f} ms/req")

    # -------------------------------------------------------------
    # 11. Memory Allocations (tracemalloc)
    # -------------------------------------------------------------
    print("\n[11/12] Measuring Peak Memory Footprint...")
    mem_init = measure_memory_peak(lambda: Firewall(), iterations=10)
    mem_scan = measure_memory_peak(lambda: fw_default.check(large_text), iterations=20)
    results["memory"] = {
        "initialization": mem_init,
        "large_scan_peak": mem_scan,
    }
    print(f"  • Initialization Heap Peak: {mem_init['peak_kb']} KB")
    print(f"  • 45KB Scan Heap Peak     : {mem_scan['peak_kb']} KB")

    # -------------------------------------------------------------
    # 12. FastAPI & CLI Overhead
    # -------------------------------------------------------------
    print("\n[12/12] Measuring FastAPI Middleware & CLI Overhead...")

    # FastAPI Benchmark
    app_base = FastAPI()
    @app_base.post("/chat")
    def chat_base(data: dict):
        return {"echo": data.get("prompt")}
    c_base = TestClient(app_base)

    app_fw = FastAPI()
    app_fw.add_middleware(FirewallMiddleware, firewall=fw_default)
    @app_fw.post("/chat")
    def chat_fw(data: dict):
        return {"echo": data.get("prompt")}
    c_fw = TestClient(app_fw)

    payload = {"prompt": small_text}
    s_fastapi_base, _, _ = measure_latency_and_throughput(lambda: c_base.post("/chat", json=payload), iterations=200)
    s_fastapi_fw, _, _ = measure_latency_and_throughput(lambda: c_fw.post("/chat", json=payload), iterations=200)
    fastapi_overhead = round(s_fastapi_fw["median"] - s_fastapi_base["median"], 4)

    results["fastapi"] = {
        "baseline_ms": s_fastapi_base["median"],
        "with_firewall_ms": s_fastapi_fw["median"],
        "overhead_ms": fastapi_overhead,
    }
    print(f"  • FastAPI Baseline: {s_fastapi_base['median']:.3f} ms | With Firewall: {s_fastapi_fw['median']:.3f} ms | Overhead: +{fastapi_overhead:.3f} ms")

    # CLI Benchmark
    t0 = time.perf_counter()
    for _ in range(25):
        subprocess.run(["llmfirewall", "--version"], capture_output=True)
    t_cli_start = ((time.perf_counter() - t0) / 25) * 1000.0

    t0 = time.perf_counter()
    for _ in range(25):
        subprocess.run(["llmfirewall", "scan", "Hello safe prompt"], capture_output=True)
    t_cli_scan = ((time.perf_counter() - t0) / 25) * 1000.0
    cli_overhead = round(t_cli_scan - t_cli_start, 3)

    results["cli"] = {
        "startup_ms": round(t_cli_start, 2),
        "total_scan_ms": round(t_cli_scan, 2),
        "execution_overhead_ms": cli_overhead,
    }
    print(f"  • CLI Startup: {t_cli_start:.2f} ms | Total CLI Scan: {t_cli_scan:.2f} ms | Scan Execution: +{cli_overhead:.2f} ms")

    # Save machine-readable output
    out_file = BENCHMARKS_DIR / "benchmark_results.json"
    with open(out_file, "w", encoding="utf-8") as out:
        json.dump(results, out, indent=2)

    print("\n" + "=" * 70)
    print(f"Benchmark run complete! Results written to: {out_file}")
    print("=" * 70)

    return results


if __name__ == "__main__":
    run_all_benchmarks()
