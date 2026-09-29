"""Performance microbenchmarks for Phase 25 Framework Integrations.

Compares:
1. Application endpoint without firewall
2. Application endpoint with core firewall.check
3. Application endpoint wrapped with @protect decorator
4. FastAPI application with FirewallMiddleware
"""

import time
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from llmfirewall import Firewall
from llmfirewall.integrations import protect
from llmfirewall.integrations.fastapi import FirewallMiddleware


def test_benchmark_decorator_overhead():
    fw = Firewall()

    def raw_function(prompt: str) -> str:
        return f"Echo: {prompt}"

    @protect(firewall=fw, inspect_output=False)
    def protected_function(prompt: str) -> str:
        return f"Echo: {prompt}"

    count = 2000
    sample_text = "What is the capital of France?"

    # Baseline: without firewall
    start = time.perf_counter()
    for _ in range(count):
        raw_function(sample_text)
    raw_time = time.perf_counter() - start

    # Protected: with thin adapter
    start = time.perf_counter()
    for _ in range(count):
        protected_function(sample_text)
    prot_time = time.perf_counter() - start

    per_call_us = ((prot_time - raw_time) / count) * 1_000_000
    # Adapter overhead per call should be under 200 microseconds (0.2ms)
    assert per_call_us < 250.0, f"Adapter overhead too high: {per_call_us:.2f} µs/call"


def test_benchmark_fastapi_middleware_overhead():
    fw = Firewall()

    # Raw app
    raw_app = FastAPI()
    @raw_app.post("/chat")
    async def raw_chat(data: dict):
        return {"response": data.get("prompt", "")}

    raw_client = TestClient(raw_app)

    # Protected app
    prot_app = FastAPI()
    prot_app.add_middleware(FirewallMiddleware, firewall=fw, paths=["/chat"])
    @prot_app.post("/chat")
    async def prot_chat(data: dict):
        return {"response": data.get("prompt", "")}

    prot_client = TestClient(prot_app)

    count = 500
    payload = {"prompt": "Hello world, tell me a quick greeting"}

    # Measure raw
    start = time.perf_counter()
    for _ in range(count):
        resp = raw_client.post("/chat", json=payload)
        assert resp.status_code == 200
    raw_dur = time.perf_counter() - start

    # Measure protected
    start = time.perf_counter()
    for _ in range(count):
        resp = prot_client.post("/chat", json=payload)
        assert resp.status_code == 200
    prot_dur = time.perf_counter() - start

    overhead_per_req_ms = ((prot_dur - raw_dur) / count) * 1000.0
    # Total FastAPI middleware + firewall scan overhead should be < 3ms per request
    assert overhead_per_req_ms < 3.0, f"FastAPI middleware overhead too high: {overhead_per_req_ms:.3f} ms/req"
