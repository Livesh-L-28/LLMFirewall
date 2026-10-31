---
name: Pilot Performance Issue
about: Report high scan latency, excessive memory overhead, or event-loop blocking in the external pilot
title: '[Pilot Performance] '
labels: ['external-pilot', 'pilot-performance']
assignees: ''
---

## Confidentiality & Privacy Confirmation
- [ ] **I confirm that this report contains NO proprietary application profiling traces or sensitive request payloads.**

---

## 1. Environment Details
- **Package Version**: `llmfirewall-core==1.3.2`
- **Python Version**: [e.g. Python 3.11.8]
- **Operating System & Hardware**: [e.g. Ubuntu 22.04 LTS x86_64, 4 vCPUs, 16GB RAM / Apple M2 Pro 16GB]
- **Concurrency Framework**: [e.g. Asyncio, FastAPI + Uvicorn, Gunicorn sync workers, ThreadPoolExecutor]

---

## 2. Performance Metric Observations
- **Observed In-Process Latency**: [e.g. 50 ms/req (expected < 2 ms)]
- **P99 Latency (if measured)**: 
- **Prompt Size / Token Count Tested**: [e.g. 500 characters, 10,000 characters]
- **Cache Enabled**: [ ] Yes (`Firewall(enable_cache=True)`) / [ ] No (`Firewall(enable_cache=False)`)

---

## 3. Minimal Benchmark Script (MRE)
Provide a standalone script demonstrating the latency or memory bottleneck:

```python
import time
from llmfirewall import Firewall

fw = Firewall()
test_prompt = """[Paste sanitized test prompt here]"""

start = time.perf_counter()
for _ in range(100):
    fw.scan(test_prompt)
elapsed = time.perf_counter() - start
print(f"Average latency: {(elapsed / 100) * 1000:.2f} ms")
```

---

## 4. Bottleneck Hypothesis or Trace Profile
*If you generated a cProfile or py-spy profile, describe the functions consuming excessive CPU cycles:*

