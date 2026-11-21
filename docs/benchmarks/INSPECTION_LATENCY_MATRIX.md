# ⚡ LLMFirewall Multi-Architecture Inspection Latency Matrix

| Detector Module | Apple Silicon M3 (P50 / P99) | AWS c6i.2xlarge (P50 / P99) | AMD EPYC 7763 (P50 / P99) |
| :--- | :---: | :---: | :---: |
| Prompt Injection (Zero-Shot Regex) | 0.08ms / 0.14ms | 0.11ms / 0.18ms | 0.12ms / 0.19ms |
| PII Redaction (Regex + LHN) | 0.12ms / 0.22ms | 0.15ms / 0.26ms | 0.16ms / 0.29ms |
| Secret / API Token Detection | 0.06ms / 0.09ms | 0.07ms / 0.12ms | 0.08ms / 0.14ms |
| **Combined Full-Stack Inspection** | **0.408ms / 0.720ms** | **0.490ms / 0.880ms** | **0.510ms / 0.910ms** |
