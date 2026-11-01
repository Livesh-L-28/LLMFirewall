# Hardened Deployment Guide: Docker & Kubernetes

## 1. Overview

Deploying LLMFirewall-Core into production enterprise environments requires adhering to modern container security baselines, including CIS Docker Benchmark, NIST SP 800-190 (Application Container Security Guide), and Kubernetes Pod Security Standards (Restricted profile).

This document details the configuration and operational requirements of the hardened deployment assets located in `deployments/`.

---

## 2. Hardened Dockerfile Architecture

The production Dockerfile (`deployments/docker/Dockerfile.hardened`) uses multi-stage builds to minimize attack surface:

### 2.1 Security Controls Enforced
1. **Multi-Stage Build**: Compilers, build tools (`gcc`), and pip build caches remain strictly in the builder stage. The final runtime image contains only standard Python 3.12 slim and installed wheels.
2. **Dedicated Non-Root User**:
   - `UID`: `10001` (`llmfirewall`)
   - `GID`: `10001` (`llmfirewall`)
   - Login shell set to `/usr/sbin/nologin`.
3. **Read-Only Root Filesystem**:
   - The root filesystem is mounted read-only.
   - Dedicated temporary scratch directories (`/app/tmp`, `/tmp`) are mounted as `tmpfs` with `noexec,nosuid,nodev`.
4. **SUID / SGID Stripping**:
   - All setuid/setgid bits are cleared to prevent local privilege escalation.
5. **Native Healthcheck**:
   - Uses standard library `urllib` to verify HTTP 200 on `/health` without introducing `curl` or `wget`.

---

## 3. Kubernetes Production Configuration

The Kubernetes manifests in `deployments/kubernetes/` comply with the **Kubernetes Pod Security Standard: Restricted**.

### 3.1 Pod Security Context
```yaml
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  runAsGroup: 10001
  fsGroup: 10001
  seccompProfile:
    type: RuntimeDefault
```

### 3.2 Container Security Context
```yaml
securityContext:
  allowPrivilegeEscalation: false
  readOnlyRootFilesystem: true
  capabilities:
    drop:
      - ALL
```

### 3.3 High Availability & Disruption Budget
- **Replicas**: Minimum 3 pods across distinct availability zones / nodes via `podAntiAffinity`.
- **Rolling Update**: `maxSurge: 1`, `maxUnavailable: 0` ensures 100% capacity during deployments.
- **PodDisruptionBudget (`pdb.yaml`)**: `minAvailable: 1` prevents node draining or cluster upgrades from interrupting the firewall service.

---

## 4. Zero-Trust Network Segmentation

`deployments/kubernetes/networkpolicy.yaml` enforces zero-trust traffic isolation:
- **Ingress**: Restricted exclusively to API Gateway / Ingress controller pods. Direct pod-to-pod ingress from unapproved namespaces is dropped.
- **Egress**:
  - DNS: Port 53 (UDP/TCP) to CoreDNS.
  - Redis: Port 6379 to internal Redis cluster.
  - OpenTelemetry: Ports 4317/4318 to collector pods.
  - Vault: Port 8200 to Vault pods.
  - Upstream LLM: Port 443 (HTTPS) to public IP ranges (blocking internal VPC RFC1918 addresses to prevent SSRF).

---

## 5. Production Readiness Verification Checklist

Before routing live production user traffic through LLMFirewall:
- [ ] Container runs under UID 10001 (`docker run --read-only`).
- [ ] `readOnlyRootFilesystem: true` verified with tmpfs on `/tmp`.
- [ ] Redis cluster configured with password authentication and TLS.
- [ ] PodDisruptionBudget active in cluster.
- [ ] NetworkPolicy applied and verified blocking unauthorized lateral movement.
- [ ] Prometheus metrics scraping endpoint `/metrics` registered.
