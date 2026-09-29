# Model Security & Artifact Verification

LLMFirewall provides streaming cryptographic artifact verification, serialization format safety analysis, and pre-load execution guards for machine learning models.

---

## 1. Streaming Cryptographic Verification

Large models (multi-GB files) are verified using streaming chunked reads (64 KB default buffer) to maintain bounded memory consumption:

```python
from llmfirewall import compute_streaming_hash, ModelVerifier

# Streaming SHA-256
sha = compute_streaming_hash("models/llama-3.safetensors", algorithm="sha256")

# Verify against expected hash using constant-time comparison
verifier = ModelVerifier()
result = verifier.verify_artifact("models/llama-3.safetensors", expected_hash=sha)

assert result.status == "MATCH"
```

### CLI Command

```bash
llmfirewall model verify models/llama-3.safetensors --sha256 <expected_hash>
```

---

## 2. Format Safety & Unsafe Serialization

Executable Python object serialization (Pickle, PyTorch `.pt`/`.bin` archives with pickle bytecode, Joblib) can lead to arbitrary code execution when unpickling untrusted weights.

LLMFirewall inspects file headers and magic bytes **without deserializing**:

- Safe formats: `.safetensors`, `.onnx`, `.gguf`
- Flagged unsafe formats: `.pkl`, `.pt`, `.joblib`

```python
from llmfirewall import detect_model_format, is_unsafe_serialization

fmt = detect_model_format("models/model.pkl")
if is_unsafe_serialization(fmt):
    print("Warning: Executable serialization format detected!")
```

---

## 3. Guarded Model Loading Context Manager

Wrap model loading calls to ensure policies, integrity, and revocation states are verified **before** loading weights into GPU or RAM:

```python
from llmfirewall import Firewall

fw = Firewall()

# Safe loading guard
with fw.model_guard(
    model_name="production-classifier",
    path_or_location="models/weights.safetensors",
    expected_hash="37eadb4772ddeab376bc33a120b21c6acd885e981cbe7601a253290aa55fe36a"
):
    # This code executes only if policy, hash, format, and revocation checks pass
    import torch
    # model = torch.load(...)
```

---

## 4. Model Registry & Change Detection

Track approvals and detect if a model artifact with the same name and version has an altered cryptographic hash:

```python
from llmfirewall import ModelSecurityRegistry, ModelArtifact

reg = ModelSecurityRegistry()

# Register approved version
reg.register_approval("classifier-v1", version="1.0.0", sha256="abc...")

# Check for unauthorized changes
finding = reg.detect_model_change(ModelArtifact(name="classifier-v1", version="1.0.0", sha256="tampered_hash"))
if finding:
    print("CRITICAL: Model weights changed on disk without version bump!")
```
