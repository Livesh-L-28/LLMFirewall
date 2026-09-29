"""Demonstration of AI Supply-Chain & Model Security (Phase 28)."""

import os
import tempfile
from llmfirewall import (
    Action,
    Firewall,
    compute_streaming_hash,
)

def main():
    print("===================================================================")
    print("LLMFirewall Phase 28 — AI Supply-Chain & Model Security Demo")
    print("===================================================================")

    fw = Firewall()

    # 1. Model Artifact Verification & Streaming Hashing
    with tempfile.NamedTemporaryFile(suffix=".safetensors", delete=False) as f:
        f.write(b"MOCK_MODEL_WEIGHTS_DATA_FOR_DEMONSTRATION")
        model_path = f.name

    try:
        sha256 = compute_streaming_hash(model_path)
        print(f"\n[1] Verifying Model Artifact: {os.path.basename(model_path)}")
        print(f"    Computed SHA-256: {sha256}")

        # Verification with valid hash
        decision_valid = fw.verify_model(
            path_or_location=model_path,
            expected_hash=sha256,
            model_name="mock_classifier",
        )
        print(f"    Verification Decision: {decision_valid.action.value.upper()} (Status: {decision_valid.hash_status.value})")

        # Verification with tampered hash
        decision_tampered = fw.verify_model(
            path_or_location=model_path,
            expected_hash="0000000000000000000000000000000000000000000000000000000000000000",
            model_name="mock_classifier",
        )
        print(f"    Tampered Verification Decision: {decision_tampered.action.value.upper()} (Status: {decision_tampered.hash_status.value})")

        # 2. Guarded Model Loading Context Manager
        print("\n[2] Guarded Model Loading:")
        try:
            with fw.model_guard("mock_classifier", path_or_location=model_path, expected_hash=sha256) as dec:
                print(f"    Guarded load succeeded. Decision: {dec.action.value.upper()}")
        except Exception as e:
            print(f"    Model load prevented: {e}")

        # 3. Offline Dependency Inventory Scan
        print("\n[3] Dependency Inventory Scan:")
        deps = fw.dependency_scanner.scan_environment()
        print(f"    Discovered {len(deps)} installed Python packages.")
        sample_deps = deps[:3]
        for d in sample_deps:
            print(f"      - {d.name}=={d.version} ({d.scope.value}, {d.source.value})")

        # 4. SBOM Generation (CycloneDX Format)
        print("\n[4] SBOM Generation (CycloneDX Preview):")
        sbom = fw.dependency_scanner.generate_sbom(sample_deps, format_type="cyclonedx")
        print(f"    BOM Format: {sbom.get('bomFormat')}, Version: {sbom.get('specVersion')}")
        print(f"    Components Listed: {len(sbom.get('components', []))}")

        # 5. Security Snapshot Generation
        print("\n[5] AI Security Snapshot Generation:")
        snapshot = fw.create_security_snapshot(application_version="1.0.0")
        print(f"    Snapshot Fingerprint: {snapshot.snapshot_hash}")
        print(f"    Total Dependencies  : {len(snapshot.dependencies)}")
        print(f"    Total Configs       : {len(snapshot.configurations)}")
        print(f"    Total Policies      : {len(snapshot.policies)}")

    finally:
        if os.path.exists(model_path):
            os.remove(model_path)

    print("\n===================================================================")
    print("AI Supply-Chain & Model Security Demo Complete.")
    print("===================================================================")


if __name__ == "__main__":
    main()
