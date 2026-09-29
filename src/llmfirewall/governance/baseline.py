"""Security baselines, cryptographic integrity verification, and comparison for Phase 31."""

from enum import Enum
import hashlib
import json
import time
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall.governance.findings import FindingStatus, GovernanceFinding


class BaselineCategory(str, Enum):
    """Categorization for baseline comparison outcomes."""
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    MISSING = "MISSING"


class BaselineDiff(BaseModel):
    """Structured, reproducible comparison between a security baseline and current evaluation."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    baseline_id: str = Field(..., description="ID of baseline compared against.")
    new_findings: List[GovernanceFinding] = Field(default_factory=list, description="Findings present now but not in baseline.")
    resolved_findings: List[GovernanceFinding] = Field(default_factory=list, description="Findings present in baseline but resolved now.")
    unchanged_findings: List[GovernanceFinding] = Field(default_factory=list, description="Findings active in both baseline and current run.")
    changed_findings: List[Dict[str, Any]] = Field(default_factory=list, description="Findings with altered severity or status.")
    regressions: List[str] = Field(default_factory=list, description="List of regressions (new failures or elevated severity).")
    is_identical: bool = Field(default=False, description="True if current evaluation matches baseline exactly.")

    def summary(self) -> Dict[str, Any]:
        return {
            "baseline_id": self.baseline_id,
            "new_count": len(self.new_findings),
            "resolved_count": len(self.resolved_findings),
            "unchanged_count": len(self.unchanged_findings),
            "changed_count": len(self.changed_findings),
            "regression_count": len(self.regressions),
            "is_identical": self.is_identical,
        }


class SecurityBaseline(BaseModel):
    """Cryptographically anchored security baseline recording verified security state.
    
    Invariants:
    1. Cryptographic Tamper Resistance: SHA-256 integrity hash across canonical fields.
    2. Zero Secret Infiltration: Never logs or serializes raw credentials or tokens.
    3. Deterministic Comparison: Yields identical diff outcomes regardless of input ordering.
    """
    model_config = ConfigDict(frozen=True, extra="forbid")

    baseline_id: str = Field(default_factory=lambda: f"BASELINE-{uuid.uuid4().hex[:8].upper()}")
    version: str = Field(default="1.0", description="Schema version of baseline.")
    created_at: float = Field(default_factory=time.time, description="Epoch timestamp of creation.")
    created_by: str = Field(default="system", description="Attribution / tool identifier.")
    test_configuration: Dict[str, Any] = Field(default_factory=dict, description="Test suite version, parameters, pass rate.")
    policy_version: str = Field(default="unknown", description="Security policy version.")
    model_identity: Dict[str, Any] = Field(default_factory=dict, description="Model name, version, hash, provider.")
    dependency_state: Dict[str, Any] = Field(default_factory=dict, description="Dependency summary and hash.")
    configuration_hash: str = Field(default="", description="Firewall configuration SHA-256 hash.")
    required_gates: List[str] = Field(default_factory=list, description="Mandatory gate IDs enforced in baseline.")
    accepted_findings: List[Dict[str, Any]] = Field(default_factory=list, description="Findings accepted with active waivers at baseline time.")
    findings: List[GovernanceFinding] = Field(default_factory=list, description="List of open or tracking findings in baseline.")
    integrity_hash: str = Field(default="", description="SHA-256 integrity digest over canonical baseline fields.")

    @staticmethod
    def _calculate_digest(
        baseline_id: str,
        version: str,
        created_at: float,
        created_by: str,
        test_configuration: Dict[str, Any],
        policy_version: str,
        model_identity: Dict[str, Any],
        dependency_state: Dict[str, Any],
        configuration_hash: str,
        required_gates: List[str],
        accepted_findings: List[Dict[str, Any]],
        findings: List[GovernanceFinding],
    ) -> str:
        # Build canonical dict sorted by key
        canonical = {
            "baseline_id": baseline_id,
            "version": version,
            "created_at": round(created_at, 4),
            "created_by": created_by,
            "test_configuration": test_configuration,
            "policy_version": policy_version,
            "model_identity": model_identity,
            "dependency_state": dependency_state,
            "configuration_hash": configuration_hash,
            "required_gates": sorted(required_gates),
            "accepted_findings": sorted(accepted_findings, key=lambda x: x.get("id", "")),
            "findings": sorted(
                [f.model_dump(mode="json") for f in findings],
                key=lambda x: x.get("fingerprint", ""),
            ),
        }
        serialized = json.dumps(canonical, sort_keys=True)
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @classmethod
    def create(
        cls,
        baseline_id: Optional[str] = None,
        version: str = "1.0",
        created_by: str = "system",
        test_configuration: Optional[Dict[str, Any]] = None,
        policy_version: str = "unknown",
        model_identity: Optional[Dict[str, Any]] = None,
        dependency_state: Optional[Dict[str, Any]] = None,
        configuration_hash: str = "",
        required_gates: Optional[List[str]] = None,
        accepted_findings: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[GovernanceFinding]] = None,
        created_at: Optional[float] = None,
    ) -> "SecurityBaseline":
        """Factory computing the baseline integrity hash."""
        b_id = baseline_id or f"BASELINE-{uuid.uuid4().hex[:8].upper()}"
        now = created_at if created_at is not None else time.time()
        test_cfg = test_configuration or {}
        mod_id = model_identity or {}
        dep_st = dependency_state or {}
        req_g = sorted(required_gates or [])
        acc_f = accepted_findings or []
        f_list = sorted(findings or [], key=lambda f: f.fingerprint)

        digest = cls._calculate_digest(
            baseline_id=b_id,
            version=version,
            created_at=now,
            created_by=created_by,
            test_configuration=test_cfg,
            policy_version=policy_version,
            model_identity=mod_id,
            dependency_state=dep_st,
            configuration_hash=configuration_hash,
            required_gates=req_g,
            accepted_findings=acc_f,
            findings=f_list,
        )

        return cls(
            baseline_id=b_id,
            version=version,
            created_at=now,
            created_by=created_by,
            test_configuration=test_cfg,
            policy_version=policy_version,
            model_identity=mod_id,
            dependency_state=dep_st,
            configuration_hash=configuration_hash,
            required_gates=req_g,
            accepted_findings=acc_f,
            findings=f_list,
            integrity_hash=digest,
        )

    def verify_integrity(self) -> bool:
        """Verify the cryptographic integrity of this baseline against tampering."""
        expected = self._calculate_digest(
            baseline_id=self.baseline_id,
            version=self.version,
            created_at=self.created_at,
            created_by=self.created_by,
            test_configuration=self.test_configuration,
            policy_version=self.policy_version,
            model_identity=self.model_identity,
            dependency_state=self.dependency_state,
            configuration_hash=self.configuration_hash,
            required_gates=self.required_gates,
            accepted_findings=self.accepted_findings,
            findings=self.findings,
        )
        return self.integrity_hash == expected

    def compare_findings(self, current_findings: List[GovernanceFinding]) -> BaselineDiff:
        """Compare current findings against this baseline to detect regressions, resolutions, and additions."""
        base_map = {f.fingerprint: f for f in self.findings}
        curr_map = {f.fingerprint: f for f in current_findings}

        new_findings: List[GovernanceFinding] = []
        unchanged_findings: List[GovernanceFinding] = []
        resolved_findings: List[GovernanceFinding] = []
        changed_findings: List[Dict[str, Any]] = []
        regressions: List[str] = []

        # Check current findings
        for fp, cur in curr_map.items():
            if fp not in base_map:
                new_findings.append(cur)
                regressions.append(f"NEW_FINDING: {cur.category} in test {cur.test_id or 'unknown'} ({cur.severity.value})")
            else:
                base = base_map[fp]
                unchanged_findings.append(cur)
                # Check for severity escalation
                severities = ["low", "medium", "high", "critical"]
                try:
                    base_idx = severities.index(base.severity.value.lower())
                    cur_idx = severities.index(cur.severity.value.lower())
                    if cur_idx > base_idx:
                        changed_findings.append({
                            "fingerprint": fp,
                            "old_severity": base.severity.value,
                            "new_severity": cur.severity.value,
                        })
                        regressions.append(f"SEVERITY_ESCALATION: {fp} escalated from {base.severity.value} to {cur.severity.value}")
                except ValueError:
                    pass

        # Check resolved findings
        for fp, base in base_map.items():
            if fp not in curr_map:
                resolved_findings.append(base)

        is_id = (
            len(new_findings) == 0
            and len(resolved_findings) == 0
            and len(changed_findings) == 0
            and len(regressions) == 0
        )

        return BaselineDiff(
            baseline_id=self.baseline_id,
            new_findings=new_findings,
            resolved_findings=resolved_findings,
            unchanged_findings=unchanged_findings,
            changed_findings=changed_findings,
            regressions=regressions,
            is_identical=is_id,
        )

    def to_json(self) -> str:
        """Serialize baseline to reproducible JSON."""
        return json.dumps(self.model_dump(mode="json"), indent=2, sort_keys=True)

    @classmethod
    def from_json(cls, data: str) -> "SecurityBaseline":
        """Deserialize baseline from JSON and validate schema."""
        raw = json.loads(data)
        return cls(**raw)
