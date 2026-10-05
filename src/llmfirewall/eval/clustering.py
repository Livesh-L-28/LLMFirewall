"""Automated Failure Clustering & Robustness Evaluation for Security Evaluation 2.0 (Phase 53).

Clusters evasion attempts and failed defenses by mutation type and attack category,
calculating quantifiable defense robustness metrics.
"""

from collections import defaultdict
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from llmfirewall import Action, Firewall
from llmfirewall.eval.mutations import AdversarialMutationEngine, MutatedPayload, MutationType


class MutationEvaluationResult(BaseModel):
    """Result of running a mutated adversarial payload against the Firewall."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    payload: MutatedPayload
    action: Action
    risk_score: float
    blocked: bool
    reason: str
    execution_time_ms: float


class FailureCluster(BaseModel):
    """Cluster of evasions grouped by mutation operator."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    mutation_type: MutationType
    total_tests: int
    evasions: int
    blocked: int
    evasion_rate: float = Field(..., description="Percentage of mutations that bypassed defense [0.0, 100.0]")
    sample_evasions: List[str] = Field(default_factory=list, description="Examples of evaded prompts")
    recommendation: str = Field(default="", description="Targeted hardening advice")


class RedTeamEvaluationReport(BaseModel):
    """Structured report produced by the Adversarial Red-Team Evaluation Runner."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    total_mutations: int
    total_blocked: int
    total_evasions: int
    robustness_score: float = Field(..., description="Robustness percentage: (blocked / total) * 100")
    clusters: List[FailureCluster] = Field(default_factory=list)
    average_latency_ms: float = Field(default=0.0)

    def to_markdown(self) -> str:
        """Format report into clean, readable GitHub-flavored markdown."""
        lines = [
            "# LLMFirewall Red-Team Robustness Evaluation Report (v1.1.0)",
            "",
            "## Summary Metrics",
            f"- **Total Mutations Tested**: {self.total_mutations}",
            f"- **Defended / Blocked**: {self.total_blocked}",
            f"- **Evasions**: {self.total_evasions}",
            f"- **Overall Robustness Score**: **{self.robustness_score:.2f}%**",
            f"- **Average Scan Latency**: {self.average_latency_ms:.2f} ms",
            "",
            "## Failure Clusters by Mutation Vector",
            "| Mutation Type | Tests | Blocked | Evasions | Evasion Rate | Hardening Recommendation |",
            "|---|---|---|---|---|---|",
        ]
        for c in self.clusters:
            lines.append(
                f"| `{c.mutation_type.value}` | {c.total_tests} | {c.blocked} | {c.evasions} | {c.evasion_rate:.1f}% | {c.recommendation} |"
            )

        if self.total_evasions > 0:
            lines.extend([
                "",
                "## Evasion Samples for Hardening",
            ])
            for c in self.clusters:
                if c.sample_evasions:
                    lines.append(f"### `{c.mutation_type.value}` Evasions")
                    for s in c.sample_evasions[:3]:
                        lines.append(f"- `{s[:80]}...`" if len(s) > 80 else f"- `{s}`")

        return "\n".join(lines)


class AdversarialRedTeamRunner:
    """Executes red-team adversarial mutations against a Firewall instance and clusters results."""

    def __init__(self, mutation_engine: Optional[AdversarialMutationEngine] = None) -> None:
        self.mutation_engine = mutation_engine or AdversarialMutationEngine()

    def evaluate_target(
        self,
        firewall: Firewall,
        seed_prompts: List[str],
        mutation_types: Optional[List[MutationType]] = None,
        max_mutations_per_type: int = 2,
    ) -> RedTeamEvaluationReport:
        """Run red-team mutations across seed prompts, record outcomes, and build clustered report."""
        if not seed_prompts:
            return RedTeamEvaluationReport(
                total_mutations=0,
                total_blocked=0,
                total_evasions=0,
                robustness_score=100.0,
                clusters=[],
                average_latency_ms=0.0,
            )

        results: List[MutationEvaluationResult] = []
        latencies: List[float] = []

        # 1. Generate mutations for all seeds
        all_mutations: List[MutatedPayload] = []
        for seed in seed_prompts:
            muts = self.mutation_engine.mutate(
                seed,
                mutation_types=mutation_types,
                max_mutations_per_type=max_mutations_per_type,
            )
            all_mutations.extend(muts)

        # 2. Execute each mutated payload against the Firewall
        for m in all_mutations:
            t0 = time.perf_counter()
            scan_res = firewall.scan_prompt(m.mutated_text)
            elapsed_ms = (time.perf_counter() - t0) * 1000.0
            latencies.append(elapsed_ms)

            is_blocked = scan_res.action == Action.BLOCK
            results.append(
                MutationEvaluationResult(
                    payload=m,
                    action=scan_res.action,
                    risk_score=scan_res.risk_score.score,
                    blocked=is_blocked,
                    reason=scan_res.reason,
                    execution_time_ms=round(elapsed_ms, 3),
                )
            )

        # 3. Cluster by mutation type
        grouped: Dict[MutationType, List[MutationEvaluationResult]] = defaultdict(list)
        for r in results:
            grouped[r.payload.mutation_type].append(r)

        clusters: List[FailureCluster] = []
        total_blocked = sum(1 for r in results if r.blocked)
        total_evasions = len(results) - total_blocked

        for mtype, group in sorted(grouped.items(), key=lambda x: x[0].value):
            count = len(group)
            blocked_in_group = sum(1 for r in group if r.blocked)
            evasions_in_group = count - blocked_in_group
            evasion_rate = (evasions_in_group / count * 100.0) if count > 0 else 0.0

            sample_evasions = [r.payload.mutated_text for r in group if not r.blocked][:3]

            rec = self._get_recommendation(mtype, evasion_rate)

            clusters.append(
                FailureCluster(
                    mutation_type=mtype,
                    total_tests=count,
                    blocked=blocked_in_group,
                    evasions=evasions_in_group,
                    evasion_rate=round(evasion_rate, 2),
                    sample_evasions=sample_evasions,
                    recommendation=rec,
                )
            )

        robustness = (total_blocked / len(results) * 100.0) if results else 100.0
        avg_lat = (sum(latencies) / len(latencies)) if latencies else 0.0

        return RedTeamEvaluationReport(
            total_mutations=len(results),
            total_blocked=total_blocked,
            total_evasions=total_evasions,
            robustness_score=round(robustness, 2),
            clusters=clusters,
            average_latency_ms=round(avg_lat, 2),
        )

    def _get_recommendation(self, mtype: MutationType, evasion_rate: float) -> str:
        if evasion_rate == 0.0:
            return "Defense fully robust against this mutation vector."
        recs = {
            MutationType.UNICODE_HOMOGLYPH: "Enable NFKC Unicode canonical normalization before tokenization.",
            MutationType.ZERO_WIDTH_INJECTION: "Strip zero-width spaces and non-printable control characters during preprocessing.",
            MutationType.BIDI_OVERRIDE: "Reject or normalize bidirectional formatting characters in user inputs.",
            MutationType.LEETSPEAK_ADVANCED: "Expand leetspeak mapping table in heuristic analyzer.",
            MutationType.ROLE_PERSONA_CONFUSION: "Strengthen system instruction hierarchy and prefix boundary detection.",
            MutationType.DELIMITER_WRAP: "Unwrap markdown and XML structural tags prior to policy evaluation.",
            MutationType.RAG_POISONING: "Enforce strict context isolation and citation boundary checks.",
            MutationType.TOOL_INJECTION: "Apply ToolSecurityEngine parameter validation and deny shell characters.",
            MutationType.CASE_NOISE: "Ensure case-insensitive matching across regex and token detectors.",
        }
        return recs.get(mtype, "Fine-tune detector thresholds for this category.")
