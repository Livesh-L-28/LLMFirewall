"""Parallel scan pool for bounded concurrent high-throughput batch processing."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Union

from llmfirewall.core.models import Action, Finding, PolicyDecision, RiskScore, ScanRequest, ScanResult, Severity

if TYPE_CHECKING:
    from llmfirewall.firewall import Firewall


class ParallelScanPool:
    """Thread-pool based parallel scan executor for high-throughput batch inspection.
    
    Guarantees:
    - Bounded concurrency: max_workers strictly capped to prevent resource exhaustion.
    - Preserved ordering: output list index strictly matches input list index.
    - Fail-closed isolation: an unhandled exception on an individual item fails-closed to BLOCK.
    """

    def __init__(self, firewall: Optional[Any] = None, max_workers: int = 4) -> None:
        if firewall is not None:
            self.firewall = firewall
        else:
            from llmfirewall.firewall import Firewall
            self.firewall = Firewall()
        self.max_workers = max(1, min(max_workers, 32))

    def scan_batch(
        self,
        items: List[Union[str, ScanRequest]],
        direction: str = "input",
        context: Optional[Dict[str, Any]] = None,
        tenant_id: Optional[str] = None,
    ) -> List[ScanResult]:
        """Scan a batch of inputs concurrently, returning ordered ScanResults."""
        if not items:
            return []

        results: List[Optional[ScanResult]] = [None] * len(items)

        def _scan_single(idx: int, item: Union[str, ScanRequest]) -> tuple[int, ScanResult]:
            try:
                res = self.firewall.scan(
                    text_or_request=item,
                    direction=direction,
                    context=context,
                    tenant_id=tenant_id,
                )
                return idx, res
            except Exception as e:
                # Safe fail-closed: return synthetic BLOCK result on unexpected failure
                req_id = item.request_id if isinstance(item, ScanRequest) else f"err-{idx}"
                text_val = item.text if isinstance(item, ScanRequest) else str(item)
                fail_res = ScanResult(
                    request_id=req_id,
                    decision=PolicyDecision(
                        action=Action.BLOCK,
                        reason=f"Fail-closed: execution failure during batch inspection ({e})",
                    ),
                    risk_score=RiskScore(score=1.0, max_severity=Severity.CRITICAL),
                    findings=[],
                    processed_text=text_val,
                )
                return idx, fail_res

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(_scan_single, i, item) for i, item in enumerate(items)]
            for fut in as_completed(futures):
                idx, res = fut.result()
                results[idx] = res

        return [r for r in results if r is not None]
