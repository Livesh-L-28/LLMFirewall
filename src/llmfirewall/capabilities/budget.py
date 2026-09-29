"""Thread-safe action and resource budget manager with reservation semantics."""

import threading
import time
from typing import Dict, Optional, Tuple

from llmfirewall.capabilities.models import ActionBudget, ActionDecisionStatus


class BudgetManager:
    """Tracks and enforces total actions, per-capability limits, and runtime timeouts."""

    def __init__(self, budget: Optional[ActionBudget] = None) -> None:
        self.budget = budget or ActionBudget()
        self._lock = threading.Lock()
        self.start_time = time.time()
        self.total_actions = 0
        self.capability_counts: Dict[str, int] = {}
        self.total_tokens = 0
        self.total_cost = 0.0

    def check_and_reserve(self, capability_name: str) -> Tuple[bool, Optional[str]]:
        """Atomically check and reserve an action against limits.
        
        Returns:
            Tuple[bool, Optional[str]]: (allowed, reason_if_exceeded)
        """
        with self._lock:
            # 1. Timeout check
            elapsed = time.time() - self.start_time
            if elapsed > self.budget.max_runtime_seconds:
                return False, f"Action budget exceeded: session runtime {elapsed:.1f}s > max {self.budget.max_runtime_seconds}s."

            # 2. Total actions limit
            if self.total_actions >= self.budget.max_actions:
                return False, f"Action budget exceeded: total actions {self.total_actions} >= max {self.budget.max_actions}."

            # 3. Per-capability limits
            cap_limit = self.budget.per_capability_limits.get(capability_name)
            curr_cap = self.capability_counts.get(capability_name, 0)
            if cap_limit is not None and curr_cap >= cap_limit:
                return False, f"Per-capability budget exceeded for '{capability_name}': {curr_cap} >= max {cap_limit}."

            # Reserve
            self.total_actions += 1
            self.capability_counts[capability_name] = curr_cap + 1
            return True, None

    def release_reservation(self, capability_name: str) -> None:
        """Release reservation if an action was denied or blocked prior to execution."""
        with self._lock:
            if self.total_actions > 0:
                self.total_actions -= 1
            curr_cap = self.capability_counts.get(capability_name, 0)
            if curr_cap > 0:
                self.capability_counts[capability_name] = curr_cap - 1

    def record_tokens(self, tokens: int) -> bool:
        """Record token usage. Returns False if token ceiling exceeded."""
        with self._lock:
            self.total_tokens += tokens
            if self.budget.max_tokens and self.total_tokens > self.budget.max_tokens:
                return False
            return True

    def record_cost(self, cost: float) -> bool:
        """Record monetary cost. Returns False if cost ceiling exceeded."""
        with self._lock:
            self.total_cost += cost
            if self.budget.max_cost and self.total_cost > self.budget.max_cost:
                return False
            return True
