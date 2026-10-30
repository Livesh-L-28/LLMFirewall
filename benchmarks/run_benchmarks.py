#!/usr/bin/env python3
"""Canonical developer execution interface for LLMFirewall Benchmarks (Phase 2).

Usage:
    python3 benchmarks/run_benchmarks.py [--suite all|security|perf] [--json] [--ci]
"""

from __future__ import annotations

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from benchmarks.runners.security_benchmark_runner import main

if __name__ == "__main__":
    main()
