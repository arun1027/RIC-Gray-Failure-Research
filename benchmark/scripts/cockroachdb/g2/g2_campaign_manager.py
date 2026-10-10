"""
g2_campaign_manager.py - Campaign Orchestrator for CockroachDB G2 Series.

Protocol Invariants:
- Levels: G2-L1 (10%), G2-L2 (30%), G2-L3 (50%)
- Repetitions: N=10 per level (Authoritative Protocol Mandate)
- Total: 30 formal runs per database
- Unique Run IDs: crdb-g2l1-formal-f01..f10, crdb-g2l2-formal-f01..f10, crdb-g2l3-formal-f01..f10
- Never silently retries or overwrites a failed formal repetition.
"""

from typing import Dict, List, Optional
from benchmark.scripts.cockroachdb.g2.g2_executor import (
    G2RunPlan,
    G2Executor,
    VALID_G2_LEVELS,
    EXPECTED_FORMAL_REPETITIONS,
)


class G2CampaignManager:
    """Manages the full 30-run CockroachDB G2 formal series."""

    TOTAL_FORMAL_RUNS = len(VALID_G2_LEVELS) * EXPECTED_FORMAL_REPETITIONS  # 3 * 10 = 30

    @classmethod
    def generate_campaign_plan(cls) -> List[G2RunPlan]:
        plans: List[G2RunPlan] = []
        for level in sorted(VALID_G2_LEVELS.keys()):
            for rep in range(1, EXPECTED_FORMAL_REPETITIONS + 1):
                plans.append(G2RunPlan.create(level=level, repetition=rep))
        return plans

    @classmethod
    def validate_run_id_uniqueness(cls, plans: List[G2RunPlan]) -> bool:
        seen = set()
        for p in plans:
            if p.run_id in seen:
                return False
            seen.add(p.run_id)
        return len(seen) == cls.TOTAL_FORMAL_RUNS

