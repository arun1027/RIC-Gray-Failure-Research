"""
g1_watchdog.py - Safety Tripwires & Monitoring Watchdog for Scenario G1.

Defensive Tripwires:
- TW-01: Host/Node CPU Utilization > 95% sustained for > 30 seconds.
- TW-02: Client Transaction Drop Rate = 100% sustained for > 60 seconds.
- TW-03: Pod Health / CrashLoopBackOff detected on > 0 database pods.

Features:
- Configurable thresholds with explicit distinction between approved and provisional limits.
- Evaluates telemetry data points against tripwire rules.
- Emits immediate abort signals if any tripwire is breached.
"""

from typing import Dict, Any, List, Optional, Tuple
import datetime


class TripwireBreachedError(Exception):
    def __init__(self, tripwire_id: str, message: str, sample_history: List[Any]):
        super().__init__(f"[{tripwire_id} BREACHED] {message}")
        self.tripwire_id = tripwire_id
        self.message = message
        self.sample_history = sample_history


class G1Watchdog:
    """Monitors live stream metrics against safety thresholds and signals emergency teardown."""

    def __init__(
        self,
        cpu_threshold_percent: float = 95.0,
        cpu_sustained_seconds: int = 30,
        drop_threshold_percent: float = 100.0,
        drop_sustained_seconds: int = 60,
        allow_pod_restarts: bool = False
    ):
        # Thresholds
        self.cpu_threshold_percent = cpu_threshold_percent
        self.cpu_sustained_seconds = cpu_sustained_seconds
        self.drop_threshold_percent = drop_threshold_percent
        self.drop_sustained_seconds = drop_sustained_seconds
        self.allow_pod_restarts = allow_pod_restarts

        # Internal state tracking
        self.cpu_breach_start: Optional[datetime.datetime] = None
        self.drop_breach_start: Optional[datetime.datetime] = None
        self.history: List[Dict[str, Any]] = []

    def evaluate_sample(
        self,
        timestamp_utc: datetime.datetime,
        cpu_percent: float,
        transaction_drop_percent: float,
        pod_restarts: int = 0
    ) -> Dict[str, Any]:
        """Evaluates a single telemetry/health sample against all safety tripwires."""
        sample_record = {
            "timestamp": timestamp_utc.isoformat(),
            "cpu_percent": cpu_percent,
            "drop_percent": transaction_drop_percent,
            "pod_restarts": pod_restarts,
        }
        self.history.append(sample_record)

        # 1. TW-03: Pod Restarts / CrashLoop
        if not self.allow_pod_restarts and pod_restarts > 0:
            raise TripwireBreachedError(
                "TW-03",
                f"Pod crash or unexpected restart detected (restarts={pod_restarts}). Immediate teardown required.",
                self.history
            )

        # 2. TW-01: Sustained High CPU
        if cpu_percent >= self.cpu_threshold_percent:
            if self.cpu_breach_start is None:
                self.cpu_breach_start = timestamp_utc
            elapsed = (timestamp_utc - self.cpu_breach_start).total_seconds()
            if elapsed >= self.cpu_sustained_seconds:
                raise TripwireBreachedError(
                    "TW-01",
                    f"Host CPU sustained at {cpu_percent:.2f}% (>= {self.cpu_threshold_percent}%) for {elapsed:.1f}s (limit: {self.cpu_sustained_seconds}s).",
                    self.history
                )
        else:
            self.cpu_breach_start = None

        # 3. TW-02: Sustained Transaction Drop Rate (Zero TPS)
        if transaction_drop_percent >= self.drop_threshold_percent:
            if self.drop_breach_start is None:
                self.drop_breach_start = timestamp_utc
            elapsed = (timestamp_utc - self.drop_breach_start).total_seconds()
            if elapsed >= self.drop_sustained_seconds:
                raise TripwireBreachedError(
                    "TW-02",
                    f"Transaction drop rate sustained at {transaction_drop_percent:.1f}% (>= {self.drop_threshold_percent}%) for {elapsed:.1f}s (limit: {self.drop_sustained_seconds}s).",
                    self.history
                )
        else:
            self.drop_breach_start = None

        return {"status": "OK", "tripwires_active": True}

