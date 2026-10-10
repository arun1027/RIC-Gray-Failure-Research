"""
G1 Package Initialization.
Defines core interfaces, constants, and governance tags for the CockroachDB G1 Gray-Failure Pilot.
"""

from typing import Dict, Any

# Governance and Scenario Constants
SCENARIO_ID = "G1-L2"
TARGET_ARCHITECTURE = "cockroachdb-ccl-v26.3.2"
DEFAULT_LATENCY_MS = 1000
DEFAULT_JITTER_MS = 20
DEFAULT_DISTRIBUTION = "normal"
DEFAULT_WARMUP_SEC = 120
DEFAULT_FAULT_INJECTION_SEC = 120
DEFAULT_FAULT_DURATION_SEC = 180
DEFAULT_FAULT_CLEARANCE_SEC = 300
DEFAULT_MEASUREMENT_SEC = 600
DEFAULT_OBSERVATION_SEC = 300
DEFAULT_CLIENTS = 20
DEFAULT_THREADS = 4
DEFAULT_SCALE_FACTOR = 50
DEFAULT_RETRY_POLICY = "--max-tries=1"

# Governance Status Flags
PHYSICAL_SELECTION_RULE_STATUS = "PROVISIONAL_PENDING_SUPERVISOR_APPROVAL"
RTO_PRIMARY_DEFINITION = "CA2_T2_MINUS_T0"
RTO_SUPPLEMENTARY_DEFINITION = "ROLLING_STEADY_STATE_RESTORATION_90PCT"


from .g1_helper_daemon import (
    PrivilegedHelperDaemon,
    HelperSecurityContext,
    TargetNamespaceSpec,
    AutonomousWatchdog,
    HelperFaultController,
    CapabilityMissingError,
    TargetVerificationError,
    WatchdogTimeoutError
)
