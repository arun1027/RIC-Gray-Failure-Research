"""
g1_recovery_authorizer.py - Fail-Closed Single-Use Emergency Recovery Authorization for Scenario G1.

Replaces the static G1_RECOVERY_AUTHORIZED environment-variable string check.
Enforces an application-level single-use authorization token (G1_RECOVERY_AUTHORIZED.json)
bound to:
- run_id
- target_pod_uid and target_pod_name
- target_pid and target_start_time_ticks
- netns_inode
- interface ('eth0')
- qdisc_handle ('100:') and qdisc_type ('netem')
- action ('EMERGENCY_TC_CLEANUP')
- issued_at_utc and expires_at_utc (bounded TTL)

SECURITY BOUNDARY NOTE:
This is an application-level authorization control. It is NOT a substitute for
Kubernetes RBAC (restricting Job creation in 'g1-chaos') or host/node security.
"""

import datetime
import json
import os
from typing import Any, Dict, Optional


class RecoveryAuthorizationError(Exception):
    """Raised when emergency recovery authorization fails closed."""
    pass


class G1RecoveryAuthorizer:
    """Validates and atomically consumes single-use emergency recovery tokens."""

    TOKEN_FILENAME = "G1_RECOVERY_AUTHORIZED.json"
    LOCK_FILENAME = "G1_RECOVERY_AUTHORIZED.json.claim"
    MAX_TTL_MINUTES = 15
    REQUIRED_FIELDS = frozenset({
        "run_id",
        "action",
        "target_pod_uid",
        "target_pod_name",
        "target_pid",
        "target_start_time_ticks",
        "netns_inode",
        "interface",
        "qdisc_handle",
        "qdisc_type",
        "issued_at_utc",
        "expires_at_utc",
        "authorized_by_operator",
    })

    def __init__(self, base_dir: str, lock_dir: Optional[str] = None, allow_readonly_secret: bool = True):
        self.base_dir = base_dir
        self.lock_dir = lock_dir or base_dir
        self.allow_readonly_secret = allow_readonly_secret

    @staticmethod
    def _parse_utc(raw: Any, label: str) -> datetime.datetime:
        if not isinstance(raw, str) or not raw.strip():
            raise RecoveryAuthorizationError(f"Invalid {label}: expected ISO-8601 UTC string.")
        try:
            dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise RecoveryAuthorizationError(f"Unparseable {label} '{raw}': {exc}") from exc
        if dt.tzinfo is None:
            raise RecoveryAuthorizationError(f"{label} must include timezone offset.")
        return dt.astimezone(datetime.timezone.utc)

    def verify_and_claim(
        self,
        expected_run_id: str,
        expected_pod_uid: str,
        expected_pod_name: str,
        observed_pid: int,
        observed_start_time_ticks: int,
        observed_netns_inode: str,
        observed_interface: str = "eth0",
        observed_qdisc_handle: str = "100:",
        observed_qdisc_type: str = "netem",
        consume_token: bool = True,
        current_time_utc: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        token_path = os.path.join(self.base_dir, self.TOKEN_FILENAME)
        lock_path = os.path.join(self.lock_dir, self.LOCK_FILENAME)

        if os.path.islink(token_path) or os.path.islink(lock_path):
            raise RecoveryAuthorizationError("Refusing symlinked recovery authorization token or claim lock.")
        if not consume_token and not self.allow_readonly_secret:
            raise RecoveryAuthorizationError(
                "Refusing non-consuming recovery claim unless allow_readonly_secret=True is explicitly enabled."
            )
        if not os.path.isfile(token_path):
            raise RecoveryAuthorizationError(f"Recovery authorization token not found: {token_path}")

        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError as exc:
            raise RecoveryAuthorizationError("Recovery token replay or concurrent claim blocked.") from exc
        except OSError as exc:
            raise RecoveryAuthorizationError(f"Failed to create recovery claim lock in '{self.lock_dir}': {exc}") from exc

        try:
            with open(token_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise RecoveryAuthorizationError(f"Failed to read/parse recovery token: {exc}") from exc

        if not isinstance(payload, dict):
            raise RecoveryAuthorizationError("Recovery token payload must be a JSON object.")

        missing = self.REQUIRED_FIELDS - set(payload.keys())
        extra = set(payload.keys()) - self.REQUIRED_FIELDS
        if missing or extra:
            raise RecoveryAuthorizationError(f"Recovery token schema mismatch: missing={sorted(missing)}, extra={sorted(extra)}.")

        if payload["action"] != "EMERGENCY_TC_CLEANUP":
            raise RecoveryAuthorizationError(f"Invalid recovery action '{payload['action']}'.")
        if payload["run_id"] != expected_run_id:
            raise RecoveryAuthorizationError("Recovery token run_id mismatch.")
        if payload["target_pod_uid"] != expected_pod_uid or payload["target_pod_name"] != expected_pod_name:
            raise RecoveryAuthorizationError("Recovery token target Pod UID/name mismatch.")
        if payload["target_pid"] != observed_pid or payload["target_start_time_ticks"] != observed_start_time_ticks:
            raise RecoveryAuthorizationError("Recovery token PID or start_time_ticks mismatch (PID reuse rejected).")
        if payload["netns_inode"] != observed_netns_inode:
            raise RecoveryAuthorizationError("Recovery token netns_inode mismatch.")
        if payload["interface"] != observed_interface:
            raise RecoveryAuthorizationError("Recovery token interface mismatch.")
        if payload["qdisc_handle"] != observed_qdisc_handle or payload["qdisc_type"] != observed_qdisc_type:
            raise RecoveryAuthorizationError("Recovery token qdisc handle/type ownership mismatch.")

        now = current_time_utc or datetime.datetime.now(datetime.timezone.utc)
        issued = self._parse_utc(payload["issued_at_utc"], "issued_at_utc")
        expires = self._parse_utc(payload["expires_at_utc"], "expires_at_utc")

        if issued > now + datetime.timedelta(seconds=30):
            raise RecoveryAuthorizationError("Recovery token issued_at_utc is in the future.")
        if now > expires:
            raise RecoveryAuthorizationError("Recovery token has expired.")
        if (expires - issued) > datetime.timedelta(minutes=self.MAX_TTL_MINUTES):
            raise RecoveryAuthorizationError(f"Recovery token TTL exceeds {self.MAX_TTL_MINUTES} minutes.")

        if consume_token:
            os.remove(token_path)

        return payload

