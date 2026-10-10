"""
g2_authorizer.py - Independent In-Container Fault Authorization for Scenario G2 Helper.

Protocol Reference:
- Enforces single-use token claim with cluster-wide atomic locking.
- Supports exactly G2-L1 (10%), G2-L2 (30%), G2-L3 (50%) packet loss.
- Validates action == "EXECUTE_G2_FAULT_HELPER".
- Validates fault_type == "packet_loss".
- Validates distribution == "uniform".
- Validates netns inode dynamic binding.
- Rejects expired tokens, future-dated tokens, and invalid nonces.
"""

from abc import ABC, abstractmethod
import datetime
import errno
import hashlib
import json
import os
from typing import Any, Dict, Optional, Set

try:
    from benchmark.scripts.cockroachdb.g2.g2_packet_loss_runtime import (
        APPROVED_PACKET_LOSS_PERCENTAGES,
        APPROVED_LOSS_DISTRIBUTION,
    )
except ImportError:
    from g2_packet_loss_runtime import (
        APPROVED_PACKET_LOSS_PERCENTAGES,
        APPROVED_LOSS_DISTRIBUTION,
    )


class FaultAuthorizationError(PermissionError):
    """Raised when G2 fault authorization fails closed."""
    pass


class IClaimStore(ABC):
    """Abstract cluster-wide atomic create-only claim store."""

    @abstractmethod
    def acquire_once(self, claim_name: str, metadata: Dict[str, Any]) -> None:
        pass


class SharedAtomicClaimStore(IClaimStore):
    """Thread-safe shared atomic claim store for testing."""

    def __init__(self) -> None:
        import threading
        self._lock = threading.Lock()
        self._claims: Dict[str, Dict[str, Any]] = {}

    def acquire_once(self, claim_name: str, metadata: Dict[str, Any]) -> None:
        with self._lock:
            if claim_name in self._claims:
                raise FaultAuthorizationError(
                    f"Cross-Pod authorization replay blocked: claim '{claim_name}' already exists."
                )
            self._claims[claim_name] = dict(metadata)

    def has_claim(self, claim_name: str) -> bool:
        with self._lock:
            return claim_name in self._claims


class G2HelperFaultAuthorizer:
    """
    Validates and atomically claims single-use G2 helper fault authorization tokens.
    """

    TOKEN_FILENAME = "G2_FAULT_AUTHORIZED.json"
    LOCK_FILENAME = "G2_FAULT_AUTHORIZED.json.claim"
    EXPECTED_ACTION = "EXECUTE_G2_FAULT_HELPER"
    EXPECTED_FAULT_TYPE = "packet_loss"
    EXPECTED_DISTRIBUTION = APPROVED_LOSS_DISTRIBUTION
    MAX_TTL_MINUTES = 15
    CLOCK_SKEW_SECONDS = 30

    REQUIRED_FIELDS: Set[str] = frozenset({
        "run_id",
        "auth_nonce",
        "action",
        "target_pod",
        "target_namespace",
        "target_netns_inode",
        "fault_type",
        "loss_percentage",
        "loss_distribution",
        "duration_sec",
        "issued_at_utc",
        "expires_at_utc",
        "authorized_by_operator",
    })

    def __init__(
        self,
        base_dir: str,
        lock_dir: Optional[str] = None,
        allow_readonly_secret: bool = False,
        claim_store: Optional[IClaimStore] = None,
        holder_identity: Optional[str] = None,
    ):
        self.base_dir = base_dir
        self.lock_dir = lock_dir or base_dir
        self.allow_readonly_secret = allow_readonly_secret
        self.claim_store = claim_store
        self.holder_identity = holder_identity or os.environ.get("HOSTNAME", "g2-helper")

    @staticmethod
    def build_claim_name(run_id: str, auth_nonce: str) -> str:
        digest = hashlib.sha256(f"{run_id}:{auth_nonce}".encode("utf-8")).hexdigest()[:24]
        return f"g2-fault-claim-{digest}"

    @staticmethod
    def _parse_utc(raw: Any, label: str) -> datetime.datetime:
        if not isinstance(raw, str) or not raw.strip():
            raise FaultAuthorizationError(f"Invalid {label}: expected ISO-8601 UTC string.")
        try:
            dt = datetime.datetime.fromisoformat(raw.replace("Z", "+00:00"))
        except ValueError as exc:
            raise FaultAuthorizationError(f"Unparseable {label} '{raw}': {exc}") from exc
        if dt.tzinfo is None:
            raise FaultAuthorizationError(f"{label} must include timezone offset.")
        return dt.astimezone(datetime.timezone.utc)

    @staticmethod
    def _require_exact_int(value: Any, expected: int, field_name: str) -> None:
        if isinstance(value, bool) or not isinstance(value, int) or value != expected:
            raise FaultAuthorizationError(
                f"Fault authorization {field_name} mismatch: expected {expected}, got {value!r}."
            )

    def verify_and_claim(
        self,
        expected_run_id: str,
        expected_target_pod: str,
        expected_loss_percentage: int,
        expected_target_namespace: str = "cockroachdb",
        expected_duration_sec: int = 180,
        observed_netns_inode: Optional[str] = None,
        consume_token: bool = True,
        current_time_utc: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        if expected_loss_percentage not in APPROVED_PACKET_LOSS_PERCENTAGES:
            raise FaultAuthorizationError(
                f"Invalid expected_loss_percentage {expected_loss_percentage}%. "
                f"Must be one of {sorted(APPROVED_PACKET_LOSS_PERCENTAGES)}."
            )

        if self.allow_readonly_secret and self.claim_store is None:
            raise FaultAuthorizationError(
                "Fail-closed: read-only Secret mode requires a shared cluster-wide claim_store."
            )

        token_path = os.path.join(self.base_dir, self.TOKEN_FILENAME)
        lock_path = os.path.join(self.lock_dir, self.LOCK_FILENAME)

        if os.path.islink(lock_path):
            raise FaultAuthorizationError("Refusing symlinked claim lock file.")

        # Create pod-local lock file (O_CREAT | O_EXCL)
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"run_id={expected_run_id}\npod={expected_target_pod}\n".encode("utf-8"))
            os.close(fd)
        except FileExistsError as exc:
            raise FaultAuthorizationError("Fault authorization replay or concurrent claim blocked.") from exc
        except OSError as exc:
            raise FaultAuthorizationError(f"Failed to create fault claim lock in '{self.lock_dir}': {exc}") from exc

        # Read and parse token
        try:
            with open(token_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except Exception as exc:
            raise FaultAuthorizationError(f"Failed to read/parse fault authorization token: {exc}") from exc

        if not isinstance(payload, dict):
            raise FaultAuthorizationError("Fault authorization payload must be a JSON object.")

        # Schema validation (13 required fields)
        missing = self.REQUIRED_FIELDS - set(payload.keys())
        extra = set(payload.keys()) - self.REQUIRED_FIELDS
        if missing or extra:
            raise FaultAuthorizationError(
                f"Fault authorization schema mismatch: missing={sorted(missing)}, extra={sorted(extra)}."
            )

        if payload["action"] != self.EXPECTED_ACTION:
            raise FaultAuthorizationError(f"Invalid fault authorization action '{payload['action']}'.")
        if payload["run_id"] != expected_run_id:
            raise FaultAuthorizationError("Fault authorization run_id mismatch.")

        auth_nonce = payload["auth_nonce"]
        if not isinstance(auth_nonce, str) or len(auth_nonce.strip()) < 8:
            raise FaultAuthorizationError("Fault authorization auth_nonce must be a non-empty string (>= 8 chars).")

        if payload["target_pod"] != expected_target_pod:
            raise FaultAuthorizationError("Fault authorization target_pod mismatch.")
        if payload["target_namespace"] != expected_target_namespace:
            raise FaultAuthorizationError("Fault authorization target_namespace mismatch.")
        if payload["fault_type"] != self.EXPECTED_FAULT_TYPE:
            raise FaultAuthorizationError(f"Fault authorization fault_type mismatch: {payload['fault_type']!r}.")
        if payload["loss_distribution"] != self.EXPECTED_DISTRIBUTION:
            raise FaultAuthorizationError(
                f"Fault authorization loss_distribution mismatch: {payload['loss_distribution']!r}."
            )

        netns_inode = payload["target_netns_inode"]
        if not isinstance(netns_inode, str) or not netns_inode.strip():
            raise FaultAuthorizationError("Fault authorization target_netns_inode must be a non-empty string.")
        if observed_netns_inode is not None and netns_inode != observed_netns_inode:
            raise FaultAuthorizationError(
                f"Fault authorization netns_inode mismatch: token={netns_inode}, observed={observed_netns_inode}."
            )

        self._require_exact_int(payload["loss_percentage"], expected_loss_percentage, "loss_percentage")
        self._require_exact_int(payload["duration_sec"], expected_duration_sec, "duration_sec")

        if not isinstance(payload["authorized_by_operator"], str) or not payload["authorized_by_operator"].strip():
            raise FaultAuthorizationError("Fault authorization missing authorized_by_operator.")

        now = current_time_utc or datetime.datetime.now(datetime.timezone.utc)
        issued = self._parse_utc(payload["issued_at_utc"], "issued_at_utc")
        expires = self._parse_utc(payload["expires_at_utc"], "expires_at_utc")

        if issued > now + datetime.timedelta(seconds=self.CLOCK_SKEW_SECONDS):
            raise FaultAuthorizationError("Fault authorization issued_at_utc is in the future.")
        if now > expires:
            raise FaultAuthorizationError("Fault authorization token has expired.")
        if (expires - issued) > datetime.timedelta(minutes=self.MAX_TTL_MINUTES):
            raise FaultAuthorizationError(f"Fault authorization TTL exceeds {self.MAX_TTL_MINUTES} minutes.")

        if self.claim_store is not None:
            claim_name = self.build_claim_name(expected_run_id, auth_nonce.strip())
            self.claim_store.acquire_once(
                claim_name,
                {
                    "run_id": expected_run_id,
                    "auth_nonce": auth_nonce.strip(),
                    "target_pod": expected_target_pod,
                    "expires_at_utc": payload["expires_at_utc"],
                    "holder_identity": self.holder_identity,
                },
            )

        if consume_token:
            try:
                os.remove(token_path)
            except OSError as exc:
                if self.allow_readonly_secret and exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
                    pass
                else:
                    raise FaultAuthorizationError(
                        f"Failed to consume single-use fault token '{token_path}': {exc}"
                    ) from exc

        return payload

