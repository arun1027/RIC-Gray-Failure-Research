"""
g1_helper_authorizer.py - Independent In-Container Fault Authorization for Scenario G1 Helper.

Phase F.3.5 + F.3.6 Remediation:
- Enforces fail-closed, single-use, atomic claim locking bound to run_id, auth_nonce,
  target_pod, target_namespace, target_netns_inode, fault_type, delay_ms, jitter_ms,
  duration_sec, and bounded TTL.
- Phase F.3.6 Cross-Pod Replay Protection:
  Pod-local emptyDir locks alone cannot prevent replay across separate Kubernetes Pods/Jobs
  mounting the same readOnly Secret. Read-only Secret mode therefore REQUIRES a shared
  cluster-wide create-only claim store (KubernetesLeaseClaimStore using coordination.k8s.io/v1
  Lease with create+get RBAC only, no delete/update).
- Strictly separate from emergency recovery authorization (G1RecoveryAuthorizer).
"""

from abc import ABC, abstractmethod
import datetime
import errno
import hashlib
import json
import os
import ssl
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, Optional


class FaultAuthorizationError(PermissionError):
    """Raised when helper fault-injection authorization fails closed."""
    pass


class IClaimStore(ABC):
    """Abstract cluster-wide atomic create-only claim store."""

    @abstractmethod
    def acquire_once(self, claim_name: str, metadata: Dict[str, Any]) -> None:
        """Atomically create a persistent claim; raise FaultAuthorizationError if it already exists or fails."""
        pass


class SharedAtomicClaimStore(IClaimStore):
    """Thread-safe shared atomic claim store for offline multi-Pod/multi-Job testing."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._claims: Dict[str, Dict[str, Any]] = {}

    def acquire_once(self, claim_name: str, metadata: Dict[str, Any]) -> None:
        with self._lock:
            if claim_name in self._claims:
                raise FaultAuthorizationError(
                    f"Cross-Pod authorization replay blocked: shared claim '{claim_name}' already exists."
                )
            self._claims[claim_name] = dict(metadata)

    def has_claim(self, claim_name: str) -> bool:
        with self._lock:
            return claim_name in self._claims


class KubernetesLeaseClaimStore(IClaimStore):
    """
    Create-only Kubernetes coordination.k8s.io/v1 Lease claim store using Python stdlib.
    Requires ONLY 'create' (and 'get') RBAC on leases in the g1-chaos namespace.
    HTTP 409 Conflict (AlreadyExists) or any API/TLS/network error fails closed.
    """

    def __init__(
        self,
        namespace: str = "g1-chaos",
        api_server: Optional[str] = None,
        token_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/token",
        ca_path: str = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
        opener: Optional[Any] = None,
    ) -> None:
        self.namespace = namespace
        host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
        port = os.environ.get("KUBERNETES_SERVICE_PORT", "443")
        self.api_server = api_server or f"https://{host}:{port}"
        self.token_path = token_path
        self.ca_path = ca_path
        self.opener = opener

    def acquire_once(self, claim_name: str, metadata: Dict[str, Any]) -> None:
        try:
            with open(self.token_path, "r", encoding="utf-8") as tf:
                sa_token = tf.read().strip()
        except OSError as exc:
            raise FaultAuthorizationError(
                f"Fail-closed: unable to read ServiceAccount token for Lease claim: {exc}"
            ) from exc

        now_iso = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        lease_body = {
            "apiVersion": "coordination.k8s.io/v1",
            "kind": "Lease",
            "metadata": {
                "name": claim_name,
                "namespace": self.namespace,
                "labels": {
                    "app.kubernetes.io/part-of": "ric-gray-failure-research",
                    "ric.research/scenario": "g1",
                },
                "annotations": {
                    "ric.research/run-id": str(metadata.get("run_id", "")),
                    "ric.research/target-pod": str(metadata.get("target_pod", "")),
                    "ric.research/expires-at-utc": str(metadata.get("expires_at_utc", "")),
                },
            },
            "spec": {
                "holderIdentity": str(metadata.get("holder_identity", "g1-helper")),
                "leaseDurationSeconds": 900,
                "acquireTime": now_iso,
            },
        }
        url = f"{self.api_server}/apis/coordination.k8s.io/v1/namespaces/{self.namespace}/leases"
        req = urllib.request.Request(
            url,
            data=json.dumps(lease_body).encode("utf-8"),
            method="POST",
            headers={
                "Authorization": f"Bearer {sa_token}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
        )
        try:
            if self.opener is not None:
                resp = self.opener(req)
                status = getattr(resp, "status", 201)
                raw_body = resp.read() if hasattr(resp, "read") else None
            else:
                ctx = ssl.create_default_context(cafile=self.ca_path)
                with urllib.request.urlopen(req, context=ctx, timeout=5) as resp:
                    status = resp.status
                    raw_body = resp.read()
            if status not in (200, 201):
                raise FaultAuthorizationError(f"Unexpected Kubernetes Lease claim HTTP status: {status}")
            if raw_body is not None:
                parsed = json.loads(raw_body.decode("utf-8"))
                if not isinstance(parsed, dict) or parsed.get("kind") != "Lease" or parsed.get("metadata", {}).get("name") != claim_name:
                    raise FaultAuthorizationError("Malformed Kubernetes Lease claim response payload.")
        except urllib.error.HTTPError as exc:
            if exc.code == 409:
                raise FaultAuthorizationError(
                    f"Cross-Pod authorization replay blocked: Lease '{claim_name}' already exists (HTTP 409)."
                ) from exc
            raise FaultAuthorizationError(
                f"Kubernetes Lease claim failed closed with HTTP {exc.code}: {exc.reason}"
            ) from exc
        except FaultAuthorizationError:
            raise
        except Exception as exc:
            raise FaultAuthorizationError(f"Kubernetes Lease claim failed closed: {exc}") from exc


class G1HelperFaultAuthorizer:
    """Validates and atomically claims single-use G1 helper fault authorization tokens."""

    TOKEN_FILENAME = "G1_FAULT_AUTHORIZED.json"
    LOCK_FILENAME = "G1_FAULT_AUTHORIZED.json.claim"
    EXPECTED_ACTION = "EXECUTE_G1_FAULT_HELPER"
    EXPECTED_FAULT_TYPE = "egress_latency"
    MAX_TTL_MINUTES = 15
    CLOCK_SKEW_SECONDS = 30

    REQUIRED_FIELDS = frozenset({
        "run_id",
        "auth_nonce",
        "action",
        "target_pod",
        "target_namespace",
        "target_netns_inode",
        "fault_type",
        "delay_ms",
        "jitter_ms",
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
        self.holder_identity = holder_identity or os.environ.get("HOSTNAME", "g1-helper")

    @staticmethod
    def build_claim_name(run_id: str, auth_nonce: str) -> str:
        digest = hashlib.sha256(f"{run_id}:{auth_nonce}".encode("utf-8")).hexdigest()[:24]
        return f"g1-fault-claim-{digest}"

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
        expected_target_namespace: str = "cockroachdb",
        expected_fault_type: str = "egress_latency",
        expected_delay_ms: int = 1000,
        expected_jitter_ms: int = 20,
        expected_duration_sec: int = 180,
        observed_netns_inode: Optional[str] = None,
        consume_token: bool = True,
        current_time_utc: Optional[datetime.datetime] = None,
    ) -> Dict[str, Any]:
        if self.allow_readonly_secret and self.claim_store is None:
            raise FaultAuthorizationError(
                "Fail-closed: read-only Secret mode requires a shared cluster-wide claim_store "
                "(pod-local emptyDir alone cannot prevent cross-Pod replay)."
            )

        token_path = os.path.join(self.base_dir, self.TOKEN_FILENAME)
        lock_path = os.path.join(self.lock_dir, self.LOCK_FILENAME)

        if os.path.islink(token_path) or os.path.islink(lock_path):
            raise FaultAuthorizationError("Refusing symlinked fault authorization token or claim lock.")
        if not os.path.isfile(token_path):
            raise FaultAuthorizationError(f"Fault authorization token not found: {token_path}")

        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"run_id={expected_run_id}\npod={expected_target_pod}\n".encode("utf-8"))
            os.close(fd)
        except FileExistsError as exc:
            raise FaultAuthorizationError("Fault authorization replay or concurrent claim blocked.") from exc
        except OSError as exc:
            raise FaultAuthorizationError(f"Failed to create fault claim lock in '{self.lock_dir}': {exc}") from exc

        try:
            with open(token_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError) as exc:
            raise FaultAuthorizationError(f"Failed to read/parse fault authorization token: {exc}") from exc

        if not isinstance(payload, dict):
            raise FaultAuthorizationError("Fault authorization payload must be a JSON object.")

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
        if payload["fault_type"] != expected_fault_type or payload["fault_type"] != self.EXPECTED_FAULT_TYPE:
            raise FaultAuthorizationError(f"Fault authorization fault_type mismatch: {payload['fault_type']!r}.")

        netns_inode = payload["target_netns_inode"]
        if not isinstance(netns_inode, str) or not netns_inode.strip():
            raise FaultAuthorizationError("Fault authorization target_netns_inode must be a non-empty string.")
        if observed_netns_inode is not None and netns_inode != observed_netns_inode:
            raise FaultAuthorizationError(
                f"Fault authorization netns_inode mismatch: token={netns_inode}, observed={observed_netns_inode}."
            )

        self._require_exact_int(payload["delay_ms"], expected_delay_ms, "delay_ms")
        self._require_exact_int(payload["jitter_ms"], expected_jitter_ms, "jitter_ms")
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

    @staticmethod
    def verify_target_binding(payload: Dict[str, Any], observed_netns_inode: str) -> None:
        """Verifies bound Linux netns inode against the claimed authorization token."""
        expected_inode = payload.get("target_netns_inode")
        if not expected_inode or expected_inode != observed_netns_inode:
            raise FaultAuthorizationError(
                f"Bound target netns_inode mismatch: authorized={expected_inode!r}, observed={observed_netns_inode!r}."
            )
