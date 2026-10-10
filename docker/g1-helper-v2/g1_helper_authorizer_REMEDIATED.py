"""
PROPOSED REMEDIATED AUTHORIZER — STAGE 5.2.4 REVIEW ARTIFACT.

Incorporates SafePathResolver into G1HelperFaultAuthorizer:
1. Replaces raw `os.path.islink(token_path)` with SafePathResolver.
   - Allows valid Kubernetes Secret volume symlinks (`..data/<file>`) strictly
     when their canonical realpath resolves inside the canonical `base_dir`.
   - Rejects directory traversals or symlink escapes.
2. Preserves strict non-symlink enforcement on `lock_path` (`/var/run/g1-lock`).
3. Uses `read_atomic_confined_json()` to mitigate TOCTOU atomic replacement issues.
4. Preserves 100% of all existing validation:
   - 13 required fields
   - run_id, target_pod, target_namespace, delay_ms, jitter_ms, duration_sec exact matches
   - auth_nonce >= 8 chars
   - action == EXECUTE_G1_FAULT_HELPER
   - TTL <= 15 minutes, clock skew <= 30s
   - Dynamic netns inode validation
   - Cluster-wide atomic Kubernetes Lease claim
"""

import datetime
import errno
import hashlib
import json
import os
from typing import Any, Dict, Optional

from g1.g1_helper_authorizer import (  # baseline audited authorizer classes
    FaultAuthorizationError,
    G1HelperFaultAuthorizer,
    IClaimStore,
)
from g1_safe_path_resolver import PathSecurityError, SafePathResolver


class RemediatedG1HelperFaultAuthorizer(G1HelperFaultAuthorizer):
    """
    Subclasses G1HelperFaultAuthorizer with safe path resolution for Kubernetes projected secrets.
    """

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

        lock_path = os.path.join(self.lock_dir, self.LOCK_FILENAME)

        # 1. Lock file security: MUST NOT be a symlink under any circumstances
        if os.path.islink(lock_path):
            raise FaultAuthorizationError("Refusing symlinked claim lock file.")

        # 2. Verify token path containment before creating lock
        try:
            resolved_token_path, _ = SafePathResolver.resolve_confined_file(
                base_dir=self.base_dir,
                filename=self.TOKEN_FILENAME,
                allow_projected_symlink=True,
            )
        except (PathSecurityError, FileNotFoundError) as exc:
            raise FaultAuthorizationError(f"Fault authorization token verification failed: {exc}") from exc

        # 3. Create pod-local lock file (O_CREAT | O_EXCL)
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.write(fd, f"run_id={expected_run_id}\npod={expected_target_pod}\n".encode("utf-8"))
            os.close(fd)
        except FileExistsError as exc:
            raise FaultAuthorizationError("Fault authorization replay or concurrent claim blocked.") from exc
        except OSError as exc:
            raise FaultAuthorizationError(f"Failed to create fault claim lock in '{self.lock_dir}': {exc}") from exc

        # 4. Atomically read and parse token with path containment
        try:
            payload = SafePathResolver.read_atomic_confined_json(
                base_dir=self.base_dir,
                filename=self.TOKEN_FILENAME,
            )
        except Exception as exc:
            raise FaultAuthorizationError(f"Failed to read/parse fault authorization token: {exc}") from exc

        if not isinstance(payload, dict):
            raise FaultAuthorizationError("Fault authorization payload must be a JSON object.")

        # 5. Exact schema validation (13 required fields)
        missing = self.REQUIRED_FIELDS - set(payload.keys())
        extra = set(payload.keys()) - self.REQUIRED_FIELDS
        if missing or extra:
            raise FaultAuthorizationError(
                f"Fault authorization schema mismatch: missing={sorted(missing)}, extra={sorted(extra)}."
            )

        # 6. Action and parameter validation
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

        # 7. Time and TTL validation
        now = current_time_utc or datetime.datetime.now(datetime.timezone.utc)
        issued = self._parse_utc(payload["issued_at_utc"], "issued_at_utc")
        expires = self._parse_utc(payload["expires_at_utc"], "expires_at_utc")

        if issued > now + datetime.timedelta(seconds=self.CLOCK_SKEW_SECONDS):
            raise FaultAuthorizationError("Fault authorization issued_at_utc is in the future.")
        if now > expires:
            raise FaultAuthorizationError("Fault authorization token has expired.")
        if (expires - issued) > datetime.timedelta(minutes=self.MAX_TTL_MINUTES):
            raise FaultAuthorizationError(f"Fault authorization TTL exceeds {self.MAX_TTL_MINUTES} minutes.")

        # 8. Cluster-wide atomic claim store (Kubernetes Lease)
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

        # 9. Read-only secret token consumption attempt
        if consume_token:
            try:
                os.remove(resolved_token_path)
            except OSError as exc:
                if self.allow_readonly_secret and exc.errno in (errno.EROFS, errno.EACCES, errno.EPERM):
                    pass
                else:
                    raise FaultAuthorizationError(
                        f"Failed to consume single-use fault token '{resolved_token_path}': {exc}"
                    ) from exc

        return payload

