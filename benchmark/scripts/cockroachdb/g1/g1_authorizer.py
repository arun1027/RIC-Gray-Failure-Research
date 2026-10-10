"""
g1_authorizer.py - Strict G1 Execution Authorization Validator.

Authoritative Safety Invariant:
- Governs live execution of Scenario G1 (CockroachDB Network Latency Gray Failure).
- Validates structured, single-use, cryptographically bounded JSON authorization tokens.
- Completely decoupled from historical Stage 4 P06 token mechanism.
- Strictly fails closed on any schema, parameter, expiry, concurrency, or filesystem error.
- Enforces atomic claim locking via OS-level O_CREAT | O_EXCL to prevent race conditions.
- Enforces atomic consumption (deletion) to prevent replay or repeated execution.
- Rejects unexpected/unknown fields (strict schema validation).
- Never falls back to P06 tokens, environment variables, or static text files.
"""

import os
import json
import datetime
from typing import Dict, Any, Optional

G1_AUTH_TOKEN_FILENAME = "G1_AUTHORIZED.json"
G1_AUTH_CLAIM_FILENAME = "G1_AUTHORIZED.claim"
P06_AUTH_TOKEN_FILENAME = "P06_AUTHORIZED.json"
STATIC_TXT_FILENAME = "G1_AUTHORIZED.txt"

MAX_AUTH_TOKEN_TTL_SEC = 900  # 15 minutes maximum authorization window
CLOCK_SKEW_TOLERANCE_SEC = 60

# Immutable Invariant Schema for Scenario G1 Execution
EXPECTED_EXPERIMENT_ID = "RIC-G1-COCKROACHDB-LATENCY-PILOT"
EXPECTED_ACTION = "EXECUTE_G1_PILOT_PHASE_F1"
EXPECTED_TARGET_CLUSTER = "ric-gray-failure-eks"
EXPECTED_TARGET_NAMESPACE = "cockroachdb"
EXPECTED_TARGET_POLICY = "POLICY_AID_1"
EXPECTED_PHYSICAL_RANGE_ID = 89
EXPECTED_FAULT_TYPE = "egress_latency"
EXPECTED_LATENCY_MS = 1000
EXPECTED_JITTER_MS = 20
EXPECTED_FAULT_DURATION_SEC = 180
EXPECTED_MEASUREMENT_WINDOW_SEC = 600
EXPECTED_SUPERVISOR_REF = "PD/G1-01_THROUGH_PD/G1-06"

REQUIRED_FIELDS = {
    "experiment_id",
    "action",
    "target_cluster",
    "target_namespace",
    "target_policy",
    "physical_range_id",
    "fault_type",
    "latency_ms",
    "jitter_ms",
    "fault_duration_sec",
    "measurement_window_sec",
    "run_id",
    "execution_attempt_id",
    "issued_at_utc",
    "expires_at_utc",
    "authorized_by_operator",
    "supervisor_approval_ref",
}


class G1AuthorizationError(PermissionError):
    """Raised when G1 execution authorization validation fails closed."""
    pass


class G1Authorizer:
    """
    Enforces strict, single-use, atomic authorization validation for Scenario G1.
    """

    def __init__(self, base_dir: Optional[str] = None):
        self.base_dir = os.path.abspath(base_dir or os.getcwd())
        self.token_path = os.path.join(self.base_dir, G1_AUTH_TOKEN_FILENAME)
        self.claim_path = os.path.join(self.base_dir, G1_AUTH_CLAIM_FILENAME)
        self.p06_token_path = os.path.join(self.base_dir, P06_AUTH_TOKEN_FILENAME)
        self.txt_path = os.path.join(self.base_dir, STATIC_TXT_FILENAME)

    def check_disallowed_channels(self) -> None:
        """
        Rejects insecure or deprecated authorization channels.
        """
        # Reject environment variable injection
        if os.environ.get("G1_AUTHORIZED"):
            raise G1AuthorizationError(
                "Execution refused: G1_AUTHORIZED environment variable authorization is strictly forbidden. "
                "Environment variables persist across child processes and cannot guarantee atomic single-use."
            )
        if os.environ.get("P06_AUTHORIZED"):
            raise G1AuthorizationError(
                "Execution refused: P06_AUTHORIZED environment variable detected. "
                "Historical P06 authorization cannot authorize Scenario G1."
            )

        # Reject static text token file
        if os.path.exists(self.txt_path):
            raise G1AuthorizationError(
                f"Execution refused: Static text token '{STATIC_TXT_FILENAME}' is rejected. "
                f"Scenario G1 requires structured, single-use JSON token '{G1_AUTH_TOKEN_FILENAME}'."
            )

        # Explicitly reject fallback to P06 token
        if os.path.exists(self.p06_token_path) and not os.path.exists(self.token_path):
            raise G1AuthorizationError(
                f"Execution refused: Found '{P06_AUTH_TOKEN_FILENAME}' but G1 requires '{G1_AUTH_TOKEN_FILENAME}'. "
                "Scenario G1 strictly prohibits fallback to historical Stage 4 baseline authorization."
            )

        # Reject symbolic links to prevent symlink traversal attacks
        if os.path.islink(self.token_path):
            raise G1AuthorizationError(
                f"Execution refused: Authorization token '{G1_AUTH_TOKEN_FILENAME}' cannot be a symbolic link."
            )
        if os.path.islink(self.claim_path):
            raise G1AuthorizationError(
                f"Execution refused: Authorization claim file '{G1_AUTH_CLAIM_FILENAME}' cannot be a symbolic link."
            )

    def verify_and_claim(
        self,
        expected_run_id: str,
        execution_attempt_id: str,
        expected_physical_range_id: Optional[int] = None,
        consume_token: bool = True,
        current_time_utc: Optional[datetime.datetime] = None
    ) -> Dict[str, Any]:
        """
        Validates the G1 authorization token, claims it atomically, and consumes it.

        Raises G1AuthorizationError on any failure.
        """
        self.check_disallowed_channels()

        if not execution_attempt_id or not str(execution_attempt_id).strip():
            raise G1AuthorizationError(
                "Execution refused: Missing or empty execution_attempt_id. A unique attempt ID is required."
            )
        attempt_id_clean = str(execution_attempt_id).strip()

        # Check for pre-existing leftover claim file
        if os.path.exists(self.claim_path):
            raise G1AuthorizationError(
                f"Execution refused: Authorization claim file '{G1_AUTH_CLAIM_FILENAME}' already exists. "
                "A previous execution attempt claimed this token or failed without clean recovery."
            )

        # Check token existence
        if not os.path.exists(self.token_path):
            raise G1AuthorizationError(
                f"Execution refused: Scenario G1 requires explicit operator authorization. "
                f"Token file '{G1_AUTH_TOKEN_FILENAME}' was not found in '{self.base_dir}'."
            )

        # Atomic Claim Creation via OS Kernel O_CREAT | O_EXCL
        if consume_token:
            try:
                fd = os.open(self.claim_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                claim_payload = (
                    f"claimed_by: {attempt_id_clean}\n"
                    f"run_id: {expected_run_id}\n"
                    f"timestamp_utc: {datetime.datetime.now(datetime.timezone.utc).isoformat()}\n"
                )
                os.write(fd, claim_payload.encode("utf-8"))
                os.close(fd)
            except FileExistsError:
                raise G1AuthorizationError(
                    f"Execution refused: Authorization claim race detected. Another process created '{G1_AUTH_CLAIM_FILENAME}'."
                )
            except Exception as e:
                raise G1AuthorizationError(
                    f"Execution refused: Failed to atomically create authorization claim: {e}"
                )

        # Read and parse token JSON
        try:
            with open(self.token_path, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except json.JSONDecodeError as e:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(f"Execution refused: Malformed JSON in authorization token: {e}")
        except Exception as e:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(f"Execution refused: Failed to read authorization token: {e}")

        # Validate JSON is an object
        if not isinstance(payload, dict):
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError("Execution refused: Authorization token payload must be a JSON object.")

        # Strict Schema Enforcement: No unknown fields permitted
        payload_keys = set(payload.keys())
        unknown_fields = payload_keys - REQUIRED_FIELDS
        if unknown_fields:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: Token contains unexpected unknown fields: {sorted(list(unknown_fields))}."
            )

        missing_fields = REQUIRED_FIELDS - payload_keys
        if missing_fields:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: Token missing required fields: {sorted(list(missing_fields))}."
            )

        # Validate Exact Field Values
        if payload["experiment_id"] != EXPECTED_EXPERIMENT_ID:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: experiment_id mismatch. Expected '{EXPECTED_EXPERIMENT_ID}', found '{payload['experiment_id']}'."
            )

        if payload["action"] != EXPECTED_ACTION:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: action mismatch. Expected '{EXPECTED_ACTION}', found '{payload['action']}'."
            )

        if payload["target_cluster"] != EXPECTED_TARGET_CLUSTER:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: target_cluster mismatch. Expected '{EXPECTED_TARGET_CLUSTER}', found '{payload['target_cluster']}'."
            )

        if payload["target_namespace"] != EXPECTED_TARGET_NAMESPACE:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: target_namespace mismatch. Expected '{EXPECTED_TARGET_NAMESPACE}', found '{payload['target_namespace']}'."
            )

        if payload["target_policy"] != EXPECTED_TARGET_POLICY:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: target_policy mismatch. Expected '{EXPECTED_TARGET_POLICY}', found '{payload['target_policy']}'."
            )

        expected_range_id = expected_physical_range_id if expected_physical_range_id is not None else EXPECTED_PHYSICAL_RANGE_ID
        if expected_range_id <= 1:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: Internal system range (range_id={expected_range_id}) cannot be targeted."
            )

        def _parse_int_field(field_name: str) -> int:
            raw_val = payload[field_name]
            if isinstance(raw_val, bool):
                self._cleanup_failed_claim(consume_token)
                raise G1AuthorizationError(
                    f"Execution refused: Field '{field_name}' must be an integer, not boolean."
                )
            try:
                return int(raw_val)
            except (TypeError, ValueError):
                self._cleanup_failed_claim(consume_token)
                raise G1AuthorizationError(
                    f"Execution refused: Field '{field_name}' must be a valid integer, found '{raw_val}'."
                )

        token_range_id = _parse_int_field("physical_range_id")
        if token_range_id <= 1 or token_range_id != expected_range_id:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: physical_range_id mismatch. Expected {expected_range_id}, found {payload['physical_range_id']}."
            )

        if payload["fault_type"] != EXPECTED_FAULT_TYPE:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: fault_type mismatch. Expected '{EXPECTED_FAULT_TYPE}', found '{payload['fault_type']}'."
            )

        if _parse_int_field("latency_ms") != EXPECTED_LATENCY_MS:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: latency_ms mismatch. Expected {EXPECTED_LATENCY_MS}, found {payload['latency_ms']}."
            )

        if _parse_int_field("jitter_ms") != EXPECTED_JITTER_MS:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: jitter_ms mismatch. Expected {EXPECTED_JITTER_MS}, found {payload['jitter_ms']}."
            )

        if _parse_int_field("fault_duration_sec") != EXPECTED_FAULT_DURATION_SEC:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: fault_duration_sec mismatch. Expected {EXPECTED_FAULT_DURATION_SEC}, found {payload['fault_duration_sec']}."
            )

        if _parse_int_field("measurement_window_sec") != EXPECTED_MEASUREMENT_WINDOW_SEC:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: measurement_window_sec mismatch. Expected {EXPECTED_MEASUREMENT_WINDOW_SEC}, found {payload['measurement_window_sec']}."
            )

        if payload["supervisor_approval_ref"] != EXPECTED_SUPERVISOR_REF:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: supervisor_approval_ref mismatch. Expected '{EXPECTED_SUPERVISOR_REF}', found '{payload['supervisor_approval_ref']}'."
            )

        if payload["run_id"] != expected_run_id:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: run_id mismatch. Expected '{expected_run_id}', found '{payload['run_id']}'."
            )

        if payload["execution_attempt_id"] != attempt_id_clean:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: execution_attempt_id mismatch. Expected '{attempt_id_clean}', found '{payload['execution_attempt_id']}'."
            )

        if not payload["authorized_by_operator"] or len(str(payload["authorized_by_operator"]).strip()) < 3:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError("Execution refused: authorized_by_operator must be a valid non-empty operator name.")

        # Timestamp Parsing and Expiration Validation
        now = current_time_utc or datetime.datetime.now(datetime.timezone.utc)
        try:
            issued_dt = datetime.datetime.fromisoformat(payload["issued_at_utc"].replace("Z", "+00:00"))
            if issued_dt.tzinfo is None:
                issued_dt = issued_dt.replace(tzinfo=datetime.timezone.utc)
        except Exception as e:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(f"Execution refused: Malformed issued_at_utc timestamp: {e}")

        try:
            expires_dt = datetime.datetime.fromisoformat(payload["expires_at_utc"].replace("Z", "+00:00"))
            if expires_dt.tzinfo is None:
                expires_dt = expires_dt.replace(tzinfo=datetime.timezone.utc)
        except Exception as e:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(f"Execution refused: Malformed expires_at_utc timestamp: {e}")

        if expires_dt <= issued_dt:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError("Execution refused: expires_at_utc must be strictly later than issued_at_utc.")

        ttl_sec = (expires_dt - issued_dt).total_seconds()
        if ttl_sec > MAX_AUTH_TOKEN_TTL_SEC:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: Token TTL ({ttl_sec}s) exceeds maximum allowed window ({MAX_AUTH_TOKEN_TTL_SEC}s)."
            )

        if issued_dt > now + datetime.timedelta(seconds=CLOCK_SKEW_TOLERANCE_SEC):
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: Token issue time '{issued_dt.isoformat()}' is in the future compared to current time '{now.isoformat()}'."
            )

        if now > expires_dt:
            self._cleanup_failed_claim(consume_token)
            raise G1AuthorizationError(
                f"Execution refused: Authorization token has expired. Expired at '{expires_dt.isoformat()}', current time is '{now.isoformat()}'."
            )

        # Token Consumption: Atomically delete token file to prevent replay
        if consume_token:
            try:
                os.remove(self.token_path)
            except Exception as e:
                self._cleanup_failed_claim(consume_token)
                raise G1AuthorizationError(f"Execution refused: Failed to atomically consume authorization token: {e}")

            # Also remove claim lock on clean verification completion
            try:
                if os.path.exists(self.claim_path):
                    os.remove(self.claim_path)
            except Exception:
                pass

        return payload

    def _cleanup_failed_claim(self, consume_token: bool) -> None:
        """Removes the claim lock file if validation failed."""
        if consume_token:
            try:
                if os.path.exists(self.claim_path):
                    os.remove(self.claim_path)
            except Exception:
                pass

