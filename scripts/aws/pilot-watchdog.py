#!/usr/bin/env python3
"""
AWS EKS Pilot Watchdog & Cost Containment Safeguard (Hardened Production-Safety Version).
Monitors experiment execution against a hard maximum time limit (default: 4.0 hours / 14400s).

HARDENED VERIFICATION & CLEANUP AUDIT CONTROLS:
- Default mode is strictly DRY-RUN. Real teardown requires `--execute-teardown` AND
  `--confirm-teardown-phrase=DESTROY_RIC_PILOT_RESOURCES`.
- P0: Never marks `cleanup_status = SUCCESS_VERIFIED` merely because teardown exit code is 0.
- P1: Performs an independent post-teardown verification query (mockable in tests).
- P1: Separately records:
    1. Subprocess exit code
    2. Verification status (VERIFIED_CLEAN vs INCOMPLETE_RESOURCES)
    3. Residual resource list
- P1: Timeout or verification failure is never represented as successful cleanup.
"""

import os
import sys
import time
import json
import signal
import datetime
import argparse
import subprocess
from typing import Dict, Any, Optional, List, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_MAX_DURATION_SECONDS = 14400  # 4 hours
DEFAULT_POLL_INTERVAL_SECONDS = 30
DEFAULT_SUBPROCESS_TIMEOUT_SECONDS = 600
DEFAULT_REPORT_PATH = os.path.join(REPO_ROOT, "supervisor-review", "PILOT_WATCHDOG_REPORT.json")
MANDATORY_CONFIRMATION_PHRASE = "DESTROY_RIC_PILOT_RESOURCES"

class WatchdogValidationError(Exception):
    pass

class PilotWatchdog:
    def __init__(
        self,
        max_duration_seconds: int = DEFAULT_MAX_DURATION_SECONDS,
        poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
        report_path: str = DEFAULT_REPORT_PATH,
        teardown_script: Optional[str] = None,
        subprocess_timeout: int = DEFAULT_SUBPROCESS_TIMEOUT_SECONDS,
        execute_teardown: bool = False,
        confirmation_phrase: Optional[str] = None,
        expected_account_id: Optional[str] = None,
        pilot_run_id: Optional[str] = None
    ):
        if max_duration_seconds <= 0:
            raise WatchdogValidationError("max_duration_seconds must be a positive integer.")
        if poll_interval_seconds <= 0:
            raise WatchdogValidationError("poll_interval_seconds must be a positive integer.")
        if subprocess_timeout <= 0:
            raise WatchdogValidationError("subprocess_timeout must be a positive integer.")

        self.max_duration_seconds = max_duration_seconds
        self.poll_interval_seconds = poll_interval_seconds
        self.report_path = report_path
        self.teardown_script = teardown_script or os.path.join(REPO_ROOT, "scripts", "aws", "teardown-eks.sh")
        self.subprocess_timeout = subprocess_timeout
        self.execute_teardown = execute_teardown
        self.confirmation_phrase = confirmation_phrase
        self.expected_account_id = expected_account_id or os.environ.get("EXPECTED_AWS_ACCOUNT_ID", "")
        self.pilot_run_id = pilot_run_id or os.environ.get("PILOT_RUN_ID", "")

        self.start_time: Optional[float] = None
        self.terminated: bool = False
        self.termination_reason: str = "RUNNING"
        self.cleanup_status: str = "PENDING"
        self.subprocess_exit_code: Optional[int] = None
        self.verification_status: str = "UNVERIFIED"
        self.remaining_resources: List[str] = []
        self.log_entries = []

    def log(self, message: str):
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
        entry = {
            "timestamp": timestamp,
            "elapsed_seconds": round(elapsed, 2),
            "message": message
        }
        self.log_entries.append(entry)
        print(f"[{timestamp}] [WATCHDOG +{round(elapsed, 1)}s] {message}")

    def start(self):
        self.start_time = time.time()
        mode_str = "ACTIVE_EXECUTION" if self.execute_teardown else "DRY_RUN (Safe Default)"
        self.log(
            f"Pilot watchdog started. Mode: {mode_str}. "
            f"Max duration: {self.max_duration_seconds}s ({self.max_duration_seconds/3600:.2f}h), "
            f"poll interval: {self.poll_interval_seconds}s."
        )

    def check_timeout(self, current_time: Optional[float] = None) -> bool:
        now = current_time or time.time()
        if not self.start_time:
            return False
        elapsed = now - self.start_time
        if elapsed >= self.max_duration_seconds:
            self.termination_reason = f"TIMEOUT: Reached max duration limit of {self.max_duration_seconds}s"
            return True
        return False

    def verify_preconditions(self) -> bool:
        """
        Ensures teardown script and working directory exist before executing.
        """
        if not os.path.exists(self.teardown_script):
            self.log(f"ERROR: Teardown script missing at: {self.teardown_script}")
            return False
        if not os.path.isdir(REPO_ROOT):
            self.log(f"ERROR: Repository root directory missing at: {REPO_ROOT}")
            return False
        return True

    def perform_independent_verification(self) -> Tuple[bool, List[str]]:
        """
        Queries cloud CLI/APIs independently to verify zero residual billable resources.
        Audits: EKS cluster, node groups, Aurora DB cluster, EC2 instances, NAT gateways,
        and pilot-specific EBS volumes.
        Mockable in unit tests.
        """
        self.log("Performing independent post-cleanup resource verification across all resource types...")
        residual = []

        # 1. Check for remaining EKS cluster
        try:
            cmd = [
                "aws", "eks", "describe-cluster",
                "--name", "ric-gray-failure-eks",
                "--region", "us-east-1",
                "--query", "cluster.status",
                "--output", "text"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                err_msg = res.stderr.strip()
                if "ResourceNotFoundException" in err_msg or "Cannot find" in err_msg:
                    pass  # Truly absent
                else:
                    residual.append(f"VERIFICATION_ERROR_EKS_QUERY_FAILED:exit_{res.returncode}:{err_msg}")
            else:
                status = res.stdout.strip()
                if status in ["ACTIVE", "UPDATING", "DELETING"]:
                    residual.append(f"EKS_CLUSTER:{status}")
        except Exception as e:
            residual.append(f"VERIFICATION_ERROR_EKS:{e}")

        # 2. Check for remaining EKS Node Groups
        try:
            cmd = [
                "aws", "eks", "list-nodegroups",
                "--cluster-name", "ric-gray-failure-eks",
                "--region", "us-east-1",
                "--query", "nodegroups[*]",
                "--output", "text"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                err_msg = res.stderr.strip()
                if "ResourceNotFoundException" in err_msg:
                    pass
                else:
                    residual.append(f"VERIFICATION_ERROR_NODEGROUPS_QUERY_FAILED:exit_{res.returncode}:{err_msg}")
            else:
                ng_output = res.stdout.strip()
                if ng_output and ng_output != "None":
                    residual.append(f"EKS_NODEGROUPS:{ng_output}")
        except Exception as e:
            residual.append(f"VERIFICATION_ERROR_NODEGROUPS:{e}")

        # 3. Check for remaining Aurora cluster
        try:
            cmd = [
                "aws", "rds", "describe-db-clusters",
                "--db-cluster-identifier", "ric-aurora-cluster",
                "--region", "us-east-1",
                "--query", "DBClusters[0].Status",
                "--output", "text"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                err_msg = res.stderr.strip()
                if "DBClusterNotFoundFault" in err_msg or "not found" in err_msg.lower():
                    pass  # Truly absent
                else:
                    residual.append(f"VERIFICATION_ERROR_AURORA_QUERY_FAILED:exit_{res.returncode}:{err_msg}")
            else:
                output = res.stdout.strip()
                if output in ["available", "modifying", "deleting"]:
                    residual.append(f"AURORA_CLUSTER:{output}")
        except Exception as e:
            residual.append(f"VERIFICATION_ERROR_AURORA:{e}")

        # 4. Check for remaining Aurora DB instances
        try:
            cmd = [
                "aws", "rds", "describe-db-instances",
                "--region", "us-east-1",
                "--filters", "Name=db-cluster-id,Values=ric-aurora-cluster",
                "--query", "DBInstances[*].DBInstanceIdentifier",
                "--output", "text"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                err_msg = res.stderr.strip()
                if "DBInstanceNotFound" in err_msg:
                    pass
                else:
                    residual.append(f"VERIFICATION_ERROR_AURORA_INSTANCES_QUERY_FAILED:exit_{res.returncode}:{err_msg}")
            else:
                inst_output = res.stdout.strip()
                if inst_output and inst_output != "None":
                    residual.append(f"AURORA_INSTANCES:{inst_output}")
        except Exception as e:
            residual.append(f"VERIFICATION_ERROR_AURORA_INSTANCES:{e}")

        # 5. Check for remaining EC2 instances
        try:
            cmd = [
                "aws", "ec2", "describe-instances",
                "--region", "us-east-1",
                "--filters", "Name=tag:Project,Values=RIC-Gray-Failure-Research",
                             "Name=instance-state-name,Values=running,pending",
                "--query", "Reservations[*].Instances[*].InstanceId",
                "--output", "text"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                residual.append(f"VERIFICATION_ERROR_EC2_QUERY_FAILED:exit_{res.returncode}:{res.stderr.strip()}")
            else:
                output = res.stdout.strip()
                if output and output != "None":
                    residual.append(f"EC2_INSTANCES:{output}")
        except Exception as e:
            residual.append(f"VERIFICATION_ERROR_EC2:{e}")

        # 6. Check for remaining NAT Gateways
        try:
            cmd = [
                "aws", "ec2", "describe-nat-gateways",
                "--region", "us-east-1",
                "--filter", "Name=tag:Project,Values=RIC-Gray-Failure-Research",
                            "Name=state,Values=available,pending",
                "--query", "NatGateways[*].NatGatewayId",
                "--output", "text"
            ]
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if res.returncode != 0:
                residual.append(f"VERIFICATION_ERROR_NAT_QUERY_FAILED:exit_{res.returncode}:{res.stderr.strip()}")
            else:
                nat_output = res.stdout.strip()
                if nat_output and nat_output != "None":
                    residual.append(f"NAT_GATEWAYS:{nat_output}")
        except Exception as e:
            residual.append(f"VERIFICATION_ERROR_NAT:{e}")

        # 7. Check for remaining pilot-specific EBS volumes
        if self.pilot_run_id:
            try:
                cmd = [
                    "aws", "ec2", "describe-volumes",
                    "--region", "us-east-1",
                    "--filters", "Name=status,Values=available,in-use",
                                 "Name=tag:Project,Values=RIC-Gray-Failure-Research",
                                 f"Name=tag:PilotRunId,Values={self.pilot_run_id}",
                    "--query", "Volumes[*].VolumeId",
                    "--output", "text"
                ]
                res = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                if res.returncode != 0:
                    residual.append(f"VERIFICATION_ERROR_EBS_QUERY_FAILED:exit_{res.returncode}:{res.stderr.strip()}")
                else:
                    ebs_output = res.stdout.strip()
                    if ebs_output and ebs_output != "None":
                        residual.append(f"EBS_VOLUMES:{ebs_output}")
            except Exception as e:
                residual.append(f"VERIFICATION_ERROR_EBS:{e}")

        is_clean = len(residual) == 0
        return is_clean, residual

    def trigger_teardown(self) -> bool:
        """
        Executes or simulates teardown with fail-closed safety checks.
        Never declares success without independent verification pass.
        """
        self.log(f"Teardown evaluation triggered. Termination reason: {self.termination_reason}")

        # 1. Enforce Dry-Run by default
        if not self.execute_teardown:
            self.log("[DRY-RUN] Destructive teardown withheld (default mode). Pass --execute-teardown to enable.")
            self.cleanup_status = "SKIPPED_DRY_RUN_DEFAULT"
            self.verification_status = "NOT_APPLICABLE_DRY_RUN"
            return True

        # 2. Enforce explicit confirmation phrase
        if self.confirmation_phrase != MANDATORY_CONFIRMATION_PHRASE:
            self.log(
                f"ABORTED: Teardown confirmation phrase mismatch or missing. "
                f"Expected: '{MANDATORY_CONFIRMATION_PHRASE}'."
            )
            self.cleanup_status = "ABORTED_CONFIRMATION_REQUIRED"
            self.verification_status = "UNVERIFIED"
            return False

        # 3. Verify local script preconditions
        if not self.verify_preconditions():
            self.cleanup_status = "FAILED_PRECONDITIONS"
            self.verification_status = "UNVERIFIED"
            return False

        # 4. Execute with bounded timeout and explicit cwd
        try:
            self.log(f"Invoking {self.teardown_script} in {REPO_ROOT} with timeout={self.subprocess_timeout}s...")
            env = os.environ.copy()
            if self.expected_account_id:
                env["EXPECTED_AWS_ACCOUNT_ID"] = self.expected_account_id
            if self.pilot_run_id:
                env["PILOT_RUN_ID"] = self.pilot_run_id
            env["CONFIRM_DESTROY"] = "YES_DESTROY_RIC_INFRASTRUCTURE"

            res = subprocess.run(
                ["bash", self.teardown_script],
                cwd=REPO_ROOT,
                env=env,
                capture_output=True,
                text=True,
                timeout=self.subprocess_timeout
            )
            self.subprocess_exit_code = res.returncode

            if res.returncode != 0:
                self.log(f"ERROR: Teardown script failed with exit code {res.returncode}.")
                if res.stderr:
                    self.log(f"Teardown Stderr: {res.stderr.strip()}")
                self.cleanup_status = f"FAILED_EXIT_{res.returncode}"
                self.verification_status = "TEARDOWN_SCRIPT_FAILED"
                return False

            self.log("Teardown script subprocess exited with code 0. Running independent verification audit...")

            # 5. Independent Cleanup Verification Gate
            is_clean, remaining = self.perform_independent_verification()
            self.remaining_resources = remaining

            if is_clean:
                self.log("Independent verification confirmed: Zero residual resources detected.")
                self.cleanup_status = "SUCCESS_INDEPENDENTLY_VERIFIED"
                self.verification_status = "VERIFIED_ZERO_RESOURCES"
                return True
            else:
                self.log(f"CRITICAL WARNING: Teardown exited 0 but residual resources remain: {remaining}")
                self.cleanup_status = "INCOMPLETE_RESIDUAL_RESOURCES"
                self.verification_status = "FAILED_RESIDUAL_DETECTED"
                return False

        except subprocess.TimeoutExpired:
            self.log(f"ERROR: Teardown script timed out after {self.subprocess_timeout} seconds.")
            self.cleanup_status = "FAILED_TIMEOUT"
            self.verification_status = "TIMED_OUT"
            return False
        except Exception as e:
            self.log(f"ERROR: Teardown script invocation encountered exception: {e}")
            self.cleanup_status = f"FAILED_EXCEPTION_{type(e).__name__}"
            self.verification_status = "EXCEPTION_HALTED"
            return False

    def write_report(self) -> Dict[str, Any]:
        elapsed = time.time() - self.start_time if self.start_time else 0.0
        report = {
            "watchdog_version": "3.0.0-verified",
            "project": "RIC-Gray-Failure-Research",
            "max_duration_seconds": self.max_duration_seconds,
            "total_elapsed_seconds": round(elapsed, 2),
            "termination_reason": self.termination_reason,
            "cleanup_status": self.cleanup_status,
            "subprocess_exit_code": self.subprocess_exit_code,
            "verification_status": self.verification_status,
            "remaining_resources": self.remaining_resources,
            "execution_mode": "ACTIVE_EXECUTION" if self.execute_teardown else "DRY_RUN",
            "safety_boundaries": [
                "Dry-run is enforced by default; real destruction requires --execute-teardown and confirmation phrase.",
                "Timeout bounded to 600 seconds on subprocess destruction.",
                "Subprocess working directory strictly pinned to repository root.",
                "Independent post-cleanup API audit required before reporting SUCCESS_INDEPENDENTLY_VERIFIED."
            ],
            "log": self.log_entries
        }

        os.makedirs(os.path.dirname(self.report_path), exist_ok=True)
        with open(self.report_path, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        return report

def main():
    parser = argparse.ArgumentParser(
        description="Hardened Pilot Watchdog for duration monitoring and safe verified cloud cleanup."
    )
    parser.add_argument("--max-duration", type=int, default=DEFAULT_MAX_DURATION_SECONDS, help="Max duration in seconds")
    parser.add_argument("--poll-interval", type=int, default=DEFAULT_POLL_INTERVAL_SECONDS, help="Poll interval in seconds")
    parser.add_argument("--subprocess-timeout", type=int, default=DEFAULT_SUBPROCESS_TIMEOUT_SECONDS, help="Teardown subprocess timeout in seconds")
    parser.add_argument("--execute-teardown", action="store_true", default=False, help="Explicit opt-in to execute real teardown (default is dry-run)")
    parser.add_argument("--confirm-teardown-phrase", type=str, default="", help="Required confirmation phrase to execute teardown")
    parser.add_argument("--expected-account-id", type=str, default="", help="Expected 12-digit AWS Account ID")
    parser.add_argument("--pilot-run-id", type=str, default="", help="Specific Pilot Run Identifier")
    args = parser.parse_args()

    try:
        watchdog = PilotWatchdog(
            max_duration_seconds=args.max_duration,
            poll_interval_seconds=args.poll_interval,
            subprocess_timeout=args.subprocess_timeout,
            execute_teardown=args.execute_teardown,
            confirmation_phrase=args.confirm_teardown_phrase,
            expected_account_id=args.expected_account_id,
            pilot_run_id=args.pilot_run_id
        )
    except WatchdogValidationError as e:
        print(f"Watchdog Configuration Error: {e}", file=sys.stderr)
        sys.exit(1)

    # Register POSIX signal handlers where available
    def handle_sigterm(signum, frame):
        watchdog.termination_reason = "SIGTERM: External termination signal received"
        watchdog.log("Received SIGTERM signal.")
        watchdog.trigger_teardown()
        watchdog.write_report()
        sys.exit(0)

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_sigterm)

    watchdog.start()

    try:
        while True:
            time.sleep(watchdog.poll_interval_seconds)
            if watchdog.check_timeout():
                watchdog.log("Watchdog triggered timeout cutoff.")
                break
    except KeyboardInterrupt:
        watchdog.termination_reason = "KEYBOARD_INTERRUPT: Operator aborted pilot execution"
        watchdog.log("Received operator interrupt (Ctrl+C).")
    except Exception as e:
        watchdog.termination_reason = f"UNEXPECTED_ERROR: {type(e).__name__}: {e}"
        watchdog.log(f"CRITICAL: Watchdog encountered unexpected error: {e}")
        watchdog.cleanup_status = "ABORTED_ON_WATCHDOG_INTERNAL_ERROR"
        watchdog.verification_status = "UNVERIFIED_INTERNAL_ERROR"
        watchdog.write_report()
        print(f"Watchdog report written to: {watchdog.report_path}")
        sys.exit(1)

    watchdog.trigger_teardown()
    report = watchdog.write_report()
    print(f"Watchdog report written to: {watchdog.report_path}")

if __name__ == "__main__":
    main()
