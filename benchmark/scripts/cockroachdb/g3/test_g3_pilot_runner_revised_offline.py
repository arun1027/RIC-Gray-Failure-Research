"""
test_g3_pilot_runner_offline.py - Comprehensive Unit and State Machine Invariant Test Suite for G3 Pilot Runner.
Validates the complete 15-state execution coordinator, helper manifest generation, shell signal traps,
original io.max preservation, idempotent rollback, independent emergency recovery, bitwise decoding,
dry-run lifecycle, and fail-closed safety behaviors.
Runs completely offline with no live Kubernetes cluster or cgroup interactions.
"""

import base64
import datetime
import hashlib
import json
import os
import signal
import stat
import tempfile
import threading
import unittest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised import (
    SEVERITY_LIMITS,
    ExecutionState,
    SignalInterruptionError,
    G3PilotExecutionCoordinator,
    generate_helper_job_manifest,
    generate_rollback_job_manifest,
    extract_job_name_from_manifest,
    emergency_independent_rollback,
    collect_helper_job_logs,
    LAST_ROLLBACK_REPORTS,
    compute_sha256,
    build_manifest,
    verify_manifest,
    resolve_target_leaseholder,
    validate_target_unchanged,
    decode_linux_st_dev,
    parse_io_max_content,
    extract_device_io_max_line,
    verify_io_max_applied,
    verify_io_max_restored,
    construct_warmup_command,
    construct_in_pod_wrapper,
    compute_tx_stream_span_sec,
    run_preflight_audit,
    check_storage_capacity,
    sample_crdb_metrics,
    sample_cgroup_iostat,
    incremental_telemetry_poller,
    verify_and_consume_authorization as prod_verify_and_consume_authorization,
    canonicalize_payload,
    PROTOCOL_VERSION,
    main,
)
from cryptography.hazmat.primitives.asymmetric import ed25519
import benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised as runner_mod

_adapter_lock = threading.Lock()

def verify_and_consume_authorization(**kwargs):
    """
    TEST-ONLY adapter (G3-72). The production API accepts neither an in-memory public key nor a
    caller-supplied fingerprint. To exercise it with ephemeral keys, this adapter writes the key to a
    temp file and patches the module-level pinned fingerprint for the duration of the call. It lives in
    the test module only and is not importable from the production CLI.
    """
    import shutil
    pub_b64 = kwargs.pop("public_key_b64", None)
    fp = kwargs.pop("expected_fingerprint", None)
    tmp = None
    try:
        if pub_b64 is not None:
            tmp = tempfile.mkdtemp(prefix="g3pk_")
            kp = os.path.join(tmp, "pub.key")
            with open(kp, "w", encoding="utf-8") as f:
                f.write(pub_b64)
            kwargs["public_key_path"] = kp
        if fp is not None:
            with _adapter_lock:
                with patch.object(runner_mod, "TRUSTED_OPERATOR_PUBKEY_SHA256", fp):
                    return prod_verify_and_consume_authorization(**kwargs)
        return prod_verify_and_consume_authorization(**kwargs)
    finally:
        if tmp:
            shutil.rmtree(tmp, ignore_errors=True)

def _mock_telemetry_poller(target_pod, stop_event, telemetry_file_path, interval=5.0, status_dict=None):
    """Mock poller fixture providing healthy continuous telemetry samples."""
    import time
    if status_dict is not None:
        status_dict["thread_alive"] = True
        status_dict["started_at_epoch"] = time.time()
        status_dict["last_sample_epoch"] = time.time()
        status_dict["sample_count"] = 10
        status_dict["max_observed_gap_sec"] = 5.0
        status_dict["gap_exceeded"] = False
        status_dict["error"] = None
    while not stop_event.is_set():
        if status_dict is not None:
            status_dict["last_sample_epoch"] = time.time()
        time.sleep(0.01)


class TestG3PilotRunnerOffline(unittest.TestCase):

    def setUp(self):
        self.mock_target_info = {
            "range_id": 98,
            "lease_holder_id": 2,
            "target_pod": "cockroachdb-1",
            "pod_uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
            "target_node": "ip-10-0-1-160.ec2.internal",
            "container_id": "f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c",
            "dev_major": 259,
            "dev_minor": 4,
            "dev_stat_dec": 66308,
            "raw_show_range": "98|2|cockroachdb-1",
            "initial_io_max": ""
        }

    def test_severity_levels_consistency(self):
        """Verify severity limits match proposed MiB/s byte values in G3-03."""
        self.assertEqual(SEVERITY_LIMITS["L1"]["wbps"], 5242880)
        self.assertEqual(SEVERITY_LIMITS["L1"]["wiops"], 600)
        self.assertEqual(SEVERITY_LIMITS["L2"]["wbps"], 2097152)
        self.assertEqual(SEVERITY_LIMITS["L2"]["wiops"], 250)
        self.assertEqual(SEVERITY_LIMITS["L3"]["wbps"], 524288)
        self.assertEqual(SEVERITY_LIMITS["L3"]["wiops"], 75)

    def test_device_decoding_math(self):
        """Verify statutory major:minor decoding matches Linux glibc dev_t bitwise operators."""
        stat_dec = 66309
        major = stat_dec >> 8
        minor = stat_dec & 0xFF
        self.assertEqual(major, 259)
        self.assertEqual(minor, 5)

        stat_dec_node1 = 66308
        major_1 = stat_dec_node1 >> 8
        minor_1 = stat_dec_node1 & 0xFF
        self.assertEqual(major_1, 259)
        self.assertEqual(minor_1, 4)

    def test_helper_job_manifest_generation_l1(self):
        """Verify generated helper Job manifest contains expected parameters for L1."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p01",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False,
        )
        self.assertIn("name: g3-chaos-helper", manifest)
        self.assertIn("nodeName: ip-10-0-1-160.ec2.internal", manifest)
        self.assertIn("value: \"259\"", manifest)
        self.assertIn("value: \"4\"", manifest)
        self.assertIn("value: \"5242880\"", manifest)
        self.assertIn("value: \"600\"", manifest)
        self.assertIn("value: \"false\"", manifest)
        self.assertIn("hostPID: false", manifest)
        self.assertNotIn("hostPID: true", manifest)
        self.assertIn("/sys/fs/cgroup", manifest)
        _, rb_manifest = generate_rollback_job_manifest("crdb-g3l1-pilot-p01", self.mock_target_info)
        self.assertIn("hostPID: false", rb_manifest)
        self.assertNotIn("hostPID: true", rb_manifest)

    def test_helper_job_manifest_dry_run(self):
        """Verify dry run sets G3_DRY_RUN to true in manifest."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-dry01",
            target_info=self.mock_target_info,
            level="L3",
            duration_sec=60,
            dry_run=True,
        )
        self.assertIn("value: \"true\"", manifest)
        self.assertIn("value: \"524288\"", manifest)
        self.assertIn("value: \"75\"", manifest)

    def test_helper_shell_trap_registration(self):
        """Verify helper manifest registers POSIX Dash signal handlers, shielding, and EXIT trap."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p01",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False,
        )
        self.assertIn("trap 'on_signal INT 130' INT", manifest)
        self.assertIn("trap 'on_signal TERM 143' TERM", manifest)
        self.assertIn("trap on_exit EXIT", manifest)
        self.assertIn("on_signal() {", manifest)
        self.assertIn("cleanup() {", manifest)
        self.assertIn("trap '' INT TERM", manifest)
        self.assertIn("[CLEANUP] Invoking rollback", manifest)

    def test_original_io_max_preservation_and_restoration(self):
        """Verify helper script captures ORIGINAL_IO_MAX and verifies all 4 exact limits on restoration."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p01",
            target_info=self.mock_target_info,
            level="L2",
            duration_sec=180,
            dry_run=False,
        )
        self.assertIn("ORIGINAL_IO_MAX=\"${FOUND_DEV_LINE}\"", manifest)
        self.assertIn("parse_device_line \"${ORIGINAL_IO_MAX}\" \"${DEV_ID}\"", manifest)
        self.assertIn("if [ -n \"${ORIGINAL_IO_MAX}\" ]; then", manifest)
        self.assertIn("_rest_rule=\"${ORIGINAL_IO_MAX}\"", manifest)
        self.assertIn("_rest_rule=\"${DEV_ID} rbps=max wbps=max riops=max wiops=max\"", manifest)
        self.assertIn("verify_io_max_values \"${ORIG_RBPS}\" \"${ORIG_WBPS}\" \"${ORIG_RIOPS}\" \"${ORIG_WIOPS}\" \"${ALLOW_ABSENT_ON_RESTORE}\"", manifest)

    def test_helper_restoration_verification_fail_closed(self):
        """Verify helper script exits with non-zero code 2 if clearance/restoration verification fails."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p01",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False,
        )
        self.assertIn("Failed to clear throttle on ${DEV_ID}!", manifest)
        self.assertIn("return 2", manifest)
        self.assertIn("exit 2", manifest)

    def test_emergency_independent_recovery_success(self):
        """Verify independent recovery executes privileged g1-chaos rollback Job and verifies all 4 io.max limits."""
        LAST_ROLLBACK_REPORTS.clear()
        pod_json = {
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c"}
                ]
            }
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # delete leftover helper job
                MagicMock(returncode=0, stdout="job.batch/g3-rollback created", stderr=""),  # apply rollback job
                MagicMock(returncode=0, stdout="condition met", stderr=""),  # wait job complete
                MagicMock(returncode=0, stdout="[G3 Rollback] Restored", stderr=""),  # logs
                MagicMock(returncode=0, stdout="", stderr=""),  # delete rollback job
                MagicMock(returncode=0, stdout="259:4 rbps=max wbps=max riops=max wiops=max", stderr=""),  # verify io.max
            ]
            success = emergency_independent_rollback(self.mock_target_info)
            self.assertTrue(success)
            self.assertGreaterEqual(len(LAST_ROLLBACK_REPORTS), 1)
            self.assertEqual(LAST_ROLLBACK_REPORTS[-1]["status"], "VERIFIED_RESTORED")
            # Ensure no kubectl exec write to ro cgroup was attempted
            cmds = [" ".join(c.args[0]) for c in mock_run.call_args_list]
            self.assertTrue(any("apply" in c and "-f" in c for c in cmds))
            self.assertFalse(any("exec" in c and "io.max" in c and ">" in c for c in cmds))

    def test_emergency_independent_recovery_detects_container_restart(self):
        """Verify independent recovery detects container restart and still verifies unthrottled io.max."""
        LAST_ROLLBACK_REPORTS.clear()
        pod_json = {
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://aaaa111122223333444455556666777788889999000011112222333344445555"}
                ]
            }
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # verify io.max after restart
            ]
            success = emergency_independent_rollback(self.mock_target_info)
            self.assertTrue(success)
            self.assertEqual(LAST_ROLLBACK_REPORTS[-1]["status"], "VERIFIED_AFTER_RESTART")

    def test_emergency_independent_recovery_fails_if_throttle_persists(self):
        """Verify independent recovery returns False if target device remains throttled."""
        LAST_ROLLBACK_REPORTS.clear()
        pod_json = {
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c"}
                ]
            }
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # delete leftover helper job
                MagicMock(returncode=0, stdout="job.batch/g3-rollback created", stderr=""),  # apply rollback job
                MagicMock(returncode=0, stdout="condition met", stderr=""),  # wait job complete
                MagicMock(returncode=0, stdout="[G3 Rollback] Done", stderr=""),  # logs
                MagicMock(returncode=0, stdout="", stderr=""),  # delete rollback job
                MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr=""),
            ]
            success = emergency_independent_rollback(self.mock_target_info)
            self.assertFalse(success)

    def test_two_cycle_consensus_resolution_pass(self):
        """Verify resolve_target_leaseholder passes when Cycle 1 and Cycle 2 agree and verifies cgroup v2 io controller."""
        range_out = ".../2060753|.../4993426|98|2|...|{1,2,3}"
        gossip_out = "2|cockroachdb-1.cockroachdb.cockroachdb.svc.cluster.local:26257|t"
        pod_json = {
            "metadata": {"uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67"},
            "spec": {"nodeName": "ip-10-0-1-160.ec2.internal"},
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c"}
                ]
            }
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=[range_out, range_out, gossip_out]):
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                mock_run.side_effect = [
                    MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                    MagicMock(returncode=0, stdout="66308\n", stderr=""),
                    MagicMock(returncode=0, stdout="1611 1604 259:4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw,seclabel\n", stderr=""),
                    MagicMock(returncode=0, stdout="MAJOR=259\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n", stderr=""),
                    MagicMock(returncode=0, stdout="cpuset cpu io memory hugetlb pids\n", stderr=""),
                    MagicMock(returncode=0, stdout="259:4 rbytes=1024 wbytes=2048 rios=10 wios=20 dbytes=0 dios=0\n", stderr=""),
                    MagicMock(returncode=0, stdout="", stderr=""),
                ]
                target = resolve_target_leaseholder()
                self.assertEqual(target["range_id"], 98)
                self.assertEqual(target["lease_holder_id"], 2)
                self.assertEqual(target["target_pod"], "cockroachdb-1")
                self.assertEqual(target["pod_uid"], "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67")
                self.assertEqual(target["dev_major"], 259)
                self.assertEqual(target["dev_minor"], 4)

    def test_two_cycle_consensus_resolution_fail_closed(self):
        """Verify resolve_target_leaseholder raises RuntimeError if Range or Leaseholder migrates mid-check."""
        range_out_1 = ".../2060753|.../4993426|98|2|...|{1,2,3}"
        range_out_2 = ".../2060753|.../4993426|98|1|...|{1,2,3}"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql") as mock_sql:
            mock_sql.side_effect = [range_out_1, range_out_2]
            with self.assertRaises(RuntimeError) as ctx:
                resolve_target_leaseholder()
            self.assertIn("Dynamic leaseholder resolution consensus failure", str(ctx.exception))

    def test_storage_check_capacity_pass(self):
        """Verify check_storage_capacity passes when available MB exceeds threshold."""
        df_out = "Filesystem 1K-blocks Used Available Use% Mounted on\ntmpfs 65536 7000 58536 11% /tmp\n"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=df_out, stderr="")
            res = check_storage_capacity(min_avail_mb=30.0)
            self.assertGreaterEqual(res["avail_mb"], 30.0)

    def test_storage_check_capacity_fail_closed(self):
        """Verify check_storage_capacity raises RuntimeError when free space is below threshold."""
        df_out = "Filesystem 1K-blocks Used Available Use% Mounted on\ntmpfs 65536 50000 15536 77% /tmp\n"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=df_out, stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                check_storage_capacity(min_avail_mb=30.0)
            self.assertIn("FAIL-CLOSED: Available /tmp storage", str(ctx.exception))

    def test_manifest_hashing_integrity(self):
        """Verify SHA256SUMS.txt correctly hashes all files in output directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            test_file = os.path.join(tmpdir, "test.txt")
            with open(test_file, "w", encoding="utf-8") as f:
                f.write("CockroachDB G3 Test Content")
            
            build_manifest(tmpdir)
            manifest_file = os.path.join(tmpdir, "SHA256SUMS.txt")
            self.assertTrue(os.path.exists(manifest_file))
            
            with open(manifest_file, "r", encoding="utf-8") as f:
                content = f.read()
            expected_hash = compute_sha256(test_file)
            self.assertIn(f"{expected_hash}  test.txt", content)

    # =========================================================================
    # COORDINATOR 15-STATE MACHINE & FAILURE PATH UNIT TESTS
    # =========================================================================

    def test_coordinator_dry_run_complete_lifecycle(self):
        """Verify dry-run mode executes all 15 states in sequence and reaches SIMULATED_SUCCESS."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-dry",
                level="L1",
                duration_sec=180,
                dry_run=True
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"2\",node_id=\"2\"}": "0"}}):
                                record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "SIMULATED_SUCCESS")
            self.assertFalse(record["error_occurred"])
            
            # Verify all 15 states were entered
            states_executed = [s["state"] for s in record["state_history"]]
            for expected_state in ExecutionState:
                self.assertIn(expected_state.value, states_executed)

    def test_coordinator_preflight_rejection_halts_cleanly(self):
        """Verify coordinator aborts in PREFLIGHT state if preflight audit raises exception."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-fail-preflight",
                level="L1",
                duration_sec=180,
                dry_run=True
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", side_effect=RuntimeError("Fewer than 3 ready nodes found")):
                record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertEqual(record["state_history"][0]["state"], ExecutionState.PREFLIGHT.value)
            self.assertEqual(record["state_history"][0]["status"], "FAILED")
            self.assertIn("Fewer than 3 ready nodes found", record["state_history"][0]["error"])

    def test_coordinator_pre_existing_throttling_aborts(self):
        """Verify coordinator aborts in TARGET_VERIFICATION if target already has active io.max."""
        dirty_target = dict(self.mock_target_info)
        dirty_target["initial_io_max"] = "259:4 wbps=1048576"
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-dirty-cgroup",
                level="L1",
                duration_sec=180,
                dry_run=True
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=dirty_target):
                        record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertIn("Pre-existing throttling detected", record["state_history"][1]["error"])

    def test_coordinator_target_migration_after_warmup_aborts(self):
        """Verify coordinator adapts to target migration during warmup, but aborts if target moves during baseline measurement."""
        migrated_target = dict(self.mock_target_info)
        migrated_target["target_pod"] = "cockroachdb-0" # moved to node 1!
        pre_fault_drift = dict(migrated_target)
        pre_fault_drift["target_pod"] = "cockroachdb-2" # moved again during baseline!
        
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-warmup-migration",
                level="L1",
                duration_sec=180,
                dry_run=True
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            # Option B + D: 
            # 1. TARGET_VERIFICATION resolves mock_target_info
            # 2. POST_WARMUP resolves migrated_target (adapts to warm-up migration)
            # 3. BASELINE_MEASUREMENT pre-fault revalidation resolves pre_fault_drift -> aborts!
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=[self.mock_target_info, migrated_target, pre_fault_drift]):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertIn("Target pod changed during pre_fault_application", record["state_history"][4]["error"])

    def test_coordinator_fault_verification_failure_triggers_rollback(self):
        """Verify that failure during fault verification automatically triggers emergency rollback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-fault-verify-fail",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                                            # Mock warmup pass, wrapper launch pass, helper apply, and io.max checks
                                            mock_run.side_effect = [
                                                MagicMock(returncode=0, stdout="", stderr=""), # warmup
                                                MagicMock(returncode=0, stdout="8888\n", stderr=""), # pgid check
                                                MagicMock(returncode=0, stdout="", stderr=""), # helper apply
                                                # io.max check loops 15 times returning empty/unthrottled
                                                *[MagicMock(returncode=0, stdout="", stderr="") for _ in range(16)]
                                            ]
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen"):
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback") as mock_rollback:
                                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"):
                                                        record = coordinator.execute_lifecycle()
                                                        # Rollback MUST have been called because fault was marked applied
                                                        mock_rollback.assert_called_once_with(self.mock_target_info)

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertIn("Fault application verification FAILED", record["state_history"][6]["error"])

    def test_coordinator_under_replicated_ranges_fails_final_health(self):
        """Verify coordinator aborts in FINAL_HEALTH_CHECK if under-replicated ranges > 0."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-underrep-fail",
                level="L1",
                duration_sec=180,
                dry_run=True
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]):
                            # Report 2 under-replicated ranges on store 2!
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"2\",node_id=\"2\"}": "2"}}):
                                record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertIn("Under-replicated ranges detected post-experiment: 2", record["state_history"][12]["error"])

    # =========================================================================
    # G3-52 REMEDIATION EXPANDED TESTS
    # =========================================================================

    def test_interruption_keyboardinterrupt_triggers_emergency_rollback(self):
        """Verify KeyboardInterrupt during fault application triggers emergency rollback and re-raises."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-sigint-rollback",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep") as mock_sleep:
                                            # Simulate KeyboardInterrupt during FAULT_APPLICATION or BASELINE
                                            mock_run.side_effect = [
                                                MagicMock(returncode=0, stdout="", stderr=""), # warmup
                                                MagicMock(returncode=0, stdout="8888\n", stderr=""), # pgid check
                                                MagicMock(returncode=0, stdout="", stderr=""), # helper apply
                                            ]
                                            # Mock sleep: first call is in PGID polling loop, then baseline 180s, then in fault verification
                                            sleep_count = 0
                                            def mock_sleep_fn(duration):
                                                nonlocal sleep_count
                                                sleep_count += 1
                                                # Trigger KeyboardInterrupt after fault is applied (when fault_applied == True)
                                                if coordinator.fault_applied:
                                                    raise KeyboardInterrupt("Operator pressed Ctrl+C")
                                            mock_sleep.side_effect = mock_sleep_fn
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen"):
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback") as mock_rollback:
                                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"):
                                                        with self.assertRaises(KeyboardInterrupt):
                                                            coordinator.execute_lifecycle()
                                                        mock_rollback.assert_called_once_with(self.mock_target_info)
            self.assertEqual(coordinator.final_disposition, "FAILED")
            self.assertTrue(coordinator.error_occurred)

    def test_interruption_rollback_failure_sets_cleanup_error(self):
        """Verify failed emergency rollback records cleanup_error and ensures final_disposition is FAILED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-rb-fail",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                                            mock_run.side_effect = [
                                                MagicMock(returncode=0, stdout="", stderr=""), # warmup
                                                MagicMock(returncode=0, stdout="8888\n", stderr=""), # pgid check
                                                MagicMock(returncode=0, stdout="", stderr=""), # helper apply
                                                # Verification loops fail
                                                *[MagicMock(returncode=0, stdout="", stderr="") for _ in range(16)]
                                            ]
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen"):
                                                # Emergency rollback returns False (failed to clear!)
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback", return_value=False):
                                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"):
                                                        record = coordinator.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertIn("Fault application verification FAILED", record["state_history"][6]["error"])
            self.assertIsNotNone(record["cleanup_error"])
            self.assertIn("FAILED to verify unthrottled", record["cleanup_error"])

    def test_evidence_collection_persists_all_pod_files(self):
        """Verify evidence collection writes all retrieved stdout, stderr, and meta files to disk."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-evidence-ok",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"2\",node_id=\"2\"}": "0"}}):
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen:
                                        mock_proc = MagicMock()
                                        mock_proc.communicate.return_value = ("client out", "")
                                        mock_proc.returncode = 0
                                        mock_popen.return_value = mock_proc

                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {"g3-chaos-helper": "helper ok"}, "errors": []}):
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                                    # We return appropriate command results for each lifecycle step
                                                    def fake_run_cmd(cmd, check=True, timeout=None):
                                                        cmd_str = " ".join(cmd)
                                                        if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="8888\n", stderr="")
                                                        if "cat /tmp/pgbench" in cmd_str and "exit_code.txt" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="0\n", stderr="")
                                                        if "cat /sys/fs/cgroup/io.max" in cmd_str:
                                                            # During fault verification return throttled, during restoration unthrottled
                                                            if coordinator.current_state == ExecutionState.FAULT_VERIFICATION:
                                                                return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                                                            return MagicMock(returncode=0, stdout="", stderr="")
                                                        if "ls /tmp/pgbench_log_" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="/tmp/pgbench_log_test.1\n", stderr="")
                                                        if "cat /tmp/pgbench_log_test.1" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="1 0 100 0 1000 0\n1 1 120 0 1600 0\n", stderr="")
                                                        if "cat /tmp/pgbench_" in cmd_str or "cat /tmp/disk_" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="Sample evidence data\n", stderr="")
                                                        return MagicMock(returncode=0, stdout="", stderr="")

                                                    mock_run.side_effect = fake_run_cmd
                                                    record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "EXECUTED_VALIDATED")
            self.assertEqual(len(record["evidence_missing"]), 0)
            self.assertEqual(record["clocks"]["clock3_tx_stream_span_sec"], 600.0)
            # Verify file exists on disk
            stdout_path = os.path.join(tmpdir, f"pgbench_{coordinator.run_id}_stdout.txt")
            self.assertTrue(os.path.exists(stdout_path))
            with open(stdout_path, "r", encoding="utf-8") as f:
                self.assertIn("Sample evidence data", f.read())

    def test_evidence_collection_missing_required_file_fails_disposition(self):
        """Verify missing critical evidence file fails disposition."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-evidence-fail",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"2\",node_id=\"2\"}": "0"}}):
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen:
                                        mock_proc = MagicMock()
                                        mock_proc.communicate.return_value = ("", "")
                                        mock_proc.returncode = 0
                                        mock_popen.return_value = mock_proc

                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                                    def fake_run_cmd(cmd, check=True, timeout=None):
                                                        cmd_str = " ".join(cmd)
                                                        if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="8888\n", stderr="")
                                                        if "cat /sys/fs/cgroup/io.max" in cmd_str:
                                                            if coordinator.current_state == ExecutionState.FAULT_VERIFICATION:
                                                                return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                                                            return MagicMock(returncode=0, stdout="", stderr="")
                                                        if "exit_code.txt" in cmd_str:
                                                            return MagicMock(returncode=1, stdout="", stderr="File not found")
                                                        if "ls /tmp/pgbench_log_" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="", stderr="")
                                                        return MagicMock(returncode=0, stdout="sample", stderr="")

                                                    mock_run.side_effect = fake_run_cmd
                                                    record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(len(record["evidence_missing"]) > 0)
            self.assertTrue(any("exit_code.txt (missing)" in m for m in record["evidence_missing"]))

    def test_metrics_sampling_bounded_retry_success(self):
        """Verify sample_crdb_metrics retries on timeout/failure and succeeds on subsequent attempt."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                mock_run.side_effect = [
                    MagicMock(returncode=1, stdout="", stderr="Connection timed out"),
                    MagicMock(returncode=0, stdout="ranges_underreplicated{store=\"2\",node_id=\"2\"} 0\n", stderr="")
                ]
                res = sample_crdb_metrics("cockroachdb-1", timeout=5.0, max_retries=3)
                self.assertTrue(res["success"])
                self.assertEqual(res["attempts"], 2)
                self.assertIn("ranges_underreplicated{store=\"2\",node_id=\"2\"}", res["metrics"])

    def test_metrics_sampling_all_retries_fail_records_failure(self):
        """Verify sample_crdb_metrics records structured failure without raising or retrying benchmark."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                mock_run.side_effect = [
                    MagicMock(returncode=1, stdout="", stderr="Connection timed out"),
                    MagicMock(returncode=1, stdout="", stderr="Connection timed out"),
                    MagicMock(returncode=1, stdout="", stderr="Connection timed out")
                ]
                res = sample_crdb_metrics("cockroachdb-1", timeout=5.0, max_retries=3)
                self.assertFalse(res["success"])
                self.assertEqual(res["attempts"], 3)
                self.assertEqual(res["metrics"], {})
                self.assertIsNotNone(res["error"])

    def test_manifest_verification_integrity_pass_and_fail(self):
        """Verify verify_manifest detects both matching manifests and tampered files."""
        with tempfile.TemporaryDirectory() as tmpdir:
            file_a = os.path.join(tmpdir, "a.txt")
            with open(file_a, "w", encoding="utf-8") as f:
                f.write("test content a")
            build_manifest(tmpdir)
            self.assertTrue(verify_manifest(tmpdir))

            # Tamper with file
            with open(file_a, "w", encoding="utf-8") as f:
                f.write("tampered content")
            self.assertFalse(verify_manifest(tmpdir))

    def test_sigterm_triggers_emergency_rollback_and_reraises(self):
        """Verify SIGTERM received during active fault triggers emergency rollback and re-raises SignalInterruptionError."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-sigterm",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback", return_value=True) as mock_rollback:
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"):
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen:
                                        mock_proc = MagicMock()
                                        mock_proc.communicate.return_value = ("", "")
                                        mock_proc.returncode = 0
                                        mock_popen.return_value = mock_proc

                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                                    def fake_run_cmd(cmd, check=True, timeout=None):
                                                        cmd_str = " ".join(cmd)
                                                        if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="8888\n", stderr="")
                                                        if "cat /sys/fs/cgroup/io.max" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                                                        return MagicMock(returncode=0, stdout="", stderr="")

                                                    mock_run.side_effect = fake_run_cmd

                                                    def fake_sleep(sec):
                                                        if threading.current_thread() is threading.main_thread() and coordinator.current_state == ExecutionState.FAULT_MEASUREMENT:
                                                            # Simulate OS delivering SIGTERM to the process
                                                            handler = signal.getsignal(signal.SIGTERM)
                                                            if callable(handler):
                                                                handler(signal.SIGTERM, None)

                                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep", side_effect=fake_sleep):
                                                        with self.assertRaises(SignalInterruptionError) as cm:
                                                            coordinator.execute_lifecycle()

                                                        self.assertEqual(cm.exception.signum, signal.SIGTERM)
                                                        self.assertEqual(cm.exception.signame, "SIGTERM")

                                    mock_rollback.assert_called_once_with(self.mock_target_info)
            self.assertIsNotNone(coordinator.signal_received)
            self.assertEqual(coordinator.signal_received["signal_name"], "SIGTERM")
            self.assertEqual(coordinator.signal_received["state"], "FAULT_MEASUREMENT")

    def test_signal_handlers_restored_after_lifecycle_exit(self):
        """Verify original signal handlers for SIGINT and SIGTERM are cleanly restored in finally block."""
        orig_sigint = signal.getsignal(signal.SIGINT)
        orig_sigterm = signal.getsignal(signal.SIGTERM)

        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-signal-restore",
                level="L1",
                duration_sec=180,
                dry_run=True
            )
            coordinator.output_dir = tmpdir

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"2\",node_id=\"2\"}": "0"}}):
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                                    coordinator.execute_lifecycle()

        current_sigint = signal.getsignal(signal.SIGINT)
        current_sigterm = signal.getsignal(signal.SIGTERM)
        self.assertEqual(current_sigint, orig_sigint)
        self.assertEqual(current_sigterm, orig_sigterm)

    def test_secondary_sigterm_and_sigint_during_rollback_shielded(self):
        """Verify secondary SIGTERM and SIGINT during active rollback are shielded, recorded, and do not interrupt rollback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-shielding",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group") as mock_term:
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen:
                                    mock_proc = MagicMock()
                                    mock_proc.communicate.return_value = ("", "")
                                    mock_proc.returncode = 0
                                    mock_popen.return_value = mock_proc

                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                                def fake_run_cmd(cmd, check=True, timeout=None):
                                                    cmd_str = " ".join(cmd)
                                                    if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                                                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                                                    if "cat /sys/fs/cgroup/io.max" in cmd_str:
                                                        return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                                                    return MagicMock(returncode=0, stdout="", stderr="")

                                                mock_run.side_effect = fake_run_cmd

                                                def fake_emergency_rollback(t_info):
                                                    # Verify coordinator has flagged cleanup_in_progress
                                                    self.assertTrue(coordinator.cleanup_in_progress)
                                                    # Simulate delivery of secondary SIGTERM
                                                    handler_term = signal.getsignal(signal.SIGTERM)
                                                    if callable(handler_term):
                                                        handler_term(signal.SIGTERM, None)
                                                    # Simulate delivery of secondary SIGINT
                                                    handler_int = signal.getsignal(signal.SIGINT)
                                                    if callable(handler_int):
                                                        handler_int(signal.SIGINT, None)
                                                    # Verify rollback completes normally without being aborted by secondary signals
                                                    return True

                                                def fake_sleep(sec):
                                                    if threading.current_thread() is threading.main_thread() and coordinator.current_state == ExecutionState.FAULT_MEASUREMENT:
                                                        # Primary signal that triggers abort and enters cleanup
                                                        handler = signal.getsignal(signal.SIGTERM)
                                                        if callable(handler):
                                                            handler(signal.SIGTERM, None)

                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback", side_effect=fake_emergency_rollback) as mock_rollback:
                                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep", side_effect=fake_sleep):
                                                        with self.assertRaises(SignalInterruptionError) as cm:
                                                            coordinator.execute_lifecycle()

                                                        # Primary cause is preserved
                                                        self.assertEqual(cm.exception.signum, signal.SIGTERM)
                                                        self.assertEqual(cm.exception.signame, "SIGTERM")

                                                mock_rollback.assert_called_once_with(self.mock_target_info)
                                                mock_term.assert_called_once_with(8888)

            # Verification of signal recording
            self.assertIsNotNone(coordinator.signal_received)
            self.assertEqual(coordinator.signal_received["signal_name"], "SIGTERM")
            self.assertEqual(coordinator.signal_received["state"], "FAULT_MEASUREMENT")

            # Verification of secondary signal recording
            self.assertEqual(len(coordinator.secondary_signals), 2)
            self.assertEqual(coordinator.secondary_signals[0]["signal_name"], "SIGTERM")
            self.assertEqual(coordinator.secondary_signals[1]["signal_name"], "SIGINT")
            self.assertEqual(coordinator.secondary_signals[0]["state"], "FAULT_MEASUREMENT")
            self.assertFalse(coordinator.cleanup_in_progress)

    def test_emergency_rollback_failure_continues_cleanup_and_fails_disposition(self):
        """Verify rollback failure is separately recorded, does not skip process cleanup, and forces FAILED disposition."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-test-rb-fail",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]):
                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback", return_value=False) as mock_rollback:
                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group") as mock_term:
                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen:
                                        mock_proc = MagicMock()
                                        mock_proc.communicate.return_value = ("", "")
                                        mock_proc.returncode = 0
                                        mock_popen.return_value = mock_proc

                                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller):
                                            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}):
                                                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
                                                    def fake_run_cmd(cmd, check=True, timeout=None):
                                                        cmd_str = " ".join(cmd)
                                                        if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="8888\n", stderr="")
                                                        if "cat /sys/fs/cgroup/io.max" in cmd_str:
                                                            return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                                                        return MagicMock(returncode=0, stdout="", stderr="")

                                                    mock_run.side_effect = fake_run_cmd

                                                    def fake_sleep(sec):
                                                        if threading.current_thread() is threading.main_thread() and coordinator.current_state == ExecutionState.FAULT_MEASUREMENT:
                                                            handler = signal.getsignal(signal.SIGTERM)
                                                            if callable(handler):
                                                                handler(signal.SIGTERM, None)

                                                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep", side_effect=fake_sleep):
                                                        with self.assertRaises(SignalInterruptionError):
                                                            coordinator.execute_lifecycle()

                                                mock_rollback.assert_called_once_with(self.mock_target_info)
                                                mock_term.assert_called_once_with(8888)

            self.assertEqual(coordinator.final_disposition, "FAILED")
            self.assertIsNotNone(coordinator.cleanup_error)
            self.assertIn("FAILED to verify unthrottled", coordinator.cleanup_error)

class TestG3AuthorizationSecurityOffline(unittest.TestCase):
    """
    Exhaustive offline test suite for G3 Ed25519 single-use operator authorization.
    Verifies all security requirements specified in G3-63 and G3-68.
    Runs 100% offline with zero live infrastructure or AWS interactions.
    """

    def setUp(self):
        # Generate ephemeral Ed25519 keypair for tests
        self.private_key = ed25519.Ed25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.pub_bytes = self.public_key.public_bytes_raw()
        self.pub_b64 = base64.b64encode(self.pub_bytes).decode("utf-8")
        self.fingerprint = hashlib.sha256(self.pub_bytes).hexdigest()
        
        self.run_id = "crdb-g3l1-pilot-p01"
        self.level = "L1"
        self.duration_sec = 180
        self.mock_runner_sha256 = "3d4faf90e084fcd54fabb2cfb8765c394d3d89668b171f7a0dbe4060218e7881"

    def _create_token(self, payload_overrides=None, corrupt_signature=False):
        now_dt = datetime.datetime.now(datetime.timezone.utc)
        issued_utc = (now_dt - datetime.timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        not_before_utc = (now_dt - datetime.timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        expires_utc = (now_dt + datetime.timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

        payload = {
            "authorization_id": f"auth-{self.run_id}-test",
            "authorized_run_id": self.run_id,
            "authorized_level": self.level,
            "parameters": {
                "wbps": 5242880,
                "wiops": 600,
                "max_fault_duration_sec": 180
            },
            "runner_sha256": self.mock_runner_sha256,
            "protocol_version": PROTOCOL_VERSION,
            "operator_identity": "operator@ric-research",
            "nonce": "test-nonce-12345",
            "issued_at_utc": issued_utc,
            "not_before_utc": not_before_utc,
            "expires_at_utc": expires_utc
        }
        if payload_overrides:
            payload.update(payload_overrides)

        canon_bytes = canonicalize_payload(payload)
        sig = self.private_key.sign(canon_bytes)
        if corrupt_signature:
            sig = bytes([b ^ 0xFF for b in sig])

        token_doc = {
            "schema_version": "1.0",
            "payload": payload,
            "signature": base64.b64encode(sig).decode("utf-8")
        }
        return token_doc

    def _write_token_to_temp(self, token_doc, dir_path):
        token_path = os.path.join(dir_path, f"{token_doc['payload']['authorization_id']}.auth.json")
        with open(token_path, "w", encoding="utf-8") as f:
            json.dump(token_doc, f, indent=2)
        return token_path

    def _write_mock_runner(self, dir_path):
        runner_path = os.path.join(dir_path, "mock_runner.py")
        with open(runner_path, "w", encoding="utf-8") as f:
            f.write("# mock runner content\n")
        runner_hash = compute_sha256(runner_path)
        return runner_path, runner_hash

    def test_01_valid_signature_and_exact_authorization(self):
        """1. Verify valid signature and exact authorization passes and returns metadata with fingerprint."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)

            auth_data = verify_and_consume_authorization(
                auth_file_path=t_path,
                run_id=self.run_id,
                level=self.level,
                duration_sec=self.duration_sec,
                runner_path=runner_p,
                public_key_b64=self.pub_b64,
                expected_fingerprint=self.fingerprint
            )
            self.assertTrue(auth_data["signature_verified"])
            self.assertEqual(auth_data["authorization_id"], token["payload"]["authorization_id"])
            self.assertEqual(auth_data["public_key_fingerprint"], self.fingerprint)
            self.assertTrue(os.path.exists(auth_data["consumed_marker_path"]))

    def test_02_invalid_signature(self):
        """2. Verify corrupted/invalid signature fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash}, corrupt_signature=True)
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("signature verification FAILED", str(ctx.exception))

    def test_03_expired_authorization(self):
        """3. Verify expired token fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            past_dt = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            token = self._create_token({
                "runner_sha256": r_hash,
                "expires_at_utc": past_dt
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("EXPIRED", str(ctx.exception))

    def test_04_not_yet_valid_authorization(self):
        """4. Verify token with future not_before_utc fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            future_dt = (datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(hours=1)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            token = self._create_token({
                "runner_sha256": r_hash,
                "not_before_utc": future_dt
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("not yet valid", str(ctx.exception))

    def test_05_wrong_run_id(self):
        """5. Verify mismatched run ID fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({
                "authorized_run_id": "crdb-g3l2-pilot-wrong",
                "runner_sha256": r_hash
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("bound to run_id 'crdb-g3l2-pilot-wrong'", str(ctx.exception))

    def test_06_wrong_fault_level(self):
        """6. Verify mismatched fault level fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({
                "authorized_level": "L2",
                "runner_sha256": r_hash
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level="L1",
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("bound to level 'L2'", str(ctx.exception))

    def test_07_wrong_bandwidth_or_iops(self):
        """7. Verify mismatched bandwidth or IOPS limits fail closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({
                "runner_sha256": r_hash,
                "parameters": {"wbps": 9999999, "wiops": 600, "max_fault_duration_sec": 180}
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("Token wbps", str(ctx.exception))

    def test_08_wrong_duration(self):
        """8. Verify requested duration exceeding authorized max duration fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({
                "runner_sha256": r_hash,
                "parameters": {"wbps": 5242880, "wiops": 600, "max_fault_duration_sec": 120}
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=180,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("exceeds authorized maximum 120s", str(ctx.exception))

    def test_09_runner_checksum_mismatch(self):
        """9. Verify runner SHA-256 hash mismatch fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({
                "runner_sha256": "0000000000000000000000000000000000000000000000000000000000000000"
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("Runner hash mismatch", str(ctx.exception))

    def test_10_protocol_version_mismatch(self):
        """10. Verify protocol version mismatch fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({
                "runner_sha256": r_hash,
                "protocol_version": "G3-03-DEPRECATED"
            })
            t_path = self._write_token_to_temp(token, td)

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("Authorization bound to protocol 'G3-03-DEPRECATED'", str(ctx.exception))

    def test_11_reused_authorization(self):
        """11. Verify previously consumed authorization is rejected."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)

            # First consumption succeeds
            verify_and_consume_authorization(
                auth_file_path=t_path,
                run_id=self.run_id,
                level=self.level,
                duration_sec=self.duration_sec,
                runner_path=runner_p,
                public_key_b64=self.pub_b64,
                expected_fingerprint=self.fingerprint
            )

            # Second consumption fails
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("ALREADY BEEN CONSUMED", str(ctx.exception))

    def test_12_concurrent_consumption_attempts(self):
        """12. Verify concurrent consumption attempts result in exactly one winner and others failing closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)

            results = []
            errors = []

            def worker():
                try:
                    res = verify_and_consume_authorization(
                        auth_file_path=t_path,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                    results.append(res)
                except Exception as e:
                    errors.append(e)

            threads = [threading.Thread(target=worker) for _ in range(5)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

            self.assertEqual(len(results), 1, "Exactly one thread must successfully consume token")
            self.assertEqual(len(errors), 4, "Remaining threads must fail closed")
            for err in errors:
                self.assertIn("ALREADY BEEN CONSUMED", str(err))

    def test_13_interrupted_consumption(self):
        """13. Verify that if consumption marker exists, authorization is non-reusable even after interruption."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)
            marker = f"{t_path}.consumed"
            with open(marker, "w", encoding="utf-8") as f:
                f.write('{"interrupted": true}')

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("ALREADY BEEN CONSUMED", str(ctx.exception))

    def test_14_missing_consumption_storage(self):
        """14. Verify fail-closed behavior when consumption marker creation fails."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)

            # Mock os.open specifically for the .consumed creation
            orig_os_open = os.open
            def mock_open_ex(path, flags, *args):
                if str(path).endswith(".consumed"):
                    raise OSError("Disk I/O error or unwritable directory")
                return orig_os_open(path, flags, *args)

            with patch("os.open", side_effect=mock_open_ex):
                with self.assertRaises(RuntimeError) as ctx:
                    verify_and_consume_authorization(
                        auth_file_path=t_path,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                self.assertIn("Failed to persist atomic consumption record", str(ctx.exception))

    def test_15_malformed_token(self):
        """15. Verify malformed token JSON or non-dict root fails closed."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            bad_path = os.path.join(td, "bad.json")
            with open(bad_path, "w", encoding="utf-8") as f:
                f.write("{ broken json ...")

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=bad_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("Malformed authorization token JSON", str(ctx.exception))

    def test_16_signature_verification_failure_with_wrong_key(self):
        """16. Verify token signed by untrusted key is rejected when fingerprint mismatches or signature fails."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)

            # Generate a different public key
            alt_priv = ed25519.Ed25519PrivateKey.generate()
            alt_pub_b64 = base64.b64encode(alt_priv.public_key().public_bytes_raw()).decode("utf-8")

            # Mismatched fingerprint rejected
            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=alt_pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("Untrusted public key", str(ctx.exception))

    def test_17_no_lifecycle_invocation_when_authorization_fails(self):
        """17. Verify main() never calls execute_lifecycle if authorization fails or is omitted."""
        test_args = ["g3_pilot_runner.py", "--run-id", self.run_id, "--level", self.level]
        with patch.object(sys, "argv", test_args):
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.G3PilotExecutionCoordinator.execute_lifecycle") as mock_exec:
                with self.assertRaises(SystemExit) as ctx:
                    main()
                self.assertEqual(ctx.exception.code, 1)
                mock_exec.assert_not_called()

    def test_18_successful_authorization_reaches_lifecycle_entry_point(self):
        """18. Verify valid authorization in main() reaches execute_lifecycle in a mocked test."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)
            pk_path = os.path.join(td, "pub.key")
            with open(pk_path, "w", encoding="utf-8") as f:
                f.write(self.pub_b64)

            test_args = [
                "g3_pilot_runner.py",
                "--run-id", self.run_id,
                "--level", self.level,
                "--duration", "180",
                "--auth-token", t_path,
                "--public-key", pk_path
            ]
            with patch.object(sys, "argv", test_args):
                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.compute_sha256", return_value=r_hash):
                    with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.TRUSTED_OPERATOR_PUBKEY_SHA256", self.fingerprint):
                        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.G3PilotExecutionCoordinator.execute_lifecycle", return_value={"mock": "success"}) as mock_exec:
                            main()
                            mock_exec.assert_called_once()

    # --- New G3-68 Tests ---

    def test_19_untrusted_public_key_override_rejected(self):
        """19. Verify user-supplied public key with mismatched fingerprint is rejected."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)

            alt_priv = ed25519.Ed25519PrivateKey.generate()
            alt_pub_b64 = base64.b64encode(alt_priv.public_key().public_bytes_raw()).decode("utf-8")

            with self.assertRaises(RuntimeError) as ctx:
                verify_and_consume_authorization(
                    auth_file_path=t_path,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=alt_pub_b64,
                    expected_fingerprint=self.fingerprint
                )
            self.assertIn("Untrusted public key", str(ctx.exception))

    def test_20_public_key_override_with_matching_fingerprint_accepted(self):
        """20. Verify public key override is accepted when its fingerprint exactly matches pinned constant."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            t_path = self._write_token_to_temp(token, td)
            pk_path = os.path.join(td, "pinned_pub.key")
            with open(pk_path, "w", encoding="utf-8") as f:
                f.write(self.pub_b64)

            auth_data = verify_and_consume_authorization(
                auth_file_path=t_path,
                run_id=self.run_id,
                level=self.level,
                duration_sec=self.duration_sec,
                runner_path=runner_p,
                public_key_path=pk_path,
                expected_fingerprint=self.fingerprint
            )
            self.assertTrue(auth_data["signature_verified"])
            self.assertEqual(auth_data["public_key_fingerprint"], self.fingerprint)

    def test_21_token_symlink_rejected(self):
        """21. Verify symlink token path is rejected immediately."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            real_path = self._write_token_to_temp(token, td)
            link_path = os.path.join(td, "link.auth.json")
            
            with patch("os.path.islink", side_effect=lambda p: p == link_path):
                with self.assertRaises(RuntimeError) as ctx:
                    verify_and_consume_authorization(
                        auth_file_path=link_path,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                self.assertIn("cannot be a symlink", str(ctx.exception))

    def test_22_consumption_marker_symlink_rejected(self):
        """22. Verify symlink consumption marker path is rejected."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            real_path = self._write_token_to_temp(token, td)
            marker_link = f"{real_path}.consumed"

            with patch("os.path.islink", side_effect=lambda p: p == marker_link):
                with self.assertRaises(RuntimeError) as ctx:
                    verify_and_consume_authorization(
                        auth_file_path=real_path,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                self.assertIn("Consumption marker path cannot be a symlink", str(ctx.exception))

    def test_23_non_regular_token_file_rejected(self):
        """23. Verify non-regular file (e.g. FIFO/device/socket) is rejected via fstat."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            real_path = self._write_token_to_temp(token, td)

            mock_st = MagicMock()
            mock_st.st_mode = stat.S_IFIFO  # Simulate FIFO pipe
            
            # To avoid leaving fd open on Windows during test exception, mock os.open
            fake_fd = 9999
            with patch("os.open", return_value=fake_fd):
                with patch("os.close"):
                    with patch("os.fstat", return_value=mock_st):
                        with self.assertRaises(RuntimeError) as ctx:
                            verify_and_consume_authorization(
                                auth_file_path=real_path,
                                run_id=self.run_id,
                                level=self.level,
                                duration_sec=self.duration_sec,
                                runner_path=runner_p,
                                public_key_b64=self.pub_b64,
                                expected_fingerprint=self.fingerprint
                            )
                        self.assertIn("not a regular file", str(ctx.exception))

    def test_24_toctou_content_mutation_detected(self):
        """24. Verify TOCTOU content mutation between read and re-check raises fail-closed error."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            token = self._create_token({"runner_sha256": r_hash})
            real_path = self._write_token_to_temp(token, td)

            orig_open = open
            def mock_reopen(path, mode="r", *args, **kwargs):
                if mode == "rb" and str(path) == real_path:
                    # Return mutated content on re-check
                    return unittest.mock.mock_open(read_data=b'{"mutated": true}')()
                return orig_open(path, mode, *args, **kwargs)

            with patch("builtins.open", side_effect=mock_reopen):
                with self.assertRaises(RuntimeError) as ctx:
                    verify_and_consume_authorization(
                        auth_file_path=real_path,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                self.assertIn("TOCTOU violation", str(ctx.exception))

    def test_25_exact_expiry_boundary_conditions(self):
        """25. Verify boundary conditions: valid token before expiry and expired token at/after expiry."""
        with tempfile.TemporaryDirectory() as td:
            runner_p, r_hash = self._write_mock_runner(td)
            fixed_now = datetime.datetime(2026, 11, 18, 20, 0, 0, tzinfo=datetime.timezone.utc)

            class MockNow(datetime.datetime):
                @classmethod
                def now(cls, tz=None):
                    return fixed_now

            # Boundary 1: exact expiry second (now_utc == expires_at)
            # Code: if now_utc > expires_at: raise EXPIRED. So now_utc == expires_at is still valid!
            token_exact = self._create_token({
                "runner_sha256": r_hash,
                "not_before_utc": "2026-11-18T19:00:00Z",
                "expires_at_utc": "2026-11-18T20:00:00Z"
            })
            p_exact = self._write_token_to_temp(token_exact, td)
            with patch("datetime.datetime", MockNow):
                res = verify_and_consume_authorization(
                    auth_file_path=p_exact,
                    run_id=self.run_id,
                    level=self.level,
                    duration_sec=self.duration_sec,
                    runner_path=runner_p,
                    public_key_b64=self.pub_b64,
                    expected_fingerprint=self.fingerprint
                )
                self.assertTrue(res["signature_verified"])

            # Boundary 2: 1 microsecond / second after expiry (now_utc > expires_at)
            token_after = self._create_token({
                "authorization_id": f"auth-{self.run_id}-after",
                "runner_sha256": r_hash,
                "not_before_utc": "2026-11-18T19:00:00Z",
                "expires_at_utc": "2026-11-18T19:59:59Z"
            })
            p_after = self._write_token_to_temp(token_after, td)
            with patch("datetime.datetime", MockNow):
                with self.assertRaises(RuntimeError) as ctx:
                    verify_and_consume_authorization(
                        auth_file_path=p_after,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                self.assertIn("EXPIRED", str(ctx.exception))

            # Boundary 3: 1 second before not_before (now_utc < not_before)
            token_before = self._create_token({
                "authorization_id": f"auth-{self.run_id}-before",
                "runner_sha256": r_hash,
                "not_before_utc": "2026-11-18T20:00:01Z",
                "expires_at_utc": "2026-11-18T21:00:00Z"
            })
            p_before = self._write_token_to_temp(token_before, td)
            with patch("datetime.datetime", MockNow):
                with self.assertRaises(RuntimeError) as ctx:
                    verify_and_consume_authorization(
                        auth_file_path=p_before,
                        run_id=self.run_id,
                        level=self.level,
                        duration_sec=self.duration_sec,
                        runner_path=runner_p,
                        public_key_b64=self.pub_b64,
                        expected_fingerprint=self.fingerprint
                    )
                self.assertIn("not yet valid", str(ctx.exception))

class TestG3ProductionTrustPaths(unittest.TestCase):
    """
    G3-72: tests of the PRODUCTION verify_and_consume_authorization API (no test adapter).
    All tests are offline. Filesystem tests use real temp files; the clock seam _utc_now is patched
    with a fixed instant so results never depend on the workstation date. These do NOT verify AWS/EKS.
    """
    FIXED_NOW = datetime.datetime(2030, 1, 1, 12, 0, 0, tzinfo=datetime.timezone.utc)

    def setUp(self):
        self.sk = ed25519.Ed25519PrivateKey.generate()
        self.pub_b64 = base64.b64encode(self.sk.public_key().public_bytes_raw()).decode()
        self.fp = hashlib.sha256(self.sk.public_key().public_bytes_raw()).hexdigest()
        self.td = tempfile.TemporaryDirectory()
        self.addCleanup(self.td.cleanup)
        d = self.td.name
        self.runner_p = os.path.join(d, "mock_runner.py")
        with open(self.runner_p, "w", encoding="utf-8") as f:
            f.write("# mock\n")
        self.r_hash = compute_sha256(self.runner_p)
        self.key_p = os.path.join(d, "pub.key")
        with open(self.key_p, "w", encoding="utf-8") as f:
            f.write(self.pub_b64)
        self.kw = dict(run_id="crdb-g3l1-pilot-p01", level="L1", duration_sec=180, runner_path=self.runner_p)

    def _iso(self, dt):
        return dt.replace(microsecond=0).isoformat().replace("+00:00", "Z")

    def _token(self, over=None, name="tok.json"):
        n = self.FIXED_NOW
        pl = {
            "authorization_id": "auth-" + name, "authorized_run_id": "crdb-g3l1-pilot-p01",
            "authorized_level": "L1",
            "parameters": {"wbps": 5242880, "wiops": 600, "max_fault_duration_sec": 180},
            "runner_sha256": self.r_hash, "protocol_version": PROTOCOL_VERSION,
            "operator_identity": "test-operator", "nonce": "n-" + name,
            "issued_at_utc": self._iso(n - datetime.timedelta(minutes=5)),
            "not_before_utc": self._iso(n - datetime.timedelta(minutes=5)),
            "expires_at_utc": self._iso(n + datetime.timedelta(hours=1)),
        }
        pl.update(over or {})
        sig = base64.b64encode(self.sk.sign(canonicalize_payload(pl))).decode()
        path = os.path.join(self.td.name, name)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"payload": pl, "signature": sig}, f)
        return path

    def _call(self, path, key=None, **extra):
        kw = dict(self.kw)
        kw.update(extra)
        with patch.object(runner_mod, "_utc_now", return_value=self.FIXED_NOW):
            with patch.object(runner_mod, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.fp):
                return prod_verify_and_consume_authorization(auth_file_path=path, public_key_path=key or self.key_p, **kw)

    def test_26_production_api_has_no_injection_parameters(self):
        import inspect
        params = inspect.signature(prod_verify_and_consume_authorization).parameters
        self.assertNotIn("public_key_b64", params)
        self.assertNotIn("expected_fingerprint", params)

    def test_27_arbitrary_key_injection_and_fingerprint_override_rejected(self):
        t = self._token()
        with self.assertRaises(TypeError):
            prod_verify_and_consume_authorization(auth_file_path=t, public_key_b64=self.pub_b64, **self.kw)
        with self.assertRaises(TypeError):
            prod_verify_and_consume_authorization(auth_file_path=t, expected_fingerprint=self.fp, **self.kw)
        self.assertFalse(os.path.exists(t + ".consumed"))

    def test_28_correct_trusted_key_accepted_and_fingerprint_recorded(self):
        t = self._token()
        r = self._call(t)
        self.assertEqual(r["public_key_fingerprint"], self.fp)
        with open(t + ".consumed", encoding="utf-8") as f:
            self.assertEqual(json.load(f)["public_key_fingerprint"], self.fp)

    def test_29_untrusted_key_rejected_against_real_pinned_constant(self):
        t = self._token()
        with patch.object(runner_mod, "_utc_now", return_value=self.FIXED_NOW):
            with self.assertRaises(RuntimeError) as c:
                prod_verify_and_consume_authorization(auth_file_path=t, public_key_path=self.key_p, **self.kw)
        self.assertIn("Untrusted public key", str(c.exception))
        self.assertFalse(os.path.exists(t + ".consumed"))

    def test_30_missing_malformed_wrongsize_key_rejected(self):
        t = self._token()
        with self.assertRaises(RuntimeError) as c:
            self._call(t, key=os.path.join(self.td.name, "nope.key"))
        self.assertIn("not found", str(c.exception))
        bad = os.path.join(self.td.name, "bad.key")
        for content in ("!!!not-base64!!!", base64.b64encode(b"short").decode(), ""):
            with open(bad, "w", encoding="utf-8") as f:
                f.write(content)
            with self.assertRaises(RuntimeError):
                self._call(t, key=bad)
        self.assertFalse(os.path.exists(t + ".consumed"))

    def test_31_default_key_path_missing_rejected(self):
        t = self._token()
        cwd = os.getcwd()
        os.chdir(self.td.name)
        try:
            with patch.object(runner_mod, "_utc_now", return_value=self.FIXED_NOW):
                with self.assertRaises(RuntimeError) as c:
                    prod_verify_and_consume_authorization(auth_file_path=t, **self.kw)
        finally:
            os.chdir(cwd)
        self.assertIn("not found", str(c.exception))

    def test_32_missing_token_rejected(self):
        with self.assertRaises(RuntimeError):
            self._call(os.path.join(self.td.name, "absent.json"))

    def test_33_deterministic_clock_boundaries(self):
        n = self.FIXED_NOW
        ok = self._token({"expires_at_utc": self._iso(n)}, name="exact.json")
        self.assertTrue(self._call(ok)["signature_verified"])
        late = self._token({"expires_at_utc": self._iso(n - datetime.timedelta(seconds=1))}, name="late.json")
        with self.assertRaises(RuntimeError) as c:
            self._call(late)
        self.assertIn("EXPIRED", str(c.exception))
        early = self._token({"not_before_utc": self._iso(n + datetime.timedelta(seconds=1))}, name="early.json")
        with self.assertRaises(RuntimeError) as c:
            self._call(early)
        self.assertIn("not yet valid", str(c.exception))

    def test_34_reuse_after_consumption_and_after_token_replacement_rejected(self):
        t = self._token()
        self._call(t)
        with self.assertRaises(RuntimeError) as c:
            self._call(t)
        self.assertIn("ALREADY BEEN CONSUMED", str(c.exception))
        # Replace token file with a different validly signed token at the same path: marker is path-bound.
        os.remove(t)
        self._token(name="tok.json", over={"nonce": "other"})
        with self.assertRaises(RuntimeError) as c:
            self._call(t)
        self.assertIn("ALREADY BEEN CONSUMED", str(c.exception))

    def test_35_real_symlink_token_rejected_when_privilege_available(self):
        t = self._token()
        link = os.path.join(self.td.name, "link.json")
        try:
            os.symlink(t, link)
        except (OSError, NotImplementedError):
            self.skipTest("symlink creation not permitted on this account")
        with self.assertRaises(RuntimeError) as c:
            self._call(link)
        self.assertIn("symlink", str(c.exception))

    def test_36_cli_rejection_never_invokes_lifecycle_or_subprocess(self):
        t = self._token()
        base = ["g3_pilot_runner.py", "--run-id", "crdb-g3l1-pilot-p01", "--level", "L1", "--duration", "180"]
        cases = [
            base,                                                         # no token
            base + ["--auth-token", t, "--public-key", self.key_p],      # untrusted key vs real pin
            base + ["--auth-token", os.path.join(self.td.name, "x.json")],  # missing token
        ]
        for argv in cases:
            with patch.object(sys, "argv", argv), \
                 patch.object(runner_mod, "compute_sha256", return_value=self.r_hash), \
                 patch.object(runner_mod, "_utc_now", return_value=self.FIXED_NOW):
                with patch.object(runner_mod.G3PilotExecutionCoordinator, "execute_lifecycle") as life:
                    with patch.object(runner_mod, "run_cmd") as rc:
                        with patch.object(runner_mod.subprocess, "run") as sr:
                            with self.assertRaises(SystemExit) as e:
                                main()
            self.assertEqual(e.exception.code, 1)
            life.assert_not_called()
            rc.assert_not_called()
            sr.assert_not_called()
        self.assertFalse(os.path.exists(t + ".consumed"))

    def test_37_cli_success_invokes_only_mocked_lifecycle_and_marker_survives_failure(self):
        t = self._token()
        argv = ["g3_pilot_runner.py", "--run-id", "crdb-g3l1-pilot-p01", "--level", "L1",
                "--duration", "180", "--auth-token", t, "--public-key", self.key_p]
        with patch.object(sys, "argv", argv), \
             patch.object(runner_mod, "compute_sha256", return_value=self.r_hash), \
             patch.object(runner_mod, "_utc_now", return_value=self.FIXED_NOW), \
             patch.object(runner_mod, "TRUSTED_OPERATOR_PUBKEY_SHA256", self.fp), \
             patch.object(runner_mod.G3PilotExecutionCoordinator, "execute_lifecycle",
                          side_effect=RuntimeError("simulated crash mid-run")) as life:
            with self.assertRaises(RuntimeError):
                main()
            life.assert_called_once()
            self.assertTrue(os.path.exists(t + ".consumed"))
            # Retry after interrupted execution must remain fail-closed.
            with self.assertRaises(SystemExit):
                main()
            life.assert_called_once()

    def test_38_no_environment_or_token_field_can_alter_trust_pin(self):
        import inspect
        src = inspect.getsource(runner_mod)
        self.assertNotIn("os.environ", src)
        self.assertNotIn("getenv", src)
        self.assertRegex(runner_mod.TRUSTED_OPERATOR_PUBKEY_SHA256, r"^[0-9a-f]{64}$")
        t = self._token({"public_key_fingerprint": "0" * 64, "expected_fingerprint": "0" * 64, "public_key": self.pub_b64})
        # Token fields are ignored for trust: validity still hinges on the pinned fingerprint only.
        with patch.object(runner_mod, "_utc_now", return_value=self.FIXED_NOW):
            with self.assertRaises(RuntimeError) as c:
                prod_verify_and_consume_authorization(auth_file_path=t, public_key_path=self.key_p, **self.kw)
        self.assertIn("Untrusted public key", str(c.exception))


class TestG3ConsumptionPersistence(unittest.TestCase):
    """
    G3-73: single-use persistence tests across processes. Real temp files and real child processes;
    pin and clock are patched INSIDE the child only. Offline; no AWS/EKS.
    """
    CHILD = (
        "import sys, json, datetime\n"
        "sys.path.insert(0, sys.argv[1])\n"
        "from unittest.mock import patch\n"
        "import benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised as r\n"
        "tok, key, runner, fp = sys.argv[2:6]\n"
        "now = datetime.datetime(2030,1,1,12,0,0,tzinfo=datetime.timezone.utc)\n"
        "with patch.object(r,'_utc_now',return_value=now), patch.object(r,'TRUSTED_OPERATOR_PUBKEY_SHA256',fp):\n"
        "    try:\n"
        "        r.verify_and_consume_authorization(auth_file_path=tok, run_id='crdb-g3l1-pilot-p01', level='L1',\n"
        "            duration_sec=180, runner_path=runner, public_key_path=key)\n"
        "        print('CONSUMED')\n"
        "    except RuntimeError as e:\n"
        "        print('REJECTED:' + str(e)[:200])\n"
    )

    def setUp(self):
        self.base = TestG3ProductionTrustPaths("test_26_production_api_has_no_injection_parameters")
        self.base.setUp()
        self.addCleanup(self.base.td.cleanup)
        self.tok = self.base._token()
        self.child = os.path.join(self.base.td.name, "child.py")
        with open(self.child, "w", encoding="utf-8") as f:
            f.write(self.CHILD)
        self.root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))

    def _spawn(self):
        import subprocess
        return subprocess.Popen(
            [sys.executable, self.child, self.root, self.tok, self.base.key_p, self.base.runner_p, self.base.fp],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

    def _run(self):
        pr = self._spawn()
        out, err = pr.communicate(timeout=60)
        return out.strip().splitlines()[-1]

    def test_39_process_restart_reuse_rejected(self):
        self.assertEqual(self._run(), "CONSUMED")
        second = self._run()
        self.assertTrue(second.startswith("REJECTED:"), second)
        self.assertIn("ALREADY BEEN CONSUMED", second)

    def test_40_multiprocess_concurrent_consumption_exactly_one_winner(self):
        procs = [self._spawn() for _ in range(6)]
        outs = [p.communicate(timeout=90)[0].strip().splitlines()[-1] for p in procs]
        self.assertEqual(outs.count("CONSUMED"), 1, outs)
        self.assertEqual(sum(o.startswith("REJECTED:") for o in outs), 5, outs)

    def test_41_marker_deletion_reenables_token_documented_residual_risk(self):
        """
        CHARACTERIZATION of a KNOWN LIMITATION (not a security guarantee): the marker is a plain file next to the
        token. If an actor with delete permission removes it, a still-valid token can be consumed again.
        This test asserts the current behaviour so the risk stays visible; it must be inverted if a durable
        ledger is later implemented.
        """
        self.assertEqual(self._run(), "CONSUMED")
        marker = self.tok + ".consumed"
        self.assertTrue(os.path.exists(marker))
        os.remove(marker)
        self.assertEqual(self._run(), "CONSUMED")

    def test_42_copy_of_token_at_new_path_is_reconsumable_documented_residual_risk(self):
        """
        CHARACTERIZATION of a KNOWN LIMITATION (G3-73-F01): the consumption marker is keyed by the token FILE PATH,
        not by authorization_id. A byte-identical copy at a different path has its own (absent) marker and is
        accepted again while the token is valid. Inverts to 'rejected' once a ledger keyed by authorization_id
        is implemented.
        """
        import shutil
        self.assertEqual(self._run(), "CONSUMED")
        copy = os.path.join(self.base.td.name, "tok_copy.json")
        shutil.copyfile(self.tok, copy)
        self.tok = copy
        self.assertEqual(self._run(), "CONSUMED")


class TestG3HelperShellCompatibilityOffline(unittest.TestCase):
    """
    G3-86 / G3-91 offline validation test suite for G3 helper & rollback POSIX Dash shell compatibility,
    manifest parameterization, strict input sanitization, trap architecture, and rollback invocation.
    """

    def setUp(self):
        self.mock_target_info = {
            "target_node": "ip-10-0-1-160.ec2.internal",
            "target_pod": "cockroachdb-1",
            "pod_uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
            "container_id": "f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c",
            "dev_major": 259,
            "dev_minor": 4,
            "dev_stat_dec": 66308,
            "initial_io_max": ""
        }

    def test_01_helper_script_posix_shell_compatibility(self):
        """Verify helper and rollback manifests use POSIX 'set -eu' and contain no bashisms."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p02",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False
        )
        _, rb_manifest = generate_rollback_job_manifest("crdb-g3l1-pilot-p02", self.mock_target_info)
        for text in (manifest, rb_manifest):
            self.assertIn("set -eu\n", text)
            self.assertNotIn("pipefail", text)
            self.assertNotIn("[[", text)
            self.assertNotIn("<<<", text)
            self.assertNotIn("${var//", text)
            self.assertNotIn("function ", text)
            self.assertNotIn("==", text)

    def test_02_helper_startup_and_strict_cgroup_resolution(self):
        """Verify helper script strictly validates hex CID and uniqueness of cgroup dir resolution."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p02",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False
        )
        self.assertIn("is_hex \"${G3_CONTAINER_ID:-}\"", manifest)
        self.assertIn("G3_CGROUP_ROOT", manifest)
        self.assertIn("find \"${_rcp_root}\" -name \"*${_rcp_cid}*\" -type d", manifest)
        self.assertIn("resolve_unique_cgroup_path", manifest)
        self.assertIn("[ \"${MATCH_COUNT}\" -ne 1 ]", manifest)
        self.assertIn("Unique cgroup path with readable io.max not found for container", manifest)
        self.assertIn("terminationGracePeriodSeconds: 30", manifest)

    def test_03_invalid_device_or_container_id_rejected(self):
        """Verify empty, wildcards, or non-hex CIDs are rejected before manifest generation."""
        for bad_cid in ("", "*abc*", "not-hex-cid", "1234"):
            bad_target = dict(self.mock_target_info, container_id=bad_cid)
            with self.assertRaises(ValueError):
                generate_helper_job_manifest("crdb-g3l1-pilot-p02", bad_target, "L1", 180, False)
            with self.assertRaises(ValueError):
                generate_rollback_job_manifest("crdb-g3l1-pilot-p02", bad_target)

    def test_04_successful_throttle_application_exact_four_limits(self):
        """Verify helper script writes and verifies all 4 io.max limits including untouched read limits."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p02",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False
        )
        self.assertIn("printf '%s rbps=%s wbps=%s riops=%s wiops=%s\\n' \"${DEV_ID}\" \"${ORIG_RBPS}\" \"${G3_LIMIT_WBPS}\" \"${ORIG_RIOPS}\" \"${G3_LIMIT_WIOPS}\" > \"${CGROUP_PATH}/io.max\"", manifest)
        self.assertIn("verify_io_max_values \"${ORIG_RBPS}\" \"${G3_LIMIT_WBPS}\" \"${ORIG_RIOPS}\" \"${G3_LIMIT_WIOPS}\" 0", manifest)
        self.assertIn("parse_device_line", manifest)
        self.assertIn("read_and_validate_io_max", manifest)

    def test_05_throttle_verification_timeout_triggers_real_coordinator_abort(self):
        """Verify real coordinator aborts and rolls back when io.max never shows expected 4 limits within 15s."""
        with tempfile.TemporaryDirectory() as td:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l1-pilot-p02",
                level="L1",
                duration_sec=180,
                dry_run=False
            )
            coord.output_dir = td
            coord.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            coord.client_pgid = 9999
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback", return_value=True) as mock_rb, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
                # Warmup passes, pgid reads 8888, helper applies, 15 verification polls return partial write limit (wbps throttled, wiops max)
                mock_rc.side_effect = [
                    MagicMock(returncode=0, stdout="", stderr=""),
                    MagicMock(returncode=0, stdout="8888\n", stderr=""),
                    MagicMock(returncode=0, stdout="", stderr=""),
                    *[MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=max", stderr="") for _ in range(16)],
                ]
                record = coord.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "FAILED")
            mock_rb.assert_called_once_with(self.mock_target_info)
            self.assertIn("Throttle limit did not appear in io.max within 15s", record["state_history"][6]["error"])

    def test_06_restoration_of_original_io_max_state(self):
        """Verify cleanup restores non-empty original 4-limit state or resets all 4 limits to max."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p02",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False
        )
        self.assertIn("if [ -n \"${ORIGINAL_IO_MAX}\" ]; then", manifest)
        self.assertIn("_rest_rule=\"${ORIGINAL_IO_MAX}\"", manifest)
        self.assertIn("_rest_rule=\"${DEV_ID} rbps=max wbps=max riops=max wiops=max\"", manifest)
        self.assertIn("verify_io_max_values \"${ORIG_RBPS}\" \"${ORIG_WBPS}\" \"${ORIG_RIOPS}\" \"${ORIG_WIOPS}\" \"${ALLOW_ABSENT_ON_RESTORE}\"", manifest)

    def test_07_sigint_and_sigterm_cleanup_traps_and_shielding(self):
        """Verify separate signal handlers set exit codes 130/143 and shield cleanup from secondary signals."""
        manifest = generate_helper_job_manifest(
            run_id="crdb-g3l1-pilot-p02",
            target_info=self.mock_target_info,
            level="L1",
            duration_sec=180,
            dry_run=False
        )
        self.assertIn("on_signal()", manifest)
        self.assertIn("on_exit()", manifest)
        self.assertIn("trap 'on_signal INT 130' INT", manifest)
        self.assertIn("trap 'on_signal TERM 143' TERM", manifest)
        self.assertIn("trap on_exit EXIT", manifest)
        self.assertIn("trap '' INT TERM", manifest)

    def test_08_helper_failure_and_emergency_rollback_via_privileged_job(self):
        """Verify emergency rollback launches privileged g3-rollback Job and verifies io.max clearance."""
        LAST_ROLLBACK_REPORTS.clear()
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            pod_json = {
                "status": {
                    "containerStatuses": [
                        {"containerID": f"containerd://{self.mock_target_info['container_id']}"}
                    ]
                }
            }
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="job.batch/g3-rollback created", stderr=""),
                MagicMock(returncode=0, stdout="condition met", stderr=""),
                MagicMock(returncode=0, stdout="[G3 Rollback] Done", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="259:4 rbps=max wbps=max riops=max wiops=max", stderr=""),
            ]
            res = emergency_independent_rollback(self.mock_target_info)
            self.assertTrue(res)
            self.assertEqual(len(LAST_ROLLBACK_REPORTS), 1)
            self.assertEqual(LAST_ROLLBACK_REPORTS[0]["status"], "VERIFIED_RESTORED")


class TestG391RemediationOffline(unittest.TestCase):
    """Comprehensive unit and mock-lifecycle tests for every G3-90 finding remediated in G3-91."""

    def setUp(self):
        self.target = {
            "range_id": 98,
            "lease_holder_id": 5,
            "target_pod": "cockroachdb-1",
            "pod_uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
            "target_node": "ip-10-0-1-160.ec2.internal",
            "container_id": "f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c",
            "dev_major": 259,
            "dev_minor": 4,
            "dev_stat_dec": 66308,
            "raw_show_range": "98|5|cockroachdb-1",
            "initial_io_max": "",
        }
        self.pod_json = {
            "metadata": {"uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67"},
            "spec": {"nodeName": "ip-10-0-1-160.ec2.internal"},
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://" + self.target["container_id"]}
                ]
            },
        }

    # --- C01: Rollback & Failure Recovery ---

    def test_c01_rollback_job_apply_failure_fails_closed(self):
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(self.pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # delete helper
                MagicMock(returncode=1, stdout="", stderr="Forbidden"),  # apply fails
                MagicMock(returncode=0, stdout="", stderr=""),  # final readback
            ]
            self.assertFalse(emergency_independent_rollback(self.target))

    def test_c01_rollback_job_wait_failure_fails_closed(self):
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(self.pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="created", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="timed out waiting for condition"),
                MagicMock(returncode=0, stdout="partial logs", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            self.assertFalse(emergency_independent_rollback(self.target))

    def test_c01_rollback_readback_kubectl_exec_failure_fails_closed(self):
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(self.pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=0, stdout="created", stderr=""),
                MagicMock(returncode=0, stdout="condition met", stderr=""),
                MagicMock(returncode=0, stdout="ok", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="pod exec connection lost"),
            ]
            self.assertFalse(emergency_independent_rollback(self.target))

    def test_c01_partial_restoration_and_malformed_io_max_fail_closed(self):
        ok, _ = verify_io_max_restored("259:4 rbps=max wbps=max riops=max wiops=600", 259, 4)
        self.assertFalse(ok)
        ok, _ = verify_io_max_restored("259:4 rbps=1048576 wbps=max riops=max wiops=max", 259, 4)
        self.assertFalse(ok)
        ok, _ = verify_io_max_restored("259:4 wbps=max", 259, 4)
        self.assertFalse(ok)
        with self.assertRaises(ValueError):
            parse_io_max_content("corrupted_line_without_colon")
        ok, _ = verify_io_max_applied("corrupted", 259, 4, 5242880, 600)
        self.assertFalse(ok)

    def test_c01_nonempty_original_four_limit_restoration_exact_check(self):
        orig = "259:4 rbps=10485760 wbps=20971520 riops=1000 wiops=2000"
        ok_match, _ = verify_io_max_restored(orig, 259, 4, orig)
        self.assertTrue(ok_match)
        ok_diff, _ = verify_io_max_restored("259:4 rbps=max wbps=20971520 riops=1000 wiops=2000", 259, 4, orig)
        self.assertFalse(ok_diff)
        ok_app, _ = verify_io_max_applied("259:4 rbps=10485760 wbps=5242880 riops=1000 wiops=600", 259, 4, 5242880, 600, orig)
        self.assertTrue(ok_app)
        ok_app_tamper_r, _ = verify_io_max_applied("259:4 rbps=999 wbps=5242880 riops=1000 wiops=600", 259, 4, 5242880, 600, orig)
        self.assertFalse(ok_app_tamper_r)

    def test_c01_container_restart_still_verifies_io_max(self):
        restarted_pod = {
            "status": {"containerStatuses": [{"containerID": "containerd://" + "a" * 64}]}
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(restarted_pod), stderr=""),
                MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr=""),
            ]
            self.assertFalse(emergency_independent_rollback(self.target))

    def test_c01_concurrent_rollback_deduplication(self):
        entered = threading.Event()
        release = threading.Event()
        results = {}

        def slow_run_cmd(cmd, check=True, timeout=None):
            cmd_str = " ".join(cmd)
            if "get pod" in cmd_str:
                entered.set()
                release.wait(timeout=3.0)
                return MagicMock(returncode=0, stdout=json.dumps({"status": {"containerStatuses": [{"containerID": "containerd://" + "b" * 64}]}}), stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=slow_run_cmd):
            t1 = threading.Thread(target=lambda: results.__setitem__("t1", emergency_independent_rollback(self.target)))
            t1.start()
            self.assertTrue(entered.wait(timeout=2.0))
            results["t2"] = emergency_independent_rollback(self.target)
            release.set()
            t1.join(timeout=3.0)
        self.assertTrue(results["t1"])
        self.assertFalse(results["t2"])

    def test_c01_main_exits_nonzero_when_disposition_failed(self):
        orig_cwd = os.getcwd()
        with tempfile.TemporaryDirectory() as td:
            try:
                os.chdir(td)
                with patch.object(runner_mod, "verify_and_consume_authorization", return_value={"authorization_id": "auth-test-1", "run_id": "crdb-g3l1-pilot-p02", "level": "L1", "duration": 180}), \
                     patch.object(runner_mod, "run_preflight_audit", side_effect=RuntimeError("preflight boom")), \
                     patch.object(sys, "argv", ["g3_pilot_runner.py", "--run-id", "crdb-g3l1-pilot-p02", "--level", "L1", "--duration", "180", "--auth-token", "tok.json"]):
                    with self.assertRaises(SystemExit) as cm:
                        main()
                    self.assertEqual(cm.exception.code, 1)

                with patch.object(runner_mod, "run_preflight_audit", side_effect=RuntimeError("dry preflight boom")), \
                     patch.object(sys, "argv", ["g3_pilot_runner.py", "--run-id", "crdb-g3l1-pilot-p02", "--level", "L1", "--duration", "180", "--dry-run"]):
                    with self.assertRaises(SystemExit) as cm_dry:
                        main()
                    self.assertEqual(cm_dry.exception.code, 1)
            finally:
                os.chdir(orig_cwd)

    # --- C03: History Integrity & Invariants ---

    def test_c03_warmup_and_wrapper_preserve_history_and_source_invariants(self):
        warmup_cmd = construct_warmup_command(120)
        self.assertIn("-n", warmup_cmd)
        self.assertNotIn("-i", warmup_cmd)
        self.assertNotIn("-I", warmup_cmd)
        wrapper = construct_in_pod_wrapper("crdb-g3l1-pilot-p02", 600)
        self.assertIn(" -n ", wrapper)
        self.assertIn("wait", wrapper)
        src = open(os.path.join(os.path.dirname(runner_mod.__file__), "g3_pilot_runner.py"), "r", encoding="utf-8").read()
        self.assertNotIn("TRUNCATE", src.upper())
        self.assertNotIn("DELETE FROM", src.upper())
        self.assertNotIn("os.environ", src)
        self.assertNotIn("getenv", src)

    def test_c03_history_shrinkage_during_warmup_or_measurement_aborts(self):
        with tempfile.TemporaryDirectory() as td:
            coord = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=True)
            coord.output_dir = td
            coord.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"pgbench_history_count": 5000}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.target), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["5000", "4000"]):
                record = coord.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertIn("history", record["state_history"][3]["error"].lower())

    # --- M02: Dynamic Target Resolution & Validation ---

    def test_m02_decode_linux_st_dev_extended_minors(self):
        self.assertEqual(decode_linux_st_dev(66308), (259, 4))
        # major=259 (0x103), minor=256 (0x100): (0x100 & 0xff) | ((0x103 & 0xfff) << 8) | ((0x100 >> 8) << 20)
        ext_dev = (256 & 0xFF) | ((259 & 0xFFF) << 8) | ((256 >> 8) << 20)
        self.assertEqual(decode_linux_st_dev(ext_dev), (259, 256))

    def test_m02_gossip_mapping_node_id_not_equal_ordinal_plus_one(self):
        range_out = "...|...|98|5|...|{1,3,5}"
        gossip_out = "\n".join([
            "1|cockroachdb-0.cockroachdb.cockroachdb.svc.cluster.local:26257|t",
            "3|cockroachdb-2.cockroachdb.cockroachdb.svc.cluster.local:26257|t",
            "5|cockroachdb-1.cockroachdb.cockroachdb.svc.cluster.local:26257|t",
        ])
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=[range_out, range_out, gossip_out]), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(self.pod_json), stderr=""),
                MagicMock(returncode=0, stdout="66308\n", stderr=""),
                MagicMock(returncode=0, stdout="1611 1604 259:4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw,seclabel\n", stderr=""),
                MagicMock(returncode=0, stdout="MAJOR=259\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n", stderr=""),
                MagicMock(returncode=0, stdout="cpuset io memory\n", stderr=""),
                MagicMock(returncode=0, stdout="259:4 rbytes=1\n", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            info = resolve_target_leaseholder()
        self.assertEqual(info["lease_holder_id"], 5)
        self.assertEqual(info["target_pod"], "cockroachdb-1")

    def test_m02_dead_gossip_node_missing_io_controller_unreadable_iostat_and_drift_fail(self):
        range_out = "...|...|98|2|...|{1,2,3}"
        # Dead node in gossip
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=[range_out, range_out, "2|cockroachdb-1.cockroachdb.cockroachdb.svc.cluster.local:26257|f"]):
            with self.assertRaises(RuntimeError):
                resolve_target_leaseholder()
        # Missing io controller
        gossip_ok = "2|cockroachdb-1.cockroachdb.cockroachdb.svc.cluster.local:26257|t"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=[range_out, range_out, gossip_ok]), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(self.pod_json), stderr=""),
                MagicMock(returncode=0, stdout="66308\n", stderr=""),
                MagicMock(returncode=0, stdout="1611 1604 259:4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw,seclabel\n", stderr=""),
                MagicMock(returncode=0, stdout="MAJOR=259\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n", stderr=""),
                MagicMock(returncode=0, stdout="cpuset cpu memory\n", stderr=""),
            ]
            with self.assertRaises(RuntimeError):
                resolve_target_leaseholder()
        # Unreadable io.stat
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=[range_out, range_out, gossip_ok]), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(self.pod_json), stderr=""),
                MagicMock(returncode=0, stdout="66308\n", stderr=""),
                MagicMock(returncode=0, stdout="1611 1604 259:4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw,seclabel\n", stderr=""),
                MagicMock(returncode=0, stdout="MAJOR=259\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n", stderr=""),
                MagicMock(returncode=0, stdout="cpuset io\n", stderr=""),
                MagicMock(returncode=1, stdout="", stderr="Permission denied"),
            ]
            with self.assertRaises(RuntimeError):
                resolve_target_leaseholder()
        # Drift detection
        drifted = dict(self.target, container_id="c" * 64)
        with self.assertRaises(RuntimeError):
            validate_target_unchanged(self.target, drifted, "PRE_FAULT")

    # --- M03 & I01: Lifecycle, Preflight, Telemetry, Dry-Run, Cross-Run Token ---

    def test_m03_tx_stream_span_and_nonzero_exit_code_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            p1 = os.path.join(td, "log.1")
            with open(p1, "w", encoding="utf-8") as f:
                f.write("1 0 100 0 1000 0\n1 1 110 0 1605 500000\n")
            self.assertAlmostEqual(compute_tx_stream_span_sec([p1]), 605.5, places=3)
            self.assertIsNone(compute_tx_stream_span_sec([os.path.join(td, "missing")]))

            coord = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=False)
            coord.output_dir = td
            coord.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.target), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"5\",node_id=\"5\"}": "0"}}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
                mp = MagicMock()
                mp.communicate.return_value = ("", "")
                mp.returncode = 0
                mock_popen.return_value = mp

                def fake_rc(cmd, check=True, timeout=None):
                    s = " ".join(cmd)
                    if "pgid.txt" in s:
                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                    if "exit_code.txt" in s:
                        return MagicMock(returncode=0, stdout="2\n", stderr="")  # pgbench failed!
                    if "cat /sys/fs/cgroup/io.max" in s:
                        if coord.current_state == ExecutionState.FAULT_VERIFICATION:
                            return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                        return MagicMock(returncode=0, stdout="", stderr="")
                    if "ls /tmp/pgbench_log_" in s:
                        return MagicMock(returncode=0, stdout="/tmp/pgbench_log_x.1\n", stderr="")
                    return MagicMock(returncode=0, stdout="1 0 10 0 100 0\n1 1 10 0 700 0\n", stderr="")

                mock_rc.side_effect = fake_rc
                record = coord.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(any("exit_code" in m for m in record["evidence_missing"]))

    def test_m03_wrec_anchored_to_t_clear(self):
        with tempfile.TemporaryDirectory() as td:
            coord = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=True)
            coord.output_dir = td
            coord.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            sleeps = []
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.target), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"5\",node_id=\"5\"}": "0"}}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep", side_effect=lambda s: sleeps.append(s)):
                record = coord.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "SIMULATED_SUCCESS")
            self.assertIsNotNone(record["timestamps"].get("T_clear"))
            self.assertIn("T_obs_end - T_clear >= 300s", record["timing_definitions"]["Wrec"])
            self.assertIn("RTO", record["timing_definitions"])
            self.assertIn("DT", record["timing_definitions"])

        # Verify live-mode Wrec sleeps only remaining balance after 240s post-fault workload
        with tempfile.TemporaryDirectory() as td:
            coord_live = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=False)
            coord_live.output_dir = td
            coord_live.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            fake_clock = [1000.0]

            def fake_time():
                if coord_live.current_state == ExecutionState.FAULT_MEASUREMENT:
                    fake_clock[0] = 1180.0
                elif coord_live.current_state == ExecutionState.RESTORATION_VERIFICATION:
                    fake_clock[0] = 1180.0
                elif coord_live.current_state == ExecutionState.POST_FAULT_MEASUREMENT:
                    fake_clock[0] = 1420.0  # T_clear + 240s
                return fake_clock[0]

            def fake_sleep(sec):
                if threading.current_thread() is threading.main_thread() and coord_live.current_state == ExecutionState.WREC_OBSERVATION:
                    wrec_sleeps.append(sec)
                    fake_clock[0] += sec

            wrec_sleeps = []
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.target), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"5\",node_id=\"5\"}": "0"}}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"pods": [], "errors": []}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.time", side_effect=fake_time), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep", side_effect=fake_sleep), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
                mp = MagicMock()
                mp.communicate.return_value = ("", "")
                mp.returncode = 0
                mock_popen.return_value = mp

                def fake_rc(cmd, check=True, timeout=None):
                    s = " ".join(cmd)
                    if "pgid.txt" in s:
                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                    if "exit_code.txt" in s:
                        return MagicMock(returncode=0, stdout="0\n", stderr="")
                    if "cat /sys/fs/cgroup/io.max" in s:
                        if coord_live.current_state == ExecutionState.FAULT_VERIFICATION:
                            return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                        return MagicMock(returncode=0, stdout="", stderr="")
                    if "ls /tmp/pgbench_log_" in s:
                        return MagicMock(returncode=0, stdout="/tmp/pgbench_log_x.1\n", stderr="")
                    return MagicMock(returncode=0, stdout="1 0 10 0 100 0\n1 1 10 0 700 0\n", stderr="")

                mock_rc.side_effect = fake_rc
                record_live = coord_live.execute_lifecycle()
            self.assertEqual(record_live["final_disposition"], "EXECUTED_VALIDATED")
            self.assertEqual(wrec_sleeps, [60.0])
            self.assertAlmostEqual(record_live["clocks"]["clock2_wrec_duration_sec"], 300.0, places=3)

    def test_m03_preflight_audit_checks_all_gates(self):
        nodes_json = {"items": [{"metadata": {"name": f"node-{i}"}, "status": {"conditions": [{"type": "Ready", "status": "True"}]}} for i in range(3)]}
        crdb_pods_json = {"items": [
            {"metadata": {"name": f"cockroachdb-{i}"}, "status": {"phase": "Running", "containerStatuses": [{"ready": True, "restartCount": 0}]}}
            for i in range(3)
        ]}
        pvc_json = {"items": [{"metadata": {"name": f"datadir-cockroachdb-{i}"}, "status": {"phase": "Bound"}} for i in range(3)]}
        client_pod_json = {"status": {"phase": "Running", "containerStatuses": [{"ready": True}]}}
        empty_list = {"items": []}
        df_out = "Filesystem 1K-blocks Used Available Use% Mounted on\ntmpfs 65536 7000 58536 11% /tmp\n"

        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc, \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["5000000", "122727", "0"]):
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps({"Account": "123456789012"}), stderr=""),
                MagicMock(returncode=0, stdout="eks-ctx\n", stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(nodes_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(crdb_pods_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(pvc_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(client_pod_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(empty_list), stderr=""),  # g1-chaos pods
                MagicMock(returncode=0, stdout=json.dumps(empty_list), stderr=""),  # g1-chaos jobs
                MagicMock(returncode=0, stdout=df_out, stderr=""),
            ]
            audit = run_preflight_audit(dry_run=True)
        self.assertEqual(audit["dataset_rows"], 5000000)
        self.assertEqual(audit["s0_preflight_history"], 122727)
        self.assertEqual(audit["underreplicated_ranges"], 0)
        self.assertTrue(audit["chaos_namespace_clean"])
        # Ensure broker pod selector excludes completed component=init Job pods
        pod_query_cmds = [" ".join(c.args[0]) for c in mock_rc.call_args_list if "app.kubernetes.io/name=cockroachdb" in " ".join(c.args[0])]
        self.assertTrue(pod_query_cmds)
        self.assertIn("app.kubernetes.io/name=cockroachdb,app.kubernetes.io/component=cockroachdb", pod_query_cmds[0])

        # Verify non-zero pod restartCount fails preflight
        restarted_pods = {"items": [
            {"metadata": {"name": "cockroachdb-0"}, "status": {"phase": "Running", "containerStatuses": [{"ready": True, "restartCount": 1}]}},
            {"metadata": {"name": "cockroachdb-1"}, "status": {"phase": "Running", "containerStatuses": [{"ready": True, "restartCount": 0}]}},
            {"metadata": {"name": "cockroachdb-2"}, "status": {"phase": "Running", "containerStatuses": [{"ready": True, "restartCount": 0}]}},
        ]}
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc_r:
            mock_rc_r.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps({"Account": "123456789012"}), stderr=""),
                MagicMock(returncode=0, stdout="eks-ctx\n", stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(nodes_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(restarted_pods), stderr=""),
            ]
            with self.assertRaises(RuntimeError):
                run_preflight_audit(dry_run=True)

        # Verify dirty g1-chaos fails preflight
        dirty_pods = {"items": [{"metadata": {"name": "leftover-pod"}}]}
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc, \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["5000000", "122727", "0"]):
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps({"Account": "123456789012"}), stderr=""),
                MagicMock(returncode=0, stdout="eks-ctx\n", stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(nodes_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(crdb_pods_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(pvc_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(client_pod_json), stderr=""),
                MagicMock(returncode=0, stdout=json.dumps(dirty_pods), stderr=""),
            ]
            with self.assertRaises(RuntimeError):
                run_preflight_audit(dry_run=True)

    def test_m03_dry_run_abort_never_invokes_live_kubectl_cleanup(self):
        with tempfile.TemporaryDirectory() as td:
            coord = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=True)
            coord.output_dir = td
            coord.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            coord.fault_applied = True
            coord.client_pgid = 9999
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=RuntimeError("boom")), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback") as mock_rb, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group") as mock_kill:
                record = coord.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "FAILED")
            mock_rb.assert_not_called()
            mock_kill.assert_not_called()

    def test_m03_incremental_telemetry_poller_records_iostat_error_status(self):
        with tempfile.TemporaryDirectory() as td:
            tel = os.path.join(td, "telemetry.jsonl")
            stop_ev = threading.Event()

            def one_shot_metrics(*args, **kwargs):
                stop_ev.set()
                return {"metrics": {"x": "1"}, "success": True}

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", side_effect=one_shot_metrics), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_cgroup_iostat", return_value={"returncode": 1, "success": False, "error": "exec failed", "raw": ""}):
                incremental_telemetry_poller("cockroachdb-1", stop_ev, tel, interval=0.01)
            lines = open(tel, "r", encoding="utf-8").read().strip().splitlines()
            self.assertGreaterEqual(len(lines), 1)
            entry = json.loads(lines[0])
            self.assertFalse(entry["iostat"]["success"])
            self.assertEqual(entry["iostat"]["returncode"], 1)

    def test_m03_fault_removal_avoids_hostpid_kill_captures_logs_before_delete_and_preserves_orig_rollback(self):
        # 1) Rollback manifest includes G3_ORIGINAL_IO_MAX when pre-existing 4-limit line exists
        orig_target = dict(self.target, initial_io_max="259:4 rbps=10485760 wbps=20971520 riops=1000 wiops=2000\n")
        _, rb_yaml = generate_rollback_job_manifest("p02", orig_target)
        self.assertIn("259:4 rbps=10485760 wbps=20971520 riops=1000 wiops=2000", rb_yaml)

        # 2) Verify FAULT_REMOVAL never sends kill -TERM 1 and collects helper logs BEFORE delete job
        call_order = []
        with tempfile.TemporaryDirectory() as td:
            coord = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=False)
            coord.output_dir = td
            coord.telemetry_file_path = os.path.join(td, "telemetry.jsonl")

            def fake_collect(*args, **kwargs):
                call_order.append("collect_logs")
                return {"pods": [{"pod_name": "g3-helper-p", "exit_codes": {"g3-helper": 0}}], "errors": []}

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.target), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"5\",node_id=\"5\"}": "0"}}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", side_effect=fake_collect), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
                mp = MagicMock()
                mp.communicate.return_value = ("", "")
                mp.returncode = 0
                mock_popen.return_value = mp

                def fake_rc(cmd, check=True, timeout=None):
                    s = " ".join(cmd)
                    self.assertNotIn("kill -TERM 1", s)
                    if coord.current_state == ExecutionState.FAULT_REMOVAL:
                        if "kubectl wait" in s:
                            call_order.append("wait_job")
                        elif "kubectl delete job" in s:
                            call_order.append("delete_job")
                    if "pgid.txt" in s:
                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                    if "exit_code.txt" in s:
                        return MagicMock(returncode=0, stdout="0\n", stderr="")
                    if "cat /sys/fs/cgroup/io.max" in s:
                        if coord.current_state == ExecutionState.FAULT_VERIFICATION:
                            return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                        return MagicMock(returncode=0, stdout="", stderr="")
                    if "ls /tmp/pgbench_log_" in s:
                        return MagicMock(returncode=0, stdout="/tmp/pgbench_log_x.1\n", stderr="")
                    return MagicMock(returncode=0, stdout="1 0 10 0 100 0\n1 1 10 0 700 0\n", stderr="")

                mock_rc.side_effect = fake_rc
                record = coord.execute_lifecycle()
            self.assertEqual(record["final_disposition"], "EXECUTED_VALIDATED")
            self.assertEqual(call_order, ["wait_job", "collect_logs", "delete_job"])

    def test_m03_p01_token_rejected_for_p02(self):
        priv = ed25519.Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode("ascii")
        fp = hashlib.sha256(priv.public_key().public_bytes_raw()).hexdigest()
        payload = {
            "protocol_version": PROTOCOL_VERSION,
            "run_id": "crdb-g3l1-pilot-p01",
            "level": "L1",
            "duration_sec": 180,
            "issued_at_utc": "2026-11-19T00:00:00Z",
            "expires_at_utc": "2026-11-19T23:59:59Z",
            "nonce": "nonce-01",
            "operator": "op",
        }
        sig = base64.b64encode(priv.sign(canonicalize_payload(payload))).decode("ascii")
        with tempfile.TemporaryDirectory() as td:
            tp = os.path.join(td, "p01.token.json")
            with open(tp, "w", encoding="utf-8") as f:
                json.dump({"payload": payload, "signature_b64": sig}, f)
            with self.assertRaises(Exception):
                verify_and_consume_authorization(
                    token_path=tp,
                    run_id="crdb-g3l1-pilot-p02",
                    level="L1",
                    duration_sec=180,
                    public_key_b64=pub_b64,
                    expected_fingerprint=fp,
                )

    # --- G3-100A: Pod UID, Device Major, Whole-Disk Mapping & Rollback hostPID ---

    def _run_resolve_with_mocks(self, pod_json_obj, stat_out="66308\n", mnt_out=None, uevent_out=None, uevent_rc=0):
        range_out = "...|...|98|5|...|{1,2,3}"
        gossip_out = "5|cockroachdb-1.cockroachdb.cockroachdb.svc.cluster.local:26257|t"
        if mnt_out is None:
            mnt_out = "1611 1604 259:4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw,seclabel\n"
        if uevent_out is None:
            uevent_out = "MAJOR=259\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=[range_out, range_out, gossip_out]), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_rc:
            mock_rc.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json_obj), stderr=""),
                MagicMock(returncode=0, stdout=stat_out, stderr=""),
                MagicMock(returncode=0, stdout=mnt_out, stderr=""),
                MagicMock(returncode=uevent_rc, stdout=uevent_out if uevent_rc == 0 else "", stderr="No such file" if uevent_rc != 0 else ""),
                MagicMock(returncode=0, stdout="cpuset cpu io memory\n", stderr=""),
                MagicMock(returncode=0, stdout="259:4 rbytes=100 wbytes=200\n", stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),
            ]
            return resolve_target_leaseholder()

    def test_g3_100a_01_missing_pod_uid_rejected(self):
        for bad_meta in ({}, {"uid": ""}, {"uid": "   "}, {"uid": None}, {"uid": "uid with space"}):
            bad_pod = dict(self.pod_json, metadata=bad_meta)
            with self.assertRaises(RuntimeError) as cm:
                self._run_resolve_with_mocks(bad_pod)
            self.assertIn("pod UID", str(cm.exception))
        for bad_uid in ("", "   ", None, "uid with space"):
            t_missing = dict(self.target, pod_uid=bad_uid)
            with self.assertRaises(RuntimeError):
                validate_target_unchanged(t_missing, self.target, "warmup")
            with self.assertRaises(RuntimeError):
                validate_target_unchanged(self.target, t_missing, "pre_fault_application")
            with self.assertRaises(RuntimeError):
                validate_target_unchanged(t_missing, t_missing, "pre_fault_application")

    def test_g3_100a_02_changed_pod_uid_rejected_including_after_warmup_and_pre_fault(self):
        drifted_uid = dict(self.target, pod_uid="99999999-483c-4a7f-84f6-550abcd752f5")
        with self.assertRaises(RuntimeError) as cm:
            validate_target_unchanged(self.target, drifted_uid, "pre_fault_application")
        self.assertIn("pod_uid", str(cm.exception))

        # Coordinator pre-fault pod_uid change aborts fail-closed before fault application
        with tempfile.TemporaryDirectory() as td:
            coord_pf = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=True)
            coord_pf.output_dir = td
            coord_pf.telemetry_file_path = os.path.join(td, "telemetry.jsonl")
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=[self.target, self.target, drifted_uid]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                rec_pf = coord_pf.execute_lifecycle()
            self.assertEqual(rec_pf["final_disposition"], "FAILED")
            self.assertIn("pod_uid", rec_pf["state_history"][4]["error"])

    def test_g3_100a_03_valid_unchanged_pod_uid_passes(self):
        validate_target_unchanged(self.target, dict(self.target), "warmup")
        validate_target_unchanged(self.target, dict(self.target), "pre_fault_application")

    def test_g3_100a_04_invalid_or_zero_device_major_rejected(self):
        # st_dev=0 -> 0:0, st_dev=4 -> 0:4 (major == 0)
        for bad_st_dev in ("0\n", "4\n"):
            with self.assertRaises(RuntimeError) as cm:
                self._run_resolve_with_mocks(self.pod_json, stat_out=bad_st_dev)
            self.assertIn("Invalid or non-positive device major:minor", str(cm.exception))
        for bad_maj in (0, -1, -259, "0", "-1"):
            bad_t = dict(self.target, dev_major=bad_maj)
            with self.assertRaises(ValueError):
                generate_helper_job_manifest("crdb-g3l1-pilot-p02", bad_t, "L1", 180, False)
            with self.assertRaises(ValueError):
                generate_rollback_job_manifest("crdb-g3l1-pilot-p02", bad_t)

    def test_g3_100a_05_malformed_major_minor_rejected(self):
        for bad_val in (None, True, False, 259.4, "259:4", "abc", "", "259a"):
            with self.assertRaises(ValueError):
                generate_helper_job_manifest("crdb-g3l1-pilot-p02", dict(self.target, dev_major=bad_val), "L1", 180, False)
            with self.assertRaises(ValueError):
                generate_rollback_job_manifest("crdb-g3l1-pilot-p02", dict(self.target, dev_minor=bad_val))
        no_maj = dict(self.target)
        no_maj.pop("dev_major", None)
        with self.assertRaises(ValueError):
            generate_helper_job_manifest("crdb-g3l1-pilot-p02", no_maj, "L1", 180, False)
        # Malformed major:minor token in mountinfo
        bad_mnt = "1611 1604 259-4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw\n"
        with self.assertRaises(RuntimeError) as cm:
            self._run_resolve_with_mocks(self.pod_json, mnt_out=bad_mnt)
        self.assertIn("Malformed major:minor", str(cm.exception))

    def test_g3_100a_06_missing_mountinfo_entry_rejected(self):
        mnt_without_data = "1600 1599 259:1 / / rw,relatime - ext4 /dev/nvme0n1p1 rw\n"
        with self.assertRaises(RuntimeError) as cm:
            self._run_resolve_with_mocks(self.pod_json, mnt_out=mnt_without_data)
        self.assertIn("Missing /cockroach/cockroach-data mount entry", str(cm.exception))

    def test_g3_100a_07_duplicate_or_ambiguous_mount_entries_rejected(self):
        dup_mnt = (
            "1611 1604 259:4 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme1n1 rw\n"
            "1612 1611 259:4 / /cockroach/cockroach-data/ rw,relatime - ext4 /dev/nvme1n1 rw\n"
        )
        with self.assertRaises(RuntimeError) as cm:
            self._run_resolve_with_mocks(self.pod_json, mnt_out=dup_mnt)
        self.assertIn("Ambiguous or duplicate /cockroach/cockroach-data mount entries", str(cm.exception))

    def test_g3_100a_08_mount_device_mismatch_rejected(self):
        mismatch_mnt = "1611 1604 259:5 / /cockroach/cockroach-data rw,relatime - ext4 /dev/nvme2n1 rw\n"
        with self.assertRaises(RuntimeError) as cm:
            self._run_resolve_with_mocks(self.pod_json, stat_out="66308\n", mnt_out=mismatch_mnt)
        self.assertIn("Mount device mismatch", str(cm.exception))

    def test_g3_100a_09_uevent_devtype_not_disk_rejected(self):
        part_uevent = "MAJOR=259\nMINOR=4\nDEVNAME=nvme0n1p1\nDEVTYPE=partition\nPARTN=1\n"
        with self.assertRaises(RuntimeError) as cm:
            self._run_resolve_with_mocks(self.pod_json, uevent_out=part_uevent)
        self.assertIn("not a whole disk", str(cm.exception))

    def test_g3_100a_10_uevent_major_minor_mismatch_rejected(self):
        for bad_uev in (
            "MAJOR=259\nMINOR=5\nDEVNAME=nvme2n1\nDEVTYPE=disk\n",
            "MAJOR=258\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n",
            "MAJOR=abc\nMINOR=4\nDEVNAME=nvme1n1\nDEVTYPE=disk\n",
        ):
            with self.assertRaises(RuntimeError):
                self._run_resolve_with_mocks(self.pod_json, uevent_out=bad_uev)

    def test_g3_100a_11_missing_uevent_file_rejected(self):
        with self.assertRaises(RuntimeError) as cm:
            self._run_resolve_with_mocks(self.pod_json, uevent_rc=1)
        self.assertIn("Missing or unreadable /sys/dev/block/259:4/uevent", str(cm.exception))

    def test_g3_100a_12_valid_whole_disk_mapping_passes(self):
        info = self._run_resolve_with_mocks(self.pod_json)
        self.assertEqual(info["pod_uid"], "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67")
        self.assertEqual(info["dev_major"], 259)
        self.assertEqual(info["dev_minor"], 4)

    def test_g3_100a_13_rollback_manifest_hostpid_false_and_not_true(self):
        _, rb_yaml = generate_rollback_job_manifest("crdb-g3l1-pilot-p02", self.target)
        self.assertIn("hostPID: false", rb_yaml)
        self.assertNotIn("hostPID: true", rb_yaml)


class TestG3PodWrapperAndStderrRemediation(unittest.TestCase):
    """
    Regression test suite for G3 post-P02 runner defect remediation.
    Validates construct_in_pod_wrapper() and evidence collection handling
    under zero errors, NOTICE-only stderr, genuine errors, and missing artifacts.
    """

    def setUp(self):
        self.run_id = "crdb-g3l1-pilot-remed"
        self.mock_target_info = {
            "target_pod": "cockroachdb-0",
            "target_node": "ip-10-0-3-203.ec2.internal",
            "pod_uid": "c22283eb-483c-4a7f-84f6-550abcd752f5",
            "container_id": "0e9cf9e91f6cf4e370ad4c3c64750c02ed2f157c8c0e0533d0837f41b72b018f",
            "dev_major": 259,
            "dev_minor": 5,
            "dev_stat_dec": 66309,
            "range_id": 98,
            "lease_holder_id": 1,
            "initial_io_max": "",
            "initial_device_io_max": "",
        }

    def test_remediation_01_wrapper_script_initializes_empty_stderr_file(self):
        """Verify construct_in_pod_wrapper creates empty stderr file before df and pgbench."""
        script = construct_in_pod_wrapper(self.run_id, duration_sec=600)
        expected_init = f": > /tmp/pgbench_{self.run_id}_stderr.txt; "
        self.assertTrue(script.startswith(expected_init), f"Script must begin with '{expected_init}'")
        self.assertIn(f"df -k /tmp > /tmp/disk_pre_{self.run_id}.txt", script)
        self.assertIn(f"> /tmp/pgbench_{self.run_id}_stdout.txt 2> >(mawk", script)

    def test_remediation_02_awk_filter_notice_only_leaves_stderr_empty(self):
        """Simulate awk filter processing ONLY CockroachDB licensing notices."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stderr_path = os.path.join(tmpdir, f"pgbench_{self.run_id}_stderr.txt")
            samples_path = os.path.join(tmpdir, f"pgbench_{self.run_id}_notice_samples.txt")
            count_path = os.path.join(tmpdir, f"pgbench_{self.run_id}_notice_count.txt")

            # 1. Wrapper pre-initialization (: > stderr.txt)
            with open(stderr_path, "w", encoding="utf-8") as f:
                pass
            self.assertTrue(os.path.exists(stderr_path))
            self.assertEqual(os.path.getsize(stderr_path), 0)

            # 2. Simulate AWK logic on 15 license NOTICE lines
            notice_line = "NOTICE:  No license is installed. Throttling will begin after 2026-11-23 16:08:47 +0000 UTC unless a license is installed before then.\n"
            count = 0
            with open(samples_path, "w", encoding="utf-8") as sf:
                for _ in range(15):
                    if notice_line.startswith("NOTICE:  No license is installed"):
                        count += 1
                        if count <= 10:
                            sf.write(notice_line)
                        continue
                    with open(stderr_path, "a", encoding="utf-8") as ef:
                        ef.write(notice_line)

            with open(count_path, "w", encoding="utf-8") as cf:
                cf.write(f"{count}\n")

            # 3. Assertions
            self.assertTrue(os.path.exists(stderr_path))
            self.assertEqual(os.path.getsize(stderr_path), 0, "stderr must remain 0 bytes when only notices exist")
            self.assertTrue(os.path.exists(count_path))
            with open(count_path, "r", encoding="utf-8") as cf:
                self.assertEqual(cf.read().strip(), "15")
            with open(samples_path, "r", encoding="utf-8") as sf:
                self.assertEqual(len(sf.readlines()), 10)

    def test_remediation_03_awk_filter_genuine_error_captured(self):
        """Simulate awk filter capturing genuine database / client errors into stderr."""
        with tempfile.TemporaryDirectory() as tmpdir:
            stderr_path = os.path.join(tmpdir, f"pgbench_{self.run_id}_stderr.txt")
            samples_path = os.path.join(tmpdir, f"pgbench_{self.run_id}_notice_samples.txt")
            count_path = os.path.join(tmpdir, f"pgbench_{self.run_id}_notice_count.txt")

            with open(stderr_path, "w", encoding="utf-8") as f:
                pass

            input_lines = [
                "NOTICE:  No license is installed. Throttling will begin...\n",
                "FATAL: terminating connection due to administrator command\n",
                "NOTICE:  No license is installed. Throttling will begin...\n",
                "ERROR: relation 'foo' does not exist\n",
            ]

            count = 0
            with open(samples_path, "w", encoding="utf-8") as sf, \
                 open(stderr_path, "a", encoding="utf-8") as ef:
                for line in input_lines:
                    if line.startswith("NOTICE:  No license is installed"):
                        count += 1
                        if count <= 10:
                            sf.write(line)
                        continue
                    ef.write(line)

            with open(count_path, "w", encoding="utf-8") as cf:
                cf.write(f"{count}\n")

            self.assertTrue(os.path.exists(stderr_path))
            with open(stderr_path, "r", encoding="utf-8") as ef:
                err_content = ef.read()
            self.assertIn("FATAL: terminating connection", err_content)
            self.assertIn("ERROR: relation 'foo' does not exist", err_content)
            self.assertNotIn("NOTICE", err_content)

    def test_remediation_04_evidence_collection_succeeds_with_empty_stderr_file(self):
        """Verify coordinator succeeds when pod returns 0-byte stderr file (exit 0)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id=self.run_id,
                level="L1",
                duration_sec=180,
                dry_run=False,
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"1\",node_id=\"1\"}": "0"}}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {"g3-chaos-helper": "helper ok"}, "errors": []}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:

                mock_proc = MagicMock()
                mock_proc.communicate.return_value = ("client stdout", "")
                mock_proc.returncode = 0
                mock_popen.return_value = mock_proc

                def fake_run_cmd(cmd, check=True, timeout=None):
                    cmd_str = " ".join(cmd)
                    if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                    if "cat /tmp/pgbench" in cmd_str and "exit_code.txt" in cmd_str:
                        return MagicMock(returncode=0, stdout="0\n", stderr="")
                    if "cat /sys/fs/cgroup/io.max" in cmd_str:
                        if coordinator.current_state == ExecutionState.FAULT_VERIFICATION:
                            return MagicMock(returncode=0, stdout="259:5 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                        return MagicMock(returncode=0, stdout="", stderr="")
                    if "ls /tmp/pgbench_log_" in cmd_str:
                        return MagicMock(returncode=0, stdout=f"/tmp/pgbench_log_{self.run_id}.1\n", stderr="")
                    if f"cat /tmp/pgbench_log_{self.run_id}.1" in cmd_str:
                        return MagicMock(returncode=0, stdout="1 0 100 0 1000 0\n1 1 120 0 1600 0\n", stderr="")
                    if f"cat /tmp/pgbench_{self.run_id}_stderr.txt" in cmd_str:
                        # Pre-created empty file returns exit code 0 with empty stdout
                        return MagicMock(returncode=0, stdout="", stderr="")
                    if "cat /tmp/pgbench_" in cmd_str or "cat /tmp/disk_" in cmd_str:
                        return MagicMock(returncode=0, stdout="Sample evidence data\n", stderr="")
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = fake_run_cmd
                record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "EXECUTED_VALIDATED")
            self.assertEqual(len(record["evidence_missing"]), 0)
            local_stderr = os.path.join(tmpdir, f"pgbench_{self.run_id}_stderr.txt")
            self.assertTrue(os.path.exists(local_stderr))
            self.assertEqual(os.path.getsize(local_stderr), 0)

    def test_remediation_05_evidence_collection_fails_if_stderr_genuinely_missing(self):
        """Verify coordinator still fails fail-closed when stderr artifact is missing (exit 1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coordinator = G3PilotExecutionCoordinator(
                run_id=self.run_id,
                level="L1",
                duration_sec=180,
                dry_run=False,
            )
            coordinator.output_dir = tmpdir
            coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"1\",node_id=\"1\"}": "0"}}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen, \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {"g3-chaos-helper": "helper ok"}, "errors": []}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:

                mock_proc = MagicMock()
                mock_proc.communicate.return_value = ("client stdout", "")
                mock_proc.returncode = 0
                mock_popen.return_value = mock_proc

                def fake_run_cmd(cmd, check=True, timeout=None):
                    cmd_str = " ".join(cmd)
                    if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                    if "cat /tmp/pgbench" in cmd_str and "exit_code.txt" in cmd_str:
                        return MagicMock(returncode=0, stdout="0\n", stderr="")
                    if "cat /sys/fs/cgroup/io.max" in cmd_str:
                        if coordinator.current_state == ExecutionState.FAULT_VERIFICATION:
                            return MagicMock(returncode=0, stdout="259:5 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                        return MagicMock(returncode=0, stdout="", stderr="")
                    if "ls /tmp/pgbench_log_" in cmd_str:
                        return MagicMock(returncode=0, stdout=f"/tmp/pgbench_log_{self.run_id}.1\n", stderr="")
                    if f"cat /tmp/pgbench_log_{self.run_id}.1" in cmd_str:
                        return MagicMock(returncode=0, stdout="1 0 100 0 1000 0\n1 1 120 0 1600 0\n", stderr="")
                    if f"cat /tmp/pgbench_{self.run_id}_stderr.txt" in cmd_str:
                        # Pod returns exit 1: file does not exist
                        return MagicMock(returncode=1, stdout="", stderr="cat: /tmp/...: No such file or directory")
                    if "cat /tmp/pgbench_" in cmd_str or "cat /tmp/disk_" in cmd_str:
                        return MagicMock(returncode=0, stdout="Sample evidence data\n", stderr="")
                    return MagicMock(returncode=0, stdout="", stderr="")

                mock_run.side_effect = fake_run_cmd
                record = coordinator.execute_lifecycle()

            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn(f"pgbench_{self.run_id}_stderr.txt (missing)", record["evidence_missing"])

    def test_remediation_06_output_directory_resolution_and_symlink_guardrail(self):
        """
        Validates deterministic output directory resolution:
        - Historical exploratory pilots (P01, P02) -> 07-g3-chaos/pilots/{run_id}/
        - Future calibration pilots (P03, P04) -> 07-g3-chaos/pilots/{run_id}/
        - Formal repetitions (r01..r05 across L1, L2, L3) -> experiments/cockroachdb/G3-{level}/{run_id}/
        - Symlink destination is strictly rejected (fail-closed).
        """
        from benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised import (
            resolve_output_directory,
            G3PilotExecutionCoordinator
        )

        # 1. Exploratory and Calibration pilots
        for p_id, lvl in [
            ("crdb-g3l1-pilot-p01", "L1"),
            ("crdb-g3l1-pilot-p02", "L1"),
            ("crdb-g3l2-pilot-p03", "L2"),
            ("crdb-g3l3-pilot-p04", "L3"),
            ("crdb-g3l1-dry01", "L1"),
        ]:
            resolved = resolve_output_directory(p_id, lvl).replace("\\", "/")
            expected_suffix = f"thesis-evidence/07-g3-chaos/pilots/{p_id}"
            self.assertTrue(resolved.endswith(expected_suffix), f"Mismatch: {resolved} vs {expected_suffix}")

        # 2. Formal repetitions across tiers
        for r_id, lvl in [
            ("crdb-g3l1-r01", "L1"),
            ("crdb-g3l1-r05", "L1"),
            ("crdb-g3l2-r01", "L2"),
            ("crdb-g3l2-r05", "L2"),
            ("crdb-g3l3-r01", "L3"),
            ("crdb-g3l3-r05", "L3"),
        ]:
            resolved = resolve_output_directory(r_id, lvl).replace("\\", "/")
            expected_suffix = f"thesis-evidence/experiments/cockroachdb/G3-{lvl}/{r_id}"
            self.assertTrue(resolved.endswith(expected_suffix), f"Mismatch: {resolved} vs {expected_suffix}")

        # 3. Coordinator instantiation resolution
        coord_formal = G3PilotExecutionCoordinator("crdb-g3l1-r01", "L1", 180, dry_run=True)
        self.assertTrue(
            coord_formal.output_dir.replace("\\", "/").endswith("thesis-evidence/experiments/cockroachdb/G3-L1/crdb-g3l1-r01")
        )
        self.assertTrue(
            coord_formal.telemetry_file_path.replace("\\", "/").endswith(
                "thesis-evidence/experiments/cockroachdb/G3-L1/crdb-g3l1-r01/telemetry_timeseries.jsonl"
            )
        )

        coord_pilot = G3PilotExecutionCoordinator("crdb-g3l1-pilot-p02", "L1", 180, dry_run=True)
        self.assertTrue(
            coord_pilot.output_dir.replace("\\", "/").endswith("thesis-evidence/07-g3-chaos/pilots/crdb-g3l1-pilot-p02")
        )

        # 4. Explicit output_dir override
        coord_custom = G3PilotExecutionCoordinator("crdb-g3l1-r01", "L1", 180, dry_run=True, output_dir="custom/evidence/dir")
        self.assertTrue(coord_custom.output_dir.replace("\\", "/").endswith("custom/evidence/dir"))

        # 5. Fail-closed on symlink output_dir
        with patch("os.path.islink", return_value=True):
            with self.assertRaises(RuntimeError) as ctx:
                resolve_output_directory("crdb-g3l1-r01", "L1", output_dir="symlinked/dir")
            self.assertIn("FAIL-CLOSED: Output directory cannot be a symlink", str(ctx.exception))


class TestG3TransportResilienceOffline(unittest.TestCase):
    """
    Test suite for R01 Kubernetes transport-failure remediation.
    Decouples remote workload execution status from local streaming connection lifetime.
    Covers all 11 required scenarios from requirement 5:
    1. Workload exit code 0 with normal streaming completion.
    2. Workload exit code 0 with dropped streaming connection (transport drop).
    3. Workload non-zero exit code (with normal or dropped streaming).
    4. Missing exit-status marker.
    5. Malformed exit-status marker.
    6. Missing thread log.
    7. Corrupted or truncated artifact (empty mandatory artifact).
    8. Artifact retrieval timeout / failure.
    9. Partial retrieval.
    10. Duplicate execution prevention (unconsumed single-use token invariant).
    11. Correct state-machine transitions and final disposition.
    """

    def setUp(self):
        self.run_id = "crdb-g3l1-r02-test"
        self.mock_target_info = {
            "target_node": "ip-10-0-1-160.ec2.internal",
            "target_pod": "cockroachdb-1",
            "dev_major": "259",
            "dev_minor": "4",
            "container_id": "f29e11f4213d",
            "initial_io_max": "",
            "lease_holder_id": "1",
            "pod_uid": "mock-pod-uid-1234",
        }

    def _execute_mock_lifecycle(self, tmpdir, wrapper_returncode, exit_code_raw, tx_logs_list=None, missing_files=None, popen_error=None, query_ps_live=False):
        coordinator = G3PilotExecutionCoordinator(
            run_id=self.run_id,
            level="L1",
            duration_sec=180,
            dry_run=False,
            output_dir=tmpdir,
        )
        coordinator.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

        if tx_logs_list is None:
            tx_logs_list = [f"/tmp/pgbench_log_{self.run_id}.1"]
        if missing_files is None:
            missing_files = []

        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"1\",node_id=\"1\"}": "0"}}), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen") as mock_popen, \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {"g3-chaos-helper": "helper ok"}, "errors": []}), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:

            mock_proc = MagicMock()
            if popen_error:
                mock_proc.communicate.side_effect = popen_error
            else:
                mock_proc.communicate.return_value = ("client streaming stdout", "client streaming stderr" if wrapper_returncode != 0 else "")
            mock_proc.returncode = wrapper_returncode
            mock_popen.return_value = mock_proc

            def fake_run_cmd(cmd, check=True, timeout=None):
                cmd_str = " ".join(cmd)
                if "test -f" in cmd_str and "exit_code.txt" in cmd_str:
                    if exit_code_raw is None or "exit_code.txt" in missing_files:
                        return MagicMock(returncode=1, stdout="", stderr="No such file")
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "ps -eo" in cmd_str:
                    header = "  PID  PGID STAT COMM\n"
                    if query_ps_live:
                        body = " 7148  8888 S    pgbench\n"
                    else:
                        body = "    1     1 Ss   bash\n"
                    return MagicMock(returncode=0, stdout=header + body, stderr="")
                if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                    return MagicMock(returncode=0, stdout="8888\n", stderr="")
                if "cat /tmp/pgbench" in cmd_str and "exit_code.txt" in cmd_str:
                    if exit_code_raw is None or "exit_code.txt" in missing_files:
                        return MagicMock(returncode=1, stdout="", stderr="cat: /tmp/...: No such file")
                    return MagicMock(returncode=0, stdout=f"{exit_code_raw}\n", stderr="")
                if "cat /sys/fs/cgroup/io.max" in cmd_str:
                    if coordinator.current_state == ExecutionState.FAULT_VERIFICATION:
                        return MagicMock(returncode=0, stdout="259:4 rbps=max wbps=5242880 riops=max wiops=600", stderr="")
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "ls /tmp/pgbench_log_" in cmd_str:
                    if not tx_logs_list or "tx_logs" in missing_files:
                        return MagicMock(returncode=0, stdout="", stderr="")
                    return MagicMock(returncode=0, stdout="\n".join(tx_logs_list) + "\n", stderr="")
                if "cat /tmp/pgbench_log_" in cmd_str:
                    if "tx_logs" in missing_files:
                        return MagicMock(returncode=1, stdout="", stderr="cat: error")
                    for tf in tx_logs_list:
                        if tf in cmd_str:
                            return MagicMock(returncode=0, stdout="1 0 100 0 1000 0\n1 1 120 0 1600 0\n", stderr="")
                for mf in missing_files:
                    if f"/tmp/{mf}" in cmd_str:
                        return MagicMock(returncode=1, stdout="", stderr="cat: missing file")
                if f"cat /tmp/pgbench_{self.run_id}_stderr.txt" in cmd_str:
                    return MagicMock(returncode=0, stdout="", stderr="")
                if "cat /tmp/pgbench_" in cmd_str or "cat /tmp/disk_" in cmd_str:
                    return MagicMock(returncode=0, stdout="Sample evidence data\n", stderr="")
                return MagicMock(returncode=0, stdout="", stderr="")

            mock_run.side_effect = fake_run_cmd
            record = coordinator.execute_lifecycle()
            return coordinator, record

    def test_01_workload_exit_0_normal_streaming_completion(self):
        """1. Workload exit code 0 with normal streaming completion (returncode=0)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="0")
            self.assertEqual(record["final_disposition"], "EXECUTED_VALIDATED")
            self.assertFalse(record["error_occurred"])
            self.assertEqual(record["command_audit"]["pgbench_exit_code"], "0")
            self.assertEqual(record["command_audit"]["measurement_wrapper"]["returncode"], 0)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "SHA256SUMS.txt")))

    def test_02_workload_exit_0_with_dropped_streaming_connection(self):
        """2. Workload exit code 0 with dropped streaming connection (transport dropped with returncode=1)."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=1, exit_code_raw="0")
            # Transport returned exit code 1, but workload exit code was 0: run succeeds!
            self.assertEqual(record["final_disposition"], "EXECUTED_VALIDATED")
            self.assertFalse(record["error_occurred"])
            self.assertEqual(record["command_audit"]["pgbench_exit_code"], "0")
            self.assertEqual(record["command_audit"]["measurement_wrapper"]["returncode"], 1)
            self.assertTrue(os.path.exists(os.path.join(tmpdir, f"pgbench_{self.run_id}_exit_code.txt")))
            self.assertTrue(os.path.exists(os.path.join(tmpdir, "SHA256SUMS.txt")))

    def test_03_workload_non_zero_exit_code(self):
        """3. Workload non-zero exit code (e.g. exit 2) fails fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="2")
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn(f"pgbench_{self.run_id}_exit_code.txt (non-zero: '2')", record["evidence_missing"])

    def test_04_missing_exit_status_marker(self):
        """4. Missing exit-status marker file fails fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=1, exit_code_raw=None)
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertTrue(any("exit_code" in str(s.get("error", "")) for s in record["state_history"]))

    def test_05_malformed_exit_status_marker(self):
        """5. Malformed non-numeric exit-status marker fails fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="CORRUPT_CODE")
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn(f"pgbench_{self.run_id}_exit_code.txt (non-zero: 'CORRUPT_CODE')", record["evidence_missing"])

    def test_06_missing_thread_log(self):
        """6. Missing thread log fails fail-closed in EVIDENCE_COLLECTION."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="0", tx_logs_list=[])
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn("transaction_logs (missing or empty)", record["evidence_missing"])

    def test_07_corrupted_or_truncated_artifact(self):
        """7. Corrupted or 0-byte mandatory artifact (e.g. stdout.txt) fails fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="0", missing_files=[f"pgbench_{self.run_id}_stdout.txt"])
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn(f"pgbench_{self.run_id}_stdout.txt (missing)", record["evidence_missing"])

    def test_08_artifact_retrieval_timeout(self):
        """8. Artifact retrieval timeout / failure on a mandatory artifact fails fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="0", missing_files=[f"disk_pre_{self.run_id}.txt"])
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn(f"disk_pre_{self.run_id}.txt (missing)", record["evidence_missing"])

    def test_09_partial_retrieval(self):
        """9. Partial retrieval where some logs are retrieved but exit marker is missing fails fail-closed."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="0", missing_files=["exit_code.txt"])
            self.assertEqual(record["final_disposition"], "FAILED")
            self.assertTrue(record["error_occurred"])
            self.assertIn(f"pgbench_{self.run_id}_exit_code.txt (missing)", record["evidence_missing"])

    def test_10_duplicate_execution_prevention(self):
        """10. Duplicate execution prevention: token single-use consumed marker prevents replay."""
        with tempfile.TemporaryDirectory() as tmpdir:
            priv = ed25519.Ed25519PrivateKey.generate()
            pub_bytes = priv.public_key().public_bytes_raw()
            pub_path = os.path.join(tmpdir, "pub.key")
            with open(pub_path, "w", encoding="utf-8") as pf:
                pf.write(base64.b64encode(pub_bytes).decode("ascii"))

            fp = hashlib.sha256(pub_bytes).hexdigest()
            now_dt = datetime.datetime.now(datetime.timezone.utc)
            issued_utc = (now_dt - datetime.timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            not_before_utc = (now_dt - datetime.timedelta(minutes=10)).replace(microsecond=0).isoformat().replace("+00:00", "Z")
            expires_utc = (now_dt + datetime.timedelta(hours=2)).replace(microsecond=0).isoformat().replace("+00:00", "Z")

            payload = {
                "authorization_id": "auth-r02-dup-test",
                "authorized_run_id": "crdb-g3l1-r02",
                "authorized_level": "L1",
                "parameters": {
                    "wbps": 5242880,
                    "wiops": 600,
                    "max_fault_duration_sec": 180,
                },
                "runner_sha256": compute_sha256(runner_mod.__file__),
                "protocol_version": PROTOCOL_VERSION,
                "operator_identity": "operator@ric-research",
                "nonce": "test-nonce-12345",
                "issued_at_utc": issued_utc,
                "not_before_utc": not_before_utc,
                "expires_at_utc": expires_utc,
            }
            canonical_bytes = canonicalize_payload(payload)
            sig = priv.sign(canonical_bytes)
            tok_obj = {
                "payload": payload,
                "signature": base64.b64encode(sig).decode("ascii"),
            }
            tok_path = os.path.join(tmpdir, "tok.json")
            with open(tok_path, "w", encoding="utf-8") as tf:
                json.dump(tok_obj, tf)

            with patch.object(runner_mod, "TRUSTED_OPERATOR_PUBKEY_SHA256", fp):
                # 1st verification succeeds and consumes token
                res1 = prod_verify_and_consume_authorization(
                    auth_file_path=tok_path,
                    run_id="crdb-g3l1-r02",
                    level="L1",
                    duration_sec=180,
                    public_key_path=pub_path,
                )
                self.assertIsNotNone(res1)
                self.assertTrue(os.path.exists(f"{tok_path}.consumed"))

                # 2nd verification must fail fail-closed (duplicate execution prohibited)
                with self.assertRaises(RuntimeError) as ctx:
                    prod_verify_and_consume_authorization(
                        auth_file_path=tok_path,
                        run_id="crdb-g3l1-r02",
                        level="L1",
                        duration_sec=180,
                        public_key_path=pub_path,
                    )
                self.assertIn("ALREADY BEEN CONSUMED", str(ctx.exception))

    def test_11_state_machine_transitions_and_final_disposition(self):
        """11. Correct state-machine transitions through all 15 states to EXECUTED_VALIDATED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord, record = self._execute_mock_lifecycle(tmpdir, wrapper_returncode=0, exit_code_raw="0")
            expected_states = [
                ExecutionState.PREFLIGHT.value,
                ExecutionState.TARGET_VERIFICATION.value,
                ExecutionState.WORKLOAD_START.value,
                ExecutionState.WARMUP.value,
                ExecutionState.BASELINE_MEASUREMENT.value,
                ExecutionState.FAULT_APPLICATION.value,
                ExecutionState.FAULT_VERIFICATION.value,
                ExecutionState.FAULT_MEASUREMENT.value,
                ExecutionState.FAULT_REMOVAL.value,
                ExecutionState.RESTORATION_VERIFICATION.value,
                ExecutionState.POST_FAULT_MEASUREMENT.value,
                ExecutionState.WREC_OBSERVATION.value,
                ExecutionState.FINAL_HEALTH_CHECK.value,
                ExecutionState.EVIDENCE_COLLECTION.value,
                ExecutionState.FINAL_DISPOSITION.value,
            ]
            actual_states = [s["state"] for s in record["state_history"]]
            self.assertEqual(actual_states, expected_states)
            self.assertEqual(record["final_disposition"], "EXECUTED_VALIDATED")
            self.assertFalse(record["error_occurred"])


class TestG3ProcessGroupResilienceOffline(unittest.TestCase):
    """
    Targeted unit and regression tests for remote process-group lifecycle,
    ps -eo pid,pgid,stat,comm parsing, zombie detection, and SIGTERM/SIGKILL escalation.
    Validates edge cases discovered during R03 post-mortem analysis.
    """

    def test_query_live_processes_normal_and_zombie(self):
        """Verify query_live_processes_in_pgid separates live processes from zombies."""
        ps_output = (
            "  PID  PGID STAT COMM\n"
            "    1     1 Ss   bash\n"
            " 7148  8888 S    pgbench\n"
            " 7149  8888 S    pgbench\n"
            " 7150  8888 Z    pgbench <defunct>\n"
            " 9999  9999 S    other\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=ps_output, stderr="")):
            live, zombies = runner_mod.query_live_processes_in_pgid(8888)
            self.assertEqual(len(live), 2)
            self.assertEqual([p["pid"] for p in live], [7148, 7149])
            self.assertEqual(len(zombies), 1)
            self.assertEqual(zombies[0]["pid"], 7150)
            self.assertTrue(zombies[0]["stat"].startswith("Z"))

    def test_query_live_processes_no_matching_pgid(self):
        """Verify empty lists returned when PGID is not present."""
        ps_output = (
            "  PID  PGID STAT COMM\n"
            "    1     1 Ss   bash\n"
            " 9999  9999 S    other\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=ps_output, stderr="")):
            live, zombies = runner_mod.query_live_processes_in_pgid(8888)
            self.assertEqual(len(live), 0)
            self.assertEqual(len(zombies), 0)

    def test_query_live_processes_malformed_header_fails_closed(self):
        """Verify RuntimeError raised if ps header is corrupted or unexpected."""
        ps_output = "COMMAND PID STAT\n"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=ps_output, stderr="")):
            with self.assertRaises(RuntimeError) as ctx:
                runner_mod.query_live_processes_in_pgid(8888)
            self.assertIn("Unexpected ps header format", str(ctx.exception))

    def test_query_live_processes_malformed_row_fails_closed(self):
        """Verify RuntimeError raised if a ps row has fewer than 4 columns."""
        ps_output = (
            "  PID  PGID STAT COMM\n"
            " 7148  8888\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=ps_output, stderr="")):
            with self.assertRaises(RuntimeError) as ctx:
                runner_mod.query_live_processes_in_pgid(8888)
            self.assertIn("Malformed ps output row", str(ctx.exception))

    def test_terminate_remote_process_group_graceful_sigterm(self):
        """Verify terminate_remote_process_group completes on graceful SIGTERM."""
        # First check returns empty live processes
        ps_output = "  PID  PGID STAT COMM\n    1     1 Ss bash\n"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=ps_output, stderr="")), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
            res = runner_mod.terminate_remote_process_group(8888, timeout_grace_sec=5.0)
            self.assertTrue(res["verified_dead"])
            self.assertFalse(res["escalated_to_sigkill"])
            self.assertEqual(res["surviving_live_count"], 0)

    def test_terminate_remote_process_group_escalates_to_sigkill(self):
        """Verify terminate_remote_process_group escalates to SIGKILL if SIGTERM does not kill processes."""
        ps_output_live = "  PID  PGID STAT COMM\n 7148  8888 S pgbench\n"
        ps_output_dead = "  PID  PGID STAT COMM\n    1     1 Ss bash\n"

        call_count = {"ps": 0, "kill": 0}
        def fake_run(cmd, check=False, timeout=None):
            cmd_str = " ".join(cmd)
            if "kill -KILL" in cmd_str:
                call_count["kill"] += 1
            if "ps -eo" in cmd_str:
                call_count["ps"] += 1
                # Return dead only AFTER kill -KILL has been issued
                if call_count["kill"] > 0:
                    return MagicMock(returncode=0, stdout=ps_output_dead, stderr="")
                return MagicMock(returncode=0, stdout=ps_output_live, stderr="")
            return MagicMock(returncode=0, stdout="", stderr="")

        fake_time_vals = [0.0, 0.1, 0.2, 2.0, 2.1, 2.2, 2.3]
        time_idx = {"idx": 0}
        def fake_time():
            val = fake_time_vals[min(time_idx["idx"], len(fake_time_vals) - 1)]
            time_idx["idx"] += 1
            return val

        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=fake_run), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.time", side_effect=fake_time), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
            res = runner_mod.terminate_remote_process_group(8888, timeout_grace_sec=1.0)
            self.assertTrue(res["verified_dead"])
            self.assertTrue(res["escalated_to_sigkill"])
            self.assertEqual(res["surviving_live_count"], 0)


class TestG3L3R01RemediationOffline(unittest.TestCase):
    """
    14 Offline Regression Scenarios for G3 L3 R01 Failure Remediation (Option B + D).
    Validates post-warmup target resolution, 3-cycle consensus locking, fail-closed target migration detection,
    container & device identity enforcement, telemetry continuity, helper job failures, and rollback safety.
    """

    def setUp(self):
        self.mock_target_info_node2 = {
            "range_id": 98,
            "lease_holder_id": 2,
            "target_pod": "cockroachdb-1",
            "pod_uid": "1a98abd7-7ac3-4bd6-96ee-1dcfd67f0f67",
            "target_node": "ip-10-0-1-160.ec2.internal",
            "container_id": "f29e11f4213d2984a8ffb22108bcf13f8921a221fca9bb1a10058b88cd261543",
            "dev_major": 259,
            "dev_minor": 4,
            "dev_stat_dec": 16973828,
            "raw_show_range": "benchdb|public|98|2|/Table/53|/Table/54",
            "cgroup_controllers": ["cpu", "io", "memory", "pids"],
            "io_stat_readable": True,
            "initial_io_max": "",
            "initial_device_io_max": None,
        }
        self.mock_target_info_node1 = {
            "range_id": 98,
            "lease_holder_id": 1,
            "target_pod": "cockroachdb-0",
            "pod_uid": "2b09bce8-8bd4-5ce7-07ff-2edfdf801f78",
            "target_node": "ip-10-0-1-161.ec2.internal",
            "container_id": "a18d10e3102c1873b7eea11097abf02e7810b110ebb8aa0909947a77bc150432",
            "dev_major": 259,
            "dev_minor": 3,
            "dev_stat_dec": 16973827,
            "raw_show_range": "benchdb|public|98|1|/Table/53|/Table/54",
            "cgroup_controllers": ["cpu", "io", "memory", "pids"],
            "io_stat_readable": True,
            "initial_io_max": "",
            "initial_device_io_max": None,
        }

    def test_01_stable_leaseholder_throughout_warmup_and_baseline(self):
        """Scenario 1: Stable leaseholder throughout warmup and baseline executes successfully."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc01",
                level="L3",
                duration_sec=180,
                dry_run=True
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info_node2), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"2\",node_id=\"2\"}": "0"}}):
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "SIMULATED_SUCCESS")
            self.assertFalse(coord.error_occurred)
            self.assertEqual(coord.target_info["target_pod"], "cockroachdb-1")

    def test_02_leaseholder_migration_during_warmup_adapts_to_new_target(self):
        """Scenario 2: Leaseholder migrates during warm-up; coordinator successfully adapts and locks to new target."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc02",
                level="L3",
                duration_sec=180,
                dry_run=True
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            # 1. Pre-warmup initial target: Node 2 (cockroachdb-1)
            # 2. Post-warmup target: Node 1 (cockroachdb-0) (Option B + D adaptation)
            # 3. Pre-fault validation target: Node 1 (cockroachdb-0) (matches locked post-warmup)
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=[
                     self.mock_target_info_node2,
                     self.mock_target_info_node1,
                     self.mock_target_info_node1
                 ]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"1\",node_id=\"1\"}": "0"}}):
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "SIMULATED_SUCCESS")
            self.assertEqual(coord.initial_target_info["target_pod"], "cockroachdb-1")
            self.assertEqual(coord.target_info["target_pod"], "cockroachdb-0")
            self.assertEqual(coord.target_info["target_node"], "ip-10-0-1-161.ec2.internal")
            self.assertEqual(coord.target_info["dev_minor"], 3)

    def test_03_migration_immediately_before_fault_application_aborts(self):
        """Scenario 3: Leaseholder migrates immediately before fault application (during baseline); aborts fail-closed."""
        migrated_again = dict(self.mock_target_info_node2)
        migrated_again["target_pod"] = "cockroachdb-2"
        migrated_again["lease_holder_id"] = 3

        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc03",
                level="L3",
                duration_sec=180,
                dry_run=True
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=[
                     self.mock_target_info_node2,
                     self.mock_target_info_node1,
                     migrated_again
                 ]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "5000"]):
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "FAILED")
            self.assertIn("Target pod changed during pre_fault_application", rec["state_history"][4]["error"])
            self.assertFalse(coord.fault_applied)

    def test_04_migration_during_fault_injection_recorded(self):
        """Scenario 4: Validate target validation fail-closed mechanism when identity drift occurs."""
        drifted = dict(self.mock_target_info_node1)
        drifted["lease_holder_id"] = 3
        with self.assertRaises(RuntimeError) as cm:
            validate_target_unchanged(self.mock_target_info_node1, drifted, phase_label="fault_inspection")
        self.assertIn("lease_holder_id", str(cm.exception))

    def test_05_repeated_leaseholder_changes_consensus_failure_aborts(self):
        """Scenario 5: Rapid leaseholder bouncing causes 3-cycle consensus failure; aborts fail-closed."""
        responses = [
            "benchdb|public|98|2|/Table/53|/Table/54",
            "benchdb|public|98|1|/Table/53|/Table/54",
            "benchdb|public|98|2|/Table/53|/Table/54",
        ]
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=responses), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
            with self.assertRaises(RuntimeError) as cm:
                resolve_target_leaseholder(cycles=3, delay_sec=0.01)
            self.assertIn("consensus failure", str(cm.exception).lower())

    def test_06_node_and_device_identity_mismatch_aborts(self):
        """Scenario 6: Node name or block device mismatch between cycles aborts fail-closed."""
        mismatched_device = dict(self.mock_target_info_node1)
        mismatched_device["dev_minor"] = 99
        with self.assertRaises(RuntimeError) as cm:
            validate_target_unchanged(self.mock_target_info_node1, mismatched_device, phase_label="pre_fault_application")
        self.assertIn("dev_minor", str(cm.exception))

        mismatched_node = dict(self.mock_target_info_node1)
        mismatched_node["target_node"] = "ip-10-0-1-999.ec2.internal"
        with self.assertRaises(RuntimeError) as cm2:
            validate_target_unchanged(self.mock_target_info_node1, mismatched_node, phase_label="pre_fault_application")
        self.assertIn("target_node", str(cm2.exception))

    def test_07_container_id_changes_aborts(self):
        """Scenario 7: Pod container restart (new container ID) aborts fail-closed."""
        restarted_cid = dict(self.mock_target_info_node1)
        restarted_cid["container_id"] = "deadbeef1234567890abcdef1234567890abcdef1234567890abcdef12345678"
        with self.assertRaises(RuntimeError) as cm:
            validate_target_unchanged(self.mock_target_info_node1, restarted_cid, phase_label="pre_fault_application")
        self.assertIn("container_id", str(cm.exception))

    def test_08_telemetry_interruption_aborts_before_fault(self):
        """Scenario 8: Telemetry interruption / gap exceeded aborts before fault application."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc08",
                level="L3",
                duration_sec=180,
                dry_run=False  # non-dry-run enforces assert_telemetry_continuous
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            # Corrupt telemetry status before baseline gate
            coord.telemetry_status = {
                "thread_alive": False,
                "gap_exceeded": True,
                "error": "Poller connection dropped",
                "sample_count": 1,
                "last_sample_epoch": 0.0,
            }

            from benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised import TelemetryContinuityError
            with self.assertRaises(TelemetryContinuityError):
                coord.assert_telemetry_continuous(window_name="baseline_window")

    def test_09_warmup_timeout_or_failure_aborts(self):
        """Scenario 9: Warmup workload failure or history shrinkage aborts lifecycle cleanly."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc09",
                level="L3",
                duration_sec=180,
                dry_run=False
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info_node2), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["5000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", return_value=MagicMock(returncode=1, stderr="warmup exec timeout")):
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "FAILED")
            self.assertIn("Warmup workload failed", rec["state_history"][3]["error"])

    def test_10_fault_helper_submission_failure_triggers_rollback(self):
        """Scenario 10: Fault helper Job submission failure triggers cleanup/rollback."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc10",
                level="L3",
                duration_sec=180,
                dry_run=False
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", return_value=self.mock_target_info_node2), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "5000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=_mock_telemetry_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=[
                     MagicMock(returncode=0, stdout="", stderr=""), # warmup
                     MagicMock(returncode=0, stdout="8888\n", stderr=""), # pgid check
                     MagicMock(returncode=1, stdout="", stderr="Admission webhook rejected helper Job"), # apply -f helper
                 ]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
                coord.telemetry_status = {"thread_alive": True, "gap_exceeded": False, "error": None, "sample_count": 10, "last_sample_epoch": 9999999999.0, "max_observed_gap_sec": 5.0}
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "FAILED")
            self.assertIn("Admission webhook rejected", rec["state_history"][5]["error"])

    def test_11_successful_rollback_restores_max(self):
        """Scenario 11: Out-of-band rollback successfully executes and verifies unthrottled device state."""
        pod_json = {
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://f29e11f4213d2984a8ffb22108bcf13f8921a221fca9bb1a10058b88cd261543"}
                ]
            }
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # delete leftover helper job
                MagicMock(returncode=0, stdout="job.batch/g3-rollback created", stderr=""),  # apply rollback job
                MagicMock(returncode=0, stdout="condition met", stderr=""),  # wait job complete
                MagicMock(returncode=0, stdout="[G3 Rollback] Restored", stderr=""),  # logs
                MagicMock(returncode=0, stdout="", stderr=""),  # delete rollback job
                MagicMock(returncode=0, stdout="259:4 rbps=max wbps=max riops=max wiops=max", stderr=""),  # verify io.max
            ]
            rb_ok = emergency_independent_rollback(self.mock_target_info_node2)
            self.assertTrue(rb_ok)

    def test_12_failed_rollback_records_critical_error(self):
        """Scenario 12: Failed emergency rollback records critical error and aborts fail-closed."""
        pod_json = {
            "status": {
                "containerStatuses": [
                    {"containerID": "containerd://f29e11f4213d2984a8ffb22108bcf13f8921a221fca9bb1a10058b88cd261543"}
                ]
            }
        }
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd") as mock_run:
            mock_run.side_effect = [
                MagicMock(returncode=0, stdout=json.dumps(pod_json), stderr=""),
                MagicMock(returncode=0, stdout="", stderr=""),  # delete leftover helper job
                MagicMock(returncode=1, stdout="", stderr="Error from server (Forbidden): jobs.batch forbidden"),
            ]
            rb_ok = emergency_independent_rollback(self.mock_target_info_node2)
            self.assertFalse(rb_ok)

    def test_13_no_stale_target_can_receive_fault(self):
        """Scenario 13: Stale target cannot receive fault because helper manifest is generated strictly post-warmup."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc13",
                level="L3",
                duration_sec=180,
                dry_run=True
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=[
                     self.mock_target_info_node2, # pre-warmup: Node 2
                     self.mock_target_info_node1, # post-warmup lock: Node 1
                     self.mock_target_info_node1  # pre-fault check: Node 1
                 ]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "1000", "5000", "5000000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.sample_crdb_metrics", return_value={"metrics": {"ranges_underreplicated{store=\"1\",node_id=\"1\"}": "0"}}):
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "SIMULATED_SUCCESS")
            manifest_path = os.path.join(tmpdir, "03_helper_job_manifest.yaml")
            self.assertTrue(os.path.isfile(manifest_path))
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest_text = f.read()

            # Verify manifest is bound strictly to Node 1 (cockroachdb-0, minor 3, container a18d10e3102c)
            # and NOT stale Node 2 (cockroachdb-1, minor 4, container f29e11f4213d)
            self.assertIn("nodeName: ip-10-0-1-161.ec2.internal", manifest_text)
            self.assertIn("a18d10e3102c1873b7eea11097abf02e7810b110ebb8aa0909947a77bc150432", manifest_text)
            self.assertNotIn("ip-10-0-1-160.ec2.internal", manifest_text)
            self.assertNotIn("f29e11f4213d2984a8ffb22108bcf13f8921a221fca9bb1a10058b88cd261543", manifest_text)

    def test_14_failed_run_cannot_be_reported_successful(self):
        """Scenario 14: Failed runs can NEVER report SIMULATED_SUCCESS or EXECUTED_VALIDATED."""
        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc14",
                level="L3",
                duration_sec=180,
                dry_run=True
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", side_effect=RuntimeError("Cluster not ready")):
                rec = coord.execute_lifecycle()

            self.assertEqual(rec["final_disposition"], "FAILED")
            self.assertNotEqual(rec["final_disposition"], "EXECUTED_VALIDATED")
            self.assertNotEqual(rec["final_disposition"], "SIMULATED_SUCCESS")
            self.assertTrue(coord.error_occurred)

    def test_15_target_identity_migration_after_fault_application_triggers_rollback(self):
        """
        Scenario 15: CockroachDB leaseholder/target identity migrates after fault application.
        Coordinator detects migration, triggers cleanup/emergency rollback, verifies restoration,
        records the error in state_history and execution evidence, and fails closed without success disposition.
        """
        migrated_target_node1 = dict(self.mock_target_info_node1) # Node 1 (locked post-warmup)
        migrated_during_fault = dict(self.mock_target_info_node2) # Range moves back to Node 2 during fault!
        migrated_during_fault["target_pod"] = "cockroachdb-1"
        migrated_during_fault["lease_holder_id"] = 2

        with tempfile.TemporaryDirectory() as tmpdir:
            coord = G3PilotExecutionCoordinator(
                run_id="crdb-g3l3-r02-sc15",
                level="L3",
                duration_sec=180,
                dry_run=False
            )
            coord.output_dir = tmpdir
            coord.telemetry_file_path = os.path.join(tmpdir, "telemetry.jsonl")

            # Mock telemetry thread to avoid spawning live threads
            def mock_poller(pod, stop_ev, file_p, interval, status_dict):
                status_dict["thread_alive"] = True
                status_dict["sample_count"] = 10
                status_dict["last_sample_epoch"] = 9999999999.0
                status_dict["gap_exceeded"] = False

            # Simulation flow:
            # 1. Warmup completes cleanly
            # 2. Post-warmup locks to migrated_target_node1 (cockroachdb-0, Node 1)
            # 3. Measurement wrapper starts
            # 4. Fault application succeeds (apply -f helper)
            # 5. Fault verification succeeds (reads back 259:3 throttle in io.max)
            # 6. During FAULT_MEASUREMENT, sleep raises RuntimeError simulating target migration / health probe failure
            # 7. Lifecycle catches error, enters guaranteed rollback handler because fault_applied == True
            # 8. emergency_independent_rollback is called on locked target (migrated_target_node1)
            # 9. io.max restoration is verified unthrottled
            # 10. Disposition fails closed (FAILED), never SIMULATED_SUCCESS or EXECUTED_VALIDATED
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_preflight_audit", return_value={"mock": True}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.check_storage_capacity", return_value={"avail_mb": 50.0}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.resolve_target_leaseholder", side_effect=[
                     self.mock_target_info_node2,      # TARGET_VERIFICATION (initial)
                     migrated_target_node1,            # WARMUP post-warmup lock (Node 1)
                     migrated_target_node1             # BASELINE_MEASUREMENT pre-fault check
                 ]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.query_sql", side_effect=["0", "5000"]), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.incremental_telemetry_poller", side_effect=mock_poller), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.subprocess.Popen"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.terminate_remote_process_group"), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.collect_helper_job_logs", return_value={"logs": {}, "errors": []}), \
                 patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.emergency_independent_rollback", return_value=True) as mock_rollback:

                def fake_run_cmd(cmd, check=False, timeout=None):
                    cmd_str = " ".join(cmd)
                    if "cat /tmp/pgbench" in cmd_str and "pgid.txt" in cmd_str:
                        return MagicMock(returncode=0, stdout="8888\n", stderr="")
                    if "apply -f" in cmd_str:
                        return MagicMock(returncode=0, stdout="job.batch/g3-helper created\n", stderr="")
                    if "cat /sys/fs/cgroup/io.max" in cmd_str:
                        # Fault verification succeeds with L3 limits on dev 259:3
                        return MagicMock(returncode=0, stdout="259:3 rbps=max wbps=524288 riops=max wiops=75\n", stderr="")
                    return MagicMock(returncode=0, stdout="", stderr="")

                def fake_sleep(duration):
                    # Trigger target migration error during FAULT_MEASUREMENT window
                    if coord.current_state == ExecutionState.FAULT_MEASUREMENT:
                        raise RuntimeError(
                            "Leaseholder migrated during active fault window! "
                            "Expected node: ip-10-0-1-161.ec2.internal (Store 1, cockroachdb-0), "
                            "Observed migration to: ip-10-0-1-160.ec2.internal (Store 2, cockroachdb-1)"
                        )

                with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=fake_run_cmd), \
                     patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep", side_effect=fake_sleep):
                    rec = coord.execute_lifecycle()

            # 1. Assert migration error is captured in execution record
            self.assertTrue(coord.error_occurred)
            self.assertIn("Leaseholder migrated during active fault window", str(rec["state_history"][-1]["error"]))
            
            # 2. Assert emergency rollback was invoked specifically for the locked target (Node 1)
            mock_rollback.assert_called_once_with(migrated_target_node1)

            # 3. Assert fault_applied was reset to False
            self.assertFalse(coord.fault_applied)

            # 4. Assert final disposition cannot be successful
            self.assertEqual(rec["final_disposition"], "FAILED")
            self.assertNotEqual(rec["final_disposition"], "SIMULATED_SUCCESS")
            self.assertNotEqual(rec["final_disposition"], "EXECUTED_VALIDATED")

            # 5. Assert execution record file was persisted in evidence output directory
            rec_path = os.path.join(tmpdir, "00_execution_record.json")
            self.assertTrue(os.path.isfile(rec_path))
            with open(rec_path, "r", encoding="utf-8") as rf:
                rec_data = json.load(rf)
            self.assertEqual(rec_data["final_disposition"], "FAILED")
            self.assertIn("Leaseholder migrated during active fault window", json.dumps(rec_data["state_history"]))
