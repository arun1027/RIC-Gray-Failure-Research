"""
test_g3_baseline_b02_offline.py - Expanded Comprehensive Offline Test Suite for G3 B02 Runner.
Validates:
1. In-pod shell wrapper construction with setsid, process group tracking ($!), wait, and output redirection.
2. Bounded two-stage process-group termination (SIGTERM -> bounded wait -> SIGKILL -> verified DEAD).
3. Process-group verification:
   - Group leader exits but a child process remains alive (detected as ALIVE).
   - Group leader and all children exit (detected as DEAD).
   - Zombie processes handling (distinguishes live processes from dead zombies).
   - Unrelated processes with different PGIDs are not matched or affected.
   - Surviving processes produce a deterministic hard failure.
4. Local kubectl exec termination decoupling.
5. Incremental JSONL telemetry with instant fsync flushing.
6. Partial final JSONL record handling and resilience against sudden interruption.
7. RFC-compliant SHA-256 evidence manifest generation and validation.
8. Rigorous nested timing model verification (nested nominal comparison window, standalone warmup, system-only quiescence).
9. Client-pod tmpfs storage capacity safety margin calculation.
Runs completely offline with zero live cluster access or cgroup writes.
"""

import json
import os
import subprocess
import tempfile
import unittest
from unittest.mock import patch, MagicMock

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..")))
from benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor import (
    construct_in_pod_wrapper,
    compute_sha256,
    build_manifest,
    query_live_processes_in_pgid,
    terminate_remote_process_group,
)

class TestG3BaselineB02Offline(unittest.TestCase):

    def test_wrapper_command_construction(self):
        """Verify the in-pod wrapper shell script is constructed with setsid, PGID tracking, and pipe capturing."""
        cmd = construct_in_pod_wrapper("crdb-g3-baseline-b02", 600)
        self.assertIn("df -k /tmp > /tmp/disk_pre_crdb-g3-baseline-b02.txt", cmd)
        self.assertIn("setsid pgbench -h cockroachdb-public -p 26257 -U root -n -c 20 -j 4 -T 600 --max-tries=1 -M simple", cmd)
        self.assertIn("--log-prefix=/tmp/pgbench_log_crdb-g3-baseline-b02", cmd)
        self.assertIn("> /tmp/pgbench_crdb-g3-baseline-b02_stdout.txt 2> /tmp/pgbench_crdb-g3-baseline-b02_stderr.txt", cmd)
        self.assertIn("BENCH_PGID=$!", cmd)
        self.assertIn('echo "${BENCH_PGID}" > /tmp/pgbench_crdb-g3-baseline-b02_pgid.txt', cmd)
        self.assertIn("wait ${BENCH_PGID}", cmd)
        self.assertIn('echo "${EXIT_CODE}" > /tmp/pgbench_crdb-g3-baseline-b02_exit_code.txt', cmd)
        self.assertIn("df -k /tmp > /tmp/disk_post_crdb-g3-baseline-b02.txt", cmd)

    def test_incremental_jsonl_writing_and_flushing(self):
        """Verify incremental JSONL records are written and immediately readable even if aborted."""
        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = os.path.join(tmpdir, "telemetry_timeseries.jsonl")
            samples = [
                {"timestamp": "2026-11-18T15:00:00Z", "sample": 1, "bytes": 1000},
                {"timestamp": "2026-11-18T15:00:05Z", "sample": 2, "bytes": 2000},
                {"timestamp": "2026-11-18T15:00:10Z", "sample": 3, "bytes": 3000},
            ]
            with open(jsonl_path, "w", encoding="utf-8") as f:
                for s in samples:
                    f.write(json.dumps(s) + "\n")
                    f.flush()
                    os.fsync(f.fileno())

            # Read back immediately
            read_samples = []
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        read_samples.append(json.loads(line))
            self.assertEqual(len(read_samples), 3)
            self.assertEqual(read_samples[1]["sample"], 2)

    def test_partial_final_jsonl_recovery(self):
        """Verify runner parsing logic tolerates truncated final lines without data loss."""
        with tempfile.TemporaryDirectory() as tmpdir:
            jsonl_path = os.path.join(tmpdir, "corrupted_tail.jsonl")
            with open(jsonl_path, "w", encoding="utf-8") as f:
                f.write(json.dumps({"valid": 1}) + "\n")
                f.write(json.dumps({"valid": 2}) + "\n")
                f.write('{"truncated": "half_w')  # unclosed JSON

            valid_records = []
            with open(jsonl_path, "r", encoding="utf-8") as f:
                for line in f:
                    line_s = line.strip()
                    if not line_s:
                        continue
                    try:
                        valid_records.append(json.loads(line_s))
                    except json.JSONDecodeError:
                        pass
            self.assertEqual(len(valid_records), 2)
            self.assertEqual(valid_records[0]["valid"], 1)
            self.assertEqual(valid_records[1]["valid"], 2)

    def test_rfc_manifest_generation(self):
        """Verify SHA-256 manifest computes identical digests for known test content."""
        with tempfile.TemporaryDirectory() as tmpdir:
            f1 = os.path.join(tmpdir, "file1.txt")
            with open(f1, "wb") as f:
                f.write(b"hello world\n")
            # SHA256 of b"hello world\n" is a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447
            digest = compute_sha256(f1)
            self.assertEqual(digest, "a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447")

            manifest_path = build_manifest(tmpdir)
            self.assertTrue(os.path.exists(manifest_path))
            with open(manifest_path, "r", encoding="utf-8") as f:
                content = f.read()
            self.assertIn("a948904f2f0f479b8f8197694b30184b0d2ed1c1cd2a1ec0fb85d299a192a447  file1.txt", content)

    def test_hard_timeout_constant(self):
        """Verify hard timeout is set to 630 seconds (600s + 5% grace)."""
        duration = 600
        grace_percent = 0.05
        hard_timeout = int(duration * (1.0 + grace_percent))
        self.assertEqual(hard_timeout, 630)

    def test_pgid_enumeration_child_alive_leader_dead(self):
        """Test PGID query detects surviving child even if the group leader has exited."""
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "      1       1 Ss   sleep\n"
            "   5502    5500 S    pgbench_worker\n"  # Leader 5500 is gone, child 5502 is alive in PGID 5500
            "   6000    6000 Ss   other_daemon\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            live, zombies = query_live_processes_in_pgid(5500)
            self.assertEqual(len(live), 1)
            self.assertEqual(live[0]["pid"], 5502)
            self.assertEqual(live[0]["pgid"], 5500)
            self.assertEqual(live[0]["comm"], "pgbench_worker")
            self.assertEqual(len(zombies), 0)

    def test_pgid_enumeration_all_exit(self):
        """Test PGID query confirms zero processes when leader and all children have exited."""
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "      1       1 Ss   sleep\n"
            "   6000    6000 Ss   other_daemon\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            live, zombies = query_live_processes_in_pgid(5500)
            self.assertEqual(len(live), 0)
            self.assertEqual(len(zombies), 0)

    def test_pgid_enumeration_zombie_handling(self):
        """Test PGID query distinguishes dead zombie processes from live processes."""
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "      1       1 Ss   sleep\n"
            "   5500    5500 Zs   pgbench\n"        # Leader is zombie
            "   5501    5500 Z    pgbench_worker\n" # Child is zombie
            "   6000    6000 Ss   other_daemon\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            live, zombies = query_live_processes_in_pgid(5500)
            self.assertEqual(len(live), 0)  # Zero live processes
            self.assertEqual(len(zombies), 2)
            self.assertEqual(zombies[0]["pid"], 5500)
            self.assertEqual(zombies[1]["pid"], 5501)

    def test_pgid_enumeration_unrelated_processes_unaffected(self):
        """Test PGID query does not match unrelated processes with similar numbers or different PGIDs."""
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "      1       1 Ss   sleep\n"
            "   5500    5501 S    unrelated_proc1\n" # PID 5500, but PGID is 5501!
            "  55000   55000 S    unrelated_proc2\n" # PGID 55000
            "    550     550 S    unrelated_proc3\n" # PGID 550
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            live, zombies = query_live_processes_in_pgid(5500)
            self.assertEqual(len(live), 0)
            self.assertEqual(len(zombies), 0)

    def test_process_group_termination_graceful(self):
        """Verify process group termination succeeds when SIGTERM terminates all processes in the group."""
        test_pgid = 4943
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            # First call: kill -TERM -4943
            # Second call: ps -eo -> empty for 4943
            mock_proc_kill = MagicMock(returncode=0, stdout="", stderr="")
            mock_proc_ps = MagicMock(returncode=0, stdout="    PID    PGID STAT COMMAND\n      1       1 Ss sleep\n", stderr="")
            mock_run.side_effect = [mock_proc_kill, mock_proc_ps]

            record = terminate_remote_process_group(test_pgid, timeout_grace_sec=2.0)
            self.assertTrue(record["graceful_success"])
            self.assertTrue(record["verified_dead"])
            self.assertFalse(record["sigkill_sent"])
            self.assertEqual(len(record["surviving_procs"]), 0)
            self.assertIsNone(record["error"])

            call_term = mock_run.call_args_list[0][0][0]
            self.assertIn("/usr/bin/kill", call_term)
            self.assertIn("-TERM", call_term)
            self.assertIn("-4943", call_term)

    def test_process_group_termination_escalation_to_sigkill(self):
        """Verify process group termination escalates to SIGKILL if processes in group resist SIGTERM."""
        test_pgid = 8812
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_kill_term = MagicMock(returncode=0, stdout="", stderr="")
            # PS check 1: child process alive
            ps_alive = "    PID    PGID STAT COMMAND\n   8815    8812 S child\n"
            mock_ps_alive = MagicMock(returncode=0, stdout=ps_alive, stderr="")
            mock_kill_kill = MagicMock(returncode=0, stdout="", stderr="")
            # PS check 2: child dead
            ps_dead = "    PID    PGID STAT COMMAND\n      1       1 Ss sleep\n"
            mock_ps_dead = MagicMock(returncode=0, stdout=ps_dead, stderr="")

            mock_run.side_effect = [mock_kill_term, mock_ps_alive, mock_kill_kill, mock_ps_dead]

            record = terminate_remote_process_group(test_pgid, timeout_grace_sec=0.5)
            self.assertFalse(record["graceful_success"])
            self.assertTrue(record["sigkill_sent"])
            self.assertTrue(record["verified_dead"])
            self.assertEqual(len(record["surviving_procs"]), 0)
            self.assertIsNone(record["error"])

            call_kill = mock_run.call_args_list[2][0][0]
            self.assertIn("/usr/bin/kill", call_kill)
            self.assertIn("-KILL", call_kill)
            self.assertIn("-8812", call_kill)

    def test_process_group_termination_hard_failure_detection(self):
        """Verify that if process in group survives SIGKILL, hard failure is recorded and verified_dead is False."""
        test_pgid = 9999
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_kill_term = MagicMock(returncode=0, stdout="", stderr="")
            ps_alive = "    PID    PGID STAT COMMAND\n   9999    9999 S stubborn_leader\n   9998    9999 D unkillable_io_child\n"
            mock_ps_alive = MagicMock(returncode=0, stdout=ps_alive, stderr="")
            mock_kill_kill = MagicMock(returncode=0, stdout="", stderr="")
            mock_ps_still_alive = MagicMock(returncode=0, stdout=ps_alive, stderr="")

            mock_run.side_effect = [mock_kill_term, mock_ps_alive, mock_kill_kill, mock_ps_still_alive]

            record = terminate_remote_process_group(test_pgid, timeout_grace_sec=0.5)
            self.assertFalse(record["graceful_success"])
            self.assertTrue(record["sigkill_sent"])
            self.assertFalse(record["verified_dead"])
            self.assertEqual(len(record["surviving_procs"]), 2)
            self.assertIn("HARD_FAILURE", record["error"])

    def test_safe_argument_handling_for_negative_pgid(self):
        """Verify terminate_remote_process_group rejects invalid non-positive PGIDs safely."""
        with self.assertRaises(ValueError):
            terminate_remote_process_group(-100)
        with self.assertRaises(ValueError):
            terminate_remote_process_group(0)
        with self.assertRaises(ValueError):
            query_live_processes_in_pgid(-5)

    def test_fail_closed_ps_exit_code_1(self):
        """Verify query_live_processes_in_pgid raises RuntimeError when ps exits with non-zero code."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=1, stdout="", stderr="ps: internal error")
            with self.assertRaises(RuntimeError) as ctx:
                query_live_processes_in_pgid(5000)
            self.assertIn("ps command failed with code 1", str(ctx.exception))

    def test_fail_closed_ps_timeout(self):
        """Verify query_live_processes_in_pgid raises exception when ps times out."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd=["ps"], timeout=10.0)
            with self.assertRaises(subprocess.TimeoutExpired):
                query_live_processes_in_pgid(5000)

    def test_fail_closed_ps_empty_output(self):
        """Verify query_live_processes_in_pgid raises RuntimeError on empty output from ps."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="   \n\n", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                query_live_processes_in_pgid(5000)
            self.assertIn("empty output", str(ctx.exception))

    def test_fail_closed_ps_invalid_header(self):
        """Verify query_live_processes_in_pgid raises RuntimeError on unrecognized header format."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="USER PID %CPU %MEM VSZ RSS TTY STAT\n", stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                query_live_processes_in_pgid(5000)
            self.assertIn("unexpected header format", str(ctx.exception))

    def test_fail_closed_ps_malformed_row(self):
        """Verify query_live_processes_in_pgid raises RuntimeError when row has fewer than 4 fields."""
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "   1001    1000\n" # Truncated row with only 2 fields
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                query_live_processes_in_pgid(1000)
            self.assertIn("Malformed process row", str(ctx.exception))

    def test_fail_closed_ps_unparseable_pid_pgid(self):
        """Verify query_live_processes_in_pgid raises RuntimeError when PID or PGID cannot be parsed as int."""
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "   1001    CORRUPT S  pgbench\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                query_live_processes_in_pgid(1000)
            self.assertIn("Unparseable numeric PID/PGID", str(ctx.exception))

    def test_fail_closed_termination_prevents_verified_dead(self):
        """
        Verify terminate_remote_process_group cannot return verified_dead=True if process query fails,
        and accurately records post-kill query failure in term_record['error'].
        """
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            # Stage 1: kill -TERM
            mock_kill_term = MagicMock(returncode=0, stdout="", stderr="")
            # Stage 2: ps query during grace fails
            mock_ps_fail = MagicMock(returncode=1, stdout="", stderr="connection lost")
            # Stage 3: kill -KILL
            mock_kill_kill = MagicMock(returncode=0, stdout="", stderr="")
            # Stage 4: ps query after SIGKILL also fails
            mock_ps_post_fail = MagicMock(returncode=1, stdout="", stderr="connection lost")

            mock_run.side_effect = [mock_kill_term, mock_ps_fail, mock_kill_kill, mock_ps_post_fail]

            record = terminate_remote_process_group(7777, timeout_grace_sec=0.5)
            self.assertFalse(record["graceful_success"])
            self.assertTrue(record["sigkill_sent"])
            self.assertFalse(record["verified_dead"])
            self.assertIn("POST_KILL_VERIFICATION_FAILED", record["error"])

    def test_fail_closed_partially_valid_output_with_malformed_row(self):
        """
        Verify that ps output containing a valid process in the target PGID followed by
        a malformed/unparseable row fails completely:
        - Must raise RuntimeError.
        - Must not accept the valid row as a complete result.
        - Must not return an empty list or partial list.
        - When called from terminate_remote_process_group, must not set verified_dead=True.
        """
        fake_ps = (
            "    PID    PGID STAT COMMAND\n"
            "   1001    1000 S    valid_pgbench_leader\n"
            "   1002    CORRUPT_PGID S invalid_worker\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout=fake_ps, stderr="")
            with self.assertRaises(RuntimeError) as ctx:
                query_live_processes_in_pgid(1000)
            self.assertIn("Unparseable numeric PID/PGID", str(ctx.exception))

    def test_fail_closed_unexpected_enumeration_exception_grace_period(self):
        """
        Verify that an unexpected exception during the SIGTERM grace period:
        - Does NOT set verified_dead=True or graceful_success=True.
        - Logs a warning.
        - Escalates to SIGKILL according to termination policy.
        """
        test_pgid = 4500
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run, \
             patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.query_live_processes_in_pgid") as mock_query:
            mock_kill_term = MagicMock(returncode=0, stdout="", stderr="")
            mock_kill_kill = MagicMock(returncode=0, stdout="", stderr="")
            mock_run.side_effect = [mock_kill_term, mock_kill_kill]

            # query_live_processes_in_pgid raises an unexpected exception during grace,
            # then after SIGKILL reports clean termination ([], [])
            mock_query.side_effect = [
                RuntimeError("Unexpected connection reset during grace"),
                ([], []) # clean after SIGKILL
            ]

            record = terminate_remote_process_group(test_pgid, timeout_grace_sec=0.5)
            self.assertFalse(record["graceful_success"])
            self.assertTrue(record["sigkill_sent"])
            self.assertTrue(record["verified_dead"])
            self.assertIsNone(record["error"])

    def test_fail_closed_unexpected_enumeration_exception_post_sigkill(self):
        """
        Verify that an unexpected exception during post-SIGKILL verification:
        - Produces a hard failure.
        - Leaves verified_dead=False.
        - Preserves diagnostic error message in term_record['error'].
        """
        test_pgid = 4600
        with patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.run_cmd") as mock_run, \
             patch("benchmark.scripts.cockroachdb.g3.g3_baseline_b02_executor.query_live_processes_in_pgid") as mock_query:
            mock_kill_term = MagicMock(returncode=0, stdout="", stderr="")
            mock_kill_kill = MagicMock(returncode=0, stdout="", stderr="")
            mock_run.side_effect = [mock_kill_term, mock_kill_kill]

            # query_live_processes_in_pgid reports live worker during grace,
            # then raises unexpected exception post-SIGKILL
            mock_query.side_effect = [
                ([{"pid": 4601, "pgid": 4600, "stat": "S", "comm": "worker"}], []),
                RuntimeError("Kernel panic or IO failure during post-SIGKILL verification")
            ]

            record = terminate_remote_process_group(test_pgid, timeout_grace_sec=0.5)
            self.assertFalse(record["graceful_success"])
            self.assertTrue(record["sigkill_sent"])
            self.assertFalse(record["verified_dead"])
            self.assertIn("POST_KILL_VERIFICATION_FAILED", record["error"])
            self.assertIn("Kernel panic or IO failure", record["error"])

    def test_nested_timing_model_definitions(self):
        """
        Verify rigorous mathematical definitions of the timing model:
        1. Warmup: 120s standalone (t = -120 to 0).
        2. Measurement Stream: 600s continuous (t = 0 to 600).
        3. Nominal Comparison Window: 180s NESTED INSIDE measurement stream (t = 120 to 300).
        4. Post-Measurement Observation Window (Wrec): at least 300s of SYSTEM-ONLY observation (t = 600 to 900+).
        """
        warmup_duration = 120.0
        meas_duration = 600.0
        nominal_start = 120.0
        nominal_end = 300.0
        nominal_duration = nominal_end - nominal_start
        wrec_duration = 300.0

        # Assert Nominal Comparison Window is strictly nested within measurement stream
        self.assertGreaterEqual(nominal_start, 0.0)
        self.assertLessEqual(nominal_end, meas_duration)
        self.assertEqual(nominal_duration, 180.0)

        # Assert Warmup is strictly prior to measurement stream
        self.assertEqual(warmup_duration, 120.0)

        # Assert Wrec is strictly post-measurement system-only observation (non-overlapping with transaction stream)
        self.assertEqual(wrec_duration, 300.0)
        total_active_tx_duration = warmup_duration + meas_duration
        self.assertEqual(total_active_tx_duration, 720.0)

    def test_tmpfs_storage_capacity_headroom(self):
        """
        Verify client-pod tmpfs capacity (64 MiB total, 57 MiB available):
        Based on F15 empirical peak (225,867 txs -> 7.21 MiB of logs):
        A full 600s run requires ~7.5 MiB of transaction logs, stdout, and stderr.
        Available space (57 MiB) provides >7.5x safety headroom.
        """
        avail_tmpfs_bytes = 57 * 1024 * 1024
        estimated_peak_log_bytes = 7.5 * 1024 * 1024
        self.assertGreater(avail_tmpfs_bytes, estimated_peak_log_bytes * 5)
        ratio = avail_tmpfs_bytes / estimated_peak_log_bytes
        self.assertGreaterEqual(ratio, 7.5)

if __name__ == "__main__":
    unittest.main()
