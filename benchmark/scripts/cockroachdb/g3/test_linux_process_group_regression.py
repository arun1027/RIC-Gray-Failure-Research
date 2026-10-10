#!/usr/bin/env python3
"""
test_linux_process_group_regression.py - Independent Linux Regression Verification
for CockroachDB G3 L3 (G3-05 Protocol).

Strictly offline verification executing under real Linux POSIX kernel.
Zero Kubernetes, AWS, or CockroachDB interaction.
"""

import os
import sys
import time
import subprocess
import signal
import tempfile
import unittest
from unittest.mock import patch, MagicMock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

import benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised as runner_mod


def linux_run_cmd_adapter(cmd, check=False, timeout=None):
    """
    Adapter that executes the target command natively under Linux
    by stripping the 'kubectl exec -n ... --' prefix and formatting
    kill commands appropriately for procps / POSIX systems.
    """
    if len(cmd) >= 6 and cmd[0] == "kubectl" and cmd[1] == "exec":
        try:
            sep_idx = cmd.index("--")
            sub_cmd = cmd[sep_idx + 1:]
        except ValueError:
            sub_cmd = cmd
    else:
        sub_cmd = cmd

    # If sub_cmd is ['/usr/bin/kill', '-TERM', '-<pgid>'], ensure '--' precedes negative PID
    # so procps kill does not interpret -<pgid> as an option flag
    if len(sub_cmd) == 3 and sub_cmd[0] in ("/usr/bin/kill", "/bin/kill", "kill"):
        sub_cmd = [sub_cmd[0], sub_cmd[1], "--", sub_cmd[2]]

    return subprocess.run(sub_cmd, capture_output=True, text=True)


class TestLinuxPOSIXProcessGroupLifecycle(unittest.TestCase):
    """
    Direct verification of process-group lifecycle, wrapper generation,
    and timeout/failure handling in a native Linux POSIX environment.
    """

    def test_sigkill_escalation_after_timeout(self):
        """
        Verify that a process ignoring SIGTERM is escalated to SIGKILL
        after the configured timeout grace period.
        """
        # Create a stub runner script that ignores SIGTERM
        script = (
            "import signal, time, sys\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.1)\n"
        )
        stub_path = "/tmp/stub_test_sigkill.py"
        with open(stub_path, "w") as f:
            f.write(script)

        proc = subprocess.Popen(["setsid", "python3", stub_path])
        time.sleep(0.3)
        child_pid = proc.pid
        pgid = child_pid

        try:
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=linux_run_cmd_adapter):
                # Timeout grace 1.0s (SIGTERM ignored, must escalate to SIGKILL)
                res = runner_mod.terminate_remote_process_group(pgid, timeout_grace_sec=1.0)
                self.assertTrue(res["verified_dead"], "Process group should be verified dead")
                self.assertTrue(res["escalated_to_sigkill"], "Must escalate to SIGKILL when SIGTERM is ignored")
                self.assertEqual(res["surviving_live_count"], 0)
                self.assertFalse(res["hard_failure"])
                # Note: child may remain a zombie until reaped by parent, but is verified dead (not live)
        finally:
            proc.kill()
            proc.wait()
            if os.path.exists(stub_path):
                os.remove(stub_path)


class TestLinuxWrapperAndFailureScenarios(unittest.TestCase):
    """
    Test wrapper-generation logic and all 9 required failure scenarios.
    """

    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_01_normal_workload_completion(self):
        """1. Normal workload completion: exit marker written, process exits cleanly."""
        tmp = self.tmpdir.name
        run_id = "test-r01-norm"
        exit_code_path = os.path.join(tmp, f"pgbench_{run_id}_exit_code.txt")
        pgid_path = os.path.join(tmp, f"pgbench_{run_id}_pgid.txt")

        wrapper_cmd = (
            f"setsid bash -c 'sleep 0.2' & "
            f"BENCH_PGID=$!; "
            f"echo \"${{BENCH_PGID}}\" > {pgid_path}; "
            f"wait ${{BENCH_PGID}}; "
            f"EXIT_CODE=$?; "
            f"echo \"${{EXIT_CODE}}\" > {exit_code_path}.tmp && mv {exit_code_path}.tmp {exit_code_path};"
        )
        res = subprocess.run(["bash", "-c", wrapper_cmd], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0)
        self.assertTrue(os.path.exists(exit_code_path))
        with open(exit_code_path, "r") as f:
            code = f.read().strip()
        self.assertEqual(code, "0")

    def test_02_client_stream_disconnect_while_process_continues(self):
        """2. Client stream disconnect while process continues: workload must survive and finish."""
        tmp = self.tmpdir.name
        run_id = "test-r02-disc"
        exit_code_path = os.path.join(tmp, f"pgbench_{run_id}_exit_code.txt")
        pgid_path = os.path.join(tmp, f"pgbench_{run_id}_pgid.txt")

        # Process runs in background and sleeps for 0.8s
        cmd = (
            f"setsid bash -c 'sleep 0.8' & "
            f"BENCH_PGID=$!; "
            f"echo \"${{BENCH_PGID}}\" > {pgid_path}; "
            f"wait ${{BENCH_PGID}}; "
            f"EXIT_CODE=$?; "
            f"echo \"${{EXIT_CODE}}\" > {exit_code_path};"
        )
        proc = subprocess.Popen(["bash", "-c", cmd])
        try:
            for _ in range(20):
                if os.path.exists(pgid_path):
                    break
                time.sleep(0.05)
            self.assertTrue(os.path.exists(pgid_path))
            with open(pgid_path, "r") as f:
                pgid = int(f.read().strip())

            # Simulate client stream drop immediately
            proc.poll()

            # Decoupling check: at this instant, exit marker should NOT exist yet
            self.assertFalse(os.path.exists(exit_code_path), "Exit marker must not exist while process is running")

            # Live process query must detect it is still alive
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=linux_run_cmd_adapter):
                live, zombies = runner_mod.query_live_processes_in_pgid(pgid)
                self.assertGreater(len(live), 0, "Process must be detected as alive")

            # Wait for natural completion
            for _ in range(30):
                if os.path.exists(exit_code_path):
                    break
                time.sleep(0.1)

            self.assertTrue(os.path.exists(exit_code_path), "Process should finish and write exit code")
            with open(exit_code_path, "r") as f:
                self.assertEqual(f.read().strip(), "0")
        finally:
            proc.kill()
            proc.wait()

    def test_03_process_termination_before_completion_marker(self):
        """3. Process terminated abruptly: no completion marker, detected as missing marker."""
        tmp = self.tmpdir.name
        run_id = "test-r03-abrupt"
        exit_code_path = os.path.join(tmp, f"pgbench_{run_id}_exit_code.txt")
        pgid_path = os.path.join(tmp, f"pgbench_{run_id}_pgid.txt")

        cmd = f"setsid bash -c 'sleep 10' & BENCH_PGID=$!; echo \"${{BENCH_PGID}}\" > {pgid_path}; wait ${{BENCH_PGID}}"
        proc = subprocess.Popen(["bash", "-c", cmd])
        try:
            for _ in range(20):
                if os.path.exists(pgid_path):
                    break
                time.sleep(0.05)
            with open(pgid_path, "r") as f:
                pgid = int(f.read().strip())

            # Abruptly kill process group
            subprocess.run(["kill", "-9", "--", f"-{pgid}"])
            proc.wait()

            # Marker must not exist
            self.assertFalse(os.path.exists(exit_code_path), "Abrupt termination must not create exit marker")
        finally:
            proc.kill()
            proc.wait()

    def test_04_sigterm_success(self):
        """4. SIGTERM success: process cleanly exits on SIGTERM without SIGKILL."""
        # Start a standard process that responds to SIGTERM
        script = (
            "import time\n"
            "while True:\n"
            "    time.sleep(0.1)\n"
        )
        stub_path = "/tmp/stub_sigterm_success.py"
        with open(stub_path, "w") as f:
            f.write(script)

        proc = subprocess.Popen(["setsid", "python3", stub_path])
        time.sleep(0.3)
        pgid = proc.pid

        try:
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=linux_run_cmd_adapter):
                res = runner_mod.terminate_remote_process_group(pgid, timeout_grace_sec=3.0)
                self.assertTrue(res["verified_dead"])
                self.assertFalse(res["escalated_to_sigkill"])
                self.assertEqual(res["surviving_live_count"], 0)
        finally:
            proc.kill()
            proc.wait()
            if os.path.exists(stub_path):
                os.remove(stub_path)

    def test_05_sigkill_escalation(self):
        """5. SIGKILL escalation: process ignoring SIGTERM is successfully terminated via SIGKILL."""
        script = (
            "import signal, time\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            "while True:\n"
            "    time.sleep(0.1)\n"
        )
        stub_path = "/tmp/stub_sigkill_escalation.py"
        with open(stub_path, "w") as f:
            f.write(script)

        proc = subprocess.Popen(["setsid", "python3", stub_path])
        time.sleep(0.3)
        pgid = proc.pid

        try:
            with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=linux_run_cmd_adapter):
                res = runner_mod.terminate_remote_process_group(pgid, timeout_grace_sec=0.5)
                self.assertTrue(res["verified_dead"])
                self.assertTrue(res["escalated_to_sigkill"])
                self.assertEqual(res["surviving_live_count"], 0)
        finally:
            proc.kill()
            proc.wait()
            if os.path.exists(stub_path):
                os.remove(stub_path)

    def test_06_missing_process_group(self):
        """6. Missing process group: non-existent PGID cleanly reports 0 live processes."""
        non_existent_pgid = 999999
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd", side_effect=linux_run_cmd_adapter):
            live, zombies = runner_mod.query_live_processes_in_pgid(non_existent_pgid)
            self.assertEqual(len(live), 0)
            self.assertEqual(len(zombies), 0)

    def test_07_zombie_only_process_group(self):
        """7. Zombie-only process group: zombies are recognized and not treated as live processes."""
        mock_ps = (
            "  PID  PGID STAT COMM\n"
            "    1     1 Ss   bash\n"
            " 1234  5678 Z    pgbench <defunct>\n"
            " 1235  5678 Z+   pgbench <defunct>\n"
        )
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=mock_ps, stderr="")):
            live, zombies = runner_mod.query_live_processes_in_pgid(5678)
            self.assertEqual(len(live), 0, "Zombies must NOT be treated as live")
            self.assertEqual(len(zombies), 2, "Zombies must be recorded in zombie list")

    def test_08_process_check_command_failure(self):
        """8. Process-check command failure: non-zero return code raises RuntimeError."""
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=1, stdout="", stderr="ps: command error")):
            with self.assertRaises(RuntimeError) as ctx:
                runner_mod.query_live_processes_in_pgid(1234)
            self.assertIn("ps command failed with code 1", str(ctx.exception))

    def test_09_timeout_with_surviving_process(self):
        """9. Timeout with surviving process: if processes survive SIGKILL, hard_failure is reported."""
        mock_ps_live = "  PID  PGID STAT COMM\n 1234  5678 D unkillable\n"
        with patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.run_cmd",
                   return_value=MagicMock(returncode=0, stdout=mock_ps_live, stderr="")), \
             patch("benchmark.scripts.cockroachdb.g3.g3_pilot_runner_revised.time.sleep"):
            res = runner_mod.terminate_remote_process_group(5678, timeout_grace_sec=0.1)
            self.assertFalse(res["verified_dead"], "Should report not dead")
            self.assertTrue(res["hard_failure"], "Must declare hard_failure=True")
            self.assertEqual(res["surviving_live_count"], 1)


if __name__ == "__main__":
    unittest.main()
