#!/usr/bin/env python3
"""
G3-91 Isolated Runtime Test Suite for Generated POSIX/Dash Helper & Rollback Scripts.

Extracts the actual shell scripts embedded inside:
  - generate_helper_job_manifest()
  - generate_rollback_job_manifest()
and executes them under real Linux /bin/dash (natively on Linux, or via `wsl -e dash`
on Windows) against isolated temporary cgroup directories (via G3_CGROUP_ROOT).

Zero Kubernetes, AWS, or CockroachDB cluster interaction occurs in this suite.
"""

import os
import re
import secrets
import shutil
import subprocess
import sys
import unittest
from typing import Dict, List, Optional, Tuple

# Ensure project root is on sys.path when executed directly
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from benchmark.scripts.cockroachdb.g3.g3_pilot_runner import (  # noqa: E402
    generate_helper_job_manifest,
    generate_rollback_job_manifest,
)


def extract_manifest_env_and_script(manifest_yaml: str) -> Tuple[Dict[str, str], str]:
    """Parse container env map and literal `command: ... - |` shell script from Job YAML."""
    lines = manifest_yaml.splitlines()
    env_vars: Dict[str, str] = {}
    i = 0
    while i < len(lines):
        m_name = re.match(r"^\s*-\s*name:\s*([A-Za-z0-9_]+)\s*$", lines[i])
        if m_name and i + 1 < len(lines):
            m_val = re.match(r'^\s*value:\s*"(.*)"\s*$', lines[i + 1])
            if m_val:
                env_vars[m_name.group(1)] = m_val.group(1)
                i += 2
                continue
        if lines[i].strip() == "- |":
            script_lines: List[str] = []
            base_indent: Optional[int] = None
            for raw in lines[i + 1 :]:
                if not raw.strip():
                    script_lines.append("")
                    continue
                indent = len(raw) - len(raw.lstrip(" "))
                if base_indent is None:
                    base_indent = indent
                if indent < base_indent:
                    break
                script_lines.append(raw[base_indent:])
            return env_vars, "\n".join(script_lines) + "\n"
        i += 1
    raise ValueError("Unable to extract `- |` shell script from Job manifest YAML.")


def _find_dash_runner() -> List[str]:
    """Return command prefix to invoke real Linux /bin/dash."""
    if sys.platform != "win32":
        if os.path.exists("/bin/dash"):
            return ["/bin/dash"]
        dash_bin = shutil.which("dash")
        if dash_bin:
            return [dash_bin]
        raise RuntimeError("Real /bin/dash not found on POSIX host.")
    # On Windows, WSL provides authentic Linux /bin/dash
    probe = subprocess.run(
        ["wsl", "-e", "dash", "-c", "echo DASH_OK"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if probe.returncode != 0 or "DASH_OK" not in probe.stdout:
        raise RuntimeError(
            f"WSL Linux /bin/dash is unavailable (rc={probe.returncode}, err={probe.stderr.strip()!r})."
        )
    return ["wsl", "-e", "dash"]


class TestG3HelperDashRuntimeOffline(unittest.TestCase):
    """Execute actual generated helper & rollback scripts under real Linux /bin/dash."""

    @classmethod
    def setUpClass(cls):
        cls.dash_cmd = _find_dash_runner()
        cls.cid = "f29e11f4213d549b8d0eb4130546958f016adc4df22bd7bb24970c0bd223af9c"
        cls.sibling_cid = "aaaa111122223333444455556666777788889999000011112222333344445555"
        cls.target_info = {
            "target_node": "ip-10-0-1-160.ec2.internal",
            "target_pod": "cockroachdb-1",
            "container_id": cls.cid,
            "dev_major": 259,
            "dev_minor": 4,
            "dev_stat_dec": 66308,
            "initial_io_max": "",
        }

    def _run_bytes_stdin(self, cmd: List[str], stdin_text: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
        """Pass Unix LF bytes on stdin to avoid Windows CRLF translation when invoking Linux dash via WSL."""
        lf_bytes = stdin_text.replace("\r\n", "\n").encode("utf-8")
        proc = subprocess.run(
            cmd,
            input=lf_bytes,
            capture_output=True,
            timeout=timeout,
        )
        proc.stdout = proc.stdout.decode("utf-8", errors="replace")
        proc.stderr = proc.stderr.decode("utf-8", errors="replace")
        return proc

    def _run_dash_inline(self, shell_script: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
        return self._run_bytes_stdin([*self.dash_cmd, "-s"], shell_script, timeout=timeout)

    def test_01_dash_n_syntax_check_helper_and_rollback(self):
        """Run `dash -n` static syntax parser on both helper and rollback generated scripts."""
        helper_manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 2, False)
        _, helper_script = extract_manifest_env_and_script(helper_manifest)
        _, rb_script_manifest = generate_rollback_job_manifest("crdb-g3l1-pilot-p02", self.target_info)
        _, rb_script = extract_manifest_env_and_script(rb_script_manifest)

        for label, script in (("helper", helper_script), ("rollback", rb_script)):
            with self.subTest(script=label):
                res = self._run_bytes_stdin([*self.dash_cmd, "-n"], script, timeout=15.0)
                self.assertEqual(res.returncode, 0, msg=f"{label} dash -n failed: {res.stderr}")

    def test_02_normal_completion_empty_initial_io_max(self):
        """Normal completion verifies 4-limit write mid-window and all-4 max restoration on exit 0."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 2, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        driver = f"""
set -eu
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/kubepods.slice/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
: > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="2"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
APPLIED=""
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    APPLIED=$(cat "${{CDIR}}/io.max")
    break
  fi
  sleep 0.05
done
wait "${{HPID}}"
RC=$?
AFTER=$(cat "${{CDIR}}/io.max")
echo "RC=${{RC}}"
echo "APPLIED=${{APPLIED}}"
echo "AFTER=${{AFTER}}"
cat "${{ROOT}}/out.log"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stdout + "\n" + res.stderr)
        self.assertIn("RC=0", res.stdout)
        self.assertIn("APPLIED=259:4 rbps=max wbps=5242880 riops=max wiops=600", res.stdout)
        self.assertIn("AFTER=259:4 rbps=max wbps=max riops=max wiops=max", res.stdout)
        self.assertIn("Restoration VERIFIED successfully.", res.stdout)

    def test_03_normal_completion_preserves_nonempty_four_limits(self):
        """Helper preserves pre-existing rbps/riops during fault and restores exact original 4 limits."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 2, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        orig_line = "259:4 rbps=10485760 wbps=20971520 riops=1000 wiops=2000"
        driver = f"""
set -eu
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/kubepods.slice/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
printf '%s\\n' "{orig_line}" > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="2"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
APPLIED=""
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    APPLIED=$(cat "${{CDIR}}/io.max")
    break
  fi
  sleep 0.05
done
wait "${{HPID}}"
RC=$?
AFTER=$(cat "${{CDIR}}/io.max")
echo "RC=${{RC}}"
echo "APPLIED=${{APPLIED}}"
echo "AFTER=${{AFTER}}"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stdout + "\n" + res.stderr)
        self.assertIn("RC=0", res.stdout)
        self.assertIn("APPLIED=259:4 rbps=10485760 wbps=5242880 riops=1000 wiops=600", res.stdout)
        self.assertIn(f"AFTER={orig_line}", res.stdout)

    def test_04_sigterm_during_active_fault_immediate_cleanup_and_no_orphan(self):
        """SIGTERM during a 60s window triggers cleanup within <5s, exits 143, and leaves zero orphan sleep."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 60, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        marker = f"G3_ORPHAN_MARKER_{tag}"
        # Replace duration env with 57 + unique sleep check or keep G3_DURATION_SEC=57 so we can grep ps uniquely
        driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
: > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{marker}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="57"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

T0=$(date +%s)
dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
sleep 0.2
kill -TERM "${{HPID}}"
set +e
wait "${{HPID}}"
RC=$?
set -e
T1=$(date +%s)
ELAPSED=$((T1 - T0))
sleep 0.1
ORPHANS=$(ps -eo pid,ppid,args | grep -E "sleep 57$" || true)
AFTER=$(cat "${{CDIR}}/io.max")
echo "RC=${{RC}}"
echo "ELAPSED=${{ELAPSED}}"
echo "AFTER=${{AFTER}}"
echo "ORPHANS=${{ORPHANS}}"
cat "${{ROOT}}/out.log"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("RC=143", res.stdout)
        self.assertIn("AFTER=259:4 rbps=max wbps=max riops=max wiops=max", res.stdout)
        self.assertIn("ORPHANS=\n", res.stdout)
        m = re.search(r"ELAPSED=(\d+)", res.stdout)
        self.assertIsNotNone(m)
        self.assertLess(int(m.group(1)), 5)

    def test_05_sigint_during_active_fault_immediate_cleanup_exit_130(self):
        """SIGINT during a 58s window (direct SIG_DFL spawn, matching containerd) triggers cleanup in <5s and exits 130."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 58, False)
        env, script = extract_manifest_env_and_script(manifest)
        py_driver = f"""
import os, signal, subprocess, tempfile, time
with tempfile.TemporaryDirectory(prefix='g3dash_sigint_') as d:
    cdir = os.path.join(d, 'cri-containerd-{self.cid}.scope')
    os.makedirs(cdir)
    iomax = os.path.join(cdir, 'io.max')
    open(iomax, 'w').close()
    hpath = os.path.join(d, 'helper.sh')
    with open(hpath, 'w', encoding='utf-8') as f:
        f.write({script!r})
    run_env = dict(os.environ)
    run_env.update({{
        'G3_RUN_ID': {env['G3_RUN_ID']!r},
        'G3_TARGET_POD': {env['G3_TARGET_POD']!r},
        'G3_CONTAINER_ID': {env['G3_CONTAINER_ID']!r},
        'G3_DEV_MAJOR': {env['G3_DEV_MAJOR']!r},
        'G3_DEV_MINOR': {env['G3_DEV_MINOR']!r},
        'G3_LIMIT_WBPS': {env['G3_LIMIT_WBPS']!r},
        'G3_LIMIT_WIOPS': {env['G3_LIMIT_WIOPS']!r},
        'G3_DURATION_SEC': '58',
        'G3_DRY_RUN': 'false',
        'G3_CGROUP_ROOT': d,
    }})
    t0 = time.monotonic()
    p = subprocess.Popen(['dash', hpath], env=run_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    for _ in range(40):
        if 'wbps=5242880' in open(iomax).read():
            break
        time.sleep(0.05)
    time.sleep(0.2)
    p.send_signal(signal.SIGINT)
    out, _ = p.communicate(timeout=5.0)
    elapsed = time.monotonic() - t0
    after = open(iomax).read().strip()
    ps = subprocess.run(['ps', '-eo', 'pid,ppid,args'], capture_output=True, text=True).stdout
    orphans = [ln for ln in ps.splitlines() if ln.strip().endswith('sleep 58')]
    print(f'RC={{p.returncode}}')
    print(f'ELAPSED={{elapsed:.2f}}')
    print(f'AFTER={{after}}')
    print(f'ORPHANS={{len(orphans)}}')
    print(out)
"""
        py_cmd = ["wsl", "-e", "python3", "-"] if sys.platform == "win32" else [sys.executable, "-"]
        res = self._run_bytes_stdin(py_cmd, py_driver, timeout=20.0)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("RC=130", res.stdout)
        self.assertIn("AFTER=259:4 rbps=max wbps=max riops=max wiops=max", res.stdout)
        self.assertIn("ORPHANS=0", res.stdout)
        m = re.search(r"ELAPSED=([0-9.]+)", res.stdout)
        self.assertIsNotNone(m)
        self.assertLess(float(m.group(1)), 5.0)

    def test_06_repeated_sigterm_burst_single_clean_restoration(self):
        """Rapid burst of 3 SIGTERMs produces a single verified rollback with exit code 143."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 59, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
: > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="59"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
sleep 0.2
kill -TERM "${{HPID}}"
kill -TERM "${{HPID}}" 2>/dev/null || true
kill -TERM "${{HPID}}" 2>/dev/null || true
set +e
wait "${{HPID}}"
RC=$?
set -e
AFTER=$(cat "${{CDIR}}/io.max")
ROLLBACK_COUNT=$(grep -c "\\[CLEANUP\\] Invoking rollback" "${{ROOT}}/out.log" || true)
echo "RC=${{RC}}"
echo "AFTER=${{AFTER}}"
echo "ROLLBACK_COUNT=${{ROLLBACK_COUNT}}"
cat "${{ROOT}}/out.log"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("RC=143", res.stdout)
        self.assertIn("AFTER=259:4 rbps=max wbps=max riops=max wiops=max", res.stdout)
        self.assertIn("ROLLBACK_COUNT=1", res.stdout)

    def test_07_signal_during_restoration_is_shielded(self):
        """Secondary SIGTERM and SIGINT injected right after signal-trap entry do not interrupt cleanup."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 56, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        tag_root = f"/tmp/g3dash_{tag}"
        driver = f"""
ROOT="{tag_root}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
BIN="${{ROOT}}/bin"
mkdir -p "${{CDIR}}" "${{BIN}}"
: > "${{CDIR}}/io.max"
echo "0" > "${{ROOT}}/date_calls"
cat <<'__DATE_SHIM__' > "${{BIN}}/date"
#!/bin/sh
C=$(cat "{tag_root}/date_calls" 2>/dev/null || echo 0)
C=$((C + 1))
echo "${{C}}" > "{tag_root}/date_calls"
if [ -f "{tag_root}/helper.pid" ] && [ "${{C}}" -eq 6 ]; then
  TP=$(cat "{tag_root}/helper.pid")
  kill -TERM "${{TP}}" 2>/dev/null || true
  kill -INT "${{TP}}" 2>/dev/null || true
fi
/bin/date "$@"
__DATE_SHIM__
chmod +x "${{BIN}}/date"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export PATH="${{BIN}}:${{PATH}}"
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="56"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
echo "${{HPID}}" > "${{ROOT}}/helper.pid"
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
sleep 0.2
# Calls 1..5 are startup, orig state, fault apply, verified applied, sleeping -> call 6 is on_signal before cleanup!
kill -TERM "${{HPID}}"
set +e
wait "${{HPID}}"
RC=$?
set -e
AFTER=$(cat "${{CDIR}}/io.max")
echo "RC=${{RC}}"
echo "AFTER=${{AFTER}}"
cat "${{ROOT}}/out.log"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("RC=143", res.stdout)
        self.assertIn("AFTER=259:4 rbps=max wbps=max riops=max wiops=max", res.stdout)
        self.assertIn("Restoration VERIFIED successfully.", res.stdout)

    def test_08_failed_restoration_exits_code_2_fail_closed(self):
        """Making io.max read-only after fault application forces exit code 2 (cannot false-pass)."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 3, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'chmod 644 "${{ROOT}}/cri-containerd-{self.cid}.scope/io.max" 2>/dev/null || true; rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
: > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="3"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    chmod 444 "${{CDIR}}/io.max"
    break
  fi
  sleep 0.05
done
set +e
wait "${{HPID}}"
RC=$?
set -e
echo "RC=${{RC}}"
cat "${{ROOT}}/out.log"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        # Note: if running as root inside WSL, chmod 444 may still allow root write unless tested under non-root user or missing file!
        # Let's check: if UID is 0 in WSL, simulate failed write by replacing io.max with a directory or test under nobody!
        if "RC=0" in res.stdout:
            # Running as root in WSL bypasses DAC mode 444 -> re-verify fail-closed restoration using immutable directory swap after apply
            driver_root = f"""
ROOT="/tmp/g3dash_{tag}_r"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
: > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="2"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1 &
HPID=$!
for _i in $(seq 1 40); do
  if grep -q "wbps=5242880" "${{CDIR}}/io.max" 2>/dev/null; then
    rm -f "${{CDIR}}/io.max" && mkdir "${{CDIR}}/io.max"
    break
  fi
  sleep 0.05
done
set +e
wait "${{HPID}}"
RC=$?
set -e
echo "RC=${{RC}}"
cat "${{ROOT}}/out.log"
"""
            res = self._run_dash_inline(driver_root)
            self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("RC=2", res.stdout)
        self.assertIn("Failed to clear throttle", res.stdout)

    def test_09_invalid_container_id_in_env_rejected_by_dash(self):
        """Passing empty, wildcard, or non-hex G3_CONTAINER_ID directly to Dash script exits 1 without touching io.max."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 2, False)
        env, script = extract_manifest_env_and_script(manifest)
        for bad_cid in ("", "*", "*f29e*", "not_hex"):
            tag = secrets.token_hex(4)
            with self.subTest(bad_cid=bad_cid):
                driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
printf 'sentinel\\n' > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{bad_cid}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="2"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

set +e
dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1
RC=$?
set -e
echo "RC=${{RC}}"
echo "IOMAX=$(cat "${{CDIR}}/io.max")"
cat "${{ROOT}}/out.log"
"""
                res = self._run_dash_inline(driver)
                self.assertEqual(res.returncode, 0)
                self.assertIn("RC=1", res.stdout)
                self.assertIn("IOMAX=sentinel", res.stdout)

    def test_10_missing_or_duplicate_cgroup_dir_rejected(self):
        """Dash script exits 1 when 0 or 2 cgroup dirs match G3_CONTAINER_ID."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 2, False)
        env, script = extract_manifest_env_and_script(manifest)
        for count in (0, 2):
            tag = secrets.token_hex(4)
            with self.subTest(match_count=count):
                mk = ""
                if count == 2:
                    mk = (
                        f'mkdir -p "${{ROOT}}/a/cri-containerd-{self.cid}.scope" '
                        f'"${{ROOT}}/b/cri-containerd-{self.cid}.scope" && '
                        f': > "${{ROOT}}/a/cri-containerd-{self.cid}.scope/io.max" && '
                        f': > "${{ROOT}}/b/cri-containerd-{self.cid}.scope/io.max"'
                    )
                else:
                    mk = 'mkdir -p "${ROOT}"'
                driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
{mk}
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="2"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

set +e
dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1
RC=$?
set -e
echo "RC=${{RC}}"
cat "${{ROOT}}/out.log"
"""
                res = self._run_dash_inline(driver)
                self.assertEqual(res.returncode, 0)
                self.assertIn("RC=1", res.stdout)
                self.assertIn("Unique cgroup path with readable io.max not found", res.stdout)

    def test_11_malformed_io_max_rejected_prefault(self):
        """Malformed pre-existing io.max fails closed with exit code 1 before applying fault."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 2, False)
        env, script = extract_manifest_env_and_script(manifest)
        for bad_line in ("corrupted_unparsed_entry", "259:4 wbps=bad"):
            tag = secrets.token_hex(4)
            with self.subTest(bad_line=bad_line):
                driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
printf '%s\\n' "{bad_line}" > "${{CDIR}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="2"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

set +e
dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1
RC=$?
set -e
echo "RC=${{RC}}"
echo "IOMAX=$(cat "${{CDIR}}/io.max")"
cat "${{ROOT}}/out.log"
"""
                res = self._run_dash_inline(driver)
                self.assertEqual(res.returncode, 0)
                self.assertIn("RC=1", res.stdout)
                self.assertIn(f"IOMAX={bad_line}", res.stdout)

    def test_12_device_prefix_collision_and_sibling_isolation(self):
        """Targeting 259:4 never matches 259:40 in io.max and never modifies sibling container cgroups."""
        manifest = generate_helper_job_manifest("crdb-g3l1-pilot-p02", self.target_info, "L1", 1, False)
        env, script = extract_manifest_env_and_script(manifest)
        tag = secrets.token_hex(4)
        prefix_line = "259:40 rbps=111 wbps=222 riops=333 wiops=444"
        driver = f"""
ROOT="/tmp/g3dash_{tag}"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
SIB="${{ROOT}}/cri-containerd-{self.sibling_cid}.scope"
mkdir -p "${{CDIR}}" "${{SIB}}"
printf '%s\\n' "{prefix_line}" > "${{CDIR}}/io.max"
printf '259:4 rbps=max wbps=999 riops=max wiops=999\\n' > "${{SIB}}/io.max"
cat <<'__G3_SCRIPT__' > "${{ROOT}}/helper.sh"
{script}
__G3_SCRIPT__
export G3_RUN_ID="{env['G3_RUN_ID']}"
export G3_TARGET_POD="{env['G3_TARGET_POD']}"
export G3_CONTAINER_ID="{env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{env['G3_DEV_MINOR']}"
export G3_LIMIT_WBPS="{env['G3_LIMIT_WBPS']}"
export G3_LIMIT_WIOPS="{env['G3_LIMIT_WIOPS']}"
export G3_DURATION_SEC="1"
export G3_DRY_RUN="false"
export G3_CGROUP_ROOT="${{ROOT}}"

dash "${{ROOT}}/helper.sh" > "${{ROOT}}/out.log" 2>&1
RC=$?
echo "RC=${{RC}}"
echo "TARGET=$(cat "${{CDIR}}/io.max")"
echo "SIBLING=$(cat "${{SIB}}/io.max")"
"""
        res = self._run_dash_inline(driver)
        self.assertEqual(res.returncode, 0, msg=res.stderr)
        self.assertIn("RC=0", res.stdout)
        # Note: target io.max had 259:40 initially (so 259:4 was absent -> restored to all-max, NOT 111/222!)
        self.assertIn("TARGET=259:4 rbps=max wbps=max riops=max wiops=max", res.stdout)
        self.assertNotIn("rbps=111", res.stdout)
        self.assertIn("SIBLING=259:4 rbps=max wbps=999 riops=max wiops=999", res.stdout)

    def test_13_independent_rollback_job_dash_execution_paths(self):
        """Execute generated rollback Job Dash script across clear, nonempty restore, and fail-closed paths."""
        # Case A: clear throttle -> exit 0
        _, rb_yaml = generate_rollback_job_manifest("p02", self.target_info)
        rb_env, rb_script = extract_manifest_env_and_script(rb_yaml)
        tag = secrets.token_hex(4)
        driver_a = f"""
ROOT="/tmp/g3dash_{tag}_a"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
printf '259:4 rbps=max wbps=5242880 riops=max wiops=600\\n' > "${{CDIR}}/io.max"
cat <<'__RB__' > "${{ROOT}}/rb.sh"
{rb_script}
__RB__
export G3_CONTAINER_ID="{rb_env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{rb_env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{rb_env['G3_DEV_MINOR']}"
export G3_ORIGINAL_IO_MAX="{rb_env.get('G3_ORIGINAL_IO_MAX', '')}"
export G3_CGROUP_ROOT="${{ROOT}}"
dash "${{ROOT}}/rb.sh"
echo "AFTER=$(cat "${{CDIR}}/io.max")"
"""
        res_a = self._run_dash_inline(driver_a)
        self.assertEqual(res_a.returncode, 0, msg=res_a.stderr)
        self.assertIn("AFTER=259:4 rbps=max wbps=max riops=max wiops=max", res_a.stdout)

        # Case B: restore non-empty original 4 limits -> exit 0
        orig_target = dict(
            self.target_info,
            initial_io_max="259:4 rbps=10485760 wbps=20971520 riops=1000 wiops=2000\n",
        )
        _, rb_yaml_b = generate_rollback_job_manifest("p02", orig_target)
        rb_env_b, rb_script_b = extract_manifest_env_and_script(rb_yaml_b)
        driver_b = f"""
ROOT="/tmp/g3dash_{tag}_b"
trap 'rm -rf "${{ROOT}}"' EXIT
CDIR="${{ROOT}}/cri-containerd-{self.cid}.scope"
mkdir -p "${{CDIR}}"
printf '259:4 rbps=10485760 wbps=5242880 riops=1000 wiops=600\\n' > "${{CDIR}}/io.max"
cat <<'__RB__' > "${{ROOT}}/rb.sh"
{rb_script_b}
__RB__
export G3_CONTAINER_ID="{rb_env_b['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{rb_env_b['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{rb_env_b['G3_DEV_MINOR']}"
export G3_ORIGINAL_IO_MAX="{rb_env_b['G3_ORIGINAL_IO_MAX']}"
export G3_CGROUP_ROOT="${{ROOT}}"
dash "${{ROOT}}/rb.sh"
echo "AFTER=$(cat "${{CDIR}}/io.max")"
"""
        res_b = self._run_dash_inline(driver_b)
        self.assertEqual(res_b.returncode, 0, msg=res_b.stderr)
        self.assertIn("AFTER=259:4 rbps=10485760 wbps=20971520 riops=1000 wiops=2000", res_b.stdout)

        # Case C: missing cgroup & malformed G3_ORIGINAL_IO_MAX -> both fail closed exit 2
        driver_c = f"""
ROOT="/tmp/g3dash_{tag}_c"
trap 'rm -rf "${{ROOT}}"' EXIT
mkdir -p "${{ROOT}}"
cat <<'__RB__' > "${{ROOT}}/rb.sh"
{rb_script}
__RB__
export G3_CONTAINER_ID="{rb_env['G3_CONTAINER_ID']}"
export G3_DEV_MAJOR="{rb_env['G3_DEV_MAJOR']}"
export G3_DEV_MINOR="{rb_env['G3_DEV_MINOR']}"
export G3_ORIGINAL_IO_MAX=""
export G3_CGROUP_ROOT="${{ROOT}}"
set +e
dash "${{ROOT}}/rb.sh"
RC_MISS=$?
mkdir -p "${{ROOT}}/cri-containerd-{self.cid}.scope"
: > "${{ROOT}}/cri-containerd-{self.cid}.scope/io.max"
export G3_ORIGINAL_IO_MAX="259:4 wbps=bad"
dash "${{ROOT}}/rb.sh"
RC_MAL=$?
set -e
echo "RC_MISS=${{RC_MISS}}"
echo "RC_MAL=${{RC_MAL}}"
"""
        res_c = self._run_dash_inline(driver_c)
        self.assertEqual(res_c.returncode, 0, msg=res_c.stderr)
        self.assertIn("RC_MISS=2", res_c.stdout)
        self.assertIn("RC_MAL=2", res_c.stdout)


if __name__ == "__main__":
    unittest.main()
