"""
g2_process_discovery.py - Target CockroachDB Process and Network Namespace Discovery for G2 Helper.
"""

import os
import re
from typing import Dict, List, Optional, Tuple


class ProcessDiscoveryError(RuntimeError):
    """Raised when host process discovery fails or encounters ambiguity."""
    pass


def parse_start_time_ticks(stat_content: str) -> Optional[int]:
    """
    Extract start time in jiffies/ticks (field 22) from Linux /proc/[pid]/stat.
    Handles process names containing spaces and parentheses safely by splitting
    after the last closing parenthesis.
    """
    try:
        rparen_idx = stat_content.rfind(")")
        if rparen_idx == -1:
            return None
        rest = stat_content[rparen_idx + 1:].strip().split()
        # field 1: pid
        # field 2: comm in parentheses
        # rest[0]: field 3 (state)
        # field 22 is index 19 in rest
        if len(rest) >= 20:
            return int(rest[19])
    except Exception:
        pass
    return None


def discover_target_process(
    target_pod: str,
    proc_root: str = "/proc",
    target_pod_uid: Optional[str] = None,
    target_container_id: Optional[str] = None,
    expected_netns_inode: Optional[str] = None,
    expected_start_time_ticks: Optional[int] = None,
) -> Dict[str, any]:
    """
    Discovers and validates the host PID and network namespace of the target CockroachDB pod.

    Security & Safety Guarantees:
    - Scans proc_root for CockroachDB process.
    - Matches cmdline containing 'cockroach' and 'start'.
    - Matches /proc/<pid>/cgroup containing target_pod_uid, target_container_id, or target_pod.
    - Requires strictly ONE unambiguously matching process. If zero or multiple matches exist, raises ProcessDiscoveryError.
    - Captures PID and start_time_ticks.
    - Validates expected_start_time_ticks if supplied (preventing PID reuse / restart attacks).
    - Resolves network namespace inode via os.readlink or os.stat on /proc/<pid>/ns/net.
    - Validates expected_netns_inode if supplied.
    """
    if not target_pod:
        raise ProcessDiscoveryError("Missing target_pod parameter")

    pod_uid_clean = target_pod_uid.replace("-", "_") if target_pod_uid else ""
    pod_uid_raw = target_pod_uid if target_pod_uid else ""
    cid_clean = target_container_id.replace("containerd://", "") if target_container_id else ""

    matching_pids: List[int] = []

    if not os.path.exists(proc_root):
        raise ProcessDiscoveryError(f"proc_root does not exist: {proc_root}")

    for entry in os.listdir(proc_root):
        if not entry.isdigit():
            continue
        pid = int(entry)
        pid_dir = os.path.join(proc_root, entry)
        cmdline_path = os.path.join(pid_dir, "cmdline")
        cgroup_path = os.path.join(pid_dir, "cgroup")

        try:
            with open(cmdline_path, "rb") as f:
                cmdline = f.read().replace(b"\x00", b" ").decode("utf-8", errors="ignore")
            if "cockroach" not in cmdline or "start" not in cmdline:
                continue

            matched = False
            if os.path.exists(cgroup_path):
                with open(cgroup_path, "r", encoding="utf-8", errors="ignore") as cf:
                    cg = cf.read()
                    if pod_uid_clean and pod_uid_clean in cg:
                        matched = True
                    elif pod_uid_raw and pod_uid_raw in cg:
                        matched = True
                    elif cid_clean and cid_clean in cg:
                        matched = True
                    elif target_pod in cg:
                        matched = True

            if matched or (not target_pod_uid and not target_container_id):
                matching_pids.append(pid)
        except (OSError, IOError):
            continue

    if not matching_pids:
        raise ProcessDiscoveryError(
            f"Could not locate active CockroachDB process for target pod '{target_pod}' in {proc_root}."
        )

    if len(matching_pids) > 1:
        raise ProcessDiscoveryError(
            f"Ambiguous process discovery: multiple matching CockroachDB processes found for '{target_pod}': {matching_pids}."
        )

    discovered_pid = matching_pids[0]
    pid_dir = os.path.join(proc_root, str(discovered_pid))
    netns_file = os.path.join(pid_dir, "ns", "net")
    stat_file = os.path.join(pid_dir, "stat")

    if not os.path.exists(netns_file):
        raise ProcessDiscoveryError(f"Target process netns link does not exist: {netns_file}")

    try:
        target_netns_inode = os.readlink(netns_file)
    except OSError:
        st = os.stat(netns_file)
        target_netns_inode = f"net:[{st.st_ino}]"

    # Start time ticks verification
    start_ticks = None
    if os.path.exists(stat_file):
        try:
            with open(stat_file, "r", encoding="utf-8", errors="ignore") as sf:
                start_ticks = parse_start_time_ticks(sf.read())
        except (OSError, IOError):
            pass

    if expected_start_time_ticks is not None:
        if start_ticks is None or start_ticks != expected_start_time_ticks:
            raise ProcessDiscoveryError(
                f"Target process restart / PID reuse detected: expected start_time_ticks={expected_start_time_ticks}, "
                f"observed={start_ticks} (PID {discovered_pid})."
            )

    if expected_netns_inode:
        if target_netns_inode != expected_netns_inode:
            raise ProcessDiscoveryError(
                f"Network namespace inode mismatch: expected '{expected_netns_inode}', "
                f"observed '{target_netns_inode}' for target process PID {discovered_pid}."
            )

    return {
        "pid": discovered_pid,
        "netns_inode": target_netns_inode,
        "netns_path": netns_file,
        "start_time_ticks": start_ticks,
    }

