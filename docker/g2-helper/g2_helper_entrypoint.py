"""
g2_helper_entrypoint.py - Container entrypoint for G2 packet-loss helper daemon.
"""

import os
import sys

from g2_authorizer import G2HelperFaultAuthorizer
from g2_helper_daemon import (
    G2HelperConfig,
    G2TwoPhaseHelperController,
    EXIT_CODES,
    AutonomousWatchdog,
)
from g2_packet_loss_runtime import G2LinuxRuntime, NetnsIdentity
from g2_process_discovery import discover_target_process, ProcessDiscoveryError


def run_diagnostic_mode() -> int:
    """
    Controlled non-fault diagnostic mode:
    - Reads host /proc to find target CockroachDB pod process.
    - Resolves and verifies target process network namespace inode.
    - Inspects interface and verifies current qdisc is default (no netem).
    - Arms and disarms AutonomousWatchdog.
    - Strictly CANNOT inject packet loss, modify qdiscs, or execute pgbench.
    - Exits cleanly with code 0 upon verified read-only inspection.
    """
    target_pod = os.environ.get("G2_TARGET_POD", "")
    interface = os.environ.get("G2_TARGET_INTERFACE", "eth0")
    expected_inode = os.environ.get("G2_EXPECTED_NETNS_INODE", "")
    target_pod_uid = os.environ.get("G2_TARGET_POD_UID", "")
    target_container_id = os.environ.get("G2_TARGET_CONTAINER_ID", "")

    sys.stdout.write(f"[DIAGNOSTIC] Initializing non-fault diagnostic runtime for target pod '{target_pod}'...\n")

    if not target_pod:
        sys.stderr.write("[DIAGNOSTIC ERROR] Missing G2_TARGET_POD\n")
        return 1

    try:
        proc_info = discover_target_process(
            target_pod=target_pod,
            proc_root="/proc",
            target_pod_uid=target_pod_uid,
            target_container_id=target_container_id,
            expected_netns_inode=expected_inode if expected_inode else None,
        )
    except ProcessDiscoveryError as exc:
        sys.stderr.write(f"[DIAGNOSTIC ERROR] Target process discovery failed: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[DIAGNOSTIC ERROR] Failed reading host /proc: {exc}\n")
        return 1

    target_pid = proc_info["pid"]
    target_netns_inode = proc_info["netns_inode"]
    netns_path = proc_info["netns_path"]

    sys.stdout.write(
        f"[DIAGNOSTIC] Located CockroachDB process PID {target_pid}, netns: {target_netns_inode}, "
        f"start_ticks: {proc_info.get('start_time_ticks')}\n"
    )

    # Verify setns capability and inspect interface qdisc read-only
    netns = NetnsIdentity(ns_inode=target_netns_inode, path=netns_path)
    runtime = G2LinuxRuntime()

    try:
        qdisc_out = runtime.inspect_interface_and_qdisc(netns, interface=interface)
        sys.stdout.write(f"[DIAGNOSTIC] Successfully inspected {interface} in {target_netns_inode}:\n{qdisc_out}\n")
        if "netem" in qdisc_out:
            sys.stderr.write(f"[DIAGNOSTIC ERROR] Unexpected pre-existing netem qdisc detected: {qdisc_out}\n")
            return 1
    except Exception as exc:
        sys.stderr.write(f"[DIAGNOSTIC ERROR] Failed read-only inspection of interface {interface}: {exc}\n")
        return 1

    # Verify watchdog arming and disarming without side-effects
    watchdog_cleared = [False]
    def noop_cleanup():
        watchdog_cleared[0] = True

    watchdog = AutonomousWatchdog(timeout_sec=10.0, cleanup_fn=noop_cleanup)
    watchdog.arm()
    status_armed = watchdog.check_status()
    watchdog.disarm()
    status_disarmed = watchdog.check_status()

    sys.stdout.write(f"[DIAGNOSTIC] Watchdog test: armed={status_armed}, disarmed={status_disarmed}\n")
    if status_armed != "ARMED" or status_disarmed != "DISARMED":
        sys.stderr.write("[DIAGNOSTIC ERROR] Watchdog lifecycle test failed\n")
        return 1

    sys.stdout.write("[DIAGNOSTIC SUCCESS] Non-fault runtime verification complete. Zero traffic altered.\n")
    return 0


def main() -> int:
    mode = os.environ.get("G2_HELPER_MODE", "FAULT")
    if mode == "DIAGNOSTIC":
        return run_diagnostic_mode()

    run_id = os.environ.get("G2_RUN_ID", "")
    target_pod = os.environ.get("G2_TARGET_POD", "")
    loss_str = os.environ.get("G2_LOSS_PERCENTAGE", "")
    namespace = os.environ.get("G2_TARGET_NAMESPACE", "cockroachdb")
    interface = os.environ.get("G2_TARGET_INTERFACE", "eth0")
    duration_str = os.environ.get("G2_DURATION_SEC", "180")
    auth_dir = os.environ.get("G2_AUTH_TOKEN_DIR", "/var/run/g2-auth")
    lock_dir = os.environ.get("G2_AUTH_LOCK_DIR", "/var/run/g2-lock")
    expected_inode = os.environ.get("G2_EXPECTED_NETNS_INODE", "")
    target_pod_uid = os.environ.get("G2_TARGET_POD_UID", "")
    target_container_id = os.environ.get("G2_TARGET_CONTAINER_ID", "")
    start_ticks_str = os.environ.get("G2_EXPECTED_START_TIME_TICKS", "")

    try:
        loss_percentage = int(loss_str)
        duration_sec = int(duration_str)
        expected_start_ticks = int(start_ticks_str) if start_ticks_str else None
    except ValueError as exc:
        sys.stderr.write(f"[ERROR] Invalid numeric parameters: {exc}\n")
        return 1

    # Discovered host PID and netns for target CockroachDB process
    try:
        proc_info = discover_target_process(
            target_pod=target_pod,
            proc_root="/proc",
            target_pod_uid=target_pod_uid,
            target_container_id=target_container_id,
            expected_netns_inode=expected_inode if expected_inode else None,
            expected_start_time_ticks=expected_start_ticks,
        )
    except ProcessDiscoveryError as exc:
        sys.stderr.write(f"[ERROR] Target process discovery failed: {exc}\n")
        return 1
    except Exception as exc:
        sys.stderr.write(f"[ERROR] Unexpected error during process discovery: {exc}\n")
        return 1

    target_pid = proc_info["pid"]
    discovered_inode = proc_info["netns_inode"]

    sys.stdout.write(
        f"[INFO] Discovered target CockroachDB PID {target_pid} (inode={discovered_inode}, "
        f"start_ticks={proc_info.get('start_time_ticks')})\n"
    )

    config = G2HelperConfig(
        run_id=run_id,
        target_pod=target_pod,
        loss_percentage=loss_percentage,
        target_namespace=namespace,
        target_interface=interface,
        duration_sec=duration_sec,
        expected_netns_inode=discovered_inode,
        expected_pid=target_pid,
    )

    authorizer = G2HelperFaultAuthorizer(
        base_dir=auth_dir,
        lock_dir=lock_dir,
        allow_readonly_secret=True,
    )

    controller = G2TwoPhaseHelperController(
        config=config,
        authorizer=authorizer,
        runtime_factory=lambda: G2LinuxRuntime(),
    )

    return controller.run()


if __name__ == "__main__":
    sys.exit(main())
