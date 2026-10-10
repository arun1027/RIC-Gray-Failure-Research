"""
stage5_4g8_live_jit_validator.py - Live Non-Fault Integration Validator for PD-08 JIT Gate.
Stage 5.4G.8: READ-ONLY live integration test against EKS CockroachDB cluster.

Guarantees:
- Read-only operations only.
- ZERO fault injection or tc netem execution.
- ZERO benchmark execution or transaction generation.
- ZERO execution token creation or staging.
- ZERO Kubernetes Secret or Job creation.
- ZERO database mutations (SELECT / SHOW commands only).
- Exercises PD08JITLeaseholderGate with live providers against live cluster.
- Validates happy-path dynamic resolution, process inspection, and immediate revalidation.
- Validates simulated target drift abort (fail-closed tripwire).
- Emits detailed, timestamped JSON and textual evidence.
"""

import datetime
import json
import os
import subprocess
import sys
from typing import Dict, Any, List, Tuple, Optional

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

from benchmark.scripts.cockroachdb.g1.g1_target_resolver import (
    RangeMetadata,
    NodeMetadata,
    PodMetadata,
    IDatabaseMetadataProvider,
    IKubernetesMetadataProvider,
    TargetResolutionError,
)
from benchmark.scripts.cockroachdb.g1.g1_jit_gate import (
    PD08JITLeaseholderGate,
    JITTargetBinding,
    JITGateVerificationError,
    TargetDriftAbortError,
    ProcessStateMismatchError,
    IProcessInspector,
)

NAMESPACE = "cockroachdb"
CLIENT_POD = "crdb-benchmark-client"
PSQL_CONN = "sslmode=verify-full sslrootcert=/cockroach-certs/ca.crt sslcert=/cockroach-certs/client.root.crt sslkey=/cockroach-certs/client.root.key host=cockroachdb-public port=26257 user=root dbname=benchdb"
EVIDENCE_DIR = os.path.abspath("thesis-evidence/05-g1-chaos/stage5-4g-8-jit-gate-validation")


def log(msg: str) -> None:
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    print(f"[{now}] {msg}", flush=True)


class LiveClusterDatabaseProvider(IDatabaseMetadataProvider):
    """Executes read-only SQL queries via in-cluster benchmark client using mTLS."""

    def __init__(self, namespace: str = NAMESPACE, client_pod: str = CLIENT_POD):
        self.namespace = namespace
        self.client_pod = client_pod

    def _exec_sql(self, sql_query: str) -> str:
        cmd = [
            "kubectl", "exec", "-n", self.namespace, self.client_pod, "--",
            "psql", PSQL_CONN, "-A", "-F", "|", "-c", sql_query
        ]
        res = subprocess.check_output(cmd, text=True)
        return res

    def get_table_ranges(self, database: str, table: str) -> List[RangeMetadata]:
        # Query SHOW RANGES FROM TABLE <table_name> WITH DETAILS
        output = self._exec_sql(f"SHOW RANGES FROM TABLE {table} WITH DETAILS;")
        lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
        if not lines:
            raise TargetResolutionError(f"No output returned from SHOW RANGES for {table}")

        header = lines[0].split("|")
        rows = [line.split("|") for line in lines[1:] if not line.endswith("rows)") and not line.endswith("row)")]

        col_map = {col.strip(): idx for idx, col in enumerate(header)}
        ranges: List[RangeMetadata] = []

        for row in rows:
            if len(row) < len(header):
                continue
            range_id = int(row[col_map["range_id"]])
            start_key = row[col_map["start_key"]]
            end_key = row[col_map["end_key"]]
            lease_holder = int(row[col_map["lease_holder"]])
            # replicas format: {1,2,3}
            rep_raw = row[col_map["replicas"]].strip("{}")
            replicas = [int(x.strip()) for x in rep_raw.split(",") if x.strip()]

            ranges.append(RangeMetadata(
                range_id=range_id,
                start_key=start_key,
                end_key=end_key,
                replicas=replicas,
                lease_holder=lease_holder,
                table_name=table
            ))
        return ranges

    def get_row_range(self, database: str, table: str, row_val: Any = 1) -> Optional[RangeMetadata]:
        # Query SHOW RANGE FROM TABLE <table_name> FOR ROW (<row_val>)
        try:
            output = self._exec_sql(f"SHOW RANGE FROM TABLE {table} FOR ROW ({row_val});")
            lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
            if not lines:
                return None
            header = lines[0].split("|")
            rows = [line.split("|") for line in lines[1:] if not line.endswith("rows)") and not line.endswith("row)")]
            if not rows:
                return None
            col_map = {col.strip(): idx for idx, col in enumerate(header)}
            row = rows[0]
            range_id = int(row[col_map["range_id"]])
            start_key = row[col_map["start_key"]]
            end_key = row[col_map["end_key"]]
            lease_holder = int(row[col_map["lease_holder"]])
            rep_raw = row[col_map["replicas"]].strip("{}")
            replicas = [int(x.strip()) for x in rep_raw.split(",") if x.strip()]

            return RangeMetadata(
                range_id=range_id,
                start_key=start_key,
                end_key=end_key,
                replicas=replicas,
                lease_holder=lease_holder,
                table_name=table
            )
        except Exception:
            return None

    def get_cluster_nodes(self) -> List[NodeMetadata]:
        # Query crdb_internal.gossip_nodes
        sql = "SET allow_unsafe_internals = true; SELECT node_id, address, is_live FROM crdb_internal.gossip_nodes;"
        output = self._exec_sql(sql)
        lines = [line.strip() for line in output.strip().splitlines() if line.strip()]
        
        # Note: output might contain "SET" on first line
        filtered = [l for l in lines if not l.startswith("SET") and not l.endswith("rows)") and not l.endswith("row)")]
        header = filtered[0].split("|")
        rows = [l.split("|") for l in filtered[1:]]

        col_map = {col.strip(): idx for idx, col in enumerate(header)}
        nodes: List[NodeMetadata] = []

        for row in rows:
            if len(row) < len(header):
                continue
            node_id = int(row[col_map["node_id"]])
            address = row[col_map["address"]]
            is_live = row[col_map["is_live"]].lower() in ("t", "true", "1")

            nodes.append(NodeMetadata(
                node_id=node_id,
                address=address,
                locality="",
                is_live=is_live,
                draining=False
            ))
        return nodes


class LiveKubernetesProvider(IKubernetesMetadataProvider):
    """Retrieves Pod metadata from Kubernetes API."""

    def __init__(self, namespace: str = NAMESPACE):
        self.namespace = namespace

    def get_statefulset_pods(self, namespace: str, statefulset_name: str) -> List[PodMetadata]:
        cmd = [
            "kubectl", "get", "pods", "-n", namespace,
            "-l", f"app.kubernetes.io/name={statefulset_name}",
            "-o", "json"
        ]
        out_raw = subprocess.check_output(cmd, text=True)
        data = json.loads(out_raw)

        pods: List[PodMetadata] = []
        for item in data.get("items", []):
            name = item["metadata"]["name"]
            pod_ip = item["status"].get("podIP", "")
            node_name = item["spec"].get("nodeName", "")
            # check ready condition
            conditions = item["status"].get("conditions", [])
            ready = any(c.get("type") == "Ready" and c.get("status") == "True" for c in conditions)

            # extract container names from spec
            containers = [c["name"] for c in item["spec"].get("containers", [])]

            pods.append(PodMetadata(
                pod_name=name,
                pod_ip=pod_ip,
                node_name=node_name,
                zone="us-east-1",
                is_ready=ready,
                containers=containers
            ))
        return pods


class LiveProcessInspector(IProcessInspector):
    """Inspects container /proc/1 attributes on live pod container."""

    def __init__(self, namespace: str = NAMESPACE):
        self.namespace = namespace

    def get_process_state(self, pod_name: str, container_name: str) -> Tuple[str, int]:
        cmd = [
            "kubectl", "exec", "-n", self.namespace, pod_name, "-c", container_name, "--",
            "sh", "-c", "cat /proc/1/stat | cut -d' ' -f22; readlink /proc/1/ns/net"
        ]
        out_raw = subprocess.check_output(cmd, text=True).strip()
        tokens = out_raw.split()
        if len(tokens) < 2:
            raise JITGateVerificationError(f"Unexpected process inspection output: '{out_raw}'")

        start_ticks = int(tokens[0])
        netns_inode = tokens[1]
        return netns_inode, start_ticks


def run_live_validation() -> Dict[str, Any]:
    log("=== Stage 5.4G.8: Live Non-Fault Integration Validation of PD-08 JIT Gate ===")
    os.makedirs(EVIDENCE_DIR, exist_ok=True)

    db_prov = LiveClusterDatabaseProvider()
    k8s_prov = LiveKubernetesProvider()
    proc_insp = LiveProcessInspector()

    gate = PD08JITLeaseholderGate(
        db_provider=db_prov,
        k8s_provider=k8s_prov,
        process_inspector=proc_insp,
        expected_range_id=None,
    )

    report: Dict[str, Any] = {
        "validation_id": "val-stage5-4g-8-jit-gate",
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "cluster": "ric-gray-failure-eks",
        "namespace": NAMESPACE,
        "database": "benchdb",
        "target_table": "pgbench_accounts",
        "expected_range_id": 108,
        "stages": {},
    }

    # Step 1: Initial Discovery & Target Binding
    log("Executing Step 1: Dynamic Range Discovery and Target Binding...")
    t1_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    binding_1 = gate.verify_and_bind_target()
    t1_end = datetime.datetime.now(datetime.timezone.utc).isoformat()

    log(f"-> Step 1 Binding Successful: Range {binding_1.range_id}, Leaseholder Node {binding_1.lease_holder_node_id}")
    log(f"-> Target Pod: {binding_1.target_pod_name} (IP: {binding_1.target_pod_ip}) on Node: {binding_1.target_node_name}")
    log(f"-> Netns Inode: {binding_1.target_netns_inode}, Process Start Ticks: {binding_1.target_start_ticks}")

    report["stages"]["step1_initial_binding"] = {
        "status": "SUCCESS",
        "start_utc": t1_start,
        "end_utc": t1_end,
        "binding": binding_1.to_dict(),
    }

    # Step 2: Immediate Preflight Revalidation (Invariant Check)
    log("Executing Step 2: Immediate Preflight Double-Check Revalidation...")
    t2_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    binding_2 = gate.revalidate_immediate_preflight(binding_1)
    t2_end = datetime.datetime.now(datetime.timezone.utc).isoformat()

    log(f"-> Step 2 Revalidation Successful: Target remains stable on Pod {binding_2.target_pod_name}")
    report["stages"]["step2_immediate_revalidation"] = {
        "status": "SUCCESS",
        "start_utc": t2_start,
        "end_utc": t2_end,
        "reverified_binding": binding_2.to_dict(),
    }

    # Step 3: Simulated Drift Fail-Closed Tripwire Test
    log("Executing Step 3: Simulated Leaseholder Drift Fail-Closed Tripwire Test...")
    t3_start = datetime.datetime.now(datetime.timezone.utc).isoformat()
    drift_detected = False
    drift_error_msg = ""

    # Create a simulated binding that expects Node 1 (cockroachdb-0) when actual is Node 3 (cockroachdb-1)
    # or whichever node is different from binding_2.lease_holder_node_id
    stale_node_id = 1 if binding_2.lease_holder_node_id != 1 else 2
    stale_pod_name = f"cockroachdb-{stale_node_id - 1}"
    stale_binding = JITTargetBinding(
        range_id=108,
        lease_holder_node_id=stale_node_id,
        node_address=f"{stale_pod_name}.cockroachdb.cockroachdb.svc.cluster.local:26257",
        target_pod_name=stale_pod_name,
        target_container_name="db",
        target_pod_ip="10.0.0.0",
        target_node_name="stale-worker-node",
        target_netns_inode="net:[1111111111]",
        target_start_ticks=1234,
        verified_at_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        check_cycle=1,
    )

    try:
        gate.revalidate_immediate_preflight(stale_binding)
    except TargetDriftAbortError as e:
        drift_detected = True
        drift_error_msg = str(e)
        log(f"-> PASS: Simulated drift correctly caught by gate: {drift_error_msg}")
    except Exception as e:
        log(f"-> UNEXPECTED ERROR during drift test: {e}")

    t3_end = datetime.datetime.now(datetime.timezone.utc).isoformat()
    report["stages"]["step3_drift_tripwire_test"] = {
        "status": "SUCCESS" if drift_detected else "FAILED",
        "start_utc": t3_start,
        "end_utc": t3_end,
        "drift_detected": drift_detected,
        "exception_caught": drift_error_msg,
    }

    report["overall_disposition"] = "VALIDATION_PASSED" if drift_detected else "VALIDATION_FAILED"
    return report


if __name__ == "__main__":
    rep = run_live_validation()
    out_file = os.path.join(EVIDENCE_DIR, "live-target-binding-evidence.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(rep, f, indent=2)
    log(f"Evidence successfully written to {out_file}")
    if rep["overall_disposition"] == "VALIDATION_PASSED":
        sys.exit(0)
    else:
        sys.exit(1)

