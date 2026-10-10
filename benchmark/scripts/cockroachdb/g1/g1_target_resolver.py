"""
g1_target_resolver.py - Dynamic Target Resolver for CockroachDB Scenario G1.

Features:
- Injectable database metadata provider (supports mock testing).
- Discovers physical ranges for target tables (e.g. pgbench_accounts).
- Evaluates candidate selection policies to map "Logical Range 1" to a physical range.
- Flags the 'aid=1' selection rule as PROVISIONAL pending supervisor approval.
- Emits explicit warnings when fallback lexicographical sorting is invoked.
- Aborts on ambiguous or missing target range specifications.
- Dynamically queries active leaseholder SQL node ID.
- Maps SQL node ID to Kubernetes StatefulSet pod names and IP addresses without hardcoding.
"""

from typing import Dict, Any, List, Optional, Tuple
from abc import ABC, abstractmethod
import warnings


class RangeMetadata:
    def __init__(
        self,
        range_id: int,
        start_key: str,
        end_key: str,
        replicas: List[int],
        lease_holder: int,
        table_name: str = "pgbench_accounts"
    ):
        self.range_id = range_id
        self.start_key = start_key
        self.end_key = end_key
        self.replicas = replicas
        self.lease_holder = lease_holder
        self.table_name = table_name

    def to_dict(self) -> Dict[str, Any]:
        return {
            "range_id": self.range_id,
            "start_key": self.start_key,
            "end_key": self.end_key,
            "replicas": self.replicas,
            "lease_holder": self.lease_holder,
            "table_name": self.table_name,
        }


class NodeMetadata:
    def __init__(
        self,
        node_id: int,
        address: str,
        locality: str,
        is_live: bool,
        draining: bool,
        membership: str = "active"
    ):
        self.node_id = node_id
        self.address = address
        self.locality = locality
        self.is_live = is_live
        self.draining = draining
        self.membership = membership

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_id": self.node_id,
            "address": self.address,
            "locality": self.locality,
            "is_live": self.is_live,
            "draining": self.draining,
            "membership": self.membership,
        }


class PodMetadata:
    def __init__(
        self,
        pod_name: str,
        pod_ip: str,
        node_name: str,
        zone: str,
        is_ready: bool,
        containers: Optional[List[str]] = None,
    ):
        self.pod_name = pod_name
        self.pod_ip = pod_ip
        self.node_name = node_name
        self.zone = zone
        self.is_ready = is_ready
        self.containers = containers or ["db"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pod_name": self.pod_name,
            "pod_ip": self.pod_ip,
            "node_name": self.node_name,
            "zone": self.zone,
            "is_ready": self.is_ready,
            "containers": self.containers,
        }


class IDatabaseMetadataProvider(ABC):
    @abstractmethod
    def get_table_ranges(self, database: str, table: str) -> List[RangeMetadata]:
        pass

    def get_row_range(self, database: str, table: str, row_val: Any = 1) -> Optional[RangeMetadata]:
        """Optional query for exact row range via SHOW RANGE FROM TABLE ... FOR ROW (...)."""
        return None

    @abstractmethod
    def get_cluster_nodes(self) -> List[NodeMetadata]:
        pass


class IKubernetesMetadataProvider(ABC):
    @abstractmethod
    def get_statefulset_pods(self, namespace: str, statefulset_name: str) -> List[PodMetadata]:
        pass


class MockDatabaseMetadataProvider(IDatabaseMetadataProvider):
    def __init__(
        self,
        ranges: Optional[List[RangeMetadata]] = None,
        nodes: Optional[List[NodeMetadata]] = None,
        row_ranges: Optional[Dict[Any, RangeMetadata]] = None,
    ):
        self.ranges = ranges or []
        self.nodes = nodes or []
        self.row_ranges = row_ranges or {}

    def get_table_ranges(self, database: str, table: str) -> List[RangeMetadata]:
        return [r for r in self.ranges if r.table_name == table]

    def get_row_range(self, database: str, table: str, row_val: Any = 1) -> Optional[RangeMetadata]:
        if row_val in self.row_ranges:
            return self.row_ranges[row_val]
        # If not explicitly mapped in row_ranges, return None so fallback evaluates
        return None

    def get_cluster_nodes(self) -> List[NodeMetadata]:
        return self.nodes


class MockKubernetesMetadataProvider(IKubernetesMetadataProvider):
    def __init__(self, pods: Optional[List[PodMetadata]] = None):
        self.pods = pods or []

    def get_statefulset_pods(self, namespace: str, statefulset_name: str) -> List[PodMetadata]:
        return self.pods


class TargetResolutionError(Exception):
    pass


class TargetResolver:
    """
    Resolves the physical CockroachDB range, leaseholder node, and target Kubernetes pod
    for Scenario G1 based on a configurable selection policy.
    """

    POLICY_AID_1 = "INITIAL_KEY_SPAN_AID_1"  # PROVISIONAL: Range covering aid=1
    POLICY_MIN_RANGE_ID = "MIN_RANGE_ID"    # Alternative: Lowest numerical range ID
    VALID_POLICIES = [POLICY_AID_1, POLICY_MIN_RANGE_ID]

    def __init__(
        self,
        db_provider: IDatabaseMetadataProvider,
        k8s_provider: IKubernetesMetadataProvider,
        policy: str = POLICY_AID_1,
        namespace: str = "cockroachdb",
        statefulset_name: str = "cockroachdb",
        database_name: str = "benchdb",
        table_name: str = "pgbench_accounts"
    ):
        if policy not in self.VALID_POLICIES:
            raise TargetResolutionError(f"Ambiguous or invalid target selection policy: '{policy}'. Valid: {self.VALID_POLICIES}")

        self.db_provider = db_provider
        self.k8s_provider = k8s_provider
        self.policy = policy
        self.namespace = namespace
        self.statefulset_name = statefulset_name
        self.database_name = database_name
        self.table_name = table_name

    def resolve_logical_range_1(self) -> Tuple[RangeMetadata, bool]:
        """
        Applies the selection policy to identify which physical range corresponds to 'Logical Range 1'.
        Under Option 3 (Approved True Dynamic Row Targeting), first attempts direct row lookup for aid=1.
        Returns a tuple: (resolved_range_metadata, used_fallback_sort_boolean).
        """
        used_fallback = False

        if self.policy == self.POLICY_AID_1:
            # Step A: Native CockroachDB SHOW RANGE FOR ROW (1) lookup (Option 3 Approved)
            row_range = self.db_provider.get_row_range(self.database_name, self.table_name, row_val=1)
            if row_range is not None:
                if row_range.range_id <= 1:
                    raise TargetResolutionError(
                        f"Safety violation: Internal system range (range_id={row_range.range_id}) cannot be selected as a chaos target."
                    )
                return row_range, False

            # Step B: Fallback to table ranges enumeration
            ranges = self.db_provider.get_table_ranges(self.database_name, self.table_name)
            if not ranges:
                raise TargetResolutionError(f"No physical ranges found for table '{self.table_name}' in database '{self.database_name}'.")

            # Check for explicitly duplicated start keys across candidate ranges
            start_keys = [r.start_key for r in ranges]
            if len(start_keys) != len(set(start_keys)):
                raise TargetResolutionError(
                    f"Ambiguous target condition under policy '{self.policy}': Duplicate start keys detected across ranges. Aborting."
                )

            initial_ranges = [r for r in ranges if "<before:/Table/" in r.start_key]
            if len(initial_ranges) == 1:
                chosen, used_fallback = initial_ranges[0], False
            elif len(initial_ranges) > 1:
                raise TargetResolutionError(
                    f"Ambiguous target condition under policy '{self.policy}': Multiple candidate ranges with '<before:/Table/' found ({[r.range_id for r in initial_ranges]}). Aborting."
                )
            else:
                # Fallback: Sort lexicographically by start_key
                used_fallback = True
                warnings.warn(
                    f"[RESOLVER WARNING] No explicit '<before:/Table/' key found for '{self.table_name}'. "
                    f"Falling back to lexicographical start_key sort (Provisional Policy).",
                    UserWarning
                )
                sorted_by_start = sorted(ranges, key=lambda x: x.start_key)
                chosen, used_fallback = sorted_by_start[0], True

        elif self.policy == self.POLICY_MIN_RANGE_ID:
            ranges = self.db_provider.get_table_ranges(self.database_name, self.table_name)
            if not ranges:
                raise TargetResolutionError(f"No physical ranges found for table '{self.table_name}' in database '{self.database_name}'.")
            sorted_by_id = sorted(ranges, key=lambda x: x.range_id)
            chosen, used_fallback = sorted_by_id[0], False
        else:
            raise TargetResolutionError(f"Unsupported policy evaluation: {self.policy}")

        if chosen.range_id <= 1:
            raise TargetResolutionError(
                f"Safety violation: Internal system range (range_id={chosen.range_id}) cannot be selected as a chaos target."
            )
        return chosen, used_fallback

    @staticmethod
    def validate_target_freshness(
        reverified_target: Dict[str, Any],
        expected_range_id: Optional[int] = None
    ) -> None:
        """Rejects stale or system range IDs against freshly re-verified target metadata."""
        resolved_id = reverified_target.get("physical_range_id")
        if resolved_id is None or resolved_id <= 1:
            raise TargetResolutionError(
                f"Invalid or system physical_range_id ({resolved_id}) in re-verified target."
            )
        if expected_range_id is not None and resolved_id != expected_range_id:
            raise TargetResolutionError(
                f"Stale range ID rejected: expected range {expected_range_id}, but fresh discovery resolved range {resolved_id}."
            )

    def resolve_target(self) -> Dict[str, Any]:
        """
        Full end-to-end dynamic resolution:
        1. Resolve Logical Range 1 -> Physical Range.
        2. Identify leaseholder SQL node ID.
        3. Retrieve node address and metadata from cluster gossip.
        4. Map SQL node address to Kubernetes StatefulSet pod.
        5. Return resolved target descriptor.
        """
        # Step 1: Physical Range Resolution
        target_range, used_fallback = self.resolve_logical_range_1()
        lease_node_id = target_range.lease_holder
        if not lease_node_id:
            raise TargetResolutionError(f"Target range {target_range.range_id} has no valid leaseholder recorded.")

        # Validate that leaseholder is a member of the replica set
        if target_range.replicas and lease_node_id not in target_range.replicas:
            raise TargetResolutionError(
                f"Safety violation: Leaseholder node {lease_node_id} is not present in range {target_range.range_id} replica set {target_range.replicas}."
            )

        # Step 2: Node Resolution
        nodes = self.db_provider.get_cluster_nodes()
        target_node = next((n for n in nodes if n.node_id == lease_node_id), None)
        if not target_node:
            raise TargetResolutionError(f"Leaseholder SQL node {lease_node_id} not found in cluster gossip node list.")

        if not target_node.is_live or target_node.draining:
            raise TargetResolutionError(f"Leaseholder SQL node {lease_node_id} is not live or is draining (is_live={target_node.is_live}, draining={target_node.draining}).")

        # Step 3: Pod Mapping
        # CockroachDB node address contains the pod FQDN, e.g., 'cockroachdb-1.cockroachdb:26257' or IP '10.0.2.238'
        pods = self.k8s_provider.get_statefulset_pods(self.namespace, self.statefulset_name)
        if not pods:
            raise TargetResolutionError(f"No pods found for StatefulSet '{self.statefulset_name}' in namespace '{self.namespace}'.")

        matched_pod = None
        for pod in pods:
            if pod.pod_name in target_node.address or pod.pod_ip in target_node.address:
                matched_pod = pod
                break

        if not matched_pod:
            raise TargetResolutionError(
                f"Failed mapping SQL node {lease_node_id} (address '{target_node.address}') to any Kubernetes pod in {[p.pod_name for p in pods]}."
            )

        if not matched_pod.is_ready:
            raise TargetResolutionError(f"Target pod '{matched_pod.pod_name}' is not Ready.")

        target_container = matched_pod.containers[0] if matched_pod.containers else "db"

        return {
            "policy": self.policy,
            "policy_status": "PROVISIONAL_PENDING_SUPERVISOR_APPROVAL" if self.policy == self.POLICY_AID_1 else "APPROVED",
            "logical_target": "Range 1",
            "physical_range_id": target_range.range_id,
            "start_key": target_range.start_key,
            "end_key": target_range.end_key,
            "replicas": target_range.replicas,
            "lease_holder_node_id": lease_node_id,
            "node_address": target_node.address,
            "node_locality": target_node.locality,
            "target_pod_name": matched_pod.pod_name,
            "target_container_name": target_container,
            "target_pod_ip": matched_pod.pod_ip,
            "target_node_name": matched_pod.node_name,
            "target_zone": matched_pod.zone,
            "used_fallback_sort": used_fallback
        }
