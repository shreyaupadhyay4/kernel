import json
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, Iterable

from agent.detect import WINDOW_NS
from agent.telemetry_schema import normalize_event

try:
    from kafka import KafkaConsumer
except ImportError:  # pragma: no cover
    KafkaConsumer = None  # type: ignore[assignment]

try:
    from neo4j import GraphDatabase
except ImportError:  # pragma: no cover
    GraphDatabase = None  # type: ignore[assignment]


SHELL_NAMES = {"bash", "sh", "dash", "cmd.exe", "powershell", "pwsh", "zsh"}
DOWNLOADERS = {"curl", "wget"}


def build_graph_snapshot(events: Iterable[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[int | str, int | str, str], dict[str, Any]] = {}

    for raw_event in events:
        if not isinstance(raw_event, dict):
            continue
        normalized = normalize_event(raw_event)
        pid = normalized["pid"]
        process_id = f"process:{pid}"
        process_node = nodes.setdefault(
            process_id,
            {
                "id": pid,
                "type": "Process",
                "pid": pid,
                "ppid": normalized["ppid"],
                "uid": normalized["uid"],
                "comm": normalized["comm"],
                "file": normalized.get("file"),
                "event_type": normalized["event_type"],
                "first_seen_ts": normalized["ts"],
                "last_seen_ts": normalized["ts"],
                "event_count": 0,
            },
        )
        process_node["first_seen_ts"] = min(
            process_node.get("first_seen_ts", normalized["ts"]), normalized["ts"]
        )
        process_node["last_seen_ts"] = max(
            process_node.get("last_seen_ts", normalized["ts"]), normalized["ts"]
        )
        process_node["event_count"] = process_node.get("event_count", 0) + 1
        process_node.update(
            {
                "ppid": normalized["ppid"],
                "uid": normalized["uid"],
                "comm": normalized["comm"],
            }
        )
        if process_node.get("event_type") == "parent":
            process_node["event_type"] = normalized["event_type"]
        if normalized["event_type"] == "exec":
            process_node["file"] = normalized["file"]
            process_node["event_type"] = "exec"
            process_node["exec_ts"] = normalized["ts"]

        ppid = normalized["ppid"]
        if normalized["event_type"] == "exec" and ppid is not None and ppid != pid:
            parent_id = f"process:{ppid}"
            nodes.setdefault(
                parent_id,
                {
                    "id": ppid,
                    "type": "Process",
                    "pid": ppid,
                    "ppid": None,
                    "uid": None,
                    "comm": "unknown",
                    "file": "unknown",
                    "event_type": "parent",
                },
            )
            edges[(ppid, pid, "SPAWNED")] = {
                "source": ppid,
                "target": pid,
                "relationship": "SPAWNED",
            }

        if normalized["event_type"] == "file_open":
            file_id = f"file:{normalized['path']}"
            nodes.setdefault(
                file_id,
                {"id": file_id, "type": "File", "path": normalized["path"]},
            )
            edges[(pid, file_id, "OPENED")] = {
                "source": pid,
                "target": file_id,
                "relationship": "OPENED",
            }
        elif normalized["event_type"] == "connect":
            socket_id = f"socket:{normalized['dest_ip']}:{normalized['dest_port']}"
            nodes.setdefault(
                socket_id,
                {
                    "id": socket_id,
                    "type": "Socket",
                    "ip": normalized["dest_ip"],
                    "port": normalized["dest_port"],
                },
            )
            edges[(pid, socket_id, "CONNECTED_TO")] = {
                "source": pid,
                "target": socket_id,
                "relationship": "CONNECTED_TO",
            }

    return {"nodes": list(nodes.values()), "edges": list(edges.values())}


def _process_name(node: dict[str, Any]) -> str:
    value = node.get("file") or node.get("comm") or ""
    if not isinstance(value, str):
        return ""
    posix_name = PurePosixPath(value).name
    windows_name = PureWindowsPath(value).name
    return min((posix_name, windows_name), key=lambda name: (name == "", len(name))).lower()


def graph_anomaly_features(
    graph_snapshot: dict[str, list[dict[str, Any]]],
) -> dict[str, Any]:
    nodes = graph_snapshot.get("nodes", [])
    edges = graph_snapshot.get("edges", [])
    if not isinstance(nodes, list) or not isinstance(edges, list):
        return {
            "score": 0.0,
            "features": [],
            "correlated_download_shell": False,
            "downloader_network_activity": False,
            "related_child_count": 0,
        }

    processes = [
        node for node in nodes
        if isinstance(node, dict)
        and (node.get("type") == "Process" or "pid" in node)
    ]
    if not processes:
        return {
            "score": 0.0,
            "features": [],
            "correlated_download_shell": False,
            "downloader_network_activity": False,
            "related_child_count": 0,
        }

    shells = {
        node.get("pid")
        for node in processes
        if (
            _process_name(node) in SHELL_NAMES
            or _process_name(node).removesuffix(".exe") in SHELL_NAMES
        )
        and isinstance(node.get("pid"), int)
        and not isinstance(node.get("pid"), bool)
    }
    downloaders = {
        node.get("pid")
        for node in processes
        if _process_name(node) in DOWNLOADERS
        and isinstance(node.get("pid"), int)
        and not isinstance(node.get("pid"), bool)
    }

    score = (0.08 if shells else 0.0) + (0.08 if downloaders else 0.0)
    feature_labels = []
    if shells:
        feature_labels.append("shell process observed")
    if downloaders:
        feature_labels.append("download utility observed")
    spawned_children: dict[int, set[int]] = {}
    for edge in edges:
        if not isinstance(edge, dict) or edge.get("relationship") != "SPAWNED":
            continue
        parent, child = edge.get("source"), edge.get("target")
        if (
            isinstance(parent, int) and not isinstance(parent, bool)
            and isinstance(child, int) and not isinstance(child, bool)
        ):
            spawned_children.setdefault(parent, set()).add(child)

    node_by_pid = {
        node["pid"]: node
        for node in processes
        if isinstance(node.get("pid"), int) and not isinstance(node.get("pid"), bool)
    }
    children_by_parent = {}
    for pid, node in node_by_pid.items():
        parent_pid = node.get("ppid")
        if isinstance(parent_pid, int) and not isinstance(parent_pid, bool):
            children_by_parent.setdefault(parent_pid, set()).add(pid)
    for parent_pid, children in spawned_children.items():
        children_by_parent.setdefault(parent_pid, set()).update(children)

    def observed_exec_time(pid: int) -> int | None:
        node = node_by_pid.get(pid, {})
        timestamp = node.get("exec_ts", node.get("ts"))
        if isinstance(timestamp, int) and not isinstance(timestamp, bool):
            return timestamp
        return None

    has_related_shell_downloader = False
    for children in children_by_parent.values():
        for shell_pid in children & shells:
            shell_ts = observed_exec_time(shell_pid)
            for downloader_pid in children & downloaders:
                downloader_ts = observed_exec_time(downloader_pid)
                if (
                    shell_ts is not None
                    and downloader_ts is not None
                    and abs(shell_ts - downloader_ts) < WINDOW_NS
                ):
                    has_related_shell_downloader = True
                    break
            if has_related_shell_downloader:
                break
        if has_related_shell_downloader:
            break
    if has_related_shell_downloader:
        score += 0.55
        feature_labels.append(
            "shell and downloader started under one parent within two seconds"
        )

    downloader_network_activity = bool(downloaders) and any(
        isinstance(edge, dict)
        and edge.get("relationship") == "CONNECTED_TO"
        and edge.get("source") in downloaders
        for edge in edges
    )
    if downloader_network_activity:
        score += 0.08
        feature_labels.append("downloader made a network connection")

    related_child_count = sum(map(len, children_by_parent.values()))
    if related_child_count:
        score += min(0.08, 0.02 * related_child_count)
        feature_labels.append(f"{related_child_count} parent-child relationships observed")

    return {
        "score": round(min(score, 1.0), 3),
        "features": feature_labels or ["no suspicious process pattern observed"],
        "correlated_download_shell": has_related_shell_downloader,
        "downloader_network_activity": downloader_network_activity,
        "related_child_count": related_child_count,
    }


def score_graph_anomaly(graph_snapshot: dict[str, list[dict[str, Any]]]) -> float:
    return graph_anomaly_features(graph_snapshot)["score"]


def process_context_graph(
    graph_snapshot: dict[str, list[dict[str, Any]]], pid: int
) -> dict[str, list[dict[str, Any]]]:
    nodes = graph_snapshot.get("nodes", [])
    edges = graph_snapshot.get("edges", [])
    if not isinstance(pid, int) or isinstance(pid, bool):
        return {"nodes": [], "edges": []}
    process_nodes = [
        node for node in nodes
        if isinstance(node, dict)
        and (node.get("type") == "Process" or "pid" in node)
    ] if isinstance(nodes, list) else []
    target = next(
        (node for node in process_nodes if node.get("pid") == pid),
        None,
    )
    if target is None:
        return {"nodes": [], "edges": []}

    target_name = _process_name(target)
    target_is_indicator = (
        target_name in DOWNLOADERS
        or target_name in SHELL_NAMES
        or target_name.removesuffix(".exe") in SHELL_NAMES
    )
    related_pids = {pid}
    if target_is_indicator:
        parent_pid = target.get("ppid")
        if isinstance(parent_pid, int) and not isinstance(parent_pid, bool):
            related_pids.add(parent_pid)
            related_pids.update(
                node["pid"]
                for node in process_nodes
                if isinstance(node.get("pid"), int)
                and not isinstance(node.get("pid"), bool)
                and node.get("ppid") == parent_pid
            )
    else:
        related_pids.update(
            node["pid"]
            for node in process_nodes
            if isinstance(node.get("pid"), int)
            and not isinstance(node.get("pid"), bool)
            and node.get("ppid") == pid
        )

    focused_nodes = [
        node for node in process_nodes
        if node.get("pid") in related_pids
    ]
    focused_ids = {node.get("id", node.get("pid")) for node in focused_nodes}
    if isinstance(edges, list):
        resource_ids = {
            edge.get("target")
            for edge in edges
            if isinstance(edge, dict)
            and edge.get("source") in related_pids
            and isinstance(edge.get("target"), str)
        }
        focused_nodes.extend(
            node for node in nodes
            if isinstance(node, dict) and node.get("id") in resource_ids
        )
        focused_ids.update(resource_ids)
        focused_edges = [
            edge for edge in edges
            if isinstance(edge, dict)
            and edge.get("source") in focused_ids
            and edge.get("target") in focused_ids
        ]
    else:
        focused_edges = []

    return {"nodes": focused_nodes, "edges": focused_edges}


def score_process_anomaly(
    graph_snapshot: dict[str, list[dict[str, Any]]], pid: int
) -> float:
    return score_graph_anomaly(process_context_graph(graph_snapshot, pid))


def ingest_to_graph(tx, pid: int, process_name: str, uid: int | None):
    query = """
    MERGE (p:Process {pid: $pid})
    SET p.name = $name, p.uid = $uid
    MERGE (u:User {uid: $uid})
    MERGE (u)-[:EXECUTED]->(p)
    """
    tx.run(query, pid=pid, name=process_name, uid=uid)


def load_jsonl(path: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def main(path: str) -> None:
    if GraphDatabase is None:
        raise RuntimeError("neo4j is not installed in this environment")

    if KafkaConsumer is None:
        raise RuntimeError("kafka-python is not installed in this environment")

    URI = "bolt://localhost:7687"
    driver = GraphDatabase.driver(URI, auth=("", ""))
    consumer = KafkaConsumer(
        "aegis-telemetry",
        bootstrap_servers=["localhost:9092"],
        value_deserializer=lambda m: json.loads(m.decode("utf-8")),
    )

    print("🕸️ Graph Builder active. Listening for telemetry...")
    try:
        with driver.session() as session:
            for message in consumer:
                data = message.value
                session.write_transaction(
                    ingest_to_graph,
                    data["pid"],
                    data["process_name"],
                    data.get("uid"),
                )
                print(f"[Graph] Node Created: User {data.get('uid')} -> Process {data['process_name']}")
    finally:
        driver.close()


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: python detector/graph_builder.py <events.jsonl>")
    events = load_jsonl(sys.argv[1])
    graph = build_graph_snapshot(events)
    print(f"Loaded {len(graph['nodes'])} nodes and {len(graph['edges'])} edges")
    print(f"Graph anomaly score: {score_graph_anomaly(graph)}")
