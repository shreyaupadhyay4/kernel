import argparse
import json
import sys
import time
from collections import deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aegis_pipeline import build_analysis_bundle
from agent.mitre import map_execution_behavior
from agent.telemetry_schema import normalize_event
from detector.graph_builder import score_graph_anomaly

ROOT = Path(__file__).resolve().parent
INDEX = ROOT / "index.html"
SAMPLE_EVENTS = [
    {
        "ts": 1,
        "pid": 4421,
        "ppid": 2683,
        "uid": 1000,
        "comm": "bash",
        "file": "/bin/bash",
    },
    {
        "ts": 2,
        "pid": 4422,
        "ppid": 4421,
        "uid": 1000,
        "comm": "curl",
        "file": "/usr/bin/curl",
    },
    {
        "ts": 3,
        "pid": 4423,
        "ppid": 4421,
        "uid": 1000,
        "comm": "sh",
        "file": "/bin/sh",
    },
    {
        "ts": 4,
        "pid": 4422,
        "ppid": 4421,
        "uid": 1000,
        "comm": "curl",
        "event_type": "connect",
        "dest_ip": "198.51.100.12",
        "dest_port": 443,
    },
]


def load_normalized_events(path: Path, *, max_events: int = 500) -> list[dict]:
    if max_events <= 0:
        raise ValueError("max_events must be greater than zero")

    events: deque[dict] = deque(maxlen=max_events)
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                payload = json.loads(line)
                events.append(normalize_event(payload))
            except (json.JSONDecodeError, ValueError):
                continue
    return list(events)


def build_snapshot(events: list[dict], *, source: str):
    if not events:
        return {
            "timestamp": int(time.time()),
            "source": source,
            "event": None,
            "analysis": None,
            "nodes": [],
            "edges": [],
            "anomaly_score": 0.0,
            "alerts": [],
        }

    recent_events = events[-500:]
    analysis = build_analysis_bundle(recent_events)
    graph = analysis["graph_snapshot"]
    nodes = graph["nodes"]
    edges = graph["edges"]
    alerts = analysis["alerts"]
    alerted_pids = {
        pid
        for alert in alerts
        for pid in (alert.get("shell_pid"), alert.get("downloader_pid"))
        if isinstance(pid, int)
    }
    process_nodes = [node for node in nodes if node.get("type") == "Process"]
    processes_by_pid = {node["pid"]: node for node in process_nodes}
    parent_by_pid = {
        edge["target"]: edge["source"]
        for edge in edges
        if edge["relationship"] == "SPAWNED"
        and isinstance(edge["source"], int)
        and isinstance(edge["target"], int)
    }
    focus_pids = alerted_pids or {analysis["process_data"]["pid"]}
    selected_pids = set()

    for focus_pid in focus_pids:
        current_pid = focus_pid
        lineage_depth = 0
        while current_pid in processes_by_pid and current_pid not in selected_pids:
            selected_pids.add(current_pid)
            if lineage_depth >= 3:
                break
            parent_pid = parent_by_pid.get(current_pid)
            if not isinstance(parent_pid, int) or parent_pid <= 0:
                break
            current_pid = parent_pid
            lineage_depth += 1

    selected_process_nodes = [
        node for node in process_nodes if node["pid"] in selected_pids
    ]
    process_depths = {}
    for node in selected_process_nodes:
        depth = 0
        current_pid = node["pid"]
        visited = {current_pid}
        while current_pid in parent_by_pid:
            parent_pid = parent_by_pid[current_pid]
            if parent_pid not in selected_pids or parent_pid in visited:
                break
            visited.add(parent_pid)
            current_pid = parent_pid
            depth += 1
        process_depths[node["pid"]] = depth

    visible_process_ids = {node["id"] for node in selected_process_nodes}
    connected_resources = {
        edge["target"]
        for edge in edges
        if edge["source"] in visible_process_ids
        and isinstance(edge["target"], str)
    }
    resources_by_id = {
        node["id"]: node
        for node in nodes
        if node.get("type") != "Process" and node["id"] in connected_resources
    }
    selected_resources = list(resources_by_id.values())[-4:]

    positions = {}
    nodes_by_depth = {}
    for node in selected_process_nodes:
        nodes_by_depth.setdefault(process_depths[node["pid"]], []).append(node)
    for depth, level_nodes in nodes_by_depth.items():
        for index, node in enumerate(level_nodes):
            positions[node["id"]] = {
                "x": 150 + depth * 240,
                "y": 100 + index * min(110, 500 // max(len(level_nodes), 1)),
            }
    resource_x = 150 + (max(process_depths.values(), default=0) + 1) * 240
    for index, node in enumerate(selected_resources):
        positions[node["id"]] = {"x": resource_x, "y": 100 + index * 100}

    visible_nodes = []
    selected_nodes = selected_process_nodes + selected_resources
    for node in selected_nodes:
        position = positions.get(node["id"])
        if position is None:
            continue
        if node.get("event_type") == "parent":
            label = "unobserved parent"
            full_label = "Parent process was not observed"
        elif node.get("type") == "Process":
            full_label = node.get("file") or node.get("comm", "unknown")
            label = Path(str(full_label)).name or node.get("comm", "unknown")
        elif node.get("type") == "File":
            full_label = node.get("path", "unknown file")
            path_parts = str(full_label).strip("/").split("/")
            label = "/".join(path_parts[-3:]) if len(path_parts) > 1 else str(full_label)
        else:
            label = node.get("comm") or node.get("path") or node.get("ip")
            full_label = str(label or node.get("type", "unknown"))
        if node.get("type") == "Socket":
            label = f"{node['ip']}:{node['port']}"
            full_label = label
        visible_nodes.append(
            {
                "id": node["id"],
                "pid": node.get("pid"),
                "type": node.get("type", "Unknown"),
                "label": str(label or node.get("type", "unknown")),
                "full_label": str(full_label),
                **position,
                "color": (
                    "#f87171"
                    if node.get("type") == "Process" and node.get("pid") in alerted_pids
                    else {
                        "Process": "#3b82f6",
                        "File": "#d97706",
                        "Socket": "#0891b2",
                    }.get(node.get("type"), "#64748b")
                ),
            }
        )

    visible_ids = {node["id"] for node in visible_nodes}
    visible_edges = [
        {
            "source": edge["source"],
            "target": edge["target"],
            "label": edge["relationship"].lower(),
        }
        for edge in edges
        if edge["source"] in visible_ids and edge["target"] in visible_ids
    ]

    event = recent_events[-1]
    process_name = event.get("file", event["comm"])
    latest_event = {
        "pid": event["pid"],
        "process": process_name,
        "event_type": event["event_type"],
        "anomaly_score": score_graph_anomaly(graph),
        "mitre": [map_execution_behavior(process_name)]
        if map_execution_behavior(process_name)
        else [],
    }
    return {
        "timestamp": int(time.time()),
        "source": source,
        "event": latest_event,
        "analysis": {
            "decision": analysis["final_decision"],
            "requires_human_approval": analysis["results"]["decision_report"][
                "requires_human_approval"
            ],
            "risk_level": analysis["results"]["forensic_report"]["risk_level"],
            "target_pid": analysis["process_data"]["pid"],
            "target_process": analysis["process_data"]["process_name"],
            "target_score": analysis["results"]["forensic_report"]["anomaly_score"],
            "target_technique": analysis["results"]["red_team_report"]["technique"],
            "reason": analysis["results"]["decision_report"]["reason"],
        },
        "nodes": visible_nodes,
        "edges": visible_edges,
        "graph_context": {
            "focus": "alert lineage" if alerts else "recommended process lineage",
            "process_count": len(selected_process_nodes),
            "resource_count": len(selected_resources),
        },
        "anomaly_score": latest_event["anomaly_score"],
        "alerts": alerts,
    }


class DashboardHandler(BaseHTTPRequestHandler):
    events_path: Path | None = None

    def _snapshot(self):
        if self.events_path is None:
            events = SAMPLE_EVENTS
            source = "Simulated sample events"
        else:
            events = load_normalized_events(self.events_path)
            source = f"Live JSONL: {self.events_path}"
        return build_snapshot(events, source=source)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/":
            self._serve_file(INDEX)
            return
        if parsed.path == "/health":
            self._send_json({"ok": True, "service": "aegis-dashboard"})
            return
        if parsed.path == "/api/graph":
            try:
                self._send_json(self._snapshot())
            except OSError as error:
                self._send_json({"error": f"Cannot read telemetry file: {error}"}, status=500)
            return
        if parsed.path == "/events":
            self._serve_sse()
            return
        self.send_error(404, "Not found")

    def _send_json(self, payload, *, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(payload).encode())

    def _serve_file(self, path: Path):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(path.read_bytes())

    def _serve_sse(self):
        self.send_response(200)
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()

        while True:
            try:
                payload = self._snapshot()
                self.wfile.write(f"data: {json.dumps(payload)}\n\n".encode())
            except OSError as error:
                if isinstance(error, (BrokenPipeError, ConnectionResetError)):
                    return
                payload = {"error": f"Cannot read telemetry file: {error}"}
                try:
                    self.wfile.write(f"event: error\ndata: {json.dumps(payload)}\n\n".encode())
                    self.wfile.flush()
                except (BrokenPipeError, ConnectionResetError):
                    return
                time.sleep(2.0)
                continue
            try:
                self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError):
                return
            time.sleep(2.0)

    def log_message(self, *args, **kwargs):
        return


def serve(host: str = "127.0.0.1", port: int = 8000, events_path: Path | None = None):
    handler = type("ConfiguredDashboardHandler", (DashboardHandler,), {"events_path": events_path})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"AegisKernel dashboard listening on http://{host}:{port}")
    if events_path is None:
        print("Dashboard source: simulated sample events")
    else:
        print(f"Dashboard source: {events_path}")
    server.serve_forever()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Serve the AegisKernel threat graph dashboard")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument(
        "--events",
        type=Path,
        help="Read and refresh the dashboard from a telemetry JSONL file",
    )
    args = parser.parse_args()
    serve(host=args.host, port=args.port, events_path=args.events)
