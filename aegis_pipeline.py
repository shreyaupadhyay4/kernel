from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from agent.detect import detect_download_shell_chains
from agent.telemetry_schema import normalize_event
from detector.graph_builder import (
    build_graph_snapshot,
    score_graph_anomaly,
    score_process_anomaly,
)
from swarm.agent_graph import aegis_swarm


def load_events(path: str | Path) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    with Path(path).open("r", encoding="utf-8") as handle:
        for line in handle:
            try:
                payload = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(payload, dict):
                events.append(payload)
    return events


def build_analysis_bundle(events: list[dict[str, Any]]) -> dict[str, Any]:
    normalized = []
    for event in events:
        try:
            normalized.append(normalize_event(event))
        except ValueError:
            continue

    if not normalized:
        raise ValueError("No valid telemetry events were found")

    graph_snapshot = build_graph_snapshot(normalized)
    graph_anomaly = score_graph_anomaly(graph_snapshot)
    alerts = detect_download_shell_chains(normalized)

    if alerts:
        shell_pid = alerts[0]["shell_pid"]
        shell_event = next((event for event in normalized if event.get("pid") == shell_pid), None)
        target_event = shell_event
        target_source = "detected_alert"
    else:
        target_event = next(
            (event for event in reversed(normalized) if event["event_type"] == "exec"),
            normalized[-1],
        )
        target_source = "observed_event"

    process_data = {
        "pid": target_event["pid"],
        "process_name": target_event.get("file", target_event["comm"]),
        "anomaly_score": score_process_anomaly(graph_snapshot, target_event["pid"]),
        "target_source": target_source,
    }

    result = aegis_swarm.invoke({
        "process_data": process_data,
        "graph_snapshot": graph_snapshot,
    })

    return {
        "final_decision": result["final_decision"],
        "graph_anomaly_score": graph_anomaly,
        "alerts": alerts,
        "graph_snapshot": graph_snapshot,
        "process_data": process_data,
        "valid_event_count": len(normalized),
        "results": result,
    }


def run_aegis_pipeline(path: str | Path) -> dict[str, Any]:
    events = load_events(path)
    if not events:
        raise ValueError(f"No valid telemetry events were found in {path}")
    return build_analysis_bundle(events)


if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2:
        raise SystemExit("Usage: python aegis_pipeline.py <events.jsonl>")

    analysis = run_aegis_pipeline(sys.argv[1])
    print(f"Final decision: {analysis['final_decision']}")
    print(f"Graph anomaly score: {analysis['graph_anomaly_score']:.3f}")
    print(f"Alerts: {len(analysis['alerts'])}")
