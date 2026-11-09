import logging
from math import isfinite
from pathlib import PurePosixPath, PureWindowsPath
from typing import TypedDict

from agent.mitre import map_execution_behavior
from detector.graph_builder import (
    build_graph_snapshot,
    graph_anomaly_features,
    process_context_graph,
    score_process_anomaly,
)
from langgraph.graph import END, StateGraph
from swarm.contracts import (
    DecisionReport,
    ForensicReport,
    GraphReport,
    RedTeamReport,
)

logger = logging.getLogger(__name__)


class AgentState(TypedDict, total=False):
    process_data: dict[str, object]
    graph_snapshot: dict[str, object]
    forensic_report: ForensicReport
    red_team_report: RedTeamReport
    graph_report: GraphReport
    final_decision: str
    decision_report: dict[str, object]


INTERPRETER_TECHNIQUES = {
    "bash": "T1059.004",
    "dash": "T1059.004",
    "sh": "T1059.004",
    "zsh": "T1059.004",
    "cmd.exe": "T1059.003",
    "powershell": "T1059.001",
    "pwsh": "T1059.001",
}


def _process_data(state: AgentState) -> dict[str, object]:
    process_data = state.get("process_data")
    if not isinstance(process_data, dict):
        raise ValueError("process_data must be provided as an object")

    pid = process_data.get("pid")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("process_data.pid must be a positive integer")

    return process_data


def forensic_agent(state: AgentState) -> dict[str, ForensicReport]:
    process_data = _process_data(state)
    score = process_data.get("anomaly_score", 0.0)
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ValueError("process_data.anomaly_score must be a number")
    if not isfinite(score) or not 0.0 <= score <= 1.0:
        raise ValueError("process_data.anomaly_score must be between 0 and 1")

    if score >= 0.85:
        risk_level = "High"
    elif score >= 0.55:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    evidence = [f"Anomaly score: {score:.2f}"]
    logger.debug("Forensic Agent analyzed PID %s: %s risk", process_data["pid"], risk_level)
    report = ForensicReport(
        risk_level=risk_level,
        anomaly_score=float(score),
        evidence=evidence,
    )
    return {"forensic_report": report.model_dump(mode="json")}


def _normalize_process_name(process_name: str) -> str:
    candidate = process_name.strip()
    if not candidate:
        return candidate

    posix_name = PurePosixPath(candidate).name
    windows_name = PureWindowsPath(candidate).name
    return min(
        (posix_name, windows_name),
        key=lambda value: (value == "", len(value)),
    ).lower()


def red_team_agent(state: AgentState) -> dict[str, RedTeamReport]:
    process_data = _process_data(state)
    process_name = process_data.get(
        "process_name", process_data.get("comm", process_data.get("name", ""))
    )
    if not isinstance(process_name, str):
        raise ValueError("process_data.process_name must be a string")

    normalized_name = _normalize_process_name(process_name)
    technique = map_execution_behavior(process_name) or INTERPRETER_TECHNIQUES.get(normalized_name)
    tactic = "TA0002 Execution" if technique else None
    evidence = [f"Interpreter observed: {process_name}"] if technique else []
    if technique and technique.startswith("T1105"):
        tactic = "TA0011 Command and Scripting Interpreter" if tactic is None else tactic
        evidence.append("Remote payload retrieval path observed")
    report = RedTeamReport(
        tactic=tactic,
        technique=technique,
        evidence=evidence,
    )
    logger.debug(
        "Red Team Agent mapped PID %s: %s",
        process_data["pid"],
        technique or "no mapping",
    )
    return {"red_team_report": report.model_dump(mode="json")}


def graph_analysis_agent(state: AgentState) -> dict[str, GraphReport]:
    graph_snapshot = state.get("graph_snapshot")
    snapshot: dict[str, object]
    if not isinstance(graph_snapshot, dict):
        snapshot = {"nodes": [], "edges": []}
    else:
        snapshot = graph_snapshot

    if "events" in snapshot and isinstance(snapshot["events"], list):
        snapshot = build_graph_snapshot(snapshot["events"])

    if not isinstance(snapshot.get("nodes"), list):
        snapshot["nodes"] = []
    if not isinstance(snapshot.get("edges"), list):
        snapshot["edges"] = []

    process_data = _process_data(state)
    anomaly_score = score_process_anomaly(snapshot, process_data["pid"])
    features = graph_anomaly_features(
        process_context_graph(snapshot, process_data["pid"])
    )["features"]
    evidence = [
        f"Target-context behavior score: {anomaly_score:.3f} (heuristic, not a probability)",
        *features,
        f"Observed {len(snapshot['nodes'])} nodes and {len(snapshot['edges'])} edges",
    ]
    logger.debug("Graph Analysis Agent scored anomaly at %.3f", anomaly_score)
    report = GraphReport(
        anomaly_score=float(anomaly_score),
        node_count=len(snapshot["nodes"]),
        edge_count=len(snapshot["edges"]),
        evidence=evidence,
    )
    return {"graph_report": report.model_dump(mode="json")}


def supervisor_agent(state: AgentState) -> dict[str, str]:
    forensic_report = state.get("forensic_report")
    red_team_report = state.get("red_team_report")
    graph_report = state.get("graph_report")
    if forensic_report is None or red_team_report is None:
        raise ValueError("Supervisor requires both agent reports")

    graph_anomaly = graph_report["anomaly_score"] if graph_report is not None else 0.0
    consensus = (
        bool(forensic_report["evidence"])
        and red_team_report["technique"] is not None
        and bool(red_team_report["evidence"])
        and (
            forensic_report["risk_level"] == "High"
            or forensic_report["anomaly_score"] >= 0.6
            or graph_anomaly >= 0.5
        )
    )
    decision = "ISOLATE_PROCESS_SIGSTOP" if consensus else "MONITOR"
    graph_evidence = (
        graph_report["evidence"]
        if graph_report is not None
        else ["No graph evidence was provided."]
    )
    evidence_summary = "; ".join(graph_evidence)
    report = DecisionReport(
        decision=decision,
        requires_human_approval=decision == "ISOLATE_PROCESS_SIGSTOP",
        reason=(
            f"Several signals support a recommendation to pause this process. {evidence_summary} Human approval is required before any action."
            if consensus
            else f"The available signals do not meet the threshold for a pause; continue monitoring. {evidence_summary}"
        ),
    )
    approval_note = (
        "human approval required"
        if report.requires_human_approval
        else "no containment action recommended"
    )
    logger.info("Supervisor decision: %s (%s)", decision, approval_note)
    return {
        "final_decision": report.decision,
        "decision_report": report.model_dump(mode="json"),
    }


workflow = StateGraph(AgentState)
workflow.add_node("forensics", forensic_agent)
workflow.add_node("red_team", red_team_agent)
workflow.add_node("graph_analysis", graph_analysis_agent)
workflow.add_node("supervisor", supervisor_agent)
workflow.set_entry_point("forensics")
workflow.add_edge("forensics", "red_team")
workflow.add_edge("red_team", "graph_analysis")
workflow.add_edge("graph_analysis", "supervisor")
workflow.add_edge("supervisor", END)

aegis_swarm = workflow.compile()


if __name__ == "__main__":
    test_state: AgentState = {
        "process_data": {
            "pid": 4421,
            "process_name": "bash",
            "anomaly_score": 0.2,
        }
    }
    result = aegis_swarm.invoke(test_state)
    print(f"\nRecommended action: {result['final_decision']}")
