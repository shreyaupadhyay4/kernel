import unittest
import json

from swarm.agent_graph import aegis_swarm, forensic_agent
from swarm.contracts import DecisionReport, ForensicReport


class AgentGraphTests(unittest.TestCase):
    def test_low_anomaly_score_stays_in_monitor_mode(self) -> None:
        result = aegis_swarm.invoke(
            {
                "process_data": {
                    "pid": 4421,
                    "process_name": "bash",
                    "anomaly_score": 0.2,
                }
            }
        )

        self.assertEqual(result["final_decision"], "MONITOR")

    def test_high_risk_with_mitre_mapping_recommends_sigstop(self) -> None:
        result = aegis_swarm.invoke(
            {
                "process_data": {
                    "pid": 4421,
                    "process_name": "/bin/bash",
                    "anomaly_score": 0.9,
                }
            }
        )

        self.assertEqual(result["final_decision"], "ISOLATE_PROCESS_SIGSTOP")
        self.assertTrue(result["decision_report"]["requires_human_approval"])
        self.assertEqual(
            json.loads(json.dumps(result["decision_report"]))["decision"],
            "ISOLATE_PROCESS_SIGSTOP",
        )

    def test_agent_reports_enforce_json_contract(self) -> None:
        report = ForensicReport(
            risk_level="High",
            anomaly_score=0.9,
            evidence=["High anomaly score"],
        )

        self.assertEqual(report.model_dump(mode="json")["risk_level"], "High")
        with self.assertRaises(ValueError):
            ForensicReport(
                risk_level="High",
                anomaly_score=1.1,
                evidence=["out of bounds"],
            )
        with self.assertRaises(ValueError):
            DecisionReport(
                decision="DELETE_PROCESS",
                requires_human_approval=False,
                reason="invalid action",
            )

    def test_high_risk_without_mitre_mapping_stays_in_monitor_mode(self) -> None:
        result = aegis_swarm.invoke(
            {
                "process_data": {
                    "pid": 4421,
                    "process_name": "systemd",
                    "anomaly_score": 0.9,
                }
            }
        )

        self.assertEqual(result["final_decision"], "MONITOR")

    def test_windows_interpreter_path_is_mapped(self) -> None:
        result = aegis_swarm.invoke(
            {
                "process_data": {
                    "pid": 4421,
                    "process_name": "C:\\Windows\\System32\\cmd.exe",
                    "anomaly_score": 0.9,
                }
            }
        )

        self.assertEqual(result["final_decision"], "ISOLATE_PROCESS_SIGSTOP")

    def test_graph_snapshot_can_raise_decision_confidence(self) -> None:
        result = aegis_swarm.invoke(
            {
                "process_data": {
                    "pid": 4421,
                    "process_name": "/bin/bash",
                    "anomaly_score": 0.65,
                },
                "graph_snapshot": {
                    "nodes": [
                        {"id": 10, "file": "curl"},
                        {"id": 4421, "file": "bash"},
                    ],
                    "edges": [
                        {"source": 10, "target": 4421, "relationship": "SPAWNED"},
                    ],
                },
            }
        )

        self.assertEqual(result["final_decision"], "ISOLATE_PROCESS_SIGSTOP")

    def test_invalid_anomaly_score_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            forensic_agent(
                {"process_data": {"pid": 4421, "anomaly_score": 1.1}}
            )


if __name__ == "__main__":
    unittest.main()
