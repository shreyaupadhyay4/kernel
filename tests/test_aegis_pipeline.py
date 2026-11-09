import unittest

from aegis_pipeline import build_analysis_bundle, run_aegis_pipeline


class AegisPipelineTests(unittest.TestCase):
    def test_pipeline_detects_suspicious_process_tree(self) -> None:
        result = run_aegis_pipeline("agent/attack_test.jsonl")

        self.assertIn(result["final_decision"], {"MONITOR", "ISOLATE_PROCESS_SIGSTOP"})
        self.assertGreaterEqual(result["graph_anomaly_score"], 0.0)
        self.assertIsInstance(result["alerts"], list)

    def test_pipeline_raises_for_empty_event_file(self) -> None:
        with self.assertRaisesRegex(ValueError, "No valid telemetry events"):
            run_aegis_pipeline("tests/empty.jsonl")

    def test_pipeline_accepts_exec_network_and_file_events(self) -> None:
        events = [
            {
                "ts": 1_000,
                "pid": 20,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "file": "/usr/bin/curl",
            },
            {
                "ts": 1_100,
                "pid": 21,
                "ppid": 10,
                "uid": 1000,
                "comm": "bash",
                "file": "/bin/bash",
            },
            {
                "ts": 1_200,
                "pid": 20,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "event_type": "connect",
                "dest_ip": "192.0.2.10",
                "dest_port": 443,
            },
            {
                "ts": 1_300,
                "pid": 21,
                "ppid": 10,
                "uid": 1000,
                "comm": "bash",
                "event_type": "file_open",
                "path": "/tmp/example",
            },
        ]

        result = build_analysis_bundle(events)

        self.assertIn(
            {"source": 20, "target": "socket:192.0.2.10:443", "relationship": "CONNECTED_TO"},
            result["graph_snapshot"]["edges"],
        )
        self.assertIn(
            {"source": 21, "target": "file:/tmp/example", "relationship": "OPENED"},
            result["graph_snapshot"]["edges"],
        )

    def test_pipeline_uses_an_observed_pid_when_no_alert_matches(self) -> None:
        result = build_analysis_bundle(
            [
                {
                    "ts": 1_000,
                    "pid": 4321,
                    "ppid": 100,
                    "uid": 1000,
                    "comm": "bash",
                    "file": "/bin/bash",
                }
            ]
        )

        self.assertEqual(result["process_data"]["pid"], 4321)
        self.assertEqual(result["process_data"]["target_source"], "observed_event")
        self.assertEqual(result["process_data"]["anomaly_score"], result["graph_anomaly_score"])

    def test_pipeline_scores_the_recommended_process_not_the_entire_graph(self) -> None:
        result = build_analysis_bundle(
            [
                {"ts": 1, "pid": 10, "ppid": 1, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
                {"ts": 2, "pid": 11, "ppid": 10, "uid": 1000, "comm": "curl", "file": "/usr/bin/curl"},
                {"ts": 3_000_000_000, "pid": 12, "ppid": 10, "uid": 1000, "comm": "sh", "file": "/bin/sh"},
                {"ts": 4_000_000_000, "pid": 20, "ppid": 1, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
            ]
        )

        self.assertEqual(result["alerts"], [])
        self.assertEqual(result["process_data"]["pid"], 20)
        self.assertLessEqual(result["graph_anomaly_score"], 0.3)
        self.assertLessEqual(result["process_data"]["anomaly_score"], 0.2)
        self.assertEqual(result["final_decision"], "MONITOR")

    def test_pipeline_rejects_input_without_valid_telemetry(self) -> None:
        with self.assertRaisesRegex(ValueError, "No valid telemetry events"):
            build_analysis_bundle([{"not": "a telemetry event"}])


if __name__ == "__main__":
    unittest.main()
