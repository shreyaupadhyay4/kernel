import unittest

from detector.graph_builder import (
    build_graph_snapshot,
    graph_anomaly_features,
    process_context_graph,
    score_graph_anomaly,
    score_process_anomaly,
)


class GraphBuilderTests(unittest.TestCase):
    def test_builds_process_graph_snapshot(self) -> None:
        events = [
            {"ts": 1, "pid": 100, "ppid": 10, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
            {"ts": 2, "pid": 101, "ppid": 100, "uid": 1000, "comm": "curl", "file": "curl"},
        ]

        graph = build_graph_snapshot(events)

        self.assertEqual(len(graph["nodes"]), 3)
        self.assertEqual(len(graph["edges"]), 2)
        self.assertIn({"source": 10, "target": 100, "relationship": "SPAWNED"}, graph["edges"])

    def test_scores_suspicious_graph_higher(self) -> None:
        events = [
            {"ts": 1, "pid": 100, "ppid": 10, "uid": 1000, "comm": "wrapper", "file": "wrapper"},
            {"ts": 2, "pid": 101, "ppid": 100, "uid": 1000, "comm": "curl", "file": "curl"},
            {"ts": 3, "pid": 102, "ppid": 100, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
        ]

        score = score_graph_anomaly(build_graph_snapshot(events))

        self.assertGreater(score, 0.3)

    def test_adds_socket_and_file_nodes_for_observed_syscalls(self) -> None:
        events = [
            {
                "ts": 1,
                "pid": 100,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "file": "/usr/bin/curl",
            },
            {
                "ts": 2,
                "pid": 100,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "event_type": "connect",
                "dest_ip": "192.0.2.10",
                "dest_port": 443,
            },
            {
                "ts": 3,
                "pid": 100,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "event_type": "file_open",
                "path": "/tmp/output",
            },
        ]

        graph = build_graph_snapshot(events)

        self.assertIn(
            {"source": 100, "target": "socket:192.0.2.10:443", "relationship": "CONNECTED_TO"},
            graph["edges"],
        )
        self.assertIn(
            {"source": 100, "target": "file:/tmp/output", "relationship": "OPENED"},
            graph["edges"],
        )
        self.assertEqual(
            {node["type"] for node in graph["nodes"]},
            {"Process", "File", "Socket"},
        )

    def test_scoring_uses_related_process_behavior_not_resource_edge_count(self) -> None:
        benign_events = [
            {"ts": 1, "pid": 100, "ppid": 10, "uid": 1000, "comm": "worker", "file": "/usr/bin/worker"},
            *[
                {
                    "ts": timestamp,
                    "pid": 100,
                    "ppid": 10,
                    "uid": 1000,
                    "comm": "worker",
                    "event_type": "connect",
                    "dest_ip": f"192.0.2.{timestamp}",
                    "dest_port": 443,
                }
                for timestamp in range(2, 20)
            ],
        ]
        suspicious_events = [
            {"ts": 1, "pid": 100, "ppid": 10, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
            {"ts": 2, "pid": 101, "ppid": 100, "uid": 1000, "comm": "curl", "file": "/usr/bin/curl"},
            {"ts": 3, "pid": 102, "ppid": 100, "uid": 1000, "comm": "sh", "file": "/bin/sh"},
            {
                "ts": 4,
                "pid": 101,
                "ppid": 100,
                "uid": 1000,
                "comm": "curl",
                "event_type": "connect",
                "dest_ip": "192.0.2.10",
                "dest_port": 443,
            },
        ]

        benign_score = score_graph_anomaly(build_graph_snapshot(benign_events))
        suspicious_score = score_graph_anomaly(build_graph_snapshot(suspicious_events))

        self.assertLessEqual(benign_score, 0.1)
        self.assertGreaterEqual(suspicious_score, 0.7)

    def test_scoring_requires_temporal_correlation_for_download_shell_pattern(self) -> None:
        events = [
            {"ts": 1, "pid": 100, "ppid": 10, "uid": 1000, "comm": "wrapper", "file": "/usr/bin/wrapper"},
            {"ts": 2, "pid": 101, "ppid": 100, "uid": 1000, "comm": "curl", "file": "/usr/bin/curl"},
            {"ts": 4_000_000_000, "pid": 102, "ppid": 100, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
        ]

        score = score_graph_anomaly(build_graph_snapshot(events))

        self.assertLess(score, 0.3)

    def test_repeated_events_deduplicate_relationships_and_upgrade_parent_nodes(self) -> None:
        graph = build_graph_snapshot(
            [
                {"ts": 1, "pid": 101, "ppid": 100, "uid": 1000, "comm": "worker", "file": "/usr/bin/worker"},
                {"ts": 2, "pid": 100, "ppid": 1, "uid": 0, "comm": "init", "file": "/sbin/init"},
                {"ts": 3, "pid": 101, "ppid": 100, "uid": 1000, "comm": "worker", "file": "/usr/bin/worker"},
            ]
        )
        parent = next(node for node in graph["nodes"] if node.get("pid") == 100)

        self.assertEqual(parent["comm"], "init")
        self.assertEqual(parent["event_type"], "exec")
        self.assertEqual(
            len([edge for edge in graph["edges"] if edge["relationship"] == "SPAWNED"]),
            2,
        )

    def test_process_score_does_not_inherit_unrelated_process_risk(self) -> None:
        graph = build_graph_snapshot(
            [
                {"ts": 1, "pid": 10, "ppid": 1, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
                {"ts": 2, "pid": 11, "ppid": 10, "uid": 1000, "comm": "curl", "file": "/usr/bin/curl"},
                {"ts": 3, "pid": 12, "ppid": 10, "uid": 1000, "comm": "sh", "file": "/bin/sh"},
                {"ts": 4, "pid": 20, "ppid": 1, "uid": 1000, "comm": "worker", "file": "/usr/bin/worker"},
            ]
        )

        self.assertGreater(score_graph_anomaly(graph), 0.7)
        self.assertLessEqual(score_process_anomaly(graph, 20), 0.05)

    def test_process_context_score_explains_correlated_behavior(self) -> None:
        graph = build_graph_snapshot(
            [
                {"ts": 1, "pid": 10, "ppid": 1, "uid": 1000, "comm": "bash", "file": "/bin/bash"},
                {"ts": 2, "pid": 11, "ppid": 10, "uid": 1000, "comm": "curl", "file": "/usr/bin/curl"},
                {
                    "ts": 3,
                    "pid": 11,
                    "ppid": 10,
                    "uid": 1000,
                    "comm": "curl",
                    "event_type": "connect",
                    "dest_ip": "192.0.2.10",
                    "dest_port": 443,
                },
                {"ts": 4, "pid": 12, "ppid": 10, "uid": 1000, "comm": "sh", "file": "/bin/sh"},
            ]
        )
        features = graph_anomaly_features(process_context_graph(graph, 12))

        self.assertTrue(features["correlated_download_shell"])
        self.assertTrue(features["downloader_network_activity"])
        self.assertGreaterEqual(features["score"], 0.7)
        self.assertTrue(any("within two seconds" in item for item in features["features"]))


if __name__ == "__main__":
    unittest.main()
