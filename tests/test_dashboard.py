import json
import tempfile
import unittest
from pathlib import Path

from dashboard.graph_dashboard import build_snapshot, load_normalized_events


class DashboardTests(unittest.TestCase):
    def test_snapshot_uses_events_loaded_from_jsonl(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            events_path = Path(temporary_directory) / "events.jsonl"
            events_path.write_text(
                json.dumps(
                    {
                        "ts": 1_000,
                        "pid": 9876,
                        "ppid": 42,
                        "uid": 1000,
                        "comm": "curl",
                        "file": "/usr/bin/curl",
                    }
                )
                + "\n",
                encoding="utf-8",
            )

            events = load_normalized_events(events_path)
            snapshot = build_snapshot(events, source=f"Live JSONL: {events_path}")

        self.assertEqual(snapshot["event"]["pid"], 9876)
        self.assertEqual(snapshot["event"]["process"], "curl")
        self.assertTrue(snapshot["source"].startswith("Live JSONL:"))
        self.assertTrue(snapshot["nodes"])

    def test_snapshot_is_empty_when_no_valid_events_exist(self) -> None:
        snapshot = build_snapshot([], source="Live JSONL: empty")

        self.assertIsNone(snapshot["event"])
        self.assertEqual(snapshot["nodes"], [])
        self.assertEqual(snapshot["edges"], [])

    def test_snapshot_highlights_only_processes_in_detected_alerts(self) -> None:
        snapshot = build_snapshot(
            load_normalized_events(Path("agent/attack_test.jsonl")),
            source="test",
        )
        colors_by_pid = {node["pid"]: node["color"] for node in snapshot["nodes"] if node["pid"]}
        alerted_pids = {
            pid
            for alert in snapshot["alerts"]
            for pid in (alert["shell_pid"], alert["downloader_pid"])
        }

        self.assertTrue(alerted_pids)
        self.assertEqual(
            {pid for pid, color in colors_by_pid.items() if color == "#f87171"},
            alerted_pids,
        )
        self.assertTrue(
            all(node["type"] == "Process" for node in snapshot["nodes"] if node["color"] == "#f87171")
        )

    def test_snapshot_separates_process_and_resource_nodes(self) -> None:
        events = [
            {
                "ts": 1_000,
                "pid": 10,
                "ppid": 1,
                "uid": 1000,
                "comm": "bash",
                "file": "/bin/bash",
            },
            {
                "ts": 1_100,
                "pid": 11,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "file": "/usr/bin/curl",
            },
            {
                "ts": 1_200,
                "pid": 12,
                "ppid": 10,
                "uid": 1000,
                "comm": "sh",
                "file": "/bin/sh",
            },
            {
                "ts": 1_300,
                "pid": 11,
                "ppid": 10,
                "uid": 1000,
                "comm": "curl",
                "event_type": "connect",
                "dest_ip": "192.0.2.10",
                "dest_port": 443,
            },
            {
                "ts": 1_400,
                "pid": 12,
                "ppid": 10,
                "uid": 1000,
                "comm": "sh",
                "event_type": "file_open",
                "path": "/tmp/payload.sh",
            },
        ]
        snapshot = build_snapshot(
            events,
            source="test",
        )
        process_nodes = [node for node in snapshot["nodes"] if node["type"] == "Process"]
        resource_nodes = [node for node in snapshot["nodes"] if node["type"] in {"File", "Socket"}]

        self.assertTrue(process_nodes)
        self.assertTrue(resource_nodes)
        self.assertTrue(all(node["pid"] is not None for node in process_nodes))
        self.assertTrue(all(node["pid"] is None for node in resource_nodes))
        rightmost_process_x = max(node["x"] for node in process_nodes)
        self.assertTrue(all(node["x"] > rightmost_process_x for node in resource_nodes))
        self.assertEqual(
            next(node for node in resource_nodes if node["type"] == "File")["label"],
            "tmp/payload.sh",
        )

    def test_process_display_uses_executable_name(self) -> None:
        snapshot = build_snapshot(
            [
                {
                    "ts": 1_000,
                    "pid": 9876,
                    "ppid": 42,
                    "uid": 1000,
                    "comm": "old-command",
                    "file": "/usr/bin/grep",
                    "event_type": "exec",
                }
            ],
            source="test",
        )
        process_node = next(node for node in snapshot["nodes"] if node["type"] == "Process")

        self.assertEqual(process_node["label"], "grep")
        self.assertEqual(process_node["full_label"], "grep")

    def test_snapshot_excludes_unrelated_process_noise(self) -> None:
        events = [
            {
                "ts": timestamp,
                "pid": pid,
                "ppid": 1,
                "uid": 1000,
                "comm": "worker",
                "file": "/usr/bin/worker",
                "event_type": "exec",
            }
            for timestamp, pid in enumerate(range(100, 120), start=1)
        ]
        snapshot = build_snapshot(events, source="test")
        displayed_pids = {
            node["pid"] for node in snapshot["nodes"] if node["type"] == "Process"
        }

        self.assertEqual(displayed_pids, {1, 119})
        self.assertEqual(snapshot["graph_context"]["process_count"], 2)

    def test_snapshot_includes_pipeline_decision_and_approval_gate(self) -> None:
        events = load_normalized_events(Path("agent/attack_test.jsonl"))
        snapshot = build_snapshot(events, source="test")

        self.assertEqual(snapshot["analysis"]["decision"], "ISOLATE_PROCESS_SIGSTOP")
        self.assertTrue(snapshot["analysis"]["requires_human_approval"])
        self.assertEqual(
            snapshot["analysis"]["target_pid"],
            snapshot["alerts"][0]["shell_pid"],
        )
        self.assertGreaterEqual(snapshot["analysis"]["target_score"], 0.0)
        self.assertLessEqual(snapshot["analysis"]["target_score"], 1.0)
        self.assertTrue(snapshot["analysis"]["reason"])

    def test_loader_keeps_only_the_most_recent_events(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            events_path = Path(temporary_directory) / "events.jsonl"
            events_path.write_text(
                "".join(
                    json.dumps(
                        {
                            "ts": timestamp,
                            "pid": timestamp,
                            "ppid": 1,
                            "uid": 1000,
                            "comm": "bash",
                            "file": "/bin/bash",
                        }
                    )
                    + "\n"
                    for timestamp in (1, 2, 3)
                ),
                encoding="utf-8",
            )

            events = load_normalized_events(events_path, max_events=2)

        self.assertEqual([event["pid"] for event in events], [2, 3])


if __name__ == "__main__":
    unittest.main()
