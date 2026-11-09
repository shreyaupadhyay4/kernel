import unittest

from agent.telemetry_schema import ProcessEvent, normalize_event


class TelemetrySchemaTests(unittest.TestCase):
    def test_process_event_normalizes_posix_paths(self) -> None:
        event = ProcessEvent.from_mapping(
            {
                "ts": 100,
                "pid": 42,
                "ppid": 10,
                "uid": 1000,
                "comm": "bash",
                "file": "/usr/bin/bash",
            }
        )

        self.assertEqual(event.file, "bash")
        self.assertEqual(event.to_mapping()["event_type"], "exec")

    def test_process_event_normalizes_windows_paths(self) -> None:
        normalized = normalize_event(
            {
                "ts": 200,
                "pid": 43,
                "ppid": 11,
                "uid": 1001,
                "comm": "cmd.exe",
                "file": "C:\\Windows\\System32\\cmd.exe",
            }
        )

        self.assertEqual(normalized["file"], "cmd.exe")

    def test_rejects_missing_required_fields(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-empty string"):
            ProcessEvent.from_mapping({"ts": 1, "pid": 1, "comm": "", "file": "/bin/sh"})

    def test_normalizes_connect_event(self) -> None:
        event = normalize_event(
            {
                "ts": 300,
                "pid": 44,
                "ppid": 12,
                "uid": 1000,
                "comm": "curl",
                "event_type": "connect",
                "dest_ip": "2001:db8::1",
                "dest_port": 443,
            }
        )

        self.assertEqual(event["dest_ip"], "2001:db8::1")
        self.assertEqual(event["outcome"], "attempted")

    def test_normalizes_file_open_event(self) -> None:
        event = normalize_event(
            {
                "ts": 400,
                "pid": 45,
                "ppid": 12,
                "uid": 1000,
                "comm": "cat",
                "event_type": "file_open",
                "path": "/etc/hosts",
            }
        )

        self.assertEqual(event["path"], "/etc/hosts")
        self.assertEqual(event["outcome"], "attempted")

    def test_rejects_invalid_connect_address(self) -> None:
        with self.assertRaisesRegex(ValueError, "dest_ip"):
            normalize_event(
                {
                    "ts": 1,
                    "pid": 1,
                    "comm": "curl",
                    "event_type": "connect",
                    "dest_ip": "not-an-ip",
                    "dest_port": 443,
                }
            )


if __name__ == "__main__":
    unittest.main()
