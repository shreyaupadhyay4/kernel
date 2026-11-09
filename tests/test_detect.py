import json
import unittest

from agent.detect import detect_download_shell_chains


class DetectDownloadShellChainsTests(unittest.TestCase):
    def test_detects_high_risk_download_shell_chain(self) -> None:
        events = [
            {"ts": 100, "pid": 400, "ppid": 10, "file": "/usr/bin/curl"},
            {"ts": 160, "pid": 401, "ppid": 10, "file": "/bin/bash"},
            {"ts": 500, "pid": 402, "ppid": 11, "file": "/usr/bin/grep"},
        ]

        alerts = detect_download_shell_chains(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["parent_pid"], 10)
        self.assertEqual(alerts[0]["downloader"], "/usr/bin/curl")
        self.assertEqual(alerts[0]["shell"], "/bin/bash")

    def test_ignores_large_time_gap_between_download_and_shell(self) -> None:
        events = [
            {"ts": 100, "pid": 500, "ppid": 15, "file": "curl"},
            {"ts": 5_000_000_000, "pid": 501, "ppid": 15, "file": "/bin/bash"},
        ]

        self.assertEqual(detect_download_shell_chains(events), [])

    def test_uses_comm_when_executable_path_is_missing_and_ignores_other_event_types(self) -> None:
        events = [
            {"ts": 100, "pid": 500, "ppid": 15, "comm": "CURL"},
            {"ts": 200, "pid": 501, "ppid": 15, "comm": "bash", "event_type": "connect"},
            {"ts": 300, "pid": 502, "ppid": 15, "comm": "BASH"},
        ]

        alerts = detect_download_shell_chains(events)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["downloader_pid"], 500)
        self.assertEqual(alerts[0]["shell_pid"], 502)

    def test_ignores_invalid_timestamps_instead_of_crashing(self) -> None:
        events = [
            {"ts": "now", "pid": 500, "ppid": 15, "file": "curl"},
            {"ts": 100, "pid": 501, "ppid": 15, "file": "bash"},
        ]

        self.assertEqual(detect_download_shell_chains(events), [])


if __name__ == "__main__":
    unittest.main()
