import unittest
from unittest.mock import patch

from response.remediation import pause_process


class RemediationTests(unittest.TestCase):
    def test_requires_explicit_approval_before_opening_pidfd(self) -> None:
        with patch("response.remediation.os.pidfd_open") as pidfd_open:
            with self.assertRaisesRegex(PermissionError, "Human approval"):
                pause_process(1234, "bash")

        pidfd_open.assert_not_called()

    def test_pause_requires_matching_process_identity(self) -> None:
        with (
            patch("response.remediation.os.pidfd_open", return_value=7),
            patch("response.remediation.Path.read_text", return_value="bash\n"),
            patch("response.remediation.signal.pidfd_send_signal") as send_signal,
            patch("response.remediation.os.close") as close,
        ):
            result = pause_process(1234, "bash", approved=True)

        self.assertEqual(result, {
            "action": "SIGSTOP",
            "pid": 1234,
            "process_name": "bash",
            "status": "paused",
        })
        send_signal.assert_called_once()
        close.assert_called_once_with(7)

    def test_rejects_identity_mismatch_without_signaling(self) -> None:
        with (
            patch("response.remediation.os.pidfd_open", return_value=7),
            patch("response.remediation.Path.read_text", return_value="python\n"),
            patch("response.remediation.signal.pidfd_send_signal") as send_signal,
            patch("response.remediation.os.close") as close,
        ):
            with self.assertRaisesRegex(ValueError, "Process name mismatch"):
                pause_process(1234, "bash", approved=True)

        send_signal.assert_not_called()
        close.assert_called_once_with(7)

    def test_rejects_pid_one(self) -> None:
        with self.assertRaisesRegex(ValueError, "greater than 1"):
            pause_process(1, "init", approved=True)


if __name__ == "__main__":
    unittest.main()
