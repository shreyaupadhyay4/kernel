import argparse
import json
import os
import signal
from pathlib import Path

from pydantic import ValidationError

from swarm.contracts import RemediationReport


def pause_process(
    pid: int,
    expected_comm: str,
    *,
    approved: bool = False,
) -> dict[str, int | str]:
    if approved is not True:
        raise PermissionError("Human approval is required before sending SIGSTOP")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        raise ValueError("pid must be an integer greater than 1")
    if not isinstance(expected_comm, str) or not expected_comm.strip():
        raise ValueError("expected_comm must be a non-empty process name")
    if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
        raise RuntimeError("Safe PID-file-descriptor signaling is unavailable on this platform")

    process_fd = os.pidfd_open(pid)
    try:
        comm_path = Path(f"/proc/{pid}/comm")
        try:
            actual_comm = comm_path.read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise RuntimeError(f"Cannot verify process {pid}: {exc}") from exc

        if actual_comm != expected_comm.strip():
            raise ValueError(
                f"Process name mismatch for PID {pid}: expected "
                f"{expected_comm.strip()!r}, found {actual_comm!r}"
            )

        signal.pidfd_send_signal(process_fd, signal.SIGSTOP)
    finally:
        os.close(process_fd)

    report = RemediationReport(
        action="SIGSTOP",
        pid=pid,
        process_name=actual_comm,
        status="paused",
    )
    return report.model_dump(mode="json")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Pause a verified process after explicit human approval."
    )
    parser.add_argument("pid", type=int, help="PID to pause")
    parser.add_argument(
        "--expected-comm",
        required=True,
        help="expected exact /proc/PID/comm value (safety check)",
    )
    parser.add_argument(
        "--approve",
        action="store_true",
        help="confirm that a human has approved sending SIGSTOP to this process",
    )
    args = parser.parse_args()

    try:
        result = pause_process(
            args.pid,
            args.expected_comm,
            approved=args.approve,
        )
    except (PermissionError, ValueError, RuntimeError, OSError, ValidationError) as exc:
        parser.error(str(exc))

    print(json.dumps(result))


if __name__ == "__main__":
    main()
