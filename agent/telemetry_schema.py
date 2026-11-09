from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any


@dataclass(frozen=True)
class ProcessEvent:
    ts: int
    pid: int
    ppid: int | None
    uid: int | None
    comm: str
    file: str
    event_type: str = "exec"

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> "ProcessEvent":
        if not isinstance(payload, dict):
            raise ValueError("ProcessEvent payload must be a dictionary")

        ts = payload.get("ts")
        pid = payload.get("pid")
        ppid = payload.get("ppid")
        uid = payload.get("uid")
        comm = payload.get("comm")
        file_path = payload.get("file")

        if isinstance(ts, bool) or not isinstance(ts, int):
            raise ValueError("ProcessEvent.ts must be an integer timestamp")
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            raise ValueError("ProcessEvent.pid must be a positive integer")
        if ppid is not None and (isinstance(ppid, bool) or not isinstance(ppid, int) or ppid < 0):
            raise ValueError("ProcessEvent.ppid must be a non-negative integer when provided")
        if uid is not None and (isinstance(uid, bool) or not isinstance(uid, int) or uid < 0):
            raise ValueError("ProcessEvent.uid must be a non-negative integer when provided")
        if not isinstance(comm, str) or not comm.strip():
            raise ValueError("ProcessEvent.comm must be a non-empty string")
        if not isinstance(file_path, str) or not file_path.strip():
            raise ValueError("ProcessEvent.file must be a non-empty string")

        normalized = cls(
            ts=ts,
            pid=pid,
            ppid=ppid,
            uid=uid,
            comm=comm.strip(),
            file=_normalize_path(file_path),
        )
        return normalized

    def to_mapping(self) -> dict[str, Any]:
        return {
            "ts": self.ts,
            "pid": self.pid,
            "ppid": self.ppid,
            "uid": self.uid,
            "comm": self.comm,
            "file": self.file,
            "event_type": self.event_type,
            "outcome": "attempted",
        }


def _normalize_path(path: str) -> str:
    stripped = path.strip()
    if not stripped:
        return stripped

    posix_name = PurePosixPath(stripped).name
    windows_name = PureWindowsPath(stripped).name
    return min(
        (posix_name, windows_name),
        key=lambda value: (value == "", len(value)),
    )


def normalize_event(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValueError("Telemetry event payload must be a dictionary")
    event_type = payload.get("event_type", "exec")
    if event_type == "exec":
        return ProcessEvent.from_mapping(payload).to_mapping()

    ts = payload.get("ts")
    pid = payload.get("pid")
    ppid = payload.get("ppid")
    uid = payload.get("uid")
    comm = payload.get("comm")
    if isinstance(ts, bool) or not isinstance(ts, int):
        raise ValueError("Telemetry event ts must be an integer timestamp")
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("Telemetry event pid must be a positive integer")
    if ppid is not None and (
        isinstance(ppid, bool) or not isinstance(ppid, int) or ppid < 0
    ):
        raise ValueError("Telemetry event ppid must be a non-negative integer")
    if uid is not None and (
        isinstance(uid, bool) or not isinstance(uid, int) or uid < 0
    ):
        raise ValueError("Telemetry event uid must be a non-negative integer")
    if not isinstance(comm, str) or not comm.strip():
        raise ValueError("Telemetry event comm must be a non-empty string")

    normalized: dict[str, Any] = {
        "ts": ts,
        "pid": pid,
        "ppid": ppid,
        "uid": uid,
        "comm": comm.strip(),
        "event_type": event_type,
    }

    if event_type == "connect":
        address = payload.get("dest_ip")
        port = payload.get("dest_port")
        if not isinstance(address, str):
            raise ValueError("Connect event dest_ip must be an IP address")
        try:
            normalized["dest_ip"] = str(ip_address(address))
        except ValueError as exc:
            raise ValueError("Connect event dest_ip must be an IP address") from exc
        if (
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
        ):
            raise ValueError("Connect event dest_port must be between 0 and 65535")
        normalized["dest_port"] = port
    elif event_type == "file_open":
        path = payload.get("path")
        if not isinstance(path, str) or not path.strip():
            raise ValueError("File-open event path must be a non-empty string")
        normalized["path"] = path.strip()
    else:
        raise ValueError(f"Unsupported telemetry event_type: {event_type}")

    normalized["outcome"] = "attempted"
    return normalized
