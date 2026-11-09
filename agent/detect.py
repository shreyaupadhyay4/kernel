import json
import sys
from collections import defaultdict

SHELLS = (
    "/bin/sh",
    "/usr/bin/sh",
    "/bin/bash",
    "/usr/bin/bash",
    "/bin/dash",
    "/usr/bin/dash",
    "bash",
    "sh",
    "dash",
)
DOWNLOADERS = ("curl", "wget")
WINDOW_NS = 2_000_000_000  # 2 seconds


def _basename(path: str) -> str:
    return path.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]


def detect_download_shell_chains(events):
    by_parent = defaultdict(list)
    for event in events:
        if not isinstance(event, dict):
            continue
        if event.get("event_type", "exec") != "exec":
            continue
        ppid = event.get("ppid")
        if isinstance(ppid, int) and not isinstance(ppid, bool):
            by_parent[ppid].append(event)

    alerts = []
    for ppid, kids in by_parent.items():
        dl = [
            k for k in kids
            if _basename(str(k.get("file") or k.get("comm") or "")).lower() in DOWNLOADERS
        ]
        sh = [
            k for k in kids
            if _basename(str(k.get("file") or k.get("comm") or "")).lower() in SHELLS
        ]
        for d in dl:
            for s in sh:
                download_ts, shell_ts = d.get("ts"), s.get("ts")
                if (
                    isinstance(download_ts, int)
                    and not isinstance(download_ts, bool)
                    and isinstance(shell_ts, int)
                    and not isinstance(shell_ts, bool)
                    and abs(download_ts - shell_ts) < WINDOW_NS
                ):
                    alerts.append(
                        {
                            "parent_pid": ppid,
                            "downloader": d.get("file"),
                            "downloader_pid": d.get("pid"),
                            "shell": s.get("file"),
                            "shell_pid": s.get("pid"),
                        }
                    )
    return alerts


def main(path):
    events = []
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    for alert in detect_download_shell_chains(events):
        print(
            "ALERT: possible 'download | shell' under parent "
            f"{alert['parent_pid']}: {alert['downloader']} (pid {alert['downloader_pid']}) + "
            f"{alert['shell']} (pid {alert['shell_pid']})"
        )


if __name__ == "__main__":
    if len(sys.argv) != 2:
        raise SystemExit("Usage: python agent/detect.py <events.jsonl>")
    main(sys.argv[1])
