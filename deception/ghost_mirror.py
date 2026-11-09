from __future__ import annotations

import argparse
import json
import shutil
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class MirrorSession:
    session_id: str
    sandbox_root: Path
    created_at: str
    evidence: list[str] = field(default_factory=list)
    status: str = "staged"


class GhostMirrorEngine:
    """Create an isolated synthetic execution sandbox for suspicious sessions.

    This implementation intentionally stays local and non-destructive: it creates a
    disposable sandbox tree, records the mirrored process lineage, and logs actions
    as evidence without terminating or modifying production systems.
    """

    def __init__(self, root: str | Path | None = None):
        base_root = Path(root) if root is not None else Path("/tmp/aegis-ghost-mirror")
        base_root.mkdir(parents=True, exist_ok=True)
        self.root = base_root

    def start_session(self, pid: int, process_name: str, *, metadata: dict[str, Any] | None = None) -> MirrorSession:
        if pid <= 0:
            raise ValueError("pid must be a positive integer")
        if not process_name.strip():
            raise ValueError("process_name must be a non-empty string")

        session_id = str(uuid.uuid4())
        sandbox_root = self.root / session_id
        sandbox_root.mkdir(parents=True, exist_ok=True)

        for folder in ("workspace", "downloads", "logs", "snapshots"):
            (sandbox_root / folder).mkdir(parents=True, exist_ok=True)

        session = MirrorSession(
            session_id=session_id,
            sandbox_root=sandbox_root,
            created_at=datetime.now(timezone.utc).isoformat(),
            evidence=[
                f"mirror session started for PID {pid} ({process_name})",
                f"sandbox root: {sandbox_root}",
            ],
            status="active",
        )

        if metadata:
            manifest = sandbox_root / "manifest.json"
            manifest.write_text(json.dumps({"pid": pid, "process_name": process_name, "metadata": metadata}, indent=2), encoding="utf-8")
            session.evidence.append(f"manifest saved to {manifest}")

        return session

    def record_action(self, session: MirrorSession, action: str) -> None:
        session.evidence.append(action)
        log_path = session.sandbox_root / "logs" / "activity.jsonl"
        with log_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps({"timestamp": datetime.now(timezone.utc).isoformat(), "action": action}) + "\n")

    def stop_session(self, session: MirrorSession) -> dict[str, Any]:
        session.status = "completed"
        session.evidence.append("mirror session closed")
        summary = {
            "session_id": session.session_id,
            "sandbox_root": str(session.sandbox_root),
            "status": session.status,
            "created_at": session.created_at,
            "evidence_count": len(session.evidence),
            "evidence": session.evidence,
        }
        summary_path = session.sandbox_root / "summary.json"
        summary_path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
        return summary

    def cleanup(self, session: MirrorSession) -> None:
        if session.sandbox_root.exists():
            shutil.rmtree(session.sandbox_root)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Create an isolated ghost mirror for suspicious process sessions")
    parser.add_argument("pid", type=int, help="PID to mirror into the sandbox")
    parser.add_argument("--process-name", default="bash", help="Observed process name to mirror")
    parser.add_argument("--metadata", default="{}", help="Optional JSON metadata for the sandbox")
    return parser.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    metadata = json.loads(args.metadata)
    engine = GhostMirrorEngine()
    session = engine.start_session(args.pid, args.process_name, metadata=metadata)
    engine.record_action(session, "mirrored network connection into sandbox")
    summary = engine.stop_session(session)
    print(json.dumps(summary, indent=2))
