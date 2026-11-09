"""MITRE ATT&CK mappings for process execution and remote access behaviors."""

from __future__ import annotations

MITRE_MAP = {
    "bash": "T1059.004",
    "sh": "T1059.004",
    "dash": "T1059.004",
    "zsh": "T1059.004",
    "cmd.exe": "T1059.003",
    "powershell": "T1059.001",
    "pwsh": "T1059.001",
    "curl": "T1105",
    "wget": "T1105",
    "python": "T1059.006",
    "python3": "T1059.006",
    "perl": "T1059.006",
    "ruby": "T1059.006",
}


def map_execution_behavior(process_name: str) -> str | None:
    if not isinstance(process_name, str):
        return None
    cleaned = process_name.strip().lower()
    if not cleaned:
        return None
    # Preserve basename if the path includes directories
    if "/" in cleaned:
        cleaned = cleaned.rsplit("/", 1)[-1]
    if "\\" in cleaned:
        cleaned = cleaned.rsplit("\\", 1)[-1]
    return MITRE_MAP.get(cleaned)
