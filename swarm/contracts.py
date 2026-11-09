from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class AgentReport(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ForensicReport(AgentReport):
    risk_level: Literal["Low", "Medium", "High"]
    anomaly_score: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(min_length=1)


class RedTeamReport(AgentReport):
    tactic: str | None
    technique: str | None
    evidence: list[str]


class GraphReport(AgentReport):
    anomaly_score: float = Field(ge=0.0, le=1.0)
    node_count: int = Field(ge=0)
    edge_count: int = Field(ge=0)
    evidence: list[str] = Field(min_length=1)


class DecisionReport(AgentReport):
    decision: Literal["MONITOR", "ISOLATE_PROCESS_SIGSTOP"]
    requires_human_approval: bool
    reason: str = Field(min_length=1)


class RemediationReport(AgentReport):
    action: Literal["SIGSTOP"]
    pid: int = Field(gt=1)
    process_name: str = Field(min_length=1)
    status: Literal["paused"]
