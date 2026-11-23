"""Shared Pydantic contracts for multi-agent FortiGate investigations."""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, Field


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


class AgentRole(str, Enum):
    ORCHESTRATOR = "orchestrator"
    NETWORK = "network"
    SECURITY = "security"
    THREAT = "threat"
    HEALTH = "health"
    REMEDIATION = "remediation"


class FindingSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OK = "ok"
    WARNING = "warning"
    DEGRADED = "degraded"
    CRITICAL = "critical"
    UNKNOWN = "unknown"
    UNAVAILABLE = "unavailable"
    NOT_APPLICABLE = "not_applicable"
    ERROR = "error"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EvidenceItem(BaseModel):
    """Machine-readable evidence record with provenance back to a FortiGate API/tool call."""
    source_api: str = Field(description="FortiOS REST endpoint or tool name that produced this evidence")
    timestamp: str = Field(default_factory=utc_now_iso, description="UTC ISO-8601 collection timestamp")
    device: str = Field(default="", description="Target FortiGate host or hostname")
    vdom: str = Field(default="root", description="Target Virtual Domain")
    summary: str = Field(description="Concise factual observation")
    values: Dict[str, Any] = Field(default_factory=dict, description="Key raw metrics or object attributes")
    untrusted: bool = Field(default=True, description="Marks device-controlled fields as untrusted evidence")


class AgentFinding(BaseModel):
    """Structured diagnostic or security finding returned by a specialist agent."""
    category: str = Field(description="Technical domain or subsystem (e.g., routing, vpn, policy, ha, logs)")
    severity: FindingSeverity = Field(default=FindingSeverity.INFO)
    status: FindingStatus = Field(default=FindingStatus.UNKNOWN)
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM)
    summary: str = Field(description="Concise finding summary")
    details: str = Field(default="", description="Detailed technical explanation grounded in evidence")
    evidence: List[EvidenceItem] = Field(default_factory=list)
    affected_objects: List[str] = Field(
        default_factory=list,
        description="Affected devices, VDOMs, interfaces, policies, peers, or tunnels",
    )
    impact: str = Field(default="", description="Operational or security impact")
    recommended_next_checks: List[str] = Field(default_factory=list)
    remediation_proposed: bool = Field(default=False)
    remediation_required: bool = Field(default=False)


class ModelProvenance(BaseModel):
    """Records exact model/provider metadata for reproducibility and evaluation."""
    provider: str
    model_id: str
    role: AgentRole
    thinking_level: Optional[str] = None
    latency_ms: float = 0.0
    token_usage: Dict[str, int] = Field(default_factory=dict)


class InvestigationTask(BaseModel):
    """Scoped task dispatched by the Orchestrator to a specialist agent."""
    task_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    correlation_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:16])
    objective: str = Field(description="Clear investigative objective for the specialist agent")
    target_role: AgentRole
    device: str = Field(default="")
    vdom: str = Field(default="root")
    depends_on: List[str] = Field(default_factory=list)
    max_tool_calls: int = Field(default=10, ge=1, le=50)
    timeout_seconds: float = Field(default=90.0, gt=0.0)
    context_hints: Dict[str, Any] = Field(default_factory=dict)


class AgentResult(BaseModel):
    """Top-level structured contract returned by every specialist agent."""
    agent_name: str
    agent_role: AgentRole
    task_id: str
    correlation_id: str
    device: str = ""
    vdom: str = "root"
    status: str = Field(
        default="completed",
        description="Execution status: completed, partial, unknown, timeout, or error",
    )
    summary: str = ""
    findings: List[AgentFinding] = Field(default_factory=list)
    unknowns: List[str] = Field(
        default_factory=list,
        description="Explicit list of missing, unavailable, or unverifiable data points",
    )
    errors: List[str] = Field(default_factory=list)
    tools_executed: List[str] = Field(default_factory=list)
    model_provenance: Optional[ModelProvenance] = None
    started_at: str = Field(default_factory=utc_now_iso)
    completed_at: str = Field(default_factory=utc_now_iso)


class InvestigationPlan(BaseModel):
    """Execution plan built by the Orchestrator selecting only relevant specialist agents."""
    plan_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    correlation_id: str
    user_request: str
    selected_roles: List[AgentRole] = Field(default_factory=list)
    tasks: List[InvestigationTask] = Field(default_factory=list)
    rationale: str = ""


class OrchestratorReport(BaseModel):
    """Unified, evidence-backed diagnostic report synthesized by the Orchestrator Agent."""
    correlation_id: str
    user_request: str
    device: str = ""
    vdom: str = "root"
    overall_status: str = Field(
        default="unknown",
        description="Overall posture: healthy, degraded, critical, or unknown",
    )
    confidence: ConfidenceLevel = Field(default=ConfidenceLevel.MEDIUM)
    executive_summary: str = ""
    plan: InvestigationPlan
    specialist_results: List[AgentResult] = Field(default_factory=list)
    correlated_findings: List[AgentFinding] = Field(default_factory=list)
    contradictions: List[str] = Field(default_factory=list)
    unknowns: List[str] = Field(default_factory=list)
    recommended_actions: List[str] = Field(default_factory=list)
    model_provenance: Optional[ModelProvenance] = None
    started_at: str = Field(default_factory=utc_now_iso)
    completed_at: str = Field(default_factory=utc_now_iso)
