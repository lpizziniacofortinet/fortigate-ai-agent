"""Core multi-agent foundation for FortiGate AI Agent (Issue #16 Phase 1)."""

from core.schemas import (
    AgentRole,
    FindingSeverity,
    FindingStatus,
    ConfidenceLevel,
    EvidenceItem,
    AgentFinding,
    ModelProvenance,
    InvestigationTask,
    AgentResult,
)
from core.context import InvestigationContext
from core.llm_provider import (
    ModelConfig,
    ProviderResponse,
    BaseLLMProvider,
    GeminiLLMProvider,
    DeterministicMockProvider,
    ModelRegistry,
)
from core.agent_base import BaseAgent

__all__ = [
    "AgentRole",
    "FindingSeverity",
    "FindingStatus",
    "ConfidenceLevel",
    "EvidenceItem",
    "AgentFinding",
    "ModelProvenance",
    "InvestigationTask",
    "AgentResult",
    "InvestigationContext",
    "ModelConfig",
    "ProviderResponse",
    "BaseLLMProvider",
    "GeminiLLMProvider",
    "DeterministicMockProvider",
    "ModelRegistry",
    "BaseAgent",
]
