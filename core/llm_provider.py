"""Provider-agnostic LLM abstraction and flagship per-agent ModelRegistry."""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
import os
import time
from typing import Any, Callable, Dict, List, Optional

from core.schemas import AgentRole, ModelProvenance


@dataclass(frozen=True)
class ModelConfig:
    """Configuration for a specific agent's model and provider."""
    provider: str = "gemini"
    model_id: str = "gemini-4-neon"
    temperature: float = 0.2
    timeout_seconds: float = 90.0
    max_output_tokens: Optional[int] = None


@dataclass
class ProviderResponse:
    """Normalized response returned by any LLM provider implementation."""
    text: str
    tools_executed: List[str] = field(default_factory=list)
    model_provenance: Optional[ModelProvenance] = None
    raw_steps: List[Dict[str, Any]] = field(default_factory=list)


class BaseLLMProvider(ABC):
    """Abstract provider interface decoupling specialist agents from any single LLM vendor."""

    provider_name: str = "base"

    @abstractmethod
    def generate_with_tools(
        self,
        prompt: str,
        system_instruction: str,
        tools: List[Callable[..., Any]],
        model_config: ModelConfig,
        role: AgentRole,
    ) -> ProviderResponse:
        """Executes a tool-enabled reasoning turn and returns a normalized ProviderResponse."""


class GeminiLLMProvider(BaseLLMProvider):
    """Google Gemini SDK provider implementation with provenance tracking."""

    provider_name: str = "gemini"

    def __init__(self, api_key: Optional[str] = None):
        from google import genai
        from config import Config

        self._genai = genai
        self.client = genai.Client(api_key=api_key or Config.GEMINI_API_KEY)

    def generate_with_tools(
        self,
        prompt: str,
        system_instruction: str,
        tools: List[Callable[..., Any]],
        model_config: ModelConfig,
        role: AgentRole,
    ) -> ProviderResponse:
        from google.genai import types

        start = time.monotonic()
        config_kwargs: Dict[str, Any] = {
            "system_instruction": system_instruction,
            "tools": tools,
            "temperature": model_config.temperature,
        }
        if model_config.max_output_tokens is not None:
            config_kwargs["max_output_tokens"] = model_config.max_output_tokens

        gen_config = types.GenerateContentConfig(**config_kwargs)
        chat = self.client.chats.create(model=model_config.model_id, config=gen_config)
        response = chat.send_message(prompt)
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)

        tools_executed: List[str] = []
        raw_steps: List[Dict[str, Any]] = []
        for msg in chat.get_history():
            for part in getattr(msg, "parts", []) or []:
                if getattr(part, "function_call", None):
                    fn_name = part.function_call.name
                    tools_executed.append(fn_name)
                    raw_steps.append({"step": "function_call", "name": fn_name})
                elif getattr(part, "function_response", None):
                    raw_steps.append({"step": "function_response", "name": part.function_response.name})

        token_usage: Dict[str, int] = {}
        usage = getattr(response, "usage_metadata", None)
        if usage is not None:
            for attr in ("prompt_token_count", "candidates_token_count", "total_token_count"):
                val = getattr(usage, attr, None)
                if isinstance(val, int):
                    token_usage[attr] = val

        provenance = ModelProvenance(
            provider=self.provider_name,
            model_id=model_config.model_id,
            role=role,
            latency_ms=elapsed_ms,
            token_usage=token_usage,
        )
        return ProviderResponse(
            text=response.text or "",
            tools_executed=tools_executed,
            model_provenance=provenance,
            raw_steps=raw_steps,
        )


class DeterministicMockProvider(BaseLLMProvider):
    """Deterministic offline provider for unit tests and Mock Mode validation."""

    provider_name: str = "mock"

    def __init__(self, handler: Optional[Callable[[str, List[Callable[..., Any]], AgentRole], str]] = None):
        self._handler = handler

    def generate_with_tools(
        self,
        prompt: str,
        system_instruction: str,
        tools: List[Callable[..., Any]],
        model_config: ModelConfig,
        role: AgentRole,
    ) -> ProviderResponse:
        start = time.monotonic()
        tools_executed: List[str] = []
        if self._handler is not None:
            text = self._handler(prompt, tools, role)
        else:
            text = "{}"
        elapsed_ms = round((time.monotonic() - start) * 1000.0, 2)
        return ProviderResponse(
            text=text,
            tools_executed=tools_executed,
            model_provenance=ModelProvenance(
                provider=self.provider_name,
                model_id=model_config.model_id,
                role=role,
                latency_ms=elapsed_ms,
            ),
        )


class ModelRegistry:
    """
    Resolves per-agent flagship model configurations.
    Defaults to highest-capability Gemini 4 models (gemini-4-carbon for orchestration/remediation,
    gemini-4-neon for domain specialists) and supports per-agent environment overrides.
    """

    DEFAULT_ROLE_MODELS: Dict[AgentRole, str] = {
        AgentRole.ORCHESTRATOR: "gemini-4-carbon",
        AgentRole.REMEDIATION: "gemini-4-carbon",
        AgentRole.SECURITY: "gemini-4-neon",
        AgentRole.THREAT: "gemini-4-neon",
        AgentRole.NETWORK: "gemini-4-neon",
        AgentRole.HEALTH: "gemini-4-neon",
    }

    ROLE_ENV_VARS: Dict[AgentRole, str] = {
        AgentRole.ORCHESTRATOR: "ORCHESTRATOR_MODEL",
        AgentRole.REMEDIATION: "REMEDIATION_AGENT_MODEL",
        AgentRole.SECURITY: "SECURITY_AGENT_MODEL",
        AgentRole.THREAT: "THREAT_AGENT_MODEL",
        AgentRole.NETWORK: "NETWORK_AGENT_MODEL",
        AgentRole.HEALTH: "HEALTH_AGENT_MODEL",
    }

    def __init__(self, overrides: Optional[Dict[AgentRole, ModelConfig]] = None):
        self._overrides: Dict[AgentRole, ModelConfig] = dict(overrides or {})

    def get_model_config(self, role: AgentRole) -> ModelConfig:
        if role in self._overrides:
            return self._overrides[role]

        provider = os.getenv("LLM_PROVIDER", "gemini").strip().lower()
        role_env = self.ROLE_ENV_VARS[role]
        model_id = os.getenv(role_env)
        if not model_id:
            if role == AgentRole.ORCHESTRATOR:
                model_id = os.getenv("ORCHESTRATOR_MODEL", self.DEFAULT_ROLE_MODELS[role])
            else:
                model_id = os.getenv("SPECIALIST_MODEL") or os.getenv("GEMINI_MODEL") or self.DEFAULT_ROLE_MODELS[role]

        return ModelConfig(provider=provider, model_id=model_id.strip())
