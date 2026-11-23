import asyncio
import json
import os
import time
import unittest
from unittest.mock import patch, MagicMock

from core.agent_base import BaseAgent
from core.context import InvestigationContext
from core.llm_provider import DeterministicMockProvider, ModelConfig, ModelRegistry
from core.schemas import (
    AgentFinding,
    AgentResult,
    AgentRole,
    ConfidenceLevel,
    EvidenceItem,
    FindingSeverity,
    FindingStatus,
    InvestigationTask,
)
from fortigate_client import FortiGateClient
from tools.registry import ToolCapability, ToolCatalog
from write_authorization import WriteApprovalError, WriteAuthorizationController


class _DummyNetworkAgent(BaseAgent):
    role = AgentRole.NETWORK
    name = "NetworkAgent"
    allowed_capabilities = {ToolCapability.NETWORK_READ}

    def build_system_instruction(self, context: InvestigationContext) -> str:
        return f"Network specialist for {context.device} (vdom={context.vdom})."


class _IllegalWriteNetworkAgent(BaseAgent):
    role = AgentRole.NETWORK
    name = "IllegalAgent"
    allowed_capabilities = {ToolCapability.NETWORK_READ, ToolCapability.REMEDIATION_WRITE}

    def build_system_instruction(self, context: InvestigationContext) -> str:
        return "Should never initialize."


class TestPhase1Foundation(unittest.TestCase):
    """Baseline tests for Issue #16 Phase 1: schemas, context cache, tool catalog, ModelRegistry, BaseAgent."""

    def setUp(self):
        self.client = FortiGateClient(
            host="10.0.0.1",
            token="tok",
            vdom="root",
            enable_write_actions=True,
            dry_run=True,
            mock=True,
        )
        self.auth_ctrl = WriteAuthorizationController(isatty_fn=lambda: False)
        self.context = InvestigationContext(fg_client=self.client, auth_controller=self.auth_ctrl)

    def test_least_privilege_blocks_write_capability_for_diagnostic_agents(self):
        provider = DeterministicMockProvider()
        with self.assertRaises(PermissionError):
            _IllegalWriteNetworkAgent(provider=provider)

        catalog = ToolCatalog.default()
        for role in (AgentRole.ORCHESTRATOR, AgentRole.NETWORK, AgentRole.SECURITY, AgentRole.THREAT, AgentRole.HEALTH):
            with self.assertRaises(PermissionError):
                catalog.bind_for_role(role, {ToolCapability.REMEDIATION_WRITE}, self.context)

    def test_capability_scoping_and_per_investigation_telemetry_cache(self):
        spy_client = MagicMock(wraps=self.client)
        spy_client.host = self.client.host
        spy_client.vdom = self.client.vdom
        ctx = InvestigationContext(fg_client=spy_client, auth_controller=self.auth_ctrl)

        catalog = ToolCatalog.default()
        net_tools = {fn.__name__: fn for fn in catalog.bind_for_role(AgentRole.NETWORK, {ToolCapability.NETWORK_READ}, ctx)}
        health_tools = {fn.__name__: fn for fn in catalog.bind_for_role(AgentRole.HEALTH, {ToolCapability.HEALTH_READ}, ctx)}

        self.assertIn("get_interfaces", net_tools)
        self.assertIn("get_interfaces", health_tools)
        self.assertNotIn("toggle_interface", net_tools)
        self.assertNotIn("toggle_interface", health_tools)

        # Calling get_interfaces from two different agents hits FortiGateClient only once due to shared cache
        res1 = net_tools["get_interfaces"]()
        res2 = health_tools["get_interfaces"]()
        self.assertTrue(res1["untrusted_evidence"])
        self.assertTrue(res2["untrusted_evidence"])
        self.assertEqual(spy_client.get_interfaces.call_count, 1)

    def test_remediation_tools_require_explicit_approval_and_invalidate_cache(self):
        catalog = ToolCatalog.default()
        rem_tools = {
            fn.__name__: fn
            for fn in catalog.bind_for_role(
                AgentRole.REMEDIATION,
                {ToolCapability.BACKUP_READ, ToolCapability.REMEDIATION_WRITE},
                self.context,
            )
        }
        self.assertIn("toggle_interface", rem_tools)

        # Denied without proposal-bound approval in non-TTY mode
        with self.assertRaises(WriteApprovalError):
            rem_tools["toggle_interface"]("port1", "up")

        # Populate cache, then authorize exact write -> cache must be invalidated
        self.context.get_or_fetch("get_interfaces", lambda: {"results": []})
        self.assertGreater(len(self.context._cache), 0)

        prop = self.auth_ctrl.create_proposal(
            action="toggle_interface",
            target="port1",
            vdom="root",
            parameters={"interface_name": "port1", "status": "up"},
        )
        self.auth_ctrl.register_approval(self.auth_ctrl.issue_approval(prop))
        res = rem_tools["toggle_interface"]("port1", "up")
        self.assertEqual(res["status"], "dry_run")
        self.assertEqual(len(self.context._cache), 0)

    def test_model_registry_flagship_defaults_and_per_agent_overrides(self):
        with patch.dict(os.environ, {}, clear=False):
            for k in (
                "GEMINI_MODEL",
                "ORCHESTRATOR_MODEL",
                "SPECIALIST_MODEL",
                "NETWORK_AGENT_MODEL",
                "SECURITY_AGENT_MODEL",
            ):
                os.environ.pop(k, None)

            reg = ModelRegistry()
            self.assertEqual(reg.get_model_config(AgentRole.ORCHESTRATOR).model_id, "gemini-4-carbon")
            self.assertEqual(reg.get_model_config(AgentRole.REMEDIATION).model_id, "gemini-4-carbon")
            self.assertEqual(reg.get_model_config(AgentRole.NETWORK).model_id, "gemini-4-neon")

        with patch.dict(os.environ, {"SECURITY_AGENT_MODEL": "gemini-4-carbon"}, clear=False):
            reg = ModelRegistry()
            self.assertEqual(reg.get_model_config(AgentRole.SECURITY).model_id, "gemini-4-carbon")

    def test_base_agent_structured_result_and_trace_logging(self):
        task = InvestigationTask(
            objective="Check WAN interface and VPN state",
            target_role=AgentRole.NETWORK,
            device=self.context.device,
            vdom=self.context.vdom,
            correlation_id=self.context.correlation_id,
        )

        def fake_handler(prompt, tools, role):
            tool_map = {t.__name__: t for t in tools}
            intf_data = tool_map["get_interfaces"]()
            result = AgentResult(
                agent_name="NetworkAgent",
                agent_role=AgentRole.NETWORK,
                task_id=task.task_id,
                correlation_id=task.correlation_id,
                device=self.context.device,
                vdom=self.context.vdom,
                status="completed",
                summary="port2 is down",
                findings=[
                    AgentFinding(
                        category="interfaces",
                        severity=FindingSeverity.HIGH,
                        status=FindingStatus.DEGRADED,
                        confidence=ConfidenceLevel.HIGH,
                        summary="WAN backup port2 is down",
                        evidence=[
                            EvidenceItem(
                                source_api="get_interfaces",
                                device=self.context.device,
                                vdom=self.context.vdom,
                                summary="port2 link down",
                                values={"interface_count": len(intf_data["evidence_payload"]["results"])},
                            )
                        ],
                        affected_objects=["port2"],
                        remediation_required=True,
                    )
                ],
                unknowns=["Upstream ISP circuit status unavailable via FortiOS API."],
            )
            return result.model_dump_json()

        agent = _DummyNetworkAgent(provider=DeterministicMockProvider(handler=fake_handler))
        res = agent.run(task, self.context)

        self.assertEqual(res.status, "completed")
        self.assertEqual(res.correlation_id, self.context.correlation_id)
        self.assertEqual(len(res.findings), 1)
        self.assertEqual(res.findings[0].status, FindingStatus.DEGRADED)
        self.assertEqual(len(res.unknowns), 1)
        self.assertEqual(res.model_provenance.model_id, "gemini-4-neon")
        self.assertTrue(any(e["event"] == "agent_complete" for e in self.context.trace_events))

    def test_base_agent_async_timeout_and_provider_error_fallback(self):
        # 1. Provider exception -> deterministic error AgentResult
        def failing_handler(prompt, tools, role):
            raise RuntimeError("Provider 503 unavailable")

        task = InvestigationTask(objective="Check health", target_role=AgentRole.NETWORK)
        agent = _DummyNetworkAgent(provider=DeterministicMockProvider(handler=failing_handler))
        err_res = agent.run(task, self.context)
        self.assertEqual(err_res.status, "error")
        self.assertTrue(len(err_res.errors) >= 1)

        # 2. Async timeout -> deterministic timeout AgentResult
        def slow_handler(prompt, tools, role):
            time.sleep(0.3)
            return "{}"

        slow_task = InvestigationTask(objective="Slow check", target_role=AgentRole.NETWORK, timeout_seconds=0.05)
        slow_agent = _DummyNetworkAgent(provider=DeterministicMockProvider(handler=slow_handler))
        timeout_res = asyncio.run(slow_agent.arun(slow_task, self.context))
        self.assertEqual(timeout_res.status, "timeout")
        self.assertTrue(len(timeout_res.unknowns) >= 1)


if __name__ == "__main__":
    unittest.main()
