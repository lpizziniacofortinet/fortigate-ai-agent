import unittest

from agents import HealthAgent, NetworkAgent, SecurityAgent, ThreatAgent
from core.context import InvestigationContext
from core.llm_provider import DeterministicMockProvider
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
from tools.registry import ToolCapability


class TestDiagnosticSpecialists(unittest.TestCase):
    """Independent validation of all four read-only diagnostic specialist agents (Issue #16 Phase 2)."""

    def setUp(self):
        self.client = FortiGateClient(host="10.0.0.1", token="tok", vdom="root", mock=True)
        self.context = InvestigationContext(fg_client=self.client)

    def test_all_specialists_are_strictly_read_only_and_scoped(self):
        provider = DeterministicMockProvider()
        agents = [
            (NetworkAgent(provider=provider), AgentRole.NETWORK, ToolCapability.NETWORK_READ, "get_bgp_neighbors"),
            (HealthAgent(provider=provider), AgentRole.HEALTH, ToolCapability.HEALTH_READ, "get_ha_status"),
            (SecurityAgent(provider=provider), AgentRole.SECURITY, ToolCapability.SECURITY_READ, "run_security_audit"),
            (ThreatAgent(provider=provider), AgentRole.THREAT, ToolCapability.THREAT_READ, "get_top_sessions"),
        ]

        write_tool_names = {
            "toggle_interface",
            "reset_vpn_tunnel",
            "add_static_route",
            "toggle_firewall_policy",
            "apply_policy_hardening",
            "disconnect_ssl_vpn_user",
            "quarantine_ip_address",
        }

        for specialist, expected_role, expected_cap, expected_tool in agents:
            self.assertEqual(specialist.role, expected_role)
            self.assertEqual(specialist.allowed_capabilities, {expected_cap})
            bound_names = {fn.__name__ for fn in specialist.get_bound_tools(self.context)}
            self.assertIn(expected_tool, bound_names)
            self.assertTrue(bound_names.isdisjoint(write_tool_names))
            instr = specialist.build_system_instruction(self.context)
            self.assertIn("READ-ONLY", instr)
            self.assertIn("untrusted_evidence", instr)

    def test_each_specialist_runs_and_returns_structured_evidence(self):
        def build_handler(expected_tool: str, category: str):
            def _handler(prompt, tools, role):
                tool_map = {t.__name__: t for t in tools}
                raw = tool_map[expected_tool]()
                self.assertTrue(raw["untrusted_evidence"])
                return AgentResult(
                    agent_name=f"{role.value.title()}Agent",
                    agent_role=role,
                    task_id="t-1",
                    correlation_id=self.context.correlation_id,
                    device=self.context.device,
                    vdom=self.context.vdom,
                    status="completed",
                    summary=f"Inspected {expected_tool}",
                    findings=[
                        AgentFinding(
                            category=category,
                            severity=FindingSeverity.INFO,
                            status=FindingStatus.OK,
                            confidence=ConfidenceLevel.HIGH,
                            summary=f"{expected_tool} succeeded",
                            evidence=[
                                EvidenceItem(
                                    source_api=expected_tool,
                                    device=self.context.device,
                                    vdom=self.context.vdom,
                                    summary="Mock telemetry verified",
                                )
                            ],
                        )
                    ],
                ).model_dump_json()
            return _handler

        cases = [
            (NetworkAgent, AgentRole.NETWORK, "get_routing_table", "routing"),
            (HealthAgent, AgentRole.HEALTH, "get_system_resources", "resources"),
            (SecurityAgent, AgentRole.SECURITY, "get_firewall_policies", "policy"),
            (ThreatAgent, AgentRole.THREAT, "get_system_logs", "logs"),
        ]

        for cls, role, tool_name, cat in cases:
            specialist = cls(provider=DeterministicMockProvider(handler=build_handler(tool_name, cat)))
            task = InvestigationTask(
                task_id="t-1",
                correlation_id=self.context.correlation_id,
                objective=f"Inspect {cat}",
                target_role=role,
            )
            res = specialist.run(task, self.context)
            self.assertEqual(res.status, "completed")
            self.assertEqual(res.agent_role, role)
            self.assertEqual(res.findings[0].evidence[0].source_api, tool_name)


if __name__ == "__main__":
    unittest.main()
