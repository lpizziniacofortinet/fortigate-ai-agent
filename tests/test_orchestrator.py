import asyncio
import json
import time
import unittest
from unittest.mock import MagicMock

from core.context import InvestigationContext
from core.llm_provider import DeterministicMockProvider
from core.orchestrator import OrchestratorAgent
from core.schemas import (
    AgentFinding,
    AgentResult,
    AgentRole,
    ConfidenceLevel,
    FindingSeverity,
    FindingStatus,
    InvestigationTask,
)
from core.task_manager import BoundedTaskManager
from fortigate_client import FortiGateClient


class TestOrchestratorAndTaskManager(unittest.TestCase):
    """Tests for Issue #16 Phase 3: selective planning, bounded parallel dispatch, correlation, contradictions."""

    def setUp(self):
        self.client = FortiGateClient(host="10.0.0.1", token="tok", vdom="root", mock=True)
        self.context = InvestigationContext(fg_client=self.client)

    def test_selective_planning_invokes_only_relevant_agents(self):
        orch = OrchestratorAgent(provider=DeterministicMockProvider())

        # Targeted threat query -> ThreatAgent only
        p_threat = orch.plan_investigation("Check recent logs and top talker sessions for brute force", self.context)
        self.assertEqual(p_threat.selected_roles, [AgentRole.THREAT])

        # Targeted BGP query -> Network + Security (for blocking policies)
        p_bgp = orch.plan_investigation("Why is BGP peer 10.255.0.2 down?", self.context)
        self.assertIn(AgentRole.NETWORK, p_bgp.selected_roles)
        self.assertIn(AgentRole.SECURITY, p_bgp.selected_roles)
        self.assertNotIn(AgentRole.THREAT, p_bgp.selected_roles)

        # Broad incident -> all 4 specialists
        p_broad = orch.plan_investigation("Users in Milan cannot reach the datacenter", self.context)
        self.assertEqual(
            set(p_broad.selected_roles),
            {AgentRole.NETWORK, AgentRole.HEALTH, AgentRole.SECURITY, AgentRole.THREAT},
        )

    def test_orchestrator_correlates_findings_detects_contradictions_and_uses_shared_cache(self):
        spy_client = MagicMock(wraps=self.client)
        spy_client.host = self.client.host
        spy_client.vdom = self.client.vdom
        ctx = InvestigationContext(fg_client=spy_client)

        def mock_llm(prompt, tools, role):
            tool_map = {t.__name__: t for t in tools}
            if role == AgentRole.ORCHESTRATOR:
                return json.dumps({
                    "executive_summary": "port2 is reported down by NetworkAgent while HealthAgent reported ok.",
                    "recommended_actions": ["Verify physical link on port2."],
                })
            if role == AgentRole.NETWORK:
                tool_map["get_interfaces"]()
                return AgentResult(
                    agent_name="NetworkAgent",
                    agent_role=AgentRole.NETWORK,
                    task_id="n1",
                    correlation_id=ctx.correlation_id,
                    status="completed",
                    summary="port2 link is down",
                    findings=[
                        AgentFinding(
                            category="interfaces",
                            severity=FindingSeverity.HIGH,
                            status=FindingStatus.DEGRADED,
                            confidence=ConfidenceLevel.HIGH,
                            summary="port2 is down",
                            affected_objects=["port2"],
                        )
                    ],
                ).model_dump_json()
            if role == AgentRole.HEALTH:
                tool_map["get_interfaces"]()
                return AgentResult(
                    agent_name="HealthAgent",
                    agent_role=AgentRole.HEALTH,
                    task_id="h1",
                    correlation_id=ctx.correlation_id,
                    status="completed",
                    summary="port2 appeared ok in summary",
                    findings=[
                        AgentFinding(
                            category="interfaces",
                            severity=FindingSeverity.INFO,
                            status=FindingStatus.OK,
                            confidence=ConfidenceLevel.MEDIUM,
                            summary="port2 ok",
                            affected_objects=["port2"],
                        )
                    ],
                    unknowns=["Hardware fan telemetry unavailable in VM."],
                ).model_dump_json()
            return AgentResult(
                agent_name=role.value,
                agent_role=role,
                task_id="x",
                correlation_id=ctx.correlation_id,
                status="completed",
                summary="ok",
            ).model_dump_json()

        orch = OrchestratorAgent(provider=DeterministicMockProvider(handler=mock_llm))
        report = orch.investigate("Check interface port2 and system health", ctx)

        self.assertEqual(report.overall_status, "degraded")
        self.assertEqual(len(report.contradictions), 1)
        self.assertIn("port2", report.contradictions[0])
        self.assertIn("Hardware fan telemetry unavailable in VM.", report.unknowns)
        # Shared cache prevented redundant get_interfaces calls across NetworkAgent & HealthAgent
        self.assertEqual(spy_client.get_interfaces.call_count, 1)
        self.assertEqual(report.model_provenance.model_id, "gemini-4-carbon")

    def test_bounded_task_manager_dependency_waves_and_timeout_isolation(self):
        execution_order = []

        def handler(prompt, tools, role):
            if role == AgentRole.HEALTH:
                time.sleep(0.2)  # will timeout
                return "{}"
            execution_order.append(role.value)
            if role == AgentRole.SECURITY:
                # Should have received prior_findings from Network task
                self.assertIn("prior_findings", prompt)
            return AgentResult(
                agent_name=f"{role.value}Agent",
                agent_role=role,
                task_id="t",
                correlation_id=self.context.correlation_id,
                status="completed",
                summary=f"{role.value} done",
            ).model_dump_json()

        orch = OrchestratorAgent(provider=DeterministicMockProvider(handler=handler))
        t_net = InvestigationTask(task_id="t_net", objective="check net", target_role=AgentRole.NETWORK)
        t_health = InvestigationTask(
            task_id="t_health", objective="slow health", target_role=AgentRole.HEALTH, timeout_seconds=0.05
        )
        t_sec = InvestigationTask(
            task_id="t_sec", objective="check sec", target_role=AgentRole.SECURITY, depends_on=["t_net"]
        )

        mgr = BoundedTaskManager(max_concurrency=2)
        results = asyncio.run(mgr.execute_tasks([t_net, t_health, t_sec], orch.specialists, self.context))
        by_id = {r.task_id: r for r in results}

        self.assertEqual(by_id["t_net"].status, "completed")
        self.assertEqual(by_id["t_health"].status, "timeout")
        self.assertEqual(by_id["t_sec"].status, "completed")
        self.assertEqual(execution_order, ["network", "security"])


if __name__ == "__main__":
    unittest.main()
