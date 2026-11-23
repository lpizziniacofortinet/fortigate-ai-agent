import os
import tempfile
import unittest
from unittest.mock import patch

from agents.remediation_agent import RemediationAgent
from core.context import InvestigationContext
from core.llm_provider import DeterministicMockProvider
from core.policy_engine import DeterministicPolicyEngine, PolicyViolationError
from fortigate_client import BackupRequiredError, FortiGateClient
from write_authorization import WriteApprovalError, WriteAuthorizationController


class TestRemediationAgentLifecycle(unittest.TestCase):
    """End-to-end tests for safe RemediationAgent workflow (Issue #16 Phase 4)."""

    def _setup_env(self, dry_run=False, enable_write=True):
        client = FortiGateClient(
            host="10.0.0.1",
            token="tok",
            vdom="root",
            enable_write_actions=enable_write,
            dry_run=dry_run,
            backup_before_write=True,
            mock=True,
        )
        ctrl = WriteAuthorizationController(isatty_fn=lambda: False)
        ctx = InvestigationContext(fg_client=client, auth_controller=ctrl)
        agent = RemediationAgent(
            provider=DeterministicMockProvider(),
            policy_engine=DeterministicPolicyEngine(),
        )
        return client, ctrl, ctx, agent

    def test_policy_violation_blocks_proposal_creation(self):
        _, _, ctx, agent = self._setup_env()
        with self.assertRaises(PolicyViolationError):
            agent.prepare_proposal(
                action="toggle_interface",
                target="mgmt",
                parameters={"interface_name": "mgmt", "status": "down"},
                context=ctx,
            )

    def test_non_tty_execution_denied_without_exact_approval(self):
        _, _, ctx, agent = self._setup_env(dry_run=True)
        proposal, decision = agent.prepare_proposal(
            action="toggle_interface",
            target="port1",
            parameters={"interface_name": "port1", "status": "up"},
            context=ctx,
        )
        self.assertTrue(decision.allowed)
        with self.assertRaises(WriteApprovalError):
            agent.execute_proposal(proposal, ctx)

    def test_approved_execution_runs_backup_executes_and_verifies_post_change(self):
        client, ctrl, ctx, agent = self._setup_env(dry_run=False)
        proposal, _ = agent.prepare_proposal(
            action="toggle_interface",
            target="port1",
            parameters={"interface_name": "port1", "status": "up"},
            context=ctx,
        )
        token = ctrl.issue_approval(proposal, approved_by="netops-lead")

        with tempfile.TemporaryDirectory() as tmpdir:
            orig_backup = client.backup_configuration
            with patch.object(client, "backup_configuration", side_effect=lambda: orig_backup(destination_dir=tmpdir)):
                record = agent.execute_proposal(proposal, ctx, approval_token=token)

        self.assertTrue(record.executed)
        self.assertFalse(record.dry_run)
        self.assertEqual(record.approved_by, "netops-lead")
        self.assertTrue(record.post_change_verified)
        self.assertIn("Restore interface 'port1'", record.rollback_guidance)

    def test_backup_failure_aborts_approved_remediation_fail_closed(self):
        client, ctrl, ctx, agent = self._setup_env(dry_run=False)
        proposal, _ = agent.prepare_proposal(
            action="toggle_firewall_policy",
            target="policy:5",
            parameters={"policy_id": 5, "status": "disable"},
            context=ctx,
        )
        token = ctrl.issue_approval(proposal, approved_by="netops-lead")

        with patch.object(client, "backup_configuration", side_effect=ConnectionError("Backup API 500")):
            with self.assertRaises(BackupRequiredError):
                agent.execute_proposal(proposal, ctx, approval_token=token)


if __name__ == "__main__":
    unittest.main()
