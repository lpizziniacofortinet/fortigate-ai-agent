import unittest

import agent
from fortigate_client import FortiGateClient
from write_authorization import (
    WriteAuthorizationController,
    WriteApprovalError,
    ChangeProposal,
)


class TestWriteAuthorization(unittest.TestCase):
    """Tests for centralized, proposal-bound write authorization (Issue #2)."""

    def setUp(self):
        self.now = [1000.0]
        self.clock = lambda: self.now[0]
        self.mock_client = FortiGateClient(
            host="10.0.0.1",
            token="tok",
            vdom="root",
            enable_write_actions=True,
            dry_run=True,
            mock=True,
        )
        agent._client = self.mock_client
        self.orig_controller = agent.get_write_auth_controller()

    def tearDown(self):
        agent.set_write_auth_controller(self.orig_controller)

    def test_non_tty_missing_approval_denied_for_all_write_tools(self):
        ctrl = WriteAuthorizationController(clock_fn=self.clock, isatty_fn=lambda: False)
        agent.set_write_auth_controller(ctrl)

        calls = [
            lambda: agent.reset_vpn_tunnel("Branch-2-VPN"),
            lambda: agent.toggle_interface("port1", "down"),
            lambda: agent.add_static_route("10.50.0.0/16", "198.51.100.1", "port1"),
            lambda: agent.toggle_firewall_policy(5, "disable"),
            lambda: agent.apply_policy_hardening(1),
            lambda: agent.disconnect_ssl_vpn_user("jdoe"),
            lambda: agent.quarantine_ip_address("198.51.100.99", 3600, "test"),
        ]
        for fn in calls:
            with self.assertRaises(WriteApprovalError) as ctx:
                fn()
            self.assertEqual(ctx.exception.reason_code, "approval_required")
            self.assertIsInstance(ctx.exception.proposal, ChangeProposal)

    def test_valid_proposal_bound_approval_succeeds_once_and_blocks_replay(self):
        ctrl = WriteAuthorizationController(clock_fn=self.clock, isatty_fn=lambda: False)
        agent.set_write_auth_controller(ctrl)

        proposal = ctrl.create_proposal(
            action="toggle_interface",
            target="port1",
            vdom="root",
            parameters={"interface_name": "port1", "status": "up"},
        )
        token = ctrl.issue_approval(proposal, approved_by="ci-approver")
        ctrl.register_approval(token)

        res = agent.toggle_interface("port1", "up")
        self.assertEqual(res["status"], "dry_run")

        # Replay with same token must fail
        with self.assertRaises(WriteApprovalError) as ctx:
            ctrl.authorize(proposal, approval_token=token)
        self.assertEqual(ctx.exception.reason_code, "approval_replayed")

        # Second tool invocation without fresh approval must fail
        with self.assertRaises(WriteApprovalError) as ctx2:
            agent.toggle_interface("port1", "up")
        self.assertEqual(ctx2.exception.reason_code, "approval_required")

    def test_expired_approval_rejected(self):
        ctrl = WriteAuthorizationController(default_ttl_seconds=60, clock_fn=self.clock, isatty_fn=lambda: False)
        proposal = ctrl.create_proposal(
            action="toggle_interface",
            target="port1",
            vdom="root",
            parameters={"interface_name": "port1", "status": "up"},
            ttl_seconds=120,
        )
        token = ctrl.issue_approval(proposal, ttl_seconds=30)
        self.now[0] += 35.0  # advance past token expiry

        with self.assertRaises(WriteApprovalError) as ctx:
            ctrl.authorize(proposal, approval_token=token)
        self.assertEqual(ctx.exception.reason_code, "approval_expired")

    def test_mismatched_target_or_parameters_rejected(self):
        ctrl = WriteAuthorizationController(clock_fn=self.clock, isatty_fn=lambda: False)
        approved_proposal = ctrl.create_proposal(
            action="toggle_interface",
            target="port1",
            vdom="root",
            parameters={"interface_name": "port1", "status": "up"},
        )
        token = ctrl.issue_approval(approved_proposal)

        different_proposal = ctrl.create_proposal(
            action="toggle_interface",
            target="port2",
            vdom="root",
            parameters={"interface_name": "port2", "status": "down"},
        )
        with self.assertRaises(WriteApprovalError) as ctx:
            ctrl.authorize(different_proposal, approval_token=token)
        self.assertEqual(ctx.exception.reason_code, "approval_mismatch")

    def test_interactive_tty_approved_and_rejected(self):
        approved_ctrl = WriteAuthorizationController(
            clock_fn=self.clock,
            isatty_fn=lambda: True,
            interactive_confirm_fn=lambda p: True,
        )
        agent.set_write_auth_controller(approved_ctrl)
        res = agent.toggle_interface("port1", "up")
        self.assertEqual(res["status"], "dry_run")

        rejected_ctrl = WriteAuthorizationController(
            clock_fn=self.clock,
            isatty_fn=lambda: True,
            interactive_confirm_fn=lambda p: False,
        )
        agent.set_write_auth_controller(rejected_ctrl)
        with self.assertRaises(WriteApprovalError) as ctx:
            agent.toggle_interface("port1", "up")
        self.assertEqual(ctx.exception.reason_code, "approval_rejected")


if __name__ == "__main__":
    unittest.main()
