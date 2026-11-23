"""Write-gated Remediation Agent with Deterministic Policy Engine, approval enforcement, and post-change verification (Issue #16 Phase 4)."""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Tuple

from core.agent_base import BaseAgent
from core.context import InvestigationContext
from core.llm_provider import BaseLLMProvider, ModelConfig, ModelRegistry
from core.policy_engine import DeterministicPolicyEngine, PolicyDecision, PolicyViolationError
from core.schemas import AgentRole, utc_now_iso
from core.verification import PostChangeVerifier, VerificationResult, VerificationStatus
from tools.registry import ToolCapability, ToolCatalog
from write_authorization import ApprovalToken, ChangeProposal


@dataclass
class RemediationExecutionRecord:
    """Auditable end-to-end record of a proposed and executed FortiGate remediation."""
    correlation_id: str
    proposal: Dict[str, Any]
    policy_decision: Dict[str, Any]
    approved_by: Optional[str] = None
    approval_token_id: Optional[str] = None
    executed: bool = False
    dry_run: bool = False
    execution_result: Dict[str, Any] = field(default_factory=dict)
    post_change_status: Optional[str] = None
    post_change_verified: Optional[bool] = None
    post_change_evidence: Dict[str, Any] = field(default_factory=dict)
    rollback_guidance: str = ""
    timestamp: str = field(default_factory=utc_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RemediationAgent(BaseAgent):
    """
    Gated Remediation Agent (gemini-4-carbon by default).
    - Translates approved findings into immutable ChangeProposals.
    - Enforces DeterministicPolicyEngine validation before authorization.
    - Enforces WriteAuthorizationController (exact proposal-bound single-use approval).
    - Relies on FortiGateClient's fail-closed pre-change backup before writes.
    - Performs read-after-write post-change verification and records a full audit trail.
    """

    role = AgentRole.REMEDIATION
    name = "RemediationAgent"
    allowed_capabilities = {ToolCapability.BACKUP_READ, ToolCapability.REMEDIATION_WRITE}

    def __init__(
        self,
        provider: BaseLLMProvider,
        policy_engine: Optional[DeterministicPolicyEngine] = None,
        verifier: Optional[PostChangeVerifier] = None,
        model_config: Optional[ModelConfig] = None,
        model_registry: Optional[ModelRegistry] = None,
        tool_catalog: Optional[ToolCatalog] = None,
    ):
        super().__init__(
            provider=provider,
            model_config=model_config,
            model_registry=model_registry,
            tool_catalog=tool_catalog,
        )
        self.policy_engine = policy_engine or DeterministicPolicyEngine()
        self.verifier = verifier or PostChangeVerifier()

    def build_system_instruction(self, context: InvestigationContext) -> str:
        return (
            f"You are the FortiGate Remediation Specialist Agent for device '{context.device}' "
            f"(VDOM: '{context.vdom}', correlation_id: '{context.correlation_id}').\n"
            "You translate verified, evidence-backed findings into precise, minimal change proposals "
            "including rollback steps and post-change verification checks. "
            "All writes are guarded externally by DeterministicPolicyEngine, WriteAuthorizationController, "
            "and fail-closed pre-change backups."
        )

    @staticmethod
    def _build_rollback_guidance(action: str, target: str, parameters: Dict[str, Any]) -> str:
        if action == "toggle_interface":
            prev = "down" if str(parameters.get("status", "")).lower() == "up" else "up"
            return f"Restore interface '{target}' to '{prev}' via toggle_interface('{target}', '{prev}') or restore pre-change .conf backup."
        if action == "toggle_firewall_policy":
            prev = "disable" if str(parameters.get("status", "")).lower() == "enable" else "enable"
            return f"Revert policy {parameters.get('policy_id')} to '{prev}' or restore pre-change .conf backup."
        return "Restore the verified pre-change .conf backup snapshot created prior to execution."

    def prepare_proposal(
        self,
        action: str,
        target: str,
        parameters: Dict[str, Any],
        context: InvestigationContext,
        current_state: Optional[Dict[str, Any]] = None,
        proposed_state: Optional[Dict[str, Any]] = None,
    ) -> Tuple[ChangeProposal, PolicyDecision]:
        """
        Validates a candidate remediation through DeterministicPolicyEngine and creates
        an immutable ChangeProposal bound to action, target, VDOM, and exact parameters.
        """
        decision = self.policy_engine.evaluate(
            action=action,
            target=target,
            vdom=context.vdom,
            parameters=parameters,
            device=context.device,
        )
        if not decision.allowed:
            context.record_trace(
                "policy_denied",
                {"action": action, "target": target, "violations": decision.violations},
            )
            raise PolicyViolationError(decision)

        proposal = context.auth_controller.create_proposal(
            action=action,
            target=target,
            vdom=context.vdom,
            parameters=parameters,
            current_state=current_state or {"preconditions": decision.preconditions},
            proposed_state=proposed_state or parameters,
            risk=decision.risk,
        )
        context.record_trace(
            "proposal_created",
            {"proposal_id": proposal.proposal_id, "action": action, "target": target, "risk": decision.risk},
        )
        return proposal, decision

    def _verify_post_change(
        self,
        proposal: ChangeProposal,
        context: InvestigationContext,
    ) -> VerificationResult:
        """Performs action-specific, tri-state read-after-write verification against the FortiGate."""
        return self.verifier.verify(proposal, context)

    def execute_proposal(
        self,
        proposal: ChangeProposal,
        context: InvestigationContext,
        approval_token: Optional[ApprovalToken] = None,
        verify_post_change: bool = True,
    ) -> RemediationExecutionRecord:
        """
        Executes a validated, explicitly approved ChangeProposal with fail-closed backup
        and action-specific tri-state post-change verification.
        """
        # 1. Re-validate deterministically before touching authorization or firewall
        decision = self.policy_engine.evaluate(
            action=proposal.action,
            target=proposal.target,
            vdom=proposal.vdom,
            parameters=proposal.parameters,
            device=context.device,
        )
        if not decision.allowed:
            raise PolicyViolationError(decision)

        # 2. Enforce global write enablement
        client = context.fg_client
        if not client.enable_write_actions:
            raise PermissionError(
                "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True to proceed."
            )

        # 3. Enforce centralized proposal-bound authorization (non-TTY denied by default)
        consumed_token = context.auth_controller.authorize(proposal, approval_token=approval_token)

        # 4. Dispatch exact FortiGateClient write method (enforces fail-closed pre-change backup)
        dispatch = {
            "toggle_interface": lambda p: client.toggle_interface(p["interface_name"], p["status"]),
            "reset_vpn_tunnel": lambda p: client.reset_vpn_tunnel(p["p1_name"]),
            "add_static_route": lambda p: client.add_static_route(p["destination"], p["gateway"], p["interface"]),
            "toggle_firewall_policy": lambda p: client.toggle_firewall_policy(p["policy_id"], p["status"]),
            "apply_policy_hardening": lambda p: client.apply_policy_hardening(p["policy_id"]),
            "disconnect_ssl_vpn_user": lambda p: client.disconnect_ssl_vpn_user(p["username"]),
            "quarantine_ip_address": lambda p: client.quarantine_ip_address(
                p["ip_address"], p.get("duration_seconds", 3600), p.get("reason", "")
            ),
        }
        exec_res = dispatch[proposal.action](proposal.parameters)
        is_dry_run = exec_res.get("status") == "dry_run"

        # 5. Invalidate shared cache and run action-specific tri-state post-change verification
        context.invalidate_cache()
        post_status: Optional[str] = None
        verified: Optional[bool] = None
        verify_evidence: Dict[str, Any] = {}
        if verify_post_change and not is_dry_run:
            vres = self._verify_post_change(proposal, context)
            post_status = vres.status.value
            verified = vres.verified
            verify_evidence = vres.to_dict()

        record = RemediationExecutionRecord(
            correlation_id=context.correlation_id,
            proposal=proposal.to_dict(),
            policy_decision=decision.to_dict(),
            approved_by=consumed_token.approved_by,
            approval_token_id=consumed_token.token_id,
            executed=not is_dry_run,
            dry_run=is_dry_run,
            execution_result=exec_res,
            post_change_status=post_status,
            post_change_verified=verified,
            post_change_evidence=verify_evidence,
            rollback_guidance=self._build_rollback_guidance(proposal.action, proposal.target, proposal.parameters),
        )
        context.record_trace(
            "remediation_executed",
            {
                "proposal_id": proposal.proposal_id,
                "action": proposal.action,
                "dry_run": is_dry_run,
                "post_change_status": post_status,
                "post_change_verified": verified,
            },
        )
        return record
