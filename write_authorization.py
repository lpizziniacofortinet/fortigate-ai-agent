import hashlib
import hmac
import json
import sys
import time
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Callable, Dict, Optional, Set


def compute_proposal_digest(
    action: str,
    target: str,
    vdom: str,
    parameters: Dict[str, Any],
) -> str:
    """Computes a deterministic SHA-256 digest binding action, target, VDOM, and parameters."""
    canonical = json.dumps(
        {
            "action": action,
            "target": str(target),
            "vdom": str(vdom),
            "parameters": parameters,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ChangeProposal:
    """Structured change proposal for any FortiGate write/remediation action."""
    proposal_id: str
    action: str
    target: str
    vdom: str
    parameters: Dict[str, Any]
    current_state: Dict[str, Any]
    proposed_state: Dict[str, Any]
    risk: str
    created_at: float
    expires_at: float
    digest: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class ApprovalToken:
    """Single-use, expiring approval token cryptographically bound to a ChangeProposal digest."""
    token_id: str
    proposal_id: str
    proposal_digest: str
    approved_by: str
    issued_at: float
    expires_at: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class WriteApprovalError(PermissionError):
    """Raised when a write action lacks valid, unexpired, single-use authorization."""

    def __init__(self, reason_code: str, message: str, proposal: Optional[ChangeProposal] = None):
        self.reason_code = reason_code
        self.proposal = proposal
        super().__init__(message)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": "denied",
            "error": self.reason_code,
            "message": str(self),
            "proposal": self.proposal.to_dict() if self.proposal else None,
        }


def _default_interactive_confirm(proposal: ChangeProposal) -> bool:
    """Default interactive TTY confirmation prompt displaying the structured ChangeProposal."""
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Confirm

    console = Console()
    body = (
        f"[bold]Action:[/bold] [cyan]{proposal.action}[/cyan]\n"
        f"[bold]Target:[/bold] [cyan]{proposal.target}[/cyan] (VDOM: {proposal.vdom})\n"
        f"[bold]Risk:[/bold] [bold red]{proposal.risk.upper()}[/bold red]\n"
        f"[bold]Current State:[/bold] {json.dumps(proposal.current_state, default=str)}\n"
        f"[bold]Proposed State:[/bold] {json.dumps(proposal.proposed_state, default=str)}\n"
        f"[bold]Parameters:[/bold] {json.dumps(proposal.parameters, default=str)}\n"
        f"[bold]Proposal ID:[/bold] {proposal.proposal_id} | [bold]Digest:[/bold] {proposal.digest[:16]}..."
    )
    console.print(Panel(body, title="⚠️  Write Action Authorization Required", border_style="yellow"))
    return Confirm.ask("Do you authorize this exact change proposal?")


class WriteAuthorizationController:
    """
    Centralized authorization controller for all FortiGate write/mitigation actions.
    - Generates structured ChangeProposals.
    - Requires explicit approval bound to the exact proposal digest.
    - Enforces approval TTL expiration and single-use replay prevention.
    - Denies non-interactive (non-TTY, JSON, CI, cron, agentic) writes by default unless
      an explicit, valid ApprovalToken is supplied or pre-registered.
    """

    def __init__(
        self,
        default_ttl_seconds: int = 300,
        interactive_confirm_fn: Optional[Callable[[ChangeProposal], bool]] = None,
        clock_fn: Callable[[], float] = time.time,
        isatty_fn: Optional[Callable[[], bool]] = None,
    ):
        self.default_ttl_seconds = default_ttl_seconds
        self._interactive_confirm_fn = interactive_confirm_fn or _default_interactive_confirm
        self._clock = clock_fn
        self._isatty = isatty_fn or (lambda: bool(sys.stdin and sys.stdin.isatty()))
        self._consumed_token_ids: Set[str] = set()
        self._pending_approvals: Dict[str, ApprovalToken] = {}

    def create_proposal(
        self,
        action: str,
        target: str,
        vdom: str,
        parameters: Dict[str, Any],
        current_state: Optional[Dict[str, Any]] = None,
        proposed_state: Optional[Dict[str, Any]] = None,
        risk: str = "high",
        ttl_seconds: Optional[int] = None,
    ) -> ChangeProposal:
        now = self._clock()
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        digest = compute_proposal_digest(action=action, target=target, vdom=vdom, parameters=parameters)
        return ChangeProposal(
            proposal_id=uuid.uuid4().hex[:12],
            action=action,
            target=str(target),
            vdom=str(vdom),
            parameters=dict(parameters),
            current_state=dict(current_state or {}),
            proposed_state=dict(proposed_state or {}),
            risk=risk,
            created_at=now,
            expires_at=now + ttl,
            digest=digest,
        )

    def issue_approval(
        self,
        proposal: ChangeProposal,
        approved_by: str = "operator",
        ttl_seconds: Optional[int] = None,
    ) -> ApprovalToken:
        now = self._clock()
        ttl = self.default_ttl_seconds if ttl_seconds is None else ttl_seconds
        return ApprovalToken(
            token_id=uuid.uuid4().hex,
            proposal_id=proposal.proposal_id,
            proposal_digest=proposal.digest,
            approved_by=approved_by,
            issued_at=now,
            expires_at=min(proposal.expires_at, now + ttl) if ttl_seconds is None else now + ttl,
        )

    def register_approval(self, token: ApprovalToken) -> None:
        """Pre-registers a single-use approval token for non-interactive execution."""
        self._pending_approvals[token.proposal_digest] = token

    def authorize(
        self,
        proposal: ChangeProposal,
        approval_token: Optional[ApprovalToken] = None,
        allow_interactive: bool = True,
    ) -> ApprovalToken:
        now = self._clock()
        if now > proposal.expires_at:
            raise WriteApprovalError(
                "proposal_expired",
                f"Change proposal '{proposal.proposal_id}' for '{proposal.action}' has expired.",
                proposal=proposal,
            )

        token = approval_token
        used_pending_key: Optional[str] = None
        if token is None and proposal.digest in self._pending_approvals:
            token = self._pending_approvals[proposal.digest]
            used_pending_key = proposal.digest

        if token is not None:
            if token.token_id in self._consumed_token_ids:
                raise WriteApprovalError(
                    "approval_replayed",
                    f"Approval token '{token.token_id}' has already been used (replay rejected).",
                    proposal=proposal,
                )
            if now > token.expires_at:
                raise WriteApprovalError(
                    "approval_expired",
                    f"Approval token '{token.token_id}' for '{proposal.action}' has expired.",
                    proposal=proposal,
                )
            if not hmac.compare_digest(token.proposal_digest, proposal.digest):
                raise WriteApprovalError(
                    "approval_mismatch",
                    f"Approval token '{token.token_id}' does not match the target/parameters of proposal '{proposal.action}'.",
                    proposal=proposal,
                )

            self._consumed_token_ids.add(token.token_id)
            if used_pending_key is not None:
                self._pending_approvals.pop(used_pending_key, None)
            return token

        # No explicit token supplied: only interactive TTY confirmation is allowed.
        if allow_interactive and self._isatty():
            if not self._interactive_confirm_fn(proposal):
                raise WriteApprovalError(
                    "approval_rejected",
                    f"Operator rejected write action '{proposal.action}' on target '{proposal.target}'.",
                    proposal=proposal,
                )
            issued = self.issue_approval(proposal, approved_by="interactive_tty")
            self._consumed_token_ids.add(issued.token_id)
            return issued

        raise WriteApprovalError(
            "approval_required",
            (
                f"Write action '{proposal.action}' on target '{proposal.target}' (VDOM: {proposal.vdom}) "
                f"was denied in non-interactive mode: explicit proposal-bound approval is required "
                f"(proposal_id={proposal.proposal_id}, digest={proposal.digest})."
            ),
            proposal=proposal,
        )
