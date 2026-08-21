import json
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
from rich.text import Text
from rich.align import Align

from fortigate_client import FortiGateClient

logger = logging.getLogger("SecurityAudit")

class AuditSeverity:
    CRITICAL = "CRITICAL"  # -15 pts
    HIGH = "HIGH"          # -8 pts
    MEDIUM = "MEDIUM"      # -4 pts
    LOW = "LOW"            # -2 pts
    INFO = "INFO"          # 0 pts

class AuditStatus:
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    INFO = "INFO"

class SecurityAuditFinding:
    """Represents a single security audit check finding."""
    def __init__(
        self,
        rule_id: str,
        category: str,
        title: str,
        severity: str,
        status: str,
        description: str,
        impact: str,
        remediation_steps: str,
        cli_commands: Optional[List[str]] = None,
        raw_evidence: Optional[Dict[str, Any]] = None
    ):
        self.rule_id = rule_id
        self.category = category
        self.title = title
        self.severity = severity
        self.status = status
        self.description = description
        self.impact = impact
        self.remediation_steps = remediation_steps
        self.cli_commands = cli_commands or []
        self.raw_evidence = raw_evidence or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "description": self.description,
            "impact": self.impact,
            "remediation_steps": self.remediation_steps,
            "cli_commands": self.cli_commands,
            "raw_evidence": self.raw_evidence
        }

class PolicyShadowingIssue:
    """Represents a detected firewall policy shadowing / conflict condition."""
    def __init__(
        self,
        shadowed_policy_id: int,
        shadowed_policy_name: str,
        shadowing_policy_id: int,
        shadowing_policy_name: str,
        reason: str,
        recommendation: str,
        cli_reorder_command: str
    ):
        self.shadowed_policy_id = shadowed_policy_id
        self.shadowed_policy_name = shadowed_policy_name
        self.shadowing_policy_id = shadowing_policy_id
        self.shadowing_policy_name = shadowing_policy_name
        self.reason = reason
        self.recommendation = recommendation
        self.cli_reorder_command = cli_reorder_command

    def to_dict(self) -> Dict[str, Any]:
        return {
            "shadowed_policy_id": self.shadowed_policy_id,
            "shadowed_policy_name": self.shadowed_policy_name,
            "shadowing_policy_id": self.shadowing_policy_id,
            "shadowing_policy_name": self.shadowing_policy_name,
            "reason": self.reason,
            "recommendation": self.recommendation,
            "cli_reorder_command": self.cli_reorder_command
        }

class SecurityAuditReport:
    """Comprehensive FortiOS Security Posture & CIS Hardening Benchmark Report."""
    def __init__(
        self,
        hostname: str,
        firmware: str,
        overall_score: float,
        letter_grade: str,
        findings: List[SecurityAuditFinding],
        shadowing_issues: List[PolicyShadowingIssue],
        execution_time: str
    ):
        self.hostname = hostname
        self.firmware = firmware
        self.overall_score = round(overall_score, 1)
        self.letter_grade = letter_grade
        self.findings = findings
        self.shadowing_issues = shadowing_issues
        self.execution_time = execution_time

    @property
    def passed_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.PASS)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.WARNING)

    @property
    def failed_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.FAIL)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.FAIL and f.severity == AuditSeverity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.FAIL and f.severity == AuditSeverity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.FAIL and f.severity == AuditSeverity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.status == AuditStatus.FAIL and f.severity == AuditSeverity.LOW)

    def generate_hardening_playbook(self) -> str:
        """Generates a complete, ready-to-execute FortiOS CLI playbook script."""
        lines = [
            f"# =====================================================================",
            f"# FortiGate Automated Hardening Playbook",
            f"# Target Device: {self.hostname} ({self.firmware})",
            f"# Generated: {self.execution_time}",
            f"# Security Posture Score: {self.overall_score}% [Grade: {self.letter_grade}]",
            f"# Total Remediation Actions: {self.failed_count + len(self.shadowing_issues)}",
            f"# =====================================================================",
            "",
            "# IMPORTANT: Review and validate all commands before executing on production systems.",
            ""
        ]

        if self.shadowing_issues:
            lines.append("# --- [SECTION 1: FIREWALL POLICY REORDERING & SHADOWING FIXES] ---")
            lines.append("config firewall policy")
            for sh in self.shadowing_issues:
                lines.append(f"    # Fix for: Policy {sh.shadowed_policy_id} shadowed by Policy {sh.shadowing_policy_id}")
                lines.append(f"    # {sh.reason}")
                lines.append(f"    {sh.cli_reorder_command}")
            lines.append("end")
            lines.append("")

        section_num = 2 if self.shadowing_issues else 1
        has_remediation = False
        for finding in self.findings:
            if finding.status in (AuditStatus.FAIL, AuditStatus.WARNING) and finding.cli_commands:
                has_remediation = True
                lines.append(f"# --- [SECTION {section_num}: {finding.rule_id} - {finding.title.upper()}] ---")
                lines.append(f"# Severity: {finding.severity} | Category: {finding.category}")
                lines.append(f"# Impact: {finding.impact}")
                for cmd in finding.cli_commands:
                    lines.append(cmd)
                lines.append("")
                section_num += 1

        if not has_remediation and not self.shadowing_issues:
            lines.append("# ✓ No configuration hardening remediation required. System meets benchmark requirements.")

        return "\n".join(lines)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "hostname": self.hostname,
            "firmware": self.firmware,
            "execution_time": self.execution_time,
            "overall_score": self.overall_score,
            "letter_grade": self.letter_grade,
            "summary": {
                "total_checks": len(self.findings),
                "passed": self.passed_count,
                "warnings": self.warning_count,
                "failed": self.failed_count,
                "critical": self.critical_count,
                "high": self.high_count,
                "medium": self.medium_count,
                "low": self.low_count
            },
            "shadowing_issues": [s.to_dict() for s in self.shadowing_issues],
            "findings": [f.to_dict() for f in self.findings],
            "hardening_playbook": self.generate_hardening_playbook()
        }

    def to_markdown(self) -> str:
        """Exports the audit report as GitHub-flavored markdown."""
        md = []
        md.append(f"# 🛡️ FortiOS Security Posture & CIS Hardening Benchmark Report")
        md.append(f"**Target Hostname:** `{self.hostname}` | **Firmware:** `{self.firmware}` | **Audit Date:** `{self.execution_time}`\n")
        
        md.append(f"## 📊 Executive Scorecard")
        md.append(f"| Metric | Score / Value | Status |")
        md.append(f"| :--- | :--- | :--- |")
        md.append(f"| **Overall Security Score** | **`{self.overall_score} / 100`** | **Grade: {self.letter_grade}** |")
        md.append(f"| **Total Benchmark Rules** | `{len(self.findings)}` | Evaluated |")
        md.append(f"| **Passed Checks** | `{self.passed_count}` | ✅ Compliant |")
        md.append(f"| **Warnings** | `{self.warning_count}` | ⚠️ Non-Blocking |")
        md.append(f"| **Failed Checks** | `{self.failed_count}` (Critical: {self.critical_count}, High: {self.high_count}) | ❌ Action Required |")
        md.append(f"| **Policy Shadowing Conflicts** | `{len(self.shadowing_issues)}` | 🔄 Reordering Needed |")
        md.append("\n---\n")

        if self.shadowing_issues:
            md.append("## 🔄 Firewall Policy Shadowing & Order Conflicts")
            md.append("The following policies are rendered inactive or shadowed because an earlier broad policy matches traffic first:\n")
            for sh in self.shadowing_issues:
                md.append(f"- **Shadowed Policy ID {sh.shadowed_policy_id}** (`{sh.shadowed_policy_name}`):")
                md.append(f"  - **Shadowed By:** Policy ID {sh.shadowing_policy_id} (`{sh.shadowing_policy_name}`)")
                md.append(f"  - **Root Cause:** {sh.reason}")
                md.append(f"  - **Fix:** `{sh.cli_reorder_command}`\n")
            md.append("---\n")

        md.append("## 🔍 Detailed Benchmark Findings\n")
        for finding in self.findings:
            icon = "✅" if finding.status == AuditStatus.PASS else ("⚠️" if finding.status == AuditStatus.WARNING else "❌")
            md.append(f"### {icon} [{finding.rule_id}] {finding.title}")
            md.append(f"- **Category:** `{finding.category}` | **Severity:** `{finding.severity}` | **Status:** **`{finding.status}`**")
            md.append(f"- **Observation:** {finding.description}")
            if finding.status != AuditStatus.PASS:
                md.append(f"- **Security Risk / Impact:** {finding.impact}")
                md.append(f"- **Remediation Recommendation:** {finding.remediation_steps}")
                if finding.cli_commands:
                    md.append("```fortios")
                    for cmd in finding.cli_commands:
                        md.append(cmd)
                    md.append("```")
            md.append("")

        md.append("---\n")
        md.append("## 🛠️ Automated FortiOS Hardening Playbook")
        md.append("```fortios")
        md.append(self.generate_hardening_playbook())
        md.append("```")

        return "\n".join(md)


class FortiGateSecurityAuditor:
    """
    Autonomous Security Posture & CIS/FortiOS Hardening Benchmark Engine.
    Performs comprehensive deep inspection across 6 security domains.
    """

    def __init__(self, client: FortiGateClient):
        self.client = client

    def detect_policy_shadowing(self, policies: List[Dict[str, Any]]) -> List[PolicyShadowingIssue]:
        """
        Analyzes the firewall security policy list in sequential evaluation order
        to detect shadowed, unreachable, or conflicting security rules.
        """
        shadowing_issues: List[PolicyShadowingIssue] = []
        enabled_policies = [p for p in policies if isinstance(p, dict) and (p.get("status") == "enable" or "status" not in p)]

        for i in range(len(enabled_policies)):
            p_prior = enabled_policies[i]
            p_prior_id = p_prior.get("policyid", i + 1)
            p_prior_name = p_prior.get("name", f"Policy-{p_prior_id}")
            p_prior_srcintf = [x.get("name", "").lower() for x in p_prior.get("srcintf", [])]
            p_prior_dstintf = [x.get("name", "").lower() for x in p_prior.get("dstintf", [])]
            p_prior_srcaddr = [x.get("name", "").lower() for x in p_prior.get("srcaddr", [])]
            p_prior_dstaddr = [x.get("name", "").lower() for x in p_prior.get("dstaddr", [])]
            p_prior_service = [x.get("name", "").lower() for x in p_prior.get("service", [])]
            p_prior_action = p_prior.get("action", "accept").lower()

            # Check if p_prior is an ultra-broad rule (matches all or interface-any)
            is_broad_prior = (
                ("all" in p_prior_srcaddr or not p_prior_srcaddr) and
                ("all" in p_prior_dstaddr or not p_prior_dstaddr) and
                ("all" in p_prior_service or "any" in p_prior_service or not p_prior_service)
            )

            if not is_broad_prior:
                continue

            for j in range(i + 1, len(enabled_policies)):
                p_later = enabled_policies[j]
                p_later_id = p_later.get("policyid", j + 1)
                p_later_name = p_later.get("name", f"Policy-{p_later_id}")
                p_later_srcintf = [x.get("name", "").lower() for x in p_later.get("srcintf", [])]
                p_later_dstintf = [x.get("name", "").lower() for x in p_later.get("dstintf", [])]
                p_later_action = p_later.get("action", "accept").lower()

                # Check if interface pair matches or overlaps
                intf_overlap = (
                    any(intf in p_prior_srcintf or "any" in p_prior_srcintf for intf in p_later_srcintf) and
                    any(intf in p_prior_dstintf or "any" in p_prior_dstintf for intf in p_later_dstintf)
                )

                if intf_overlap:
                    # Policy p_later is shadowed by p_prior!
                    reason = (
                        f"Prior Policy ID {p_prior_id} ('{p_prior_name}') matches all sources, destinations, and services "
                        f"on overlapping interfaces ({','.join(p_prior_srcintf)} -> {','.join(p_prior_dstintf)}). "
                        f"Subsequent Policy ID {p_later_id} ('{p_later_name}') with action '{p_later_action}' will never be evaluated."
                    )
                    rec = f"Move Policy {p_later_id} before Policy {p_prior_id}, or refine Policy {p_prior_id} to specific addresses/services."
                    cli_cmd = f"move {p_later_id} before {p_prior_id}"

                    shadowing_issues.append(PolicyShadowingIssue(
                        shadowed_policy_id=p_later_id,
                        shadowed_policy_name=p_later_name,
                        shadowing_policy_id=p_prior_id,
                        shadowing_policy_name=p_prior_name,
                        reason=reason,
                        recommendation=rec,
                        cli_reorder_command=cli_cmd
                    ))

        return shadowing_issues

    def run_audit(self) -> SecurityAuditReport:
        """Runs the complete multi-domain security audit and computes the benchmark scorecard."""
        findings: List[SecurityAuditFinding] = []
        
        # 1. Fetch raw telemetry safely
        try:
            sys_status = self.client.get_system_status()
        except Exception:
            sys_status = {}

        try:
            sys_res = self.client.get_system_resources()
        except Exception:
            sys_res = {}

        try:
            interfaces = self.client.get_interfaces()
        except Exception:
            interfaces = {}

        try:
            policies_raw = self.client.get_firewall_policies()
        except Exception:
            policies_raw = {}

        try:
            fortiguard = self.client.get_fortiguard_status()
        except Exception:
            fortiguard = {}

        try:
            ha_status = self.client.get_ha_status()
        except Exception:
            ha_status = {}

        try:
            sdwan_status = self.client.get_sdwan_status()
        except Exception:
            sdwan_status = {}

        try:
            vpn_status = self.client.get_vpn_status()
        except Exception:
            vpn_status = {}

        try:
            bgp_status = self.client.get_bgp_neighbors()
        except Exception:
            bgp_status = {}

        try:
            ospf_status = self.client.get_ospf_neighbors()
        except Exception:
            ospf_status = {}

        try:
            quarantined = self.client.get_quarantined_ips()
        except Exception:
            quarantined = {}

        try:
            arp_table = self.client.get_arp_table()
        except Exception:
            arp_table = {}

        try:
            dhcp_leases = self.client.get_dhcp_leases()
        except Exception:
            dhcp_leases = {}

        # Extract system metadata
        status_res = sys_status.get("results", {}) if isinstance(sys_status, dict) else {}
        if isinstance(status_res, list) and status_res:
            status_res = status_res[0]
        elif not isinstance(status_res, dict):
            status_res = {}

        hostname = status_res.get("hostname") or sys_status.get("hostname", "FortiGate-Unit")
        version = sys_status.get("version") or status_res.get("version", "FortiOS 7.x")
        build = sys_status.get("build") or status_res.get("build", "")
        firmware_str = f"FortiOS {version}" + (f" build {build}" if build else "")

        # -------------------------------------------------------------
        # DOMAIN 1: FIREWALL POLICIES & ACCESS CONTROL
        # -------------------------------------------------------------
        policy_list = policies_raw.get("results", []) if isinstance(policies_raw, dict) else []
        if isinstance(policy_list, dict):
            policy_list = list(policy_list.values())
        elif not isinstance(policy_list, list):
            policy_list = []

        # Check SEC-POL-01: Any-to-Any without UTM
        any_any_without_utm = []
        for p in policy_list:
            if not isinstance(p, dict):
                continue
            srcaddr = [x.get("name", "").lower() for x in p.get("srcaddr", [])]
            dstaddr = [x.get("name", "").lower() for x in p.get("dstaddr", [])]
            service = [x.get("name", "").lower() for x in p.get("service", [])]
            action = p.get("action", "accept").lower()
            status = p.get("status", "enable").lower()

            if action == "accept" and status == "enable":
                is_any = ("all" in srcaddr or not srcaddr) and ("all" in dstaddr or not dstaddr) and ("all" in service or "any" in service or not service)
                has_utm = (
                    p.get("utm-status") == "enable" or
                    p.get("utm_status") == "enable" or 
                    bool(p.get("av-profile")) or 
                    bool(p.get("av_profile")) or 
                    bool(p.get("ips-sensor")) or 
                    bool(p.get("ips_sensor")) or 
                    bool(p.get("webfilter-profile")) or 
                    bool(p.get("webfilter_profile")) or 
                    bool(p.get("ssl-ssh-profile")) or
                    bool(p.get("ssl_ssh_profile"))
                )
                if is_any and not has_utm:
                    any_any_without_utm.append(p.get("policyid", p.get("name", "Unknown")))

        if any_any_without_utm:
            cli_cmds = []
            for pid in any_any_without_utm:
                cli_cmds.extend([
                    "config firewall policy",
                    f"    edit {pid}",
                    "        set utm-status enable",
                    '        set ssl-ssh-profile "certificate-inspection"',
                    '        set av-profile "default"',
                    '        set ips-sensor "default"',
                    '        set webfilter-profile "default"',
                    "        set logtraffic all",
                    "    next",
                    "end"
                ])
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-1.1",
                category="Firewall Policy & Access Control",
                title="Permissive Any-to-Any Firewall Rules without Unified Threat Management (UTM)",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.FAIL,
                description=f"Detected {len(any_any_without_utm)} enabled firewall policy/policies ({', '.join(map(str, any_any_without_utm))}) matching all traffic (ALL source/dest/service) without AntiVirus, IPS, Web Filter, or SSL inspection profiles.",
                impact="Unrestricted, uninspected traffic can pass through the perimeter, allowing malware propagation, C2 beaconing, and lateral movement.",
                remediation_steps="Apply strict UTM profiles (AV, IPS, Web Filter, SSL Inspection) and enable full session logging on all accepted traffic policies.",
                cli_commands=cli_cmds
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-1.1",
                category="Firewall Policy & Access Control",
                title="Permissive Any-to-Any Firewall Rules without Unified Threat Management (UTM)",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.PASS,
                description="All active firewall policies have strict service/address constraints or active UTM profiles configured.",
                impact="Zero-Trust traffic inspection verified.",
                remediation_steps="None required."
            ))

        # Check SEC-POL-02: Policy Shadowing & Precedence Analysis
        shadowing_issues = self.detect_policy_shadowing(policy_list)
        if shadowing_issues:
            cli_reorders = ["config firewall policy"]
            for sh in shadowing_issues:
                cli_reorders.append(f"    {sh.cli_reorder_command}")
            cli_reorders.append("end")

            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-1.2",
                category="Firewall Policy & Access Control",
                title="Firewall Policy Precedence Inversion & Rule Shadowing",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.FAIL,
                description=f"Detected {len(shadowing_issues)} shadowed policy condition(s). Specifically, Policy {shadowing_issues[0].shadowed_policy_id} ('{shadowing_issues[0].shadowed_policy_name}') is rendered inactive by earlier broad Policy {shadowing_issues[0].shadowing_policy_id}.",
                impact="Crucial security restrictions (e.g. deny rules or specific routing controls) are bypassed because earlier broad policies match first.",
                remediation_steps="Reorder security policies so granular deny and application rules are evaluated prior to broad catch-all rules.",
                cli_commands=cli_reorders
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-1.2",
                category="Firewall Policy & Access Control",
                title="Firewall Policy Precedence Inversion & Rule Shadowing",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.PASS,
                description="Firewall policy sequence evaluation is optimal with no shadowed or unreachable rules detected.",
                impact="Rule evaluation integrity maintained.",
                remediation_steps="None required."
            ))

        # Check SEC-POL-03: Stale / Inactive Disabled Policies
        disabled_policies = [p.get("policyid", p.get("name", "Unknown")) for p in policy_list if isinstance(p, dict) and p.get("status") == "disable"]
        if len(disabled_policies) > 3:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-1.3",
                category="Firewall Policy & Access Control",
                title="Accumulation of Stale / Disabled Firewall Policies",
                severity=AuditSeverity.LOW,
                status=AuditStatus.WARNING,
                description=f"Detected {len(disabled_policies)} disabled firewall policy entries ({', '.join(map(str, disabled_policies[:5]))}...).",
                impact="Clutters configuration audits and increases risk of accidental reactivation during change windows.",
                remediation_steps="Audit and permanently decommission inactive or obsolete firewall rules.",
                cli_commands=[f"# Review or purge disabled policies: {', '.join(map(str, disabled_policies))}"]
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-1.3",
                category="Firewall Policy & Access Control",
                title="Accumulation of Stale / Disabled Firewall Policies",
                severity=AuditSeverity.LOW,
                status=AuditStatus.PASS,
                description=f"Firewall policy base is clean ({len(disabled_policies)} disabled policies).",
                impact="Clean audit posture.",
                remediation_steps="None required."
            ))

        # -------------------------------------------------------------
        # DOMAIN 2: MANAGEMENT PLANE & INTERFACE SECURITY
        # -------------------------------------------------------------
        raw_intfs = interfaces.get("results", []) if isinstance(interfaces, dict) else []
        if isinstance(raw_intfs, dict):
            raw_intfs = list(raw_intfs.values())
        elif not isinstance(raw_intfs, list):
            raw_intfs = []

        insecure_mgmt_ports = []
        for intf in raw_intfs:
            if not isinstance(intf, dict):
                continue
            name = intf.get("name", "")
            allowaccess = str(intf.get("allowaccess", "")).lower()
            desc = str(intf.get("description", "")).lower()
            
            # Check for HTTP, Telnet, or cleartext SNMP
            if "http" in allowaccess and "https" not in allowaccess:
                insecure_mgmt_ports.append((name, "HTTP"))
            if "telnet" in allowaccess:
                insecure_mgmt_ports.append((name, "Telnet"))

        if insecure_mgmt_ports:
            cli_cmds = []
            for name, proto in insecure_mgmt_ports:
                cli_cmds.extend([
                    "config system interface",
                    f'    edit "{name}"',
                    "        set allowaccess ping https ssh",
                    "    next",
                    "end"
                ])
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-2.1",
                category="Management Plane & Interface Security",
                title="Insecure Cleartext Administrative Protocols on Network Interfaces",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.FAIL,
                description=f"Insecure cleartext management protocols ({', '.join([f'{p} on {n}' for n, p in insecure_mgmt_ports])}) detected on administrative interfaces.",
                impact="Cleartext passwords and session tokens can be intercepted via network sniffing or Man-in-the-Middle (MitM) attacks.",
                remediation_steps="Disable HTTP and Telnet administrative access; enforce TLS 1.3 HTTPS and SSH with public keys.",
                cli_commands=cli_cmds
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-2.1",
                category="Management Plane & Interface Security",
                title="Insecure Cleartext Administrative Protocols on Network Interfaces",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.PASS,
                description="No cleartext management protocols (HTTP, Telnet) exposed on network interfaces. HTTPS and SSH enforced.",
                impact="Management plane encrypted in transit.",
                remediation_steps="None required."
            ))

        # Check SEC-MGMT-02: Link state & Interface reachability
        down_wan_links = []
        for intf in raw_intfs:
            if isinstance(intf, dict):
                name = intf.get("name", "")
                status = intf.get("status", "").lower()
                desc = intf.get("description", "").lower()
                if ("wan" in name.lower() or "wan" in desc or "isp" in desc) and status == "down":
                    down_wan_links.append(name)

        if down_wan_links:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-2.2",
                category="Management Plane & Interface Security",
                title="Perimeter WAN / ISP Network Interface Down",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.WARNING,
                description=f"WAN interface(s) ({', '.join(down_wan_links)}) are in a DOWN/Disconnected state.",
                impact="Reduces WAN resilience, invalidates multi-homing failover, or cuts off secondary ISP uplinks.",
                remediation_steps="Check physical fiber/copper cabling, verify carrier upstream circuit, or enable administrative status.",
                cli_commands=[f'config system interface\n    edit "{down_wan_links[0]}"\n        set status up\n    next\nend']
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-2.2",
                category="Management Plane & Interface Security",
                title="Perimeter WAN / ISP Network Interface Down",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.PASS,
                description="All perimeter WAN uplink interfaces are online and operating normally.",
                impact="Full WAN redundancy operational.",
                remediation_steps="None required."
            ))

        # -------------------------------------------------------------
        # DOMAIN 3: FORTIGUARD SECURITY SUBSCRIPTIONS & THREAT ENGINES
        # -------------------------------------------------------------
        fg_res = fortiguard.get("results", {}) if isinstance(fortiguard, dict) else {}
        av_stat = fg_res.get("antivirus", {}).get("status", "N/A") if isinstance(fg_res.get("antivirus"), dict) else "N/A"
        ips_stat = fg_res.get("ips", {}).get("status", "N/A") if isinstance(fg_res.get("ips"), dict) else "N/A"
        wf_stat = fg_res.get("web_filter", {}).get("status", "N/A") if isinstance(fg_res.get("web_filter"), dict) else "N/A"

        expired_engines = []
        if av_stat != "valid" and av_stat != "N/A":
            expired_engines.append(f"AntiVirus ({av_stat})")
        if ips_stat != "valid" and ips_stat != "N/A":
            expired_engines.append(f"IPS ({ips_stat})")
        if wf_stat != "valid" and wf_stat != "N/A":
            expired_engines.append(f"Web Filter ({wf_stat})")

        if expired_engines:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-3.1",
                category="FortiGuard & Threat Defense",
                title="FortiGuard AI Security Engine Subscriptions Degraded or Expired",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.FAIL,
                description=f"The following FortiGuard threat protection engines are not valid: {', '.join(expired_engines)}.",
                impact="Firewall is operating with outdated threat definitions, creating vulnerability to zero-day malware and emerging CVE exploits.",
                remediation_steps="Renew FortiGuard AI-Powered Security Subscriptions and force immediate signature synchronization.",
                cli_commands=[
                    "execute update-now",
                    "diagnose autoupdate status"
                ]
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-3.1",
                category="FortiGuard & Threat Defense",
                title="FortiGuard AI Security Engine Subscriptions",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.PASS,
                description=f"FortiGuard licenses are active and current (AV: {av_stat}, IPS: {ips_stat}, Web Filter: {wf_stat}).",
                impact="Next-generation threat defense engines fully active.",
                remediation_steps="None required."
            ))

        # -------------------------------------------------------------
        # DOMAIN 4: HIGH AVAILABILITY & INFRASTRUCTURE RESILIENCY
        # -------------------------------------------------------------
        ha_res = ha_status.get("results", {}) if isinstance(ha_status, dict) else {}
        ha_sync = ha_res.get("sync_status", "in-sync")
        ha_mode = ha_res.get("mode", "standalone")

        if ha_mode != "standalone" and ha_sync != "in-sync":
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-4.1",
                category="High Availability & Resiliency",
                title="High Availability (HA) Cluster Configuration Out-of-Sync",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.FAIL,
                description=f"HA cluster checksum status is '{ha_sync}'. Secondary peer configuration has diverged from primary master node.",
                impact="Failover will result in split-brain behavior, packet drops, or mismatched firewall security policies.",
                remediation_steps="Force HA configuration resynchronization from the master node.",
                cli_commands=[
                    "diagnose sys ha checksum cluster",
                    "diagnose sys ha checksum recalculate",
                    "execute ha synchronize start"
                ]
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-4.1",
                category="High Availability & Resiliency",
                title="High Availability (HA) Cluster Health & Sync",
                severity=AuditSeverity.CRITICAL,
                status=AuditStatus.PASS,
                description=f"HA cluster mode is '{ha_mode}' and sync status is '{ha_sync}'. Checksums verified.",
                impact="High availability failover ready.",
                remediation_steps="None required."
            ))

        # Check SEC-INFRA-02: SD-WAN SLA Compliance
        sdwan_raw = sdwan_status.get("results", []) if isinstance(sdwan_status, dict) else []
        if isinstance(sdwan_raw, list):
            failing_sdwan = [m.get("interface", "member") for m in sdwan_raw if isinstance(m, dict) and m.get("sla_status") != "pass"]
            if failing_sdwan:
                findings.append(SecurityAuditFinding(
                    rule_id="CIS-FOS-4.2",
                    category="High Availability & Resiliency",
                    title="SD-WAN Member Link SLA Violation & Packet Loss",
                    severity=AuditSeverity.HIGH,
                    status=AuditStatus.WARNING,
                    description=f"SD-WAN member(s) ({', '.join(failing_sdwan)}) are failing performance SLA thresholds (high packet loss / latency).",
                    impact="Application traffic routed over degraded links experiences jitter, dropped VoIP calls, and slow SaaS performance.",
                    remediation_steps="Verify upstream ISP health, adjust SLA jitter/loss targets, or steer critical traffic to healthy WAN paths.",
                    cli_commands=[
                        "diagnose sys virtual-wan-link health-check",
                        "diagnose sys virtual-wan-link service"
                    ]
                ))
            else:
                findings.append(SecurityAuditFinding(
                    rule_id="CIS-FOS-4.2",
                    category="High Availability & Resiliency",
                    title="SD-WAN Member Link SLA Performance",
                    severity=AuditSeverity.HIGH,
                    status=AuditStatus.PASS,
                    description="All SD-WAN member links meet target latency, jitter, and packet loss SLA thresholds.",
                    impact="Optimal application delivery maintained.",
                    remediation_steps="None required."
                ))

        # -------------------------------------------------------------
        # DOMAIN 5: DYNAMIC ROUTING & NEIGHBOR ADJACENCIES
        # -------------------------------------------------------------
        bgp_res = bgp_status.get("results", []) if isinstance(bgp_status, dict) else []
        down_bgp = []
        if isinstance(bgp_res, list):
            for peer in bgp_res:
                if isinstance(peer, dict):
                    state = peer.get("state", "Established")
                    neighbor = peer.get("neighbor", "unknown")
                    if state != "Established":
                        down_bgp.append((neighbor, state))

        ospf_res = ospf_status.get("results", []) if isinstance(ospf_status, dict) else []
        down_ospf = []
        if isinstance(ospf_res, list):
            for nbr in ospf_res:
                if isinstance(nbr, dict):
                    state = nbr.get("state", "Full")
                    nbr_id = nbr.get("neighbor_id", "unknown")
                    if state not in ("Full", "2-Way"):
                        down_ospf.append((nbr_id, state))

        if down_bgp or down_ospf:
            desc_parts = []
            if down_bgp:
                desc_parts.append(f"BGP peer(s) in down state: {', '.join([f'{n} ({s})' for n, s in down_bgp])}")
            if down_ospf:
                desc_parts.append(f"OSPF neighbor(s) in down state: {', '.join([f'{n} ({s})' for n, s in down_ospf])}")
            
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-5.1",
                category="Dynamic Routing & Network Topology",
                title="Dynamic Routing Neighbor Adjacency Degradation (BGP / OSPF)",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.FAIL,
                description="; ".join(desc_parts),
                impact="Dynamic routing convergence failure prevents prefix learning, leading to blackholed traffic or split routing.",
                remediation_steps="Check if dynamic routing ports (BGP TCP 179 / OSPF Proto 89) are blocked by local-in or firewall policies, and verify dynamic routing neighbor authentication.",
                cli_commands=[
                    "get router info bgp summary",
                    "get router info ospf neighbor",
                    "diagnose ip router bgp all enable"
                ]
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-5.1",
                category="Dynamic Routing & Network Topology",
                title="Dynamic Routing Neighbor Adjacencies (BGP / OSPF)",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.PASS,
                description="All dynamic routing peers (BGP & OSPF) are fully established and adjacent.",
                impact="Dynamic routing fabric converged.",
                remediation_steps="None required."
            ))

        # -------------------------------------------------------------
        # DOMAIN 6: VPN & REMOTE ACCESS SECURITY
        # -------------------------------------------------------------
        vpn_res = vpn_status.get("results", {}) if isinstance(vpn_status, dict) else {}
        if isinstance(vpn_res, list) and vpn_res:
            vpn_res = vpn_res[0]
        elif not isinstance(vpn_res, dict):
            vpn_res = {}

        ipsec_tunnels = vpn_res.get("ipsec", [])
        if isinstance(ipsec_tunnels, dict):
            ipsec_tunnels = list(ipsec_tunnels.values())
        elif not isinstance(ipsec_tunnels, list):
            ipsec_tunnels = []

        down_tunnels = []
        for t in ipsec_tunnels:
            if isinstance(t, dict):
                name = t.get("name", "vpn")
                status = t.get("status", "").lower()
                link = t.get("link", True)
                if status == "down" or link is False:
                    down_tunnels.append(name)

        if down_tunnels:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-6.1",
                category="VPN & Remote Access Security",
                title="IPsec VPN Site-to-Site Tunnel Offline",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.WARNING,
                description=f"Configured IPsec tunnel(s) ({', '.join(down_tunnels)}) are currently DOWN (Phase 1 / Phase 2 SA disconnected).",
                impact="Cross-site secure communications and hybrid cloud connectivity are broken.",
                remediation_steps="Reset Phase 1 negotiation, verify pre-shared key (PSK) matching, and inspect IKE debug logs.",
                cli_commands=[
                    f"diagnose vpn ike gateway clear name {down_tunnels[0]}",
                    "diagnose vpn ipsec tunnel summary"
                ]
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-6.1",
                category="VPN & Remote Access Security",
                title="IPsec VPN Site-to-Site Tunnel Status",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.PASS,
                description="All configured IPsec site-to-site tunnels are active and transmitting encrypted traffic.",
                impact="Secure overlay connectivity established.",
                remediation_steps="None required."
            ))

        # Check SEC-SYS-01: System Resource Thresholds
        res_data = sys_res.get("results", {}) if isinstance(sys_res, dict) else {}
        if isinstance(res_data, list) and res_data:
            res_data = res_data[0]
        elif not isinstance(res_data, dict):
            res_data = {}

        def _val(v):
            if isinstance(v, (int, float)): return float(v)
            if isinstance(v, list) and v and isinstance(v[0], dict): return float(v[0].get("current", 0))
            if isinstance(v, dict): return float(v.get("current", 0))
            try: return float(v)
            except: return 0.0

        cpu_val = _val(res_data.get("cpu", 0))
        mem_val = _val(res_data.get("mem") or res_data.get("memory", 0))

        if cpu_val > 80.0 or mem_val > 80.0:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-7.1",
                category="System & Threat Posture",
                title="Critical System Resource Utilization (CPU/Memory)",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.FAIL,
                description=f"High resource utilization detected (CPU: {cpu_val}%, Memory: {mem_val}%).",
                impact="Risk of kernel conserve mode, session dropping, or firewall responsiveness degradation.",
                remediation_steps="Inspect top talker sessions, check for memory leaks, or optimize UTM inspection modes (proxy vs flow).",
                cli_commands=[
                    "diagnose sys top 2 20",
                    "diagnose hardware sysinfo memory",
                    "diagnose sys session stat"
                ]
            ))
        else:
            findings.append(SecurityAuditFinding(
                rule_id="CIS-FOS-7.1",
                category="System & Threat Posture",
                title="System Resource Utilization (CPU & Memory)",
                severity=AuditSeverity.HIGH,
                status=AuditStatus.PASS,
                description=f"System resource usage is within healthy parameters (CPU: {cpu_val}%, Memory: {mem_val}%).",
                impact="System stability confirmed.",
                remediation_steps="None required."
            ))

        # -------------------------------------------------------------
        # COMPUTE QUANTITATIVE SCORE & LETTER GRADE
        # -------------------------------------------------------------
        score = 100.0
        for f in findings:
            if f.status == AuditStatus.FAIL:
                if f.severity == AuditSeverity.CRITICAL:
                    score -= 15.0
                elif f.severity == AuditSeverity.HIGH:
                    score -= 8.0
                elif f.severity == AuditSeverity.MEDIUM:
                    score -= 4.0
                elif f.severity == AuditSeverity.LOW:
                    score -= 2.0
            elif f.status == AuditStatus.WARNING:
                score -= 1.5

        # Policy shadowing penalties
        score -= (len(shadowing_issues) * 5.0)

        # Clamp between 0.0 and 100.0
        score = max(0.0, min(100.0, score))

        if score >= 95.0:
            grade = "A+"
        elif score >= 90.0:
            grade = "A"
        elif score >= 80.0:
            grade = "B"
        elif score >= 70.0:
            grade = "C"
        elif score >= 60.0:
            grade = "D"
        else:
            grade = "F"

        return SecurityAuditReport(
            hostname=hostname,
            firmware=firmware_str,
            overall_score=score,
            letter_grade=grade,
            findings=findings,
            shadowing_issues=shadowing_issues,
            execution_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    def print_terminal_report(self, report: SecurityAuditReport, console: Optional[Console] = None):
        """Renders an executive visual scorecard in the Rich console."""
        if console is None:
            console = Console()

        # Header Scorecard
        score_color = "green" if report.overall_score >= 90 else ("yellow" if report.overall_score >= 75 else "red")
        
        score_banner = (
            f"[bold {score_color}]🛡️  FORTIOS SECURITY POSTURE & CIS HARDENING SCORECARD[/bold {score_color}]\n\n"
            f"Overall Security Health Score: [bold {score_color}]{report.overall_score} / 100[/bold {score_color}]  "
            f"|  Letter Grade: [bold {score_color}][{report.letter_grade}][/bold {score_color}]\n"
            f"Target Appliance: [bold cyan]{report.hostname}[/bold cyan] ({report.firmware})  |  Date: [white]{report.execution_time}[/white]"
        )
        console.print(Panel(Align.center(score_banner), border_style=score_color, expand=False))

        # Metrics Breakdown Table
        summary_table = Table(title="Benchmark Evaluation Summary", show_header=True, header_style="bold magenta")
        summary_table.add_column("Audit Metric", style="cyan")
        summary_table.add_column("Count", style="white", justify="right")
        summary_table.add_column("Assessment", style="white")

        summary_table.add_row("Total Benchmark Checks", str(len(report.findings)), "Evaluated")
        summary_table.add_row("Compliant (Passed)", f"[green]{report.passed_count}[/green]", "[green]Meets Best Practices[/green]")
        summary_table.add_row("Warnings", f"[yellow]{report.warning_count}[/yellow]", "[yellow]Non-Blocking Gaps[/yellow]")
        summary_table.add_row("Failed Checks", f"[red]{report.failed_count}[/red]", f"[red]Critical: {report.critical_count}, High: {report.high_count}[/red]")
        summary_table.add_row("Policy Shadowing Conflicts", f"[bold red]{len(report.shadowing_issues)}[/bold red]", "[red]Rule Reordering Required[/red]" if report.shadowing_issues else "[green]Optimal Sequence[/green]")
        console.print(summary_table)

        # Policy Shadowing Deep-Dive Table
        if report.shadowing_issues:
            console.print("\n[bold red]⚠️  Firewall Policy Precedence & Shadowing Conflicts Detected:[/bold red]")
            sh_table = Table(show_header=True, header_style="bold red")
            sh_table.add_column("Shadowed Policy", style="yellow")
            sh_table.add_column("Shadowed By", style="red")
            sh_table.add_column("Root Cause & Impact", style="white")
            sh_table.add_column("Recommended CLI Fix", style="cyan")

            for sh in report.shadowing_issues:
                sh_table.add_row(
                    f"ID {sh.shadowed_policy_id} ({sh.shadowed_policy_name})",
                    f"ID {sh.shadowing_policy_id} ({sh.shadowing_policy_name})",
                    sh.reason,
                    sh.cli_reorder_command
                )
            console.print(sh_table)

        # Findings Detail Table
        console.print("\n[bold purple]Detailed Security Benchmark Findings:[/bold purple]")
        findings_table = Table(show_header=True, header_style="bold purple")
        findings_table.add_column("Rule ID", style="cyan", width=12)
        findings_table.add_column("Category", style="magenta", width=24)
        findings_table.add_column("Status", width=10)
        findings_table.add_column("Severity", width=10)
        findings_table.add_column("Finding Summary & Action", style="white")

        for f in report.findings:
            if f.status == AuditStatus.PASS:
                status_str = "[green]PASS[/green]"
            elif f.status == AuditStatus.WARNING:
                status_str = "[yellow]WARN[/yellow]"
            else:
                status_str = "[red]FAIL[/red]"

            sev_color = "red" if f.severity == AuditSeverity.CRITICAL else ("yellow" if f.severity == AuditSeverity.HIGH else "cyan")
            sev_str = f"[{sev_color}]{f.severity}[/{sev_color}]"

            finding_desc = f"[bold]{f.title}[/bold]\n{f.description}"
            if f.status != AuditStatus.PASS and f.remediation_steps:
                finding_desc += f"\n[bold green]→ Fix:[/bold green] {f.remediation_steps}"

            findings_table.add_row(
                f.rule_id,
                f.category,
                status_str,
                sev_str,
                finding_desc
            )
        console.print(findings_table)
