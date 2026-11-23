import os
import sys
import html
import json
import logging
import argparse
from datetime import datetime
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm


# Configure Logging
def setup_logging():
    """Sets up file logging for diagnostic trace and sets root logging levels."""
    file_handler = logging.FileHandler("fortigate_agent.log", mode="a", encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    )
    file_handler.setFormatter(file_formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    if root_logger.hasHandlers():
        root_logger.handlers.clear()
        
    root_logger.addHandler(file_handler)

setup_logging()
logger = logging.getLogger("FortiGateMain")

from config import Config
from fortigate_client import FortiGateClient
from agent import FortiGateAgent
from security_audit import FortiGateSecurityAuditor, SecurityAuditReport

console = Console()

from rich.align import Align
from rich.text import Text

def export_report_to_html(markdown_content: str, output_path: str, title: str = "FortiGate AI Operations & Health Report"):
    """Exports diagnostic report to a standalone, responsive, XSS-hardened HTML document."""
    safe_title = html.escape(title, quote=True)
    safe_pre_content = html.escape(markdown_content, quote=False)
    safe_json_content = (
        json.dumps(markdown_content)
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )
    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{safe_title}</title>
    <style>
        :root {{
            --bg-color: #0f172a;
            --card-bg: #1e293b;
            --text-main: #f8fafc;
            --text-muted: #94a3b8;
            --border: #334155;
            --code-bg: #0b0f19;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
            background-color: var(--bg-color);
            color: var(--text-main);
            line-height: 1.6;
            padding: 2rem 1rem;
        }}
        .container {{ max-width: 960px; margin: 0 auto; }}
        .header {{
            background: linear-gradient(135deg, #1e1b4b 0%, #312e81 100%);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.5);
        }}
        .header h1 {{ color: #c084fc; font-size: 1.8rem; margin-bottom: 0.5rem; }}
        .header p {{ color: var(--text-muted); font-size: 0.95rem; }}
        .card {{
            background-color: var(--card-bg);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.3);
        }}
        h2, h3, h4 {{ color: #e2e8f0; margin-top: 1.5rem; margin-bottom: 0.75rem; border-bottom: 1px solid var(--border); padding-bottom: 0.3rem; }}
        p, ul, ol {{ margin-bottom: 1rem; }}
        ul, ol {{ padding-left: 1.5rem; }}
        li {{ margin-bottom: 0.4rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1.5rem 0; font-size: 0.95rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
        th {{ background-color: #0f172a; color: #a855f7; font-weight: 600; }}
        tr:hover {{ background-color: rgba(255, 255, 255, 0.02); }}
        code {{
            background-color: var(--code-bg);
            color: #38bdf8;
            padding: 0.2rem 0.4rem;
            border-radius: 4px;
            font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
            font-size: 0.875em;
        }}
        pre {{
            background-color: var(--code-bg);
            border: 1px solid var(--border);
            padding: 1rem;
            border-radius: 8px;
            overflow-x: auto;
            margin: 1rem 0;
        }}
        pre code {{ padding: 0; background: none; color: #f1f5f9; }}
        .footer {{ text-align: center; color: var(--text-muted); font-size: 0.85rem; margin-top: 3rem; }}
    </style>
    <script src="https://cdn.jsdelivr.net/npm/marked@12.0.2/marked.min.js" integrity="sha384-/TQbtLCAerC3jgaim+N78RZSDYV7ryeoBCVqTuzRrFec2akfBkHS7ACQ3PQhvMVi" crossorigin="anonymous"></script>
    <script src="https://cdn.jsdelivr.net/npm/dompurify@3.0.9/dist/purify.min.js" integrity="sha384-3HPB1XT51W3gGRxAmZ+qbZwRpRlFQL632y8x+adAqCr4Wp3TaWwCLSTAJJKbyWEK" crossorigin="anonymous"></script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ FortiGate AI Health & Diagnostics Report</h1>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} | Powered by Gemini AI Agent</p>
        </div>
        <div class="card" id="report-content">
            <pre style="white-space: pre-wrap;">{safe_pre_content}</pre>
        </div>
        <div class="footer">
            <p>FortiGate AI Operations & Diagnostics Agent | Executive Operational Report</p>
        </div>
    </div>
    <script>
        if (typeof marked !== 'undefined' && typeof DOMPurify !== 'undefined') {{
            const rawContent = {safe_json_content};
            const parsedHTML = marked.parse(rawContent);
            document.getElementById('report-content').innerHTML = DOMPurify.sanitize(parsedHTML);
        }}
    </script>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_template)

def export_report(content: str, output_path: str, is_json: bool = False):
    """Saves report output to the specified target path in HTML, Markdown, or JSON format."""
    try:
        if output_path.lower().endswith(".html") and not is_json:
            export_report_to_html(content, output_path)
        else:
            with open(output_path, "w", encoding="utf-8") as f:
                f.write(content)
        console.print(f"[green]✓ Diagnostic report successfully exported to:[/green] [bold cyan]{output_path}[/bold cyan]")
    except Exception as e:
        console.print(f"[red]Failed to export report to '{output_path}': {e}[/red]")

def display_welcome_banner():
    """Displays a premium ASCII and text welcome banner."""
    ascii_art = (
        "███████╗ ██████╗ ██████╗ ████████╗██╗██████╗  █████╗ ████████╗███████╗\n"
        "██╔════╝██╔═══██╗██╔══██╗╚══██╔══╝██║██╔════╝ ██╔══██╗╚══██╔══╝██╔════╝\n"
        "█████╗  ██║   ██║██████╔╝   ██║   ██║██║  ███╗███████║   ██║   █████╗  \n"
        "██╔══╝  ██║   ██║██╔══██╗   ██║   ██║██║   ██║██╔══██║   ██║   ██╔══╝  \n"
        "██║     ╚██████╔╝██║  ██║   ██║   ██║╚██████╔╝██║  ██║   ██║   ███████╗\n"
        "╚═╝      ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝"
    )
    banner_content = Align.center(
        Text(ascii_art, style="bold cyan") + "\n\n" + Text("FortiGate AI Operations & Diagnostics Agent", style="bold purple")
    )
    console.print(Panel(banner_content, border_style="purple", expand=False))

def ensure_api_key():
    """Checks for the Gemini API Key. If missing, prompts the user to enter it."""
    if not Config.GEMINI_API_KEY:
        console.print(Panel(
            "[yellow]Gemini API Key is not set![/yellow]\n"
            "An API key is required to power the AI Agent's reasoning.\n"
            "You can get one for free/developer tier from: [cyan]https://aistudio.google.com/[/cyan]",
            title="API Key Configuration Required",
            border_style="yellow"
        ))
        api_key = Prompt.ask("Please enter your Gemini API Key", password=True)
        if not api_key.strip():
            console.print("[red]Error: API Key is required. Exiting...[/red]")
            sys.exit(1)
        
        # Save key in memory and offer to write to .env
        Config.GEMINI_API_KEY = api_key.strip()
        if Confirm.ask("Would you like to save this key to your .env file?"):
            try:
                env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
                content = ""
                if os.path.exists(env_path):
                    with open(env_path, "r") as f:
                        content = f.read()
                
                if "GEMINI_API_KEY=" in content:
                    # Replace existing
                    lines = []
                    for line in content.splitlines():
                        if line.startswith("GEMINI_API_KEY="):
                            lines.append(f"GEMINI_API_KEY={api_key.strip()}")
                        elif line.startswith("# GEMINI_API_KEY="):
                            lines.append(f"GEMINI_API_KEY={api_key.strip()}")
                        else:
                            lines.append(line)
                    content = "\n".join(lines)
                else:
                    content += f"\nGEMINI_API_KEY={api_key.strip()}\n"
                
                with open(env_path, "w") as f:
                    f.write(content)
                import stat
                try:
                    os.chmod(env_path, stat.S_IRUSR | stat.S_IWUSR)
                except Exception:
                    pass
                console.print("[green]API Key saved to .env successfully (permissions restricted to 0600).[/green]")
            except Exception as e:
                console.print(f"[red]Failed to save API key to .env: {e}[/red]")

def run_diagnostics(agent: FortiGateAgent, output_json: bool = False):
    """Gathers all information from the FortiGate client and queries Gemini for a complete report."""
    prompt = (
        "Please run a full diagnostics review of the FortiGate. Check the system status, resource usage, "
        "network interfaces, VPN configurations, and routing table. Analyze the logs and outputs to compile "
        "a comprehensive health and security report. Explicitly list any warnings, issues, or down tunnels, "
        "and suggest immediate troubleshooting steps for any anomalies."
    )

    if output_json:
        try:
            # Direct structured agent call
            report = agent.run_structured_query(prompt)
            json_output = report.model_dump_json(indent=2)
            print(json_output)
            if Config.OUTPUT_FILE:
                export_report(json_output, Config.OUTPUT_FILE, is_json=True)
        except Exception as e:
            import json
            print(json.dumps({"error": f"AI Agent Diagnostics Error: {e}"}))
        return

    console.print("\n[bold blue]Starting Full FortiGate Security & Health Diagnostics...[/bold blue]")
    
    # 1. Show local raw metrics summary before LLM report
    with console.status("[bold green]Querying FortiGate details (Status, Resources, Interfaces, VPN, Routing, FortiGuard, Quarantined IPs, Sessions, Logs, ARP, DHCP)...") as status:
        try:
            sys_status = agent.fg_client.get_system_status()
            sys_res = agent.fg_client.get_system_resources()
            interfaces = agent.fg_client.get_interfaces()
            vpn = agent.fg_client.get_vpn_status()
            routes = agent.fg_client.get_routing_table()
            logs = agent.fg_client.get_system_logs()
            sdwan = agent.fg_client.get_sdwan_status()
            ha = agent.fg_client.get_ha_status()
            arp = agent.fg_client.get_arp_table()
            dhcp = agent.fg_client.get_dhcp_leases()
            fortiguard = agent.fg_client.get_fortiguard_status()
            quarantined = agent.fg_client.get_quarantined_ips()
            top_sessions = agent.fg_client.get_top_sessions(limit=5)
        except Exception as e:
            console.print(f"[red]Failed to fetch data from FortiGate: {e}[/red]")
            return
            
    # Present Raw Summary Table
    table = Table(title="Retrieved FortiGate Raw Operational Data Summary", show_header=True, header_style="bold magenta")
    table.add_column("Component", style="cyan")
    table.add_column("Status / Key Metrics", style="white")
    
    # Status results parsing
    status_res = sys_status.get("results", {}) if isinstance(sys_status, dict) else {}
    if isinstance(status_res, list) and status_res:
        status_res = status_res[0]
    elif not isinstance(status_res, dict):
        status_res = {}
        
    hostname = status_res.get("hostname") or sys_status.get("hostname", "Unknown")
    version = sys_status.get("version") or status_res.get("version", "Unknown")
    build = sys_status.get("build") or status_res.get("build", "")
    build_str = f" (build {build})" if build else ""
    model = status_res.get("model_number") or status_res.get("model_name") or status_res.get("model", "")
    model_str = f" [{model}]" if model else ""
    
    uptime_sec = status_res.get("uptime") or sys_status.get("uptime") or 0
    if isinstance(uptime_sec, (int, float)) and uptime_sec > 0:
        uptime_str = f"{uptime_sec // 86400}d {(uptime_sec % 86400) // 3600}h {(uptime_sec % 3600) // 60}m"
    else:
        uptime_str = "N/A"
    
    table.add_row("System Status", f"Hostname: [bold]{hostname}[/bold]{model_str}, OS: [green]FortiOS {version}{build_str}[/green], Uptime: {uptime_str}")
    
    # HA Cluster
    ha_res = ha.get("results", {}) if isinstance(ha, dict) else {}
    ha_sync = ha_res.get("sync_status", "N/A")
    ha_mode = ha_res.get("mode", "N/A")
    sync_style = "green" if ha_sync == "in-sync" else "red"
    table.add_row("HA Cluster", f"Mode: [bold]{ha_mode}[/bold], Sync Status: [{sync_style}]{ha_sync}[/{sync_style}]")

    # FortiGuard & Subscriptions
    fg_res = fortiguard.get("results", {}) if isinstance(fortiguard, dict) else {}
    av_stat = fg_res.get("antivirus", {}).get("status", "N/A") if isinstance(fg_res.get("antivirus"), dict) else "N/A"
    ips_stat = fg_res.get("ips", {}).get("status", "N/A") if isinstance(fg_res.get("ips"), dict) else "N/A"
    wf_stat = fg_res.get("web_filter", {}).get("status", "N/A") if isinstance(fg_res.get("web_filter"), dict) else "N/A"
    fg_style = "green" if av_stat == "valid" and ips_stat == "valid" else "yellow"
    table.add_row("FortiGuard Subscriptions", f"[{fg_style}]AV: {av_stat}, IPS: {ips_stat}, Web Filter: {wf_stat}[/{fg_style}]")

    # Resources
    res_data = sys_res.get("results", {}) if isinstance(sys_res, dict) else {}
    if isinstance(res_data, list) and res_data:
        res_data = res_data[0]
    elif not isinstance(res_data, dict):
        res_data = {}
        
    def _parse_metric(v):
        if isinstance(v, (int, float)):
            return str(v)
        if isinstance(v, list) and v and isinstance(v[0], dict):
            return str(v[0].get("current", "N/A"))
        if isinstance(v, dict):
            return str(v.get("current", "N/A"))
        return str(v)

    cpu = _parse_metric(res_data.get("cpu", "N/A"))
    mem = _parse_metric(res_data.get("mem") or res_data.get("memory", "N/A"))
    sessions = _parse_metric(res_data.get("session", "N/A"))
    table.add_row("Resources Usage", f"CPU: [bold]{cpu}%[/bold], Memory: [bold]{mem}%[/bold], Sessions: [bold]{sessions}[/bold]")

    # Top Talkers & Sessions
    top_src = top_sessions.get("top_source_ips", []) if isinstance(top_sessions, dict) else []
    if top_src and isinstance(top_src, list):
        top_src_ip = top_src[0].get("ip", "N/A")
        top_src_mb = round(top_src[0].get("total_bytes", 0) / (1024 * 1024), 1)
        table.add_row("Top Talkers (Bandwidth)", f"Top Source: [bold cyan]{top_src_ip}[/bold cyan] ({top_src_mb} MB in active flows)")
    
    # Interfaces
    raw_intf = interfaces.get("results", []) if isinstance(interfaces, dict) else []
    if isinstance(raw_intf, dict):
        intf_list = list(raw_intf.values())
    elif isinstance(raw_intf, list):
        intf_list = raw_intf
    else:
        intf_list = []
    
    intf_up = sum(1 for i in intf_list if isinstance(i, dict) and (i.get("status") == "up" or i.get("link") is True or i.get("link_status") == 1))
    intf_down = sum(1 for i in intf_list if isinstance(i, dict) and (i.get("status") == "down" or i.get("link") is False or i.get("link_status") == 0))
    table.add_row("Interfaces", f"Total: {len(intf_list)} (Active: [green]{intf_up}[/green], Inactive: [red]{intf_down}[/red])")
    
    # SD-WAN
    sdwan_raw = sdwan.get("results", []) if isinstance(sdwan, dict) else []
    if isinstance(sdwan_raw, list):
        sdwan_pass = sum(1 for m in sdwan_raw if isinstance(m, dict) and m.get("sla_status") == "pass")
        sdwan_fail = sum(1 for m in sdwan_raw if isinstance(m, dict) and m.get("sla_status") != "pass")
        table.add_row("SD-WAN Link Health", f"Members SLA Pass: [green]{sdwan_pass}[/green], Fail: [red]{sdwan_fail}[/red]")

    # VPN
    vpn_results = vpn.get("results", {}) if isinstance(vpn, dict) else {}
    if isinstance(vpn_results, list) and vpn_results:
        vpn_results = vpn_results[0]
    elif not isinstance(vpn_results, dict):
        vpn_results = {}
    ipsec_tunnels = vpn_results.get("ipsec", [])
    if isinstance(ipsec_tunnels, dict):
        ipsec_tunnels = list(ipsec_tunnels.values())
    elif not isinstance(ipsec_tunnels, list):
        ipsec_tunnels = []
        
    def _is_ipsec_up(t: dict) -> bool:
        if not isinstance(t, dict):
            return False
        if t.get("status") == "up" or t.get("link") is True or t.get("connection_count", 0) > 0:
            return True
        proxyid = t.get("proxyid", [])
        if isinstance(proxyid, list) and any(isinstance(p, dict) and p.get("status") == "up" for p in proxyid):
            return True
        return False

    ipsec_total = len(ipsec_tunnels)
    ipsec_up = sum(1 for t in ipsec_tunnels if _is_ipsec_up(t))
    ipsec_down = ipsec_total - ipsec_up
    ssl_sessions = vpn_results.get("ssl_vpn", {}).get("active_sessions_count", 0) if isinstance(vpn_results.get("ssl_vpn"), dict) else 0
    table.add_row("VPN Tunnels & Sessions", f"IPsec Active: [green]{ipsec_up}/{ipsec_total} Up[/green] (Down: [red]{ipsec_down}[/red]), Active SSL Users: [bold]{ssl_sessions}[/bold]")
    
    # Routing
    route_raw = routes.get("results", []) if isinstance(routes, dict) else []
    if isinstance(route_raw, dict):
        route_list = list(route_raw.values())
    elif isinstance(route_raw, list):
        route_list = route_raw
    else:
        route_list = []
    table.add_row("Routing Table", f"Total routes active: [bold]{len(route_list)}[/bold]")

    # ARP & DHCP
    arp_res = arp.get("results", []) if isinstance(arp, dict) else []
    arp_count = len(arp_res) if isinstance(arp_res, list) else 0
    dhcp_res = dhcp.get("results", []) if isinstance(dhcp, dict) else []
    dhcp_count = len(dhcp_res) if isinstance(dhcp_res, list) else 0
    table.add_row("Network Neighbors & DHCP", f"ARP Entries: [bold]{arp_count}[/bold], Active DHCP Leases: [bold]{dhcp_count}[/bold]")

    # Quarantined & Banned IPs
    q_res = quarantined.get("results", []) if isinstance(quarantined, dict) else []
    q_count = len(q_res) if isinstance(q_res, list) else 0
    q_style = "yellow" if q_count > 0 else "green"
    table.add_row("Quarantined Threat Hosts", f"[{q_style}]Active IP Bans: {q_count}[/{q_style}]")

    # Logs
    log_raw = logs.get("results", []) if isinstance(logs, dict) else []
    if isinstance(log_raw, dict):
        log_list = list(log_raw.values())
    elif isinstance(log_raw, list):
        log_list = log_raw
    else:
        log_list = []
    table.add_row("Recent Event Logs", f"Retrieved [bold]{len(log_list)}[/bold] recent event log entries")
    
    console.print(table)
    
    # 2. Query Agent for AI Report
    console.print("\n[bold purple]Generating AI Diagnostic Report and Health Assessment...[/bold purple]")
    
    with console.status("[bold purple]Gemini AI Agent is analyzing operational metrics...") as status:
        try:
            ai_report = agent.run_query(prompt)
        except Exception as e:
            console.print(f"[red]AI Agent Analysis Error: {e}[/red]")
            return
            
    console.print(Panel(Markdown(ai_report), title="FortiGate Health & Diagnostics Report", border_style="purple"))

    if Config.OUTPUT_FILE:
        export_report(ai_report, Config.OUTPUT_FILE)

def run_interactive_mode(agent: FortiGateAgent):
    """Launches an interactive chat loop with the FortiGate agent."""
    console.print("\n[bold purple]Entering Interactive Agent Console...[/bold purple]")
    console.print("You are now speaking with the FortiGate AI Agent. It has access to live API tools.")
    console.print("Ask questions like:")
    console.print(" - '[cyan]Are there any interfaces down?[/cyan]'")
    console.print(" - '[cyan]Explain the routing table and find the default gateway.[/cyan]'")
    console.print(" - '[cyan]Is my AWS VPN tunnel up? What is the traffic on it?[/cyan]'")
    console.print(" - '[cyan]Check CPU and memory usage and summarize the status.[/cyan]'")
    console.print("Type '[bold red]exit[/bold red]' or '[bold red]quit[/bold red]' to return to menu.\n")
    
    try:
        chat = agent.create_chat_session()
    except Exception as e:
        console.print(f"[red]Failed to start chat session: {e}[/red]")
        return
        
    while True:
        try:
            user_input = Prompt.ask("\n[bold purple]Agent[/bold purple] >")
            if user_input.strip().lower() in ("exit", "quit"):
                console.print("[yellow]Exiting interactive console...[/yellow]")
                break
                
            if not user_input.strip():
                continue
                
            with console.status("[bold purple]Agent is working...") as status:
                response = chat.send_message(user_input)
                
            console.print(Panel(Markdown(response.text), title="Agent Response", border_style="purple"))
        except KeyboardInterrupt:
            console.print("\n[yellow]Exiting interactive console...[/yellow]")
            break
        except Exception as e:
            console.print(f"[red]Error during agent processing: {e}[/red]")

DEFAULT_AGENTIC_PROMPT = (
    "Perform a comprehensive, multi-step autonomous investigation of the FortiGate firewall across all operational subsystems: "
    "1. System health, CPU/memory utilization, and HA cluster sync. "
    "2. Network interfaces, SD-WAN member link SLAs (packet loss, latency, jitter), and ARP/DHCP reachability. "
    "3. Dynamic routing state (BGP peerings and OSPF neighbor adjacencies) and IPv4 routing table. "
    "4. VPN tunnel connectivity (IPsec Phase 1/2 and active SSL-VPN sessions). "
    "5. FortiGuard security engine subscriptions (AV, IPS, Web Filter database updates and license expiry). "
    "6. Active firewall session table, identifying top talkers and high-bandwidth or anomalous flows. "
    "If any degraded state, link failure, dropped tunnel, routing issue, or security anomaly is detected, "
    "autonomously pivot to inspect system event logs and firewall security policies to identify the exact root cause, "
    "and synthesize a prioritized, actionable remediation plan."
)

def run_agentic_mode(agent: FortiGateAgent, prompt: Optional[str] = None):
    """Runs a multi-step agentic call with chain-of-thought tool execution tracing."""
    if not prompt:
        if sys.stdin.isatty():
            console.print("\n[bold purple]Autonomous Multi-Step Agentic Reasoning[/bold purple]")
            console.print("Enter your investigative objective, or press [bold cyan]Enter[/bold cyan] for full autonomous health & root-cause sweep:")
            user_input = Prompt.ask("[cyan]Objective[/cyan]", default="")
            prompt = user_input.strip() if user_input.strip() else DEFAULT_AGENTIC_PROMPT
        else:
            prompt = DEFAULT_AGENTIC_PROMPT
        
    console.print("\n[bold purple]Starting Autonomous Multi-Step Agentic Call...[/bold purple]")
    console.print(f"[cyan]Prompt:[/cyan] {prompt}\n")
    
    with console.status("[bold purple]Agentic loop executing tool calls and reasoning steps...") as status:
        try:
            result = agent.run_agentic_loop(prompt)
        except Exception as e:
            console.print(f"[red]Agentic Loop Execution Error: {e}[/red]")
            return

    # Display Chain-of-Thought / Executed Tools
    tools_called = result.get("tools_executed", [])
    if tools_called:
        console.print(Panel(
            "\n".join(f" [green]✓[/green] Tool Executed: [bold]{t}[/bold]" for t in tools_called),
            title="Agentic Reasoning Trace (Executed Tools)",
            border_style="green"
        ))
    else:
        console.print("[yellow]No external tools required for this query.[/yellow]")
        
    # Display Final Assessment
    console.print(Panel(Markdown(result["final_response"]), title="Final Agentic Assessment", border_style="purple"))


def run_multi_agent_mode(client: FortiGateClient, prompt: Optional[str] = None, output_json: bool = False):
    """Runs the coordinated Multi-Agent Orchestrator + Domain Specialists workflow (Issue #16)."""
    from core.context import InvestigationContext
    from core.llm_provider import GeminiLLMProvider
    from core.orchestrator import OrchestratorAgent

    objective = prompt.strip() if prompt and prompt.strip() else DEFAULT_AGENTIC_PROMPT
    context = InvestigationContext(fg_client=client)
    provider = GeminiLLMProvider(api_key=Config.GEMINI_API_KEY)
    orchestrator = OrchestratorAgent(provider=provider)

    if output_json:
        report = orchestrator.investigate(objective, context)
        json_out = report.model_dump_json(indent=2)
        print(json_out)
        if Config.OUTPUT_FILE:
            export_report(json_out, Config.OUTPUT_FILE, is_json=True)
        return

    console.print("\n[bold purple]Starting Coordinated Multi-Agent Investigation...[/bold purple]")
    console.print(f"[cyan]Correlation ID:[/cyan] {context.correlation_id} | [cyan]Objective:[/cyan] {objective}\n")

    with console.status("[bold purple]Orchestrator planning & dispatching read-only specialist agents in parallel..."):
        report = orchestrator.investigate(objective, context)

    roles_str = ", ".join(r.value for r in report.plan.selected_roles)
    console.print(Panel(
        f"[bold]Overall Status:[/bold] {report.overall_status.upper()} | [bold]Confidence:[/bold] {report.confidence.value.upper()}\n"
        f"[bold]Specialists Dispatched:[/bold] {roles_str}\n"
        f"[bold]Findings:[/bold] {len(report.correlated_findings)} | [bold]Contradictions:[/bold] {len(report.contradictions)} | [bold]Unknowns:[/bold] {len(report.unknowns)}",
        title="Multi-Agent Investigation Summary",
        border_style="cyan"
    ))
    console.print(Panel(Markdown(report.executive_summary), title="Orchestrator Executive Synthesis", border_style="purple"))

    if report.recommended_actions:
        actions_md = "\n".join(f"- {a}" for a in report.recommended_actions)
        console.print(Panel(Markdown(actions_md), title="Prioritized Next Actions", border_style="green"))

def run_security_audit_mode(client: FortiGateClient, playbook_path: Optional[str] = None, output_json: bool = False):
    """Executes the full FortiOS Security Posture & CIS Hardening Benchmark Audit."""
    auditor = FortiGateSecurityAuditor(client)

    if output_json:
        try:
            report = auditor.run_audit()
            json_output = json.dumps(report.to_dict(), indent=2)
            print(json_output)
            if Config.OUTPUT_FILE:
                export_report(json_output, Config.OUTPUT_FILE, is_json=True)
            if playbook_path:
                with open(playbook_path, "w", encoding="utf-8") as f:
                    f.write(report.generate_hardening_playbook())
        except Exception as e:
            print(json.dumps({"error": f"Security Audit Error: {e}"}))
        return

    console.print("\n[bold purple]Running FortiOS Security Posture & CIS Hardening Benchmark Audit...[/bold purple]")
    with console.status("[bold purple]Auditing firewall policies, shadow rules, management access, FortiGuard subscriptions, HA sync, and VPN crypto...") as status:
        try:
            report = auditor.run_audit()
        except Exception as e:
            console.print(f"[red]Failed to execute security audit: {e}[/red]")
            return

    # Render Visual Scorecard & Finding Tables
    auditor.print_terminal_report(report, console=console)

    # Export hardening playbook if requested
    if playbook_path:
        playbook_content = report.generate_hardening_playbook()
        try:
            with open(playbook_path, "w", encoding="utf-8") as f:
                f.write(playbook_content)
            console.print(Panel(
                f"[green]✓ Hardening Playbook successfully exported to:[/green] [bold cyan]{playbook_path}[/bold cyan]\n"
                f"Contains [bold]{report.failed_count + len(report.shadowing_issues)}[/bold] validated FortiOS CLI remediation commands.",
                title="FortiOS Hardening Playbook Export",
                border_style="green"
            ))
        except Exception as e:
            console.print(f"[red]Failed to export hardening playbook to '{playbook_path}': {e}[/red]")

    # Export report if configured
    if Config.OUTPUT_FILE:
        if Config.OUTPUT_FILE.lower().endswith(".json"):
            export_report(json.dumps(report.to_dict(), indent=2), Config.OUTPUT_FILE, is_json=True)
        elif Config.OUTPUT_FILE.lower().endswith(".html"):
            export_report_to_html(report.to_markdown(), Config.OUTPUT_FILE, title=f"FortiOS Security Posture Audit - {report.hostname}")
            console.print(f"[green]✓ Security audit HTML report exported to:[/green] [bold cyan]{Config.OUTPUT_FILE}[/bold cyan]")
        else:
            export_report(report.to_markdown(), Config.OUTPUT_FILE, is_json=False)

def parse_args():
    """Parses command-line arguments for CLI overrides."""
    parser = argparse.ArgumentParser(
        description="FortiGate AI Operations & Diagnostics Agent"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["diagnose", "interactive", "agentic", "multi-agent", "config", "backup", "audit"],
        help="Command to run directly. If omitted, displays the interactive selection menu."
    )
    parser.add_argument(
        "--json", "-j",
        action="store_true",
        help="Output parsed diagnostics result in raw JSON format (suppresses standard output)."
    )
    parser.add_argument(
        "--mock", "-m",
        action="store_true",
        help="Force Mock Mode (simulated offline responses)."
    )
    parser.add_argument(
        "--enable-write", "-w",
        action="store_true",
        help="Enable active write/mitigation actions (default: False for security)."
    )
    parser.add_argument(
        "--dry-run", "-d",
        action="store_true",
        help="Simulate write actions without modifying firewall (safety dry run)."
    )
    parser.add_argument(
        "--output", "-o",
        help="Export diagnostic or audit report to a file (.md, .html, or .json)."
    )
    parser.add_argument(
        "--playbook",
        help="Export automated FortiOS CLI hardening playbook to a file (.conf)."
    )
    parser.add_argument(
        "--ip", "-i",
        help="Override FortiGate IP address."
    )
    parser.add_argument(
        "--token", "-t",
        help="Override FortiGate API access token."
    )
    parser.add_argument(
        "--port", "-p",
        type=int,
        help="Override FortiGate API port."
    )
    parser.add_argument(
        "--vdom", "-v",
        help="Override target VDOM."
    )
    parser.add_argument(
        "--verify-ssl", "-k",
        action="store_true",
        help="Enable HTTPS certificate verification (enabled by default)."
    )
    parser.add_argument(
        "--insecure", "--no-verify-ssl",
        dest="insecure",
        action="store_true",
        help="Explicitly disable HTTPS TLS certificate verification (lab troubleshooting only; emits a security warning)."
    )
    parser.add_argument(
        "--ca-bundle", "-c",
        help="Path to custom CA certificate bundle (enables verification)."
    )
    parser.add_argument(
        "--model",
        help="Override Gemini model name (e.g. gemini-4-carbon, gemini-4-neon, gemini-4-argon, gemini-3.1-pro-preview)."
    )
    parser.add_argument(
        "--thinking-level",
        choices=["minimal", "low", "medium", "high", "xhigh"],
        help="Override Gemini 4 reasoning thinking level (default: medium for specialists, high for orchestrator)."
    )
    parser.add_argument(
        "--prompt",
        help="Custom objective or investigative prompt for autonomous agentic reasoning mode."
    )
    return parser.parse_args()

def main():
    args = parse_args()

    # Apply CLI overrides to Config
    if args.model:
        Config.GEMINI_MODEL = args.model
    if getattr(args, "thinking_level", None):
        lvl = args.thinking_level.upper()
        Config.GEMINI_THINKING_LEVEL = lvl
        Config.ORCHESTRATOR_THINKING_LEVEL = lvl
        Config.SPECIALIST_THINKING_LEVEL = lvl
        os.environ["GEMINI_THINKING_LEVEL"] = lvl
        os.environ["ORCHESTRATOR_THINKING_LEVEL"] = lvl
        os.environ["SPECIALIST_THINKING_LEVEL"] = lvl
    if args.mock:
        Config.MOCK_MODE = True
    if args.ip:
        Config.FORTIGATE_IP = args.ip
    if args.token:
        Config.FORTIGATE_TOKEN = args.token
    if args.port:
        Config.FORTIGATE_PORT = args.port
    if args.vdom:
        Config.FORTIGATE_VDOM = args.vdom
    if args.verify_ssl:
        Config.VERIFY_SSL = True
    if getattr(args, "insecure", False):
        Config.VERIFY_SSL = False
    if args.ca_bundle:
        Config.CA_BUNDLE = args.ca_bundle
        Config.VERIFY_SSL = True
    if args.enable_write:
        Config.ENABLE_WRITE_ACTIONS = True
    if args.dry_run:
        Config.DRY_RUN = True
    if args.output:
        Config.OUTPUT_FILE = args.output

    # Re-evaluate mock mode if settings changed
    if not Config.MOCK_MODE and not (Config.FORTIGATE_IP and Config.FORTIGATE_TOKEN):
        Config.MOCK_MODE = True

    if args.json:
        # Check API key without interactive prompt if not audit
        if args.command != "audit" and not Config.GEMINI_API_KEY:
            import json
            print(json.dumps({"error": "Gemini API key is not configured. Specify GEMINI_API_KEY in environment or .env file."}))
            sys.exit(1)
    else:
        display_welcome_banner()
        Config.print_status()
        if not Config.MOCK_MODE and Config.USE_SSL and not Config.VERIFY_SSL and not Config.CA_BUNDLE:
            console.print(Panel(
                "[bold red]WARNING: TLS certificate verification is DISABLED (--insecure / VERIFY_SSL=False).[/bold red]\n"
                "Management-plane HTTPS traffic and API credentials are vulnerable to interception.\n"
                "For private PKI, configure [cyan]CA_BUNDLE[/cyan] or pass [cyan]--ca-bundle <path>[/cyan] instead.",
                title="⚠️ Insecure TLS Configuration",
                border_style="red"
            ))
        if "2.5" in Config.GEMINI_MODEL or "flash" in Config.GEMINI_MODEL.lower():
            console.print(Panel(
                f"[yellow]Current Model ({Config.GEMINI_MODEL}):[/yellow]\n"
                "Lightweight or legacy Flash/2.5 models trade reasoning depth for speed.\n"
                "For complex root-cause analysis, multi-step security correlation, and remediation planning,\n"
                "use flagship Gemini 4 models ([cyan]gemini-4-carbon[/cyan] or [cyan]gemini-4-neon[/cyan]) via [bold]--model <name>[/bold].",
                title="💡 Gemini Model & Precision Advisory",
                border_style="yellow"
            ))
        if args.command != "audit":
            ensure_api_key()

    # Initialize Client
    client = FortiGateClient(
        host=Config.FORTIGATE_IP,
        token=Config.FORTIGATE_TOKEN,
        port=Config.FORTIGATE_PORT,
        use_ssl=Config.USE_SSL,
        verify_ssl=Config.VERIFY_SSL,
        vdom=Config.FORTIGATE_VDOM,
        ca_bundle=Config.CA_BUNDLE,
        enable_write_actions=Config.ENABLE_WRITE_ACTIONS,
        dry_run=Config.DRY_RUN,
        backup_before_write=Config.BACKUP_BEFORE_WRITE,
        mock=Config.MOCK_MODE
    )

    # Initialize Agent
    try:
        agent = FortiGateAgent(fg_client=client)
    except Exception as e:
        if args.json:
            import json
            print(json.dumps({"error": f"Error initializing AI Agent: {e}"}))
        else:
            console.print(f"[red]Error initializing AI Agent: {e}[/red]")
        sys.exit(1)

    # If --json is set without explicit command, default is diagnose
    if args.json and not args.command:
        run_diagnostics(agent, output_json=True)
        return

    # Direct Command Dispatcher (Standard Text Modes)
    if args.command:
        cmd = args.command.lower()
        if cmd == "diagnose":
            run_diagnostics(agent, output_json=args.json)
            return
        elif cmd == "interactive":
            run_interactive_mode(agent)
            return
        elif cmd == "agentic":
            run_agentic_mode(agent, prompt=args.prompt)
            return
        elif cmd == "multi-agent":
            run_multi_agent_mode(client, prompt=args.prompt, output_json=args.json)
            return
        elif cmd == "audit":
            run_security_audit_mode(client, playbook_path=args.playbook, output_json=args.json)
            return
        elif cmd == "config":
            # Configuration was already printed
            return
        elif cmd == "backup":
            with console.status("[bold green]Creating configuration snapshot backup..."):
                try:
                    res = client.backup_configuration()
                    console.print(Panel(
                        f"[green]✓ Configuration backup successfully created![/green]\n"
                        f"File path: [bold cyan]{res.get('file_path')}[/bold cyan]\n"
                        f"Timestamp: [white]{res.get('timestamp')}[/white]",
                        title="Configuration Backup",
                        border_style="green"
                    ))
                except Exception as e:
                    console.print(f"[red]Failed to create backup: {e}[/red]")
            return

    # Interactive Menu Loop
    while True:
        console.print("\n[bold cyan]Select an Operation Mode:[/bold cyan]")
        console.print(" 1. Run Automated Diagnostics & Health Report")
        console.print(" 2. Enter Interactive Chat Console")
        console.print(" 3. Run Autonomous Agentic Reasoning Call")
        console.print(" 4. Run FortiOS Security Posture & CIS Hardening Benchmark")
        console.print(" 5. Create Configuration Snapshot Backup")
        console.print(" 6. View Current Configuration Settings")
        console.print(" 7. Exit")
        
        choice = Prompt.ask("Enter selection (1-7)", choices=["1", "2", "3", "4", "5", "6", "7"], default="1")
        
        if choice == "1":
            run_diagnostics(agent, output_json=False)
        elif choice == "2":
            run_interactive_mode(agent)
        elif choice == "3":
            run_agentic_mode(agent)
        elif choice == "4":
            playbook_opt = None
            if Confirm.ask("Would you like to export the automated FortiOS Hardening Playbook (.conf)?", default=True):
                playbook_opt = Prompt.ask("Enter destination playbook path", default="fortigate_hardening_playbook.conf")
            run_security_audit_mode(client, playbook_path=playbook_opt, output_json=False)
        elif choice == "5":
            with console.status("[bold green]Creating configuration snapshot backup..."):
                try:
                    res = client.backup_configuration()
                    console.print(Panel(
                        f"[green]✓ Configuration backup successfully created![/green]\n"
                        f"File path: [bold cyan]{res.get('file_path')}[/bold cyan]\n"
                        f"Timestamp: [white]{res.get('timestamp')}[/white]",
                        title="Configuration Backup",
                        border_style="green"
                    ))
                except Exception as e:
                    console.print(f"[red]Failed to create backup: {e}[/red]")
        elif choice == "6":
            Config.print_status()
        elif choice == "7":
            console.print("[green]Goodbye![/green]")
            break

if __name__ == "__main__":
    main()

