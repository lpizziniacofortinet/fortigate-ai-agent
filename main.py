import os
import sys
import logging
import argparse
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

console = Console()

def display_welcome_banner():
    """Displays a premium ASCII and text welcome banner."""
    banner_text = """
    ███████╗  ██████╗  ██████╗  ████████╗ ██╗  ██████╗  █████╗  ████████╗ ███████╗
    ██╔════╝ ██╔═══██╗ ██╔══██╗ ╚══██╔══╝ ██║ ██╔════╝ ██╔══██╗ ╚══██╔══╝ ██╔════╝
    █████╗   ██║   ██║ ██████╔╝    ██║    ██║ ██║  ███╗ ███████║    ██║    █████╗  
    ██╔══╝   ██║   ██║ ██╔══██╗    ██║    ██║ ██║   ██║ ██╔══██║    ██║    ██╔══╝  
    ██║      ╚██████╔╝ ██║  ██║    ██║    ██║ ╚██████╔╝ ██║  ██║    ██║    ███████╗
    ╚═╝       ╚═════╝  ╚═╝  ╚═╝    ╚═╝    ╚═╝  ╚═════╝  ╚═╝  ╚═╝    ╚═╝    ╚══════╝
                            
                    [bold purple]FortiGate AI Operations & Diagnostics Agent[/bold purple]
    """
    console.print(Panel(banner_text.strip(), border_style="purple"))

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
                console.print("[green]API Key saved to .env successfully.[/green]")
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
            print(report.model_dump_json(indent=2))
        except Exception as e:
            import json
            print(json.dumps({"error": f"AI Agent Diagnostics Error: {e}"}))
        return

    console.print("\n[bold blue]Starting Full FortiGate Security & Health Diagnostics...[/bold blue]")
    
    # 1. Show local raw metrics summary before LLM report
    with console.status("[bold green]Querying FortiGate details (Status, Resources, Interfaces, VPN, Routing, Logs)...") as status:
        try:
            sys_status = agent.fg_client.get_system_status()
            sys_res = agent.fg_client.get_system_resources()
            interfaces = agent.fg_client.get_interfaces()
            vpn = agent.fg_client.get_vpn_status()
            routes = agent.fg_client.get_routing_table()
            logs = agent.fg_client.get_system_logs()
            sdwan = agent.fg_client.get_sdwan_status()
            ha = agent.fg_client.get_ha_status()
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
    hostname = status_res.get("hostname", "Unknown")
    version = status_res.get("version", "Unknown")
    uptime_sec = status_res.get("uptime", 0) if isinstance(status_res.get("uptime"), (int, float)) else 0
    uptime_str = f"{uptime_sec // 86400}d {(uptime_sec % 86400) // 3600}h {(uptime_sec % 3600) // 60}m"
    
    table.add_row("System Status", f"Hostname: [bold]{hostname}[/bold], OS: [green]FortiOS {version}[/green], Uptime: {uptime_str}")
    
    # HA Cluster
    ha_res = ha.get("results", {}) if isinstance(ha, dict) else {}
    ha_sync = ha_res.get("sync_status", "N/A")
    ha_mode = ha_res.get("mode", "N/A")
    sync_style = "green" if ha_sync == "in-sync" else "red"
    table.add_row("HA Cluster", f"Mode: [bold]{ha_mode}[/bold], Sync Status: [{sync_style}]{ha_sync}[/{sync_style}]")

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
    mem = _parse_metric(res_data.get("memory", "N/A"))
    sessions = _parse_metric(res_data.get("session", "N/A"))
    table.add_row("Resources Usage", f"CPU: [bold]{cpu}%[/bold], Memory: [bold]{mem}%[/bold], Sessions: [bold]{sessions}[/bold]")
    
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
    ipsec_up = sum(1 for t in ipsec_tunnels if isinstance(t, dict) and (t.get("status") == "up" or t.get("link") is True))
    ipsec_down = sum(1 for t in ipsec_tunnels if isinstance(t, dict) and (t.get("status") == "down" or t.get("link") is False))
    ssl_sessions = vpn_results.get("ssl_vpn", {}).get("active_sessions_count", 0) if isinstance(vpn_results.get("ssl_vpn"), dict) else 0
    table.add_row("VPN Tunnels & Sessions", f"IPsec Up: [green]{ipsec_up}[/green]/[red]{ipsec_down}[/red], Active SSL Users: [bold]{ssl_sessions}[/bold]")
    
    # Routing
    route_raw = routes.get("results", []) if isinstance(routes, dict) else []
    if isinstance(route_raw, dict):
        route_list = list(route_raw.values())
    elif isinstance(route_raw, list):
        route_list = route_raw
    else:
        route_list = []
    table.add_row("Routing Table", f"Total routes active: [bold]{len(route_list)}[/bold]")

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

def run_agentic_mode(agent: FortiGateAgent, prompt: Optional[str] = None):
    """Runs a multi-step agentic call with chain-of-thought tool execution tracing."""
    if not prompt:
        prompt = (
            "Perform an autonomous multi-step investigation of the FortiGate firewall. "
            "Inspect system health, interfaces, routing table, and VPN status. "
            "If any interface or routing/VPN anomaly is found, inspect system logs or policies to explain the root cause."
        )
        
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

def parse_args():
    """Parses command-line arguments for CLI overrides."""
    parser = argparse.ArgumentParser(
        description="FortiGate AI Operations & Diagnostics Agent"
    )
    parser.add_argument(
        "command",
        nargs="?",
        choices=["diagnose", "interactive", "agentic", "config"],
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
        help="Enable HTTPS certificate verification."
    )
    parser.add_argument(
        "--ca-bundle", "-c",
        help="Path to custom CA certificate bundle (enables verification)."
    )
    return parser.parse_args()

def main():
    args = parse_args()

    # Apply CLI overrides to Config
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
    if args.ca_bundle:
        Config.CA_BUNDLE = args.ca_bundle
        Config.VERIFY_SSL = True
    if args.enable_write:
        Config.ENABLE_WRITE_ACTIONS = True

    # Re-evaluate mock mode if settings changed
    if not Config.MOCK_MODE and not (Config.FORTIGATE_IP and Config.FORTIGATE_TOKEN):
        Config.MOCK_MODE = True

    if args.json:
        # Check API key without interactive prompt
        if not Config.GEMINI_API_KEY:
            import json
            print(json.dumps({"error": "Gemini API key is not configured. Specify GEMINI_API_KEY in environment or .env file."}))
            sys.exit(1)
    else:
        display_welcome_banner()
        Config.print_status()
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

    # If --json is set, default command is diagnose
    if args.json:
        run_diagnostics(agent, output_json=True)
        return

    # Direct Command Dispatcher (Standard Text Modes)
    if args.command:
        cmd = args.command.lower()
        if cmd == "diagnose":
            run_diagnostics(agent, output_json=False)
            return
        elif cmd == "interactive":
            run_interactive_mode(agent)
            return
        elif cmd == "agentic":
            run_agentic_mode(agent)
            return
        elif cmd == "config":
            # Configuration was already printed
            return

    # Interactive Menu Loop
    while True:
        console.print("\n[bold cyan]Select an Operation Mode:[/bold cyan]")
        console.print(" 1. Run Automated Diagnostics & Health Report")
        console.print(" 2. Enter Interactive Chat Console")
        console.print(" 3. Run Autonomous Agentic Reasoning Call")
        console.print(" 4. View Current Configuration Settings")
        console.print(" 5. Exit")
        
        choice = Prompt.ask("Enter selection (1-5)", choices=["1", "2", "3", "4", "5"], default="1")
        
        if choice == "1":
            run_diagnostics(agent, output_json=False)
        elif choice == "2":
            run_interactive_mode(agent)
        elif choice == "3":
            run_agentic_mode(agent)
        elif choice == "4":
            Config.print_status()
        elif choice == "5":
            console.print("[green]Goodbye![/green]")
            break

if __name__ == "__main__":
    main()

