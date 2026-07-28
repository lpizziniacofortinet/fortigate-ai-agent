import logging
from typing import Dict, Any, List, Optional
from google import genai
from google.genai import types
from pydantic import BaseModel, Field

from config import Config
from fortigate_client import FortiGateClient

logger = logging.getLogger("FortiGateAgent")

class DiagnosticFinding(BaseModel):
    category: str = Field(description="Component category: system, resources, interfaces, vpn, or routing")
    status: str = Field(description="Status of the finding: ok, warning, critical")
    summary: str = Field(description="Short summary of the finding")
    details: str = Field(description="Detailed explanation and raw metrics observed")

class DiagnosticReport(BaseModel):
    hostname: str = Field(description="Hostname of the FortiGate device")
    overall_health: str = Field(description="Overall health status: healthy, degraded, or critical")
    findings: List[DiagnosticFinding] = Field(description="Detailed component status findings")
    troubleshooting_steps: List[str] = Field(description="Step-by-step troubleshooting recommendations for any warnings or critical findings")

# Global reference to the initialized FortiGateClient
_client: Optional[FortiGateClient] = None

def get_fg_client() -> FortiGateClient:
    """Helper to get the current FortiGate client."""
    global _client
    if _client is None:
        raise ValueError("FortiGateClient has not been initialized. Call initialize_agent_client() first.")
    return _client

# =====================================================================
# Tools for the Gemini Agent (with docstrings for the LLM to inspect)
# =====================================================================

def get_system_status() -> Dict[str, Any]:
    """
    Get the basic status of the FortiGate firewall.
    
    Returns details such as:
    - Hostname
    - Firmware version and build
    - Serial Number
    - Device uptime (in seconds)
    - High Availability (HA) mode and role
    - Operation Mode (e.g., NAT or Transparent)
    """
    client = get_fg_client()
    return client.get_system_status()

def get_system_resources() -> Dict[str, Any]:
    """
    Get current system resource utilization metrics for the FortiGate.
    
    Returns details such as:
    - CPU usage percentage (%)
    - Memory usage percentage (%)
    - Active network session count and maximum allowed sessions
    - Disk usage percentage (%)
    """
    client = get_fg_client()
    return client.get_system_resources()

def get_interfaces() -> Dict[str, Any]:
    """
    Get status, IP configurations, and traffic statistics for all network interfaces.
    
    Returns details such as:
    - Interface names (e.g., port1, port2, dmz)
    - Connection status (up/down)
    - IP addresses and subnets
    - Link speed and duplex settings
    - Traffic counters (Rx/Tx bytes, Rx/Tx packets)
    - Interface descriptions
    """
    client = get_fg_client()
    return client.get_interfaces()

def get_vpn_status() -> Dict[str, Any]:
    """
    Get real-time monitoring data for both IPsec tunnels and SSL-VPN connections.
    
    Returns details such as:
    - IPsec tunnels configuration, status (up/down), remote gateway IP, and throughput
    - SSL-VPN active sessions count and user details (IP, login duration, bytes exchanged)
    """
    client = get_fg_client()
    return client.get_vpn_status()

def get_routing_table() -> Dict[str, Any]:
    """
    Get the active IPv4 routing table from the FortiGate.
    
    Returns details such as:
    - Destination IP subnets (prefixes)
    - Next-hop gateway IP addresses
    - Egress interface names
    - Administrative distance and metric
    - Route type (e.g., connected, static, dynamic/OSPF/BGP)
    """
    client = get_fg_client()
    return client.get_routing_table()

def get_system_logs(log_type: str = "event", limit: int = 15) -> Dict[str, Any]:
    """
    Get recent system/event/traffic/security logs from the FortiGate unit.
    
    Parameters:
    - log_type: The category of logs (typically 'event', 'traffic', or 'security'). Defaults to 'event'.
    - limit: The maximum number of log messages to retrieve. Defaults to 15.
    
    Returns a list of event logs with timestamps, levels (warning, info, notice), subtypes, and messages.
    """
    client = get_fg_client()
    return client.get_system_logs(log_type=log_type, limit=limit)

def reset_vpn_tunnel(p1_name: str) -> Dict[str, Any]:
    """
    Reset or flush an IPsec VPN Phase 1 tunnel to force re-negotiation.
    Use this when a configured VPN tunnel is down or negotiation is stuck.
    
    Parameters:
    - p1_name: The Phase 1 configuration name of the VPN tunnel to reset.
    """
    import sys
    client = get_fg_client()
    
    if not client.enable_write_actions:
        raise PermissionError(
            "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True in .env "
            "or use the --enable-write CLI flag, and ensure your API key has write permissions."
        )

    if sys.stdin.isatty():
        from rich.console import Console
        from rich.prompt import Confirm
        console = Console()
        console.print(f"\n[bold yellow]⚠️  WARNING: AI Agent requested to RESET VPN Tunnel: [bold cyan]{p1_name}[/bold cyan][/bold yellow]")
        if not Confirm.ask("Do you authorize this operation?"):
            raise PermissionError("User rejected the VPN reset operation.")

    return client.reset_vpn_tunnel(p1_name=p1_name)

def toggle_interface(interface_name: str, status: str) -> Dict[str, Any]:
    """
    Toggle the administrative state of a network interface (bring it 'up' or 'down').
    Use this to reset or bounce a degraded port, or shut down a port.
    
    Parameters:
    - interface_name: The name of the interface (e.g. 'port1', 'port2').
    - status: Target status, must be 'up' or 'down'.
    """
    import sys
    client = get_fg_client()
    
    if not client.enable_write_actions:
        raise PermissionError(
            "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True in .env "
            "or use the --enable-write CLI flag, and ensure your API key has write permissions."
        )

    if sys.stdin.isatty():
        from rich.console import Console
        from rich.prompt import Confirm
        console = Console()
        console.print(f"\n[bold yellow]⚠️  WARNING: AI Agent requested to TOGGLE interface [bold cyan]{interface_name}[/bold cyan] to [bold cyan]{status}[/bold cyan][/bold yellow]")
        if not Confirm.ask("Do you authorize this operation?"):
            raise PermissionError("User rejected the interface toggle operation.")

    return client.toggle_interface(interface_name=interface_name, status=status)

def add_static_route(destination: str, gateway: str, interface: str) -> Dict[str, Any]:
    """
    Configure a new static IPv4 route on the FortiGate firewall.
    Use this when a subnet is unreachable and requires a static next-hop route.
    
    Parameters:
    - destination: Destination IP prefix / subnet mask (e.g. '10.50.0.0/16').
    - gateway: Next-hop gateway IP address (e.g. '198.51.100.254').
    - interface: Output interface device name (e.g. 'port1').
    """
    import sys
    client = get_fg_client()
    
    if not client.enable_write_actions:
        raise PermissionError(
            "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True in .env "
            "or use the --enable-write CLI flag, and ensure your API key has write permissions."
        )

    if sys.stdin.isatty():
        from rich.console import Console
        from rich.prompt import Confirm
        console = Console()
        console.print(f"\n[bold yellow]⚠️  WARNING: AI Agent requested to ADD static route to [bold cyan]{destination}[/bold cyan] via [bold cyan]{gateway}[/bold cyan] on [bold cyan]{interface}[/bold cyan][/bold yellow]")
        if not Confirm.ask("Do you authorize this operation?"):
            raise PermissionError("User rejected the static route addition.")

    return client.add_static_route(destination=destination, gateway=gateway, interface=interface)

def get_bgp_neighbors() -> Dict[str, Any]:
    """
    Get BGP dynamic routing neighbor peer states and stats from the FortiGate.
    Use this to verify if BGP peerings are Established or in Active/Idle down states.
    """
    client = get_fg_client()
    return client.get_bgp_neighbors()

def get_firewall_policies() -> Dict[str, Any]:
    """
    Get configured security policies from the FortiGate firewall.
    Use this to audit if policies block traffic, restrict services, or block routing ports.
    """
    client = get_fg_client()
    return client.get_firewall_policies()

def get_ospf_neighbors() -> Dict[str, Any]:
    """
    Get OSPF dynamic routing neighbor peer states and stats from the FortiGate.
    Use this to verify if OSPF adjacencies are established (Full) or down/stuck (Init, Attempt, Down).
    """
    client = get_fg_client()
    return client.get_ospf_neighbors()

def get_sdwan_status() -> Dict[str, Any]:
    """
    Get SD-WAN interface member states and performance SLA metrics (latency, jitter, packet loss).
    Use this to check WAN link health, SLA status (pass/fail), and packet loss on internet links.
    """
    client = get_fg_client()
    return client.get_sdwan_status()

def get_ha_status() -> Dict[str, Any]:
    """
    Get High Availability (HA) cluster status, peer member node health, role (master/slave), and checksum sync status.
    Use this to verify if HA nodes are in-sync or if cluster failover/sync issues exist.
    """
    client = get_fg_client()
    return client.get_ha_status()

def toggle_firewall_policy(policy_id: int, status: str) -> Dict[str, Any]:
    """
    Toggle the administrative state of a firewall policy (enable or disable).
    Use this to enable a disabled policy or disable a policy that is blocking legitimate traffic.
    
    Parameters:
    - policy_id: The numerical ID of the firewall security policy (e.g. 5).
    - status: Target status, must be 'enable' or 'disable'.
    """
    import sys
    client = get_fg_client()
    
    if not client.enable_write_actions:
        raise PermissionError(
            "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True in .env "
            "or use the --enable-write CLI flag, and ensure your API key has write permissions."
        )

    if sys.stdin.isatty():
        from rich.console import Console
        from rich.prompt import Confirm
        console = Console()
        console.print(f"\n[bold yellow]⚠️  WARNING: AI Agent requested to TOGGLE firewall policy ID [bold cyan]{policy_id}[/bold cyan] to [bold cyan]{status}[/bold cyan][/bold yellow]")
        if not Confirm.ask("Do you authorize this operation?"):
            raise PermissionError("User rejected the firewall policy toggle operation.")

    return client.toggle_firewall_policy(policy_id=policy_id, status=status)

def disconnect_ssl_vpn_user(username: str) -> Dict[str, Any]:
    """
    Forcefully disconnect an active SSL-VPN user session.
    Use this to terminate suspicious or unauthorized user sessions.
    
    Parameters:
    - username: The SSL-VPN user account name to terminate (e.g. 'jdoe').
    """
    import sys
    client = get_fg_client()
    
    if not client.enable_write_actions:
        raise PermissionError(
            "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True in .env "
            "or use the --enable-write CLI flag, and ensure your API key has write permissions."
        )

    if sys.stdin.isatty():
        from rich.console import Console
        from rich.prompt import Confirm
        console = Console()
        console.print(f"\n[bold yellow]⚠️  WARNING: AI Agent requested to DISCONNECT SSL-VPN session for user: [bold cyan]{username}[/bold cyan][/bold yellow]")
        if not Confirm.ask("Do you authorize this operation?"):
            raise PermissionError("User rejected the SSL-VPN disconnect operation.")

    return client.disconnect_ssl_vpn_user(username=username)

def get_vdom_list() -> Dict[str, Any]:
    """
    Get the list of configured Virtual Domains (VDOMs) on the FortiGate firewall.
    Use this to inspect multi-VDOM environments and view configured VDOM partitions.
    """
    client = get_fg_client()
    return client.get_vdom_list()


# List of all tools to expose to Gemini
FORTIGATE_TOOLS = [
    get_system_status,
    get_system_resources,
    get_interfaces,
    get_vpn_status,
    get_routing_table,
    get_system_logs,
    get_bgp_neighbors,
    get_ospf_neighbors,
    get_firewall_policies,
    get_sdwan_status,
    get_ha_status,
    get_vdom_list,
    reset_vpn_tunnel,
    toggle_interface,
    add_static_route,
    toggle_firewall_policy,
    disconnect_ssl_vpn_user
]

SYSTEM_INSTRUCTION = """
You are a highly skilled Network Security AI Agent specialized in FortiGate Firewalls (FortiOS).
You have access to tools that query and modify a target FortiGate firewall's REST API in real time.

Your role is to help the user diagnose, inspect, verify, and restore the health of their FortiGate unit.
When responding to requests:
1. Use your tools to fetch necessary data (e.g., get_system_status, get_system_resources, get_interfaces, get_vpn_status, get_routing_table, get_system_logs, get_bgp_neighbors, get_ospf_neighbors, get_firewall_policies, get_sdwan_status, get_ha_status, get_vdom_list).
2. Analyze the outputs carefully:
   - Check if any interfaces are unexpectedly down (especially WAN interfaces with a link status of 'down').
   - Check SD-WAN health metrics (get_sdwan_status) for packet loss, high latency/jitter, or SLA failure.
   - Check HA cluster status (get_ha_status) for sync status ('in-sync' vs out-of-sync checksums) and node health.
   - Check for resource bottlenecks (e.g., CPU/Memory usage above 80%).
   - Inspect VPN tunnels for disconnects (status 'down' for configured tunnels) or active SSL-VPN session anomalies.
   - Verify BGP dynamic routing status (get_bgp_neighbors) to check if BGP peers are 'Established' or down ('Active', 'Idle').
   - Verify OSPF dynamic routing status (get_ospf_neighbors) to check if OSPF neighbors are fully adjacent ('Full') or down/stuck ('Init', 'Down').
   - Inspect firewall security policies (get_firewall_policies) to check if policies block necessary dynamic routing protocols (like BGP TCP port 179) or specific traffic routes.
   - Verify that there is a default route (0.0.0.0/0) in the routing table and trace how routes route traffic.
   - Read system logs (get_system_logs) to troubleshoot issues, find login failures, or explain why VPN connection attempts failed.
3. You have access to active configuration write tools: `reset_vpn_tunnel`, `toggle_interface`, `add_static_route`, `toggle_firewall_policy`, and `disconnect_ssl_vpn_user`.
   - BEFORE invoking any write action, explain to the user exactly what you propose to do.
   - If the client fails with a PermissionError, explain to the user that write/mitigation actions are disabled (they must set `ENABLE_WRITE_ACTIONS=True` in their environment or .env file) or that their FortiGate REST API token lacks write permissions. Suggest equivalent CLI commands they can execute manually.
4. Be professional, structured, and clear. Format your reports and answers with Markdown tables, bold key metrics, and bulleted lists.
5. When identifying issues, always provide logical troubleshooting steps or CLI commands to fix them (e.g., "diagnose vpn ike gateway list" or "get router info routing-table all").
"""

class FortiGateAgent:
    """
    AI Agent that wraps the Gemini SDK and provides function-calling interaction
    with the FortiGate firewall.
    """
    def __init__(self, fg_client: FortiGateClient, api_key: Optional[str] = None):
        global _client
        _client = fg_client
        self.fg_client = fg_client
        
        # Initialize Gemini Client
        # The Client will automatically look for GEMINI_API_KEY environment variable if api_key is None
        self.ai_client = genai.Client(api_key=api_key or Config.GEMINI_API_KEY)
        self.model = Config.GEMINI_MODEL

    def run_query(self, prompt: str) -> str:
        """Runs a single prompt query against the agent with automatic tool calling."""
        logger.info(f"Running agent query: '{prompt}'")
        
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=FORTIGATE_TOOLS,
            temperature=0.2  # Lower temperature for more factual diagnostic responses
        )
        
        response = self.ai_client.models.generate_content(
            model=self.model,
            contents=prompt,
            config=config
        )
        return response.text

    def run_structured_query(self, prompt: str) -> DiagnosticReport:
        """Runs a prompt query and enforces structured JSON output using a Pydantic schema."""
        logger.info("Running structured agent query")
        import json
        schema_json = DiagnosticReport.model_json_schema()
        
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=FORTIGATE_TOOLS,
            temperature=0.2
        )
        
        full_prompt = (
            f"{prompt}\n\n"
            f"REQUIRED OUTPUT FORMAT:\n"
            f"You MUST provide your final answer as raw, valid JSON matching this exact JSON schema:\n"
            f"{json.dumps(schema_json, indent=2)}\n"
            f"Do not include any extra explanatory text outside of the JSON markdown block."
        )
        
        response = self.ai_client.models.generate_content(
            model=self.model,
            contents=full_prompt,
            config=config
        )
        
        text = response.text.strip() if response.text else "{}"
        if text.startswith("```json"):
            text = text.split("```json", 1)[1].rsplit("```", 1)[0].strip()
        elif text.startswith("```"):
            text = text.split("```", 1)[1].rsplit("```", 1)[0].strip()
            
        try:
            return DiagnosticReport.model_validate_json(text)
        except Exception as e:
            logger.warning(f"Could not parse Pydantic model directly: {e}. Falling back to default DiagnosticReport.")
            return DiagnosticReport(
                hostname="FortiGate",
                overall_health="degraded",
                findings=[
                    DiagnosticFinding(
                        category="system",
                        status="warning",
                        summary="Structured JSON Parsing Notice",
                        details=f"Raw AI Output: {text[:500]}"
                    )
                ],
                troubleshooting_steps=["Verify API response formatting."]
            )



    def create_chat_session(self):
        """Creates an interactive chat session with automatic function calling."""
        config = types.GenerateContentConfig(
            system_instruction=SYSTEM_INSTRUCTION,
            tools=FORTIGATE_TOOLS,
            temperature=0.2
        )
        
        return self.ai_client.chats.create(
            model=self.model,
            config=config
        )

    def run_agentic_loop(self, prompt: str) -> Dict[str, Any]:
        """
        Executes a multi-turn agentic reasoning loop with step-by-step tool inspection and chain-of-thought tracking.
        
        Returns:
            Dict containing:
            - 'prompt': Original prompt
            - 'tools_executed': List of tool names called during reasoning
            - 'history_steps': Detailed step-by-step execution log
            - 'final_response': Synthesized final agent response text
        """
        logger.info(f"Starting explicit agentic reasoning loop for: '{prompt}'")
        chat = self.create_chat_session()
        response = chat.send_message(prompt)
        
        history = chat.get_history()
        tools_executed = []
        history_steps = []
        
        for msg in history:
            role = msg.role
            for part in msg.parts:
                if hasattr(part, 'function_call') and part.function_call:
                    fn_name = part.function_call.name
                    fn_args = dict(part.function_call.args) if part.function_call.args else {}
                    tools_executed.append(fn_name)
                    history_steps.append({
                        "step": "function_call",
                        "name": fn_name,
                        "args": fn_args
                    })
                    logger.info(f"[Agentic Loop] Executed Tool: {fn_name} with args: {fn_args}")
                elif hasattr(part, 'function_response') and part.function_response:
                    fn_name = part.function_response.name
                    history_steps.append({
                        "step": "function_response",
                        "name": fn_name
                    })
                elif hasattr(part, 'text') and part.text:
                    history_steps.append({
                        "step": "thought_or_response",
                        "role": role,
                        "text": part.text
                    })

        return {
            "prompt": prompt,
            "tools_executed": tools_executed,
            "history_steps": history_steps,
            "final_response": response.text
        }
