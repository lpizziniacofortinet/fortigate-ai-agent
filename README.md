# FortiGate AI Operations & Diagnostics Agent

A production-ready AI operations and troubleshooting agent written in Python that interfaces directly with FortiGate firewalls running FortiOS (v7.0+) using the modern **`google-genai`** SDK. The agent is equipped with 23 custom function-calling tools that enable it to dynamically retrieve, inspect, correlate, and remediate network configurations, resource utilization, interfaces, SD-WAN health metrics, VPN tunnels, dynamic routing adjacencies (BGP & OSPF), ARP tables, DHCP leases, FortiGuard security subscriptions (AV/IPS/WebFilter), quarantined threat actors, firewall security policies, system configuration backups, and event logs.

It provides five operational modes:
1. **Automated Diagnostics**: Gathers operational metrics across all subsystems, passes them to the AI agent, and generates a structured markdown-based health assessment and troubleshooting plan.
2. **Interactive Console**: A stateful chat session where you can ask arbitrary questions about the FortiGate, and the AI agent autonomously decides which API tools to invoke in the background.
3. **Autonomous Agentic Call**: Multi-step chain-of-thought call loop where the AI agent autonomously executes tool calls, inspects findings, triggers follow-up telemetry (e.g. log queries or firewall policy inspections), and prints a live reasoning trace of all tools called.
4. **Configuration Backup**: Generates an immediate full system configuration snapshot (`.conf`) for disaster recovery and change auditing.
5. **Configuration Inspector**: Displays active environment variables, target VDOM, SSL verification modes, and Gemini model settings.

It also features a high-fidelity **Mock Mode** for offline testing and demonstration purposes without requiring a physical or virtual FortiGate appliance.

---

## Architecture & Endpoints Used

The agent communicates with the standard FortiOS REST API (`/api/v2`) and implements automatic fallback endpoints for multi-version compatibility:

- **System Status**: `GET /api/v2/monitor/system/status` (falls back to `GET /api/v2/cmdb/system/global` if restricted)
- **HA Cluster & Sync**: `GET /api/v2/monitor/system/ha-checksum` (falls back to `GET /api/v2/monitor/system/ha`)
- **System Resources**: `GET /api/v2/monitor/system/resource/usage` (falls back to `GET /api/v2/monitor/system/resource`)
- **Network Interfaces**: `GET /api/v2/monitor/system/interface` (status, speed, duplex, IP, and traffic counts)
- **Interface State Modification**: `PUT /api/v2/cmdb/system/interface/{interface_name}` (administrative up/down toggle)
- **SD-WAN Link Health**: `GET /api/v2/monitor/virtual-wan/health-check` (falls back to `GET /api/v2/monitor/virtual-wan/members` for SLA metrics, latency, jitter, and packet loss)
- **VPN Tunnels**: `GET /api/v2/monitor/vpn/ipsec` and `GET /api/v2/monitor/vpn/ssl` (IPsec tunnel status and SSL-VPN active user sessions)
- **IPsec Tunnel Reset**: `POST /api/v2/monitor/vpn/ipsec/tunnel_reset_stats` (forces Phase 1 re-negotiation)
- **SSL-VPN Disconnect**: `POST /api/v2/monitor/vpn/ssl/disconnect` (active user session termination)
- **Routing Table**: `GET /api/v2/monitor/router/ipv4` (active IPv4 routing table entries)
- **Static Route Creation**: `POST /api/v2/cmdb/router/static` (adds static IPv4 route entry)
- **BGP Dynamic Routing**: `GET /api/v2/monitor/router/bgp/neighbors` (BGP peer status, uptime, route counts)
- **OSPF Dynamic Routing**: `GET /api/v2/monitor/router/ospf/neighbors` (falls back to `GET /api/v2/monitor/router/ospf`)
- **Firewall Policies**: `GET /api/v2/cmdb/firewall/policy` (inspects configured security rules)
- **Firewall Policy Toggle**: `PUT /api/v2/cmdb/firewall/policy/{policy_id}` (enable or disable specific policies)
- **FortiGuard Subscriptions**: `GET /api/v2/monitor/system/fortiguard` (falls back to `GET /api/v2/cmdb/system/fortiguard` for AV, IPS, Web Filter, and signature engine levels)
- **Quarantined / Banned IPs**: `GET /api/v2/monitor/user/banned` (active banned hosts table)
- **IP Quarantine / Ban**: `POST /api/v2/monitor/user/banned/add` (immediate threat containment)
- **Virtual Domains (VDOMs)**: `GET /api/v2/cmdb/system/vdom` (configured VDOM partitions)
- **ARP Table**: `GET /api/v2/monitor/network/arp` (falls back to `GET /api/v2/monitor/system/arp` for Layer 2 MAC mappings)
- **DHCP Leases**: `GET /api/v2/monitor/system/dhcp` (falls back to `GET /api/v2/monitor/system/dhcp/status` for active IP allocations)
- **Configuration Backup**: `GET /api/v2/monitor/system/config/backup` (full system configuration snapshot)
- **Event Logs**: `GET /api/v2/monitor/log/memory/messages` (falls back to `GET /api/v2/monitor/log/disk/messages` and `GET /api/v2/monitor/log/current`)

For authentication, the client utilizes the secure **`Authorization: Bearer <API-TOKEN>`** HTTP header conforming to modern FortiOS standards (v7.2.x, v7.4.x, v7.6.x+).

---

## AI Agent Tools Reference (Function Calling)

The AI Agent exposes 23 Python function-calling tools (`FORTIGATE_TOOLS`) registered directly with the Gemini model via the modern `google-genai` SDK. In interactive or agentic modes, the model autonomously analyzes user queries, selects appropriate tools, executes them, and synthesizes operational findings.

### 1. Read-Only Telemetry & Inspection Tools (16 Tools)

| Tool Name | Parameters | Description / Telemetry Gathered |
| :--- | :--- | :--- |
| **`get_system_status`** | _None_ | Retrieves hostname, firmware version, build number, serial number, uptime, HA cluster role, and operation mode. |
| **`get_system_resources`** | _None_ | Retrieves CPU utilization (%), memory usage (%), active and maximum concurrent sessions, and disk usage. |
| **`get_interfaces`** | _None_ | Inspects network interfaces: administrative and physical link status (up/down), IP assignments, speed, duplex, and Rx/Tx byte/packet counters. |
| **`get_vpn_status`** | _None_ | Gathers IPsec Phase 1/Phase 2 tunnel states, remote gateways, throughput, and active SSL-VPN user sessions (username, source IP, duration, bytes). |
| **`get_routing_table`** | _None_ | Retrieves active IPv4 routing table entries, next-hop gateways, egress interface names, administrative distances, and route types (static, connected, dynamic). |
| **`get_arp_table`** | _None_ | Retrieves IPv4 ARP table mappings (IP, MAC, interface, state) to verify Layer 2 neighbor resolution and reachability. |
| **`get_dhcp_leases`** | _None_ | Retrieves active DHCP client lease assignments (IP, MAC, hostname, interface, expiration) to troubleshoot client addressing. |
| **`get_fortiguard_status`** | _None_ | Retrieves FortiGuard subscription licenses, AV/IPS database versions, Web Filter status, and signature expiration dates. |
| **`get_quarantined_ips`** | _None_ | Retrieves the list of currently banned/quarantined IP addresses, ban reasons, and expiration timers from the FortiGate user ban table. |
| **`get_system_logs`** | `log_type` (str, default: `"event"`), `limit` (int, default: `15`) | Fetches recent event, traffic, or security log entries with timestamps, severity levels (warning, info, notice), subtypes, and messages. |
| **`get_bgp_neighbors`** | _None_ | Checks BGP dynamic routing peer states (`Established`, `Active`, `Idle`), remote AS numbers, uptime, and advertised/received route counts. |
| **`get_ospf_neighbors`** | _None_ | Checks OSPF dynamic routing neighbor states (`Full`, `Init`, `Attempt`, `Down`), neighbor router IDs, priorities, and interfaces. |
| **`get_firewall_policies`** | _None_ | Audits configured firewall security policies, rule IDs, source/destination interfaces, addresses, actions (`accept`/`deny`), services, and administrative status. |
| **`get_sdwan_status`** | _None_ | Checks SD-WAN member health, packet loss (%), latency (ms), jitter (ms), and SLA status (`pass`/`fail`). |
| **`get_ha_status`** | _None_ | Monitors High Availability (HA) cluster status, peer members, sync state (`in-sync`/out-of-sync), and checksum matches. |
| **`get_vdom_list`** | _None_ | Lists configured Virtual Domains (VDOMs) and cluster partition IDs for multi-tenant deployments. |

### 2. Active Remediation & Write Tools (7 Tools)

> [!NOTE]
> All write tools require `ENABLE_WRITE_ACTIONS=True` (or `--enable-write` CLI flag) and an API token with read-write permissions. In interactive terminal sessions, the agent will always request explicit confirmation (`y/N`) before modifying any configuration. When `DRY_RUN=True` or `--dry-run` is specified, write actions are safely simulated.

| Tool Name | Parameters | Target Remediation Action |
| :--- | :--- | :--- |
| **`backup_configuration`** | `destination_dir` (str, default: `".backups"`) | Downloads and saves a complete timestamped configuration snapshot (.conf) locally. |
| **`quarantine_ip_address`** | `ip_address` (str), `duration_seconds` (int, default: `3600`), `reason` (str, default: `""`) | Bans and quarantines a malicious or compromised IP address on the FortiGate firewall. |
| **`reset_vpn_tunnel`** | `p1_name` (str) | Flushes and resets an IPsec Phase 1 VPN tunnel to restart IKE/IPsec negotiations. |
| **`toggle_interface`** | `interface_name` (str), `status` (`"up"` \| `"down"`) | Administratively enables (`up`) or disables (`down`) a network interface. |
| **`add_static_route`** | `destination` (str), `gateway` (str), `interface` (str) | Configures a new static IPv4 route on the FortiGate firewall. |
| **`toggle_firewall_policy`** | `policy_id` (int), `status` (`"enable"` \| `"disable"`) | Enables or disables a specific firewall security policy by policy ID. |
| **`disconnect_ssl_vpn_user`** | `username` (str) | Forcefully terminates an active SSL-VPN user session. |


---

## Installation & Setup

### 1. Prerequisites
- Python 3.10 or higher
- A Google Gemini API key (obtain one from [Google AI Studio](https://aistudio.google.com/))

### 2. Set Up Virtual Environment & Dependencies
Clone or navigate to the project directory:
```bash
# Create and activate a Python virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install required dependencies
pip install -r requirements.txt
```

### 3. Configure the Environment
Copy the configuration template:
```bash
cp .env.template .env
```

Open `.env` and fill in your settings:
```ini
# Gemini API Key (Required for AI Agent operations)
GEMINI_API_KEY=your_gemini_api_key_here
GEMINI_MODEL=gemini-2.5-flash

# FortiGate Connection Details
# Leave empty to automatically use high-fidelity MOCK MODE
FORTIGATE_IP=192.168.1.99
FORTIGATE_TOKEN=your_fortigate_api_token_here
FORTIGATE_PORT=443
FORTIGATE_VDOM=root
USE_SSL=True
VERIFY_SSL=False
CA_BUNDLE=

# Set to True to force offline mock simulation
MOCK_MODE=False

# Enable active write/mitigation actions (disable for safe read-only mode)
ENABLE_WRITE_ACTIONS=False

# Dry run mode: simulate write actions without executing REST calls
DRY_RUN=False

# Automatically take configuration snapshot backup before executing write actions
BACKUP_BEFORE_WRITE=True
```

### 4. Environment Variables Reference

| Variable | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `GEMINI_API_KEY` | String | _None_ | Google Gemini API key for AI reasoning. |
| `GEMINI_MODEL` | String | `gemini-2.5-flash` | Target Gemini model (`gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-3.5-flash`, `gemini-3.1-pro-preview`, `gemini-pro-latest`). |
| `FORTIGATE_IP` | String | `""` | IP address or hostname of the FortiGate firewall. |
| `FORTIGATE_TOKEN` | String | `""` | REST API Access Token generated in FortiOS GUI. |
| `FORTIGATE_PORT` | Integer | `443` | Target API connection port. |
| `FORTIGATE_VDOM` | String | `root` | Target Virtual Domain (VDOM) for API queries. |
| `USE_SSL` | Boolean | `True` | Whether to connect via HTTPS (`True`) or HTTP (`False`). |
| `VERIFY_SSL` | Boolean | `False` | Whether to verify HTTPS SSL certificates. |
| `CA_BUNDLE` | String | `""` | File path to a custom CA certificate bundle (.pem). Enables SSL verification. |
| `MOCK_MODE` | Boolean | `Auto` | If `True` or if IP/Token are omitted, runs offline mock simulation. |
| `ENABLE_WRITE_ACTIONS` | Boolean | `False` | If `True`, enables active configuration modifications (VPN reset, interface toggle, static routes, policy changes). |
| `DRY_RUN` | Boolean | `False` | If `True`, simulates write actions and displays proposed parameters without applying changes. |
| `BACKUP_BEFORE_WRITE` | Boolean | `True` | If `True`, automatically takes a `.conf` backup snapshot before applying write actions. |
| `OUTPUT_FILE` | String | `""` | File path to export diagnostic reports (`.html`, `.md`, or `.json`). |

---

## Generating an API Token on FortiGate

If running in Live Mode, generate a REST API Administrator key on your FortiGate:
1. Log into your FortiGate GUI.
2. Navigate to **System > Administrators**.
3. Click **Create New > REST API Admin**.
4. Set a username (e.g., `ai_operator`).
5. Choose an admin profile:
   * **Read-Only**: Suitable for monitoring and diagnostics mode.
   * **Read/Write**: Required if you wish to use active remediation tools (interface toggle, route addition, policy toggle, tunnel reset).
6. Configure **Trusted Hosts** (strongly recommended to restrict access to your administrative workstation).
7. Click **OK**. A dialog will display your **API Key**. Copy it immediately as it will not be displayed again.

---

## Usage

### Interactive Menu Mode
Launch the application without arguments to view the interactive Rich TUI menu:
```bash
python3 main.py
```
This presents 6 options:
1. **Run Automated Diagnostics & Health Report**: Executes a full health assessment.
2. **Enter Interactive Chat Console**: Launches a stateful conversational session with live tool calling.
3. **Run Autonomous Agentic Reasoning Call**: Executes multi-turn reasoning with live tool execution tracing.
4. **Create Configuration Snapshot Backup**: Manually triggers an immediate full configuration backup snapshot.
5. **View Current Configuration Settings**: Displays active settings in a formatted table.
6. **Exit**: Exits the program.

### CLI Direct Commands & Overrides
You can bypass the menu and directly run specific commands or override settings using command-line arguments:

```bash
# General Syntax
python3 main.py [diagnose | interactive | agentic | config | backup] [options]

# Examples:
# 1. Run automated diagnostics and export an executive HTML dashboard report
python3 main.py diagnose --output report.html

# 2. Run diagnostics against a live firewall with custom port and VDOM
python3 main.py diagnose --ip 10.0.0.1 --port 8443 --vdom CustomVDOM --verify-ssl

# 3. Launch interactive console in offline Mock Mode
python3 main.py interactive --mock

# 4. Run interactive console with Safety Dry Run mode enabled
python3 main.py interactive --enable-write --dry-run

# 5. Create an immediate configuration backup snapshot
python3 main.py backup

# 6. Run autonomous multi-step agentic call with execution tracing
python3 main.py agentic
```

### Available CLI Options

| Flag | Short | Description |
| :--- | :--- | :--- |
| `command` | _Positional_ | Command to execute: `diagnose`, `interactive`, `agentic`, `config`, `backup`. (Default: Interactive Menu). |
| `--json` | `-j` | Output parsed diagnostics result in raw structured JSON (suppresses banner and TUI prints). |
| `--mock` | `-m` | Force offline Mock Mode (simulated responses). |
| `--enable-write` | `-w` | Enable active write/mitigation actions (disabled by default for safety). |
| `--dry-run` | `-d` | Simulate write actions safely without modifying firewall configuration. |
| `--output` | `-o` | Export diagnostic report to a standalone HTML (`.html`), Markdown (`.md`), or JSON (`.json`) file. |
| `--ip` | `-i` | Override the target FortiGate IP address. |
| `--token` | `-t` | Override the FortiGate REST API Access Token. |
| `--port` | `-p` | Override the target connection port (default: `443`). |
| `--vdom` | `-v` | Override target Virtual Domain (default: `"root"`). |
| `--verify-ssl` | `-k` | Enable HTTPS certificate verification. |
| `--ca-bundle` | `-c` | Path to custom CA certificate bundle file (enables certificate verification). |
| `--model` | _None_ | Override Gemini model (e.g. `gemini-2.5-flash`, `gemini-2.5-pro`, `gemini-3.5-flash`, `gemini-pro-latest`). |
| `--help` | `-h` | Show CLI help message and exit. |

---

## Gemini Model Selection & Precision Advisory

The agent supports selecting different Gemini models based on your operational requirements:
* **Flash Series (`gemini-2.5-flash`, `gemini-3.5-flash`)**: High-speed, low-latency execution ideal for routine diagnostics, automated cron polling, and CI/CD pipelines.
* **Pro & Precision Series (`gemini-2.5-pro`, `gemini-3.1-pro-preview`, `gemini-pro-latest`)**: Recommended for complex multi-tier root-cause analysis, dynamic routing correlation, and multi-step autonomous troubleshooting.

Override the model via `.env` (`GEMINI_MODEL=gemini-2.5-pro`) or CLI flag (`--model gemini-2.5-pro`).

---

## Active Mitigation & Safety System

By default, the AI Agent operates in a strictly **Read-Only** monitoring mode to prevent accidental network configuration changes.

### 1. Enabling Write Actions
To allow the agent to execute remediation tools (`reset_vpn_tunnel`, `toggle_interface`, `add_static_route`, `toggle_firewall_policy`, `disconnect_ssl_vpn_user`), enable write actions via `.env`:
```ini
ENABLE_WRITE_ACTIONS=True
```
Or via the CLI flag:
```bash
python3 main.py --enable-write
```

### 2. Confirmation Prompts
* **Interactive Terminal Sessions**: Even if write actions are enabled, the agent **always prompts for confirmation** before executing any write/mitigation operation. You will see a warning panel detailing the operation and target parameters and must select `y/N` to proceed.
* **Scripted/JSON Pipeline Sessions**: If running non-interactively (e.g. `--json`), the agent executes actions without terminal prompting, provided `ENABLE_WRITE_ACTIONS=True`.

### 3. FortiOS REST API Permission Handling
If write actions are enabled in the agent but your FortiGate API token is restricted to a **Read-Only** profile in FortiOS, the firewall returns `403 Forbidden` errors. The AI agent catches these permission errors, reports them clearly, and generates the exact FortiOS CLI commands for manual execution.

---

## Structured JSON Output & Automation

For automated scripting, monitoring pipelines, SIEM ingest, and alerting (e.g., Slack webhooks, PagerDuty, or cron jobs), run the agent with `--json` / `-j`. This runs silently and outputs a structured JSON object validated against a Pydantic schema (`DiagnosticReport`):

```bash
python3 main.py --json --mock | jq .
```

### Example JSON Output
```json
{
  "hostname": "FG-HQ-Primary",
  "overall_health": "degraded",
  "findings": [
    {
      "category": "interfaces",
      "status": "warning",
      "summary": "Backup WAN interface 'port2' is Down",
      "details": "Interface 'port2' is configured but reports status 'down' (Link Down)."
    },
    {
      "category": "vpn",
      "status": "critical",
      "summary": "VPN tunnel 'Branch-2-VPN' is disconnected",
      "details": "IPsec phase 1/2 are down. Remote gateway: 198.51.100.50. Uptime: 0s."
    }
  ],
  "troubleshooting_steps": [
    "Verify layer 1 physical connection on port2.",
    "Check Pre-Shared Key (PSK) settings for VPN tunnel 'Branch-2-VPN' on FortiGate and remote gateway.",
    "Run CLI command: 'diagnose vpn ike gateway list name Branch-2-VPN'"
  ]
}
```

### Schema Field Enumeration
* `overall_health`: `"healthy"` | `"degraded"` | `"critical"`
* `findings[].category`: `"system"` | `"resources"` | `"interfaces"` | `"vpn"` | `"routing"`
* `findings[].status`: `"ok"` | `"warning"` | `"critical"`
* `troubleshooting_steps`: Array of actionable CLI commands and remediation steps.

---

## Testing & Quality Assurance

The repository includes a comprehensive unit and integration test suite in `tests/test_agent_reasoning.py`.

### Running Tests
```bash
# Run all unit and integration tests
python3 -m unittest discover -s tests

# Run specific test file with verbose output
python3 -m unittest -v tests/test_agent_reasoning.py
```

### Test Coverage Highlights
* **VDOM Injection**: Verifies that `vdom` parameters are automatically appended to all REST API queries.
* **HTTP 429 Rate Limiting & Retry**: Validates exponential backoff retries using Tenacity when API rate limits are encountered.
* **Permission Enforcement**: Asserts that write operations throw `PermissionError` when `ENABLE_WRITE_ACTIONS=False`.
* **Mock Telemetry Validation**: Tests the response structures for SD-WAN SLA metrics, HA cluster sync, VDOM listings, and policy toggles.
* **AI Dynamic Routing Root-Cause Reasoning**: An integration test that validates Gemini's ability to correlate an inactive BGP peer (`Active` state) with a blocking firewall security policy (denying TCP port 179) and generate correct remediation recommendations.

---

## Project Structure

```
.
├── agent.py                 # Gemini AI agent integration, tool definitions, and reasoning loops
├── config.py                # Centralized configuration loader and status printer
├── fortigate_client.py      # FortiOS REST API client, tenacity retries, and mock engine
├── main.py                  # CLI driver, argument parser, TUI banner, and interactive loop
├── requirements.txt         # Python package dependencies
├── .env.template            # Environment variables configuration template
├── .env                     # Local environment configuration (git-ignored)
├── Dockerfile               # Production container image definition
├── docker-compose.yml       # Docker Compose service orchestration
├── fortigate-ai-agent.1     # Linux manual page (man page)
├── fortigate_agent.log      # Persistent audit log file
├── tests/
│   └── test_agent_reasoning.py  # Unit tests and multi-step reasoning integration tests
└── LICENSE                  # MIT License
```

---

## Containerization & Deployment

You can build and deploy the AI agent inside an isolated Docker container.

### 1. Build and Run via Docker CLI
Build the Docker image:
```bash
docker build -t fortigate-ai-agent .
```

Run a diagnostics check (inheriting local `.env` configuration):
```bash
docker run --rm --env-file .env -v "$(pwd)/fortigate_agent.log:/app/fortigate_agent.log" fortigate-ai-agent diagnose
```

Run silent JSON diagnostics (ideal for cron jobs):
```bash
docker run --rm --env-file .env fortigate-ai-agent --json
```

### 2. Deploy via Docker Compose
```bash
# Build and run the default automated diagnostics
docker-compose up --build

# Run an interactive session in Docker
docker-compose run --rm agent interactive
```

---

## Linux Manual Page (Man Page)

The repository provides a formatted Unix/Linux manual page:
```bash
# View the manual page locally
man ./fortigate-ai-agent.1

# (Optional) Install system-wide
sudo cp fortigate-ai-agent.1 /usr/local/share/man/man1/
sudo mandb
man fortigate-ai-agent
```

---

## Log Auditing & Resilience

All internal API requests, parameters, status codes, and AI tool invocations are recorded to:
`fortigate_agent.log`

This log captures:
* Exact request URLs, parameters, and SSL certificate verification paths.
* Rate-limiting (HTTP 429) events and Tenacity exponential backoff retries.
* AI function-calling reasoning traces and remediation tool executions.

---

## References & Documentation

### Fortinet & FortiOS Resources
- [Fortinet Document Library](https://docs.fortinet.com/) — Official FortiOS administration, configuration, and architecture guides.
- [FortiOS REST API Reference (v7.0 - v7.6+)](https://docs.fortinet.com/document/fortigate/7.4.0/rest-api-reference) — FortiOS REST API CMDB and Monitor endpoint specifications.
- [Fortinet Developer Network (FNDN)](https://fndn.fortinet.net/) — Developer resources, schemas, and API documentation for Fortinet solutions.
- [Fortinet FortiGate Best Practices](https://docs.fortinet.com/document/fortigate/7.4.0/best-practices) — Hardening, high availability, and security guidelines.

### Google Gemini & SDK Documentation
- [Google GenAI Python SDK (`google-genai`)](https://github.com/googleapis/python-genai) — Next-generation Python SDK for Gemini models.
- [Google AI Studio](https://aistudio.google.com/) — Developer console for API key provisioning and prompt engineering.
- [Gemini Function Calling Guide](https://ai.google.dev/gemini-api/docs/function-calling) — Architecture specifications for structured tool calling and schema validation.

### Networking & Security RFC Standards
- [RFC 4271](https://datatracker.ietf.org/doc/html/rfc4271) — A Border Gateway Protocol 4 (BGP-4).
- [RFC 2328](https://datatracker.ietf.org/doc/html/rfc2328) — OSPF Version 2.
- [RFC 4301](https://datatracker.ietf.org/doc/html/rfc4301) — Security Architecture for the Internet Protocol (IPsec).
- [RFC 826](https://datatracker.ietf.org/doc/html/rfc826) — Ethernet Address Resolution Protocol (ARP).
- [RFC 2131](https://datatracker.ietf.org/doc/html/rfc2131) — Dynamic Host Configuration Protocol (DHCP).

---

## License

This project is licensed under the MIT License. See the LICENSE file for details.



