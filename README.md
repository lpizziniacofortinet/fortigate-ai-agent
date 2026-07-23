# FortiGate AI Operations & Diagnostics Agent

A basic AI agent written in Python that connects to a FortiGate firewall's REST API using the modern **`google-genai`** SDK. The agent is equipped with custom tools (API functions) that enable it to dynamically retrieve and inspect device status, resource utilization, network interfaces, VPN tunnel connectivity (both IPsec and SSL-VPN), IPv4 routing tables, and system event logs. 

It provides two operations modes:
1. **Automated Diagnostics**: Gathers all diagnostics data, passes it to the AI agent, and generates a structured markdown-based health assessment and troubleshooting report.
2. **Interactive Console**: A stateful chat session where you can ask arbitrary questions about the FortiGate, and the AI agent automatically decides which API tools to invoke in the background to respond to you.

It also features a high-fidelity **Mock Mode** for offline testing and demonstration purposes.

---

## Architecture & Endpoints Used

The agent calls the following standard FortiOS API paths to gather details:
- **System Status**: `GET /api/v2/monitor/system/status` (falls back to config `GET /api/v2/cmdb/system/global` if restricted)
- **System Resources**: `GET /api/v2/monitor/system/resource/usage` (CPU, memory, session count)
- **Network Interfaces**: `GET /api/v2/monitor/system/interface` (status, speed, duplex, IP, and traffic counts)
- **VPN Tunnels**: `GET /api/v2/monitor/vpn/ipsec` and `GET /api/v2/monitor/vpn/ssl` (IPsec tunnel status and SSL-VPN active user sessions)
- **Routing Table**: `GET /api/v2/monitor/router/ipv4` (active IPv4 routing table entries)
- **BGP Dynamic Routing**: `GET /api/v2/monitor/router/bgp/neighbors` (BGP peer status)
- **OSPF Dynamic Routing**: `GET /api/v2/monitor/router/ospf/neighbors` (falls back to `/monitor/router/ospf` depending on version)
- **Firewall Policies**: `GET /api/v2/cmdb/firewall/policy` (configured firewall access control entries)
- **Event Logs**: `GET /api/v2/monitor/log/disk/messages` (falls back to `GET /api/v2/monitor/log/current` depending on firmware version)

For authentication, the script utilizes the secure **`Authorization: Bearer <API-TOKEN>`** HTTP header, conforming to modern FortiOS standards (v7.4.x / v7.6.x+).

---

## Installation & Setup

### 1. Prerequisites
- Python 3.10 or higher
- A Google Gemini API key (you can obtain one from [Google AI Studio](https://aistudio.google.com/))

### 2. Install Dependencies
Clone/navigate to the directory and install requirements:
```bash
pip install -r requirements.txt
```

### 3. Configure the Environment
Copy the configuration template:
```bash
cp .env.template .env
```
Open `.env` and fill in your details:
```ini
# Gemini API Key (Required for AI Agent operations)
GEMINI_API_KEY=your_gemini_api_key_here

# FortiGate Connection Details
# Leave empty to automatically use high-fidelity MOCK MODE
FORTIGATE_IP=192.168.1.99
FORTIGATE_TOKEN=your_fortigate_api_token_here
FORTIGATE_PORT=443
USE_SSL=True
VERIFY_SSL=False

# Set to True if you want to force simulation of the FortiGate
MOCK_MODE=False
```

*Note: If no IP and Token are provided, the script automatically defaults to Mock Mode, allowing you to test-drive the agent offline.*

---

## Generating an API Token on FortiGate

If you are running in Live Mode, you must generate an API Key on your FortiGate firewall:
1. Log into your FortiGate GUI.
2. Go to **System > Administrators**.
3. Click **Create New > REST API Admin**.
4. Set a username (e.g., `ai_operator`).
5. Choose an admin profile (e.g., `read-only` or custom profile with Read permissions on system configuration, router, and VPN monitoring).
6. Configure **Trusted Hosts** (highly recommended for security, restricting access to your local machine IP).
7. Save. A pop-up will display your **API Key**. Copy it immediately as it will not be shown again.

---

## Usage

You can launch the main CLI driver directly to view the interactive selection menu:
```bash
python3 main.py
```

### Command-Line Arguments & Overrides
You can bypass the menu and directly target specific environments or configurations using CLI flags:
```bash
# General Syntax
python3 main.py [diagnose | interactive | config] [options]

# Direct Overrides Examples:
# Run diagnostics on a specific IP, port, and VDOM with SSL verification enabled
python3 main.py diagnose --ip 10.0.0.1 --port 8443 --vdom CustomVDOM --verify-ssl

# Enter the interactive AI console forcing offline mock mode simulation
python3 main.py interactive --mock
```

Available options:
* `command` (positional): Command to run directly. Choices: `diagnose`, `interactive`, `config`.
* `--json`, `-j`: Output parsed diagnostics result in raw JSON format (suppresses standard stdout prints, useful for scripting).
* `--mock`, `-m`: Force Mock Mode (simulated responses).
* `--enable-write`, `-w`: Enable active write/mitigation actions (disabled by default for safety).
* `--ip`, `-i`: Override the target FortiGate IP address.
* `--token`, `-t`: Override the FortiGate API Access Token.
* `--port`, `-p`: Override the target connection port (default: `443`).
* `--vdom`, `-v`: Override the target VDOM configuration (default: `"root"`).
* `--verify-ssl`, `-k`: Enable SSL certificate checks.
* `--ca-bundle`, `-c`: Path to a custom CA certificate bundle file (enables certificate verification).

---

## Active Mitigation & Safety Disclaimer

By default, the AI Agent operates in a strictly **Read-Only** monitoring mode to prevent accidental configuration errors.

### Enabling Write Actions
To allow the agent to execute active remediations (such as restarting VPN tunnels, bouncing network interfaces, or adding static routes), you must explicitly enable write actions using one of two methods:
1. In your `.env` file:
   ```ini
   ENABLE_WRITE_ACTIONS=True
   ```
2. Via the CLI flag:
   ```bash
   python3 main.py --enable-write
   ```

### Safety & Confirmation Prompts
* **Interactive Terminal Sessions**: Even if write actions are enabled, the agent will **always prompt you for confirmation** before executing any write/mitigation operation. You will see a warning panel detailing the action and must select `y/N` to authorize.
* **Scripted/JSON Pipeline Sessions**: If running non-interactively (e.g. `--json`), the agent executes actions without terminal prompting, provided `ENABLE_WRITE_ACTIONS` is set to `True`.

### FortiGate REST API Permissions Disclaimer
If write actions are enabled in the agent but your FortiGate API administrator key (Token) is configured with a **Read-Only** profile in the FortiOS GUI, the firewall will return `403 Forbidden` errors. The AI agent will detect these permission failures, report them, and suggest equivalent CLI commands for you to run manually.
To resolve this:
1. Log into your FortiGate GUI.
2. Go to **System > Administrators**.
3. Edit your REST API Administrator profile to grant **Read/Write** permissions on system settings, routing, and VPN configurations.

### 3. Structured JSON Output
For automated scripting and integration (e.g. piping into `jq`, Slack webhooks, or SIEM pipelines), run the agent with the `--json` or `-j` flag. This runs the diagnostics silently and prints a structured JSON response matching a Pydantic schema:
```bash
python3 main.py --json --mock | jq .
```

Example JSON schema returned:
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

---

## Containerization & Deployment

You can build and deploy the AI agent inside an isolated Docker container.

### 1. Build and Run via Docker CLI
Build the Docker image:
```bash
docker build -t fortigate-ai-agent .
```

Run a diagnostics check (inheriting your local `.env` variables):
```bash
docker run --rm --env-file .env -v "$(pwd)/fortigate_agent.log:/app/fortigate_agent.log" fortigate-ai-agent diagnose
```

Run in JSON mode (perfect for automated cron triggers):
```bash
docker run --rm --env-file .env fortigate-ai-agent --json
```

### 2. Deploy via Docker Compose
Build and run the service using `docker-compose`:
```bash
# Build and run the default automated diagnostics command
docker-compose up --build

# Run a specific command
docker-compose run --rm agent interactive
```

---

## Log Auditing

All internal requests, operations, API status codes, and error traces are recorded to:
`fortigate_agent.log`

This log captures:
- Exact request URLs, parameters, and certificate targets.
- Rate-limiting (HTTP 429) details and backoff auto-retry attempts.
- Internal AI agent tool invocations for audit trails.

