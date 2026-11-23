import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    """Configuration class for FortiGate AI Agent."""
    
    # Gemini API settings (highest-capability flagship defaults)
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-4-neon")
    ORCHESTRATOR_MODEL = os.getenv("ORCHESTRATOR_MODEL", "gemini-4-carbon")
    SPECIALIST_MODEL = os.getenv("SPECIALIST_MODEL", GEMINI_MODEL)
    # Gemini 4 reasoning depth (MINIMAL, LOW, MEDIUM, HIGH, XHIGH); temperature is omitted on Gemini 4
    GEMINI_THINKING_LEVEL = os.getenv("GEMINI_THINKING_LEVEL", "MEDIUM").strip().upper()
    ORCHESTRATOR_THINKING_LEVEL = os.getenv("ORCHESTRATOR_THINKING_LEVEL", "HIGH").strip().upper()
    SPECIALIST_THINKING_LEVEL = os.getenv("SPECIALIST_THINKING_LEVEL", GEMINI_THINKING_LEVEL).strip().upper()
    
    # FortiGate settings
    FORTIGATE_IP = os.getenv("FORTIGATE_IP", "")
    FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN", "")
    FORTIGATE_PORT = int(os.getenv("FORTIGATE_PORT", "443"))
    USE_SSL = os.getenv("USE_SSL", "True").lower() in ("true", "1", "yes")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "True").lower() in ("true", "1", "yes")
    
    FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root")
    CA_BUNDLE = os.getenv("CA_BUNDLE", "")
    ENABLE_WRITE_ACTIONS = os.getenv("ENABLE_WRITE_ACTIONS", "False").lower() in ("true", "1", "yes")
    DRY_RUN = os.getenv("DRY_RUN", "False").lower() in ("true", "1", "yes")
    BACKUP_BEFORE_WRITE = os.getenv("BACKUP_BEFORE_WRITE", "True").lower() in ("true", "1", "yes")
    OUTPUT_FILE = os.getenv("OUTPUT_FILE", "")
    
    # Run settings
    # Default to Mock Mode if IP or Token are not provided
    MOCK_MODE = os.getenv("MOCK_MODE", "").lower() in ("true", "1", "yes") or not (FORTIGATE_IP and FORTIGATE_TOKEN)

    @classmethod
    def print_status(cls):
        """Prints the current configuration safely."""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        table = Table(title="Agent Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Gemini Model", cls.GEMINI_MODEL)
        table.add_row("Thinking Level", f"{cls.GEMINI_THINKING_LEVEL} (Orchestrator: {cls.ORCHESTRATOR_THINKING_LEVEL})")
        table.add_row("Gemini API Key", "Configured (from environment)" if cls.GEMINI_API_KEY else "Missing (Specify GEMINI_API_KEY environment variable)")
        table.add_row("FortiGate IP", cls.FORTIGATE_IP if cls.FORTIGATE_IP else "<Not Configured>")
        table.add_row("FortiGate Port", str(cls.FORTIGATE_PORT))
        table.add_row("Virtual Domain (VDOM)", cls.FORTIGATE_VDOM)
        table.add_row("Use SSL/HTTPS", str(cls.USE_SSL))
        table.add_row("Verify SSL Cert", str(cls.VERIFY_SSL))
        table.add_row("CA Bundle Path", cls.CA_BUNDLE if cls.CA_BUNDLE else "None (default verification)")
        table.add_row("Write Actions (Read-Write)", "ENABLED (Agent can modify configs)" if cls.ENABLE_WRITE_ACTIONS else "DISABLED (Read-Only Safe Mode)")
        table.add_row("Dry Run Mode", "ENABLED (Simulate write actions without modifying firewall)" if cls.DRY_RUN else "DISABLED (Direct execution)")
        table.add_row("Pre-Change Auto-Backup", "ENABLED (Save config snapshot before write)" if cls.BACKUP_BEFORE_WRITE else "DISABLED")
        table.add_row("Running Mode", "MOCK MODE (Simulating FortiGate)" if cls.MOCK_MODE else "LIVE MODE (Connecting to FortiGate)")
        if cls.OUTPUT_FILE:
            table.add_row("Report Export Target", cls.OUTPUT_FILE)
        
        console.print(table)
