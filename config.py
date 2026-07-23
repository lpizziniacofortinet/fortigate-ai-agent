import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists
load_dotenv()

class Config:
    """Configuration class for FortiGate AI Agent."""
    
    # Gemini API settings
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    
    # FortiGate settings
    FORTIGATE_IP = os.getenv("FORTIGATE_IP", "")
    FORTIGATE_TOKEN = os.getenv("FORTIGATE_TOKEN", "")
    FORTIGATE_PORT = int(os.getenv("FORTIGATE_PORT", "443"))
    USE_SSL = os.getenv("USE_SSL", "True").lower() in ("true", "1", "yes")
    VERIFY_SSL = os.getenv("VERIFY_SSL", "False").lower() in ("true", "1", "yes")
    
    FORTIGATE_VDOM = os.getenv("FORTIGATE_VDOM", "root")
    CA_BUNDLE = os.getenv("CA_BUNDLE", "")
    ENABLE_WRITE_ACTIONS = os.getenv("ENABLE_WRITE_ACTIONS", "False").lower() in ("true", "1", "yes")
    
    # Run settings
    # Default to Mock Mode if IP or Token are not provided
    MOCK_MODE = os.getenv("MOCK_MODE", "").lower() in ("true", "1", "yes") or not (FORTIGATE_IP and FORTIGATE_TOKEN)

    @classmethod
    def print_status(cls):
        """Prints the current configuration configuration safely."""
        from rich.console import Console
        from rich.table import Table
        
        console = Console()
        table = Table(title="Agent Configuration")
        table.add_column("Setting", style="cyan")
        table.add_column("Value", style="green")
        
        table.add_row("Gemini Model", cls.GEMINI_MODEL)
        table.add_row("Gemini API Key", "Configured (from environment)" if cls.GEMINI_API_KEY else "Missing (Specify GEMINI_API_KEY environment variable)")
        table.add_row("FortiGate IP", cls.FORTIGATE_IP if cls.FORTIGATE_IP else "<Not Configured>")
        table.add_row("FortiGate Port", str(cls.FORTIGATE_PORT))
        table.add_row("Virtual Domain (VDOM)", cls.FORTIGATE_VDOM)
        table.add_row("Use SSL/HTTPS", str(cls.USE_SSL))
        table.add_row("Verify SSL Cert", str(cls.VERIFY_SSL))
        table.add_row("CA Bundle Path", cls.CA_BUNDLE if cls.CA_BUNDLE else "None (default verification)")
        table.add_row("Write Actions (Read-Write)", "ENABLED (Agent can modify configs)" if cls.ENABLE_WRITE_ACTIONS else "DISABLED (Read-Only Safe Mode)")
        table.add_row("Running Mode", "MOCK MODE (Simulating FortiGate)" if cls.MOCK_MODE else "LIVE MODE (Connecting to FortiGate)")
        
        console.print(table)
