import os
import logging
import urllib3
import requests
from datetime import datetime
from typing import Dict, Any, List, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type

# Suppress insecure request warnings for self-signed certificates (common in local setups)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger("FortiGateClient")

class FortiGateClient:
    """
    A client for interacting with the FortiOS REST API.
    Supports real connection to FortiGate as well as a high-fidelity Mock Mode
    for development and offline testing.
    """
    def __init__(
        self,
        host: str,
        token: str,
        port: int = 443,
        use_ssl: bool = True,
        verify_ssl: bool = False,
        vdom: str = "root",
        ca_bundle: str = "",
        enable_write_actions: bool = False,
        dry_run: bool = False,
        backup_before_write: bool = True,
        mock: bool = False
    ):
        self.host = host.strip()
        self.token = token.strip()
        self.port = port
        self.use_ssl = use_ssl
        self.verify_ssl = verify_ssl
        self.vdom = vdom.strip() if vdom else "root"
        self.ca_bundle = ca_bundle.strip() if ca_bundle else ""
        self.enable_write_actions = enable_write_actions
        self.dry_run = dry_run
        self.backup_before_write = backup_before_write
        self.mock = mock

        # Set up base URL
        protocol = "https" if use_ssl else "http"
        self.base_url = f"{protocol}://{self.host}:{self.port}/api/v2"

        # Set up headers
        self.headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception_type((requests.exceptions.RequestException, ConnectionError)),
        reraise=True
    )
    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Helper to send GET requests to the FortiGate API with automatic retry."""
        if self.mock:
            raise NotImplementedError("Direct REST API call not supported in mock mode.")

        url = f"{self.base_url}{path}"
        
        # Ensure vdom is added to the parameters if defined
        req_params = params.copy() if params else {}
        if self.vdom and "vdom" not in req_params:
            req_params["vdom"] = self.vdom

        # Determine SSL verification path (CA Bundle or boolean)
        verify_path = self.verify_ssl
        if self.use_ssl and self.ca_bundle:
            verify_path = self.ca_bundle

        try:
            logger.info(f"Sending GET request to {url} (params: {req_params}, verify: {verify_path})")
            response = requests.get(
                url,
                headers=self.headers,
                params=req_params,
                verify=verify_path,
                timeout=10
            )
            # Explicitly check for rate limiting (HTTP 429) to trigger retry
            if response.status_code == 429:
                logger.warning("API rate limit hit (429). Retrying...")
                response.raise_for_status()
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling endpoint {url}: {e}")
            raise ConnectionError(f"Failed to communicate with FortiGate at {self.host}: {e}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception_type((requests.exceptions.RequestException, ConnectionError)),
        reraise=True
    )
    def _put(self, path: str, json_data: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Helper to send PUT requests to the FortiGate API."""
        if not self.enable_write_actions:
            raise PermissionError(
                "Write/Mitigation actions are currently disabled. Enable ENABLE_WRITE_ACTIONS in your config to proceed."
            )

        if self.mock:
            raise NotImplementedError("Direct REST API call not supported in mock mode.")

        url = f"{self.base_url}{path}"
        req_params = params.copy() if params else {}
        if self.vdom and "vdom" not in req_params:
            req_params["vdom"] = self.vdom

        verify_path = self.verify_ssl
        if self.use_ssl and self.ca_bundle:
            verify_path = self.ca_bundle

        try:
            logger.info(f"Sending PUT request to {url} (params: {req_params}, verify: {verify_path})")
            response = requests.put(
                url,
                headers=self.headers,
                params=req_params,
                json=json_data,
                verify=verify_path,
                timeout=10
            )
            if response.status_code == 429:
                logger.warning("API rate limit hit (429). Retrying...")
                response.raise_for_status()
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling endpoint {url}: {e}")
            raise ConnectionError(f"Failed to modify FortiGate configuration at {self.host}: {e}")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=4),
        retry=retry_if_exception_type((requests.exceptions.RequestException, ConnectionError)),
        reraise=True
    )
    def _post(self, path: str, json_data: Dict[str, Any], params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Helper to send POST requests to the FortiGate API."""
        if not self.enable_write_actions:
            raise PermissionError(
                "Write/Mitigation actions are currently disabled. Enable ENABLE_WRITE_ACTIONS in your config to proceed."
            )

        if self.mock:
            raise NotImplementedError("Direct REST API call not supported in mock mode.")

        url = f"{self.base_url}{path}"
        req_params = params.copy() if params else {}
        if self.vdom and "vdom" not in req_params:
            req_params["vdom"] = self.vdom

        verify_path = self.verify_ssl
        if self.use_ssl and self.ca_bundle:
            verify_path = self.ca_bundle

        try:
            logger.info(f"Sending POST request to {url} (params: {req_params}, verify: {verify_path})")
            response = requests.post(
                url,
                headers=self.headers,
                params=req_params,
                json=json_data,
                verify=verify_path,
                timeout=10
            )
            if response.status_code == 429:
                logger.warning("API rate limit hit (429). Retrying...")
                response.raise_for_status()
                
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error calling endpoint {url}: {e}")
            raise ConnectionError(f"Failed to execute action on FortiGate at {self.host}: {e}")

    def get_system_status(self) -> Dict[str, Any]:
        """Retrieves system status including hostname, version, serial number, and uptime."""
        if self.mock:
            return {
                "status": "success",
                "vdom": "root",
                "results": {
                    "hostname": "FG-HQ-Primary",
                    "serial": "FGT60E3G18012345",
                    "version": "v7.4.2",
                    "build": 2555,
                    "branch": 2555,
                    "os": "FortiOS",
                    "uptime": 104523,  # seconds (approx 1.2 days)
                    "ha_mode": "active-passive",
                    "ha_role": "master",
                    "operation_mode": "nat",
                    "vdom_enabled": False,
                    "license": {
                        "status": "valid",
                        "expires": "2027-12-31"
                    }
                }
            }

        try:
            # We first try monitor/system/status
            resp = self._get("/monitor/system/status")
            if isinstance(resp, dict) and isinstance(resp.get("results"), dict):
                res_dict = resp["results"]
                if "version" not in res_dict and "version" in resp:
                    res_dict["version"] = resp["version"]
                if "serial" not in res_dict and "serial" in resp:
                    res_dict["serial"] = resp["serial"]
                if "build" not in res_dict and "build" in resp:
                    res_dict["build"] = resp["build"]
            return resp
        except Exception as e:
            logger.warning(f"Could not retrieve monitor/system/status, trying cmdb fallback: {e}")
            # Fallback to cmdb global config to extract details
            try:
                global_cfg = self._get("/cmdb/system/global")
                return {
                    "status": "success",
                    "results": global_cfg.get("results", {})
                }
            except Exception as inner_e:
                raise ConnectionError(f"Could not retrieve system status: {inner_e}")

    def get_system_resources(self) -> Dict[str, Any]:
        """Retrieves CPU, Memory, and Session resources usage."""
        if self.mock:
            return {
                "status": "success",
                "results": {
                    "cpu": 12.5,
                    "memory": 45.8,
                    "session": 245,
                    "max_session": 100000,
                    "disk": 22.1,
                    "set_mem": 8192,
                    "set_cpu": 4
                }
            }

        try:
            return self._get("/monitor/system/resource/usage")
        except Exception as e:
            logger.warning(f"Failed to fetch resource usage directly: {e}")
            # Try alternate endpoint
            return self._get("/monitor/system/resource")

    def get_interfaces(self) -> Dict[str, Any]:
        """Retrieves statistics and status for all interfaces."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "name": "port1",
                        "status": "up",
                        "ip": "198.51.100.2/24",
                        "speed": 1000,
                        "duplex": "full",
                        "rx_bytes": 5798205432,
                        "tx_bytes": 12984210492,
                        "rx_packets": 4820392,
                        "tx_packets": 9284021,
                        "description": "WAN 1 Connection (ISP-A)"
                    },
                    {
                        "name": "port2",
                        "status": "down",
                        "ip": "0.0.0.0/0",
                        "speed": 0,
                        "duplex": "unknown",
                        "rx_bytes": 0,
                        "tx_bytes": 0,
                        "rx_packets": 0,
                        "tx_packets": 0,
                        "description": "WAN 2 Backup (ISP-B) - LINK DOWN"
                    },
                    {
                        "name": "port3",
                        "status": "up",
                        "ip": "192.168.1.1/24",
                        "speed": 1000,
                        "duplex": "full",
                        "rx_bytes": 86102938102,
                        "tx_bytes": 49201982039,
                        "rx_packets": 64820310,
                        "tx_packets": 32840921,
                        "description": "Corporate LAN Switch"
                    },
                    {
                        "name": "dmz",
                        "status": "up",
                        "ip": "10.0.1.1/24",
                        "speed": 100,
                        "duplex": "full",
                        "rx_bytes": 128948201,
                        "tx_bytes": 209849201,
                        "rx_packets": 89201,
                        "tx_packets": 142019,
                        "description": "DMZ Servers Zone"
                    }
                ]
            }

        return self._get("/monitor/system/interface")

    def get_vpn_status(self) -> Dict[str, Any]:
        """Retrieves VPN tunnel status including IPsec and SSL-VPN details."""
        if self.mock:
            return {
                "status": "success",
                "results": {
                    "ipsec": [
                        {
                            "name": "AWS-Transit",
                            "status": "up",
                            "phase1": "up",
                            "phase2": "up",
                            "remote_gw": "203.0.113.10",
                            "rx_bytes": 45092031,
                            "tx_bytes": 87109204,
                            "incoming_selector": "0.0.0.0/0",
                            "outgoing_selector": "0.0.0.0/0",
                            "duration": 43200
                        },
                        {
                            "name": "Branch-2-VPN",
                            "status": "down",
                            "phase1": "down",
                            "phase2": "down",
                            "remote_gw": "198.51.100.50",
                            "rx_bytes": 0,
                            "tx_bytes": 0,
                            "incoming_selector": "192.168.1.0/24",
                            "outgoing_selector": "192.168.2.0/24",
                            "duration": 0
                        }
                    ],
                    "ssl_vpn": {
                        "active_sessions_count": 3,
                        "sessions": [
                            {
                                "user": "jdoe",
                                "ip": "198.51.100.82",
                                "tunnel_ip": "10.212.134.10",
                                "duration": 7200,
                                "bytes_sent": 1048576,
                                "bytes_received": 2097152
                            },
                            {
                                "user": "asmith",
                                "ip": "198.51.100.95",
                                "tunnel_ip": "10.212.134.11",
                                "duration": 3600,
                                "bytes_sent": 512000,
                                "bytes_received": 1024000
                            },
                            {
                                "user": "admin_test",
                                "ip": "127.0.0.1",
                                "tunnel_ip": "10.212.134.12",
                                "duration": 1500,
                                "bytes_sent": 25600,
                                "bytes_received": 51200
                            }
                        ]
                    }
                }
            }

        vpn_data = {"ipsec": [], "ssl_vpn": {}}

        # Fetch IPsec details
        try:
            ipsec_resp = self._get("/monitor/vpn/ipsec")
            vpn_data["ipsec"] = ipsec_resp.get("results", [])
        except Exception as e:
            logger.warning(f"Could not retrieve IPsec VPN status: {e}")
            vpn_data["ipsec_error"] = str(e)

        # Fetch SSL VPN details
        try:
            ssl_resp = self._get("/monitor/vpn/ssl")
            # The structure for SSL can be under 'results' or direct sessions list.
            results = ssl_resp.get("results", {})
            if isinstance(results, list):
                vpn_data["ssl_vpn"] = {
                    "active_sessions_count": len(results),
                    "sessions": results
                }
            else:
                vpn_data["ssl_vpn"] = results
        except Exception as e:
            logger.warning(f"Could not retrieve SSL VPN status: {e}")
            vpn_data["ssl_vpn_error"] = str(e)

        return {
            "status": "success",
            "results": vpn_data
        }

    def get_routing_table(self) -> Dict[str, Any]:
        """Retrieves the active routing table (IPv4 routing table)."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "destination": "0.0.0.0/0",
                        "gateway": "198.51.100.1",
                        "interface": "port1",
                        "distance": 10,
                        "metric": 0,
                        "type": "static",
                        "active": True
                    },
                    {
                        "destination": "192.168.1.0/24",
                        "gateway": "0.0.0.0",
                        "interface": "port3",
                        "distance": 0,
                        "metric": 0,
                        "type": "connected",
                        "active": True
                    },
                    {
                        "destination": "10.0.1.0/24",
                        "gateway": "0.0.0.0",
                        "interface": "dmz",
                        "distance": 0,
                        "metric": 0,
                        "type": "connected",
                        "active": True
                    },
                    {
                        "destination": "10.50.0.0/16",
                        "gateway": "198.51.100.254",
                        "interface": "port1",
                        "distance": 10,
                        "metric": 0,
                        "type": "static",
                        "active": True
                    },
                    {
                        "destination": "172.16.0.0/12",
                        "gateway": "0.0.0.0",
                        "interface": "AWS-Transit",
                        "distance": 15,
                        "metric": 0,
                        "type": "static",
                        "active": True
                    }
                ]
            }

        return self._get("/monitor/router/ipv4")

    def get_system_logs(self, log_type: str = "event", limit: int = 15) -> Dict[str, Any]:
        """
        Retrieves recent system logs from the FortiGate (defaults to 'event' logs).
        In Mock Mode, retrieves high-fidelity event simulations (e.g. VPN fail, user login).
        """
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "time": "14:10:02",
                        "date": "2026-07-17",
                        "logid": "0101039002",
                        "type": "event",
                        "subtype": "vpn",
                        "level": "warning",
                        "message": "VPN phase 1 connection negotiation failed",
                        "tunnel": "Branch-2-VPN",
                        "remotegw": "198.51.100.50",
                        "reason": "Pre-shared key mismatch"
                    },
                    {
                        "time": "14:15:30",
                        "date": "2026-07-17",
                        "logid": "0102043005",
                        "type": "event",
                        "subtype": "vpn",
                        "level": "information",
                        "message": "SSL-VPN user jdoe logged in successfully",
                        "user": "jdoe",
                        "srcip": "198.51.100.82",
                        "tunnel_ip": "10.212.134.10"
                    },
                    {
                        "time": "14:22:11",
                        "date": "2026-07-17",
                        "logid": "0100021020",
                        "type": "event",
                        "subtype": "system",
                        "level": "notice",
                        "message": "Configuration changed via REST API",
                        "user": "api_operator",
                        "msg": "updated static route to 10.50.0.0/16"
                    },
                    {
                        "time": "14:30:00",
                        "date": "2026-07-17",
                        "logid": "0100022001",
                        "type": "event",
                        "subtype": "system",
                        "level": "information",
                        "message": "Performance statistics: CPU 12.5%, Memory 45.8%, Sessions 245"
                    }
                ][:limit]
            }

        # Try memory log endpoint first, then disk, then current
        for endpoint in ["/monitor/log/memory/messages", "/monitor/log/disk/messages", "/monitor/log/current"]:
            try:
                return self._get(endpoint, params={"type": log_type, "limit": limit})
            except Exception as e:
                logger.warning(f"Could not read from {endpoint}: {e}")
        
        logger.warning("All log endpoints failed. Returning empty log results.")
        return {"status": "warning", "results": [], "message": "Log retrieval not supported or logging is disabled on target FortiGate"}

    def _execute_write_prechecks(self, action_name: str, details: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Validates write permissions, handles dry-run simulation, and triggers pre-change backup."""
        if not self.enable_write_actions:
            raise PermissionError(
                "Write/Mitigation actions are currently disabled. Set ENABLE_WRITE_ACTIONS=True in .env "
                "or use the --enable-write CLI flag, and ensure your API key has write permissions."
            )

        if self.dry_run:
            logger.info(f"[DRY RUN] Simulating {action_name}: {details}")
            return {
                "status": "dry_run",
                "action": action_name,
                "message": f"[DRY RUN - No Changes Made] Would execute '{action_name}' on FortiGate with parameters: {details}",
                "parameters": details
            }

        if self.backup_before_write:
            try:
                backup_res = self.backup_configuration()
                logger.info(f"Pre-change configuration backup created: {backup_res.get('file_path')}")
            except Exception as e:
                logger.warning(f"Could not complete pre-change configuration backup: {e}")

        return None

    def backup_configuration(self, destination_dir: str = ".backups") -> Dict[str, Any]:
        """
        Retrieves a full system configuration snapshot from the FortiGate and saves it locally.
        """
        os.makedirs(destination_dir, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        host_tag = self.host if self.host else "mock_fortigate"
        file_name = f"fortigate_backup_{host_tag}_{timestamp}.conf"
        file_path = os.path.join(destination_dir, file_name)

        if self.mock:
            content = (
                f"# FortiOS Configuration Snapshot (Simulated Backup)\n"
                f"# Hostname: FG-HQ-Primary\n"
                f"# Timestamp: {datetime.now().isoformat()}\n"
                f"# VDOM: {self.vdom}\n"
                f"# Auto-generated before configuration write operation.\n"
                f"config system global\n"
                f"    set hostname \"FG-HQ-Primary\"\n"
                f"end\n"
            )
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            return {
                "status": "success",
                "file_path": file_path,
                "file_name": file_name,
                "message": f"Configuration backup snapshot saved to '{file_path}'.",
                "timestamp": timestamp,
                "scope": "global"
            }

        try:
            resp = self._get("/monitor/system/config/backup", params={"scope": "global"})
            content = resp if isinstance(resp, str) else str(resp)
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            return {
                "status": "success",
                "file_path": file_path,
                "file_name": file_name,
                "message": f"Live configuration backup snapshot saved to '{file_path}'.",
                "timestamp": timestamp,
                "scope": "global"
            }
        except Exception as e:
            logger.error(f"Failed to backup configuration from FortiGate: {e}")
            raise ConnectionError(f"Configuration backup failed: {e}")

    def reset_vpn_tunnel(self, p1_name: str) -> Dict[str, Any]:
        """
        Sends a POST request to reset VPN Phase 1 tunnel statistics.
        This forces Phase 1 negotiations to restart.
        """
        precheck = self._execute_write_prechecks("reset_vpn_tunnel", {"p1_name": p1_name})
        if precheck:
            return precheck

        if self.mock:
            return {
                "status": "success",
                "message": f"[Mock Mode] Successfully triggered reset/flush for VPN tunnel '{p1_name}'."
            }
        
        return self._post("/monitor/vpn/ipsec/tunnel_reset_stats", json_data={"p1name": p1_name})

    def toggle_interface(self, interface_name: str, status: str) -> Dict[str, Any]:
        """
        Toggles the administrative state of a network interface (up or down).
        """
        status = status.strip().lower()
        if status not in ("up", "down"):
            raise ValueError("Status parameter must be 'up' or 'down'.")

        precheck = self._execute_write_prechecks("toggle_interface", {"interface_name": interface_name, "status": status})
        if precheck:
            return precheck

        if self.mock:
            return {
                "status": "success",
                "message": f"[Mock Mode] Successfully set interface '{interface_name}' status to '{status}'."
            }
        
        return self._put(f"/cmdb/system/interface/{interface_name}", json_data={"status": status})

    def add_static_route(self, destination: str, gateway: str, interface: str) -> Dict[str, Any]:
        """
        Configures a static route on the FortiGate CMDB.
        """
        precheck = self._execute_write_prechecks("add_static_route", {
            "destination": destination,
            "gateway": gateway,
            "interface": interface
        })
        if precheck:
            return precheck

        if self.mock:
            return {
                "status": "success",
                "message": f"[Mock Mode] Successfully added static route to '{destination}' via '{gateway}' on '{interface}'."
            }
        
        route_payload = {
            "dst": destination.strip(),
            "gateway": gateway.strip(),
            "device": interface.strip()
        }
        return self._post("/cmdb/router/static", json_data=route_payload)

    def get_bgp_neighbors(self) -> Dict[str, Any]:
        """Retrieves BGP dynamic routing neighbor status details."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "neighbor": "10.255.0.1",
                        "remote_as": 65001,
                        "state": "Established",
                        "uptime": 86400,
                        "messages_received": 14201,
                        "messages_sent": 14190,
                        "routes_received": 15,
                        "routes_advertised": 10
                    },
                    {
                        "neighbor": "10.255.0.2",
                        "remote_as": 65002,
                        "state": "Active",  # Active state means down (trying to establish TCP handshake)
                        "uptime": 0,
                        "messages_received": 0,
                        "messages_sent": 12,
                        "routes_received": 0,
                        "routes_advertised": 0
                    }
                ]
            }

        return self._get("/monitor/router/bgp/neighbors")

    def get_firewall_policies(self) -> Dict[str, Any]:
        """Retrieves configured firewall security policies."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "policyid": 1,
                        "name": "Allow-LAN-to-WAN",
                        "srcintf": [{"name": "port3"}],
                        "dstintf": [{"name": "port1"}],
                        "srcaddr": [{"name": "all"}],
                        "dstaddr": [{"name": "all"}],
                        "action": "accept",
                        "service": [{"name": "ALL"}],
                        "status": "enable"
                    },
                    {
                        "policyid": 5,
                        "name": "Block-BGP-Peers",
                        "srcintf": [{"name": "port1"}],
                        "dstintf": [{"name": "port3"}],
                        "srcaddr": [{"name": "all"}],
                        "dstaddr": [{"name": "all"}],
                        "action": "deny",
                        "service": [{"name": "BGP"}],
                        "status": "enable"
                    }
                ]
            }

        return self._get("/cmdb/firewall/policy")

    def get_ospf_neighbors(self) -> Dict[str, Any]:
        """Retrieves OSPF dynamic routing neighbor status details."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "neighbor_id": "172.16.100.1",
                        "priority": 1,
                        "state": "Full",  # Full state is the correct up state for OSPF adjacency
                        "state_changes": 2,
                        "ip": "172.16.100.1",
                        "interface": "dmz",
                        "options": "0x02",
                        "dead_time": 35
                    },
                    {
                        "neighbor_id": "172.16.100.2",
                        "priority": 1,
                        "state": "Init",  # Init/Down state means adjacency is down
                        "state_changes": 15,
                        "ip": "172.16.100.2",
                        "interface": "port3",
                        "options": "0x00",
                        "dead_time": 0
                    }
                ]
            }

        try:
            return self._get("/monitor/router/ospf/neighbors")
        except Exception as e:
            logger.warning(f"Failed to fetch OSPF neighbors via /monitor/router/ospf/neighbors: {e}. Trying fallback...")
            try:
                return self._get("/monitor/router/ospf")
            except Exception as inner_e:
                raise ConnectionError(f"Could not retrieve OSPF neighbors: {inner_e}")

    def get_sdwan_status(self) -> Dict[str, Any]:
        """Retrieves SD-WAN member status, health-check performance SLA metrics (latency, loss, jitter)."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "interface": "port1",
                        "status": "up",
                        "health_check": "ISP-A-SLA",
                        "latency_ms": 14.2,
                        "jitter_ms": 1.8,
                        "packet_loss_pct": 0.0,
                        "sla_status": "pass"
                    },
                    {
                        "interface": "port2",
                        "status": "down",
                        "health_check": "ISP-B-SLA",
                        "latency_ms": 0.0,
                        "jitter_ms": 0.0,
                        "packet_loss_pct": 100.0,
                        "sla_status": "fail"
                    }
                ]
            }

        try:
            return self._get("/monitor/virtual-wan/health-check")
        except Exception as e:
            logger.warning(f"Could not fetch SD-WAN health check: {e}. Trying member status fallback...")
            try:
                return self._get("/monitor/virtual-wan/members")
            except Exception as inner_e:
                logger.info(f"SD-WAN monitoring endpoints unavailable or not configured: {inner_e}")
                return {"status": "not_configured", "results": [], "message": "SD-WAN is not configured or endpoint is restricted."}

    def get_ha_status(self) -> Dict[str, Any]:
        """Retrieves High Availability (HA) cluster member status, sync state, and checksums."""
        if self.mock:
            return {
                "status": "success",
                "results": {
                    "mode": "active-passive",
                    "group_id": 0,
                    "sync_status": "in-sync",
                    "checksum_match": True,
                    "members": [
                        {
                            "serial": "FGT60E3G18012345",
                            "hostname": "FG-HQ-Primary",
                            "role": "master",
                            "priority": 200,
                            "cpu": 12.5,
                            "memory": 45.8,
                            "status": "ok"
                        },
                        {
                            "serial": "FGT60E3G18054321",
                            "hostname": "FG-HQ-Secondary",
                            "role": "slave",
                            "priority": 100,
                            "cpu": 8.1,
                            "memory": 42.0,
                            "status": "ok"
                        }
                    ]
                }
            }

        try:
            return self._get("/monitor/system/ha-checksum")
        except Exception as e:
            logger.warning(f"Could not fetch HA checksums: {e}. Trying /monitor/system/ha fallback...")
            try:
                return self._get("/monitor/system/ha")
            except Exception as inner_e:
                logger.info(f"HA cluster monitoring endpoints unavailable (likely standalone unit): {inner_e}")
                return {
                    "status": "standalone",
                    "results": {
                        "mode": "standalone",
                        "sync_status": "standalone",
                        "members": []
                    },
                    "message": "Device operating in standalone mode (HA not enabled)."
                }

    def toggle_firewall_policy(self, policy_id: int, status: str) -> Dict[str, Any]:
        """
        Toggles the administrative state of a firewall policy ('enable' or 'disable').
        """
        status = status.strip().lower()
        if status not in ("enable", "disable"):
            raise ValueError("Status parameter must be 'enable' or 'disable'.")

        precheck = self._execute_write_prechecks("toggle_firewall_policy", {"policy_id": policy_id, "status": status})
        if precheck:
            return precheck

        if self.mock:
            return {
                "status": "success",
                "message": f"[Mock Mode] Successfully set firewall policy ID '{policy_id}' status to '{status}'."
            }

        return self._put(f"/cmdb/firewall/policy/{policy_id}", json_data={"status": status})

    def disconnect_ssl_vpn_user(self, username: str) -> Dict[str, Any]:
        """
        Disconnects an active SSL-VPN user session.
        """
        username = username.strip()
        if not username:
            raise ValueError("Username parameter must not be empty.")

        precheck = self._execute_write_prechecks("disconnect_ssl_vpn_user", {"username": username})
        if precheck:
            return precheck

        if self.mock:
            return {
                "status": "success",
                "message": f"[Mock Mode] Successfully disconnected SSL-VPN session for user '{username}'."
            }

        return self._post("/monitor/vpn/ssl/disconnect", json_data={"user": username})

    def get_vdom_list(self) -> Dict[str, Any]:
        """Retrieves the list of configured Virtual Domains (VDOMs) on the FortiGate."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {"name": "root", "short_name": "root", "vcluster_id": 1},
                    {"name": "DMZ-VDOM", "short_name": "dmz_vdom", "vcluster_id": 1},
                    {"name": "Guest-VDOM", "short_name": "guest_vdom", "vcluster_id": 1}
                ]
            }

        return self._get("/cmdb/system/vdom")

    def get_arp_table(self) -> Dict[str, Any]:
        """Retrieves the active IPv4 ARP address resolution table."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {"ip": "198.51.100.1", "mac": "00:09:0f:aa:bb:01", "interface": "port1", "state": "reachable"},
                    {"ip": "198.51.100.254", "mac": "00:09:0f:aa:bb:fe", "interface": "port1", "state": "reachable"},
                    {"ip": "192.168.1.100", "mac": "f4:8e:38:12:34:56", "interface": "port3", "state": "reachable"},
                    {"ip": "10.0.1.50", "mac": "52:54:00:12:34:56", "interface": "dmz", "state": "reachable"}
                ]
            }

        try:
            return self._get("/monitor/network/arp")
        except Exception as e:
            logger.warning(f"Failed to fetch ARP table via /monitor/network/arp: {e}. Trying fallback...")
            return self._get("/monitor/system/arp")

    def get_dhcp_leases(self) -> Dict[str, Any]:
        """Retrieves active DHCP client lease assignments and reservations."""
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {"ip": "192.168.1.100", "mac": "f4:8e:38:12:34:56", "hostname": "Workstation-Fin-01", "interface": "port3", "lease_expire": 86400, "status": "active"},
                    {"ip": "192.168.1.101", "mac": "f4:8e:38:98:76:54", "hostname": "Printer-HQ-Color", "interface": "port3", "lease_expire": 43200, "status": "active"},
                    {"ip": "10.0.1.50", "mac": "52:54:00:12:34:56", "hostname": "DMZ-Web-Staging", "interface": "dmz", "lease_expire": 86400, "status": "active"}
                ]
            }

        try:
            return self._get("/monitor/system/dhcp")
        except Exception as e:
            logger.warning(f"Failed to fetch DHCP leases via /monitor/system/dhcp: {e}. Trying fallback...")
            return self._get("/monitor/system/dhcp/status")

    def get_fortiguard_status(self) -> Dict[str, Any]:
        """
        Retrieves FortiGuard security subscription status, package versions, and license expiry.
        """
        if self.mock:
            return {
                "status": "success",
                "results": {
                    "connection": "connected",
                    "server": "usfortiguard.fortinet.net",
                    "antivirus": {
                        "status": "valid",
                        "version": "92.00124",
                        "engine_version": "6.00287",
                        "expiry": "2027-12-31",
                        "last_update": "2026-08-19 04:12:00"
                    },
                    "ips": {
                        "status": "valid",
                        "version": "24.00891",
                        "engine_version": "7.00412",
                        "expiry": "2027-12-31",
                        "last_update": "2026-08-19 06:30:00"
                    },
                    "web_filter": {
                        "status": "valid",
                        "version": "27.00045",
                        "expiry": "2027-12-31"
                    },
                    "industrial_db": {
                        "status": "valid",
                        "version": "21.00140",
                        "expiry": "2027-12-31"
                    },
                    "outbreak_prevention": {
                        "status": "valid",
                        "expiry": "2027-12-31"
                    }
                }
            }

        try:
            return self._get("/monitor/system/fortiguard")
        except Exception as e:
            logger.warning(f"Failed to fetch FortiGuard status via /monitor/system/fortiguard: {e}. Trying fallback...")
            try:
                return self._get("/cmdb/system/fortiguard")
            except Exception as inner_e:
                logger.warning(f"Could not retrieve FortiGuard details: {inner_e}")
                return {"status": "warning", "results": {}, "message": "FortiGuard status query not available or restricted."}

    def get_quarantined_ips(self) -> Dict[str, Any]:
        """
        Retrieves currently banned/quarantined IP addresses from the FortiGate user ban table.
        """
        if self.mock:
            return {
                "status": "success",
                "results": [
                    {
                        "ip": "198.51.100.99",
                        "created": 1724150000,
                        "expires": 1724153600,
                        "source": "admin",
                        "reason": "Brute-force SSH attack detected"
                    }
                ]
            }

        try:
            return self._get("/monitor/user/banned")
        except Exception as e:
            logger.warning(f"Could not fetch banned users/IPs from /monitor/user/banned: {e}")
            return {"status": "success", "results": []}

    def quarantine_ip_address(self, ip_address: str, duration_seconds: int = 3600, reason: str = "") -> Dict[str, Any]:
        """
        Bans / quarantines an IP address on the FortiGate to immediately block traffic from a malicious or compromised endpoint.
        """
        ip_clean = ip_address.strip()
        if not ip_clean:
            raise ValueError("IP address must not be empty.")

        precheck = self._execute_write_prechecks("quarantine_ip_address", {
            "ip_address": ip_clean,
            "duration_seconds": duration_seconds,
            "reason": reason
        })
        if precheck:
            return precheck

        if self.mock:
            return {
                "status": "success",
                "message": f"[Mock Mode] Successfully quarantined IP address '{ip_clean}' for {duration_seconds}s. Reason: {reason or 'Threat containment'}",
                "ip": ip_clean,
                "duration_seconds": duration_seconds
            }

        payload = {
            "ip": ip_clean,
            "expiry": duration_seconds
        }
        return self._post("/monitor/user/banned/add", json_data=payload)

    def get_top_sessions(self, limit: int = 10, sort_by: str = "bytes") -> Dict[str, Any]:
        """
        Retrieves active network sessions from the FortiGate firewall session table,
        sorted by bandwidth consumption (bytes), packet counts, or duration.
        """
        if self.mock:
            mock_sessions = [
                {
                    "session_id": 10421,
                    "proto": "tcp",
                    "proto_name": "HTTPS",
                    "src_ip": "192.168.1.100",
                    "src_port": 54122,
                    "dst_ip": "142.250.190.46",
                    "dst_port": 443,
                    "duration": 1840,
                    "bytes": 2840920140,
                    "packets": 2104921,
                    "policy_id": 1,
                    "interface": "port1",
                    "nat_src": "198.51.100.2"
                },
                {
                    "session_id": 10422,
                    "proto": "tcp",
                    "proto_name": "SMB / File Backup",
                    "src_ip": "192.168.1.50",
                    "src_port": 49201,
                    "dst_ip": "10.0.1.50",
                    "dst_port": 445,
                    "duration": 3600,
                    "bytes": 18492019482,
                    "packets": 14920192,
                    "policy_id": 1,
                    "interface": "dmz",
                    "nat_src": "none"
                },
                {
                    "session_id": 10423,
                    "proto": "tcp",
                    "proto_name": "SSH",
                    "src_ip": "198.51.100.99",
                    "src_port": 41209,
                    "dst_ip": "198.51.100.2",
                    "dst_port": 22,
                    "duration": 45,
                    "bytes": 12840,
                    "packets": 120,
                    "policy_id": 5,
                    "interface": "port1",
                    "nat_src": "none"
                },
                {
                    "session_id": 10424,
                    "proto": "udp",
                    "proto_name": "DNS",
                    "src_ip": "192.168.1.100",
                    "src_port": 61240,
                    "dst_ip": "8.8.8.8",
                    "dst_port": 53,
                    "duration": 12,
                    "bytes": 4820,
                    "packets": 32,
                    "policy_id": 1,
                    "interface": "port1",
                    "nat_src": "198.51.100.2"
                },
                {
                    "session_id": 10425,
                    "proto": "tcp",
                    "proto_name": "HTTPS Cloud Sync",
                    "src_ip": "192.168.1.101",
                    "src_port": 58921,
                    "dst_ip": "52.95.120.34",
                    "dst_port": 443,
                    "duration": 720,
                    "bytes": 524288000,
                    "packets": 390200,
                    "policy_id": 1,
                    "interface": "port1",
                    "nat_src": "198.51.100.2"
                }
            ]

            sort_key = "bytes"
            if sort_by in ("packets", "duration"):
                sort_key = sort_by
            sorted_sessions = sorted(mock_sessions, key=lambda s: s.get(sort_key, 0), reverse=True)[:limit]

            src_bytes = {}
            dst_bytes = {}
            for s in sorted_sessions:
                src_bytes[s["src_ip"]] = src_bytes.get(s["src_ip"], 0) + s["bytes"]
                dst_bytes[s["dst_ip"]] = dst_bytes.get(s["dst_ip"], 0) + s["bytes"]

            return {
                "status": "success",
                "total_active_sessions": 245,
                "returned_sessions_count": len(sorted_sessions),
                "sort_by": sort_key,
                "top_source_ips": sorted([{"ip": ip, "total_bytes": b} for ip, b in src_bytes.items()], key=lambda x: x["total_bytes"], reverse=True),
                "top_destination_ips": sorted([{"ip": ip, "total_bytes": b} for ip, b in dst_bytes.items()], key=lambda x: x["total_bytes"], reverse=True),
                "results": sorted_sessions
            }

        try:
            params = {"count": limit}
            if sort_by in ("bytes", "packets", "duration"):
                params["sort_by"] = sort_by
            return self._get("/monitor/firewall/session", params=params)
        except Exception as e:
            logger.warning(f"Could not retrieve sessions via /monitor/firewall/session: {e}")
            return {"status": "warning", "results": [], "message": f"Session table query failed: {e}"}




