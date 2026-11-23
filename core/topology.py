"""Lightweight in-memory Network Topology & Impact Graph for FortiGate correlation (Issue #16 Phase 5)."""

from collections import deque
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set

from fortigate_client import FortiGateClient


@dataclass
class TopologyNode:
    id: str
    kind: str  # device, vdom, interface, subnet, vpn_tunnel, bgp_peer, ospf_neighbor, sdwan_member, policy
    status: str = "unknown"
    attributes: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class TopologyEdge:
    source: str
    target: str
    relation: str  # contains, routes_via, depends_on, peers_over, matches

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class NetworkTopologyGraph:
    """
    In-memory directed topology graph linking FortiGate devices, VDOMs, interfaces,
    routes/subnets, VPN tunnels, BGP/OSPF peers, SD-WAN members, and firewall policies
    to enable deterministic blast-radius and impact analysis.
    """

    def __init__(self):
        self.nodes: Dict[str, TopologyNode] = {}
        self.edges: List[TopologyEdge] = []
        self._edge_set: Set[TopologyEdge] = set()

    def add_node(self, node: TopologyNode) -> None:
        self.nodes[node.id] = node

    def add_edge(self, source: str, target: str, relation: str) -> None:
        edge = TopologyEdge(source=source, target=target, relation=relation)
        if edge not in self._edge_set:
            self._edge_set.add(edge)
            self.edges.append(edge)

    @classmethod
    def build_from_client(cls, client: FortiGateClient) -> "NetworkTopologyGraph":
        graph = cls()

        def _safe(fn, default):
            try:
                return fn()
            except Exception:
                return default

        sys_status = _safe(client.get_system_status, {})
        status_res = sys_status.get("results", {}) if isinstance(sys_status, dict) else {}
        if isinstance(status_res, list) and status_res:
            status_res = status_res[0]
        elif not isinstance(status_res, dict):
            status_res = {}

        hostname = status_res.get("hostname") or client.host or "fortigate"
        device_id = f"device:{hostname}"
        graph.add_node(
            TopologyNode(
                id=device_id,
                kind="device",
                status="up",
                attributes={"host": client.host, "version": sys_status.get("version") or status_res.get("version", "")},
            )
        )

        # VDOMs
        vdom_id = f"vdom:{client.vdom}"
        graph.add_node(TopologyNode(id=vdom_id, kind="vdom", status="active"))
        graph.add_edge(device_id, vdom_id, "contains")

        vdoms_raw = _safe(client.get_vdom_list, {}).get("results", [])
        if isinstance(vdoms_raw, list):
            for v in vdoms_raw:
                if isinstance(v, dict) and v.get("name"):
                    vid = f"vdom:{v['name']}"
                    graph.add_node(TopologyNode(id=vid, kind="vdom", status="active", attributes=v))
                    graph.add_edge(device_id, vid, "contains")

        # Interfaces
        raw_intfs = _safe(client.get_interfaces, {}).get("results", [])
        intf_list = list(raw_intfs.values()) if isinstance(raw_intfs, dict) else (raw_intfs if isinstance(raw_intfs, list) else [])
        for intf in intf_list:
            if not isinstance(intf, dict):
                continue
            name = intf.get("name") or intf.get("id")
            if not name:
                continue
            is_up = intf.get("status") == "up" or intf.get("link") is True or intf.get("link_status") == 1
            nid = f"interface:{name}"
            graph.add_node(
                TopologyNode(
                    id=nid,
                    kind="interface",
                    status="up" if is_up else "down",
                    attributes={"ip": intf.get("ip", ""), "speed": intf.get("speed", 0)},
                )
            )
            graph.add_edge(vdom_id, nid, "contains")

        # VPN Tunnels
        vpn_res = _safe(client.get_vpn_status, {}).get("results", {})
        ipsec_list = vpn_res.get("ipsec", []) if isinstance(vpn_res, dict) else []
        if isinstance(ipsec_list, dict):
            ipsec_list = list(ipsec_list.values())
        if isinstance(ipsec_list, list):
            for t in ipsec_list:
                if isinstance(t, dict) and t.get("name"):
                    tid = f"vpn:{t['name']}"
                    graph.add_node(
                        TopologyNode(
                            id=tid,
                            kind="vpn_tunnel",
                            status=str(t.get("status", "unknown")).lower(),
                            attributes={"remote_gw": t.get("remote_gw", "")},
                        )
                    )
                    graph.add_edge(vdom_id, tid, "contains")

        # Routing Table (subnets -> egress interface/VPN)
        routes_raw = _safe(client.get_routing_table, {}).get("results", [])
        if isinstance(routes_raw, list):
            for r in routes_raw:
                if not isinstance(r, dict):
                    continue
                dst = r.get("destination") or r.get("ip_mask")
                egress = r.get("interface")
                if not dst:
                    continue
                rid = f"subnet:{dst}"
                graph.add_node(
                    TopologyNode(
                        id=rid,
                        kind="subnet",
                        status="active" if r.get("active", True) else "inactive",
                        attributes={"gateway": r.get("gateway", ""), "type": r.get("type", "")},
                    )
                )
                if egress:
                    target_id = f"vpn:{egress}" if f"vpn:{egress}" in graph.nodes else f"interface:{egress}"
                    if target_id not in graph.nodes:
                        graph.add_node(TopologyNode(id=target_id, kind="interface", status="unknown"))
                    graph.add_edge(rid, target_id, "routes_via")

        # SD-WAN members
        sdwan_raw = _safe(client.get_sdwan_status, {}).get("results", [])
        if isinstance(sdwan_raw, list):
            for m in sdwan_raw:
                if isinstance(m, dict) and m.get("interface"):
                    sid = f"sdwan:{m['interface']}"
                    graph.add_node(
                        TopologyNode(
                            id=sid,
                            kind="sdwan_member",
                            status=str(m.get("sla_status", "unknown")).lower(),
                            attributes={"latency_ms": m.get("latency_ms"), "packet_loss_pct": m.get("packet_loss_pct")},
                        )
                    )
                    graph.add_edge(sid, f"interface:{m['interface']}", "depends_on")

        # Firewall policies
        pols_raw = _safe(client.get_firewall_policies, {}).get("results", [])
        if isinstance(pols_raw, list):
            for p in pols_raw:
                if not isinstance(p, dict) or "policyid" not in p:
                    continue
                pid = f"policy:{p['policyid']}"
                graph.add_node(
                    TopologyNode(
                        id=pid,
                        kind="policy",
                        status=str(p.get("status", "enable")).lower(),
                        attributes={"name": p.get("name", ""), "action": p.get("action", "")},
                    )
                )
                for field_name in ("srcintf", "dstintf"):
                    for item in p.get(field_name, []) or []:
                        if isinstance(item, dict) and item.get("name"):
                            graph.add_edge(pid, f"interface:{item['name']}", "depends_on")

        return graph

    def impact_analysis(self, failed_node_id: str) -> Dict[str, Any]:
        """
        Computes downstream blast radius: all nodes that directly or transitively
        depend on (`depends_on`, `routes_via`, `peers_over`) the given `failed_node_id`.
        """
        reverse_adj: Dict[str, List[TopologyEdge]] = {}
        for edge in self.edges:
            if edge.relation in ("depends_on", "routes_via", "peers_over"):
                reverse_adj.setdefault(edge.target, []).append(edge)

        visited: Set[str] = {failed_node_id}
        queue: deque = deque([failed_node_id])
        impacted_nodes: List[Dict[str, Any]] = []

        while queue:
            curr = queue.popleft()
            for edge in reverse_adj.get(curr, []):
                dependent = edge.source
                if dependent not in visited:
                    visited.add(dependent)
                    queue.append(dependent)
                    node = self.nodes.get(dependent)
                    impacted_nodes.append(
                        {
                            "id": dependent,
                            "kind": node.kind if node else "unknown",
                            "status": node.status if node else "unknown",
                            "relation": edge.relation,
                            "via": curr,
                        }
                    )

        return {
            "source_node": failed_node_id,
            "impacted_count": len(impacted_nodes),
            "impacted_nodes": impacted_nodes,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges],
        }
