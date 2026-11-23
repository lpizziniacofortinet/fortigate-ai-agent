import unittest

from core.topology import NetworkTopologyGraph
from fortigate_client import FortiGateClient


class TestNetworkTopologyGraph(unittest.TestCase):
    """Tests for NetworkTopologyGraph construction and blast-radius impact analysis (Issue #16 Phase 5)."""

    def test_mock_topology_and_impact_analysis(self):
        client = FortiGateClient(host="10.0.0.1", token="tok", vdom="root", mock=True)
        graph = NetworkTopologyGraph.build_from_client(client)

        data = graph.to_dict()
        self.assertGreater(data["node_count"], 10)
        self.assertGreater(data["edge_count"], 10)

        # Impact of port1 going down: default route 0.0.0.0/0, 10.50.0.0/16, SD-WAN member, and policies
        impact_port1 = graph.impact_analysis("interface:port1")
        impacted_ids = {n["id"] for n in impact_port1["impacted_nodes"]}
        self.assertIn("subnet:0.0.0.0/0", impacted_ids)
        self.assertIn("subnet:10.50.0.0/16", impacted_ids)
        self.assertIn("sdwan:port1", impacted_ids)
        self.assertIn("policy:1", impacted_ids)

        # Impact of AWS-Transit VPN tunnel going down: 172.16.0.0/12 route depends on it
        impact_vpn = graph.impact_analysis("vpn:AWS-Transit")
        vpn_impacted_ids = {n["id"] for n in impact_vpn["impacted_nodes"]}
        self.assertIn("subnet:172.16.0.0/12", vpn_impacted_ids)


if __name__ == "__main__":
    unittest.main()
