import unittest

import pandas as pd

from app.features import extract_state
from app.graph import build_graph
from app.scoring import score_flows


class NetworkStateTests(unittest.TestCase):
    def setUp(self):
        self.frame = pd.DataFrame([
            {"Source IP": f"10.0.0.{(i % 4) + 1}", "Destination IP": f"10.0.1.{(i % 3) + 1}",
             "Source Port": 40000 + i, "Destination Port": 443 if i % 2 else 53,
             "Protocol": "TCP" if i % 2 else "UDP", "Packets": 10 + i,
             "Bytes": 800 + 50 * i, "Flow Duration": 100 + 3 * i,
             "SYN Flag Count": 1 if i % 2 else 0, "ACK Flag Count": i % 2}
            for i in range(24)
        ])

    def test_state_is_an_18_dimension_normalized_vector(self):
        flows, state = extract_state(self.frame)
        self.assertEqual(len(flows), 24)
        self.assertEqual(state["feature_count"], 18)
        self.assertEqual(len(state["features"]), 18)
        for feature in state["features"]:
            if feature["normalized"] is not None:
                self.assertGreaterEqual(feature["normalized"], 0)
                self.assertLessEqual(feature["normalized"], 1)

    def test_flow_batch_gets_scored_and_graph_has_observed_edges(self):
        flows, _ = extract_state(self.frame)
        scored, model = score_flows(flows)
        graph = build_graph(flows, scored)
        self.assertTrue(model["available"])
        self.assertEqual(len(scored), 24)
        self.assertGreater(graph["node_count"], 0)
        self.assertGreater(graph["edge_count"], 0)
        self.assertTrue(all(edge["flow_count"] > 0 for edge in graph["edges"]))

    def test_insufficient_records_are_not_misrepresented_as_scored(self):
        flows, _ = extract_state(self.frame.head(5))
        scored, model = score_flows(flows)
        self.assertFalse(model["available"])
        self.assertEqual(scored, [])


if __name__ == "__main__":
    unittest.main()
