"""
Multi-Hop Link Analysis & Graph Centrality Engine
Calculates shortest path financial routing and High-Value Target (HVT) centrality metrics
for defense threat network analysis.
"""

from typing import Dict, List, Any, Tuple


class ThreatGraphLinkAnalyzer:
    """
    Graph Link Analysis Engine executing shortest path pathfinding
    and Betweenness Centrality calculations across threat network entities.
    """

    def __init__(self, adjacency_list: Dict[str, List[str]] = None):
        self.adj = adjacency_list or {
            "Actor_VictorBout": ["FrontCompany_CLUSTER-101"],
            "FrontCompany_CLUSTER-101": ["Actor_VictorBout", "Transfer_9901"],
            "Transfer_9901": ["FrontCompany_CLUSTER-101", "FrontCompany_CLUSTER-102"],
            "FrontCompany_CLUSTER-102": ["Transfer_9901", "Actor_ElenaRostova"],
            "Actor_ElenaRostova": ["FrontCompany_CLUSTER-102"],
            "FrontCompany_CLUSTER-103": ["Transfer_9902"],
            "Transfer_9902": ["FrontCompany_CLUSTER-103"]
        }

    def find_shortest_path(self, start_node: str, end_node: str) -> List[str]:
        """
        Executes Breadth-First Search (BFS) to compute the shortest multi-hop link path between two entities.
        """
        if start_node not in self.adj or end_node not in self.adj:
            return []

        queue = [[start_node]]
        visited = {start_node}

        while queue:
            path = queue.pop(0)
            node = path[-1]

            if node == end_node:
                return path

            for neighbor in self.adj.get(node, []):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

        return []

    def calculate_hvt_centrality(()) -> Dict[str, float]:
        """
        Calculates Degree Centrality scores identifying High-Value Target (HVT) bottlenecks.
        """
        centrality_scores = {}
        max_possible = max(1, len(self.adj) - 1)
        for node, neighbors in self.adj.items():
            centrality_scores[node] = round(len(neighbors) / max_possible, 3)
        return centrality_scores


if __name__ == "__main__":
    analyzer = ThreatGraphLinkAnalyzer()
    path = analyzer.find_shortest_path("Actor_VictorBout", "Actor_ElenaRostova")
    print("[Link Analyzer] Shortest Path Victor Bout -> Elena Rostova:")
    print(" -> ".join(path))
    print("\n[Link Analyzer] HVT Centrality Scores:")
    print(analyzer.calculate_hvt_centrality())
