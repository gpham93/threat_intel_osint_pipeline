"""
Multi-Hop Link Analysis & Graph Centrality Engine
Calculates:
1. Dynamic RDF Graph Adjacency Extraction across semantic predicates
2. Shortest Path Multi-Hop Routing (BFS / Dijkstra) with edge predicates
3. True Betweenness Centrality (Brandes' Algorithm) & Degree Centrality for HVT detection
"""

from typing import Dict, List, Any, Tuple, Set, Optional
from collections import deque
import rdflib
from rdflib import Graph, URIRef


class ThreatGraphLinkAnalyzer:
    """
    Graph Link Analysis Engine executing shortest path pathfinding
    and Betweenness Centrality calculations dynamically across threat network entities.
    """

    def __init__(self, graph: Optional[Graph] = None, adjacency_list: Optional[Dict[str, List[str]]] = None):
        self.graph = graph
        self.adj: Dict[str, Dict[str, str]] = {}  # node -> {neighbor: predicate}
        self.nodes: Set[str] = set()

        if graph is not None:
            self.build_from_rdf_graph(graph)
        elif adjacency_list is not None:
            for u, neighbors in adjacency_list.items():
                self.adj[u] = {}
                self.nodes.add(u)
                for v in neighbors:
                    self.adj[u][v] = "threat:connectedTo"
                    self.nodes.add(v)
        else:
            self._load_default_topology()

    def _load_default_topology(self):
        """Loads default topology if no graph is provided."""
        default_edges = [
            ("Actor_VictorBout", "FrontCompany_CLUSTER-101", "threat:associatedWith"),
            ("FrontCompany_CLUSTER-101", "Transfer_9901", "threat:has_sender"),
            ("Transfer_9901", "FrontCompany_CLUSTER-102", "threat:has_receiver"),
            ("FrontCompany_CLUSTER-102", "Actor_ElenaRostova", "threat:associatedWith"),
            ("FrontCompany_CLUSTER-103", "Transfer_9902", "threat:has_sender"),
            ("Transfer_9902", "FrontCompany_CLUSTER-101", "threat:has_receiver")
        ]
        for u, v, pred in default_edges:
            self.add_edge(u, v, pred)

    def add_edge(self, u: str, v: str, predicate: str = "threat:connectedTo"):
        """Adds a bidirectional or directed edge between entities."""
        self.nodes.add(u)
        self.nodes.add(v)
        if u not in self.adj:
            self.adj[u] = {}
        if v not in self.adj:
            self.adj[v] = {}
        self.adj[u][v] = predicate
        self.adj[v][u] = f"inverse_{predicate}"

    def build_from_rdf_graph(self, rdf_graph: Graph):
        """
        Dynamically builds the network topology directly from RDF triples.
        Extracts relationships across object properties.
        """
        self.adj.clear()
        self.nodes.clear()

        query = """
        PREFIX threat: <http://example.org/threat#>
        PREFIX cco: <http://www.ontologyrepository.com/CommonCoreOntologies/>
        PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>

        SELECT DISTINCT ?s ?p ?o ?sLabel ?oLabel WHERE {
            ?s ?p ?o .
            OPTIONAL { ?s rdfs:label ?sLabel } .
            OPTIONAL { ?o rdfs:label ?oLabel } .
            FILTER (isURI(?o) && STRSTARTS(STR(?p), "http://example.org/threat#"))
        }
        """
        for row in rdf_graph.query(query):
            s_str = str(row[0]).split("#")[-1]
            p_str = str(row[1]).split("#")[-1]
            o_str = str(row[2]).split("#")[-1]
            self.add_edge(s_str, o_str, f"threat:{p_str}")

    def find_shortest_path(self, start_node: str, end_node: str) -> Dict[str, Any]:
        """
        Executes Breadth-First Search (BFS) to compute the shortest multi-hop link path
        between two entities, including exact predicate edges along the route.
        """
        start_clean = start_node.split("#")[-1]
        end_clean = end_node.split("#")[-1]

        # Fuzzy match if exact node name not directly in key
        start_key = next((n for n in self.nodes if start_clean.lower() in n.lower()), start_clean)
        end_key = next((n for n in self.nodes if end_clean.lower() in n.lower()), end_clean)

        if start_key not in self.adj or end_key not in self.adj:
            return {"path": [], "hops": 0, "edge_predicates": [], "found": False}

        queue = deque([[start_key]])
        visited = {start_key}

        while queue:
            path = queue.popleft()
            curr = path[-1]

            if curr == end_key:
                # Reconstruct edge predicates
                edge_preds = []
                for i in range(len(path) - 1):
                    pred = self.adj.get(path[i], {}).get(path[i + 1], "threat:connectedTo")
                    edge_preds.append(pred)

                return {
                    "path": path,
                    "hops": len(path) - 1,
                    "edge_predicates": edge_preds,
                    "found": True,
                    "summary": " -> ".join([f"{path[i]} --[{edge_preds[i]}]--> {path[i+1]}" for i in range(len(path)-1)])
                }

            for neighbor in self.adj.get(curr, {}):
                if neighbor not in visited:
                    visited.add(neighbor)
                    new_path = list(path)
                    new_path.append(neighbor)
                    queue.append(new_path)

        return {"path": [], "hops": 0, "edge_predicates": [], "found": False}

    def calculate_betweenness_centrality(self) -> Dict[str, float]:
        """
        Calculates exact Betweenness Centrality using Brandes' Algorithm:
        C_B(v) = sum_{s != v != t} (sigma_st(v) / sigma_st)
        """
        cb: Dict[str, float] = {node: 0.0 for node in self.nodes}
        node_list = list(self.nodes)

        for s in node_list:
            stack: List[str] = []
            predecessors: Dict[str, List[str]] = {w: [] for w in self.nodes}
            sigma: Dict[str, int] = {w: 0 for w in self.nodes}
            sigma[s] = 1
            dist: Dict[str, int] = {w: -1 for w in self.nodes}
            dist[s] = 0
            q = deque([s])

            while q:
                v = q.popleft()
                stack.append(v)
                for w in self.adj.get(v, {}):
                    # Path discovery
                    if dist[w] < 0:
                        dist[w] = dist[v] + 1
                        q.append(w)
                    # Path counting
                    if dist[w] == dist[v] + 1:
                        sigma[w] += sigma[v]
                        predecessors[w].append(v)

            # Accumulation of dependencies
            delta: Dict[str, float] = {w: 0.0 for w in self.nodes}
            while stack:
                w = stack.pop()
                for v in predecessors[w]:
                    if sigma[w] != 0:
                        delta[v] += (sigma[v] / sigma[w]) * (1.0 + delta[w])
                if w != s:
                    cb[w] += delta[w]

        # Normalize for undirected graph
        n = len(self.nodes)
        scale = 1.0 / ((n - 1) * (n - 2)) if n > 2 else 1.0
        for node in cb:
            cb[node] = round(cb[node] * scale, 4)

        return dict(sorted(cb.items(), key=lambda item: item[1], reverse=True))

    def calculate_degree_centrality(self) -> Dict[str, float]:
        """Calculates normalized Degree Centrality for each entity in the network."""
        n = len(self.nodes)
        scale = 1.0 / (n - 1) if n > 1 else 1.0
        deg = {node: round(len(neighbors) * scale, 3) for node, neighbors in self.adj.items()}
        return dict(sorted(deg.items(), key=lambda item: item[1], reverse=True))

    def calculate_hvt_centrality(self) -> Dict[str, float]:
        """Calculates composite High-Value Target (HVT) bottleneck score."""
        return self.calculate_betweenness_centrality()


if __name__ == "__main__":
    analyzer = ThreatGraphLinkAnalyzer()
    res = analyzer.find_shortest_path("Actor_VictorBout", "Actor_ElenaRostova")
    print("[Link Analyzer] Shortest Path Route:")
    print(res.get("summary", "No path found"))
    print("\n[Link Analyzer] Real Brandes Betweenness Centrality (HVT Bottlenecks):")
    print(analyzer.calculate_betweenness_centrality())
