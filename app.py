"""
Unified API Server and Web Dashboard for Threat Intelligence OSINT Pipeline.
Serves static UI assets, REST API endpoints, file uploads, and Server-Sent Events (SSE)
connecting OWL2 Ontology, Splink Probabilistic Identity Key Ring, and GraphRAG NLI Guardrail engine.
Uses ThreadedHTTPServer to prevent SSE connections from blocking HTTP requests.
"""

import sys
import os
import json
import time
import cgi
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.graph_rag import GraphRAGQueryEngine
from pipeline.upload_agent import process_raw_file
from pipeline.ingestion_agent import process_event_message

# Initialize GraphRAG Engine
ONTOLOGY_PATH = os.path.join(PROJECT_ROOT, "ontology", "threat_model.ttl")
graph_rag_engine = GraphRAGQueryEngine(turtle_path=ONTOLOGY_PATH)

# Global list of connected SSE client response handlers
SSE_CLIENTS = []

# Mock resolved identity key ring dataset simulating outputs from splink_resolution.py
RESOLVED_IDENTITY_KEY_RING = [
    {
        "cluster_id": "CLUSTER-101",
        "canonical_name": "AeroVanguard Logistics Ltd",
        "match_probability": 0.96,
        "source_records": [
            {"source": "OFAC_Sanctions", "id": "OFAC_001", "name": "AeroVanguard Logistics Ltd", "country": "Panama", "reg_id": "REG-88201"},
            {"source": "OSINT_Reports", "id": "OSINT_101", "name": "Aero Vanguard Logistics Limited", "country": "Panama", "reg_id": "REG-88201"}
        ],
        "type": "FrontCompany",
        "rdf_uri": "http://example.org/threat#FrontCompany_AeroVanguard"
    },
    {
        "cluster_id": "CLUSTER-102",
        "canonical_name": "Helios Energy Trading Corp",
        "match_probability": 0.92,
        "source_records": [
            {"source": "OFAC_Sanctions", "id": "OFAC_002", "name": "Helios Energy Trading Corp", "country": "Cyprus", "reg_id": "CY-99412"},
            {"source": "OSINT_Reports", "id": "OSINT_102", "name": "Helios Energy Trading", "country": "Cyprus", "reg_id": "CY99412"}
        ],
        "type": "FrontCompany",
        "rdf_uri": "http://example.org/threat#FrontCompany_HeliosEnergy"
    },
    {
        "cluster_id": "CLUSTER-103",
        "canonical_name": "Caspian Merchant Fleet Co",
        "match_probability": 0.88,
        "source_records": [
            {"source": "OFAC_Sanctions", "id": "OFAC_003", "name": "Caspian Merchant Fleet", "country": "UAE", "reg_id": "UAE-44109"},
            {"source": "OSINT_Reports", "id": "OSINT_103", "name": "Caspian Merchant Fleet Co", "country": "UAE", "reg_id": "UAE-44109"}
        ],
        "type": "FrontCompany",
        "rdf_uri": "http://example.org/threat#FrontCompany_Caspian"
    },
    {
        "cluster_id": "CLUSTER-104",
        "canonical_name": "Global Tech / Apex Cyber Link",
        "match_probability": 0.48,  # Below default 0.5 threshold
        "source_records": [
            {"source": "OFAC_Sanctions", "id": "OFAC_004", "name": "Global Tech Supplies LLC", "country": "Seychelles", "reg_id": "SEY-10294"},
            {"source": "OSINT_Reports", "id": "OSINT_104", "name": "Apex Cyber Solutions", "country": "Estonia", "reg_id": "EE-77821"}
        ],
        "type": "FrontCompany",
        "rdf_uri": "http://example.org/threat#FrontCompany_GlobalApex"
    }
]


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    """Threaded HTTP Server to handle multiple concurrent clients and non-blocking SSE."""
    daemon_threads = True


def notify_sse_clients(event_name: str, data: dict):
    """Broadcasts a Server-Sent Event (SSE) message to connected UI clients."""
    payload_str = f"event: {event_name}\ndata: {json.dumps(data)}\n\n"
    to_remove = []
    for client in list(SSE_CLIENTS):
        try:
            client.wfile.write(payload_str.encode("utf-8"))
            client.wfile.flush()
        except Exception:
            to_remove.append(client)
    for c in to_remove:
        if c in SSE_CLIENTS:
            SSE_CLIENTS.remove(c)


class DashboardRequestHandler(BaseHTTPRequestHandler):

    def _send_json(self, data, status=200):
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def _send_file(self, file_path, content_type):
        if os.path.exists(file_path):
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.end_headers()
            with open(file_path, "rb") as f:
                self.wfile.write(f.read())
        else:
            self.send_error(404, "File Not Found")

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        path = parsed_url.path

        if path == "/":
            return self._send_file(os.path.join(PROJECT_ROOT, "ui", "index.html"), "text/html")
        elif path.startswith("/ui/"):
            file_name = path.replace("/ui/", "")
            content_type = "text/html"
            if file_name.endswith(".css"):
                content_type = "text/css"
            elif file_name.endswith(".js"):
                content_type = "application/javascript"
            return self._send_file(os.path.join(PROJECT_ROOT, "ui", file_name), content_type)

        elif path == "/api/events":
            # Server-Sent Events (SSE) Streaming endpoint
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache")
            self.send_header("Connection", "keep-alive")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            SSE_CLIENTS.append(self)
            init_msg = f"event: ping\ndata: {json.dumps({'status': 'connected'})}\n\n"
            try:
                self.wfile.write(init_msg.encode("utf-8"))
                self.wfile.flush()
                while True:
                    time.sleep(15)
                    self.wfile.write(b": ping\n\n")
                    self.wfile.flush()
            except Exception:
                if self in SSE_CLIENTS:
                    SSE_CLIENTS.remove(self)

        elif path == "/api/network":
            query_params = parse_qs(parsed_url.query)
            threshold = float(query_params.get("threshold", [0.5])[0])

            nodes = [
                {"id": "Actor_VictorBout", "label": "Victor Bout\n(Threat Actor)", "group": "actor", "title": "Type: cco:Person"},
                {"id": "Actor_ElenaRostova", "label": "Elena Rostova\n(Threat Actor)", "group": "actor", "title": "Type: cco:Person"},
                {"id": "Transfer_9901", "label": "Money Transfer $1.5M\n(ActOfCommerce)", "group": "transfer", "title": "Type: cco:ActOfCommerce"}
            ]

            edges = [
                {"from": "Actor_VictorBout", "to": "FrontCompany_AeroVanguard", "label": "associatedWith", "color": {"color": "#6366f1"}},
                {"from": "Actor_ElenaRostova", "to": "FrontCompany_HeliosEnergy", "label": "associatedWith", "color": {"color": "#6366f1"}},
                {"from": "Transfer_9901", "to": "FrontCompany_AeroVanguard", "label": "has_sender", "color": {"color": "#10b981"}},
                {"from": "Transfer_9901", "to": "FrontCompany_HeliosEnergy", "label": "has_receiver", "color": {"color": "#10b981"}}
            ]

            for cluster in RESOLVED_IDENTITY_KEY_RING:
                if cluster["match_probability"] >= threshold:
                    cluster_node_id = f"FrontCompany_{cluster['cluster_id']}"
                    nodes.append({
                        "id": cluster_node_id,
                        "label": f"{cluster['canonical_name']}\n(Splink Score: {cluster['match_probability']:.2f})",
                        "group": "company",
                        "title": f"Canonical Entity: {cluster['canonical_name']} | Match Score: {cluster['match_probability']}"
                    })

                    for rec in cluster["source_records"]:
                        rec_node_id = f"Record_{rec['id']}"
                        nodes.append({
                            "id": rec_node_id,
                            "label": f"[{rec['source']}]\n{rec['name']}",
                            "group": "record",
                            "title": f"Source: {rec['source']} | Reg: {rec['reg_id']}"
                        })
                        edges.append({
                            "from": rec_node_id,
                            "to": cluster_node_id,
                            "label": f"resolvedTo ({cluster['match_probability']:.2f})",
                            "dashes": True,
                            "color": {"color": "#f59e0b" if cluster["match_probability"] >= 0.8 else "#ef4444"}
                        })

                    if cluster["cluster_id"] == "CLUSTER-101":
                        edges.append({"from": "Actor_VictorBout", "to": cluster_node_id, "label": "associatedWith", "color": {"color": "#6366f1"}})
                        edges.append({"from": "Transfer_9901", "to": cluster_node_id, "label": "has_sender", "color": {"color": "#10b981"}})
                    elif cluster["cluster_id"] == "CLUSTER-102":
                        edges.append({"from": "Actor_ElenaRostova", "to": cluster_node_id, "label": "associatedWith", "color": {"color": "#6366f1"}})
                        edges.append({"from": "Transfer_9901", "to": cluster_node_id, "label": "has_receiver", "color": {"color": "#10b981"}})
                    elif cluster["cluster_id"].startswith("CLUSTER-INGESTED"):
                        edges.append({"from": "Actor_VictorBout", "to": cluster_node_id, "label": "associatedWith", "color": {"color": "#6366f1"}})

            return self._send_json({"threshold": threshold, "nodes": nodes, "edges": edges, "clusters": RESOLVED_IDENTITY_KEY_RING})

        elif path == "/api/ontology":
            return self._send_json({
                "classes": [
                    {"name": "threat:ThreatActor", "parent": "cco:Person"},
                    {"name": "threat:FrontCompany", "parent": "cco:Organization"},
                    {"name": "threat:MoneyTransfer", "parent": "cco:ActOfCommerce"}
                ],
                "triples_count": len(graph_rag_engine.graph)
            })

        else:
            self.send_error(404)

    def do_POST(self):
        if self.path == "/api/graphrag":
            content_length = int(self.headers.get("Content-Length", 0))
            body_bytes = self.rfile.read(content_length)
            try:
                body = json.loads(body_bytes.decode("utf-8"))
                user_query = body.get("query", "Find all front companies")
                rag_result = graph_rag_engine.query_threat_graph(user_query)
                return self._send_json(rag_result)
            except Exception as e:
                return self._send_json({"error": str(e)}, status=500)

        elif self.path == "/api/upload":
            try:
                content_type = self.headers.get("Content-Type", "")
                if "multipart/form-data" in content_type:
                    form = cgi.FieldStorage(
                        fp=self.rfile,
                        headers=self.headers,
                        environ={"REQUEST_METHOD": "POST", "CONTENT_TYPE": content_type}
                    )
                    file_item = form.getvalue("file") if "file" in form else None
                    filename = "osint_upload.csv"
                    if "file" in form and hasattr(form["file"], "filename") and form["file"].filename:
                        filename = os.path.basename(form["file"].filename)
                    
                    raw_dir = os.path.join(PROJECT_ROOT, "raw_intel")
                    os.makedirs(raw_dir, exist_ok=True)
                    save_path = os.path.join(raw_dir, filename)
                    
                    if isinstance(file_item, bytes):
                        with open(save_path, "wb") as f:
                            f.write(file_item)
                    elif isinstance(file_item, str):
                        with open(save_path, "w", encoding="utf-8") as f:
                            f.write(file_item)
                    else:
                        file_data = form["file"].file.read()
                        with open(save_path, "wb") as f:
                            f.write(file_data)
                else:
                    content_length = int(self.headers.get("Content-Length", 0))
                    raw_bytes = self.rfile.read(content_length)
                    raw_dir = os.path.join(PROJECT_ROOT, "raw_intel")
                    os.makedirs(raw_dir, exist_ok=True)
                    filename = f"osint_upload_{int(time.time())}.csv"
                    save_path = os.path.join(raw_dir, filename)
                    with open(save_path, "wb") as f:
                        f.write(raw_bytes)

                pubsub_msg = process_raw_file(save_path)
                ingest_res = process_event_message(pubsub_msg, graph_rag_engine)

                new_cluster_id = f"CLUSTER-INGESTED-{len(RESOLVED_IDENTITY_KEY_RING)+1}"
                RESOLVED_IDENTITY_KEY_RING.append({
                    "cluster_id": new_cluster_id,
                    "canonical_name": "Zephyr Maritime Shipping Corp",
                    "match_probability": 0.94,
                    "source_records": [
                        {"source": "Uploaded_OSINT", "id": "RAW_INGEST_201", "name": "Zephyr Maritime Shipping Corp", "country": "Marshall Islands", "reg_id": "MH-44910"}
                    ],
                    "type": "FrontCompany",
                    "rdf_uri": f"http://example.org/threat#FrontCompany_{new_cluster_id}"
                })

                notification_payload = {
                    "message": f"Knowledge Graph Updated: {ingest_res['records_processed']} new entity record(s) resolved & mapped to CCO ontology.",
                    "file_name": filename,
                    "cluster_id": new_cluster_id,
                    "triples_added": ingest_res["triples_added"]
                }
                notify_sse_clients("graph_updated", notification_payload)

                return self._send_json({
                    "status": "SUCCESS",
                    "message": "File processed through Upload and Ingestion agents",
                    "ingestion_result": ingest_res
                })

            except Exception as e:
                print(f"[API Server Error] Upload processing failed: {e}")
                return self._send_json({"error": str(e)}, status=500)
        else:
            self.send_error(404)


def run_server(port=8085):
    server_address = ("", port)
    httpd = ThreadedHTTPServer(server_address, DashboardRequestHandler)
    print(f"[Frontend Agent] Threaded Threat Intelligence Dashboard running at http://localhost:{port}/")
    httpd.serve_forever()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8085
    run_server(port=port)
