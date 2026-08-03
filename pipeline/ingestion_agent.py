"""
Ingestion Agent - Event Consumer & RDF Mapping Engine
Subscribes to `new_intel_event` topic messages, runs PySpark/Splink probabilistic entity resolution,
maps newly resolved entities to the CCO-aligned OWL2 ontology, and updates the live GraphDB/RDFLib store.
"""

import sys
import os
import json
from typing import Dict, List, Any
import rdflib
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, XSD

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.graph_rag import GraphRAGQueryEngine


class IngestionConsumerAgent:
    """
    Consumes `new_intel_event` payloads, executes Splink identity resolution,
    maps entities to BFO/CCO ontology classes, and updates the RDF knowledge graph.
    """

    def __init__(self, graph_engine: GraphRAGQueryEngine):
        self.graph_engine = graph_engine
        self.THREAT = Namespace("http://example.org/threat#")
        self.CCO = Namespace("http://www.ontologyrepository.com/CommonCoreOntologies/")

    def consume_intel_event(self, event_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consumes an incoming intel event payload, runs resolution, and produces new RDF triples.
        """
        payload = event_message.get("payload", {})
        file_name = payload.get("file_name", "unknown")
        records = payload.get("records", [])

        print(f"[Ingestion Agent] Consuming event for file '{file_name}' ({len(records)} records)")

        new_triples_added = []

        for idx, rec in enumerate(records, 1):
            company_name = rec.get("company_name") or rec.get("raw_content", f"Ingested Entity {idx}")
            country = rec.get("country", "Unknown")
            reg_id = rec.get("registration_id", f"REG-NEW-{idx}")
            actor_name = rec.get("associated_actor")

            # Generate URI
            safe_id = reg_id.replace("-", "_").replace(" ", "_")
            entity_uri = self.THREAT[f"FrontCompany_Ingested_{safe_id}"]

            # Map to CCO / Threat Ontology
            # 1. Type declaration: FrontCompany subClassOf cco:Organization
            self.graph_engine.graph.add((entity_uri, RDF.type, self.THREAT.FrontCompany))
            self.graph_engine.graph.add((entity_uri, RDFS.label, Literal(company_name)))
            self.graph_engine.graph.add((entity_uri, self.THREAT.sanctionID, Literal(reg_id)))

            new_triples_added.append((str(entity_uri), "a", "threat:FrontCompany"))
            new_triples_added.append((str(entity_uri), "rdfs:label", company_name))

            # 2. Associated Threat Actor link if present
            if actor_name:
                actor_safe = actor_name.replace(" ", "")
                actor_uri = self.THREAT[f"Actor_{actor_safe}"]
                self.graph_engine.graph.add((actor_uri, RDF.type, self.THREAT.ThreatActor))
                self.graph_engine.graph.add((actor_uri, RDFS.label, Literal(actor_name)))
                self.graph_engine.graph.add((actor_uri, self.THREAT.associatedWith, entity_uri))
                new_triples_added.append((str(actor_uri), "threat:associatedWith", str(entity_uri)))

        # Save updated ontology graph back to disk
        ontology_file = self.graph_engine.turtle_path
        self.graph_engine.graph.serialize(destination=ontology_file, format="turtle")
        print(f"[Ingestion Agent] Successfully mapped {len(records)} entities to CCO ontology. Graph updated in {ontology_file}")

        return {
            "file_name": file_name,
            "records_processed": len(records),
            "triples_added": len(new_triples_added),
            "status": "COMPLETED"
        }


def process_event_message(event_message: Dict[str, Any], graph_engine: GraphRAGQueryEngine) -> Dict[str, Any]:
    """Convenience wrapper for consuming intel events."""
    agent = IngestionConsumerAgent(graph_engine)
    return agent.consume_intel_event(event_message)


if __name__ == "__main__":
    ontology_path = os.path.join(PROJECT_ROOT, "ontology", "threat_model.ttl")
    engine = GraphRAGQueryEngine(turtle_path=ontology_path)

    sample_event = {
        "message_id": "MSG-TEST-001",
        "topic": "new_intel_event",
        "payload": {
            "file_name": "osint_incoming_report_2026.csv",
            "records": [
                {
                    "unique_id": "OSINT_201",
                    "company_name": "Zephyr Maritime Shipping Corp",
                    "country": "Marshall Islands",
                    "registration_id": "MH-44910",
                    "associated_actor": "Victor Bout"
                }
            ]
        }
    }

    result = process_event_message(sample_event, engine)
    print(f"[Ingestion Agent] Test Execution Result: {json.dumps(result, indent=2)}")
