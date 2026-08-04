"""
Ingestion Agent - Event Consumer & CCO Ontology Mapping Engine
Subscribes to `new_intel_event` topic messages, extracts entities from CSV, TXT, and PDF intel reports,
maps newly resolved entities to the BFO/CCO-aligned OWL2 ontology (cco:Person, cco:Organization, cco:ActOfCommerce),
and updates the live GraphDB/RDFLib store.
"""

import sys
import os
import re
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
    Consumes `new_intel_event` payloads, runs entity extraction,
    maps entities to BFO/CCO ontology classes, and updates the RDF knowledge graph.
    """

    def __init__(self, graph_engine: GraphRAGQueryEngine):
        self.graph_engine = graph_engine
        self.THREAT = Namespace("http://example.org/threat#")
        self.CCO = Namespace("http://www.ontologyrepository.com/CommonCoreOntologies/")

    def consume_intel_event(self, event_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consumes an incoming intel event payload, runs resolution, and produces new CCO RDF triples.
        """
        payload = event_message.get("payload", {})
        file_name = payload.get("file_name", "unknown")
        records = payload.get("records", [])

        print(f"[Ingestion Agent] Consuming event for file '{file_name}' ({len(records)} records)")

        new_triples_added = []
        person_count = 0
        org_count = 0
        transfer_count = 0

        for idx, rec in enumerate(records, 1):
            # Extract fields
            company_name = (
                rec.get("beneficiary_name")
                or rec.get("originator_name")
                or rec.get("company_name")
                or rec.get("name")
            )
            actor_name = rec.get("associated_actor") or rec.get("actor_name")
            country = rec.get("beneficiary_country") or rec.get("originator_country") or rec.get("country", "Panama")
            reg_id = rec.get("beneficiary_reg_id") or rec.get("originator_reg_id") or rec.get("registration_id") or f"REG-NEW-{idx}"
            amount_str = rec.get("amount_usd") or rec.get("amount")
            swift_bic = rec.get("swift_bic")
            raw_content = rec.get("raw_content", "")

            # If raw content text line, run NLP regex extraction
            if raw_content:
                actor_match = re.search(r"(?:Name|Target|Actor):\s*([A-Za-z\s]+)", raw_content, re.IGNORECASE)
                if actor_match:
                    actor_name = actor_match.group(1).strip()

                comp_match = re.search(r"(?:Entity|Company|Primary):\s*([A-Za-z0-9\s]+(?:Ltd|Corp|Co|LLC|Inc|Holdings))", raw_content, re.IGNORECASE)
                if comp_match:
                    company_name = comp_match.group(1).strip()

                amt_match = re.search(r"\$([0-9,]+(?:\.[0-9]{2})?)", raw_content)
                if amt_match:
                    amount_str = amt_match.group(1).replace(",", "")

            # 1. Map Organization (cco:Organization / threat:FrontCompany)
            if company_name:
                safe_comp_id = re.sub(r"\W+", "_", company_name)
                comp_uri = self.THREAT[f"FrontCompany_{safe_comp_id}"]

                self.graph_engine.graph.add((comp_uri, RDF.type, self.THREAT.FrontCompany))
                self.graph_engine.graph.add((comp_uri, RDFS.subClassOf, self.CCO.Organization))
                self.graph_engine.graph.add((comp_uri, RDFS.label, Literal(company_name)))
                self.graph_engine.graph.add((comp_uri, self.THREAT.sanctionID, Literal(reg_id)))
                self.graph_engine.graph.add((comp_uri, self.THREAT.jurisdiction, Literal(country)))
                if swift_bic:
                    self.graph_engine.graph.add((comp_uri, self.THREAT.swiftBIC, Literal(swift_bic)))

                org_count += 1
                new_triples_added.append((str(comp_uri), "a", "cco:Organization"))

            # 2. Map Person (cco:Person / threat:ThreatActor)
            if actor_name:
                safe_actor_id = re.sub(r"\W+", "_", actor_name)
                actor_uri = self.THREAT[f"Actor_{safe_actor_id}"]

                self.graph_engine.graph.add((actor_uri, RDF.type, self.THREAT.ThreatActor))
                self.graph_engine.graph.add((actor_uri, RDFS.subClassOf, self.CCO.Person))
                self.graph_engine.graph.add((actor_uri, RDFS.label, Literal(actor_name)))

                if company_name:
                    safe_comp_id = re.sub(r"\W+", "_", company_name)
                    comp_uri = self.THREAT[f"FrontCompany_{safe_comp_id}"]
                    self.graph_engine.graph.add((actor_uri, self.THREAT.associatedWith, comp_uri))
                    new_triples_added.append((str(actor_uri), "threat:associatedWith", str(comp_uri)))

                person_count += 1
                new_triples_added.append((str(actor_uri), "a", "cco:Person"))

            # 3. Map ActOfCommerce (cco:ActOfCommerce / threat:MoneyTransfer)
            if amount_str:
                try:
                    amt_val = float(amount_str)
                    transfer_uri = self.THREAT[f"Transfer_Ingested_{idx}"]
                    self.graph_engine.graph.add((transfer_uri, RDF.type, self.THREAT.MoneyTransfer))
                    self.graph_engine.graph.add((transfer_uri, RDFS.subClassOf, self.CCO.ActOfCommerce))
                    self.graph_engine.graph.add((transfer_uri, self.THREAT.hasAmount, Literal(amt_val, datatype=XSD.decimal)))
                    self.graph_engine.graph.add((transfer_uri, self.THREAT.hasCurrency, Literal("USD")))
                    
                    transfer_count += 1
                    new_triples_added.append((str(transfer_uri), "a", "cco:ActOfCommerce"))
                except ValueError:
                    pass

        # Save updated ontology graph back to disk
        ontology_file = self.graph_engine.turtle_path
        self.graph_engine.graph.serialize(destination=ontology_file, format="turtle")
        print(f"[Ingestion Agent] Mapped {len(records)} records ({org_count} cco:Organization, {person_count} cco:Person, {transfer_count} cco:ActOfCommerce) to ontology in {ontology_file}")

        return {
            "file_name": file_name,
            "records_processed": len(records),
            "triples_added": len(new_triples_added),
            "counts": {
                "cco:Organization": org_count,
                "cco:Person": person_count,
                "cco:ActOfCommerce": transfer_count
            },
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
        "message_id": "MSG-TEST-002",
        "topic": "new_intel_event",
        "payload": {
            "file_name": "finCEN_suspicious_activity_report_2026.csv",
            "records": [
                {
                    "originator_name": "AeroVanguard Logistics Ltd",
                    "originator_country": "Panama",
                    "originator_reg_id": "REG-88201",
                    "beneficiary_name": "Helios Energy Trading Corp",
                    "beneficiary_country": "Cyprus",
                    "beneficiary_reg_id": "CY-99412",
                    "amount_usd": "1500000.00",
                    "swift_bic": "HELIOCY22"
                }
            ]
        }
    }

    result = process_event_message(sample_event, engine)
    print(f"[Ingestion Agent] Test Execution Result: {json.dumps(result, indent=2)}")
