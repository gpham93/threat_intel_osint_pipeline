"""
Ingestion Agent - Event Consumer, Entity Resolution & CCO Ontology Mapping Engine
Subscribes to `new_intel_event` topic messages, runs probabilistic identity resolution,
maps newly resolved entities to the BFO/CCO-aligned OWL2 ontology, and updates the live RDFLib store.
"""

import sys
import os
import re
import json
from typing import Dict, List, Any
import rdflib
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, XSD, OWL

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from api.graph_rag import GraphRAGQueryEngine
from pipeline.splink_resolution import FellegiSunterEntityResolver


class IngestionConsumerAgent:
    """
    Consumes `new_intel_event` payloads, executes probabilistic entity linkage against
    the active graph, maps entities to BFO/CCO ontology classes, and updates the RDF knowledge graph.
    """

    def __init__(self, graph_engine: GraphRAGQueryEngine):
        self.graph_engine = graph_engine
        self.THREAT = Namespace("http://example.org/threat#")
        self.CCO = Namespace("http://www.ontologyrepository.com/CommonCoreOntologies/")
        self.resolver = FellegiSunterEntityResolver()

    def _find_existing_entity_uri(self, name: str, country: str = "", reg_id: str = "") -> str:
        """Checks if a matching entity already exists in the graph using probabilistic matching."""
        incoming_record = {"name": name, "country": country, "registration_id": reg_id}
        
        for uri, meta in self.graph_engine.entity_index.items():
            existing_record = {
                "name": meta["label"],
                "country": "",
                "registration_id": meta["sanctionID"]
            }
            prob = self.resolver.compute_match_probability(incoming_record, existing_record)
            if prob >= 0.70:
                return uri

        # Fallback to deterministic clean URI
        safe_id = re.sub(r"\W+", "_", name).strip("_")
        return str(self.THREAT[f"FrontCompany_{safe_id}"])

    def consume_intel_event(self, event_message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Consumes an incoming intel event payload, runs probabilistic entity resolution,
        and adds structured BFO/CCO RDF triples to the live triple store.
        """
        payload = event_message.get("payload", {})
        file_name = payload.get("file_name", "unknown")
        records = payload.get("records", [])

        print(f"[Ingestion Agent] Ingesting event for '{file_name}' with {len(records)} record(s)...")

        new_triples_added = []
        person_count = 0
        org_count = 0
        transfer_count = 0

        for idx, rec in enumerate(records, 1):
            company_name = (
                rec.get("beneficiary_name")
                or rec.get("originator_name")
                or rec.get("company_name")
                or rec.get("name")
            )
            actor_name = rec.get("associated_actor") or rec.get("actor_name")
            country = rec.get("beneficiary_country") or rec.get("originator_country") or rec.get("country", "")
            reg_id = rec.get("beneficiary_reg_id") or rec.get("originator_reg_id") or rec.get("registration_id") or ""
            amount_str = rec.get("amount_usd") or rec.get("amount")
            swift_bic = rec.get("swift_bic")
            raw_content = rec.get("raw_content", "")

            # Regex extraction if freeform raw text
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

            # 1. Probabilistic Resolution & Mapping for Organization
            comp_uri_ref = None
            if company_name:
                comp_uri_str = self._find_existing_entity_uri(company_name, country, reg_id)
                comp_uri_ref = URIRef(comp_uri_str)

                self.graph_engine.graph.add((comp_uri_ref, RDF.type, self.THREAT.FrontCompany))
                self.graph_engine.graph.add((comp_uri_ref, RDFS.subClassOf, self.CCO.Organization))
                self.graph_engine.graph.add((comp_uri_ref, RDFS.label, Literal(company_name)))
                if reg_id:
                    self.graph_engine.graph.add((comp_uri_ref, self.THREAT.sanctionID, Literal(reg_id)))
                if country:
                    self.graph_engine.graph.add((comp_uri_ref, self.THREAT.jurisdiction, Literal(country)))
                if swift_bic:
                    self.graph_engine.graph.add((comp_uri_ref, self.THREAT.swiftBIC, Literal(swift_bic)))

                org_count += 1
                new_triples_added.append((str(comp_uri_ref), "a", "threat:FrontCompany"))

            # 2. Mapping Threat Actor
            actor_uri_ref = None
            if actor_name:
                safe_actor_id = re.sub(r"\W+", "_", actor_name).strip("_")
                actor_uri_ref = self.THREAT[f"Actor_{safe_actor_id}"]

                self.graph_engine.graph.add((actor_uri_ref, RDF.type, self.THREAT.ThreatActor))
                self.graph_engine.graph.add((actor_uri_ref, RDFS.subClassOf, self.CCO.Person))
                self.graph_engine.graph.add((actor_uri_ref, RDFS.label, Literal(actor_name)))

                if comp_uri_ref:
                    self.graph_engine.graph.add((actor_uri_ref, self.THREAT.associatedWith, comp_uri_ref))
                    new_triples_added.append((str(actor_uri_ref), "threat:associatedWith", str(comp_uri_ref)))

                person_count += 1
                new_triples_added.append((str(actor_uri_ref), "a", "threat:ThreatActor"))

            # 3. Mapping Money Transfer
            if amount_str:
                try:
                    amt_val = float(amount_str)
                    transfer_uri = self.THREAT[f"Transfer_Ingested_{idx}_{len(self.graph_engine.graph)}"]
                    self.graph_engine.graph.add((transfer_uri, RDF.type, self.THREAT.MoneyTransfer))
                    self.graph_engine.graph.add((transfer_uri, RDFS.subClassOf, self.CCO.ActOfCommerce))
                    self.graph_engine.graph.add((transfer_uri, self.THREAT.hasAmount, Literal(amt_val, datatype=XSD.decimal)))
                    self.graph_engine.graph.add((transfer_uri, self.THREAT.hasCurrency, Literal("USD")))

                    if comp_uri_ref:
                        self.graph_engine.graph.add((transfer_uri, self.THREAT.has_sender, comp_uri_ref))

                    transfer_count += 1
                    new_triples_added.append((str(transfer_uri), "a", "threat:MoneyTransfer"))
                except ValueError:
                    pass

        # Re-index GraphRAG schema & entity index dynamically
        self.graph_engine._introspect_schema()

        # Persist updated graph to Turtle file
        if self.graph_engine.turtle_path and os.path.exists(os.path.dirname(self.graph_engine.turtle_path)):
            try:
                self.graph_engine.graph.serialize(destination=self.graph_engine.turtle_path, format="turtle")
            except Exception as e:
                print(f"[Ingestion Agent] Serialization note: {e}")

        print(f"[Ingestion Agent] Completed ingestion: {org_count} orgs, {person_count} persons, {transfer_count} transfers. Graph now has {len(self.graph_engine.graph)} triples.")

        return {
            "file_name": file_name,
            "records_processed": len(records),
            "triples_added": len(new_triples_added),
            "total_graph_triples": len(self.graph_engine.graph),
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
