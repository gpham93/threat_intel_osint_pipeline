"""
Large-Scale Threat Intelligence Knowledge Graph Synthesizer
Generates a synthetic enterprise-grade dataset with 10,000+ RDF Triples,
500+ Front Companies, 150+ Threat Actors, and $142M+ Monitored Financial Volume.
Outputs W3C OWL2 Turtle file ontology/threat_model_large.ttl.
"""

import os
import random
from rdflib import Graph, Namespace, URIRef, Literal, RDF, RDFS, XSD


def generate_large_scale_knowledge_graph(output_path: str, num_actors: int = 250, num_companies: int = 1024, num_transfers: int = 800) -> int:
    """
    Synthesizes large-scale threat network ontology graph containing over 10,000 RDF triples.
    """
    g = Graph()
    THREAT = Namespace("http://example.org/threat#")
    CCO = Namespace("http://www.ontologyrepository.com/CommonCoreOntologies/")
    BFO = Namespace("http://purl.obolibrary.org/obo/")

    g.bind("threat", THREAT)
    g.bind("cco", CCO)
    g.bind("bfo", BFO)
    g.bind("rdfs", RDFS)
    g.bind("xsd", XSD)

    # Class Definitions
    g.add((THREAT.ThreatActor, RDFS.subClassOf, CCO.Person))
    g.add((THREAT.FrontCompany, RDFS.subClassOf, CCO.Organization))
    g.add((THREAT.MoneyTransfer, RDFS.subClassOf, CCO.ActOfCommerce))

    first_names = ["Victor", "Elena", "Dmitry", "Alexander", "Mikhail", "Sergei", "Natalia", "Igor", "Boris", "Olga"]
    last_names = ["Bout", "Rostova", "Volkov", "Petrov", "Sokolov", "Popov", "Kuznetsov", "Smirnov", "Ivanov", "Vasiliev"]
    countries = ["Panama", "Cyprus", "British Virgin Islands", "Marshall Islands", "Cayman Islands", "Seychelles", "UAE", "Switzerland"]
    company_prefixes = ["AeroVanguard", "Helios", "Caspian", "Titan", "Krypton", "Apex", "Zenith", "Orion", "Nexus", "Vanguard"]
    company_suffixes = ["Logistics Ltd", "Energy Trading Corp", "Merchant Fleet Co", "Cyber Defense LLC", "Transoceanic Shipping", "Holdings Inc"]

    actor_uris = []
    company_uris = []

    # 1. Synthesize Threat Actors (150+)
    for i in range(1, num_actors + 1):
        actor_uri = THREAT[f"Actor_{i:04d}"]
        actor_uris.append(actor_uri)
        name = f"{random.choice(first_names)} {random.choice(last_names)}"
        alias = f"Operator_{i}"

        g.add((actor_uri, RDF.type, THREAT.ThreatActor))
        g.add((actor_uri, RDFS.label, Literal(name)))
        g.add((actor_uri, THREAT.aliasName, Literal(alias)))
        g.add((actor_uri, CCO.has_clearance_level, Literal("SECRET")))

    # 2. Synthesize Front Companies (512+)
    for i in range(1, num_companies + 1):
        company_uri = THREAT[f"FrontCompany_{i:04d}"]
        company_uris.append(company_uri)
        comp_name = f"{random.choice(company_prefixes)} {random.choice(company_suffixes)} #{i}"
        country = random.choice(countries)
        reg_id = f"REG-{random.randint(10000, 99999)}"

        g.add((company_uri, RDF.type, THREAT.FrontCompany))
        g.add((company_uri, RDFS.label, Literal(comp_name)))
        g.add((company_uri, THREAT.sanctionID, Literal(reg_id)))
        g.add((company_uri, THREAT.jurisdiction, Literal(country)))

        # Assign owner actor
        owner_actor = random.choice(actor_uris)
        g.add((owner_actor, THREAT.associatedWith, company_uri))
        g.add((company_uri, THREAT.has_agent, owner_actor))

    # 3. Synthesize Money Transfers (350+)
    for i in range(1, num_transfers + 1):
        transfer_uri = THREAT[f"Transfer_{i:04d}"]
        sender = random.choice(company_uris)
        receiver = random.choice(company_uris)
        while receiver == sender:
            receiver = random.choice(company_uris)

        amount = round(random.uniform(50000.0, 5000000.0), 2)

        g.add((transfer_uri, RDF.type, THREAT.MoneyTransfer))
        g.add((transfer_uri, THREAT.has_sender, sender))
        g.add((transfer_uri, THREAT.has_receiver, receiver))
        g.add((transfer_uri, THREAT.hasAmount, Literal(amount, datatype=XSD.decimal)))
        g.add((transfer_uri, THREAT.hasCurrency, Literal("USD")))

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    g.serialize(destination=output_path, format="turtle")
    triple_count = len(g)
    print(f"[Scale Synthesizer] Generated {triple_count} RDF triples in {output_path}")
    return triple_count


if __name__ == "__main__":
    current_dir = os.path.dirname(os.path.abspath(__file__))
    output_file = os.path.join(current_dir, "..", "ontology", "threat_model_large.ttl")
    generate_large_scale_knowledge_graph(output_file)
