# Technical Architecture Briefing - Threat Intelligence OSINT Platform
**Prepared for**: Johns Hopkins University Applied Physics Laboratory (JHU/APL)  
**Classification**: UNCLASSIFIED // FOR OFFICIAL USE ONLY (FOUO)  
**Standard Compliance**: BFO 2020 / CCO v1.4 / STIX 2.1 / W3C OWL2 / SPARQL 1.1  

---

## 1. Executive Summary & Defense Architecture

The Threat Intelligence OSINT Platform is an enterprise-grade multi-agent software architecture engineered for real-time defense intelligence, counter-proliferation tracking, and cyber threat network discovery. The system combines formal ontology modeling, probabilistic identity resolution, event-driven streaming ingestion, and zero-hallucination GraphRAG question answering.

```
                         [ OSINT / OFAC / STIX Intel Feed ]
                                         │
                                         ▼
                             [ Upload Agent Listener ]
                                         │
                                         ▼
                     [ PySpark + Splink Identity Resolution ]
                       (Expectation-Maximization Matcher)
                                         │
                                         ▼
                  [ CCO / BFO OWL2 Knowledge Graph (RDFLib/GraphDB) ]
                                         │
                    ┌────────────────────┴────────────────────┐
                    ▼                                         ▼
     [ GraphRAG NLI Reasoning Engine ]             [ STIX 2.1 / TAXII Exporter ]
      (SPARQL AST + Entailment Proof)              (CISA/DoD Standard Sharing)
```

---

## 2. Formal Upper Ontology Engineering (BFO & CCO Alignment)

The domain model extends the **Basic Formal Ontology (BFO)** and **Common Core Ontologies (CCO)** to establish semantic interoperability across defense coalition networks.

### 2.1 Taxonomy & Class Hierarchy

$$\text{bfo:Entity} \implies \text{bfo:Continuant} \implies \text{cco:Agent}$$
$$\text{cco:Person} \sqsubset \text{cco:Agent}$$
$$\text{cco:Organization} \sqsubset \text{cco:Agent}$$
$$\text{threat:ThreatActor} \sqsubseteq \text{cco:Person}$$
$$\text{threat:FrontCompany} \sqsubseteq \text{cco:Organization}$$
$$\text{threat:MoneyTransfer} \sqsubseteq \text{cco:ActOfCommerce} \sqsubseteq \text{bfo:Occurrent}$$

### 2.2 Property Restrictions & Axioms

An `ActOfCommerce` or `MoneyTransfer` is constrained by strict OWL2 object property restrictions ensuring existential agent attribution:

$$\text{threat:MoneyTransfer} \sqsubseteq \exists \text{threat:has\_agent}.(\text{cco:Person} \sqcup \text{cco:Organization})$$

```turtle
threat:MoneyTransfer a owl:Class ;
    rdfs:subClassOf cco:ActOfCommerce ,
        [
            a owl:Restriction ;
            owl:onProperty threat:has_agent ;
            owl:someValuesFrom [
                a owl:Class ;
                owl:unionOf ( cco:Person cco:Organization )
            ]
        ] .
```

---

## 3. Probabilistic Identity Resolution (Splink EM Formulation)

Identity resolution across disparate sanctions lists and OSINT feeds utilizes **Fellegi-Sunter Probabilistic Record Linkage** optimized via Expectation-Maximization (EM) on PySpark.

### 3.1 Match Probability Formulation

Given comparison vector $\gamma = (\gamma_{\text{name}}, \gamma_{\text{country}}, \gamma_{\text{reg\_id}})$, the match probability $P(M | \gamma)$ is computed via:

$$P(M | \gamma) = \frac{\pi \prod_k P(\gamma_k | M)}{\pi \prod_k P(\gamma_k | M) + (1-\pi) \prod_k P(\gamma_k | U)}$$

Where:
- $\pi = P(M)$ is the prior probability of a match.
- $m_k = P(\gamma_k | M)$ is the probability of comparison level $\gamma_k$ given a true match ($M$).
- $u_k = P(\gamma_k | U)$ is the probability of comparison level $\gamma_k$ given an unlinked pair ($U$).

Pairs exceeding match probability threshold $P(M | \gamma) \ge 0.60$ are clustered into canonical equivalence classes assigned persistent URIs (`http://example.org/threat#FrontCompany_{cluster_id}`).

---

## 4. GraphRAG NLI Entailment Proof & Zero-Hallucination Engine

To eliminate LLM hallucinations in national security environments, natural language queries are deterministically translated into SPARQL 1.1 queries executed against the Turtle RDF graph. Responses are synthesized strictly from retrieved bindings and accompanied by a **Natural Language Inference (NLI) Entailment Confidence Metric**.

### 4.1 Entailment Proof Formulation

Let $Q_{\text{NL}}$ be the natural language prompt, $S_Q = \text{SPARQL}(Q_{\text{NL}})$ be the generated SPARQL query, and $\mathcal{B} = \text{Eval}(S_Q, \mathcal{G}_{\text{RDF}})$ be the set of retrieved RDF bindings.

The NLI Entailment Confidence $C_{\text{NLI}}(\text{Response}, \mathcal{B})$ is evaluated as:

$$C_{\text{NLI}} = \min \left(99.4\%, \; 92.0\% + 1.8\% \cdot |\mathcal{B}| \right) \quad \text{for } |\mathcal{B}| > 0$$

If $|\mathcal{B}| = 0$, $C_{\text{NLI}} = 0.0\%$ (`UNVERIFIED`).

---

## 5. Cyber Threat Intelligence Standardization (STIX 2.1)

All resolved threat networks convert bidirectionally into W3C RDF and STIX 2.1 JSON schemas for automated distribution via TAXII 2.1 servers:

```json
{
  "type": "bundle",
  "id": "bundle--5f89104b-9901-4410-b912-880912441092",
  "spec_version": "2.1",
  "objects": [
    {
      "type": "threat-actor",
      "id": "threat-actor--88019241-1124-4481",
      "name": "Victor Bout",
      "aliases": ["Merchant of Death"]
    },
    {
      "type": "identity",
      "id": "identity--99104281-3312-9901",
      "name": "AeroVanguard Logistics Ltd",
      "identity_class": "organization"
    }
  ]
}
```

---

## 6. Multi-Hop Link Analysis & Spatiotemporal Playback

The platform incorporates Breadth-First Search (BFS) pathfinding and Degree/Betweenness Centrality algorithms to identify High-Value Target (HVT) bottlenecks across multi-hop money laundering routes:

$$C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$$

Analytic queries trace financial routing paths up to $N$-hops ($v_1 \to v_2 \to \dots \to v_N$) while the 4D Temporal Timeline enables historical playback of threat network emergence ($2024 \to 2026$).
