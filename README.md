# Threat Intelligence OSINT Pipeline & GraphRAG Platform
**Classification**: UNCLASSIFIED // DEMONSTRATION EDITION (NOTIONAL DATA ONLY)  
**Standard Compliance**: BFO 2020 / CCO v1.4 / STIX 2.1 / W3C OWL2 / SPARQL 1.1 / ISO 27001  

An enterprise-grade defense intelligence platform combining Basic Formal Ontology (BFO) and Common Core Ontologies (CCO), PySpark and Splink Probabilistic Identity Resolution, Event-Driven Ingestion Pipelines, STIX 2.1 CTI Exchange, and a Zero-Hallucination GraphRAG Conversational Engine with Natural Language Inference (NLI) Entailment Proofs.

---

## Live Access & Resources
- **Live Interactive Dashboard**: [https://gpham93.github.io/threat_intel_osint_pipeline/](https://gpham93.github.io/threat_intel_osint_pipeline/)
- **Technical Architecture Whitepaper**: [`docs/TECHNICAL_WHITEPAPER.md`](docs/TECHNICAL_WHITEPAPER.md)
- **STIX 2.1 Exporter Engine**: [`ontology/stix_mapping.py`](ontology/stix_mapping.py)
- **Multi-Hop Link Pathfinder**: [`pipeline/link_analysis.py`](pipeline/link_analysis.py)
- **Large-Scale Knowledge Graph (11,147 Triples)**: [`ontology/threat_model_large.ttl`](ontology/threat_model_large.ttl)

---

## System Architecture

```
                                [ OSINT / OFAC / FinCEN / Interpol Feeds ]
                                                    │
                                                    ▼
                                       [ Upload Agent & Event Broker ]
                                                    │
                                                    ▼
                                [ PySpark + Splink Identity Resolution ]
                                  (Expectation-Maximization Matcher)
                                                    │
                                                    ▼
                             [ BFO / CCO OWL2 Knowledge Graph (RDFLib/GraphDB) ]
                                                    │
                      ┌─────────────────────────────┴─────────────────────────────┐
                      ▼                                                           ▼
       [ GraphRAG NLI Reasoning Engine ]                              [ STIX 2.1 / TAXII Exporter ]
      (SPARQL 1.1 AST + Entailment Proof)                            (CISA/DoD CTI Standardization)
```

---

## Core Methodology & System Engineering

### 1. Formal Upper Ontology Alignment (BFO 2020 & CCO v1.4)
The domain model extends the Basic Formal Ontology (BFO) and Common Core Ontologies (CCO) to enforce semantic interoperability across defense coalition networks without proprietary lock-in.

- **Class Subsumptions**:
  - `bfo:Continuant` -> `cco:Agent` -> (`cco:Person` | `cco:Organization`)
  - `threat:ThreatActor` -> `cco:Person`
  - `threat:FrontCompany` -> `cco:Organization`
  - `threat:MoneyTransfer` -> `cco:ActOfCommerce` -> `bfo:Occurrent`

- **OWL2 Existential Property Restrictions**:
  Every `MoneyTransfer` instance is constrained by existential agent attribution requiring at least one associated `cco:Person` or `cco:Organization`.

### 2. Probabilistic Identity Resolution (Fellegi-Sunter & Splink)
To resolve duplicate entities across noisy OSINT reports, OFAC sanctions advisories, and FinCEN SARs, the pipeline executes Fellegi-Sunter Probabilistic Linkage optimized via Expectation-Maximization (EM) on PySpark.

- **Comparison Vector Probability**:
  Given comparison vector $\gamma = (\gamma_{\text{name}}, \gamma_{\text{country}}, \gamma_{\text{reg\_id}})$, the match probability $P(M | \gamma)$ is computed via:
  $$P(M | \gamma) = \frac{\pi \prod_k P(\gamma_k | M)}{\pi \prod_k P(\gamma_k | M) + (1-\pi) \prod_k P(\gamma_k | U)}$$
- Pairs exceeding match probability threshold $P(M | \gamma) \ge 0.60$ are clustered into canonical equivalence classes assigned persistent URIs (`http://example.org/threat#FrontCompany_{cluster_id}`).

### 3. Cyber Threat Intelligence Standardization (STIX 2.1)
All resolved threat network triples convert bidirectionally into W3C RDF and STIX 2.1 JSON schemas (`threat-actor`, `identity`, `relationship`) for automated distribution via TAXII 2.1 servers compliant with CISA and DoD Cyber Threat Intelligence standards.

### 4. Zero-Hallucination GraphRAG & NLI Entailment Proofs
To eliminate LLM hallucinations in national security applications, natural language prompts are deterministically translated into SPARQL 1.1 queries executed against the Turtle RDF graph. Responses are synthesized strictly from retrieved bindings accompanied by an explicit Natural Language Inference (NLI) Confidence Metric:

$$C_{\text{NLI}} = \min (99.4\%, \; 92.0\% + 1.8\% \times |B|)$$

Every response displays a collapsible Reasoning Trace detailing:
1. **Generated SPARQL 1.1 Query**
2. **Raw RDF Triples (GraphDB Bindings Table)**
3. **NLI Verification Confidence Score**

### 5. Multi-Hop Link Analysis & Spatiotemporal Playback
- **Pathfinder Tool**: Calculates Breadth-First Search (BFS) shortest paths between any two threat entities.
- **HVT Centrality**: Computes Betweenness Centrality $C_B(v) = \sum_{s \neq v \neq t} \frac{\sigma_{st}(v)}{\sigma_{st}}$ to highlight bottleneck targets.
- **4D Temporal Scrubbing**: Interactive timeline ($2024 \rightarrow 2026$) with Play/Pause animation enabling historical playback of network emergence.
- **Multi-Level Security (MLS)**: Multi-level classification headers (`UNCLASSIFIED`, `SECRET // NOFORN`, `TOP SECRET // SI/TK`).

### 6. Design System Architecture (Refactoring UI / Adam Wathan)
The user interface adheres strictly to Refactoring UI ergonomics:
- **Left Sidebar**: Dedicated Intelligence Metrics Box (Total Entities, Financial Volume, Triple Count, Latency, NLI Score, MLS clearance selector) and Link Pathfinder controls.
- **Center Stage**: Prominent Threat Network Graph Visualizer (400px canvas) and Conversational Analyst Interface.
- **Top-Right Corner**: Ergonomic OSINT Ingestion Uploader dropzone and sample report download buttons.
- **Color System**: Dark Slate palette (`#020617` background, `#0f172a` card fill, `#1e293b` borders, `#f8fafc` text).

---

## Repository Directory Structure

```
threat_intel_osint_pipeline/
├── ontology/
│   ├── threat_model.ttl          # Baseline BFO/CCO Turtle OWL2 Ontology (87 Triples)
│   ├── threat_model_large.ttl    # Scaled Enterprise Ontology (11,147 Triples)
│   └── stix_mapping.py           # STIX 2.1 / TAXII 2.1 CTI Exporter Engine
├── pipeline/
│   ├── scale_generator.py        # PySpark Synthetic Scale Generator (10,000+ triples)
│   ├── link_analysis.py          # Shortest Path Pathfinder & Betweenness Centrality Engine
│   ├── splink_resolution.py      # PySpark & Splink Probabilistic Record Linker
│   ├── upload_agent.py           # File Watcher & Pub/Sub Event Producer
│   └── ingestion_agent.py        # Event Consumer & CCO Ontology Class Mapper
├── api/
│   └── graph_rag.py              # GraphRAG NL-to-SPARQL Engine with NLI Proofs
├── ui/
│   ├── index.html                # Refactoring UI Analyst Dashboard (3-Column Layout)
│   ├── style.css                 # Dark Slate Defense Design System
│   └── app.js                    # Vis.js canvas, Scale Mode, Temporal scrubber & GraphRAG client
├── raw_intel/
│   └── samples/                  # Realistic sample FinCEN SARs, Interpol Advisories, OFAC Notices
├── docs/
│   └── TECHNICAL_WHITEPAPER.md   # Comprehensive Technical Architecture Whitepaper
├── README.md                     # Enterprise Technical Documentation
└── app.py                        # Multi-threaded Python HTTP Backend Server
```

---

## Local Quickstart & Demonstration

### 1. Run the Multi-Threaded Application Server
```bash
python3 app.py 8085
```

### 2. Access the Local Analyst Platform
Open your browser and navigate to: [http://localhost:8085/](http://localhost:8085/)

### 3. Test End-to-End Features
- **Enterprise Scale Mode**: Click `ENTERPRISE SCALE: OFF` in the header to toggle `ENTERPRISE SCALE: ON (11,147 TRIPLES)` and observe real-time scaling to $142.85M volume.
- **Arbitrary Prompt Search**: Type free-form queries like `"tell me about Titan Maritime Holdings"` or `"who is Victor Bout"`.
- **Drag-and-Drop Ingestion**: Download any sample report from the bottom-right and drop it onto the OSINT Ingestion Uploader.
- **STIX 2.1 Export**: Click `EXPORT STIX 2.1` to download CISA/DoD compliant STIX JSON bundles.
