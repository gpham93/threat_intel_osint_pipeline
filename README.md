# Threat Intelligence OSINT Pipeline & GraphRAG Platform

An enterprise-grade, multi-agent threat intelligence platform combining **BFO / CCO OWL2 Ontologies**, **PySpark & Splink Probabilistic Identity Resolution**, **Event-Driven Ingestion Pipelines**, and a **GraphRAG Conversational Interface** with **NLI Reasoning Trace Guardrails**.

---

## 🏛️ Architecture & Components

```
threat_intel_osint_pipeline/
├── ontology/
│   └── threat_model.ttl          # W3C OWL2 Ontology in Turtle (BFO & CCO compliant)
├── pipeline/
│   ├── splink_resolution.py      # PySpark & Splink probabilistic identity resolution
│   ├── upload_agent.py           # File watcher & Pub/Sub event message producer
│   └── ingestion_agent.py        # Event consumer, ontology mapper & GraphDB store updater
├── api/
│   └── graph_rag.py              # GraphRAG engine with SPARQL translation & NLI citations
├── ui/
│   ├── index.html                # High-contrast monochrome analyst chat dashboard
│   ├── style.css                 # Zero-emoji professional defense theme
│   └── app.js                    # Vis.js network graph, threshold slider & SSE event loop
├── raw_intel/
│   └── samples/                  # Sample OSINT CSV, TXT, and PDF reports for testing
└── app.py                        # Multi-threaded HTTP backend server
```

---

## 🚀 Key Features

1. **CCO & BFO OWL2 Ontology (`/ontology/threat_model.ttl`)**:
   - Built on Basic Formal Ontology (`bfo:`) and Common Core Ontologies (`cco:`).
   - Expresses `threat:ThreatActor` (`cco:Person`), `threat:FrontCompany` (`cco:Organization`), and `threat:MoneyTransfer` (`cco:ActOfCommerce`).
   - OWL2 property restrictions enforcing valid `has_agent` relations.

2. **Probabilistic Identity Resolution (`/pipeline/splink_resolution.py`)**:
   - PySpark pipeline using `splink` for fuzzy matching across sanctions and OSINT reports.
   - Outputs a canonical identity key ring mapped to RDF subject URIs.

3. **Event-Driven Ingestion Pipeline (`/pipeline/upload_agent.py` & `ingestion_agent.py`)**:
   - Drag & Drop file ingestion supporting CSV, TXT, and PDF formats.
   - Real-time Server-Sent Events (SSE) broadcasting `graph_updated` notifications to web clients.

4. **Conversational GraphRAG with NLI Reasoning Trace (`/api/graph_rag.py`)**:
   - Translates natural language analyst prompts into SPARQL 1.1 queries.
   - Provides an expandable **Reasoning Trace** accordion for every response detailing:
     - **a) Generated SPARQL Query**
     - **b) Raw RDF Triples (GraphDB Bindings)**
     - **c) NLI Grounding Confidence Score** (`99.4% [VERIFIED ENTAILMENT]`)

5. **Monochrome Analyst Platform UI**:
   - High-contrast, zero-emoji corporate/defense intelligence styling.
   - Interactive Vis.js threat network visualization with live Splink confidence slider.

---

## 💻 Running the Platform Locally

1. **Start the API Server**:
   ```bash
   python3 app.py 8085
   ```

2. **Open the Analyst Dashboard**:
   Navigate to [http://localhost:8085/](http://localhost:8085/) in your web browser.

3. **Test Ingestion & GraphRAG Queries**:
   - Drag and drop any file from [`raw_intel/samples/`](file:///Users/gabrielpham/.gemini/antigravity-ide/scratch/threat_intel_osint_pipeline/raw_intel/samples/) onto the upload dropzone.
   - Submit analyst prompts like *"Show me all money transfers over $10k linked to Front Company A"* to inspect the NLI Reasoning Trace.
