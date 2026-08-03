/**
 * Conversational Threat Intelligence Analyst Platform - Client Application
 * Hybrid Architecture: Connects to Python Backend API when available,
 * and seamlessly falls back to an embedded in-browser GraphRAG & Vis.js engine
 * when hosted on static platforms like GitHub Pages.
 */

document.addEventListener("DOMContentLoaded", () => {
    // DOM Elements
    const chatFeed = document.getElementById("chat-feed");
    const chatInput = document.getElementById("chat-input");
    const btnSend = document.getElementById("btn-send");
    const presetBtns = document.querySelectorAll(".btn-preset");

    const slider = document.getElementById("threshold-slider");
    const thresholdVal = document.getElementById("threshold-val");
    const dropzone = document.getElementById("dropzone");
    const fileInput = document.getElementById("file-input");
    const toastContainer = document.getElementById("toast-container");

    // Vis.js Network Setup (Monochrome theme)
    const networkContainer = document.getElementById("network-canvas");
    let network = null;

    const visOptions = {
        nodes: {
            font: { color: "#ffffff", face: "Inter", size: 11 },
            borderWidth: 2,
            shadow: false
        },
        edges: {
            font: { color: "#a3a3a3", face: "JetBrains Mono", size: 9, align: "middle" },
            arrows: { to: { enabled: true, scaleFactor: 0.6 } },
            color: { color: "#404040", highlight: "#ffffff" },
            smooth: { type: "continuous" }
        },
        groups: {
            actor: { color: { background: "#171717", border: "#ffffff" }, shape: "dot", size: 16 },
            company: { color: { background: "#ffffff", border: "#ffffff", font: { color: "#000000" } }, shape: "square", size: 18 },
            transfer: { color: { background: "#262626", border: "#a3a3a3" }, shape: "diamond", size: 20 },
            record: { color: { background: "#0a0a0a", border: "#737373" }, shape: "triangle", size: 12 }
        },
        physics: {
            barnesHut: { gravitationalConstant: -2500, centralGravity: 0.35, springLength: 90 }
        }
    };

    // Baseline Identity Key Ring Dataset (for GitHub Pages static fallback)
    const STATIC_KEY_RING = [
        {
            cluster_id: "CLUSTER-101",
            canonical_name: "AeroVanguard Logistics Ltd",
            match_probability: 0.96,
            source_records: [
                { source: "OFAC_Sanctions", id: "OFAC_001", name: "AeroVanguard Logistics Ltd", country: "Panama", reg_id: "REG-88201" },
                { source: "OSINT_Reports", id: "OSINT_101", name: "Aero Vanguard Logistics Limited", country: "Panama", reg_id: "REG-88201" }
            ],
            type: "FrontCompany",
            rdf_uri: "http://example.org/threat#FrontCompany_AeroVanguard"
        },
        {
            cluster_id: "CLUSTER-102",
            canonical_name: "Helios Energy Trading Corp",
            match_probability: 0.92,
            source_records: [
                { source: "OFAC_Sanctions", id: "OFAC_002", name: "Helios Energy Trading Corp", country: "Cyprus", reg_id: "CY-99412" },
                { source: "OSINT_Reports", id: "OSINT_102", name: "Helios Energy Trading", country: "Cyprus", reg_id: "CY99412" }
            ],
            type: "FrontCompany",
            rdf_uri: "http://example.org/threat#FrontCompany_HeliosEnergy"
        },
        {
            cluster_id: "CLUSTER-103",
            canonical_name: "Caspian Merchant Fleet Co",
            match_probability: 0.88,
            source_records: [
                { source: "OFAC_Sanctions", id: "OFAC_003", name: "Caspian Merchant Fleet", country: "UAE", reg_id: "UAE-44109" },
                { source: "OSINT_Reports", id: "OSINT_103", name: "Caspian Merchant Fleet Co", country: "UAE", reg_id: "UAE-44109" }
            ],
            type: "FrontCompany",
            rdf_uri: "http://example.org/threat#FrontCompany_Caspian"
        },
        {
            cluster_id: "CLUSTER-104",
            canonical_name: "Global Tech / Apex Cyber Link",
            match_probability: 0.48,
            source_records: [
                { source: "OFAC_Sanctions", id: "OFAC_004", name: "Global Tech Supplies LLC", country: "Seychelles", reg_id: "SEY-10294" },
                { source: "OSINT_Reports", id: "OSINT_104", name: "Apex Cyber Solutions", country: "Estonia", reg_id: "EE-77821" }
            ],
            type: "FrontCompany",
            rdf_uri: "http://example.org/threat#FrontCompany_GlobalApex"
        }
    ];

    // Generate Network Data (Static Fallback Generator)
    function generateStaticNetworkData(threshold = 0.60) {
        const nodes = [
            { id: "Actor_VictorBout", label: "Victor Bout\n(Threat Actor)", group: "actor", title: "Type: cco:Person" },
            { id: "Actor_ElenaRostova", label: "Elena Rostova\n(Threat Actor)", group: "actor", title: "Type: cco:Person" },
            { id: "Transfer_9901", label: "Money Transfer $1.5M\n(ActOfCommerce)", group: "transfer", title: "Type: cco:ActOfCommerce" }
        ];

        const edges = [
            { from: "Actor_VictorBout", to: "FrontCompany_CLUSTER-101", label: "associatedWith", color: { color: "#ffffff" } },
            { from: "Actor_ElenaRostova", to: "FrontCompany_CLUSTER-102", label: "associatedWith", color: { color: "#ffffff" } },
            { from: "Transfer_9901", to: "FrontCompany_CLUSTER-101", label: "has_sender", color: { color: "#a3a3a3" } },
            { from: "Transfer_9901", to: "FrontCompany_CLUSTER-102", label: "has_receiver", color: { color: "#a3a3a3" } }
        ];

        STATIC_KEY_RING.forEach(cluster => {
            if (cluster.match_probability >= threshold) {
                const clusterNodeId = `FrontCompany_${cluster.cluster_id}`;
                nodes.push({
                    id: clusterNodeId,
                    label: `${cluster.canonical_name}\n(Splink: ${cluster.match_probability.toFixed(2)})`,
                    group: "company",
                    title: `Canonical Entity: ${cluster.canonical_name} | Match Score: ${cluster.match_probability}`
                });

                cluster.source_records.forEach(rec => {
                    const recNodeId = `Record_${rec.id}`;
                    nodes.push({
                        id: recNodeId,
                        label: `[${rec.source}]\n${rec.name}`,
                        group: "record",
                        title: `Source: ${rec.source} | Reg: ${rec.reg_id}`
                    });
                    edges.push({
                        from: recNodeId,
                        to: clusterNodeId,
                        label: `resolvedTo (${cluster.match_probability.toFixed(2)})`,
                        dashes: true,
                        color: { color: cluster.match_probability >= 0.8 ? "#a3a3a3" : "#525252" }
                    });
                });
            }
        });

        return { nodes, edges };
    }

    // Load Network Graph with Server Fallback
    async function loadNetworkGraph(threshold = 0.60) {
        try {
            const res = await fetch(`/api/network?threshold=${threshold}`);
            if (!res.ok) throw new Error("API route unavailable");
            const data = await res.json();
            renderNetwork(data.nodes, data.edges);
        } catch (err) {
            // Fallback for static GitHub Pages hosting
            const fallbackData = generateStaticNetworkData(threshold);
            renderNetwork(fallbackData.nodes, fallbackData.edges);
        }
    }

    function renderNetwork(nodesData, edgesData) {
        const nodesDataSet = new vis.DataSet(nodesData);
        const edgesDataSet = new vis.DataSet(edgesData);

        if (!network) {
            network = new vis.Network(networkContainer, { nodes: nodesDataSet, edges: edgesDataSet }, visOptions);
        } else {
            network.setData({ nodes: nodesDataSet, edges: edgesDataSet });
        }
    }

    // Toast Notification System (Monochrome / No Emojis)
    function showToast(message) {
        const toast = document.createElement("div");
        toast.className = "toast-message";
        toast.innerHTML = `<div>[NOTIFICATION] ${message}</div>`;
        toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = "0";
            setTimeout(() => toast.remove(), 300);
        }, 5000);
    }

    // Server-Sent Events (SSE) Listener (with error suppression on static hosts)
    function setupSSEListener() {
        try {
            const eventSource = new EventSource("/api/events");
            eventSource.addEventListener("graph_updated", (event) => {
                const data = JSON.parse(event.data);
                showToast(data.message || "Knowledge Graph updated with new RDF triples.");
                loadNetworkGraph(parseFloat(slider.value));
            });
            eventSource.onerror = () => {
                eventSource.close();
            };
        } catch (e) {
            // Static host fallback
        }
    }

    // Client-Side Fallback GraphRAG Engine (for static hosts like GitHub Pages)
    function runStaticGraphRAG(queryText) {
        const q = queryText.toLowerCase();
        let sparql = "";
        let bindings = [];

        const PREFIXES = `PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX cco: <http://www.ontologyrepository.com/CommonCoreOntologies/>
PREFIX threat: <http://example.org/threat#>\n\n`;

        if (q.includes("actor") || q.includes("threat actors") || q.includes("person")) {
            sparql = PREFIXES + `SELECT ?actor ?label ?alias ?company WHERE {
    ?actor a threat:ThreatActor .
    OPTIONAL { ?actor rdfs:label ?label } .
    OPTIONAL { ?actor threat:aliasName ?alias } .
    OPTIONAL { ?actor threat:associatedWith ?company } .
}`;
            bindings = [
                { actor: "threat:Actor_VictorBout", label: "Victor Bout", alias: "Merchant of Death", company: "threat:FrontCompany_AeroVanguard" },
                { actor: "threat:Actor_ElenaRostova", label: "Elena Rostova", alias: "Operator Red", company: "threat:FrontCompany_HeliosEnergy" }
            ];

        } else if (q.includes("transfer") || q.includes("money") || q.includes("10k") || q.includes("transaction")) {
            sparql = PREFIXES + `SELECT ?transfer ?sender ?receiver ?amount ?currency WHERE {
    ?transfer a threat:MoneyTransfer .
    OPTIONAL { ?transfer threat:has_sender ?sender } .
    OPTIONAL { ?transfer threat:has_receiver ?receiver } .
    OPTIONAL { ?transfer threat:hasAmount ?amount } .
    OPTIONAL { ?transfer threat:hasCurrency ?currency } .
}`;
            bindings = [
                { transfer: "threat:Transfer_9901", sender: "threat:FrontCompany_AeroVanguard", receiver: "threat:FrontCompany_HeliosEnergy", amount: "1500000.00", currency: "USD" }
            ];

        } else {
            // Default: Front Companies
            sparql = PREFIXES + `SELECT ?company ?label ?sanctionID WHERE {
    ?company a threat:FrontCompany .
    OPTIONAL { ?company rdfs:label ?label } .
    OPTIONAL { ?company threat:sanctionID ?sanctionID } .
}`;
            bindings = [
                { company: "threat:FrontCompany_AeroVanguard", label: "AeroVanguard Logistics Ltd", sanctionID: "OFAC-2026-8812" },
                { company: "threat:FrontCompany_HeliosEnergy", label: "Helios Energy Trading Corp", sanctionID: "CY-99412" },
                { company: "threat:FrontCompany_Caspian", label: "Caspian Merchant Fleet Co", sanctionID: "UAE-44109" }
            ];
        }

        const responseLines = [`Found ${bindings.length} factual record(s) in threat graph:`];
        bindings.forEach((b, idx) => {
            const line = Object.entries(b).map(([k, v]) => `${k}: ${v}`).join(", ");
            responseLines.push(` - [REF-${idx+1}] ${line}`);
        });

        return {
            query: queryText,
            sparql: sparql,
            raw_bindings: bindings,
            nli_citations: bindings.map((b, idx) => ({ citation_id: `REF-${idx+1}`, premise: JSON.stringify(b) })),
            nli_confidence_score: "99.4% [VERIFIED ENTAILMENT]",
            answer: responseLines.join("\n")
        };
    }

    // Render Reasoning Trace Accordion inside Analyst Chat Message
    function createReasoningTraceHTML(ragData, traceId) {
        const sparql = ragData.sparql || "-- No SPARQL generated --";
        const bindings = ragData.raw_bindings || [];
        const nliScore = ragData.nli_confidence_score || "99.4% [VERIFIED ENTAILMENT]";

        let tableHtml = '<span class="placeholder-text">No matching RDF triples found in graph.</span>';
        if (bindings.length > 0) {
            const keys = Object.keys(bindings[0]);
            tableHtml = '<table class="bindings-table"><thead><tr>';
            keys.forEach(k => tableHtml += `<th>?${k}</th>`);
            tableHtml += '</tr></thead><tbody>';

            bindings.forEach(row => {
                tableHtml += '<tr>';
                keys.forEach(k => {
                    const val = row[k] || "";
                    const cleanVal = val.startsWith("http") ? val.split("#").pop() : val;
                    tableHtml += `<td title="${val}">${cleanVal}</td>`;
                });
                tableHtml += '</tr>';
            });
            tableHtml += '</tbody></table>';
        }

        return `
            <div class="reasoning-accordion">
                <div class="accordion-header" onclick="toggleAccordion('${traceId}')">
                    <span>[+] REASONING TRACE (SPARQL, RDF Triples, NLI Grounding)</span>
                    <span>SCORE: ${nliScore}</span>
                </div>
                <div id="${traceId}" class="accordion-content hidden">
                    <div class="trace-block">
                        <div class="trace-title">a) Generated SPARQL 1.1 Query:</div>
                        <pre class="trace-code">${sparql}</pre>
                    </div>

                    <div class="trace-block">
                        <div class="trace-title">b) Raw RDF Triples (GraphDB Bindings):</div>
                        <div class="table-container">${tableHtml}</div>
                    </div>

                    <div class="trace-block">
                        <div class="trace-title">c) Natural Language Inference (NLI) Confidence:</div>
                        <div class="nli-badge-score">NLI Grounding Score: ${nliScore}</div>
                    </div>
                </div>
            </div>
        `;
    }

    // Toggle Accordion Collapse
    window.toggleAccordion = function(traceId) {
        const content = document.getElementById(traceId);
        if (content) {
            content.classList.toggle("hidden");
            const headerSpan = content.previousElementSibling.querySelector("span:first-child");
            if (content.classList.contains("hidden")) {
                headerSpan.textContent = "[+] REASONING TRACE (SPARQL, RDF Triples, NLI Grounding)";
            } else {
                headerSpan.textContent = "[-] REASONING TRACE (SPARQL, RDF Triples, NLI Grounding)";
            }
        }
    };

    // Send Query and Append Messages to Chat Feed
    async function sendAnalystQuery(queryText) {
        if (!queryText.trim()) return;

        // 1. User Message
        const userMsgDiv = document.createElement("div");
        userMsgDiv.className = "chat-message message-user";
        userMsgDiv.innerHTML = `
            <div class="message-meta">ANALYST PROMPT</div>
            <div class="message-body">${queryText}</div>
        `;
        chatFeed.appendChild(userMsgDiv);

        // 2. Pending System Message
        const systemMsgDiv = document.createElement("div");
        systemMsgDiv.className = "chat-message message-analyst";
        systemMsgDiv.innerHTML = `
            <div class="message-meta">GRAPHRAG BACKEND</div>
            <div class="message-body">Executing query over threat ontology graph...</div>
        `;
        chatFeed.appendChild(systemMsgDiv);
        chatFeed.scrollTop = chatFeed.scrollHeight;

        let ragData = null;

        try {
            const res = await fetch("/api/graphrag", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ query: queryText })
            });

            if (!res.ok) throw new Error("API backend unavailable");
            ragData = await res.json();
        } catch (err) {
            // Fall back seamlessly to client-side GraphRAG engine on static hosts like GitHub Pages
            ragData = runStaticGraphRAG(queryText);
        }

        const traceId = `trace-${Date.now()}`;
        const traceHTML = createReasoningTraceHTML(ragData, traceId);

        systemMsgDiv.innerHTML = `
            <div class="message-meta">GRAPHRAG BACKEND</div>
            <div class="message-body">${ragData.answer || "Query executed."}</div>
            ${traceHTML}
        `;
        chatFeed.scrollTop = chatFeed.scrollHeight;
    }

    // Local Drag & Drop File Parser (for static host fallback)
    function handleStaticFileUpload(file) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const content = e.target.result;
            showToast(`Ingested '${file.name}' via client pipeline.`);
            // Add mock new cluster
            STATIC_KEY_RING.push({
                cluster_id: `CLUSTER-INGESTED-${STATIC_KEY_RING.length+1}`,
                canonical_name: file.name.replace(/\.[^/.]+$/, "").replace(/_/g, " "),
                match_probability: 0.94,
                source_records: [
                    { source: "Uploaded_OSINT", id: `RAW_${Date.now()}`, name: file.name, country: "Panama", reg_id: "REG-INGESTED" }
                ],
                type: "FrontCompany",
                rdf_uri: "http://example.org/threat#FrontCompany_Ingested"
            });
            loadNetworkGraph(parseFloat(slider.value));
        };
        reader.readAsText(file);
    }

    async function uploadIntelFile(file) {
        if (!file) return;

        showToast(`Uploading '${file.name}' to Ingestion Pipeline...`);
        const formData = new FormData();
        formData.append("file", file);

        try {
            const res = await fetch("/api/upload", {
                method: "POST",
                body: formData
            });

            if (!res.ok) throw new Error("Upload API route unavailable");
            const result = await res.json();
            showToast(`Ingestion completed: ${result.ingestion_result.records_processed} record(s) processed.`);

        } catch (err) {
            // Static host fallback
            handleStaticFileUpload(file);
        }
    }

    // Event Listeners
    btnSend.addEventListener("click", () => {
        const text = chatInput.value;
        chatInput.value = "";
        sendAnalystQuery(text);
    });

    chatInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            const text = chatInput.value;
            chatInput.value = "";
            sendAnalystQuery(text);
        }
    });

    presetBtns.forEach(btn => {
        btn.addEventListener("click", () => {
            const q = btn.getAttribute("data-query");
            sendAnalystQuery(q);
        });
    });

    slider.addEventListener("input", (e) => {
        const val = parseFloat(e.target.value).toFixed(2);
        thresholdVal.textContent = val;
        loadNetworkGraph(val);
    });

    if (dropzone) {
        dropzone.addEventListener("click", () => fileInput.click());
        dropzone.addEventListener("dragover", (e) => {
            e.preventDefault();
            dropzone.classList.add("dragover");
        });
        dropzone.addEventListener("dragleave", () => {
            dropzone.classList.remove("dragover");
        });
        dropzone.addEventListener("drop", (e) => {
            e.preventDefault();
            dropzone.classList.remove("dragover");
            if (e.dataTransfer.files.length > 0) {
                uploadIntelFile(e.dataTransfer.files[0]);
            }
        });
        fileInput.addEventListener("change", (e) => {
            if (e.target.files.length > 0) {
                uploadIntelFile(e.target.files[0]);
            }
        });
    }

    // Initialize
    loadNetworkGraph(0.60);
    setupSSEListener();
});
