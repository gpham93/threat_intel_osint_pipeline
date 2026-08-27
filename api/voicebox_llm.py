"""
Semantic LLM Engine for Threat Intelligence OSINT Pipeline
Implements Multi-Turn Conversational NL-to-SPARQL & Structured Narrative Briefing Synthesis:
1. Dynamic BFO/CCO Schema Context & Entity Injection
2. NL-to-SPARQL 1.1 Compilation via Gemini 2.5 Flash / Pro & OpenAI GPT-4o
3. Multi-Turn Coreference Resolution & Conversational State Tracking
4. Cohesive Structured Narrative Intelligence Briefing Synthesis
"""

import os
import json
import re
import urllib.request
import urllib.error
from typing import Dict, List, Any, Optional, Tuple


class SemanticLLMEngine:
    """
    Production LLM Engine for conversational Knowledge Graph interaction.
    Translates analyst natural language prompts into precise SPARQL 1.1 queries,
    and synthesizes cohesive, structured executive paragraphs from graph facts.
    """

    def __init__(self, model_name: Optional[str] = None):
        self.model_name = model_name
        self.gemini_api_key = os.environ.get("GEMINI_API_KEY", "").strip()
        self.openai_api_key = os.environ.get("OPENAI_API_KEY", "").strip()

    def set_api_keys(self, gemini_key: Optional[str] = None, openai_key: Optional[str] = None):
        if gemini_key:
            self.gemini_api_key = gemini_key.strip()
        if openai_key:
            self.openai_api_key = openai_key.strip()

    def _call_gemini_api(self, prompt: str, system_instruction: str, model: Optional[str] = None, api_key: Optional[str] = None) -> str:
        """Invokes Google Gemini REST API."""
        key = api_key or self.gemini_api_key
        if not key:
            raise ValueError("Gemini API key is not configured. Set GEMINI_API_KEY environment variable or provide key in UI settings.")

        target_model = model or self.model_name or "gemini-2.5-flash"
        # Sanitize model name
        if not target_model.startswith("gemini-"):
            target_model = "gemini-2.5-flash"

        url = f"https://generativelanguage.googleapis.com/v1beta/models/{target_model}:generateContent?key={key}"

        payload = {
            "contents": [
                {
                    "parts": [{"text": prompt}]
                }
            ],
            "systemInstruction": {
                "parts": [{"text": system_instruction}]
            },
            "generationConfig": {
                "temperature": 0.1,
                "maxOutputTokens": 1024
            }
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"}
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts:
                        return parts[0].get("text", "")
        except urllib.error.HTTPError as e:
            # Fallback to gemini-1.5-flash if 2.5 is not accessible with key
            if "2.5" in target_model:
                fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={key}"
                req2 = urllib.request.Request(fallback_url, data=json.dumps(payload).encode("utf-8"), headers={"Content-Type": "application/json"})
                with urllib.request.urlopen(req2, timeout=30) as resp2:
                    data2 = json.loads(resp2.read().decode("utf-8"))
                    candidates2 = data2.get("candidates", [])
                    if candidates2:
                        parts2 = candidates2[0].get("content", {}).get("parts", [])
                        if parts2:
                            return parts2[0].get("text", "")
            raise e
        return ""

    def _call_openai_api(self, prompt: str, system_instruction: str, model: Optional[str] = None, api_key: Optional[str] = None) -> str:
        """Invokes OpenAI ChatGPT REST API."""
        key = api_key or self.openai_api_key
        if not key:
            raise ValueError("OpenAI API key is not configured. Set OPENAI_API_KEY environment variable or provide key in UI settings.")

        target_model = model or self.model_name or "gpt-4o"
        url = "https://api.openai.com/v1/chat/completions"

        payload = {
            "model": target_model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": 1024
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {key}"
            }
        )

        with urllib.request.urlopen(req, timeout=30) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            choices = data.get("choices", [])
            if choices:
                return choices[0].get("message", {}).get("content", "")
        return ""

    def generate_sparql_with_llm(
        self,
        user_query: str,
        schema_context: str,
        conversation_history: Optional[List[Dict[str, str]]] = None,
        provider: str = "gemini-2.5-flash",
        api_key: Optional[str] = None
    ) -> Tuple[str, str]:
        """Translates user natural language query into valid W3C SPARQL 1.1 query with multi-turn history."""
        system_prompt = f"""
You are an expert Semantic Knowledge Graph AI for Threat Intelligence.
Your task is to translate natural language user questions into valid W3C SPARQL 1.1 queries against an RDF Turtle Knowledge Graph.

Ontology Prefixes:
PREFIX rdf: <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX rdfs: <http://www.w3.org/2000/01/rdf-schema#>
PREFIX owl: <http://www.w3.org/2002/07/owl#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
PREFIX bfo: <http://purl.obolibrary.org/obo/>
PREFIX cco: <http://www.ontologyrepository.com/CommonCoreOntologies/>
PREFIX threat: <http://example.org/threat#>

Schema & Known Entities:
{schema_context}

Multi-Turn Coreference Resolution:
If the user asks follow-up questions referencing previous entities (e.g. "which of those companies is in Cyprus?", "how much did the second one transfer?", "what is his clearance?", "plot transfers for them"), use the conversation history to identify the target subject entities and construct the appropriate multi-hop SPARQL query.

Return a valid JSON object with EXACTLY two keys:
1. "sparql": A single valid SPARQL 1.1 SELECT query string.
2. "explanation": A concise 1-2 sentence explanation of the reasoning and traversal strategy.

Example Response format:
{{
  "sparql": "PREFIX threat: <http://example.org/threat#>\\nSELECT ?s ?p ?o WHERE {{ ?s ?p ?o }} LIMIT 25",
  "explanation": "Traversing threat graph for entities."
}}
"""

        user_prompt = f"User Question: {user_query}\n"
        if conversation_history:
            history_str = "\n".join([f"{m['role'].upper()}: {m['content']}" for m in conversation_history[-6:]])
            user_prompt = f"Recent Multi-Turn Conversation History:\n{history_str}\n\n" + user_prompt

        raw_response = ""
        is_openai = "gpt" in provider.lower()
        if is_openai:
            raw_response = self._call_openai_api(user_prompt, system_prompt, model=provider, api_key=api_key)
        else:
            raw_response = self._call_gemini_api(user_prompt, system_prompt, model=provider, api_key=api_key)

        try:
            cleaned = re.sub(r"^```json\s*", "", raw_response.strip(), flags=re.MULTILINE)
            cleaned = re.sub(r"```$", "", cleaned.strip(), flags=re.MULTILINE).strip()
            data = json.loads(cleaned)
            return data.get("sparql", ""), data.get("explanation", "")
        except Exception:
            sparql_match = re.search(r"(SELECT\s+[\s\S]+?)(?:```|$)", raw_response, re.IGNORECASE)
            sparql = sparql_match.group(1) if sparql_match else ""
            return sparql, "Compiled SPARQL query from prompt."

    def synthesize_semantic_response(
        self,
        user_query: str,
        sparql_query: str,
        bindings: List[Dict[str, str]],
        explanation: str,
        provider: str = "gemini-2.5-flash",
        api_key: Optional[str] = None
    ) -> str:
        """Synthesizes a fluent, structured executive narrative briefing from RDF bindings."""
        if not bindings:
            return f"No verified threat intelligence records found in the knowledge graph matching query: '{user_query}'."

        system_prompt = """
You are a senior Defense & Threat Intelligence Analyst.
Synthesize a fluent, structured, and cohesive intelligence briefing in 1 to 2 executive paragraphs.
Do NOT use bullet points or bracketed reference numbers like [REF-1] in the narrative.
Write professional, flowing prose detailing:
- Key threat operatives, aliases, and clearance levels
- Controlled front organizations, jurisdictions, and OFAC sanction identifiers
- Financial transaction routes, dollar amounts, and operational purposes
- Threat network risk analysis and implications
"""

        prompt = f"""
User Question: {user_query}
Query Traversal Strategy: {explanation}
Executed SPARQL:
{sparql_query}

Retrieved Knowledge Graph Facts (RDF Bindings):
{json.dumps(bindings[:25], indent=2)}

Write the structured executive intelligence narrative:
"""

        is_openai = "gpt" in provider.lower()
        if is_openai:
            return self._call_openai_api(prompt, system_prompt, model=provider, api_key=api_key)
        else:
            return self._call_gemini_api(prompt, system_prompt, model=provider, api_key=api_key)
