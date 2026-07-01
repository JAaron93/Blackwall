---
name: gemini-documentation-router
description: >-
  Mandatory routing logic for researching documentation. Use this skill whenever
  the user asks to research, find syntax, troubleshoot errors, or look up
  documentation for Gemini models, ADK 2.0, Google Cloud, agents-cli, or third-party libraries.
---

# Documentation Routing Protocol
You are operating in a tri-MCP environment equipped with `gemini-api-docs-mcp`, `google-developer-knowledge`, and `context7`. To prevent tool use confusion and token exhaustion, you must strictly adhere to the following deterministic routing hierarchy.

## 1. Local Agent Skills (Priority 1)
Before invoking external MCP tools, check if the required syntax is already available in your locally bundled `google-agents-cli` skills. Use `google-agents-cli-adk-code` for immediate, in-context guidance on ADK 2.0 graph structures, tool definitions, and callbacks.

## 2. Gemini API Docs MCP 
* **Available Tools:** `search_documentation`, `get_capability_page`
* **Authorized Domain:** `ai.google.dev`
* **Execution Rules:** Strictly reserve this server for core LLM generation. Use it to retrieve bleeding-edge prompting techniques, basic `google-genai` SDK initialization, structured output syntax, and model capabilities.

## 3. Google Developer Knowledge MCP 
* **Available Tools:** `search_documents`, `get_document`, `batch_get_documents`
* **Authorized Domain:** Google Cloud, Vertex AI, Firebase, Android, Agent Registry
* **Execution Rules:** Mandate the use of this server whenever the domain shifts to infrastructure or framework deployment. Use this to troubleshoot IAM permissions, configure Cloud Trace observability spans, manage ADK 2.0 stateful workflows, and query Cloud Run orchestration patterns.

## 4. Context7 MCP
* **Available Tools:** `resolve-library-id`, `query-docs`
* **Authorized Domain:** External frameworks, third-party libraries, and non-Google dependencies
* **Execution Rules:** Explicitly use this server as the authoritative source for all non-Google syntax. Use this to retrieve version-specific API documentation and code examples when deploying applications on FastAPI Cloud Beta, writing React components, or configuring any external packages or ORMs.

## 5. Negative Constraints & Overlap Resolution
* **FORBIDDEN:** Do not use `gemini-api-docs-mcp` for any queries related to Google Cloud infrastructure or third-party libraries. Its local database lacks this information.
* **FORBIDDEN:** Do not use `context7` to search for Google Cloud architecture or core Gemini SDK syntax.
* **SEQUENTIAL EXECUTION:** If a task spans domains (e.g., deploying a FastAPI container to Google Cloud Run), query the servers sequentially. Use `context7` for the framework routing syntax first, then use `google-developer-knowledge` for the Cloud Run deployment architecture.