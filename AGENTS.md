# Blackwall Agent: Project Context & Technical Architecture

## 1. Project Context & Requirements
This project will be submitted to the Kaggle "AI Agents: Intensive Vibe Coding" hackathon under the Freestyle track, which emphasizes the best practices of agent development and deployment.
* **Core Logic:** The agent must function as an autonomous Agentic Firewall that actively intercepts execution flows before they reach external systems or the host OS. It must leverage self-learning loops to dynamically create new defensive skills and decision-activated loops for real-time threat mitigation. (Note: The baseline behavioral system prompt and few-shot examples for the Blackwall Agent have already been finalized. Do not draft or generate them).
* **Tech Stack:** The environment will utilize Google's Agent Development Kit (ADK 2.0) and the Agents CLI, running exclusively in a local sandboxed testing environment to validate defensive logic. Blackwall should be built with Gemini 3-tier models in mind.
* **Deliverables:** The project requires a public GitHub repository structure, a comprehensive README with setup instructions, architectural diagrams, and a final written submission.

## 2. Spec-Driven Development (SDD) Rules
* **Format Optimization:** Write narrative instructions and overarching architectural logic in clean Markdown.
* **Behavior-Driven Specifications:** Draft the technical design using Behavior-Driven Development (BDD). Describe the threat mitigation system's behavior using Gherkin syntax (Scenario / Given / When / Then).
* **Test-Driven Guarantees:** Mandate that all code generation and bug fixes must be preceded by a failing unit test or a reproduction command (e.g., `curl`).

## 3. Security & Guardrail Architecture
The blueprint must explicitly define a "Zero-Trust" safety net:
1. **Hybrid Policy Server:** Design a gating mechanism that intercepts all tool calls. It must include Structural Gating (fast, deterministic YAML rules based on environment roles) and Semantic Gating (an LLM-based referee evaluating intent against plain-language guidelines).
2. **Context Hygiene:** Specify a regex-based `ContextResolver` middleware to dynamically replace sensitive data with generic placeholders (e.g., `[[VARIABLE_NAME]]`), ensuring the agent operates on sterilized data to prevent context hallucination.
3. **Behavioral Evaluation:** Define an evaluation protocol utilizing an LLM-as-judge scoring matrix (0-5) to monitor behavioral drift during security events, focusing on tolerance bands rather than binary test assertions.

## 4. Configured MCP Servers for Blackwall Agent
1. **Google Threat Intelligence (GTI) MCP: The Live Referee**
   * **When it is used:** At the exact millisecond an external tool call is intercepted by the ADK `before_tool_callback`.
   * **The Workflow:** When the Blackwall Agent physically pauses an execution, it uses the GTI server as a real-time referee to query live Indicators of Compromise (IOCs).
   * **The Execution:** If a rogue agent attempts a `curl` command to an unknown IP, Blackwall instantly asks GTI if that IP is flagged on VirusTotal. Furthermore, if Blackwall needs to understand how a specific malicious script behaves in the wild, it can query GTI for live malware campaign data.
   * **The Mitigation:** If GTI returns a positive flag for malicious activity, Blackwall immediately blocks the execution and writes a new "Threat Signature" to its self-learning library to dynamically refine its policies.

2. **`codebase-memory-mcp`: The Structural Graph**
   * **When exactly it is used:** Blackwall triggers graph searches immediately *after* an incoming action is intercepted, but *before* it decides whether the action poses a structural threat to the application's underlying architecture.
   * **The Workflow:** Instead of running massive, context-destroying `grep` searches to understand what a rogue agent is attempting to touch, Blackwall queries the embedded SQLite knowledge graph.
   * **The Execution:** Blackwall uses the graph to trace data flow and identify exactly where untrusted input reaches critical sinks, such as potential SQL injections or command injections.
   * **The Mitigation:** By parsing the Abstract Syntax Tree (AST) to map out hard relationships—like functions, modules, and call chains—Blackwall instantly understands the exact "blast radius" of the targeted code without ingesting thousands of lines of irrelevant code.

**The Interception Synthesis (How They Work Together)**
1. **The Intercept:** A rogue agent attempts to inject an obfuscated payload into a user input field that interacts with a backend function (e.g., `ProcessOrder`). The ADK physically pauses the execution.
2. **The Structural Verification (Graph):** Blackwall asks the `codebase-memory-mcp`, "What is the dependency chain for `ProcessOrder`?". The structural graph instantly reveals that this function pipes directly into a raw database query, flagging it as a highly vulnerable critical sink.
3. **The External Verification (GTI):** Because the graph confirmed the target is a critical sink, Blackwall extracts the payload string and queries the GTI MCP to see if this specific syntax matches known, live exploit campaigns.
4. **The Verdict:** GTI confirms the malicious nature of the payload. Blackwall permanently blocks the execution, writes a Threat Signature detailing the attack vector and the vulnerable call chain, and remains lean and token-efficient.

## 5. Optimization Engineering & API Constraints
Blackwall agent will be running through the paid Gemini API tier to utilize server-side context caching, keeping costs low by preventing the need to resubmit massive context payloads on every loop. 

However, the paid tier of the Gemini API has a cap of 300 Requests Per Minute (RPM). Red-team attackers may run up to 600 RPM. To counter this speed mismatch, we are utilizing **batched API calls** for the interception layer. This introduces critical architectural constraints:

1. **The Asynchronous Batching Bottleneck**
   * **The Callback Lock:** If Blackwall is configured to wait for a "batch" of 5 attacks before querying Gemini, the first 4 Red-Teamer execution threads will hang in a suspended state via the ADK `before_tool_callback`.
   * **The Solution:** An asynchronous batch resolver must be implemented. The webhook listener must hold the paused tool callbacks open in a temporary queue, dispatch the batched JSON payload to the Gemini API, and then carefully map the returning array of verdicts back to their respective paused execution threads, releasing them simultaneously. Define a max wait and flush partial batches so the demo cannot deadlock
2. **Threat Signature Graph Schema (SQLite)**
   * **Schema Design:** The spec must explicitly outline a semantic graph schema defining Nodes (e.g., Attacker Intent, Payload Structure, Target Tool) and Edges (e.g., "SIMILAR_TO", "MITIGATED_BY"). This allows Blackwall to rapidly query the SQLite graph for structurally similar attacks rather than relying on exact string matches.
   * **Concurrency & Bloat Management:** To prevent `database is locked` crashes when asynchronous threads resolve simultaneously, the SQLite database must be initialized in **WAL (Write-Ahead Logging) mode** with strict connection pooling. Furthermore, the schema must include an eviction policy (**TTL or LFU pruning**) so Blackwall autonomously drops outdated or duplicate signatures, keeping graph queries under 10 milliseconds.
3. **Formal Evaluation Metrics (Evasion vs. FRR)**
   * **False Refusal Rate (FRR) / False Positive Rate (FPR):** Automated endpoint security tools demand a sub-10% False Positive Rate to remain viable.
   * **Evasion Rate (False Negative Rate):** Measures how many malicious payloads the Red-Teamer successfully slips past Blackwall's interception layer.
   * **Requirement:** The spec must include a dedicated test script to calculate these exact percentages at the end of the demo run.

## 6. Demo Video & Sandbox Setup
Testing the Blackwall Agent safely and demonstrating its capabilities for the Kaggle judges will involve a controlled, dual-agent showdown contained entirely within a local VM sandbox.

**The Sandbox Arena Setup**
* **The Host Environment:** Run locally within a Kali Linux VM. To mitigate threats, the Rogue Agent must execute with dropped OS privileges (e.g., as an unprivileged user) to reduce the blast radius. However, because dropped privileges do not prevent local execution bypasses, the sandbox must also implement a strict runtime block via a **Python Runtime Audit Hook (`sys.addaudithook`)**. This hook will intercept and deny all raw `os`, `subprocess`, and `pty` execution paths with a `PermissionError`, explicitly forcing the hostile agent to route its actions through the ADK tool layer where Blackwall's `before_tool_callback` can evaluate them.
* **The Target Application:** A simple, vulnerable mock application hosted directly inside the sandbox (e.g., Metasploitable).
* **The Ambient Daemon:** Launched via `adk run`, Blackwall acts as a background process monitoring state via the `before_tool_callback`.
* **Models & Providers:** - **Blackwall Agent:** Gemini 3.1 Flash-Lite via paid Gemini Interactions API (300 RPM).
  - **Adversarial Red-Teamer:** Qwen3-Coder 480B via paid Hyperbolic API (600 RPM).

**The Dual-Agent Showdown (The Test Execution)**
Using the Antigravity 2.0 harness, a temporary "Rogue Agent" will run malicious tools against the mock application.
* **Attempt 1 (The Novel Attack):** The rogue agent attempts a novel exploit (e.g., install a reverse shell).
* **The Interception:** Blackwall physically pauses execution, evaluates intent, blocks the action, and writes a "Threat Signature".
* **Attempt 2 (Dynamic Mitigation):** The rogue agent attempts a modified version of the same attack. Blackwall instantly blocks it by referencing its newly created Threat Signature (Zero static allowlists).
* **The Visual Proof:** A split-screen terminal recording showing the Rogue Agent failing to execute payloads on one side, and Blackwall's live log output (intercepting, generating signatures, and shutting it down) on the other.

## 7. Mandatory Behavior-Driven Development (BDD) Verification

To ensure all architectural guardrails are strictly enforced, Blackwall utilizes Behavior-Driven Development via `pytest-bdd`.

* **Test Framework:** All end-to-end security and interception tests MUST be written using `pytest-bdd` combined with `pytest-asyncio`.
* **Feature Contract:** The authoritative behavioral requirements are defined in `tests/features/blackwall_guardrails.feature`. Do NOT modify or remove the Gherkin scenarios in this file without explicit human authorization.
* **Step Definitions:** Step definitions must be implemented in `tests/step_defs/test_guardrails.py` and bind directly to the existing Given-When-Then statements in the `.feature` file.
* **The Verification Gate:** Before marking any implementation task in `tasks.md` as complete, you must run `pytest -v tests/` and confirm that all BDD guardrail scenarios pass. Never bypass a failing BDD test by weakening the test assertion.
