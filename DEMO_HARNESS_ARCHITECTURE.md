# Blackwall Agent: Demo Harness & Dual-Agent Showdown Architecture

## 1. Introduction
To effectively demonstrate the capabilities of the Blackwall Agentic Firewall for the Kaggle "AI Agents: Intensive Vibe Coding" hackathon, we implemented a sophisticated, self-contained dual-agent testing harness. 

This harness provides a safe, contained environment—a "sandbox arena"—where a hostile "Rogue Agent" can attempt to exploit a vulnerable application while the Blackwall Agent monitors, intercepts, and mitigates those threats in real-time.

## 2. Architectural Components

The demo harness consists of five primary components designed to showcase the agentic firewall's capabilities under live fire:

### A. The Target Sandbox (FastAPI Mock Application)
- **Component:** `scripts/mock_app.py`
- **Role:** Simulates a vulnerable internal application (e.g., Metasploitable) hosting mocked endpoints that a hostile agent might try to target.
- **Security:** Built using FastAPI, it runs entirely on `localhost`.

### B. The Python Runtime Audit Hook (The Ultimate Sandbox Constraint)
- **Role:** Dropping OS privileges for a rogue agent is insufficient to prevent all local execution bypasses. To enforce strict routing through the Agent Development Kit (ADK) tool layer, the sandbox implements a strict runtime block via a **Python Runtime Audit Hook (`sys.addaudithook`)**. This hook is one layer of sandbox enforcement and operates strictly within the *current interpreter*. Separate rogue-agent or child processes require independent hook installation to be constrained.
- **Mechanism:** Within the interpreter where it is installed, the hook intercepts all raw `os`, `subprocess`, and `pty` execution paths, immediately raising a `PermissionError`. This forces the hostile agent to use the ADK's registered tools to interact with the system and prevents it from spawning unmonitored child processes to bypass enforcement.
- **Why it matters:** By funneling all actions through the ADK tools, Blackwall’s `before_tool_callback` can safely pause and evaluate every single intent *before* execution occurs.

### C. The Rogue Agent (Red-Teamer)
- **Component:** `scripts/run_rogue.py`
- **Role:** An adversarial agent driven by a high-speed model (Qwen3-Coder 480B via Hyperbolic API, running at 600 RPM). It is explicitly prompted to act as a red-teamer and attempt to compromise the mock application.
- **Capabilities:** It attempts novel exploits, such as injecting payloads or establishing reverse shells, testing Blackwall's ability to recognize malicious intent dynamically.

### D. The Blackwall Agent (The Defender)
- **Role:** The ambient daemon running in the background. It intercepts the Rogue Agent's tool calls, evaluates their structural and semantic safety, and decides whether to allow or block the action.
- **Mitigation Loop:** When a threat is detected, Blackwall not only blocks the execution but also dynamically writes a "Threat Signature" to its local SQLite Threat Graph, allowing it to instantly block similar future attacks without invoking expensive LLM evaluations.

### E. The Orchestration Layer
- **Component:** `scripts/run_demo.sh`
- **Role:** A `tmux`-based shell script that automates the entire showdown. It splits the terminal screen, launches the FastAPI mock application, initializes the Blackwall daemon, and kicks off the Rogue Agent, allowing observers to watch the real-time battle.

## 3. How the Demo Functions (The Execution Flow)

The orchestrated showdown follows a specific narrative arc:

1. **The Novel Attack (Attempt 1):**
   - The Rogue Agent attempts a novel exploit against the mock application.
   - Because the action must pass through the ADK tools (due to the audit hooks), Blackwall physically pauses the execution.
   - Blackwall evaluates the intent through mandatory primary layers: the SQLite Threat Signature Graph, structural YAML rules, and Codebase Memory (AST analysis and dependency blast radius). Only after all primary layers complete does Blackwall optionally consult the Google Threat Intelligence MCP for external IOC validation.
   - Recognizing the threat, Blackwall blocks the action and dynamically generates a new Threat Signature.

2. **The Dynamic Mitigation (Attempt 2):**
   - The Rogue Agent, having failed, attempts a modified version of the same attack (polymorphic evasion).
   - Blackwall intercepts the call. This time, it references the newly created Threat Signature in its SQLite graph.
   - It instantly recognizes the structural similarity and blocks the attack *without* needing a full LLM evaluation round, demonstrating zero static allowlists and high-speed mitigation.

## 4. What Users and Judges Gain from Witnessing It

The demo is designed to visually prove several advanced engineering concepts:

* **The Reality of Agentic Threats:** Demonstrates how fast and creative autonomous agents can be when tasked with malicious objectives, proving the necessity of agent-specific firewalls.
* **The "Zero-Trust" Safety Net:** Visually confirms that dropping OS privileges is not enough, and that true safety requires intercepting intent at the tool-execution boundary.
* **Dynamic, Self-Learning Defense:** Shows that Blackwall does not rely on static, outdated blocklists. It learns from its environment in real-time, creating structural signatures that protect against polymorphic attacks.
* **Token-Efficient Architecture:** By showing how the second attack is blocked instantly via the SQLite graph, the demo highlights Blackwall's cost-efficiency and speed, proving it can handle the 600 RPM speed of the attacker using only a 300 RPM API budget.
