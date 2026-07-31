# Functional & Technical Requirements: Blackwall Enterprise Security Mesh

## 1. Glossary & Terminology

- **Blackwall Core (Individual Edition)**: Single-host Python daemon operating in user-space with ADK callbacks, Python audit hooks, and local SQLite graph. Zero external network dependencies.
- **Blackwall Enterprise Mesh (Enterprise Edition)**: Multi-host security mesh featuring eBPF kernel probes, ZeroMQ signature broadcast, ephemeral identity sidecar, pipeline wrappers, local forensic engine, and 4 open-source Enterprise MCP servers.
- **`ebpf-falco-mcp`**: Open-source kernel telemetry MCP server providing syscall and process lineage events.
- **`hashicorp-vault-mcp`**: Open-source secret manager MCP server providing JIT credential exchange via local Vault Dev Mode or LocalStack.
- **`container-sandbox-mcp`**: Open-source sandbox governance MCP server interfacing with Docker/gVisor local APIs.
- **`opentelemetry-mcp`**: Open-source telemetry exporter MCP server providing log stream ingestion via Jaeger/OTel.

---

## 2. Functional Requirements (FR)

### Dual-Tier Product Architecture & Enterprise MCPs
- **FR-00 (Tier Isolation)**: The system MUST maintain `Blackwall Core` as a standalone, lightweight, single-host Python daemon. Enterprise modules and MCP server adapters MUST be modularized under `blackwall.enterprise`.
- **FR-16 (Open-Source Local MCP Suite)**: Enterprise Edition MUST support testing via 4 open-source, zero-cost local MCP servers (`ebpf-falco-mcp`, `hashicorp-vault-mcp`, `container-sandbox-mcp`, `opentelemetry-mcp`) without requiring paid cloud SaaS subscriptions.
- **FR-17 (Vault Dev Mode & JIT Exchange)**: `hashicorp-vault-mcp` MUST support HashiCorp Vault Dev Mode (`vault server -dev`) and LocalStack mock STS endpoints for local developer verification.
- **FR-18 (Docker/gVisor Micro-Sandbox Control)**: `container-sandbox-mcp` MUST interface with local Docker or gVisor (`runsc`) daemons to isolate untrusted dataset loader routines in unprivileged container sandboxes.

### Pillar 1: Kernel-Level Interception (`blackwall.kernel`)
- **FR-01 (Syscall Interception)**: Enterprise Edition MUST intercept system calls including `execve`, `socket.connect`, and `ptrace` before the OS executes the command.
- **FR-02 (Dual Driver Fallback)**: The system MUST detect kernel platform support. On Linux systems (kernel >= 5.4), it MUST load `LinuxeBPFDriver`. On macOS or systems lacking eBPF support, it MUST fallback to `UserSpaceAuditDriver`.

### Pillar 2: Distributed Threat Mesh (`blackwall.mesh`)
- **FR-04 (Pub/Sub Signature Broadcast)**: When an enterprise node generates a new `ThreatSignature`, it MUST broadcast the signature payload over ZeroMQ/NATS mesh to all cluster nodes within 15 ms.

### Pillar 3: Ephemeral Identity Sidecar (`blackwall.identity`)
- **FR-07 (Environment Sterilization)**: Enterprise Identity Sidecar MUST scan environment variables at boot and replace sensitive credentials with synthetic honey-tokens (`BW_SYNTHETIC_*`).
- **FR-08 (Honey-Token Exfiltration Alert)**: Any attempt by an agent to read or exfiltrate synthetic honey-tokens MUST trigger a `CRITICAL` alert.

### Pillar 4: Application Pipeline Interception Wrappers (`blackwall.pipeline`)
- **FR-10 (Dataset Loader Guard)**: Untrusted dataset loaders MUST execute inside isolated worker processes via `container-sandbox-mcp`.

### Pillar 5: Native Local Forensic Triage Engine (`blackwall.forensics`)
- **FR-13 (Primary Ollama LLM Triage)**: When Ollama is available, forensic triage MUST execute via local Ollama LLM endpoint without cloud safety refusals.
- **FR-14 (Standalone Lightweight Fallback Parser)**: When GPU/Ollama is offline, the system MUST automatically fail over to `LightweightForensicParser`.

---

## 3. Non-Functional Requirements (NFR)

- **NFR-01 (Fast-Path Latency)**: Fast-path local signature evaluation MUST complete within `<= 8 ms` per interception call.
- **NFR-02 (Mesh Sync Latency)**: Threat signatures MUST propagate across multi-node cluster meshes within `<= 15 ms`.
- **NFR-03 (Zero Cost Developer Testing)**: All Enterprise MCP servers and test suites MUST be executable on local developer workstations for `$0.00` total software cost.
- **NFR-04 (Fallback Availability)**: Standalone forensic fallback parser MUST achieve `100%` availability when GPU/Ollama is offline.
