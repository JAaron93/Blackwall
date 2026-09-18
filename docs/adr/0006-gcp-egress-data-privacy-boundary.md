# ADR 0006: GCP Egress Control & Data Privacy Boundary as a Security Invariant

## Status
Approved (Extends ADR 0004)

## Context

Blackwall is an agentic security firewall operating at a uniquely sensitive position in the software stack: it sits **inline between an AI agent and its OS/network execution surface**, intercepting every tool call argument in real time. This means Blackwall's evaluation pipeline necessarily ingests raw, unredacted production payloads, including:

- File system paths and directory listings
- SQL query strings and database arguments
- Shell command text (bash, Python, etc.)
- Internal API endpoint URLs and HTTP request bodies
- Environment variable values and configuration fragments
- Cryptographic key material fragments that may surface in tool arguments before sanitization

This creates a categorical data sensitivity requirement that goes beyond standard ML model selection criteria: **the classifier backend receiving this traffic must not exfiltrate it outside the operator's controlled infrastructure boundary**. 

ADR 0004 established GCP Vertex AI and the Gemini Interactions API as the exclusive inline resolution backend for performance and API-feature reasons. However, it did not explicitly document the **egress control and data privacy boundary** as an independent, first-class security invariant. This ADR records that decision.

The concern became concrete when evaluating third-party specialist model alternatives — lightweight decision classifiers and zero-shot routing models offered by external cloud providers — which present compelling latency and economics characteristics but **route all inference traffic through infrastructure outside the operator's network security perimeter**, with data handling terms that may not satisfy enterprise compliance requirements.

---

## Decision

We formally adopt **GCP Vertex AI (Gemini Enterprise Agent Platform) as Blackwall's exclusive inference boundary** on the additional grounds of egress control and data privacy, independent of the API-feature justifications in ADR 0004.

### 1. Private VPC Service Controls & Tenant Network Boundary

All Gemini inference traffic submitted via the Gemini Interactions API on GCP Vertex AI is processed within **Google's private tenant infrastructure**, governed by VPC Service Controls:

- **VPC-SC Perimeters**: Operators can enforce `accessPolicies` that restrict Vertex AI API calls to originate only from within a defined VPC network. This ensures intercepted tool payloads never traverse the public internet to reach the model endpoint.
- **Private Service Connect**: Vertex AI endpoints can be accessed via Private Service Connect forwarding rules, creating a private, internal IP route entirely within the operator's GCP project network — eliminating any public egress hop.
- **Single-Tenant Isolation**: GCP Gemini Enterprise Agent Platform provides logical tenant isolation, ensuring one customer's inference workloads and data are never co-mingled with another's at the compute layer.

By contrast, third-party external classifier APIs route all inference traffic through their proprietary multi-tenant cloud infrastructure over the public internet, with no operator-controlled network perimeter.

### 2. Data Residency & Regulatory Compliance

GCP Vertex AI supports configurable **data residency** controls:

- Inference requests can be pinned to specific GCP regions (e.g., `us-central1`, `europe-west4`) to satisfy data sovereignty requirements under GDPR, HIPAA, FedRAMP, or sector-specific compliance frameworks.
- Vertex AI processes requests without using them for model training by default, with explicit contractual Data Processing Addendums (DPAs) that define data handling obligations.
- GCP's compliance certifications (ISO 27001, SOC 2 Type II, PCI DSS, HIPAA BAA) apply to the inference API layer, providing a legally-grounded audit trail.

Early-stage AI startups typically lack equivalent regulatory coverage, regional data routing controls, and the contractual obligations required for enterprise security deployments.

### 3. Customer-Managed Encryption Keys (CMEK)

GCP Vertex AI supports **CMEK** for Vertex AI resources, allowing operators to control the encryption key lifecycle for data processed in the inference layer:

- Operators can supply their own key material via Cloud KMS, ensuring that inference payloads (which contain sensitive tool arguments) are encrypted with keys under their exclusive control.
- Key revocation terminates inference capability immediately, providing a cryptographic kill-switch.

Third-party decision classifier APIs do not expose CMEK controls, meaning the operator has no control over how inference payloads are encrypted or for how long they persist in the provider's infrastructure.

### 4. Structured Egress Audit Log via Cloud Logging

All Vertex AI API calls are surfaced in **Cloud Logging** (`cloudaudit.googleapis.com`) as Data Access audit log entries, providing:

- Immutable, tamper-evident records of every inference request with request metadata (model ID, project, timestamp, IP origin).
- Integration with Chronicle SIEM, BigQuery Security Analytics, and Cloud Monitoring for anomaly detection over Blackwall's own inference call patterns.
- A verifiable chain of custody for forensic investigations: if an intercepted tool call later becomes relevant to an incident investigation, the inference log proves the call was evaluated, when, and by which model.

This audit capability is architecturally impossible when using external third-party APIs, where the operator has no visibility into the provider's logging posture or log retention.

### 5. The Third-Party External API Security Anti-Pattern for Security Tools

The most pointed architectural objection to using external third-party classifier APIs for inline security interception is **architectural self-defeat**: a security tool that sends all potentially-sensitive payloads to an uncontrolled external network endpoint before blocking them is itself an exfiltration channel.

Consider the threat model:
- A rogue AI agent injects a credential harvesting payload into a tool argument: `cat /etc/shadow > /tmp/loot.txt`.
- Blackwall intercepts this call and sends the raw argument string (including `/etc/shadow`) to an external classification API.
- Even if Blackwall correctly blocks the agent, the raw argument text — which reveals the attacker's targeting intent and possibly internal path structures — has already left the operator's network to an external party.

Keeping all inference within GCP VPC boundaries closes this side channel. The tool argument never leaves the operator's private network perimeter: it is transmitted directly via Private Service Connect to a Vertex AI regional endpoint within the same GCP tenant.

---

## Consequences

### Positive
- **Zero Public Internet Egress for Tool Payloads**: Intercepted tool arguments (potentially containing secrets, credentials, or PII fragments) are processed entirely within the operator's GCP VPC perimeter via Private Service Connect.
- **Regulatory Compliance Baseline**: GCP's ISO 27001, SOC 2, GDPR DPAs, and HIPAA BAA coverage satisfies enterprise and regulated-sector audit requirements out of the box.
- **Cryptographic Data Custody**: CMEK support gives operators the encryption key lifecycle, with revocation as a hard kill-switch.
- **Immutable Inference Audit Trail**: Cloud Logging Data Access logs provide forensic proof of every security evaluation event, timestamped and tamper-evident.
- **Closed Side-Channel**: Keeping inference on-VPC eliminates the structural anti-pattern of a security tool leaking sensitive arguments to an uncontrolled external endpoint.

### Negative & Trade-offs
- **Vendor Lock-In (Accepted)**: The VPC-SC, Private Service Connect, CMEK, and Cloud Logging integrations are GCP-exclusive constructs. Migrating to a different inference provider would require rebuilding these controls from scratch and forfeiting the compliance certifications that depend on them.
- **GCP Project Setup Overhead**: VPC-SC perimeters, Private Service Connect forwarding rules, and CMEK key rings require initial GCP project configuration. The default public-endpoint Vertex AI configuration is still used in local development and CI environments where these network controls are not provisioned.
- **No Air-Gap Fallback for Inference**: As documented in ADR 0004, environments with no GCP connectivity enforce a strict fail-closed `QUARANTINE` policy. This remains the correct security posture — an unknown event is safer quarantined than evaluated by a degraded fallback that bypasses data privacy controls.

### Relationship to ADR 0004
ADR 0004 established GCP exclusivity on **API-feature grounds** (background webhooks, `previous_interaction_id` caching, structured output decoding, thinking level routing). This ADR establishes GCP exclusivity on **data security grounds** (VPC-SC isolation, egress control, CMEK, audit log). Both rationales are independent and mutually reinforcing: removing either one is sufficient reason to maintain GCP exclusivity.
