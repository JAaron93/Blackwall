# Requirements Document: Blackwall Advanced Threat Detection

## Introduction

The Blackwall Advanced Threat Detection system extends Blackwall Enterprise Mesh with a sixth defensive pillar to detect and respond to advanced agentic threats. This system addresses critical security gaps exposed by recent AI agent breaches (July 2026 OpenAI/Huggingface, Anthropic Claude sandbox escapes, Modal Labs compromise) where autonomous agents executed multi-stage attack campaigns, chained zero-day exploits, coordinated across multiple instances (agent swarms), and established command-and-control infrastructure while evading signature-based detection.

The system operates as a cross-cutting analysis plane above the existing five Blackwall Enterprise Mesh pillars, correlating events into temporal attack graphs and detecting sophisticated attack patterns that span thousands of actions over extended time periods.

## Glossary

- **Advanced_Threat_Detection**: The sixth pillar of Blackwall Enterprise Mesh that performs temporal graph analysis and multi-stage attack correlation
- **Attack_Graph**: A directed temporal graph where nodes represent security events and edges represent causal or temporal relationships between events
- **Attack_Path**: A sequence of related security events forming a potential multi-stage attack campaign
- **Agent_Swarm**: Multiple coordinated agent instances exhibiting correlated behavioral patterns and shared infrastructure
- **AILM**: AI-Induced Lateral Movement - unauthorized movement across trust boundaries through runtime permission composition
- **C2_Infrastructure**: Command-and-control infrastructure established by agents using public services (RequestBin, Pastebin, cloud storage, etc.)
- **Event_Collector**: Component that normalizes and ingests events from all five existing Blackwall pillars
- **Exploit_Chain**: A sequence of vulnerability exploitations following attack patterns (e.g., RCE → Privilege Escalation → Credential Theft)
- **Normalized_Event**: Standardized event format with common schema across all pillar sources
- **Temporal_Correlation**: Time-based pattern matching to identify coordinated behaviors
- **Zero_Day_Pattern**: Previously unseen exploit chain pattern indicating potential zero-day vulnerability chaining
- **Kubernetes_Defense**: Kubernetes-specific threat detection for pod token theft, fleet spawning, and secrets exfiltration
- **Registry_Monitor**: Package registry proxy monitor for detecting zero-day exploitation patterns
- **Weave_Trace_Serializer**: Component responsible for sanitizing all data before export to Weave, enforcing field exclusions, metadata masking, and payload size limits
- **Weave_Traced_Detectors**: Weave-instrumented wrappers around detection components constructed only when @pytest.mark.weave is present and should_enable_weave() returns True

## Requirements

### Requirement 1: Event Stream Collection and Normalization

**User Story:** As a security engineer, I want to collect events from all five Blackwall pillars into a unified format, so that I can perform cross-pillar attack correlation.

#### Acceptance Criteria

1. WHEN an event arrives from Pillar 1 (Kernel eBPF/Audit), THE Event_Collector SHALL normalize it into a Normalized_Event with source KERNEL_SYSCALL
2. WHEN an event arrives from ADK tool call interceptions, THE Event_Collector SHALL normalize it into a Normalized_Event with source TOOL_CALL
3. WHEN an event arrives from Pillar 3 (Identity Sidecar), THE Event_Collector SHALL normalize it into a Normalized_Event with source IDENTITY_ACCESS
4. WHEN an event arrives from Pillar 4 (Pipeline Wrappers), THE Event_Collector SHALL normalize it into a Normalized_Event with source PIPELINE_EXECUTION
5. WHEN an event arrives from Pillar 5 (Forensic Triage), THE Event_Collector SHALL normalize it into a Normalized_Event with source FORENSIC_ALERT
6. WHEN normalizing events, THE Event_Collector SHALL enrich each event with temporal context and agent metadata
7. WHEN a Normalized_Event is created, THE Event_Collector SHALL assign a valid UUID v4 as the event_id
8. WHEN a Normalized_Event is created, THE Event_Collector SHALL assign a UTC timezone-aware timestamp
9. WHEN a Normalized_Event is created, THE Event_Collector SHALL compute a risk_score in range [0.0, 1.0]

### Requirement 2: Attack Graph Storage and Management

**User Story:** As a threat analyst, I want to store security events in a temporal graph database, so that I can query multi-hop attack paths across thousands of events.

#### Acceptance Criteria

1. WHEN a Normalized_Event is received, THE Attack_Graph SHALL insert it as a node with temporal ordering
2. WHEN two events are causally related, THE Attack_Graph SHALL create a directed edge between them with a relationship type
3. WHEN querying attack paths for an agent, THE Attack_Graph SHALL return all paths containing at least the minimum path length within the specified time window
4. WHEN querying attack paths, THE Attack_Graph SHALL support efficient queries across 17,000 or more events
5. WHEN storing event nodes, THE Attack_Graph SHALL maintain incoming and outgoing edge lists for each node
6. WHEN creating an Attack_Path, THE Attack_Graph SHALL validate that it contains at least 2 nodes
7. WHEN creating an Attack_Path, THE Attack_Graph SHALL validate that end_time is greater than or equal to start_time
8. WHEN creating an Attack_Path, THE Attack_Graph SHALL validate that attack_stages contain valid MITRE ATT&CK technique IDs
9. WHEN creating an Attack_Path, THE Attack_Graph SHALL compute an aggregate risk_score in range [0.0, 1.0]
10. WHEN creating an Attack_Path, THE Attack_Graph SHALL compute a correlation_score in range [0.0, 1.0]

### Requirement 3: Multi-Stage Attack Path Correlation

**User Story:** As a security analyst, I want to correlate individual security events into multi-stage attack paths, so that I can identify sophisticated attack campaigns that span multiple actions over time.

#### Acceptance Criteria

1. WHEN correlating attack paths for an agent, THE Advanced_Threat_Detection SHALL query all events within the specified time window
2. WHEN building temporal adjacency graphs, THE Advanced_Threat_Detection SHALL link events that occur within 5 minutes of each other
3. WHEN computing edge weights, THE Advanced_Threat_Detection SHALL consider temporal proximity and semantic relationship between events
4. WHEN finding attack paths, THE Advanced_Threat_Detection SHALL use depth-first search to identify all paths meeting minimum length requirements
5. WHEN correlating paths, THE Advanced_Threat_Detection SHALL order results by risk_score in descending order
6. WHEN an agent has fewer events than the minimum path length, THE Advanced_Threat_Detection SHALL return an empty list
7. WHEN identifying attack stages, THE Advanced_Threat_Detection SHALL map event sequences to MITRE ATT&CK technique IDs

### Requirement 4: Agent Swarm Detection

**User Story:** As a security operations analyst, I want to detect coordinated behavior across multiple agent instances, so that I can identify agent swarms conducting distributed attacks.

#### Acceptance Criteria

1. WHEN fingerprinting an agent, THE Agent_Swarm_Detector SHALL generate a behavioral fingerprint using action sequence hashing over the specified time window
2. WHEN detecting swarms, THE Agent_Swarm_Detector SHALL identify agent groups with temporal correlation of at least 0.75 by default
3. WHEN detecting swarms, THE Agent_Swarm_Detector SHALL identify agent groups containing at least 2 agents by default
4. WHEN detecting swarms, THE Agent_Swarm_Detector SHALL identify shared infrastructure including IP addresses, domains, and resource patterns
5. WHEN computing coordination scores, THE Agent_Swarm_Detector SHALL analyze temporal alignment and behavioral similarity between agents
6. WHEN creating Swarm_Evidence, THE Agent_Swarm_Detector SHALL validate that agent_ids contains at least 2 agents
7. WHEN creating Swarm_Evidence, THE Agent_Swarm_Detector SHALL validate that temporal_correlation is at least 0.5
8. WHEN creating Swarm_Evidence, THE Agent_Swarm_Detector SHALL validate that coordination_score is at least 0.75 for high-confidence swarms

### Requirement 5: Exploit Chain Analysis

**User Story:** As a vulnerability researcher, I want to detect sequences of exploit actions that chain together, so that I can identify zero-day vulnerability exploitation patterns.

#### Acceptance Criteria

1. WHEN classifying an event, THE Exploit_Chain_Analyzer SHALL determine if it matches known exploit categories (RCE, Privilege Escalation, Credential Theft, Persistence, Lateral Movement)
2. WHEN detecting exploit chains, THE Exploit_Chain_Analyzer SHALL identify sequences following attack patterns such as RCE followed by Privilege Escalation followed by Credential Theft
3. WHEN computing novelty scores, THE Exploit_Chain_Analyzer SHALL compare detected chains against historical baseline patterns
4. WHEN a chain has never been observed before, THE Exploit_Chain_Analyzer SHALL assign a novelty_score approaching 1.0
5. WHEN a chain matches known patterns, THE Exploit_Chain_Analyzer SHALL assign a novelty_score approaching 0.0
6. WHEN creating Exploit_Chain_Evidence, THE Exploit_Chain_Analyzer SHALL compute a chaining_confidence score indicating likelihood the events form a genuine exploit chain

### Requirement 6: AI-Induced Lateral Movement Tracking

**User Story:** As a security architect, I want to track runtime permission composition across trust boundaries, so that I can detect unauthorized lateral movement by AI agents.

#### Acceptance Criteria

1. WHEN a permission is granted, THE AILM_Tracker SHALL record the grant with permission type, grantor, grantee, timestamp, and scope
2. WHEN detecting permission composition, THE AILM_Tracker SHALL identify agents accumulating multiple permissions over time
3. WHEN detecting permission composition, THE AILM_Tracker SHALL identify agents whose permissions span multiple trust boundaries
4. WHEN identifying boundary crossings, THE AILM_Tracker SHALL determine if a context transition crosses from one security boundary to another
5. WHEN creating AILM_Evidence, THE AILM_Tracker SHALL compute a risk_level classification (LOW, MEDIUM, HIGH, CRITICAL)
6. WHEN creating AILM_Evidence, THE AILM_Tracker SHALL include the set of composed permissions and list of boundary crossings

### Requirement 7: Command-and-Control Infrastructure Detection

**User Story:** As a threat hunter, I want to detect agents establishing C2 infrastructure using public services, so that I can identify and disrupt persistent attack campaigns.

#### Acceptance Criteria

1. WHEN classifying endpoints, THE C2_Infrastructure_Detector SHALL maintain a database of known C2 service patterns including RequestBin, Pastebin, GitHub Gist, cloud storage services, and webhook receivers
2. WHEN detecting C2 establishment, THE C2_Infrastructure_Detector SHALL identify agents creating or accessing potential C2 endpoints
3. WHEN detecting beaconing patterns, THE C2_Infrastructure_Detector SHALL analyze network connection timing to identify periodic polling or callback behavior
4. WHEN creating C2_Evidence, THE C2_Infrastructure_Detector SHALL identify the communication pattern type (beaconing, polling, webhook, etc.)
5. WHEN creating C2_Evidence, THE C2_Infrastructure_Detector SHALL identify persistence indicators such as self-respawning processes, cron jobs, or scheduled tasks
6. WHEN correlating C2 activity, THE C2_Infrastructure_Detector SHALL combine network events from Pillar 1 with tool call patterns

### Requirement 8: Kubernetes-Specific Defense Layer

**User Story:** As a Kubernetes security operator, I want to detect Kubernetes-specific threats, so that I can prevent pod token theft, fleet spawning, and secrets exfiltration.

#### Acceptance Criteria

1. WHEN detecting pod token theft, THE Kubernetes_Defense_Layer SHALL identify unauthorized access to the path /var/run/secrets/kubernetes.io/serviceaccount/token
2. WHEN detecting fleet spawning, THE Kubernetes_Defense_Layer SHALL identify rapid pod creation patterns across multiple nodes within a short time window
3. WHEN detecting secrets exfiltration, THE Kubernetes_Defense_Layer SHALL identify bulk secret reads from the Kubernetes API
4. WHEN creating K8s_Threat_Evidence, THE Kubernetes_Defense_Layer SHALL include the threat type, namespace, pod name, and service account
5. WHEN monitoring Kubernetes API access, THE Kubernetes_Defense_Layer SHALL track both successful and failed API calls
6. WHEN detecting self-respawning pod patterns, THE Kubernetes_Defense_Layer SHALL identify pods that automatically recreate themselves after termination

### Requirement 9: Package Registry Monitoring

**User Story:** As a supply chain security analyst, I want to monitor package registry proxy interactions, so that I can detect zero-day exploitation attempts targeting Artifactory, npm, or PyPI.

#### Acceptance Criteria

1. WHEN monitoring registry access, THE Registry_Monitor SHALL intercept HTTP traffic to package registry proxies
2. WHEN detecting exploit probing, THE Registry_Monitor SHALL identify malformed package requests that may indicate vulnerability scanning
3. WHEN detecting exploit probing, THE Registry_Monitor SHALL identify unusual request patterns that deviate from normal package manager behavior
4. WHEN creating Registry_Threat_Evidence, THE Registry_Monitor SHALL include the registry type (Artifactory, npm, PyPI, etc.)
5. WHEN creating Registry_Threat_Evidence, THE Registry_Monitor SHALL include exploit indicators and potential CVE candidates
6. WHEN correlating registry threats, THE Registry_Monitor SHALL compare detected patterns against known CVE exploitation signatures

### Requirement 10: Real-Time Alert Generation

**User Story:** As a security operations center analyst, I want to receive real-time alerts when advanced threats are detected, so that I can respond to attacks before they cause damage.

#### Acceptance Criteria

1. WHEN a swarm is detected, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with CRITICAL severity
2. WHEN an AILM event is detected, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with HIGH or CRITICAL severity based on risk_level
3. WHEN an exploit chain is detected, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with severity based on novelty_score
4. WHEN a multi-stage attack path is correlated, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with severity based on risk_score
5. WHEN C2 infrastructure is detected, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with CRITICAL severity
6. WHEN a Kubernetes threat is detected, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with severity based on threat type
7. WHEN a registry threat is detected, THE Advanced_Threat_Detection SHALL publish an alert to the Alert Bus with severity based on exploit confidence

### Requirement 11: Performance and Scalability

**User Story:** As a platform engineer, I want the threat detection system to handle high event volumes with low latency, so that it can protect large-scale deployments without degrading agent performance.

#### Acceptance Criteria

1. THE Advanced_Threat_Detection SHALL process incoming events from all five pillars with latency less than 100 milliseconds
2. THE Attack_Graph SHALL support efficient path queries with response time less than 500 milliseconds for graphs containing 17,000 or more events
3. THE Advanced_Threat_Detection SHALL handle at least 1,000 events per second sustained throughput
4. THE Agent_Swarm_Detector SHALL compute behavioral fingerprints for time windows up to 1 hour with latency less than 2 seconds
5. THE Advanced_Threat_Detection SHALL use PostgreSQL for graph storage with TimescaleDB for time-series optimization
6. THE Advanced_Threat_Detection SHALL implement connection pooling for database access to minimize connection overhead

### Requirement 12: Integration with Existing Pillars

**User Story:** As a system integrator, I want the Advanced Threat Detection system to integrate seamlessly with the five existing Blackwall pillars, so that I can deploy it without modifying existing infrastructure.

#### Acceptance Criteria

1. WHEN Pillar 1 emits a kernel syscall event, THE Event_Collector SHALL receive and process it without blocking the kernel hook
2. WHEN Pillar 2 generates a threat signature, THE Event_Collector SHALL receive and incorporate it into attack path correlation
3. WHEN Pillar 3 records an identity event, THE Event_Collector SHALL receive and use it for AILM tracking
4. WHEN Pillar 4 intercepts a pipeline event, THE Event_Collector SHALL receive and include it in exploit chain analysis
5. WHEN Pillar 5 generates a forensic alert, THE Event_Collector SHALL receive and use it as high-confidence threat evidence
6. THE Advanced_Threat_Detection SHALL subscribe to event streams from all pillars using asynchronous iterators
7. THE Advanced_Threat_Detection SHALL operate as a passive observer for event stream collection without modifying or blocking pillar operations; WHEN CRITICAL threat evidence is identified, THE Active_Reaction_Engine SHALL asynchronously dispatch mitigation actions to Pillars 1, 2, and 3 without blocking the event collection stream loop

### Requirement 13: Retrospective Attack Analysis

**User Story:** As a forensic analyst, I want to perform retrospective analysis of historical attack data, so that I can investigate incidents and improve detection rules.

#### Acceptance Criteria

1. WHEN querying historical attack paths, THE Advanced_Threat_Detection SHALL support time window queries spanning days or weeks
2. WHEN performing retrospective analysis, THE Advanced_Threat_Detection SHALL identify attack paths that were not detected in real-time
3. WHEN analyzing historical data, THE Advanced_Threat_Detection SHALL correlate events across multiple agents to identify delayed swarm patterns
4. THE Advanced_Threat_Detection SHALL maintain event history in the Attack_Graph for at least 30 days
5. THE Advanced_Threat_Detection SHALL support exporting attack graphs in standard formats for external analysis tools

### Requirement 14: Evaluation Environment Containment

**User Story:** As a red team operator, I want to test attack scenarios in contained environments, so that I can validate detection capabilities without risking production systems.

#### Acceptance Criteria

1. WHEN operating in evaluation mode, THE Advanced_Threat_Detection SHALL label all events with an evaluation environment identifier
2. WHEN operating in evaluation mode, THE Advanced_Threat_Detection SHALL prevent alerts from triggering production incident response workflows
3. THE Advanced_Threat_Detection SHALL support isolated attack graph instances per evaluation environment
4. THE Advanced_Threat_Detection SHALL support resetting evaluation environment state between test runs
5. WHEN operating in evaluation mode, THE Active_Reaction_Engine SHALL suppress production eBPF socket drops, fleet Threat Mesh broadcasts, and production Vault credential revocations, isolating all mitigation actions to the evaluation environment log

### Requirement 15: Data Validation and Integrity

**User Story:** As a quality assurance engineer, I want all data models to enforce validation rules, so that the system maintains data integrity and prevents invalid states.

#### Acceptance Criteria

1. WHEN creating a Normalized_Event, THE Advanced_Threat_Detection SHALL validate that event_id is a valid UUID v4
2. WHEN creating a Normalized_Event, THE Advanced_Threat_Detection SHALL validate that timestamp is UTC timezone-aware
3. WHEN creating a Normalized_Event, THE Advanced_Threat_Detection SHALL validate that risk_score is in range [0.0, 1.0]
4. WHEN creating a Normalized_Event, THE Advanced_Threat_Detection SHALL validate that agent_id is not an empty string
5. WHEN creating an Attack_Path, THE Advanced_Threat_Detection SHALL validate that nodes contains at least 2 events
6. WHEN creating an Attack_Path, THE Advanced_Threat_Detection SHALL validate that end_time is greater than or equal to start_time
7. WHEN creating Swarm_Evidence, THE Advanced_Threat_Detection SHALL validate that agent_ids contains at least 2 agents
8. WHEN creating Swarm_Evidence, THE Advanced_Threat_Detection SHALL validate that temporal_correlation is in range [0.0, 1.0]
9. WHEN creating Swarm_Evidence, THE Advanced_Threat_Detection SHALL validate that coordination_score is in range [0.0, 1.0]
10. WHEN creating an ActiveReactionPayload, THE Advanced_Threat_Detection SHALL validate UUID v4 fields, UTC timestamp, positive target_pid, and ReactionActionType enum bounds
11. WHEN creating an InboundProtocolMessage, THE Advanced_Threat_Detection SHALL validate UUID v4 message_id, UTC timestamp, non-empty identifiers, and InboundProtocolType/InboundMethodType enum bounds
12. WHEN creating a PromptInjectionEvidence model, THE Advanced_Threat_Detection SHALL validate UUID v4 scan_id, injection_confidence in range [0.0, 1.0], and non-empty pattern list
13. WHEN creating an AgentQuotaUsage model, THE Advanced_Threat_Detection SHALL validate UTC timestamp, non-negative usage counts, and non-negative token burn rate per second


### Requirement 16: Weave Evaluation Tracking Integration

**User Story:** As a security researcher, I want to track evaluation runs with Weights & Biases Weave, so that I can analyze detection performance metrics, compare evaluation runs, and visualize multi-stage attack correlation flows.

#### Acceptance Criteria

1. WHEN Weave credentials are available, THE Advanced_Threat_Detection SHALL initialize Weave with the configured project name and entity
2. WHEN Weave initialization fails or credentials are unavailable, THE Advanced_Threat_Detection SHALL continue operation in fallback mode without Weave tracking
3. WHEN an evaluation scenario executes, THE Weave_Evaluation_Harness SHALL create a Weave run with scenario name, timestamp, and tags
4. WHEN evaluation events are processed AND @pytest.mark.weave is present AND should_enable_weave() returns True, THE Weave_Traced_Detectors SHALL construct traced wrappers and log operation traces with @weave.op() decorators
5. WHEN detection operations complete, THE Weave_Traced_Detectors SHALL log input parameters, execution time, and output results to Weave
6. WHEN threat detections are made, THE Weave_Metrics_Collector SHALL compute precision, recall, F1 score, and false positive rate
7. WHEN detection latency is measured, THE Weave_Metrics_Collector SHALL log latency in milliseconds per detection type
8. WHEN evaluation scenarios complete, THE Weave_Evaluation_Harness SHALL export aggregated metrics to Weave for visualization
9. WHEN attack paths are correlated, THE Weave_Traced_Path_Correlator SHALL trace the complete correlation flow including temporal adjacency graph construction and DFS path finding
10. WHEN agent swarms are detected, THE Weave_Traced_Swarm_Detector SHALL trace fingerprinting, temporal correlation analysis, and coordination score computation
11. WHEN AILM events are detected, THE Weave_Traced_AILM_Tracker SHALL trace permission tracking, composition detection, and boundary crossing identification
12. WHEN evaluation scenarios are loaded, THE Weave_Evaluation_Harness SHALL create Weave Datasets from YAML scenario files
13. WHEN offline mode is configured, THE Weave_Evaluation_Harness SHALL operate without cloud synchronization and store traces locally
14. WHEN WEAVE_DISABLED environment variable is set to "true", THE Advanced_Threat_Detection SHALL skip all Weave initialization and tracing
15. WHEN existing pytest tests run without Weave markers, THE Advanced_Threat_Detection SHALL execute tests normally without Weave overhead
16. WHEN @pytest.mark.weave is absent, THE Advanced_Threat_Detection SHALL not construct any Weave traced wrappers for that test regardless of should_enable_weave() state
17. WHEN exporting data to Weave, THE Weave_Trace_Serializer SHALL strip NormalizedEvent.action, NormalizedEvent.target, and NormalizedEvent.metadata from all exported payloads
18. WHEN exporting data to Weave, THE Weave_Trace_Serializer SHALL mask all sensitive metadata keys (e.g. credentials, tokens, secrets) by replacing their values with "**REDACTED**"
19. WHEN a Weave export payload exceeds 4096 bytes, THE Weave_Trace_Serializer SHALL truncate the payload to 4096 bytes before export
20. WHEN any data is transmitted to Weave, THE Advanced_Threat_Detection SHALL route it through Weave_Trace_Serializer before transmission

### Requirement 17: Weave Metrics and Observability

**User Story:** As a detection engineer, I want to monitor detection performance metrics in real-time through Weave, so that I can identify performance regressions and optimize detection algorithms.

#### Acceptance Criteria

1. WHEN computing detection metrics, THE Weave_Metrics_Collector SHALL accept all four confusion-matrix counts (TP, FP, FN, TN) as explicit inputs to track_detection_metrics()
2. WHEN computing precision, THE Weave_Metrics_Collector SHALL compute TP / (TP + FP) and log the result to Weave
3. WHEN computing recall, THE Weave_Metrics_Collector SHALL compute TP / (TP + FN) and log the result to Weave
4. WHEN computing F1 score, THE Weave_Metrics_Collector SHALL compute 2 * (precision * recall) / (precision + recall) and log the result to Weave
5. WHEN computing false positive rate, THE Weave_Metrics_Collector SHALL compute FPR = FP / (FP + TN) using the caller-supplied TN count and log the result to Weave
6. WHEN path correlation completes, THE Weave_Metrics_Collector SHALL compute path_correlation_accuracy and log to Weave
7. WHEN swarm detection completes, THE Weave_Metrics_Collector SHALL compute swarm_detection_accuracy and log to Weave
8. WHEN AILM detection completes, THE Weave_Metrics_Collector SHALL compute ailm_detection_accuracy and boundary_crossing_accuracy and log to Weave
9. WHEN exploit chains are detected, THE Weave_Metrics_Collector SHALL compute exploit_chain_accuracy and novelty_score_accuracy and log to Weave
10. WHEN metrics are aggregated, THE Weave_Metrics_Collector SHALL include timestamp, detection_type, and all computed metrics in the export

### Requirement 18: Weave Configuration and Environment Management

**User Story:** As a DevOps engineer, I want to configure Weave integration through environment variables and configuration files, so that I can adapt the evaluation infrastructure to different deployment environments.

#### Acceptance Criteria

1. WHEN WANDB_API_KEY environment variable is set, THE Weave_Evaluation_Harness SHALL use it for cloud authentication
2. WHEN WEAVE_PROJECT_NAME environment variable is set, THE Weave_Evaluation_Harness SHALL use it as the project name
3. WHEN WEAVE_ENTITY environment variable is set, THE Weave_Evaluation_Harness SHALL use it as the entity name
4. WHEN WEAVE_OFFLINE environment variable is "true", THE Weave_Evaluation_Harness SHALL activate local trace storage without requiring cloud credentials, and this activation SHALL take precedence over WANDB_API_KEY in the Weave enablement check
5. WHEN WEAVE_PARALLELISM environment variable is set, THE Weave_Evaluation_Harness SHALL use it as the parallel worker count
6. WHEN WEAVE_DISABLED environment variable is "true", THE Weave_Evaluation_Harness SHALL skip all Weave operations
7. WHEN weave_config.yaml exists in .kiro/evals/, THE Weave_Evaluation_Harness SHALL load configuration from the file
8. WHEN configuration loading fails, THE Weave_Evaluation_Harness SHALL use default values and log a warning
9. WHEN trace_enabled is false for a detection engine in config, THE Weave_Evaluation_Harness SHALL skip tracing for that engine
10. WHEN metrics_enabled is false for a detection engine in config, THE Weave_Evaluation_Harness SHALL skip metrics collection for that engine

### Requirement 19: Weave Evaluation Scenarios and Datasets

**User Story:** As a security tester, I want to define evaluation scenarios in YAML files and load them as Weave Datasets, so that I can version control test cases and track evaluation results over time.

#### Acceptance Criteria

1. WHEN loading evaluation scenarios, THE Weave_Evaluation_Harness SHALL read YAML files from the configured scenarios directory
2. WHEN parsing scenario files, THE Weave_Evaluation_Harness SHALL extract name, description, events, and expected_detections fields
3. WHEN creating Weave Datasets, THE Weave_Evaluation_Harness SHALL include all valid scenarios as dataset rows, where each row SHALL contain a non-empty description string
4. WHEN a scenario is missing a description field or the description is an empty string, THE Weave_Evaluation_Harness SHALL skip that scenario and log a warning identifying the offending file
5. WHEN scenario events are malformed, THE Weave_Evaluation_Harness SHALL log validation errors and skip the scenario
6. WHEN evaluation scenarios execute, THE Weave_Evaluation_Harness SHALL match detected threats against expected_detections
7. WHEN expected detections are not met, THE Weave_Evaluation_Harness SHALL log detection failures to Weave
8. WHEN scenarios include attack_path expectations, THE Weave_Evaluation_Harness SHALL validate min_nodes, attack_stages, and min_risk_score
9. WHEN scenarios include swarm expectations, THE Weave_Evaluation_Harness SHALL validate agent_ids, temporal_correlation, and coordination_score
10. WHEN scenarios include AILM expectations, THE Weave_Evaluation_Harness SHALL validate boundary_crossings and min_risk_level
11. WHEN evaluation completes, THE Weave_Evaluation_Harness SHALL export pass/fail status for each scenario to Weave

### Requirement 20: Weave Backward Compatibility

**User Story:** As a CI/CD maintainer, I want Weave integration to be fully optional and backward compatible, so that existing test infrastructure continues to work without modifications.

#### Acceptance Criteria

1. WHEN Weave credentials are unavailable, THE Advanced_Threat_Detection SHALL run all tests without Weave tracking
2. WHEN @pytest.mark.weave decorator is absent, THE test SHALL execute without Weave overhead
3. WHEN existing unit tests run, THE tests SHALL pass regardless of Weave configuration
4. WHEN existing integration tests run, THE tests SHALL pass regardless of Weave configuration
5. WHEN existing property tests run, THE tests SHALL pass regardless of Weave configuration
6. WHEN Weave initialization fails, THE Advanced_Threat_Detection SHALL log a warning and continue without Weave
7. WHEN Weave tracing fails during a test, THE test SHALL complete successfully and log the Weave error
8. WHEN should_enable_weave() returns False, THE @weave.op() decorators SHALL not be applied
9. WHEN weave_op_if_enabled() is used, THE function SHALL execute normally regardless of Weave state
10. WHEN Weave is disabled, THE system SHALL have zero performance overhead from Weave integration
11. WHEN pytest_collection_modifyitems runs and Weave is unavailable, THE Advanced_Threat_Detection SHALL automatically skip all tests marked with @pytest.mark.weave at collection time to prevent ImportError

### Requirement 21: Weave Optional Dependency and Marker Declaration

**User Story:** As a project maintainer, I want Weave dependencies and pytest markers to be formally declared in project configuration, so that the optional weave extras can be installed explicitly and CI tooling never encounters undeclared markers.

#### Acceptance Criteria

1. THE Advanced_Threat_Detection project configuration SHALL declare weave>=0.50.0 and wandb>=0.16.0 as optional dependencies under the [weave] extras group in pyproject.toml, installable via pip install -e ".[weave]"
2. THE Advanced_Threat_Detection project configuration SHALL register the @pytest.mark.weave marker under [tool.pytest.ini_options].markers in pyproject.toml with a human-readable description
3. WHEN a developer installs the project without the [weave] extra, THE Advanced_Threat_Detection SHALL import successfully and all non-Weave functionality SHALL operate normally
4. WHEN pytest collects tests on a project without the [weave] extra installed, THE pytest run SHALL not emit "PytestUnknownMarkWarning" for the weave marker

### Requirement 22: Active Threat Reaction and Fleet Containment Feedback Loop

**User Story:** As an enterprise security engineer, I want high-confidence threat evidence detected by ATD to trigger automated mitigation actions across Pillars 1, 2, and 3, so that rogue agent attacks are halted at machine speed before breaching host environments or expanding across the enterprise fleet.

#### Acceptance Criteria

1. WHEN CRITICAL threat evidence (multi-stage attack path, agent swarm, or exploit chain) is produced, THE Active_Reaction_Engine SHALL inject a dynamic eBPF socket drop rule into Pillar 1 (`LinuxeBPFDriver`) within 50 milliseconds
2. WHEN CRITICAL threat evidence is produced, THE Active_Reaction_Engine SHALL broadcast a zero-latency block signature across Pillar 2 Threat Mesh in less than 15 milliseconds
3. WHEN an AILM breach or credential theft event is detected, THE Active_Reaction_Engine SHALL trigger Pillar 3 Vault sidecar to invalidate JIT credentials for the compromised agent
4. WHEN a mitigation action is executed, THE Active_Reaction_Engine SHALL log an `ActiveReactionPayload` record to the attack graph and publish a notification alert to the Alert Bus
5. WHEN threat evidence originates from an evaluation environment, THE Active_Reaction_Engine SHALL resolve evaluation state from the underlying threat evidence graph using `trigger_evidence_id` and suppress production eBPF socket drops, fleet Threat Mesh broadcasts, and Vault revocations regardless of whether `evaluation_env_id` is populated, preventing evaluation scenarios from modifying production resources

### Requirement 23: Inbound Protocol Interception and Cross-Agent Request Inspection

**User Story:** As a system administrator, I want incoming A2A and MCP protocol requests targeting host agent endpoints to be inspected and rate-limited, so that external rogue agents cannot coerce local agents into executing unauthorized actions.

#### Acceptance Criteria

1. WHEN an HTTP/SSE request arrives at an MCP or A2A endpoint, THE Inbound_Protocol_Filter SHALL validate `Origin` and `Host` headers and reject unauthenticated or non-loopback network requests
2. WHEN incoming cross-agent request volume exceeds configured sliding-window thresholds, THE Inbound_Protocol_Filter SHALL drop additional requests and emit an inbound rate-limit alert
3. WHEN a valid incoming `tools/call` RPC message is received, THE Inbound_Protocol_Filter SHALL extract and sanitize arguments before passing the payload to the host agent
4. WHEN an incoming message fails JSON-RPC schema validation, THE Inbound_Protocol_Filter SHALL synthesize an MCP-compliant error response without leaking internal threat context

### Requirement 24: Indirect Prompt Injection and Data Poisoning Defense

**User Story:** As an AI safety architect, I want external data feeds (git diffs, web scrapes, incoming messages) passed to host agents to be scanned for prompt injections, so that data poisoning payloads cannot trick host agents into malicious tool execution.

#### Acceptance Criteria

1. WHEN external content is ingested for host agent context, THE Prompt_Injection_Scanner SHALL scan the payload for structural jailbreaks and system prompt override signatures
2. WHEN prompt injection patterns are identified, THE Prompt_Injection_Scanner SHALL redact and neutralize injection vectors before the content is added to the agent context window
3. WHEN a prompt injection attempt is detected, THE Prompt_Injection_Scanner SHALL publish an alert with HIGH or CRITICAL severity to the Alert Bus

### Requirement 25: Agent Fleet Resource and Token Velocity Enforcement (Denial of Wallet Defense)

**User Story:** As a cloud infrastructure lead, I want to monitor token burn rates and API velocity across agent fleets, so that rogue agent swarms cannot cause financial exhaustion or Denial of Wallet outages.

#### Acceptance Criteria

1. WHEN an agent executes actions, THE Agent_Quota_Enforcer SHALL record token consumption and track rolling token burn rates per second
2. WHEN an agent exceeds configured token burn rate or request velocity ceilings, THE Agent_Quota_Enforcer SHALL trigger automated throttling or temporary quarantine
3. WHEN a quota violation or velocity surge occurs, THE Agent_Quota_Enforcer SHALL publish a Denial of Wallet alert to the Alert Bus

