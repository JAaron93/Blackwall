# Implementation Plan: Blackwall Advanced Threat Detection

## Overview

This implementation plan creates the sixth pillar of Blackwall Enterprise Mesh: **Advanced Threat Detection**. The system performs temporal graph analysis, agent swarm detection, zero-day exploit chain recognition, and AI-Induced Lateral Movement (AILM) tracking across events from all five existing pillars.

The implementation follows a test-driven development approach with property-based testing for universal correctness properties and BDD feature tests (pytest-bdd) for security behavior contracts, and integration tests for cross-component behavior. Each task builds incrementally, validating functionality early through automated tests.

## Tasks

- [x] 1. Set up core project structure and data models
  - [x] 1.1 Create directory structure under `src/blackwall/enterprise/advanced_threat_detection/`
    - Create `__init__.py`, `models.py`, `enums.py`
    - Set up module exports and basic logging configuration
    - _Requirements: 15.1, 15.2, 15.3, 15.4_
    - _Verification: `pytest -c pyproject.toml -k "from blackwall.enterprise.advanced_threat_detection import models" --collect-only`_

  - [x] 1.2 Implement core data models with Pydantic validation
    - Create `NormalizedEvent`, `AttackNode`, `AttackPath`, `SwarmEvidence`, `ExploitChainEvidence`, `AILMEvidence`, `C2Evidence`, `K8sThreatEvidence`, `RegistryThreatEvidence` models
    - Implement field validators for UUID v4, timezone-aware timestamps, score ranges [0.0, 1.0]
    - Add validator for minimum list/set sizes (paths >= 2 nodes, swarms >= 2 agents)
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9_
    - _Verification: `pytest tests/unit/test_models.py -v`_

  - [x] 1.3 Write property tests for data model validation
    - **Property 3: Normalized Event UUID Validity**
    - **Property 4: Normalized Event Timestamp Timezone**
    - **Property 5: Risk Score Bounds**
    - **Property 10: Attack Path Minimum Node Validation**
    - **Property 11: Attack Path Temporal Validity**
    - **Property 26: Swarm Evidence Agent Count Validation**
    - **Property 27: Swarm Evidence Correlation Threshold Validation**
    - **Validates: Requirements 15.1, 15.2, 15.3, 15.5, 15.6, 15.7, 15.8**
    - _Verification: `pytest tests/property/test_models_properties.py --hypothesis-seed=0 -v`_

  - [ ] 1.4 Write BDD feature tests for core data models
    - Create `tests/features/data_models.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_data_models_bdd.py` using `run_async` from `tests.step_defs.async_utils`
    - Scenario: NormalizedEvent creation assigns valid UUID v4 and UTC timezone-aware timestamp
    - Scenario: risk_score outside [0.0, 1.0] is rejected with a validation error
    - Scenario: AttackPath with fewer than 2 nodes is rejected with a validation error
    - Scenario: SwarmEvidence with fewer than 2 agent_ids is rejected with a validation error
    - _Requirements: 15.1, 15.2, 15.3, 15.4, 15.5, 15.6, 15.7, 15.8, 15.9_
    - _Verification: `pytest tests/step_defs/test_data_models_bdd.py -v`_


- [x] 2. Implement Attack Graph Store with PostgreSQL/TimescaleDB
  - [x] 2.1 Create AttackGraphStore class with connection pooling
    - Implement async PostgreSQL connection pool using `asyncpg`
    - Create schema for event nodes and temporal edges
    - Set up TimescaleDB hypertable for time-series optimization
    - _Requirements: 11.5, 11.6_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_connection_pool -v`_

  - [x] 2.2 Implement event insertion with temporal ordering
    - Create `insert_event()` method storing NormalizedEvent as AttackNode
    - Maintain incoming/outgoing edge lists for each node
    - Ensure temporal ordering preserved in graph structure
    - Wrap DB persistence in `async with conn.transaction()` and mutate in-memory cache only after commit (architecture rule 2)
    - _Requirements: 2.1, 2.5_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_insert_event -v`_

  - [x] 2.3 Implement causal edge creation
    - Create `link_events()` method with relationship type parameter
    - Update edge lists for both source and target nodes atomically
    - Wrap UUID parsing in try/except for malformed edge UUIDs (architecture rule 9)
    - _Requirements: 2.2_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_link_events -v`_

  - [x] 2.4 Implement multi-hop path query engine
    - Create `query_paths()` method with time window and minimum path length filters
    - Validate `max_nodes`, `max_paths`, `max_depth`, `limit` are strictly positive (architecture rule 10)
    - Optimize queries for 17K+ event graphs (response time < 500ms); include warmup query before SLA timing (testing rule 1)
    - Return AttackPath objects ordered by risk_score descending
    - _Requirements: 2.3, 2.4, 11.2_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_query_paths_performance -v`_

  - [x] 2.5 Write property tests for Attack Graph Store
    - **Property 6: Temporal Ordering Preservation**
    - **Property 7: Causal Edge Creation**
    - **Property 8: Path Query Minimum Length Enforcement**
    - **Property 9: Node Edge List Integrity**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.5**
    - _Verification: `pytest tests/property/test_attack_graph_properties.py --hypothesis-seed=0 -v`_

  - [ ] 2.6 Write BDD feature tests for Attack Graph Store
    - Create `tests/features/attack_graph_store.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_attack_graph_store_bdd.py` using `run_async`
    - Scenario: inserting a NormalizedEvent creates a node with temporal ordering preserved
    - Scenario: linking two events creates a directed edge with the specified relationship type
    - Scenario: querying paths returns only paths with at least min_path_length nodes within the time window
    - Scenario: path query on a 17K+ event graph completes in under 500ms (warmup run excluded)
    - Scenario: non-positive limit parameter raises ValueError
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 11.2_
    - _Verification: `pytest tests/step_defs/test_attack_graph_store_bdd.py -v`_

- [x] 3. Checkpoint - Verify core infrastructure
  - Ensure all tests pass, ask the user if questions arise.

- [x] 4. Implement Event Stream Collector
  - [x] 4.1 Create EventStreamCollector class with pillar subscriptions
    - Implement async iterator interfaces for all five pillar event streams
    - Create event source enum mapping (KERNEL_SYSCALL, TOOL_CALL, IDENTITY_ACCESS, PIPELINE_EXECUTION, FORENSIC_ALERT)
    - Subscribe passively without blocking pillar operations (architecture rule 12.7)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_pillar_subscriptions -v`_

  - [x] 4.2 Implement event normalization logic
    - Create normalization functions for each pillar event type
    - Enrich events with temporal context and agent metadata
    - Generate UUID v4 event_id and UTC timestamp for each event
    - Use `val is None` checks (not truthiness) for falsy agent_id=0 (architecture rule 8)
    - Naive datetimes must log a warning and fall back to `datetime.now(timezone.utc)` (architecture rule 8)
    - Compute initial risk_score based on event characteristics
    - _Requirements: 1.6, 1.7, 1.8, 1.9_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_normalization -v`_

  - [x] 4.3 Implement error handling for pillar connection failures
    - Add exponential backoff reconnection logic; validate `hasattr(stream, "__aiter__")` (architecture rule 8)
    - Re-raise TypeError/ValueError immediately without backoff (architecture rule 8)
    - Log malformed events without blocking stream; include EventSource in warning with %-formatting
    - _Requirements: 12.1, 12.6_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_error_handling -v`_

  - [x] 4.4 Write property tests for event normalization
    - **Property 1: Event Normalization Source Mapping**
    - **Property 2: Event Enrichment Completeness**
    - **Property 76: Agent ID Non-Empty Validation**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 15.4**
    - _Verification: `pytest tests/property/test_event_collector_properties.py --hypothesis-seed=0 -v`_

  - [ ] 4.5 Write BDD feature tests for Event Stream Collector
    - Create `tests/features/event_stream_collector.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_event_stream_collector_bdd.py` using `run_async`
    - Scenario: kernel syscall event is normalized to KERNEL_SYSCALL source with UTC timestamp and UUID v4
    - Scenario: each of the five pillar sources maps to the correct EventSource enum value
    - Scenario: event is enriched with temporal context and agent metadata
    - Scenario: pillar stream disconnection triggers exponential backoff and reconnection attempt
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 12.1, 12.2, 12.3, 12.4, 12.5_
    - _Verification: `pytest tests/step_defs/test_event_stream_collector_bdd.py -v`_

- [x] 5. Implement Multi-Stage Attack Path Correlation
  - [x] 5.1 Create PathCorrelator class with DFS path finding
    - Implement `correlate_attack_paths()` with time window filtering
    - Build temporal adjacency graph with 5-minute window edges; break loop when delta_sec > 300 (architecture rule 10)
    - Compute edge weights based on temporal proximity and semantic relationships
    - _Requirements: 3.1, 3.2, 3.3_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_temporal_adjacency -v`_

  - [x] 5.2 Implement depth-first search for path enumeration
    - Create recursive DFS with minimum path length constraint
    - Precompute incoming edge index for O(1) directed edge lookup (architecture rule 10)
    - Skip reverse-ordered sequences where end_time < start_time (architecture rule 10)
    - Handle empty path list when agent has insufficient events
    - _Requirements: 3.4, 3.6_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_dfs_path_finding -v`_

  - [x] 5.3 Implement MITRE ATT&CK technique mapping
    - Map event sequences to MITRE ATT&CK technique IDs
    - Populate attack_stages field in AttackPath
    - Validate all technique IDs against MITRE database
    - _Requirements: 2.8, 3.7_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_mitre_mapping -v`_

  - [x] 5.4 Implement risk scoring and path ranking
    - Compute aggregate risk_score for paths
    - Compute correlation_score for path confidence
    - Sort results by risk_score descending
    - _Requirements: 2.9, 2.10, 3.5_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_risk_scoring -v`_

  - [x] 5.5 Write property tests for path correlation
    - **Property 14: Time Window Filtering**
    - **Property 15: Temporal Adjacency Rule**
    - **Property 16: Edge Weight Computation**
    - **Property 17: Path Finding Completeness**
    - **Property 18: Risk Score Ordering**
    - **Property 19: Empty Path List for Insufficient Events**
    - **Property 20: MITRE Technique Mapping**
    - Include dense-window regression test: 150+ events in a 300s window, assert sub-500ms (testing rule 14)
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
    - _Verification: `pytest tests/property/test_path_correlator_properties.py --hypothesis-seed=0 -v`_

  - [ ] 5.6 Write BDD feature tests for Multi-Stage Attack Path Correlation
    - Create `tests/features/path_correlation.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_path_correlation_bdd.py` using `run_async`
    - Scenario: events within 5 minutes of each other are linked in the temporal adjacency graph
    - Scenario: events more than 5 minutes apart are not linked
    - Scenario: DFS finds all paths meeting the minimum length requirement
    - Scenario: returned paths are ordered by risk_score descending
    - Scenario: agent with fewer events than min_path_length returns an empty list
    - Scenario: attack stages are mapped to valid MITRE ATT&CK technique IDs
    - _Requirements: 2.8, 2.9, 2.10, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_
    - _Verification: `pytest tests/step_defs/test_path_correlation_bdd.py -v`_

- [x] 6. Checkpoint - Verify attack path correlation
  - Ensure all tests pass, ask the user if questions arise.

- [x] 7. Implement Agent Swarm Detector
  - [x] 7.1 Create AgentSwarmDetector class with behavioral fingerprinting
    - Implement `fingerprint_agent()` using action sequence hashing
    - Generate consistent fingerprints over configurable time windows (default 3600s)
    - _Requirements: 4.1_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_fingerprinting -v`_

  - [x] 7.2 Implement temporal correlation analysis
    - Create `detect_swarms()` with correlation threshold (default 0.75)
    - Compute temporal correlation between agent pairs
    - Identify groups with minimum agent count (default 2)
    - _Requirements: 4.2, 4.3_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_temporal_correlation -v`_

  - [x] 7.3 Implement shared infrastructure identification
    - Detect shared IP addresses across agents
    - Detect shared domains and resource patterns
    - Populate shared_patterns field in SwarmEvidence
    - _Requirements: 4.4_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_shared_infrastructure -v`_

  - [x] 7.4 Implement coordination score computation
    - Create `compute_coordination_score()` analyzing temporal alignment
    - Analyze behavioral similarity between agents
    - Validate coordination_score range [0.0, 1.0]
    - _Requirements: 4.5, 15.9_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_coordination_score -v`_

  - [x]* 7.5 Write property tests for swarm detection
    - **Property 21: Behavioral Fingerprint Generation**
    - **Property 22: Swarm Correlation Threshold Enforcement**
    - **Property 23: Swarm Minimum Size Enforcement**
    - **Property 24: Shared Infrastructure Identification**
    - **Property 25: Coordination Score Computation**
    - **Property 28: High-Confidence Swarm Threshold**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.8**
    - _Verification: `pytest tests/property/test_swarm_detector_properties.py --hypothesis-seed=0 -v`_

  - [x] 7.6 Write BDD feature tests for Agent Swarm Detector
    - Create `tests/features/agent_swarm_detector.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_agent_swarm_detector_bdd.py` using `run_async`
    - Scenario: agent behavioral fingerprint is consistent for the same action sequence over a time window
    - Scenario: two agents with temporal_correlation >= 0.75 are grouped into a swarm
    - Scenario: fewer than 2 agents cannot form a swarm
    - Scenario: shared IP addresses and domains are identified in SwarmEvidence.shared_patterns
    - Scenario: SwarmEvidence with coordination_score >= 0.75 is classified as high-confidence
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 15.7, 15.8, 15.9_
    - _Verification: `pytest tests/step_defs/test_agent_swarm_detector_bdd.py -v`_

- [x] 8. Implement Exploit Chain Analyzer
  - [x] 8.1 Create ExploitChainAnalyzer class with exploit classification
    - Implement `classify_exploit()` mapping events to ExploitCategory enum
    - Support categories: RCE, Privilege Escalation, Credential Theft, Persistence, Lateral Movement
    - Return None for non-exploit events
    - _Requirements: 5.1_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_classify_exploit -v`_

  - [x] 8.2 Implement exploit chain pattern detection
    - Create `detect_chains()` identifying sequences like RCE → Privilege Escalation → Credential Theft
    - Filter chains by time window constraints
    - Generate ExploitChainEvidence with chain_id and exploits list
    - _Requirements: 5.2_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_chain_detection -v`_

  - [x] 8.3 Implement novelty scoring against baseline
    - Create `compute_novelty_score()` comparing chains to historical patterns
    - Novel chains approach 1.0, known patterns approach 0.0
    - Maintain baseline pattern database
    - _Requirements: 5.3, 5.4, 5.5_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_novelty_scoring -v`_

  - [x] 8.4 Implement chaining confidence computation
    - Compute chaining_confidence for ExploitChainEvidence
    - Consider temporal proximity and semantic relationships
    - _Requirements: 5.6_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_chaining_confidence -v`_

  - [x] 8.5 Write property tests for exploit chain analysis
    - **Property 29: Exploit Event Classification**
    - **Property 30: Exploit Chain Pattern Detection**
    - **Property 31: Novelty Score Baseline Comparison**
    - **Property 32: Novel Chain High Novelty Score**
    - **Property 33: Known Chain Low Novelty Score**
    - **Property 34: Chaining Confidence Computation**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6**
    - _Verification: `pytest tests/property/test_exploit_chain_properties.py --hypothesis-seed=0 -v`_

  - [x] 8.6 Write BDD feature tests for Exploit Chain Analyzer
    - Create `tests/features/exploit_chain_analyzer.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_exploit_chain_analyzer_bdd.py` using `run_async`
    - Scenario: a known RCE event is classified as ExploitCategory.RCE
    - Scenario: an event with no exploit indicators returns None classification
    - Scenario: RCE → Privilege Escalation → Credential Theft sequence is detected as an exploit chain
    - Scenario: a never-before-seen chain receives novelty_score approaching 1.0
    - Scenario: a chain matching baseline patterns receives novelty_score approaching 0.0
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
    - _Verification: `pytest tests/step_defs/test_exploit_chain_analyzer_bdd.py -v`_

- [x] 9. Checkpoint - Verify detection engines
  - Ensure all tests pass, ask the user if questions arise.

- [x] 10. Implement AI-Induced Lateral Movement (AILM) Tracker
  - [x] 10.1 Create AILMTracker class with permission tracking
    - Implement `track_permission_grant()` recording PermissionGrant objects
    - Store grants with permission, granted_by, granted_to, timestamp, and scope
    - _Requirements: 6.1_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_track_permission -v`_

  - [x] 10.2 Implement permission composition detection
    - Create `detect_permission_composition()` identifying accumulation patterns
    - Detect agents accumulating multiple permissions over time
    - Detect permissions spanning multiple trust boundaries
    - _Requirements: 6.2, 6.3_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_composition_detection -v`_

  - [x] 10.3 Implement security boundary crossing identification
    - Create `identify_boundary_crossing()` determining if context transitions cross boundaries
    - Define trust boundary mappings
    - _Requirements: 6.4_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_boundary_crossing -v`_

  - [x] 10.4 Implement AILM risk level computation
    - Compute risk_level classification (LOW, MEDIUM, HIGH, CRITICAL)
    - Populate composed_permissions and boundary_crossings in AILMEvidence
    - _Requirements: 6.5, 6.6_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_risk_level -v`_

  - [x] 10.5 Write property tests for AILM tracking
    - **Property 35: Permission Grant Recording**
    - **Property 36: Permission Accumulation Detection**
    - **Property 37: Cross-Boundary Permission Detection**
    - **Property 38: Security Boundary Crossing Identification**
    - **Property 39: AILM Risk Level Computation**
    - **Property 40: AILM Evidence Completeness**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6**
    - _Verification: `pytest tests/property/test_ailm_tracker_properties.py --hypothesis-seed=0 -v`_

  - [x] 10.6 Write BDD feature tests for AILM Tracker
    - Create `tests/features/ailm_tracker.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_ailm_tracker_bdd.py` using `run_async`
    - Scenario: a permission grant is recorded with all required fields (permission, granted_by, granted_to, timestamp, scope)
    - Scenario: an agent accumulating permissions across multiple time windows is detected
    - Scenario: permissions spanning two trust boundaries are identified as a cross-boundary composition
    - Scenario: AILM evidence with 3+ boundary crossings receives CRITICAL risk_level
    - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6_
    - _Verification: `pytest tests/step_defs/test_ailm_tracker_bdd.py -v`_

- [ ] 11. Implement C2 Infrastructure Detector
  - [ ] 11.1 Create C2InfrastructureDetector class with endpoint classification
    - Implement `classify_endpoint()` with database of known C2 service patterns
    - Detect RequestBin, Pastebin, GitHub Gist, cloud storage services, webhook receivers
    - Return service type or None for non-C2 endpoints
    - _Requirements: 7.1_
    - _Verification: `pytest tests/unit/test_c2_detector.py::test_classify_endpoint -v`_

  - [ ] 11.2 Implement C2 establishment detection
    - Create `detect_c2_establishment()` identifying agents creating/accessing C2 endpoints
    - Populate C2Evidence with c2_endpoints list
    - _Requirements: 7.2_
    - _Verification: `pytest tests/unit/test_c2_detector.py::test_c2_establishment -v`_

  - [ ] 11.3 Implement beaconing pattern detection
    - Create `detect_beaconing()` analyzing network connection timing
    - Identify periodic polling or callback behavior
    - Classify communication_pattern (beaconing, polling, webhook, etc.)
    - _Requirements: 7.3, 7.4_
    - _Verification: `pytest tests/unit/test_c2_detector.py::test_beaconing -v`_

  - [ ] 11.4 Implement persistence indicator identification
    - Detect self-respawning processes, cron jobs, scheduled tasks
    - Populate persistence_indicators list in C2Evidence
    - Correlate network events from Pillar 1 with tool call patterns
    - _Requirements: 7.5, 7.6_
    - _Verification: `pytest tests/unit/test_c2_detector.py::test_persistence_indicators -v`_

  - [ ] 11.5 Write property tests for C2 detection
    - **Property 41: C2 Endpoint Detection**
    - **Property 42: Beaconing Pattern Detection**
    - **Property 43: C2 Communication Pattern Classification**
    - **Property 44: C2 Persistence Indicator Identification**
    - **Property 45: Cross-Pillar C2 Correlation**
    - **Validates: Requirements 7.2, 7.3, 7.4, 7.5, 7.6**
    - _Verification: `pytest tests/property/test_c2_detector_properties.py --hypothesis-seed=0 -v`_

  - [ ] 11.6 Write BDD feature tests for C2 Infrastructure Detector
    - Create `tests/features/c2_infrastructure_detector.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_c2_infrastructure_detector_bdd.py` using `run_async`
    - Scenario: a Pastebin URL is classified as a known C2 endpoint
    - Scenario: an agent accessing a C2 endpoint generates C2Evidence with the endpoint in c2_endpoints
    - Scenario: periodic connections at regular intervals are identified as beaconing
    - Scenario: a process that recreates itself after termination is identified as a persistence indicator
    - Scenario: C2 evidence includes cross-pillar correlation between Pillar 1 network events and tool calls
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
    - _Verification: `pytest tests/step_defs/test_c2_infrastructure_detector_bdd.py -v`_

- [ ] 12. Implement Kubernetes Defense Layer
  - [ ] 12.1 Create KubernetesDefenseLayer class with pod token theft detection
    - Implement `detect_pod_token_theft()` identifying unauthorized access to service account tokens
    - Monitor file access to `/var/run/secrets/kubernetes.io/serviceaccount/token`
    - Generate K8sThreatEvidence with threat_type, namespace, pod_name, service_account
    - _Requirements: 8.1, 8.4_
    - _Verification: `pytest tests/unit/test_k8s_defense.py::test_pod_token_theft -v`_

  - [ ] 12.2 Implement fleet spawning detection
    - Create `detect_fleet_spawning()` identifying rapid pod creation patterns
    - Detect creation across multiple nodes within short time windows
    - _Requirements: 8.2_
    - _Verification: `pytest tests/unit/test_k8s_defense.py::test_fleet_spawning -v`_

  - [ ] 12.3 Implement secrets exfiltration detection
    - Create `detect_secrets_exfiltration()` identifying bulk secret reads from Kubernetes API
    - Track both successful and failed API calls
    - _Requirements: 8.3, 8.5_
    - _Verification: `pytest tests/unit/test_k8s_defense.py::test_secrets_exfiltration -v`_

  - [ ] 12.4 Implement self-respawning pod detection
    - Detect pods that automatically recreate after termination
    - Identify restart loop patterns
    - _Requirements: 8.6_
    - _Verification: `pytest tests/unit/test_k8s_defense.py::test_self_respawn -v`_

  - [ ] 12.5 Write property tests for Kubernetes defense
    - **Property 46: Pod Token Theft Detection**
    - **Property 47: Fleet Spawning Detection**
    - **Property 48: Secrets Exfiltration Detection**
    - **Property 49: K8s Threat Evidence Completeness**
    - **Property 50: K8s API Access Tracking Coverage**
    - **Property 51: Self-Respawning Pod Detection**
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6**
    - _Verification: `pytest tests/property/test_k8s_defense_properties.py --hypothesis-seed=0 -v`_

  - [ ] 12.6 Write BDD feature tests for Kubernetes Defense Layer
    - Create `tests/features/kubernetes_defense.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_kubernetes_defense_bdd.py` using `run_async`
    - Scenario: file access to `/var/run/secrets/kubernetes.io/serviceaccount/token` triggers pod token theft detection
    - Scenario: 10 pods created across 5 nodes in 60 seconds is detected as fleet spawning
    - Scenario: bulk reads of Kubernetes secrets via the API are flagged as secrets exfiltration
    - Scenario: a pod that recreates after termination is detected as self-respawning
    - Scenario: K8sThreatEvidence includes threat_type, namespace, pod_name, and service_account
    - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6_
    - _Verification: `pytest tests/step_defs/test_kubernetes_defense_bdd.py -v`_

- [ ] 13. Implement Package Registry Monitor
  - [ ] 13.1 Create PackageRegistryMonitor class with registry access monitoring
    - Implement `monitor_registry_access()` as async iterator for registry events
    - Intercept HTTP traffic to Artifactory, npm, PyPI proxies
    - Generate NormalizedEvent for each registry access
    - _Requirements: 9.1_
    - _Verification: `pytest tests/unit/test_registry_monitor.py::test_monitor_access -v`_

  - [ ] 13.2 Implement exploit probing detection
    - Create `detect_exploit_probing()` identifying malformed package requests
    - Detect unusual request patterns deviating from normal package manager behavior
    - Generate RegistryThreatEvidence with registry_type and exploit_indicators
    - _Requirements: 9.2, 9.3, 9.4, 9.5_
    - _Verification: `pytest tests/unit/test_registry_monitor.py::test_exploit_probing -v`_

  - [ ] 13.3 Implement CVE correlation
    - Compare detected patterns against known CVE exploitation signatures
    - Populate cve_candidates list in RegistryThreatEvidence
    - _Requirements: 9.6_
    - _Verification: `pytest tests/unit/test_registry_monitor.py::test_cve_correlation -v`_

  - [ ] 13.4 Write property tests for registry monitoring
    - **Property 52: Malformed Registry Request Detection**
    - **Property 53: Unusual Registry Pattern Detection**
    - **Property 54: Registry Threat Evidence Type**
    - **Property 55: Registry Threat Evidence Indicators**
    - **Property 56: Registry CVE Correlation**
    - **Validates: Requirements 9.2, 9.3, 9.4, 9.5, 9.6**
    - _Verification: `pytest tests/property/test_registry_monitor_properties.py --hypothesis-seed=0 -v`_

  - [ ] 13.5 Write BDD feature tests for Package Registry Monitor
    - Create `tests/features/package_registry_monitor.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_package_registry_monitor_bdd.py` using `run_async`
    - Scenario: a malformed npm package request is detected as exploit probing
    - Scenario: an unusual request sequence deviating from normal PyPI behavior is flagged
    - Scenario: RegistryThreatEvidence includes the registry_type (Artifactory, npm, or PyPI)
    - Scenario: detected pattern matching a known CVE signature populates cve_candidates
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_
    - _Verification: `pytest tests/step_defs/test_package_registry_monitor_bdd.py -v`_

- [ ] 14. Checkpoint - Verify all detection components
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 15. Implement Alert Generation and Real-Time Integration
  - [ ] 15.1 Create AlertBus class for alert publication
    - Implement alert publishing interface with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
    - Add retry logic for alert delivery failures (up to 5 retries)
    - Log persistent failures for manual investigation
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_
    - _Verification: `pytest tests/unit/test_alert_bus.py::test_alert_publishing -v`_

  - [ ] 15.2 Implement alert generation for swarm detection
    - Publish CRITICAL alerts when swarms detected
    - Include SwarmEvidence in alert payload
    - _Requirements: 10.1_
    - _Verification: `pytest tests/unit/test_alert_generation.py::test_swarm_alerts -v`_

  - [ ] 15.3 Implement alert generation for AILM events
    - Map AILM risk_level to alert severity (HIGH or CRITICAL)
    - Include AILMEvidence in alert payload
    - _Requirements: 10.2_
    - _Verification: `pytest tests/unit/test_alert_generation.py::test_ailm_alerts -v`_

  - [ ] 15.4 Implement alert generation for exploit chains, attack paths, C2, K8s threats, and registry threats
    - Map novelty_score to severity for exploit chains
    - Map risk_score to severity for attack paths
    - CRITICAL severity for C2 infrastructure detection
    - Map threat_type to severity for Kubernetes threats
    - Map exploit confidence to severity for registry threats
    - _Requirements: 10.3, 10.4, 10.5, 10.6, 10.7_
    - _Verification: `pytest tests/unit/test_alert_generation.py::test_all_alert_types -v`_

  - [ ] 15.5 Write property tests for alert generation
    - **Property 57: Swarm Detection Alert Generation**
    - **Property 58: AILM Alert Severity Mapping**
    - **Property 59: Exploit Chain Alert Severity Mapping**
    - **Property 60: Attack Path Alert Severity Mapping**
    - **Property 61: C2 Detection Alert Generation**
    - **Property 62: K8s Threat Alert Severity Mapping**
    - **Property 63: Registry Threat Alert Severity Mapping**
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7**
    - _Verification: `pytest tests/property/test_alert_generation_properties.py --hypothesis-seed=0 -v`_

  - [ ] 15.6 Write BDD feature tests for Alert Generation
    - Create `tests/features/alert_generation.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_alert_generation_bdd.py` using `run_async`
    - Scenario: detected swarm publishes a CRITICAL alert to the AlertBus
    - Scenario: AILM evidence with HIGH risk_level publishes a HIGH severity alert
    - Scenario: exploit chain with novelty_score 0.9 publishes a CRITICAL alert
    - Scenario: detected C2 infrastructure publishes a CRITICAL alert
    - Scenario: alert delivery failure retries up to 5 times before logging a persistent failure
    - _Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7_
    - _Verification: `pytest tests/step_defs/test_alert_generation_bdd.py -v`_

- [ ] 16. Implement Performance Optimization and SLA Validation
  - [ ] 16.1 Optimize event processing pipeline for low latency
    - Ensure event processing from all pillars < 100ms latency
    - Implement async batching and connection pooling
    - _Requirements: 11.1_
    - _Verification: `pytest tests/integration/test_performance.py::test_event_processing_latency -v`_

  - [ ] 16.2 Optimize path query performance
    - Ensure path queries < 500ms for 17K+ event graphs
    - Add database indexes for temporal queries
    - Implement query result caching where appropriate
    - Run one warmup query before SLA timing (testing rule 1)
    - _Requirements: 11.2_
    - _Verification: `pytest tests/integration/test_performance.py::test_path_query_latency -v`_

  - [ ] 16.3 Implement sustained throughput handling
    - Validate system handles 1,000 events/second sustained
    - Load test for at least 5 minutes
    - _Requirements: 11.3_
    - _Verification: `pytest tests/integration/test_performance.py::test_sustained_throughput -v`_

  - [ ] 16.4 Optimize swarm detection fingerprinting
    - Ensure behavioral fingerprints for 1-hour windows < 2 seconds latency
    - Implement incremental fingerprint updates
    - _Requirements: 11.4_
    - _Verification: `pytest tests/integration/test_performance.py::test_fingerprint_latency -v`_

  - [ ] 16.5 Write BDD feature tests for Performance and SLA Validation
    - Create `tests/features/performance_sla.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_performance_sla_bdd.py` using `run_async`
    - Scenario: event processing latency is under 100ms (warmup run excluded from measurement)
    - Scenario: path query on 17K+ event graph completes in under 500ms
    - Scenario: system sustains 1,000 events/second for at least 5 minutes without errors
    - Scenario: behavioral fingerprint for a 1-hour window is computed in under 2 seconds
    - _Requirements: 11.1, 11.2, 11.3, 11.4_
    - _Verification: `pytest tests/step_defs/test_performance_sla_bdd.py -v`_

- [ ] 17. Implement Retrospective Analysis and Historical Queries
  - [ ] 17.1 Implement historical time window support
    - Support queries spanning days or weeks
    - Maintain 30-day event history in Attack_Graph
    - _Requirements: 13.1, 13.4_
    - _Verification: `pytest tests/integration/test_retrospective.py::test_historical_windows -v`_

  - [ ] 17.2 Implement retrospective path detection
    - Identify attack paths not detected in real-time
    - Support batch analysis of historical data
    - _Requirements: 13.2_
    - _Verification: `pytest tests/integration/test_retrospective.py::test_retrospective_detection -v`_

  - [ ] 17.3 Implement multi-agent historical correlation
    - Correlate events across multiple agents for delayed swarm pattern detection
    - _Requirements: 13.3_
    - _Verification: `pytest tests/integration/test_retrospective.py::test_historical_correlation -v`_

  - [ ] 17.4 Implement attack graph export
    - Support export in standard formats (JSON, GraphML)
    - Enable external analysis tool integration
    - _Requirements: 13.5_
    - _Verification: `pytest tests/unit/test_graph_export.py::test_export_formats -v`_

  - [ ] 17.5 Write property tests for retrospective analysis
    - **Property 65: Historical Time Window Support**
    - **Property 66: Retrospective Path Detection**
    - **Property 67: Multi-Agent Historical Correlation**
    - **Property 68: Attack Graph Export Format Compliance**
    - **Validates: Requirements 13.1, 13.2, 13.3, 13.5**
    - _Verification: `pytest tests/property/test_retrospective_properties.py --hypothesis-seed=0 -v`_

  - [ ] 17.6 Write BDD feature tests for Retrospective Analysis
    - Create `tests/features/retrospective_analysis.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_retrospective_analysis_bdd.py` using `run_async`
    - Scenario: historical time window query spanning 7 days returns all attack paths in that period
    - Scenario: retrospective analysis identifies attack paths missed during real-time processing
    - Scenario: multi-agent correlation across 30-day history detects delayed swarm patterns
    - Scenario: attack graph export produces valid JSON and GraphML output
    - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.5_
    - _Verification: `pytest tests/step_defs/test_retrospective_analysis_bdd.py -v`_

- [ ] 18. Implement Evaluation Environment Support
  - [ ] 18.1 Create evaluation environment labeling
    - Add evaluation environment identifier to event metadata
    - Prevent eval alerts from triggering production workflows
    - _Requirements: 14.1, 14.2_
    - _Verification: `pytest tests/unit/test_evaluation_mode.py::test_eval_labeling -v`_

  - [ ] 18.2 Implement isolated attack graph instances per evaluation environment
    - Create separate graph instances for each eval environment
    - Ensure isolation from production and other eval environments
    - _Requirements: 14.3_
    - _Verification: `pytest tests/unit/test_evaluation_mode.py::test_graph_isolation -v`_

  - [ ] 18.3 Implement evaluation state reset
    - Support resetting eval environment to clean state
    - Clear attack graphs and event history
    - _Requirements: 14.4_
    - _Verification: `pytest tests/unit/test_evaluation_mode.py::test_state_reset -v`_

  - [ ] 18.4 Write property tests for evaluation mode
    - **Property 69: Evaluation Mode Event Labeling**
    - **Property 70: Evaluation Mode Alert Isolation**
    - **Property 71: Evaluation Environment Graph Isolation**
    - **Property 72: Evaluation State Reset**
    - **Property 97: Evaluation Mode Reaction Suppression**
    - **Validates: Requirements 14.1, 14.2, 14.3, 14.4, 14.5, 22.5**
    - _Verification: `pytest tests/property/test_evaluation_mode_properties.py --hypothesis-seed=0 -v`_

  - [ ] 18.5 Write BDD feature tests for Evaluation Environment Support
    - Create `tests/features/evaluation_environment.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_evaluation_environment_bdd.py` using `run_async`
    - Scenario: events in evaluation mode carry the eval environment identifier in metadata
    - Scenario: alerts generated in evaluation mode do not trigger production incident response
    - Scenario: two evaluation environments use isolated attack graph instances with no shared state
    - Scenario: resetting evaluation state returns the environment to a clean initial state
    - Scenario: threat evidence generated in evaluation mode suppresses production reactions and logs payloads to evaluation log
    - _Requirements: 14.1, 14.2, 14.3, 14.4, 14.5, 22.5_
    - _Verification: `pytest tests/step_defs/test_evaluation_environment_bdd.py -v`_

- [ ] 19. Checkpoint - Verify auxiliary features
  - Ensure all tests pass, ask the user if questions arise.

- [ ] 20. Implement Error Handling and Resilience
  - [ ] 20.1 Implement pillar connection failure handling
    - Add exponential backoff reconnection for pillar streams
    - Validate `hasattr(stream, "__aiter__")` before iterating (architecture rule 8)
    - Continue collecting from available pillars during partial failures
    - Log connection failures with detailed diagnostics using EventSource %-formatting
    - _Requirements: 12.1, 12.6_
    - _Verification: `pytest tests/unit/test_error_handling.py::test_pillar_failure_recovery -v`_

  - [ ] 20.2 Implement database failure handling
    - Return error results on database unavailability
    - Retry transactions up to 3 times with exponential backoff
    - Handle query timeouts with partial results
    - _Requirements: 2.4, 11.5_
    - _Verification: `pytest tests/unit/test_error_handling.py::test_database_failure_handling -v`_

  - [ ] 20.3 Implement detection engine error recovery
    - Skip failed detections without crashing service
    - Log full error context for debugging
    - Continue with other detections
    - Throttle processing on resource exhaustion
    - _Verification: `pytest tests/unit/test_error_handling.py::test_detection_error_recovery -v`_

  - [ ] 20.4 Write integration tests for error scenarios
    - Test pillar disconnection and reconnection
    - Test database failover scenarios
    - Test partial system degradation
    - _Verification: `pytest tests/integration/test_error_scenarios.py -v`_

  - [ ] 20.5 Write BDD feature tests for Error Handling and Resilience
    - Create `tests/features/error_handling.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_error_handling_bdd.py` using `run_async`
    - Scenario: pillar stream disconnection triggers exponential backoff without blocking other pillars
    - Scenario: database transaction failure retries up to 3 times then returns an error result
    - Scenario: detection engine exception skips that detection and continues with remaining engines
    - Scenario: resource exhaustion throttles processing and emits a capacity warning
    - _Verification: `pytest tests/step_defs/test_error_handling_bdd.py -v`_

- [ ] 21. Integration and System Wiring
  - [ ] 21.1 Create main AdvancedThreatDetection orchestrator class
    - Wire EventStreamCollector to AttackGraphStore
    - Wire AttackGraphStore to all detection engines
    - Wire detection engines to AlertBus
    - Implement async event processing loops
    - _Requirements: 12.6, 12.7_
    - _Verification: `pytest tests/integration/test_orchestrator.py::test_component_wiring -v`_

  - [ ] 21.2 Implement pillar integration points
    - Subscribe to Pillar 1 (Kernel eBPF/Audit) event stream
    - Subscribe to Pillar 2 (Threat Mesh) signature stream
    - Subscribe to Pillar 3 (Identity Sidecar) identity event stream
    - Subscribe to Pillar 4 (Pipeline Wrappers) pipeline event stream
    - Subscribe to Pillar 5 (Forensic Triage) alert stream
    - Verify passive observation without blocking pillar operations
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.7_
    - _Verification: `pytest tests/integration/test_pillar_integration.py -v`_

  - [ ] 21.3 Implement configuration management
    - Create configuration schema for thresholds and parameters
    - Support environment variable overrides
    - Validate configuration on startup; raise ValueError when DSN provided with `in_memory=False` and connection fails (architecture rule 3)
    - _Verification: `pytest tests/unit/test_configuration.py -v`_

  - [ ] 21.4 Write end-to-end integration tests
    - Test complete event flow from pillar ingestion to alert generation
    - Verify all detection engines activate on appropriate patterns
    - Test multi-pillar event correlation
    - **Property 64: Passive Observation Invariant**
    - **Validates: Requirement 12.7**
    - _Verification: `pytest tests/integration/test_end_to_end.py -v`_

  - [ ] 21.5 Write BDD feature tests for Integration and System Wiring
    - Create `tests/features/system_integration.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_system_integration_bdd.py` using `run_async`
    - Scenario: an event from each of the 5 pillars flows through the full pipeline to an alert
    - Scenario: the orchestrator processes events from all pillars without blocking any pillar operation
    - Scenario: a multi-pillar attack event (kernel + identity + pipeline) is correlated into a single attack path
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_
    - _Verification: `pytest tests/step_defs/test_system_integration_bdd.py -v`_

- [ ] 22. Implement Weave Evaluation Tracking Integration
  - [ ] 22.1 Create Weave configuration and initialization infrastructure
    - Add `weave>=0.50.0` and `wandb>=0.16.0` as optional dependencies under the `[weave]` extras group in `pyproject.toml` (install with `pip install -e ".[weave]"`); omit for non-Weave environments — satisfies Req 21.1 and 21.3
    - Register `@pytest.mark.weave` under `[tool.pytest.ini_options].markers` in `pyproject.toml` with a human-readable description to prevent `PytestUnknownMarkWarning` (testing rule 9) — satisfies Req 21.2 and 21.4
    - Implement `WeaveConfig` dataclass with `project_name`, `entity`, `offline_mode`, `parallelism`, `tags`
    - Create `should_enable_weave()` with explicit priority order:
      1. `WEAVE_DISABLED=true` → return False (always highest priority)
      2. `WEAVE_OFFLINE=true` → return True (local trace storage, no credentials required)
      3. `WANDB_API_KEY` set → return True (cloud sync with API key)
      4. netrc / config-file credentials found → return True
      5. None of the above → return False
    - Implement graceful fallback (log warning, continue) when Weave credentials unavailable
    - Create `weave_config.yaml` parser for `.kiro/evals/` directory
    - _Requirements: 16.1, 16.2, 16.13, 16.14, 18.1, 18.2, 18.3, 18.4, 18.6, 18.8, 21.1, 21.2, 21.3, 21.4_
    - _Verification: `pytest tests/unit/test_weave_config.py -v --strict-markers`_

  - [ ] 22.2 Implement WeaveEvaluationHarness class
    - Create initialization with WeaveConfig, handling offline mode and parallelism
    - Implement `run_evaluation()` with `@weave.op()` decorator creating Weave runs with scenario name, timestamp, and tags
    - Implement `track_detection_metrics(detection_type, true_positives, false_positives, false_negatives, true_negatives, detection_latency_ms)` — all four confusion-matrix counts required so FPR = FP / (FP + TN) can be computed alongside precision, recall, and F1
    - _Requirements: 16.3, 16.8, 17.1, 17.2, 17.3, 17.4, 17.5, 19.5_
    - _Verification: `pytest tests/unit/test_weave_harness.py -v`_

  - [ ] 22.3 Implement Weave traced wrappers and WeaveTraceSerializer
    - Implement `WeaveTraceSerializer` in `src/blackwall/enterprise/advanced_threat_detection/weave_serializer.py`:
      - `serialize_event()` exports only `_SAFE_EVENT_FIELDS` (`event_id`, `timestamp`, `source`, `risk_score`); drops `action`, `target`, and `metadata` entirely (Req 16.17)
      - `serialize_path()` exports `_SAFE_PATH_FIELDS` and replaces node list with a `node_count` scalar
      - `serialize_swarm()` exports `_SAFE_SWARM_FIELDS`
      - `mask_metadata()` recursively replaces values whose keys match `_SENSITIVE_KEY_PATTERNS` with `"**REDACTED**"` (Req 16.18); descends into nested dicts, lists, and tuples (preserving list vs tuple type)
      - `_enforce_size()` truncates payloads exceeding `_MAX_PAYLOAD_BYTES` (4096 bytes) and returns `{"_truncated": True, "_original_bytes": N}` (Req 16.19)
      - Sanitization is transport-independent: offline and cloud modes use the same serializer (Req 16.20)
    - Create `WeaveTracedPathCorrelator`, `WeaveTracedSwarmDetector`, `WeaveTracedAILMTracker`, `WeaveTracedExploitChainAnalyzer`, `WeaveTracedC2Detector` — each passes inputs/outputs through `WeaveTraceSerializer` before logging; raw event payloads must never reach Weave
    - Write unit tests asserting:
      - `event.action`, `event.target`, and `event.metadata` absent from `serialize_event()` output
      - Top-level sensitive keys (`secret`, `token`, `password`, `key`, etc.) replaced with `"**REDACTED**"`
      - Nested dict sensitive keys replaced (e.g. `{"outer": {"api_token": "x"}}`)
      - Sensitive keys inside dicts nested within lists masked
      - Sensitive keys inside dicts nested within tuples masked; tuple type preserved
      - Non-sensitive values inside lists/tuples pass through unchanged
      - Payloads exceeding `_MAX_PAYLOAD_BYTES` return `{"_truncated": True, "_original_bytes": N}`
    - Write integration test asserting no raw `NormalizedEvent` payload appears in any Weave trace during an evaluation run
    - _Requirements: 16.4, 16.5, 16.9, 16.10, 16.11, 16.17, 16.18, 16.19, 16.20_
    - _Verification: `pytest tests/unit/test_weave_traced_detectors.py tests/unit/test_weave_serializer.py tests/integration/test_weave_trace_sanitization.py -v`_

  - [ ] 22.4 Implement WeaveMetricsCollector for aggregated metrics
    - Create `ThreatDetectionMetrics` dataclass with precision, recall, F1, FPR, latency, TP, FP, TN, FN, timestamp, detection_type
    - Implement `compute_detection_metrics()` computing precision, recall, F1, FPR
    - Implement `compute_path_correlation_metrics()` with path_correlation_accuracy and latency
    - Implement `compute_swarm_detection_metrics()` with swarm_detection_accuracy
    - Implement `compute_ailm_detection_metrics()` with ailm_detection_accuracy and boundary_crossing_accuracy
    - Implement `compute_exploit_chain_metrics()` with exploit_chain_accuracy and novelty_score_accuracy
    - Implement `export_metrics_to_weave()` including timestamp, detection_type, and all computed metrics
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8, 17.9, 17.10_
    - _Verification: `pytest tests/unit/test_weave_metrics_collector.py -v`_

  - [ ] 22.5 Implement Weave Dataset creation from YAML evaluation scenarios
    - Create `create_evaluation_dataset()` loading YAML files from the configured scenarios directory
    - Parse all four required fields: `name`, `description`, `events`, `expected_detections`; each Dataset row must contain all four
    - Skip and log a warning for any scenario with missing, non-string, or whitespace-only `description`; other valid scenarios must still load
    - Skip and log for scenarios missing `name`, `events`, or `expected_detections`
    - Write unit tests asserting: valid scenario produces a full row; missing description skips that row; whitespace-only description skips that row; remaining scenarios still load
    - Support attack_path, swarm, AILM, exploit_chain, C2, K8s, registry threat expectations
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.5, 19.7, 19.8, 19.9_
    - _Verification: `pytest tests/unit/test_weave_datasets.py -v`_

  - [ ] 22.6 Implement environment variable and configuration management
    - Support `WANDB_API_KEY`, `WEAVE_PROJECT_NAME`, `WEAVE_ENTITY`, `WEAVE_OFFLINE`, `WEAVE_PARALLELISM`, `WEAVE_DISABLED`
    - `WEAVE_DISABLED=true` takes highest priority; `WEAVE_OFFLINE=true` enables local tracing without cloud credentials
    - Implement config file loading from `.kiro/evals/weave_config.yaml` with per-engine trace_enabled and metrics_enabled flags
    - Use default values and log a warning on config load failure
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 18.8, 18.9, 18.10_
    - _Verification: `pytest tests/unit/test_weave_environment.py -v`_

  - [ ] 22.7 Implement Weave integration with AttackGraphStore
    - Create `WeaveTracedAttackGraphStore` wrapping `AttackGraphStore`
    - Trace `insert_event()` with serialized event metadata (via WeaveTraceSerializer)
    - Trace `query_paths()` logging `query_latency_ms` and `paths_found` count
    - _Requirements: 16.4, 16.5_
    - _Verification: `pytest tests/unit/test_weave_attack_graph.py -v`_

  - [ ] 22.8 Implement backward compatibility helpers
    - Create `weave_op_if_enabled()` decorator applying `@weave.op()` only when `should_enable_weave()` returns True; no-op otherwise (zero overhead)
    - Verify `WEAVE_OFFLINE=true` enables local tracing without `WANDB_API_KEY`
    - Verify `WEAVE_DISABLED=true` takes precedence even when `WEAVE_OFFLINE=true` is also set
    - Verify existing unit, integration, and property tests pass regardless of Weave config
    - _Requirements: 16.13, 16.15, 16.16, 18.4, 18.6, 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8, 20.9, 20.10_
    - _Verification: `pytest tests/integration/test_weave_backward_compat.py -v`_

  - [ ] 22.9 Create Weave evaluation test suite, detector factory, and conftest hooks
    - Implement `build_detector_suite()` factory in `src/blackwall/enterprise/advanced_threat_detection/weave_factory.py`:
      - Accept bare component instances + `force_traced: bool = False` flag
      - Gate traced-wrapper construction on `should_enable_weave() and force_traced`; no internal marker detection
      - Return a `DetectorSuite` dataclass; this is the **only** code path allowed to instantiate `WeaveTraced*` classes
    - Add `pytest_collection_modifyitems` hook to `tests/conftest.py`:
      - Implement `_weave_available()` checking `WEAVE_DISABLED`, `WEAVE_OFFLINE`, `WANDB_API_KEY`, and importability of `weave` package
      - When `_weave_available()` returns False, add `pytest.mark.skip` with descriptive reason to all items carrying `@pytest.mark.weave`
    - Add `detector_suite` fixture to `tests/conftest.py`:
      - `marked = request.node.get_closest_marker("weave") is not None` (pytest public API)
      - Calls `build_detector_suite(..., force_traced=marked)`
      - Yields bare components for unmarked tests; yields traced wrappers for `@pytest.mark.weave` tests when `should_enable_weave()` is True
    - Create `tests/evals/test_atd_weave_evaluations.py` consuming `detector_suite` fixture
    - Implement evaluation tests for multi-stage attack detection, swarm detection, AILM, and exploit chain novelty scoring
    - Verify precision >= 0.95, recall >= 0.90, FPR <= 0.05
    - _Requirements: 16.3, 16.6, 16.7, 16.16, 17.6, 17.7, 17.8, 20.2, 20.8, 20.10, 20.11_
    - _Verification: `pytest tests/evals/test_atd_weave_evaluations.py -v -m weave`_

  - [ ] 22.10 Write property tests for Weave integration
    - **Property 82: Weave Initialization Fallback**
    - **Property 83: Weave Offline Mode Compliance**
    - **Property 84: Weave Metric Precision Calculation**
    - **Property 85: Weave Metric Recall Calculation**
    - **Property 86: Weave Metric F1 Score Calculation**
    - **Property 87: Weave Metric FPR Calculation**
    - **Property 88: Weave Trace Parameter Logging**
    - **Validates: Requirements 16.2, 16.4, 16.5, 16.13, 17.2, 17.3, 17.4, 17.5**
    - _Verification: `pytest tests/property/test_weave_properties.py --hypothesis-seed=0 -v`_

  - [ ] 22.11 Write BDD feature tests for Weave Evaluation Tracking
    - Create `tests/features/weave_evaluation.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_weave_evaluation_bdd.py` using `run_async`
    - Scenario: Weave initializes successfully when WANDB_API_KEY is set
    - Scenario: `WEAVE_DISABLED=true` skips all Weave initialization and tracing with zero overhead
    - Scenario: `WEAVE_OFFLINE=true` enables local tracing without WANDB_API_KEY
    - Scenario: evaluation run is tracked with scenario name, timestamp, and tags
    - Scenario: track_detection_metrics computes correct precision, recall, F1, and FPR from TP/FP/FN/TN
    - Scenario: `WeaveTraceSerializer` strips `action`, `target`, and `metadata` from all event exports
    - Scenario: test without `@pytest.mark.weave` executes without any Weave overhead
    - Scenario: YAML scenario with empty description is skipped and remaining scenarios load normally
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 16.13, 16.14, 16.15, 16.17, 16.18, 16.19, 16.20, 17.1, 17.2, 17.3, 17.4, 17.5, 18.1, 18.4, 18.6, 19.1, 19.3, 19.4, 20.1, 20.11, 21.1, 21.2, 21.3, 21.4_
    - _Verification: `pytest tests/step_defs/test_weave_evaluation_bdd.py -v`_

- [ ] 23. Red Team Evaluation Scenarios with Weave Tracking
  - [ ] 23.1 Create red team scenario: Agent swarm attack with Weave metrics
    - Simulate coordinated multi-agent attack with shared infrastructure
    - Verify swarm detection triggers CRITICAL alert
    - Track temporal_correlation and coordination_score in Weave; measure detection latency
    - _Requirements: 4.2, 4.3, 10.1, 16.3, 16.10, 17.7_
    - _Verification: `pytest tests/evaluation/test_swarm_scenario.py -v -m weave`_

  - [ ] 23.2 Create red team scenario: Multi-stage exploit chain with Weave metrics
    - Simulate RCE → Privilege Escalation → Credential Theft chain
    - Verify exploit chain detection with appropriate novelty score; test both known and novel chains
    - Track novelty_score and chaining_confidence in Weave
    - _Requirements: 5.2, 5.4, 5.5, 10.3, 16.3, 17.9_
    - _Verification: `pytest tests/evaluation/test_exploit_chain_scenario.py -v -m weave`_

  - [ ] 23.3 Create red team scenario: C2 infrastructure establishment with Weave metrics
    - Simulate agent establishing RequestBin/Pastebin C2 with beaconing
    - Verify C2 detection triggers CRITICAL alert; test persistence indicator detection
    - Track beaconing pattern detection metrics in Weave
    - _Requirements: 7.2, 7.3, 7.5, 10.5, 16.3_
    - _Verification: `pytest tests/evaluation/test_c2_scenario.py -v -m weave`_

  - [ ] 23.4 Create red team scenario: Kubernetes pod token theft with Weave metrics
    - Simulate service account token theft followed by rapid pod creation
    - Verify Kubernetes defense layer detects both threats
    - Track K8s threat detection latency in Weave
    - _Requirements: 8.1, 8.2, 10.6, 16.3_
    - _Verification: `pytest tests/evaluation/test_k8s_scenario.py -v -m weave`_

  - [ ] 23.5 Create red team scenario: AILM across trust boundaries with Weave metrics
    - Simulate permission accumulation spanning multiple boundaries
    - Verify AILM tracker detects composition and computes correct risk level
    - Track boundary_crossing_accuracy in Weave
    - _Requirements: 6.2, 6.3, 6.5, 10.2, 16.3, 16.11, 17.8_
    - _Verification: `pytest tests/evaluation/test_ailm_scenario.py -v -m weave`_

  - [ ] 23.6 Create end-to-end Weave evaluation comparing detection algorithms
    - Run multiple evaluation scenarios with different threshold configurations
    - Compare precision, recall, F1, FPR across configurations in Weave UI
    - Generate Weave comparison reports for algorithm tuning
    - _Requirements: 16.8, 17.10_
    - _Verification: `pytest tests/evaluation/test_weave_algorithm_comparison.py -v -m weave`_

  - [ ] 23.7 Write BDD feature tests for Red Team Evaluation Scenarios
    - Create `tests/features/red_team_scenarios.feature` with Gherkin scenarios
    - Implement `Given/When/Then` steps in `tests/step_defs/test_red_team_scenarios_bdd.py` using `run_async`
    - Scenario: coordinated multi-agent attack with shared IPs triggers CRITICAL swarm alert tracked in Weave
    - Scenario: RCE → Privilege Escalation → Credential Theft chain is detected with novelty_score logged to Weave
    - Scenario: agent establishing C2 beaconing to Pastebin triggers CRITICAL alert; metrics tracked in Weave
    - Scenario: K8s service account token theft followed by fleet spawning both detected; latency logged to Weave
    - Scenario: AILM spanning 3 trust boundaries triggers CRITICAL alert; boundary_crossing_accuracy logged
    - Verify all scenarios meet accuracy thresholds (precision >= 0.95, recall >= 0.90, FPR <= 0.05)
    - _Requirements: 4.2, 4.3, 5.2, 5.4, 5.5, 6.2, 6.3, 6.5, 7.2, 7.3, 7.5, 8.1, 8.2, 10.1, 10.2, 10.3, 10.5, 10.6, 16.3, 17.7, 17.8, 17.9_
    - _Verification: `pytest tests/step_defs/test_red_team_scenarios_bdd.py -v -m weave`_

- [ ] 24. Implement Active Threat Reaction Engine (Feedback Loop to Pillars 1, 2, 3)
  - [ ] 24.1 Create `ActiveReactionEngine` class
    - Convert CRITICAL threat evidence into dynamic mitigation actions
    - Implement `ActiveReactionPayload` model logging with Pydantic v2 validation and `evaluation_env_id` tracking
    - Implement evaluation containment check that mandatorily queries `is_evaluation_mode(payload.trigger_evidence_id)` and suppresses production mitigation actions whenever the underlying evidence originated in evaluation mode, regardless of whether `evaluation_env_id` is populated
    - _Requirements: 22.4, 22.5, 14.5, 15.10_
    - _Verification: `pytest tests/unit/test_active_reaction_engine.py::test_payload_creation -v`_

  - [ ] 24.2 Implement dynamic eBPF socket drop rule injection
    - Inject eBPF PID/socket drop rules into Pillar 1 (`LinuxeBPFDriver`) within 50ms (production mode only)
    - _Requirements: 22.1, 22.5_
    - _Verification: `pytest tests/unit/test_active_reaction_engine.py::test_ebpf_socket_drop -v`_

  - [ ] 24.3 Implement fleet-wide ZeroMQ threat signature broadcast
    - Publish zero-latency block signatures to Pillar 2 Threat Mesh (<15ms) (production mode only)
    - _Requirements: 22.2, 22.5_
    - _Verification: `pytest tests/unit/test_active_reaction_engine.py::test_mesh_broadcast -v`_

  - [ ] 24.4 Implement Vault JIT credential invalidation
    - Trigger Pillar 3 Vault Sidecar session revocation for compromised agents (production mode only)
    - _Requirements: 22.3, 22.5_
    - _Verification: `pytest tests/unit/test_active_reaction_engine.py::test_credential_invalidation -v`_

  - [ ] 24.5 Write property tests for Active Threat Reaction Engine
    - **Property 82: Dynamic eBPF Socket Drop Injection**
    - **Property 83: Zero-Latency Threat Mesh Broadcast**
    - **Property 84: Identity Credential Invalidation**
    - **Property 85: Reaction Execution Logging**
    - **Property 97: Evaluation Mode Reaction Suppression**
    - **Validates: Requirements 22.1, 22.2, 22.3, 22.4, 22.5, 14.5**
    - _Verification: `pytest tests/property/test_active_reaction_properties.py --hypothesis-seed=0 -v`_

  - [ ] 24.6 Write BDD feature tests for Active Threat Reaction Engine
    - Create `tests/features/active_threat_reaction.feature` with Gherkin scenarios
    - Scenario: CRITICAL swarm detection injects eBPF socket drop rule into Pillar 1 within 50ms
    - Scenario: CRITICAL exploit chain broadcasts ZeroMQ signature across Threat Mesh in <15ms
    - Scenario: AILM breach revokes JIT tokens via Pillar 3 Vault sidecar
    - Scenario: CRITICAL evidence originating from an evaluation environment suppresses production eBPF drop, Threat Mesh broadcast, and Vault credential revocation
    - _Requirements: 22.1, 22.2, 22.3, 22.4, 22.5, 14.5_
    - _Verification: `pytest tests/step_defs/test_active_threat_reaction_bdd.py -v`_

- [ ] 25. Implement Inbound Protocol Interception and Cross-Agent Inspection
  - [ ] 25.1 Create `InboundProtocolFilter` class
    - Implement ingress RPC message parsing and `InboundProtocolMessage` validation
    - _Requirements: 23.4, 15.11_
    - _Verification: `pytest tests/unit/test_inbound_protocol_filter.py::test_message_parsing -v`_

  - [ ] 25.2 Implement Origin/Host header validation
    - Enforce origin checks for HTTP/SSE MCP and A2A endpoints; reject unauthenticated remote connections
    - _Requirements: 23.1_
    - _Verification: `pytest tests/unit/test_inbound_protocol_filter.py::test_header_validation -v`_

  - [ ] 25.3 Implement sliding-window inbound rate-limiting
    - Limit incoming cross-agent request volume per sender identity
    - _Requirements: 23.2_
    - _Verification: `pytest tests/unit/test_inbound_protocol_filter.py::test_rate_limiting -v`_

  - [ ] 25.4 Implement JSON-RPC payload sanitization
    - Extract and sanitize `tools/call` parameters before host agent execution
    - _Requirements: 23.3_
    - _Verification: `pytest tests/unit/test_inbound_protocol_filter.py::test_rpc_sanitization -v`_

  - [ ] 25.5 Write property tests for Inbound Protocol Filter
    - **Property 86: Inbound Header and Origin Enforcement**
    - **Property 87: Inbound Rate Limit Boundary**
    - **Property 88: Inbound JSON-RPC Sanitization**
    - **Property 89: Malformed Protocol Rejection**
    - **Validates: Requirements 23.1, 23.2, 23.3, 23.4**
    - _Verification: `pytest tests/property/test_inbound_filter_properties.py --hypothesis-seed=0 -v`_

  - [ ] 25.6 Write BDD feature tests for Inbound Protocol Filter
    - Create `tests/features/inbound_protocol_filter.feature` with Gherkin scenarios
    - Scenario: incoming RPC request with invalid Origin header is rejected
    - Scenario: request surge exceeding sliding-window limit drops additional messages
    - Scenario: valid incoming tools/call arguments are sanitized before execution
    - _Requirements: 23.1, 23.2, 23.3, 23.4_
    - _Verification: `pytest tests/step_defs/test_inbound_protocol_filter_bdd.py -v`_

- [ ] 26. Implement Indirect Prompt Injection and Data Poisoning Defense
  - [ ] 26.1 Create `PromptInjectionScanner` class
    - Implement pattern matcher for structural jailbreaks and `PromptInjectionEvidence` validation
    - _Requirements: 24.1, 15.12_
    - _Verification: `pytest tests/unit/test_prompt_injection_scanner.py::test_pattern_matching -v`_

  - [ ] 26.2 Implement payload scanning across external data sources
    - Scan git diffs, web scrapes, and incoming messages before context ingestion
    - _Requirements: 24.1_
    - _Verification: `pytest tests/unit/test_prompt_injection_scanner.py::test_payload_scanning -v`_

  - [ ] 26.3 Implement injection vector redaction
    - Redact and quash injection vectors before passing data to host agent context
    - _Requirements: 24.2_
    - _Verification: `pytest tests/unit/test_prompt_injection_scanner.py::test_vector_redaction -v`_

  - [ ] 26.4 Write property tests for Prompt Injection Scanner
    - **Property 90: Prompt Injection Pattern Detection**
    - **Property 91: Injection Vector Redaction**
    - **Property 92: Injection Alert Generation**
    - **Validates: Requirements 24.1, 24.2, 24.3**
    - _Verification: `pytest tests/property/test_prompt_injection_properties.py --hypothesis-seed=0 -v`_

  - [ ] 26.5 Write BDD feature tests for Prompt Injection Scanner
    - Create `tests/features/prompt_injection_scanner.feature` with Gherkin scenarios
    - Scenario: git diff containing hidden system prompt override is detected and flagged
    - Scenario: injection vectors are redacted before content enters agent context
    - Scenario: detected prompt injection attempt emits a HIGH severity alert to Alert Bus
    - _Requirements: 24.1, 24.2, 24.3_
    - _Verification: `pytest tests/step_defs/test_prompt_injection_scanner_bdd.py -v`_

- [ ] 27. Implement Agent Fleet Resource and Token Velocity Enforcement (Denial of Wallet Defense)
  - [ ] 27.1 Create `AgentQuotaEnforcer` class
    - Track real-time token consumption and rolling burn rate per second with `AgentQuotaUsage` validation
    - _Requirements: 25.1, 15.13_
    - _Verification: `pytest tests/unit/test_agent_quota_enforcer.py::test_token_tracking -v`_

  - [ ] 27.2 Implement velocity limit enforcement and quarantine
    - Trigger automated throttling or temporary quarantine when velocity caps exceeded
    - _Requirements: 25.2_
    - _Verification: `pytest tests/unit/test_agent_quota_enforcer.py::test_velocity_enforcement -v`_

  - [ ] 27.3 Implement Denial of Wallet alert generation
    - Publish Denial of Wallet alerts when token burn spikes occur
    - _Requirements: 25.3_
    - _Verification: `pytest tests/unit/test_agent_quota_enforcer.py::test_dow_alerts -v`_

  - [ ] 27.4 Write property tests for Agent Quota Enforcer
    - **Property 93: Token Consumption Rate Tracking**
    - **Property 94: Velocity Limit Quarantine Trigger**
    - **Property 95: Quota Violation Alert Mapping**
    - **Validates: Requirements 25.1, 25.2, 25.3**
    - _Verification: `pytest tests/property/test_quota_enforcer_properties.py --hypothesis-seed=0 -v`_

  - [ ] 27.5 Write BDD feature tests for Agent Quota Enforcer
    - Create `tests/features/agent_quota_enforcer.feature` with Gherkin scenarios
    - Scenario: token burn rate exceeding 500 tokens/sec triggers agent quarantine
    - Scenario: API call velocity surge emits Denial of Wallet alert to Alert Bus
    - _Requirements: 25.1, 25.2, 25.3_
    - _Verification: `pytest tests/step_defs/test_agent_quota_enforcer_bdd.py -v`_

- [ ] 28. System-wide integration and end-to-end verification
  - [ ] 28.1 Wire new defensive components into orchestrator
    - Connect ActiveReactionEngine, InboundProtocolFilter, PromptInjectionScanner, AgentQuotaEnforcer
    - _Requirements: 22.1-22.4, 23.1-23.4, 24.1-24.3, 25.1-25.3_
    - _Verification: `pytest tests/integration/test_orchestrator_breach_defenses.py -v`_

  - [ ] 28.2 Write BDD feature tests for System-Wide Breach Defense Integration
    - Create `tests/features/system_breach_defense.feature` with Gherkin scenarios
    - Scenario: CRITICAL swarm detection triggers eBPF drop, ZeroMQ mesh broadcast, and Vault token revocation
    - Scenario: incoming unauthorized A2A request is rate-limited and sanitized
    - Scenario: git diff with prompt injection is neutralized before execution
    - _Requirements: 22.1-22.4, 23.1-23.4, 24.1-24.3, 25.1-25.3_
    - _Verification: `pytest tests/step_defs/test_system_breach_defense_bdd.py -v`_

- [ ] 29. Checkpoint - Verify breach defense integrations
  - Ensure all breach defense tests pass, ask the user if questions arise.

- [ ] 30. Final checkpoint - Complete system verification
  - Ensure all tests pass, ask the user if questions arise.

## Task Dependency Graph

```json
{
  "waves": [
    { "id": 0, "tasks": ["1.1", "1.2"] },
    { "id": 1, "tasks": ["1.3", "2.1"] },
    { "id": 2, "tasks": ["1.4", "2.2", "2.3", "4.1"] },
    { "id": 3, "tasks": ["2.4", "4.2", "4.3"] },
    { "id": 4, "tasks": ["2.5", "4.4", "5.1"] },
    { "id": 5, "tasks": ["2.6", "5.2", "5.3", "7.1"] },
    { "id": 6, "tasks": ["4.5", "5.4", "7.2", "7.3", "8.1"] },
    { "id": 7, "tasks": ["5.5", "7.4", "8.2", "10.1"] },
    { "id": 8, "tasks": ["5.6", "7.5", "8.3", "10.2", "11.1"] },
    { "id": 9, "tasks": ["8.4", "10.3", "11.2", "12.1"] },
    { "id": 10, "tasks": ["7.6", "8.5", "10.4", "11.3", "12.2", "13.1"] },
    { "id": 11, "tasks": ["10.5", "11.4", "12.3", "13.2"] },
    { "id": 12, "tasks": ["8.6", "11.5", "12.4", "13.3"] },
    { "id": 13, "tasks": ["10.6", "12.5", "13.4", "15.1"] },
    { "id": 14, "tasks": ["11.6", "15.2", "15.3", "15.4", "16.1"] },
    { "id": 15, "tasks": ["12.6", "13.5", "15.5", "16.2", "16.3", "17.1"] },
    { "id": 16, "tasks": ["15.6", "16.4", "17.2", "18.1"] },
    { "id": 17, "tasks": ["16.5", "17.3", "18.2", "20.1"] },
    { "id": 18, "tasks": ["17.4", "18.3", "20.2"] },
    { "id": 19, "tasks": ["17.5", "17.6", "18.4", "20.3", "21.1"] },
    { "id": 20, "tasks": ["18.5", "20.4", "21.2"] },
    { "id": 21, "tasks": ["20.5", "21.3"] },
    { "id": 22, "tasks": ["21.4", "21.5", "22.1"] },
    { "id": 23, "tasks": ["22.2", "22.5", "22.6"] },
    { "id": 24, "tasks": ["22.3", "22.4", "22.7"] },
    { "id": 25, "tasks": ["22.8", "22.9"] },
    { "id": 26, "tasks": ["22.10", "22.11"] },
    { "id": 27, "tasks": ["23.1", "23.2", "23.3"] },
    { "id": 28, "tasks": ["23.4", "23.5"] },
    { "id": 29, "tasks": ["23.6"] },
    { "id": 30, "tasks": ["23.7"] },
    { "id": 31, "tasks": ["24.1", "25.1", "26.1", "27.1"] },
    { "id": 32, "tasks": ["24.2", "24.3", "24.4", "25.2", "25.3", "25.4", "26.2", "26.3", "27.2", "27.3"] },
    { "id": 33, "tasks": ["24.5", "24.6", "25.5", "25.6", "26.4", "26.5", "27.4", "27.5"] },
    { "id": 34, "tasks": ["28.1", "28.2"] }
  ]
}
```
