# Implementation Plan: Blackwall Advanced Threat Detection

## Overview

This implementation plan creates the sixth pillar of Blackwall Enterprise Mesh: **Advanced Threat Detection**. The system performs temporal graph analysis, agent swarm detection, zero-day exploit chain recognition, and AI-Induced Lateral Movement (AILM) tracking across events from all five existing pillars.

The implementation follows a test-driven development approach with property-based testing for universal correctness properties and integration tests for cross-component behavior. Each task builds incrementally, validating functionality early through automated tests.

## Tasks

- [x] 1. Set up core project structure and data models
  - [x] 1.1 Create directory structure under `src/blackwall/enterprise/advanced_threat_detection/`
    - Create `__init__.py`, `models.py`, `enums.py`
    - Set up module exports and basic logging configuration
    - _Requirements: 15.1, 15.2, 15.3, 15.4_
    - _Verification: `python -c "from blackwall.enterprise.advanced_threat_detection import models"`_
  
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
    - _Verification: `pytest tests/property/test_models_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 1.4 Write BDD feature tests for core data models
    - Create tests/features/data_models.feature with Gherkin scenarios
    - Implement Given/When/Then steps for NormalizedEvent creation with valid UUID and timezone
    - Implement scenarios for score validation bounds [0.0, 1.0]
    - Implement scenarios for AttackPath minimum node validation (>= 2 nodes)
    - Implement scenarios for SwarmEvidence minimum agent validation (>= 2 agents)
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
    - _Requirements: 2.1, 2.5_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_insert_event -v`_
  
  - [x] 2.3 Implement causal edge creation
    - Create `link_events()` method with relationship type parameter
    - Update edge lists for both source and target nodes
    - _Requirements: 2.2_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_link_events -v`_
  
  - [x] 2.4 Implement multi-hop path query engine
    - Create `query_paths()` method with time window and minimum path length filters
    - Optimize queries for 17K+ event graphs (response time < 500ms)
    - Return AttackPath objects ordered by risk_score descending
    - _Requirements: 2.3, 2.4, 11.2_
    - _Verification: `pytest tests/integration/test_attack_graph_store.py::test_query_paths_performance -v`_
  
  - [x] 2.5 Write property tests for Attack Graph Store
    - **Property 6: Temporal Ordering Preservation**
    - **Property 7: Causal Edge Creation**
    - **Property 8: Path Query Minimum Length Enforcement**
    - **Property 9: Node Edge List Integrity**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.5**
    - _Verification: `pytest tests/property/test_attack_graph_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 2.6 Write BDD feature tests for Attack Graph Store
    - Create tests/features/attack_graph_store.feature with Gherkin scenarios
    - Implement Given/When/Then steps for event insertion with temporal ordering
    - Implement scenarios for causal edge creation between related events
    - Implement scenarios for multi-hop path queries with time windows
    - Implement scenarios for path query performance (< 500ms for 17K+ events)
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 11.2_
    - _Verification: `pytest tests/step_defs/test_attack_graph_store_bdd.py -v`_

- [x] 3. Checkpoint - Verify core infrastructure
  - Ensure all tests pass, ask the user if questions arise.


- [x] 4. Implement Event Stream Collector
  - [x] 4.1 Create EventStreamCollector class with pillar subscriptions
    - Implement async iterator interfaces for all five pillar event streams
    - Create event source enum mapping (KERNEL_SYSCALL, TOOL_CALL, IDENTITY_ACCESS, PIPELINE_EXECUTION, FORENSIC_ALERT)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_pillar_subscriptions -v`_
  
  - [x] 4.2 Implement event normalization logic
    - Create normalization functions for each pillar event type
    - Enrich events with temporal context and agent metadata
    - Generate UUID v4 event_id and UTC timestamp for each event
    - Compute initial risk_score based on event characteristics
    - _Requirements: 1.6, 1.7, 1.8, 1.9_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_normalization -v`_
  
  - [x] 4.3 Implement error handling for pillar connection failures
    - Add exponential backoff reconnection logic
    - Log malformed events without blocking stream
    - Validate schema for all incoming events
    - _Requirements: Error Handling - Event Collection Errors_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_error_handling -v`_
  
  - [x] 4.4 Write property tests for event normalization
    - **Property 1: Event Normalization Source Mapping**
    - **Property 2: Event Enrichment Completeness**
    - **Property 76: Agent ID Non-Empty Validation**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 15.4**
    - _Verification: `pytest tests/property/test_event_collector_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 4.5 Write BDD feature tests for Event Stream Collector
    - Create tests/features/event_stream_collector.feature with Gherkin scenarios
    - Implement Given/When/Then steps for pillar event subscription and normalization
    - Implement scenarios for event source mapping (KERNEL_SYSCALL, TOOL_CALL, IDENTITY_ACCESS, etc.)
    - Implement scenarios for event enrichment with temporal context and agent metadata
    - Implement scenarios for error handling with exponential backoff reconnection
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 1.7, 1.8, 1.9, 12.1, 12.2, 12.3, 12.4, 12.5_
    - _Verification: `pytest tests/step_defs/test_event_stream_collector_bdd.py -v`_



- [x] 5. Implement Multi-Stage Attack Path Correlation
  - [x] 5.1 Create PathCorrelator class with DFS path finding
    - Implement `correlate_attack_paths()` with time window filtering
    - Build temporal adjacency graph with 5-minute window edges
    - Compute edge weights based on temporal proximity and semantic relationships
    - _Requirements: 3.1, 3.2, 3.3_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_temporal_adjacency -v`_
  
  - [x] 5.2 Implement depth-first search for path enumeration
    - Create recursive DFS with minimum path length constraint
    - Identify all valid paths meeting length requirements
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
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
    - _Verification: `pytest tests/property/test_path_correlator_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 5.6 Write BDD feature tests for Multi-Stage Attack Path Correlation
    - Create tests/features/path_correlation.feature with Gherkin scenarios
    - Implement Given/When/Then steps for temporal adjacency graph construction (5-minute windows)
    - Implement scenarios for depth-first search path finding with minimum length constraints
    - Implement scenarios for MITRE ATT&CK technique mapping to attack stages
    - Implement scenarios for risk score computation and path ranking
    - _Requirements: 2.8, 2.9, 2.10, 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7_
    - _Verification: `pytest tests/step_defs/test_path_correlation_bdd.py -v`_

- [x] 6. Checkpoint - Verify attack path correlation
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 7. Implement Agent Swarm Detector
  - [ ] 7.1 Create AgentSwarmDetector class with behavioral fingerprinting
    - Implement `fingerprint_agent()` using action sequence hashing
    - Generate consistent fingerprints over configurable time windows (default 3600s)
    - _Requirements: 4.1_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_fingerprinting -v`_
  
  - [ ] 7.2 Implement temporal correlation analysis
    - Create `detect_swarms()` with correlation threshold (default 0.75)
    - Compute temporal correlation between agent pairs
    - Identify groups with minimum agent count (default 2)
    - _Requirements: 4.2, 4.3_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_temporal_correlation -v`_
  
  - [ ] 7.3 Implement shared infrastructure identification
    - Detect shared IP addresses across agents
    - Detect shared domains and resource patterns
    - Populate shared_patterns field in SwarmEvidence
    - _Requirements: 4.4_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_shared_infrastructure -v`_
  
  - [ ] 7.4 Implement coordination score computation
    - Create `compute_coordination_score()` analyzing temporal alignment
    - Analyze behavioral similarity between agents
    - Validate coordination_score range [0.0, 1.0]
    - _Requirements: 4.5, 15.9_
    - _Verification: `pytest tests/unit/test_agent_swarm_detector.py::test_coordination_score -v`_
  
  - [ ] 7.5 Write property tests for swarm detection
    - **Property 21: Behavioral Fingerprint Generation**
    - **Property 22: Swarm Correlation Threshold Enforcement**
    - **Property 23: Swarm Minimum Size Enforcement**
    - **Property 24: Shared Infrastructure Identification**
    - **Property 25: Coordination Score Computation**
    - **Property 28: High-Confidence Swarm Threshold**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.8**
    - _Verification: `pytest tests/property/test_swarm_detector_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 7.6 Write BDD feature tests for Agent Swarm Detector
    - Create tests/features/agent_swarm_detector.feature with Gherkin scenarios
    - Implement Given/When/Then steps for behavioral fingerprinting using action sequence hashing
    - Implement scenarios for temporal correlation analysis (threshold >= 0.75)
    - Implement scenarios for shared infrastructure detection (IP addresses, domains)
    - Implement scenarios for coordination score computation with temporal alignment
    - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 15.7, 15.8, 15.9_
    - _Verification: `pytest tests/step_defs/test_agent_swarm_detector_bdd.py -v`_


- [ ] 8. Implement Exploit Chain Analyzer
  - [ ] 8.1 Create ExploitChainAnalyzer class with exploit classification
    - Implement `classify_exploit()` mapping events to ExploitCategory enum
    - Support categories: RCE, Privilege Escalation, Credential Theft, Persistence, Lateral Movement
    - Return None for non-exploit events
    - _Requirements: 5.1_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_classify_exploit -v`_
  
  - [ ] 8.2 Implement exploit chain pattern detection
    - Create `detect_chains()` identifying sequences like RCE → Privilege Escalation → Credential Theft
    - Filter chains by time window constraints
    - Generate ExploitChainEvidence with chain_id and exploits list
    - _Requirements: 5.2_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_chain_detection -v`_
  
  - [ ] 8.3 Implement novelty scoring against baseline
    - Create `compute_novelty_score()` comparing chains to historical patterns
    - Novel chains approach 1.0, known patterns approach 0.0
    - Maintain baseline pattern database
    - _Requirements: 5.3, 5.4, 5.5_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_novelty_scoring -v`_
  
  - [ ] 8.4 Implement chaining confidence computation
    - Compute chaining_confidence for ExploitChainEvidence
    - Consider temporal proximity and semantic relationships
    - _Requirements: 5.6_
    - _Verification: `pytest tests/unit/test_exploit_chain_analyzer.py::test_chaining_confidence -v`_
  
  - [ ] 8.5 Write property tests for exploit chain analysis
    - **Property 29: Exploit Event Classification**
    - **Property 30: Exploit Chain Pattern Detection**
    - **Property 31: Novelty Score Baseline Comparison**
    - **Property 32: Novel Chain High Novelty Score**
    - **Property 33: Known Chain Low Novelty Score**
    - **Property 34: Chaining Confidence Computation**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6**
    - _Verification: `pytest tests/property/test_exploit_chain_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 8.6 Write BDD feature tests for Exploit Chain Analyzer
    - Create tests/features/exploit_chain_analyzer.feature with Gherkin scenarios
    - Implement Given/When/Then steps for exploit classification (RCE, Privilege Escalation, Credential Theft, etc.)
    - Implement scenarios for exploit chain pattern detection (e.g., RCE → Privilege Escalation → Credential Theft)
    - Implement scenarios for novelty scoring against baseline patterns
    - Implement scenarios for chaining confidence computation
    - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6_
    - _Verification: `pytest tests/step_defs/test_exploit_chain_analyzer_bdd.py -v`_

- [ ] 9. Checkpoint - Verify detection engines
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 10. Implement AI-Induced Lateral Movement (AILM) Tracker
  - [ ] 10.1 Create AILMTracker class with permission tracking
    - Implement `track_permission_grant()` recording PermissionGrant objects
    - Store grants with permission, grantor, grantee, timestamp, and scope
    - _Requirements: 6.1_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_track_permission -v`_
  
  - [ ] 10.2 Implement permission composition detection
    - Create `detect_permission_composition()` identifying accumulation patterns
    - Detect agents accumulating multiple permissions over time
    - Detect permissions spanning multiple trust boundaries
    - _Requirements: 6.2, 6.3_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_composition_detection -v`_
  
  - [ ] 10.3 Implement security boundary crossing identification
    - Create `identify_boundary_crossing()` determining if context transitions cross boundaries
    - Define trust boundary mappings
    - _Requirements: 6.4_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_boundary_crossing -v`_
  
  - [ ] 10.4 Implement AILM risk level computation
    - Compute risk_level classification (LOW, MEDIUM, HIGH, CRITICAL)
    - Populate composed_permissions and boundary_crossings in AILMEvidence
    - _Requirements: 6.5, 6.6_
    - _Verification: `pytest tests/unit/test_ailm_tracker.py::test_risk_level -v`_
  
  - [ ] 10.5 Write property tests for AILM tracking
    - **Property 35: Permission Grant Recording**
    - **Property 36: Permission Accumulation Detection**
    - **Property 37: Cross-Boundary Permission Detection**
    - **Property 38: Security Boundary Crossing Identification**
    - **Property 39: AILM Risk Level Computation**
    - **Property 40: AILM Evidence Completeness**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6**
    - _Verification: `pytest tests/property/test_ailm_tracker_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 10.6 Write BDD feature tests for AILM Tracker
    - Create tests/features/ailm_tracker.feature with Gherkin scenarios
    - Implement Given/When/Then steps for permission grant recording with grantor/grantee/scope
    - Implement scenarios for permission composition detection across time windows
    - Implement scenarios for security boundary crossing identification
    - Implement scenarios for risk level computation (LOW, MEDIUM, HIGH, CRITICAL)
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
    - _Verification: `pytest tests/property/test_c2_detector_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 11.6 Write BDD feature tests for C2 Infrastructure Detector
    - Create tests/features/c2_infrastructure_detector.feature with Gherkin scenarios
    - Implement Given/When/Then steps for endpoint classification (RequestBin, Pastebin, GitHub Gist, etc.)
    - Implement scenarios for C2 establishment detection
    - Implement scenarios for beaconing pattern analysis with periodic timing
    - Implement scenarios for persistence indicator identification (self-respawning, cron jobs)
    - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6_
    - _Verification: `pytest tests/step_defs/test_c2_infrastructure_detector_bdd.py -v`_


- [ ] 12. Implement Kubernetes Defense Layer
  - [ ] 12.1 Create KubernetesDefenseLayer class with pod token theft detection
    - Implement `detect_pod_token_theft()` identifying unauthorized access to service account tokens
    - Monitor file access to /var/run/secrets/kubernetes.io/serviceaccount/token
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
    - _Verification: `pytest tests/property/test_k8s_defense_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 12.6 Write BDD feature tests for Kubernetes Defense Layer
    - Create tests/features/kubernetes_defense.feature with Gherkin scenarios
    - Implement Given/When/Then steps for pod token theft detection (service account token access)
    - Implement scenarios for fleet spawning detection (rapid pod creation across nodes)
    - Implement scenarios for secrets exfiltration detection (bulk Kubernetes API secret reads)
    - Implement scenarios for self-respawning pod detection (restart loop patterns)
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
    - _Verification: `pytest tests/property/test_registry_monitor_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 13.5 Write BDD feature tests for Package Registry Monitor
    - Create tests/features/package_registry_monitor.feature with Gherkin scenarios
    - Implement Given/When/Then steps for registry access monitoring (Artifactory, npm, PyPI)
    - Implement scenarios for exploit probing detection (malformed requests, unusual patterns)
    - Implement scenarios for CVE correlation with known exploitation signatures
    - Implement scenarios for RegistryThreatEvidence generation with registry type and indicators
    - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6_
    - _Verification: `pytest tests/step_defs/test_package_registry_monitor_bdd.py -v`_

- [ ] 14. Checkpoint - Verify all detection components
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 15. Implement Alert Generation and Real-Time Integration
  - [ ] 15.1 Create AlertBus class for alert publication
    - Implement alert publishing interface with severity levels (LOW, MEDIUM, HIGH, CRITICAL)
    - Add retry logic for alert delivery failures (up to 5 retries)
    - Log persistent failures for manual investigation
    - _Requirements: Error Handling - Alert Bus Errors_
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
    - _Verification: `pytest tests/property/test_alert_generation_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 15.6 Write BDD feature tests for Alert Generation
    - Create tests/features/alert_generation.feature with Gherkin scenarios
    - Implement Given/When/Then steps for AlertBus publication with severity levels
    - Implement scenarios for swarm detection alerts (CRITICAL severity)
    - Implement scenarios for AILM alert severity mapping (HIGH/CRITICAL based on risk_level)
    - Implement scenarios for exploit chain, attack path, C2, K8s, and registry threat alerts
    - Implement scenarios for alert retry logic (up to 5 retries)
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
    - Create tests/features/performance_sla.feature with Gherkin scenarios
    - Implement Given/When/Then steps for event processing latency (< 100ms)
    - Implement scenarios for path query performance (< 500ms for 17K+ events)
    - Implement scenarios for sustained throughput (1,000 events/second for 5+ minutes)
    - Implement scenarios for swarm fingerprint latency (< 2 seconds for 1-hour windows)
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
    - _Verification: `pytest tests/property/test_retrospective_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 17.6 Write BDD feature tests for Retrospective Analysis
    - Create tests/features/retrospective_analysis.feature with Gherkin scenarios
    - Implement Given/When/Then steps for historical time window queries (days/weeks)
    - Implement scenarios for retrospective path detection (missed in real-time)
    - Implement scenarios for multi-agent historical correlation (delayed swarm patterns)
    - Implement scenarios for attack graph export (JSON, GraphML formats)
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
    - **Validates: Requirements 14.1, 14.2, 14.3, 14.4**
    - _Verification: `pytest tests/property/test_evaluation_mode_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 18.5 Write BDD feature tests for Evaluation Environment Support
    - Create tests/features/evaluation_environment.feature with Gherkin scenarios
    - Implement Given/When/Then steps for evaluation environment labeling
    - Implement scenarios for evaluation alert isolation (preventing production workflow triggers)
    - Implement scenarios for isolated attack graph instances per eval environment
    - Implement scenarios for evaluation state reset (clean state restoration)
    - _Requirements: 14.1, 14.2, 14.3, 14.4_
    - _Verification: `pytest tests/step_defs/test_evaluation_environment_bdd.py -v`_

- [ ] 19. Checkpoint - Verify auxiliary features
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 20. Implement Error Handling and Resilience
  - [ ] 20.1 Implement pillar connection failure handling
    - Add exponential backoff reconnection for pillar streams
    - Continue collecting from available pillars during partial failures
    - Log connection failures with detailed diagnostics
    - _Requirements: Error Handling - Event Collection Errors_
    - _Verification: `pytest tests/unit/test_error_handling.py::test_pillar_failure_recovery -v`_
  
  - [ ] 20.2 Implement database failure handling
    - Return error results on database unavailability
    - Retry transactions up to 3 times with exponential backoff
    - Handle query timeouts with partial results
    - _Requirements: Error Handling - Attack Graph Errors_
    - _Verification: `pytest tests/unit/test_error_handling.py::test_database_failure_handling -v`_
  
  - [ ] 20.3 Implement detection engine error recovery
    - Skip failed detections without crashing service
    - Log full error context for debugging
    - Continue with other detections
    - Throttle processing on resource exhaustion
    - _Requirements: Error Handling - Detection Engine Errors_
    - _Verification: `pytest tests/unit/test_error_handling.py::test_detection_error_recovery -v`_
  
  - [ ] 20.4 Write integration tests for error scenarios
    - Test pillar disconnection and reconnection
    - Test database failover scenarios
    - Test partial system degradation
    - _Verification: `pytest tests/integration/test_error_scenarios.py -v`_
  
  - [ ] 20.5 Write BDD feature tests for Error Handling and Resilience
    - Create tests/features/error_handling.feature with Gherkin scenarios
    - Implement Given/When/Then steps for pillar connection failure with exponential backoff
    - Implement scenarios for database failure handling with transaction retries
    - Implement scenarios for detection engine error recovery without service crashes
    - Implement scenarios for resource exhaustion throttling
    - _Requirements: Error Handling - Event Collection Errors, Attack Graph Errors, Detection Engine Errors_
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
    - Validate configuration on startup
    - _Verification: `pytest tests/unit/test_configuration.py -v`_
  
  - [ ] 21.4 Write end-to-end integration tests
    - Test complete event flow from pillar ingestion to alert generation
    - Verify all detection engines activate on appropriate patterns
    - Test multi-pillar event correlation
    - **Property 64: Passive Observation Invariant**
    - **Validates: Requirement 12.7**
    - _Verification: `pytest tests/integration/test_end_to_end.py -v`_
  
  - [ ] 21.5 Write BDD feature tests for Integration and System Wiring
    - Create tests/features/system_integration.feature with Gherkin scenarios
    - Implement Given/When/Then steps for component wiring (EventStreamCollector → AttackGraphStore → Detection Engines → AlertBus)
    - Implement scenarios for pillar integration points (all 5 pillars)
    - Implement scenarios for passive observation (no blocking of pillar operations)
    - Implement scenarios for end-to-end event flow from ingestion to alert
    - _Requirements: 12.1, 12.2, 12.3, 12.4, 12.5, 12.6, 12.7_
    - _Verification: `pytest tests/step_defs/test_system_integration_bdd.py -v`_


- [ ] 22. Implement Weave Evaluation Tracking Integration
  - [ ] 22.1 Create Weave configuration and initialization infrastructure
    - Add `weave>=0.50.0` and `wandb>=0.16.0` to the `[weave]` optional-dependencies group in `pyproject.toml` (install with `pip install -e ".[weave]"`; omit for non-Weave environments to avoid mandatory cloud-SDK dependencies)
    - Register the `weave` custom marker in `pyproject.toml` under `[tool.pytest.ini_options].markers` to prevent `PytestUnknownMarkWarning` (required by project testing rules in `.agents/rules/testing_and_hygiene.md` rule 9)
    - Implement WeaveConfig dataclass with project_name, entity, offline_mode, parallelism, tags
    - Create `should_enable_weave()` with the following priority order:
      1. `WEAVE_DISABLED=true` → return False (highest priority, always wins)
      2. `WEAVE_OFFLINE=true` → return True (offline mode; local trace storage, no credentials required)
      3. `WANDB_API_KEY` set → return True (cloud sync with API key)
      4. netrc / config-file credentials found → return True (cloud sync via credential file)
      5. None of the above → return False
    - Implement graceful fallback when Weave credentials unavailable
    - Create weave_config.yaml parser for .kiro/evals/ directory
    - _Requirements: 16.1, 16.2, 16.13, 16.14, 18.1, 18.2, 18.3, 18.4, 18.6, 18.8_
    - _Verification: `pytest tests/unit/test_weave_config.py -v --strict-markers`_
  
  - [ ] 22.2 Implement WeaveEvaluationHarness class
    - Create initialization with WeaveConfig, handling offline mode and parallelism
    - Implement `run_evaluation()` with @weave.op() decorator creating Weave runs
    - Add scenario name, timestamp, and tags to Weave run metadata
    - Implement `track_detection_metrics(detection_type, true_positives, false_positives, false_negatives, true_negatives, detection_latency_ms)` — all four confusion-matrix counts are required so that FPR = FP / (FP + TN) can be computed alongside precision, recall, and F1
    - _Requirements: 16.3, 16.8, 17.1, 17.2, 17.3, 17.4, 17.5, 19.5_
    - _Verification: `pytest tests/unit/test_weave_harness.py -v`_
  
  - [ ] 22.3 Implement Weave traced wrappers and trace serializer
    - Implement `WeaveTraceSerializer` in `src/blackwall/enterprise/advanced_threat_detection/weave_serializer.py`:
      - `serialize_event()` exports only `_SAFE_EVENT_FIELDS` (`event_id`, `timestamp`, `source`, `risk_score`); drops `action`, `target`, and `metadata`
      - `serialize_path()` exports `_SAFE_PATH_FIELDS` and replaces node list with a `node_count` scalar
      - `serialize_swarm()` exports `_SAFE_SWARM_FIELDS`
      - `mask_metadata()` recursively replaces values whose keys match `_SENSITIVE_KEY_PATTERNS` with `"**REDACTED**"`
      - `_enforce_size()` truncates and annotates payloads exceeding `_MAX_PAYLOAD_BYTES` (4096 bytes)
      - Offline (`WEAVE_OFFLINE=true`) and cloud modes use the same serializer; sanitization is transport-independent
    - Create `WeaveTracedPathCorrelator`, `WeaveTracedSwarmDetector`, `WeaveTracedAILMTracker`, `WeaveTracedExploitChainAnalyzer`, `WeaveTracedC2Detector` — each must pass inputs and outputs through `WeaveTraceSerializer` before logging to Weave; raw event payloads must never be emitted
    - Write unit tests asserting:
      - `event.action`, `event.target`, and `event.metadata` are absent from `serialize_event()` output
      - Top-level keys matching sensitive patterns (`secret`, `token`, `password`, `key`, etc.) are replaced with `"**REDACTED**"`
      - Nested dict keys matching sensitive patterns are replaced (e.g. `{"outer": {"api_token": "x"}}`)
      - Sensitive keys inside dicts nested within **lists** are masked (e.g. `{"items": [{"api_token": "abc"}]}` → `{"items": [{"api_token": "**REDACTED**"}]}`)
      - Sensitive keys inside dicts nested within **tuples** are masked identically; tuple type is preserved
      - Non-sensitive values inside lists/tuples pass through unchanged
      - Payloads exceeding `_MAX_PAYLOAD_BYTES` return `{"_truncated": True, "_original_bytes": N}`
    - Write integration test asserting no raw `NormalizedEvent` payload appears in any Weave trace captured during an evaluation run
    - _Requirements: 16.4, 16.5, 16.9, 16.10, 16.11_
    - _Verification: `pytest tests/unit/test_weave_traced_detectors.py tests/unit/test_weave_serializer.py tests/integration/test_weave_trace_sanitization.py -v`_
  
  - [ ] 22.4 Implement WeaveMetricsCollector for aggregated metrics
    - Create ThreatDetectionMetrics dataclass with precision, recall, F1, FPR, latency, TP, FP, TN, FN
    - Implement `compute_detection_metrics()` computing standard classification metrics
    - Implement `compute_path_correlation_metrics()` with path correlation accuracy
    - Implement `compute_swarm_detection_metrics()` with swarm detection accuracy
    - Implement `compute_ailm_detection_metrics()` with AILM accuracy and boundary crossing accuracy
    - Implement `compute_exploit_chain_metrics()` with exploit chain accuracy and novelty score accuracy
    - Implement `export_metrics_to_weave()` for aggregated metric export
    - _Requirements: 17.1, 17.2, 17.3, 17.4, 17.5, 17.6, 17.7, 17.8, 17.9, 17.10_
    - _Verification: `pytest tests/unit/test_weave_metrics_collector.py -v`_
  
  - [ ] 22.5 Implement Weave Dataset creation from YAML scenarios
    - Create `create_evaluation_dataset()` loading YAML files from scenarios directory
    - Parse and include all four required scenario fields: `name`, `description`, `events`, `expected_detections` — each Dataset row must contain all four
    - Validate that `description` is a non-empty string; log a warning and skip the scenario if it is missing, empty, or not a string (do not raise — other valid scenarios must still load)
    - Validate that `name`, `events`, and `expected_detections` are present and non-empty; log and skip on failure
    - Write unit tests asserting:
      - A fully-valid scenario produces a row containing `name`, `description`, `events`, and `expected_detections`
      - A scenario missing `description` is skipped and logged; the remaining scenarios are loaded
      - A scenario with a non-string or whitespace-only `description` is skipped and logged
    - Support attack_path, swarm, AILM, exploit_chain, C2, k8s, registry threat expectations
    - _Requirements: 19.1, 19.2, 19.3, 19.4, 19.7, 19.8, 19.9_
    - _Verification: `pytest tests/unit/test_weave_datasets.py -v`_
  
  - [ ] 22.6 Implement environment variable and configuration management
    - Support WANDB_API_KEY for authentication
    - Support WEAVE_PROJECT_NAME, WEAVE_ENTITY for project configuration
    - Support WEAVE_OFFLINE for offline mode without cloud sync
    - Support WEAVE_PARALLELISM for parallel worker count
    - Support WEAVE_DISABLED to completely disable Weave
    - Implement configuration file loading from .kiro/evals/weave_config.yaml
    - Add per-engine trace_enabled and metrics_enabled flags
    - _Requirements: 18.1, 18.2, 18.3, 18.4, 18.5, 18.6, 18.7, 18.9, 18.10_
    - _Verification: `pytest tests/unit/test_weave_environment.py -v`_
  
  - [ ] 22.7 Implement Weave integration with AttackGraphStore
    - Create WeaveTracedAttackGraphStore wrapping AttackGraphStore
    - Trace `insert_event()` with event metadata
    - Trace `query_paths()` with latency tracking and result counts
    - Log query_latency_ms and paths_found to Weave
    - _Requirements: 16.4, 16.5_
    - _Verification: `pytest tests/unit/test_weave_attack_graph.py -v`_
  
  - [ ] 22.8 Implement backward compatibility helpers
    - Create `weave_op_if_enabled()` decorator applying @weave.op() conditionally
    - Ensure tests without @pytest.mark.weave execute without Weave overhead
    - Verify existing unit, integration, property tests pass regardless of Weave config
    - Implement zero-overhead when Weave disabled
    - Verify `WEAVE_OFFLINE=true` enables local tracing **without** requiring WANDB_API_KEY (credential-free offline path must not fall through to the disabled branch)
    - Verify `WEAVE_DISABLED=true` takes precedence even when `WEAVE_OFFLINE=true` is also set
    - _Requirements: 16.13, 18.4, 18.6, 20.1, 20.2, 20.3, 20.4, 20.5, 20.6, 20.7, 20.8, 20.9, 20.10_
    - _Verification: `pytest tests/integration/test_weave_backward_compat.py -v`_
  
  - [ ] 22.9 Create Weave evaluation test suite and detector factory
    - Implement `build_detector_suite()` factory in `src/blackwall/enterprise/advanced_threat_detection/weave_factory.py`:
      - Accept bare component instances + `force_traced: bool = False` flag
      - Gate traced-wrapper construction on `should_enable_weave() and force_traced` — no internal marker detection; callers are responsible for passing the correct value
      - Return a `DetectorSuite` dataclass whose members are either bare components or `WeaveTraced*` wrappers
      - This is the **only** code path allowed to instantiate `WeaveTraced*` classes
    - Do **not** implement `_test_is_weave_marked()` — marker detection belongs exclusively in the `detector_suite` fixture via `request.node.get_closest_marker("weave")`
    - Add `detector_suite` fixture to `tests/conftest.py`:
      - Reads `marked = request.node.get_closest_marker("weave") is not None` using pytest's public `request` API
      - Calls `build_detector_suite(..., force_traced=marked)`
      - Yields bare components for unmarked tests (zero Weave overhead regardless of env vars)
      - Yields traced wrappers for `@pytest.mark.weave` tests (when `should_enable_weave()` is also True)
    - Create `test_atd_weave_evaluations.py` in `tests/evals/` consuming `detector_suite` fixture
    - Implement evaluation tests for multi-stage attack detection, swarm detection, AILM, and exploit chain novelty scoring
    - Verify precision >= 0.95, recall >= 0.90, FPR <= 0.05
    - _Requirements: 16.3, 16.6, 16.7, 17.6, 17.7, 17.8, 20.2, 20.8, 20.10_
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
    - _Verification: `pytest tests/property/test_weave_properties.py --hypothesis-iterations=100 -v`_
  
  - [ ] 22.11 Write BDD feature tests for Weave Evaluation Tracking
    - Create tests/features/weave_evaluation.feature with Gherkin scenarios
    - Implement Given/When/Then steps for Weave initialization with graceful fallback
    - Implement scenarios for evaluation run tracking with scenario metadata
    - Implement scenarios for detection metrics computation (precision, recall, F1, FPR)
    - Implement scenarios for Weave traced wrappers (PathCorrelator, SwarmDetector, AILMTracker, etc.)
    - Implement scenarios for backward compatibility (zero overhead when disabled)
    - _Requirements: 16.1, 16.2, 16.3, 16.4, 16.5, 17.1, 17.2, 17.3, 17.4, 17.5, 18.1-18.10, 19.1-19.10, 20.1-20.10_
    - _Verification: `pytest tests/step_defs/test_weave_evaluation_bdd.py -v`_

- [ ] 23. Red Team Evaluation Scenarios with Weave Tracking
  - [ ] 23.1 Create red team scenario: Agent swarm attack with Weave metrics
    - Simulate coordinated multi-agent attack with shared infrastructure
    - Verify swarm detection triggers CRITICAL alert
    - Measure detection latency and accuracy with Weave
    - Track temporal_correlation and coordination_score in Weave
    - _Requirements: 4.2, 4.3, 10.1, 16.3, 16.10, 17.7_
    - _Verification: `pytest tests/evaluation/test_swarm_scenario.py -v -m weave`_
  
  - [ ] 23.2 Create red team scenario: Multi-stage exploit chain with Weave metrics
    - Simulate RCE → Privilege Escalation → Credential Theft chain
    - Verify exploit chain detection with appropriate novelty score
    - Test both known and novel chain patterns
    - Track novelty_score and chaining_confidence in Weave
    - _Requirements: 5.2, 5.4, 5.5, 10.3, 16.3, 17.9_
    - _Verification: `pytest tests/evaluation/test_exploit_chain_scenario.py -v -m weave`_
  
  - [ ] 23.3 Create red team scenario: C2 infrastructure establishment with Weave metrics
    - Simulate agent establishing RequestBin/Pastebin C2 with beaconing
    - Verify C2 detection triggers CRITICAL alert
    - Test persistence indicator detection
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
    - Create tests/features/red_team_scenarios.feature with Gherkin scenarios
    - Implement Given/When/Then steps for agent swarm attack simulation with Weave metrics
    - Implement scenarios for multi-stage exploit chain detection (RCE → Privilege Escalation → Credential Theft)
    - Implement scenarios for C2 infrastructure establishment with beaconing patterns
    - Implement scenarios for Kubernetes pod token theft and fleet spawning
    - Implement scenarios for AILM across trust boundaries
    - Verify all scenarios track metrics in Weave and meet accuracy thresholds (precision >= 0.95, recall >= 0.90)
    - _Requirements: 4.2, 4.3, 5.2, 5.4, 5.5, 6.2, 6.3, 6.5, 7.2, 7.3, 7.5, 8.1, 8.2, 10.1, 10.2, 10.3, 10.5, 10.6, 16.3, 17.7, 17.8, 17.9_
    - _Verification: `pytest tests/step_defs/test_red_team_scenarios_bdd.py -v -m weave`_

- [ ] 24. Checkpoint - Verify Weave integration
  - Ensure all Weave tests pass with credentials, ask the user if questions arise.
  - Verify backward compatibility: all tests pass without WANDB_API_KEY

- [ ] 25. Final checkpoint - Complete system verification
  - Ensure all tests pass, ask the user if questions arise.


## Notes

- Each task references specific requirements for traceability
- Verification commands use `pytest` with verbose output to validate implementation
- Property tests use Hypothesis with minimum 100 iterations as specified in design
- Integration tests use real PostgreSQL/TimescaleDB instances (not mocks) for performance validation
- Checkpoints ensure incremental validation at logical breaks
- All components follow async/await patterns consistent with existing Blackwall architecture
- Error handling is comprehensive with exponential backoff, retry logic, and graceful degradation
- Performance SLAs are validated through integration tests: event processing < 100ms, path queries < 500ms, sustained throughput 1,000 events/sec
- Red team scenarios validate detection capabilities in realistic attack simulations
- The system operates as a passive observer (Property 64) without modifying pillar operations
- All timestamps use UTC timezone-aware datetime objects
- Score fields (risk_score, correlation_score, temporal_correlation, coordination_score, novelty_score, chaining_confidence) are validated to range [0.0, 1.0]
- Minimum cardinality constraints are enforced: attack paths >= 2 nodes, swarms >= 2 agents
- **Weave Integration (Tasks 22.x)**: Weave evaluation tracking is fully optional and backward compatible. All tests run without Weave when WANDB_API_KEY is unavailable. Use `-m weave` marker to run Weave-specific tests. Weave tracks evaluation metrics (precision, recall, F1, FPR, latency) and provides tracing for multi-stage attack correlation flows.
- **Weave Configuration**: Set WEAVE_OFFLINE=true for offline mode, WEAVE_DISABLED=true to completely disable Weave, WEAVE_PARALLELISM to control worker count (1-10). Configuration file at .kiro/evals/weave_config.yaml provides per-engine trace and metrics toggles.


## Task Dependency Graph

```json
{
  "waves": [
    {
      "id": 0,
      "tasks": ["1.1", "1.2"]
    },
    {
      "id": 1,
      "tasks": ["1.3", "2.1"]
    },
    {
      "id": 2,
      "tasks": ["1.4", "2.2", "2.3", "4.1"]
    },
    {
      "id": 3,
      "tasks": ["2.4", "4.2", "4.3"]
    },
    {
      "id": 4,
      "tasks": ["2.5", "4.4", "5.1"]
    },
    {
      "id": 5,
      "tasks": ["2.6", "5.2", "5.3", "7.1"]
    },
    {
      "id": 6,
      "tasks": ["4.5", "5.4", "7.2", "7.3", "8.1"]
    },
    {
      "id": 7,
      "tasks": ["5.5", "7.4", "8.2", "10.1"]
    },
    {
      "id": 8,
      "tasks": ["5.6", "7.5", "8.3", "10.2", "11.1"]
    },
    {
      "id": 9,
      "tasks": ["8.4", "10.3", "11.2", "12.1"]
    },
    {
      "id": 10,
      "tasks": ["7.6", "8.5", "10.4", "11.3", "12.2", "13.1"]
    },
    {
      "id": 11,
      "tasks": ["10.5", "11.4", "12.3", "13.2"]
    },
    {
      "id": 12,
      "tasks": ["8.6", "11.5", "12.4", "13.3"]
    },
    {
      "id": 13,
      "tasks": ["10.6", "12.5", "13.4", "15.1"]
    },
    {
      "id": 14,
      "tasks": ["11.6", "15.2", "15.3", "15.4", "16.1"]
    },
    {
      "id": 15,
      "tasks": ["12.6", "13.5", "15.5", "16.2", "16.3", "17.1"]
    },
    {
      "id": 16,
      "tasks": ["15.6", "16.4", "17.2", "18.1"]
    },
    {
      "id": 17,
      "tasks": ["16.5", "17.3", "18.2", "20.1"]
    },
    {
      "id": 18,
      "tasks": ["17.4", "18.3", "20.2"]
    },
    {
      "id": 19,
      "tasks": ["17.5", "17.6", "18.4", "20.3", "21.1"]
    },
    {
      "id": 20,
      "tasks": ["18.5", "20.4", "21.2"]
    },
    {
      "id": 21,
      "tasks": ["20.5", "21.3"]
    },
    {
      "id": 22,
      "tasks": ["21.4", "21.5", "22.1"]
    },
    {
      "id": 23,
      "tasks": ["22.2", "22.5", "22.6"]
    },
    {
      "id": 24,
      "tasks": ["22.3", "22.4", "22.7"]
    },
    {
      "id": 25,
      "tasks": ["22.8", "22.9"]
    },
    {
      "id": 26,
      "tasks": ["22.10", "22.11"]
    },
    {
      "id": 27,
      "tasks": ["23.1", "23.2", "23.3"]
    },
    {
      "id": 28,
      "tasks": ["23.4", "23.5"]
    },
    {
      "id": 29,
      "tasks": ["23.6"]
    },
    {
      "id": 30,
      "tasks": ["23.7"]
    }
  ]
}
```
