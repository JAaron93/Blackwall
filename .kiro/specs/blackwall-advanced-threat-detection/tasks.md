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
  
  - [x]* 1.3 Write property tests for data model validation
    - **Property 3: Normalized Event UUID Validity**
    - **Property 4: Normalized Event Timestamp Timezone**
    - **Property 5: Risk Score Bounds**
    - **Property 10: Attack Path Minimum Node Validation**
    - **Property 11: Attack Path Temporal Validity**
    - **Property 26: Swarm Evidence Agent Count Validation**
    - **Property 27: Swarm Evidence Correlation Threshold Validation**
    - **Validates: Requirements 15.1, 15.2, 15.3, 15.5, 15.6, 15.7, 15.8**
    - _Verification: `pytest tests/property/test_models_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [x]* 2.5 Write property tests for Attack Graph Store
    - **Property 6: Temporal Ordering Preservation**
    - **Property 7: Causal Edge Creation**
    - **Property 8: Path Query Minimum Length Enforcement**
    - **Property 9: Node Edge List Integrity**
    - **Validates: Requirements 2.1, 2.2, 2.3, 2.5**
    - _Verification: `pytest tests/property/test_attack_graph_properties.py --hypothesis-iterations=100 -v`_

- [x] 3. Checkpoint - Verify core infrastructure
  - Ensure all tests pass, ask the user if questions arise.


- [ ] 4. Implement Event Stream Collector
  - [ ] 4.1 Create EventStreamCollector class with pillar subscriptions
    - Implement async iterator interfaces for all five pillar event streams
    - Create event source enum mapping (KERNEL_SYSCALL, TOOL_CALL, IDENTITY_ACCESS, PIPELINE_EXECUTION, FORENSIC_ALERT)
    - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.5, 12.1, 12.2, 12.3, 12.4, 12.5, 12.6_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_pillar_subscriptions -v`_
  
  - [ ] 4.2 Implement event normalization logic
    - Create normalization functions for each pillar event type
    - Enrich events with temporal context and agent metadata
    - Generate UUID v4 event_id and UTC timestamp for each event
    - Compute initial risk_score based on event characteristics
    - _Requirements: 1.6, 1.7, 1.8, 1.9_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_normalization -v`_
  
  - [ ] 4.3 Implement error handling for pillar connection failures
    - Add exponential backoff reconnection logic
    - Log malformed events without blocking stream
    - Validate schema for all incoming events
    - _Requirements: Error Handling - Event Collection Errors_
    - _Verification: `pytest tests/unit/test_event_stream_collector.py::test_error_handling -v`_
  
  - [ ]* 4.4 Write property tests for event normalization
    - **Property 1: Event Normalization Source Mapping**
    - **Property 2: Event Enrichment Completeness**
    - **Property 76: Agent ID Non-Empty Validation**
    - **Validates: Requirements 1.1, 1.2, 1.3, 1.4, 1.5, 1.6, 15.4**
    - _Verification: `pytest tests/property/test_event_collector_properties.py --hypothesis-iterations=100 -v`_


- [ ] 5. Implement Multi-Stage Attack Path Correlation
  - [ ] 5.1 Create PathCorrelator class with DFS path finding
    - Implement `correlate_attack_paths()` with time window filtering
    - Build temporal adjacency graph with 5-minute window edges
    - Compute edge weights based on temporal proximity and semantic relationships
    - _Requirements: 3.1, 3.2, 3.3_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_temporal_adjacency -v`_
  
  - [ ] 5.2 Implement depth-first search for path enumeration
    - Create recursive DFS with minimum path length constraint
    - Identify all valid paths meeting length requirements
    - Handle empty path list when agent has insufficient events
    - _Requirements: 3.4, 3.6_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_dfs_path_finding -v`_
  
  - [ ] 5.3 Implement MITRE ATT&CK technique mapping
    - Map event sequences to MITRE ATT&CK technique IDs
    - Populate attack_stages field in AttackPath
    - Validate all technique IDs against MITRE database
    - _Requirements: 2.8, 3.7_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_mitre_mapping -v`_
  
  - [ ] 5.4 Implement risk scoring and path ranking
    - Compute aggregate risk_score for paths
    - Compute correlation_score for path confidence
    - Sort results by risk_score descending
    - _Requirements: 2.9, 2.10, 3.5_
    - _Verification: `pytest tests/unit/test_path_correlator.py::test_risk_scoring -v`_
  
  - [ ]* 5.5 Write property tests for path correlation
    - **Property 14: Time Window Filtering**
    - **Property 15: Temporal Adjacency Rule**
    - **Property 16: Edge Weight Computation**
    - **Property 17: Path Finding Completeness**
    - **Property 18: Risk Score Ordering**
    - **Property 19: Empty Path List for Insufficient Events**
    - **Property 20: MITRE Technique Mapping**
    - **Validates: Requirements 3.1, 3.2, 3.3, 3.4, 3.5, 3.6, 3.7**
    - _Verification: `pytest tests/property/test_path_correlator_properties.py --hypothesis-iterations=100 -v`_

- [ ] 6. Checkpoint - Verify attack path correlation
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
  
  - [ ]* 7.5 Write property tests for swarm detection
    - **Property 21: Behavioral Fingerprint Generation**
    - **Property 22: Swarm Correlation Threshold Enforcement**
    - **Property 23: Swarm Minimum Size Enforcement**
    - **Property 24: Shared Infrastructure Identification**
    - **Property 25: Coordination Score Computation**
    - **Property 28: High-Confidence Swarm Threshold**
    - **Validates: Requirements 4.1, 4.2, 4.3, 4.4, 4.5, 4.8**
    - _Verification: `pytest tests/property/test_swarm_detector_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [ ]* 8.5 Write property tests for exploit chain analysis
    - **Property 29: Exploit Event Classification**
    - **Property 30: Exploit Chain Pattern Detection**
    - **Property 31: Novelty Score Baseline Comparison**
    - **Property 32: Novel Chain High Novelty Score**
    - **Property 33: Known Chain Low Novelty Score**
    - **Property 34: Chaining Confidence Computation**
    - **Validates: Requirements 5.1, 5.2, 5.3, 5.4, 5.5, 5.6**
    - _Verification: `pytest tests/property/test_exploit_chain_properties.py --hypothesis-iterations=100 -v`_

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
  
  - [ ]* 10.5 Write property tests for AILM tracking
    - **Property 35: Permission Grant Recording**
    - **Property 36: Permission Accumulation Detection**
    - **Property 37: Cross-Boundary Permission Detection**
    - **Property 38: Security Boundary Crossing Identification**
    - **Property 39: AILM Risk Level Computation**
    - **Property 40: AILM Evidence Completeness**
    - **Validates: Requirements 6.1, 6.2, 6.3, 6.4, 6.5, 6.6**
    - _Verification: `pytest tests/property/test_ailm_tracker_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [ ]* 11.5 Write property tests for C2 detection
    - **Property 41: C2 Endpoint Detection**
    - **Property 42: Beaconing Pattern Detection**
    - **Property 43: C2 Communication Pattern Classification**
    - **Property 44: C2 Persistence Indicator Identification**
    - **Property 45: Cross-Pillar C2 Correlation**
    - **Validates: Requirements 7.2, 7.3, 7.4, 7.5, 7.6**
    - _Verification: `pytest tests/property/test_c2_detector_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [ ]* 12.5 Write property tests for Kubernetes defense
    - **Property 46: Pod Token Theft Detection**
    - **Property 47: Fleet Spawning Detection**
    - **Property 48: Secrets Exfiltration Detection**
    - **Property 49: K8s Threat Evidence Completeness**
    - **Property 50: K8s API Access Tracking Coverage**
    - **Property 51: Self-Respawning Pod Detection**
    - **Validates: Requirements 8.1, 8.2, 8.3, 8.4, 8.5, 8.6**
    - _Verification: `pytest tests/property/test_k8s_defense_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [ ]* 13.4 Write property tests for registry monitoring
    - **Property 52: Malformed Registry Request Detection**
    - **Property 53: Unusual Registry Pattern Detection**
    - **Property 54: Registry Threat Evidence Type**
    - **Property 55: Registry Threat Evidence Indicators**
    - **Property 56: Registry CVE Correlation**
    - **Validates: Requirements 9.2, 9.3, 9.4, 9.5, 9.6**
    - _Verification: `pytest tests/property/test_registry_monitor_properties.py --hypothesis-iterations=100 -v`_

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
  
  - [ ]* 15.5 Write property tests for alert generation
    - **Property 57: Swarm Detection Alert Generation**
    - **Property 58: AILM Alert Severity Mapping**
    - **Property 59: Exploit Chain Alert Severity Mapping**
    - **Property 60: Attack Path Alert Severity Mapping**
    - **Property 61: C2 Detection Alert Generation**
    - **Property 62: K8s Threat Alert Severity Mapping**
    - **Property 63: Registry Threat Alert Severity Mapping**
    - **Validates: Requirements 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7**
    - _Verification: `pytest tests/property/test_alert_generation_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [ ]* 17.5 Write property tests for retrospective analysis
    - **Property 65: Historical Time Window Support**
    - **Property 66: Retrospective Path Detection**
    - **Property 67: Multi-Agent Historical Correlation**
    - **Property 68: Attack Graph Export Format Compliance**
    - **Validates: Requirements 13.1, 13.2, 13.3, 13.5**
    - _Verification: `pytest tests/property/test_retrospective_properties.py --hypothesis-iterations=100 -v`_


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
  
  - [ ]* 18.4 Write property tests for evaluation mode
    - **Property 69: Evaluation Mode Event Labeling**
    - **Property 70: Evaluation Mode Alert Isolation**
    - **Property 71: Evaluation Environment Graph Isolation**
    - **Property 72: Evaluation State Reset**
    - **Validates: Requirements 14.1, 14.2, 14.3, 14.4**
    - _Verification: `pytest tests/property/test_evaluation_mode_properties.py --hypothesis-iterations=100 -v`_

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
  
  - [ ]* 20.4 Write integration tests for error scenarios
    - Test pillar disconnection and reconnection
    - Test database failover scenarios
    - Test partial system degradation
    - _Verification: `pytest tests/integration/test_error_scenarios.py -v`_


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
  
  - [ ]* 21.4 Write end-to-end integration tests
    - Test complete event flow from pillar ingestion to alert generation
    - Verify all detection engines activate on appropriate patterns
    - Test multi-pillar event correlation
    - **Property 64: Passive Observation Invariant**
    - **Validates: Requirement 12.7**
    - _Verification: `pytest tests/integration/test_end_to_end.py -v`_


- [ ] 22. Red Team Evaluation Scenarios
  - [ ] 22.1 Create red team scenario: Agent swarm attack
    - Simulate coordinated multi-agent attack with shared infrastructure
    - Verify swarm detection triggers CRITICAL alert
    - Measure detection latency and accuracy
    - _Requirements: 4.2, 4.3, 10.1_
    - _Verification: `pytest tests/evaluation/test_swarm_scenario.py -v`_
  
  - [ ] 22.2 Create red team scenario: Multi-stage exploit chain
    - Simulate RCE → Privilege Escalation → Credential Theft chain
    - Verify exploit chain detection with appropriate novelty score
    - Test both known and novel chain patterns
    - _Requirements: 5.2, 5.4, 5.5, 10.3_
    - _Verification: `pytest tests/evaluation/test_exploit_chain_scenario.py -v`_
  
  - [ ] 22.3 Create red team scenario: C2 infrastructure establishment
    - Simulate agent establishing RequestBin/Pastebin C2 with beaconing
    - Verify C2 detection triggers CRITICAL alert
    - Test persistence indicator detection
    - _Requirements: 7.2, 7.3, 7.5, 10.5_
    - _Verification: `pytest tests/evaluation/test_c2_scenario.py -v`_
  
  - [ ] 22.4 Create red team scenario: Kubernetes pod token theft and fleet spawning
    - Simulate service account token theft followed by rapid pod creation
    - Verify Kubernetes defense layer detects both threats
    - _Requirements: 8.1, 8.2, 10.6_
    - _Verification: `pytest tests/evaluation/test_k8s_scenario.py -v`_
  
  - [ ] 22.5 Create red team scenario: AILM across trust boundaries
    - Simulate permission accumulation spanning multiple boundaries
    - Verify AILM tracker detects composition and computes correct risk level
    - _Requirements: 6.2, 6.3, 6.5, 10.2_
    - _Verification: `pytest tests/evaluation/test_ailm_scenario.py -v`_

- [ ] 23. Final checkpoint - Complete system verification
  - Ensure all tests pass, ask the user if questions arise.


## Notes

- Tasks marked with `*` are optional property-based test tasks and can be skipped for faster MVP delivery
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
      "tasks": ["2.2", "2.3", "4.1"]
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
      "tasks": ["5.2", "5.3", "7.1"]
    },
    {
      "id": 6,
      "tasks": ["5.4", "7.2", "7.3", "8.1"]
    },
    {
      "id": 7,
      "tasks": ["5.5", "7.4", "8.2", "10.1"]
    },
    {
      "id": 8,
      "tasks": ["7.5", "8.3", "10.2", "11.1"]
    },
    {
      "id": 9,
      "tasks": ["8.4", "10.3", "11.2", "12.1"]
    },
    {
      "id": 10,
      "tasks": ["8.5", "10.4", "11.3", "12.2", "13.1"]
    },
    {
      "id": 11,
      "tasks": ["10.5", "11.4", "12.3", "13.2"]
    },
    {
      "id": 12,
      "tasks": ["11.5", "12.4", "13.3"]
    },
    {
      "id": 13,
      "tasks": ["12.5", "13.4", "15.1"]
    },
    {
      "id": 14,
      "tasks": ["15.2", "15.3", "15.4", "16.1"]
    },
    {
      "id": 15,
      "tasks": ["15.5", "16.2", "16.3", "17.1"]
    },
    {
      "id": 16,
      "tasks": ["16.4", "17.2", "18.1"]
    },
    {
      "id": 17,
      "tasks": ["17.3", "18.2", "20.1"]
    },
    {
      "id": 18,
      "tasks": ["17.4", "18.3", "20.2"]
    },
    {
      "id": 19,
      "tasks": ["17.5", "18.4", "20.3", "21.1"]
    },
    {
      "id": 20,
      "tasks": ["20.4", "21.2"]
    },
    {
      "id": 21,
      "tasks": ["21.3"]
    },
    {
      "id": 22,
      "tasks": ["21.4"]
    },
    {
      "id": 23,
      "tasks": ["22.1", "22.2", "22.3"]
    },
    {
      "id": 24,
      "tasks": ["22.4", "22.5"]
    }
  ]
}
```
