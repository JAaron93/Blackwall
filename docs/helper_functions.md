# Centralized Helper Functions & Utility Modules

This document serves as the centralized reference for reusable helper functions and utility modules across the Blackwall codebase to enforce the DRY (Don't Repeat Yourself) principle.

---

## 1. Validation & Utility Helpers (`src/blackwall/validators.py`)

Module Location: [`src/blackwall/validators.py`](../src/blackwall/validators.py)

| Function | Signature | Description / Purpose | Use Cases & Applied Locations |
| :--- | :--- | :--- | :--- |
| `validate_semver_format` | `(v: str) -> str` | Validates that a version string strictly follows the `MAJOR.MINOR.PATCH` semantic versioning format via regex `^\d+\.\d+\.\d+$`. Raises `ValueError` on mismatch. | `PolicyServerState.validate_semver` ([models.py](../src/blackwall/models.py)), `PolicyConfig.validate_semver` ([policy/models.py](../src/blackwall/policy/models.py)). |
| `validate_utc_datetime` | `(v: datetime) -> datetime` | Validates that a `datetime` object is timezone-aware and set to UTC (`v.tzinfo` is not None and UTC offset matches UTC). Raises `ValueError` if naive or non-UTC. | `NormalizedEvent`, `AttackPath`, `SwarmEvidence`, `PermissionGrant`, `AgentQuotaUsage`, `CovertChannelEvidence` field validators ([enterprise/advanced_threat_detection/models.py](../src/blackwall/enterprise/advanced_threat_detection/models.py)), `SwarmContextSummary.validate_utc_timestamps` ([models.py](../src/blackwall/models.py)). |
| `utc_now` | `() -> datetime` | Returns the current timezone-aware UTC `datetime` (`datetime.now(timezone.utc)`). | Default factories in Pydantic models, telemetry spans, audit timestamps. |
| `validate_uuid_v4_format` | `(v: Any, field_name: str = "event_id") -> UUID` | Validates that a string or UUID object is a valid UUID v4 format and returns a `uuid.UUID` instance. Raises `ValueError` if invalid format or version != 4. | `NormalizedEvent.validate_uuid_v4`, `PermissionGrant.validate_uuid_v4_fields`, `CovertChannelEvidence.validate_channel_id` ([enterprise/advanced_threat_detection/models.py](../src/blackwall/enterprise/advanced_threat_detection/models.py)). |
| `ensure_uuid_v4` | `(v: Any = None) -> UUID` | Returns a valid `uuid.UUID` (version 4) instance if input is valid UUID v4; falls back to generating a new random `uuid.UUID` instance if invalid or `None`. | `EventStreamCollector.normalize_event` ([enterprise/advanced_threat_detection/collector.py](../src/blackwall/enterprise/advanced_threat_detection/collector.py)). |
| `validate_non_empty_string` | `(v: str, field_name: str = "string") -> str` | Validates that a string is not empty or whitespace only. Raises `ValueError` if empty. | `NormalizedEvent.validate_non_empty_agent_id`, `PermissionGrant.validate_non_empty_fields`, `PromptInjectionEvidence.validate_non_empty_sanitized`, `AgentQuotaUsage.validate_non_empty_agent_id` ([enterprise/advanced_threat_detection/models.py](../src/blackwall/enterprise/advanced_threat_detection/models.py)), `PromptInjectionScanner.__init__` ([enterprise/advanced_threat_detection/prompt_injection.py](../src/blackwall/enterprise/advanced_threat_detection/prompt_injection.py)), `AgentQuotaEnforcer` ([enterprise/advanced_threat_detection/quota_enforcer.py](../src/blackwall/enterprise/advanced_threat_detection/quota_enforcer.py)). |
| `validate_min_items` | `(v: T, min_items: int = 2, field_name: str = "collection", custom_msg: Optional[str] = None) -> T` | Validates that a collection contains at least `min_items` elements. Raises `ValueError` if below minimum size. | `AttackPath.validate_min_nodes`, `SwarmEvidence.validate_min_agents`, `CovertChannelEvidence.validate_min_agents`, `PromptInjectionEvidence.validate_min_patterns` ([enterprise/advanced_threat_detection/models.py](../src/blackwall/enterprise/advanced_threat_detection/models.py)). |
| `validate_temporal_sequence` | `(start_time: datetime, end_time: datetime, start_name: str = "start_time", end_name: str = "end_time", custom_msg: Optional[str] = None) -> None` | Validates that `end_time >= start_time` for UTC-aware datetimes. Raises `ValueError` on reversed temporal ordering. | `AttackPath.validate_temporal_ordering`, `SwarmEvidence.validate_temporal_ordering`, `CovertChannelEvidence.validate_temporal_ordering` ([enterprise/advanced_threat_detection/models.py](../src/blackwall/enterprise/advanced_threat_detection/models.py)), `SwarmContextSummary.validate_temporal_ordering` ([models.py](../src/blackwall/models.py)), `PathCorrelator.correlate_attack_paths` ([enterprise/advanced_threat_detection/correlator.py](../src/blackwall/enterprise/advanced_threat_detection/correlator.py)), `AgentSwarmDetector.detect_swarms` ([enterprise/advanced_threat_detection/swarm.py](../src/blackwall/enterprise/advanced_threat_detection/swarm.py)), `ExploitChainAnalyzer.detect_chains` ([enterprise/advanced_threat_detection/exploit.py](../src/blackwall/enterprise/advanced_threat_detection/exploit.py)), `AILMTracker.get_permission_grants` ([enterprise/advanced_threat_detection/ailm.py](../src/blackwall/enterprise/advanced_threat_detection/ailm.py)), `C2InfrastructureDetector` ([enterprise/advanced_threat_detection/c2.py](../src/blackwall/enterprise/advanced_threat_detection/c2.py)), `KubernetesDefenseLayer` ([enterprise/advanced_threat_detection/k8s.py](../src/blackwall/enterprise/advanced_threat_detection/k8s.py)), `PackageRegistryMonitor` ([enterprise/advanced_threat_detection/registry.py](../src/blackwall/enterprise/advanced_threat_detection/registry.py)). |
| `parse_json_safely` | `(v: Optional[Union[str, bytes]], default: Any = None) -> Any` | Safely parses a JSON string or bytes payload; returns `default` if `None`, empty, or on `JSONDecodeError`. | `SQLiteThreatRepository` ([db/repository.py](../src/blackwall/db/repository.py)), `ReportGenerator` ([eval/report_generator.py](../src/blackwall/eval/report_generator.py)). |
| `format_iso_datetime` | `(v: Optional[datetime] = None) -> str` | Formats a timezone-aware UTC datetime (or current UTC time if `None`) to an ISO 8601 string representation. | `SQLiteThreatRepository` ([db/repository.py](../src/blackwall/db/repository.py)), `ReportGenerator` ([eval/report_generator.py](../src/blackwall/eval/report_generator.py)). |
| `parse_iso_datetime` | `(v: Optional[Union[str, datetime]], default: Optional[datetime] = None) -> Optional[datetime]` | Parses an ISO 8601 string or datetime into a UTC timezone-aware datetime. | `SQLiteThreatRepository` ([db/repository.py](../src/blackwall/db/repository.py)). |
| `compute_word_intersection_match_quality` | `(query_text: str, candidate_text: str) -> float` | Computes word-level intersection match quality (`len(intersection) / max(min_len, 1)`) for FTS queries and candidate texts using native Rust SIMD/zero-allocation extension (`_core_rs.compute_word_intersection_match_quality`) with pure-Python fallback. | `SQLiteThreatRepository.find_similar_signatures` ([db/repository.py](../src/blackwall/db/repository.py)). |
| `compute_shannon_entropy` | `(text: str) -> float` | Computes the Shannon character entropy \( -\sum p_i \log_2(p_i) \) of a string using native compiled Rust extension (`_core_rs.compute_shannon_entropy`) with pure-Python fallback. | `extract_iocs` in `src/blackwall/policy/semantic.py` and threat scoring models. |
| `normalize_time_window` | `(time_window: Optional[Tuple[datetime, datetime]] = None, default_duration_seconds: float = 300.0) -> Tuple[datetime, datetime]` | Validates and normalizes an optional `(start_time, end_time)` window into timezone-aware UTC datetimes, enforcing temporal ordering. If `None`, defaults to `(now - default_duration, now)`. | `PathCorrelator`, `AgentSwarmDetector`, `ExploitChainAnalyzer`, `AILMTracker`, `C2InfrastructureDetector`, `KubernetesDefenseLayer`, `PackageRegistryMonitor`, `RetrospectiveAnalyzer`, `AdvancedThreatDetection` orchestrator ([enterprise/advanced_threat_detection/](../src/blackwall/enterprise/advanced_threat_detection/)). |
| `compute_jaccard_similarity` | `(set_a: Union[Set[Any], Sequence[Any]], set_b: Union[Set[Any], Sequence[Any]]) -> float` | Computes the Jaccard similarity coefficient \( \frac{\|A \cap B\|}{\|A \cup B\|} \) between two sets or collections. Returns `1.0` if both empty, `0.0` if one empty. | `AgentSwarmDetector` ([enterprise/advanced_threat_detection/swarm.py](../src/blackwall/enterprise/advanced_threat_detection/swarm.py)), `RetrospectiveAnalyzer` ([enterprise/advanced_threat_detection/retrospective.py](../src/blackwall/enterprise/advanced_threat_detection/retrospective.py)). |
| `compute_exponential_decay` | `(delta_seconds: float, half_life_seconds: float) -> float` | Computes exponential decay factor \( e^{-\frac{\Delta t}{\tau}} \) for temporal proximity scoring. Returns `1.0` for \( \Delta t \le 0 \). | `PathCorrelator` ([enterprise/advanced_threat_detection/correlator.py](../src/blackwall/enterprise/advanced_threat_detection/correlator.py)), `AgentSwarmDetector` ([enterprise/advanced_threat_detection/swarm.py](../src/blackwall/enterprise/advanced_threat_detection/swarm.py)), `ExploitChainAnalyzer` ([enterprise/advanced_threat_detection/exploit.py](../src/blackwall/enterprise/advanced_threat_detection/exploit.py)), `RetrospectiveAnalyzer` ([enterprise/advanced_threat_detection/retrospective.py](../src/blackwall/enterprise/advanced_threat_detection/retrospective.py)). |
| `clamp_score` | `(score: float, min_val: float = 0.0, max_val: float = 1.0, decimals: Optional[int] = None) -> float` | Clamps a numeric score within `[min_val, max_val]` bounds and optionally rounds to `decimals` precision. | `PathCorrelator`, `AgentSwarmDetector`, `ExploitChainAnalyzer`, `RetrospectiveAnalyzer` ([enterprise/advanced_threat_detection/](../src/blackwall/enterprise/advanced_threat_detection/)). |
| `is_evaluation_metadata` | `(metadata: Optional[Dict[str, Any]]) -> bool` | Checks if an event, alert, or payload metadata dictionary carries evaluation environment labeling (`is_evaluation=True`, `eval_mode=True`, or non-empty `evaluation_env_id`). | `EvaluationEnvironmentManager` ([enterprise/advanced_threat_detection/evaluation.py](../src/blackwall/enterprise/advanced_threat_detection/evaluation.py)), `ActiveReactionEngine` ([enterprise/advanced_threat_detection/reaction.py](../src/blackwall/enterprise/advanced_threat_detection/reaction.py)). |
| `stamp_evaluation_metadata` | `(metadata: Optional[Dict[str, Any]], env_id: str) -> Dict[str, Any]` | Immutably stamps a metadata dictionary with evaluation markers (`evaluation_env_id`, `is_evaluation=True`, `eval_mode=True`). | `EvaluationEnvironmentManager` ([enterprise/advanced_threat_detection/evaluation.py](../src/blackwall/enterprise/advanced_threat_detection/evaluation.py)). |

---

## 2. Threat Detection Domain Helpers (`src/blackwall/enterprise/advanced_threat_detection/correlator.py`)

Module Location: [`src/blackwall/enterprise/advanced_threat_detection/correlator.py`](../src/blackwall/enterprise/advanced_threat_detection/correlator.py)

| Function | Signature | Description / Purpose | Use Cases & Applied Locations |
| :--- | :--- | :--- | :--- |
| `map_mitre_attack_techniques` | `(nodes: Sequence[AttackNode], default_fallback: Optional[str] = "T1059") -> List[str]` | Maps attack graph nodes to MITRE ATT&CK technique codes using precompiled regex patterns across action and target fields without order-dependent duplicates. | `PathCorrelator` ([enterprise/advanced_threat_detection/correlator.py](../src/blackwall/enterprise/advanced_threat_detection/correlator.py)), `RetrospectiveAnalyzer` ([enterprise/advanced_threat_detection/retrospective.py](../src/blackwall/enterprise/advanced_threat_detection/retrospective.py)). |

---

## 3. Test Step Async Helper (`tests/step_defs/async_utils.py`)

Module Location: [`tests/step_defs/async_utils.py`](../tests/step_defs/async_utils.py)

| Function | Signature | Description / Purpose | Use Cases & Applied Locations |
| :--- | :--- | :--- | :--- |
| `run_async` | `(coro: Coroutine) -> Any` | Safely executes an asynchronous coroutine synchronously inside `pytest-bdd` step definitions using an isolated event loop. | `test_advanced_threat_detection_bdd.py`, `test_agent_swarm_detector_bdd.py`, `test_exploit_chain_analyzer_bdd.py`, `test_ailm_tracker_bdd.py`, `test_c2_infrastructure_detector_bdd.py`, `test_kubernetes_defense_bdd.py`, `test_package_registry_monitor_bdd.py`, `test_inbound_protocol_filter_bdd.py`, `test_prompt_injection_scanner_bdd.py`, `test_batch_resolver_bdd.py`, `test_enterprise_mesh.py`. |


---

## 4. BDD Security Contract Helpers (`tests/step_defs/test_security_contract_validators_steps.py`)

Module Location: [`tests/step_defs/test_security_contract_validators_steps.py`](../tests/step_defs/test_security_contract_validators_steps.py)
Feature Location: [`tests/features/security_contract_validators.feature`](../tests/features/security_contract_validators.feature)

| Step Definition | Gherkin Pattern | Description / Purpose |
| :--- | :--- | :--- |
| `set_version_string` | `Given a version string "{version_str}"` | Sets test version input on `ValidatorState`. |
| `execute_semver_validation` | `When the semver validation helper is executed` | Executes `validate_semver_format` and captures exceptions into state. |
| `execute_utc_datetime_validation` | `When the UTC datetime validation helper is executed` | Executes `validate_utc_datetime` and captures exceptions into state. |
| `set_naive_datetime` | `Given a naive datetime without timezone info` | Generates a naive datetime without timezone info (`tzinfo=None`). |
| `set_non_utc_datetime` | `Given a non-UTC timezone-aware datetime` | Generates a non-UTC timezone-aware datetime object. |
| `set_valid_uuid_v4` | `Given a valid UUID v4 string` | Generates a valid UUID v4 string for validation state. |
| `set_invalid_uuid` | `Given an invalid UUID string "{invalid_uuid}"` | Sets an invalid UUID string input on `ValidatorState`. |
| `execute_uuid_v4_validation` | `When the UUID v4 validation helper is executed` | Executes `validate_uuid_v4_format` and captures exceptions into state. |
| `set_non_empty_string` | `Given a non-empty string "{input_str}"` | Sets non-empty string input on `ValidatorState`. |
| `set_empty_string` | `Given an empty string "{input_str}"` | Sets empty or whitespace string input on `ValidatorState`. |
| `execute_non_empty_string_validation` | `When the non-empty string validation helper is executed` | Executes `validate_non_empty_string` and captures exceptions into state. |
| `set_collection_count` | `Given a collection with {count:d} items` | Populates a list with `count` items on `ValidatorState`. |
| `execute_min_items_validation` | `When the min items validation helper is executed with min size {min_size:d}` | Executes `validate_min_items` and captures exceptions into state. |
| `set_valid_temporal_times` | `Given a valid UTC start time and a later UTC end time` | Generates valid UTC `start_time` and `end_time` pair. |
| `set_invalid_temporal_times` | `Given a valid UTC start time and an earlier UTC end time` | Generates reversed `start_time` and `end_time` pair. |
| `execute_temporal_sequence_validation` | `When the temporal sequence validation helper is executed` | Executes `validate_temporal_sequence` and captures exceptions into state. |

---

## 5. Guidelines for Adding New Helpers
1. Place general domain/validation helpers in `src/blackwall/validators.py` or dedicated sub-package utility modules.
2. Ensure all helper functions follow the **Single Responsibility Principle**.
3. Always add unit tests for new helper functions in `tests/unit/test_validators.py`.
4. Add corresponding BDD security contract scenarios under `tests/features/` and executable steps under `tests/step_defs/`.
5. Update this document whenever new shared helper functions are added or modified.
