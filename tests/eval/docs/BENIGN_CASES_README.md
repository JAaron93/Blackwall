# Benign Test Cases Dataset

This document describes the comprehensive benign test cases generated for the Blackwall Security Evaluation dataset.

## Overview

- **Total Cases**: 69 benign operations
- **Generator**: `create_benign_comprehensive.py`
- **Output File**: `benign_cases.json`
- **Ground Truth**: All cases marked as `"BENIGN"`
- **Format**: Reference-based with semantic markers (`[[MARKER_NAME]]`)

## Schema

Each benign case follows the standard schema:

```json
{
  "id": "benign_category_###",
  "tool_name": "tool_type",
  "tool_call_context": {
    "agentId": "demo-agent",
    "toolName": "tool_type",
    "rawArguments": {
      // Tool-specific parameters with sanitized markers
    },
    "environmentRole": "role_name"
  },
  "ground_truth": "BENIGN",
  "reason": "Concise explanation why this is benign",
  "categories": ["category_name"],
  "notes": "Implementation-specific notes"
}
```

## Categories and Distribution

### 1. Database Operations (15 cases)
Legitimate database queries and operations showing proper parameterization:
- **SELECT queries** (5 cases): Basic SELECT, filtering, pagination, LIKE patterns
- **Aggregation queries** (3 cases): COUNT, SUM, AVG, GROUP BY, HAVING
- **JOIN operations** (2 cases): INNER JOIN, LEFT JOIN, multi-table queries
- **INSERT/UPDATE** (3 cases): Audit logs, notifications, profile updates
- **Advanced queries** (2 cases): Window functions, recursive CTEs

**Markers used**: `[[SANITIZED_ID]]`, `[[REGION_NAME]]`, `[[TIMESTAMP]]`, `[[START_DATE]]`, `[[END_DATE]]`

### 2. File Operations (13 cases)
Safe file system access patterns for authorized roles:
- **Read operations** (5 cases): Log files, config files, source code, CSV data
- **Write operations** (4 cases): Temporary files, reports, backups, logs
- **Directory operations** (2 cases): Listing, checking existence
- **Metadata operations** (2 cases): File size, existence checks

**Markers used**: `[[PROJECT_ROOT]]`, `[[DATA_DIR]]`, `[[SESSION_ID]]`, `[[OUTPUT_DIR]]`

### 3. Network Operations (11 cases)
Legitimate external API calls and internal service communication:
- **Public API calls** (3 cases): GitHub, PyPI, npm registries
- **Internal service calls** (3 cases): Authenticated requests, service discovery
- **Monitoring/telemetry** (3 cases): Health checks, metrics push, webhooks
- **Security operations** (2 cases): DNS lookups, SSL certificate checks

**Markers used**: `[[AUTH_TOKEN]]`, `[[DOMAIN_NAME]]`, `[[API_ENDPOINT]]`, `[[ISO_TIMESTAMP]]`

### 4. Agent Tool Usage (13 cases)
Standard ADK-style agent operations and patterns:
- **Invocation** (1 case): Agent-to-agent communication
- **Resilience patterns** (4 cases): Retry logic, circuit breaker, health checks
- **Observability** (4 cases): Logging, metrics, state checkpoints
- **Concurrency** (3 cases): Parallel execution, semaphores, context management
- **Resource management** (1 case): Resource cleanup

**Markers used**: `[[AGENT_ID]]`, `[[TASK_ID]]`, `[[CHECKPOINT_ID]]`, `[[RESOURCE_NAME]]`

### 5. Edge Cases (17 cases)
Complex but legitimate operations demonstrating advanced patterns:
- **Batch operations** (2 cases): Large batches, partial failures
- **Async operations** (2 cases): Asynchronous calls, streaming
- **Concurrency** (3 cases): Concurrent operations, multi-region
- **Data consistency** (3 cases): Transactions, UPSERT, idempotency
- **Advanced queries** (4 cases): Complex JOINs, full-text search, partitioning
- **Flow control** (3 cases): Rate limiting, timeout protection, fan-out

**Markers used**: All categories of markers in realistic combinations

## Sanitized Markers

All potentially sensitive values are replaced with semantic markers:

| Marker | Purpose | Example |
|--------|---------|---------|
| `[[SANITIZED_ID]]` | User/record ID | User identifiers |
| `[[AUTH_TOKEN]]` | Authentication | API tokens, bearer tokens |
| `[[FILE_PATH]]` | File paths | `/var/log/app.log` |
| `[[IP_ADDRESS]]` | IP addresses | `192.168.1.1` |
| `[[DOMAIN_NAME]]` | Domain names | `api.company.local` |
| `[[REGION_NAME]]` | Region info | `us-east-1` |
| `[[TIMESTAMP]]` | Timestamps | Temporal values |
| `[[ISO_TIMESTAMP]]` | ISO 8601 | Full datetime |
| `[[SESSION_ID]]` | Session IDs | Correlation IDs |
| `[[AGENT_ID]]` | Agent identifiers | Executor names |
| `[[RESOURCE_NAME]]` | Resource names | Semaphore names |

## Use Cases

These benign cases are designed for:

1. **False Positive Rate (FPR) Testing**: Verify Blackwall allows legitimate operations
2. **Performance Baseline**: Measure detection latency on known-good inputs
3. **Regression Testing**: Ensure new threat signatures don't block benign ops
4. **Model Training**: Provide negative examples for ML-based detection
5. **Documentation**: Show examples of compliant agent behavior

## Tool Coverage

Benign cases cover these ADK tool types:

- `database_query` - SQL operations
- `file_read`, `file_write`, `file_append`, `file_list`, `file_exists`, `file_size` - File ops
- `http_request` - HTTP/HTTPS calls
- `dns_lookup` - DNS operations
- `agent_invoke`, `agent_retry`, `agent_log`, `agent_cache_*` - Agent ops
- `agent_parallel_map`, `agent_circuit_breaker`, `agent_health_check` - Resilience
- `agent_state_save`, `agent_metric_record`, `agent_acquire_semaphore` - Observability

## Environment Roles

Cases are tagged with realistic ADK environment roles:

- `data_analyst` - Data access and reporting
- `system_administrator` - Infrastructure operations
- `developer` - Application development
- `system` - Internal system operations
- `monitoring` - Observability operations
- `package_manager` - Dependency management
- `security_auditor` - Audit operations
- `inventory_manager` - Business operations

## Validation

All cases have been validated for:

✓ Valid JSON structure  
✓ Required fields present in all cases  
✓ All ground_truth values set to "BENIGN"  
✓ Proper schema compliance  
✓ Realistic tool call contexts  
✓ Appropriate marker usage  

## Related Files

- `malicious_cases.json` - Corresponding malicious test cases
- `README_MALICIOUS.md` - Malicious cases documentation
- Generator script: `../../create_benign_comprehensive.py`

## Integration with Blackwall

These cases should be used in:

1. **Evaluation Phase**: Combined with malicious_cases.json for comprehensive testing
2. **Regression Suite**: Automated testing to catch false positives
3. **Benchmark Suite**: Performance profiling on known-good inputs
4. **Documentation**: Example payloads in threat modeling guides

## Statistics

- **Total cases**: 69
- **Average fields per case**: 7 (all required)
- **Semantic markers used**: 15+ unique types
- **Tool types covered**: 8+
- **Environment roles covered**: 8
- **Cases per category**: 11-17 (well-distributed)
