# Blackwall Security Evaluation Dataset

This directory contains the reference datasets for evaluating Blackwall's security capabilities.

## Files

### Benign Cases

**File**: `benign_cases.json`  
**Cases**: 68 benign operations  
**Purpose**: Testing false positive rate and proper handling of legitimate agent operations

- **Database Operations** (15): SELECT, INSERT, UPDATE, JOIN, aggregations with proper parameterization
- **File Operations** (13): Safe file reads/writes, config access, logging
- **Network Operations** (11): GitHub/PyPI/npm API calls, internal services, webhooks
- **Agent Tool Usage** (13): Invocations, retry logic, logging, caching, concurrency
- **Edge Cases** (17): Large batches, async operations, transactions, complex queries

**Documentation**: See `BENIGN_CASES_README.md`

### Malicious Cases

**File**: `malicious_cases.json`  
**Cases**: 59 malicious injection/attack patterns  
**Purpose**: Testing true positive rate and threat detection accuracy

- **SQL Injection** (10): Boolean-based, time-based blind, UNION, stacked queries, etc.
- **Command Injection** (10): Semicolon, pipe, OR/AND operators, command substitution
- **Path Traversal** (8): Directory traversal, null bytes, encoding bypasses, symlinks
- **C2 Communication** (8): Known IOCs, malicious domains, DNS tunneling, botnets
- **Credential Exfiltration** (5): HTTP POST, file write, DNS tunneling, environment dumps
- **Reverse Shells** (6): curl|bash, nc, bash redirection, Python/socat
- **Obfuscation Techniques** (2): Base64 encoding, URL encoding

**Documentation**: See `README_MALICIOUS.md`

## Data Format

### Schema

All test cases follow this standard JSON schema:

```json
{
  "id": "category_attack_###",
  "tool_name": "tool_type",
  "tool_call_context": {
    "agentId": "demo-agent",
    "toolName": "tool_type",
    "rawArguments": { /* tool-specific params */ },
    "environmentRole": "role_name"
  },
  "ground_truth": "BENIGN|MALICIOUS",
  "reason": "Explanation",
  "categories": ["category_name"],
  "notes": "Additional context",
  
  // Malicious-only fields:
  "attack_type": "ATTACK_TYPE",
  "cwe_id": "CWE-###",
  "cwe_url": "https://cwe.mitre.org/...",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW",
  "references": ["https://..."]
}
```

### Sanitization Markers

To ensure data hygiene and prevent context hallucination, all sensitive values are replaced with semantic markers:

```
[[SANITIZED_ID]]      - User/record identifiers
[[AUTH_TOKEN]]        - Authentication credentials
[[FILE_PATH]]         - File system paths
[[IP_ADDRESS]]        - IP addresses
[[DOMAIN_NAME]]       - Domain names
[[REGION_NAME]]       - Geographic/cloud regions
[[TIMESTAMP]]         - Temporal values
[[ISO_TIMESTAMP]]     - ISO 8601 datetime
[[SESSION_ID]]        - Session/correlation IDs
[[AGENT_ID]]          - Agent names/identifiers
[[RESOURCE_NAME]]     - Resource identifiers
```

## Tool Coverage

Both datasets cover these ADK tool types:

- `database_query` - SQL operations
- `file_read`, `file_write`, `file_append`, `file_list` - File operations
- `http_request` - HTTP/HTTPS calls
- `dns_lookup` - DNS operations
- `execute_shell` - Command execution
- `agent_*` - Agent framework tools

## Usage

### For Evaluation

1. Load both datasets:
```python
import json

with open('benign_cases.json') as f:
    benign = json.load(f)
    
with open('malicious_cases.json') as f:
    malicious = json.load(f)
```

2. Calculate metrics:
```python
# Total test population
total_cases = len(benign) + len(malicious)

# Expected accuracy baseline
fp_rate_target = 0.05  # < 5% false positives
tp_rate_target = 0.95  # > 95% true positives
```

3. Run evaluation:
```bash
python3 ../../evaluate_blackwall.py \
  --benign benign_cases.json \
  --malicious malicious_cases.json \
  --output evaluation_report.json
```

### For Training

- Use benign cases as negative examples for ML models
- Use malicious cases as positive examples for pattern learning
- Split 70/30 for training/validation

### For Documentation

- Reference specific cases in threat modeling
- Use case IDs in vulnerability reports
- Link to CWE/CVE references in security briefs

## Statistics

| Category | Benign | Malicious | Total |
|----------|--------|-----------|-------|
| Database | 15 | 10 | 25 |
| File/Path | 13 | 8 | 21 |
| Network | 11 | 8 | 19 |
| Command | 0 | 10 | 10 |
| Credentials | 0 | 5 | 5 |
| Reverse Shell | 0 | 6 | 6 |
| Obfuscation | 0 | 2 | 2 |
| Agent/Tools | 13 | 0 | 13 |
| Edge Cases | 17 | 0 | 17 |
| **TOTAL** | **68** | **59** | **127** |

## Validation

### Benign Cases
- ✓ All cases marked as `"BENIGN"`
- ✓ All 68 cases have required fields
- ✓ Valid JSON structure
- ✓ Realistic tool invocations
- ✓ Proper use of semantic markers
- ✓ Diverse role coverage

### Malicious Cases
- ✓ All cases marked as `"MALICIOUS"`
- ✓ CWE/CVE references included
- ✓ Valid attack patterns
- ✓ Severity levels assigned
- ✓ Related to real vulnerabilities
- ✓ Threat intelligence references

## Integration with Blackwall

These datasets integrate with:

1. **Evaluation Pipeline** (`tests/eval/`)
   - Input for FPR/TPR calculation
   - Baseline for performance benchmarking

2. **Regression Suite** (`tests/features/blackwall_guardrails.feature`)
   - Validation that Blackwall allows benign ops
   - Validation that Blackwall blocks malicious ops

3. **Documentation** (`docs/`)
   - Example cases in threat modeling guides
   - Reference for security guardrails

4. **Metrics** (JUDGE_EVALUATION.md)
   - False Positive Rate (FPR) < 5%
   - False Negative Rate (FNR) / Evasion Rate < 10%
   - Detection accuracy > 95%

## References

- **Malicious Cases**: Based on OWASP Top 10, CWE/CVSS standards
- **Benign Cases**: Modeled on real ADK 2.0 usage patterns
- **Schema**: Aligned with Gemini API and GTI MCP specifications
- **Compliance**: Follows Blackwall's Zero-Trust safety architecture

## Contributing

To add new test cases:

1. Follow the schema defined above
2. Use semantic markers for all sensitive data
3. Include proper categorization
4. Add CWE references (for malicious cases)
5. Validate JSON before committing
6. Update the README with new statistics

## Security Notes

- All case data is **non-executable** - it's specification data only
- Sensitive values are **always replaced** with markers
- Cases reference **real CVEs** but don't contain working exploits
- Intended for **secure, sandboxed evaluation** only

## Last Updated

Generated: 2025-01-06  
Benign Cases: 68 cases  
Malicious Cases: 59 cases  
Evasion Cases: 30 cases  
Total Dataset Size: ~98 KB JSON
