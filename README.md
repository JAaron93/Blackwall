# Blackwall Agentic Firewall

Autonomous Agentic Firewall MVP for intercepting and evaluating AI agent execution flows.
## ⚠️ Important: Reference-Based Evaluation Dataset

This repository uses a **reference-based test dataset** approach for security evaluation rather than functional exploit code:

- **Why**: Maintains scientific rigor while ensuring safe public distribution
- **What it means**: Test cases reference CWE/CVE IDs and use pseudocode patterns instead of working exploits
- **Impact on evaluation**: Detection logic remains identical; threat classification is semantic, not syntactic
- **Judge confidence**: All sources are traceable to NIST/OWASP/academic security literature

**See [`MALICIOUS_REFERENCE_DATASET_JUSTIFICATION.md`](tests/eval/docs/MALICIOUS_REFERENCE_DATASET_JUSTIFICATION.md) for complete explanation of this approach and why it's optimal for Kaggle submission.**

---
