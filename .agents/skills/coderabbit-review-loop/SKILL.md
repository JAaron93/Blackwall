---
name: coderabbit-review-loop
description: AI-driven local code review loop using CodeRabbit CLI. Trigger this skill when the user wants to execute a CodeRabbit review loop on local changes, analyze review suggestions, decide on fixes, modify code, and iterate up to 3 times.
---

# CodeRabbit CLI Local Review Loop

This skill guides the agent through running a local, iterative code review loop using the CodeRabbit CLI. It allows inspecting code suggestions, parsing recommendations, resolving valid issues, and verifying correctness in a repeating cycle of up to three iterations.

## Workflow Execution Steps

### 1. Identify Base Branch
Determine the base branch to compare against. 
- Default to the parent branch (e.g., `main` or the base tracking branch of the current worktree/feature branch).
- In Git, this can be resolved using:
  `git show-branch --merge-base` or checking the tracking configuration.

### 2. Execute CodeRabbit CLI
Run CodeRabbit review in plain text mode to output findings directly to the console:
```bash
/Users/pretermodernist/.local/bin/coderabbit review --plain --base <base-branch>
```
*Note: Always use `--plain` to prevent interactive CLI prompt blockages.*

### 3. Parse and Triage Suggestions
Review the command output and categorize each finding:
1. **Valid/High-Value Findings**: Security vulnerabilities, logic bugs, performance SLA bottlenecks, memory leaks, or non-compliance with the project specifications.
2. **Invalid/Low-Value Findings**: False positives, tool misunderstandings, or suggestions that conflict with established project requirements.

For each finding, output:
- **Finding**: Summary of the suggestion.
- **Verdict**: *Resolve* (with planned fix details) or *Skip* (with clear explanation of why it is invalid).

### 4. Establish a Reproduction
Before modifying code, run and record a failing focused test or reproduction command.

### 5. Apply Fixes
Modify the corresponding files using code edit tools to resolve the *Resolve* items. Ensure edits are minimal, targeted, and respect the project style.

### 6. Verify via Test Suite
Run the test suite and verify all BDD guardrail scenarios pass:
```bash
pytest -v tests/
```

### 7. Iterate
- If code changes were made and tests pass, loop back to **Step 2** to request another review.
- Repeat the review-fix-test cycle up to a maximum of **3 times**.
- If no new valid suggestions are found in a cycle, or the 3-loop limit is reached, terminate the loop.

### 8. Commit
Once the loop is completed and the test suite is green, stage the final changes and commit:
```bash
git add <modified-files>
git commit -m "refactor: address CodeRabbit review recommendations"
```
