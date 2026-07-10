---
name: spec-creator
description: Generates or updates technical specifications in a strict sequence (design.md to requirements.md to tasks.md) mimicking the Blackwall/Kiro spec pattern. Use this skill when the user asks to create a new project spec, draft architectural documents, or update an existing specification.
---

# Specification Creator (spec-creator)

This skill guides you through generating or updating technical specifications using a strict, three-document sequence, mirroring the structure used in the Blackwall Agentic Firewall (originally modeled after Kiro's specs).

## The Specification Sequence

You MUST generate or update the specifications in this exact sequence:
1. **`design.md`**: The architectural overview, components, and constraints.
2. **`requirements.md`**: Functional and Non-Functional Requirements (including TDD and BDD constraints) and User Stories, derived from the design.
3. **`tasks.md`**: The test-driven implementation plan, breaking down the requirements into actionable execution tracks.

## Formatting Guidelines

When drafting the specs (particularly `tasks.md`), adhere to the following best practices learned from the Blackwall development cycle:
- **Mirror the Kiro Structure**: Use clear headers, glossaries, and traceability metrics (e.g., tying tasks back to FR/NFR/US IDs).
- **Explicit Dependencies**: Clearly state dependencies under each individual task in `tasks.md` (i.e., which tasks must be completed before others).
- **Highlight Parallelism**: Be creative in highlighting tasks that can be completed in parallel. Use markdown features like GitHub alerts (`> [!TIP] PARALLEL EXECUTION`) or grouped "Tracks" to visually segment concurrent work from linear, sequential work.
- **TDD & BDD Rigor**: Explicitly incorporate Test-Driven Development (TDD) and Behavior-Driven Development (BDD) using Gherkin syntax as mandatory acceptance criteria.

## Cascading Update Rules

When invoked to review or edit an *existing* spec, you MUST follow these cascading rules:

- **If `design.md` is edited**: You MUST subsequently update `requirements.md` and `tasks.md` to reflect the architectural changes.
- **If `requirements.md` is edited**: You MUST subsequently update `tasks.md` to reflect the new constraints. You DO NOT need to update `design.md`.
- **If `tasks.md` is edited**: You DO NOT need to update `design.md` or `requirements.md`. They may remain as is.

Always update in a "design-first" direction (Design -> Requirements -> Tasks). Never edit `tasks.md` first if the change requires an architectural shift; start at `design.md` and let the changes cascade down.
