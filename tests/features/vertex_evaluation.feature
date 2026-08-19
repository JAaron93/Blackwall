@vertex_evaluation @advanced_threat_detection
Feature: GCP Vertex AI Gen AI Evaluation Engine and Telemetry
  As a security engineer
  I want to evaluate threat detection accuracy, agent trajectories, and latency SLAs
  So that Blackwall operates with high precision and zero SaaS exfiltration

  Scenario: Vertex AI initializes successfully via Application Default Credentials
    Given a configured GCP Vertex AI environment
    When the evaluation harness is instantiated
    Then the evaluation harness is initialized with valid project and location

  Scenario: Evaluation run executes EvalTask with Pointwise and Pairwise metrics
    Given a dataset containing adversarial prompt injection samples
    When the evaluation harness runs an EvalTask with threat accuracy autoraters
    Then the evaluation run completes and aggregates precision and recall metrics

  Scenario: Telemetry spans are exported to Google Cloud Trace
    Given an active GCP Cloud Trace exporter
    When an evaluation span is recorded with GenAI semantic conventions
    Then the span is captured with standard OpenTelemetry attributes and latency duration

  Scenario: Agent trajectory evaluation validates tool call sequence
    Given a reference tool execution trajectory and a candidate agent trajectory
    When the evaluation harness assesses trajectory precision and recall
    Then the trajectory evaluation computes correct step precision and in-order match
