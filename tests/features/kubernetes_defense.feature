Feature: Kubernetes Defense Layer
  As a Kubernetes security operator
  I want to detect Kubernetes-specific threats
  So that pod token theft, fleet spawning, secrets exfiltration, and self-respawning pod patterns are detected and recorded in K8sThreatEvidence

  Scenario: file access to /var/run/secrets/kubernetes.io/serviceaccount/token triggers pod token theft detection
    Given an agent "agent-k8s-bdd-1" performing file access to "/var/run/secrets/kubernetes.io/serviceaccount/token"
    When the Kubernetes defense layer runs pod token theft detection for "agent-k8s-bdd-1"
    Then pod token theft evidence should be generated with threat_type "pod_token_theft"

  Scenario: 10 pods created across 5 nodes in 60 seconds is detected as fleet spawning
    Given 10 pods created across 5 nodes in 60 seconds by agent "spawner-bdd-agent"
    When the Kubernetes defense layer runs fleet spawning detection
    Then fleet spawning evidence should be generated with threat_type "fleet_spawning"

  Scenario: bulk reads of Kubernetes secrets via the API are flagged as secrets exfiltration
    Given an agent "exfil-bdd-agent" reading 6 Kubernetes secrets via the API with 3 successful and 3 failed requests
    When the Kubernetes defense layer runs secrets exfiltration detection for "exfil-bdd-agent"
    Then secrets exfiltration evidence should be generated with threat_type "secrets_exfiltration"

  Scenario: a pod that recreates after termination is detected as self-respawning
    Given a pod "resilient-app-pod" terminated and recreated 3 times by agent "respawn-bdd-agent"
    When the Kubernetes defense layer runs self-respawning pod detection
    Then self-respawning pod evidence should be generated with threat_type "self_respawning_pod"

  Scenario: K8sThreatEvidence includes threat_type, namespace, pod_name, and service_account
    Given a detected Kubernetes threat evidence object for namespace "prod", pod "worker-1", service account "app-sa", and threat type "pod_token_theft"
    When inspecting the K8sThreatEvidence model
    Then it should contain non-empty threat_type, namespace, pod_name, and service_account
