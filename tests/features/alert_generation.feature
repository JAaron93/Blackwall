Feature: Real-Time Alert Generation and AlertBus Integration
  As a security operations center analyst
  I want real-time alerts generated and published to the AlertBus across all detection engines
  So that malicious attacks, rogue swarms, exploit chains, and lateral movement are escalated immediately

  Scenario: detected swarm publishes a CRITICAL alert to the AlertBus
    Given a detected agent swarm with agents "agent-swarm-1,agent-swarm-2" and coordination_score 0.92
    When the AlertBus generates and publishes an alert for the swarm
    Then a published alert with severity "CRITICAL" and threat_type "swarm_detection" should be received

  Scenario: AILM evidence with HIGH risk_level publishes a HIGH severity alert
    Given an AILM evidence for agent "agent-ailm-1" with risk_level "HIGH"
    When the AlertBus generates and publishes an alert for the AILM evidence
    Then a published alert with severity "HIGH" and threat_type "ailm" should be received

  Scenario: exploit chain with novelty_score 0.9 publishes a CRITICAL alert
    Given an exploit chain evidence with novelty_score 0.90
    When the AlertBus generates and publishes an alert for the exploit chain
    Then a published alert with severity "CRITICAL" and threat_type "exploit_chain" should be received

  Scenario: detected C2 infrastructure publishes a CRITICAL alert
    Given a C2 evidence for agent "agent-c2-1" with endpoint "https://pastebin.com/raw/malicious"
    When the AlertBus generates and publishes an alert for the C2 evidence
    Then a published alert with severity "CRITICAL" and threat_type "c2_infrastructure" should be received

  Scenario: alert delivery failure retries up to 5 times before logging a persistent failure
    Given an AlertBus configured with 5 max retries and a subscriber that always fails
    When a threat alert is published to the AlertBus
    Then the delivery should be attempted 5 times and recorded as a persistent failure

  Scenario: correlated attack path with high risk publishes a CRITICAL alert
    Given a correlated attack path for agent "agent-path-1" with risk_score 0.88
    When the AlertBus generates and publishes an alert for the attack path
    Then a published alert with severity "CRITICAL" and threat_type "attack_path" should be received

  Scenario: Kubernetes pod token theft publishes a CRITICAL alert
    Given a Kubernetes threat evidence with threat_type "pod_token_theft" in namespace "kube-system"
    When the AlertBus generates and publishes an alert for the Kubernetes threat
    Then a published alert with severity "CRITICAL" and threat_type "k8s_pod_token_theft" should be received

  Scenario: package registry threat with high confidence publishes a CRITICAL alert
    Given a package registry threat evidence for "npm" package "express-malicious" with exploit confidence 0.85
    When the AlertBus generates and publishes an alert for the registry threat
    Then a published alert with severity "CRITICAL" and threat_type "package_registry" should be received
