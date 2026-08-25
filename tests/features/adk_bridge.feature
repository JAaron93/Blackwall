Feature: ADK to EvalTask Dataset Bridge
  As an evaluation pipeline engineer
  I want to bridge ADK evalset cases to judge-consumable scenario schemas
  So that existing test datasets can be evaluated by autonomous judge agents

  Scenario: Benign ADK case transforms to judge scenario with ground_truth_verdict ALLOW
    Given a benign ADK eval case with ID "benign_db_001" and tool "database_query"
    When the ADK case is transformed by the bridge
    Then the judge scenario ID should be "benign_db_001"
    And the ground_truth_verdict should be "ALLOW"
    And the ground_truth_label should be "BENIGN"

  Scenario: Malicious ADK case transforms with ground_truth_label MALICIOUS and reference trajectory
    Given a malicious ADK eval case with ID "malicious_rce_001" and attack type "REMOTE_CODE_EXECUTION"
    When the ADK case is transformed by the bridge
    Then the judge scenario ID should be "malicious_rce_001"
    And the ground_truth_verdict should be "BLOCK"
    And the ground_truth_label should be "MALICIOUS"
    And the reference_trajectory should contain "before_tool_callback"

  Scenario: Evasion ADK case preserves evasion_type and parent_case_id in metadata
    Given an evasion ADK eval case with ID "evasion_sql_001", parent "malicious_sql_001", and evasion type "HEX_ENCODING"
    When the ADK case is transformed by the bridge
    Then the judge scenario ID should be "evasion_sql_001"
    And the metadata field "evasion_type" should equal "HEX_ENCODING"
    And the metadata field "parent_case_id" should equal "malicious_sql_001"
