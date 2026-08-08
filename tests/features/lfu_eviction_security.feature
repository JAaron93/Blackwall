Feature: LFU Eviction Security and Batch Deletion Validation
  As a Threat Graph Administrator
  I want LFU batch eviction to execute parameterized single-query deletions per chunk
  So that low-frequency signatures are safely evicted while high-value signatures remain protected

  Scenario: LFU batch eviction evicts low-count signatures while preserving high-value signatures
    Given a threat repository populated with 120 low-value signatures and 10 high-value signatures
    When LFU eviction is executed with a max signature limit of 100
    Then 30 low-value signatures are evicted in batch
    And all 10 high-value signatures remain intact in the database
    And single-query parameterized batch deletion is executed without per-row executemany calls
