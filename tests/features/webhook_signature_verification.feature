Feature: Webhook Signature Verification and Payload Processing Security
  As the Blackwall Agentic Firewall webhook listener
  I want to verify the integrity and authenticity of incoming webhook requests
  So that only legitimate, non-replayed, and structurally valid payloads are processed

  Background:
    Given the WebhookListener is initialized with a valid audience and mock dependencies

  Scenario: Valid webhook signature is accepted
    Given a valid JWT RS256 token is signed for interaction "interaction-abc-123"
    And the webhook-timestamp header is set to the current time
    And the webhook-id header is set to a unique value "webhook-id-001"
    And the JSON payload contains data.id "interaction-abc-123"
    When the webhook request is sent to the listener
    Then the response status code is 200

  Scenario: Invalid webhook signature is rejected
    Given a JWT token with a tampered signature is provided
    And the webhook-timestamp header is set to the current time
    And the webhook-id header is set to a unique value "webhook-id-002"
    And the JSON payload contains data.id "interaction-abc-123"
    When the webhook request is sent to the listener
    Then the response status code is 400

  Scenario: Missing signature header is rejected
    Given no Webhook-Signature header is present in the request
    And the webhook-timestamp header is set to the current time
    And the webhook-id header is set to a unique value "webhook-id-003"
    And the JSON payload contains data.id "interaction-abc-123"
    When the webhook request is sent to the listener
    Then the response status code is 400

  Scenario: Expired timestamp is rejected
    Given a valid JWT RS256 token is signed for interaction "interaction-abc-456"
    And the webhook-timestamp header is set to a timestamp 600 seconds in the past
    And the webhook-id header is set to a unique value "webhook-id-004"
    And the JSON payload contains data.id "interaction-abc-456"
    When the webhook request is sent to the listener
    Then the response status code is 400

  Scenario: Valid payload is processed successfully
    Given a valid JWT RS256 token is signed for interaction "interaction-process-001"
    And the webhook-timestamp header is set to the current time
    And the webhook-id header is set to a unique value "webhook-id-005"
    And the JSON payload contains data.id "interaction-process-001"
    And the mock gemini client returns a valid interaction for "interaction-process-001"
    When the webhook request is sent to the listener
    Then the response status code is 200
    And a background processing task is enqueued for interaction "interaction-process-001"

  Scenario: Malformed JSON payload is rejected
    Given a valid JWT RS256 token is signed for interaction "interaction-abc-789"
    And the webhook-timestamp header is set to the current time
    And the webhook-id header is set to a unique value "webhook-id-006"
    And the request body is not valid JSON
    When the webhook request is sent to the listener
    Then the response status code is 400

  Scenario: Replay attack is detected
    Given a valid JWT RS256 token is signed for interaction "interaction-replay-001"
    And the webhook-timestamp header is set to the current time
    And the webhook-id header is set to a unique value "webhook-id-007"
    And the JSON payload contains data.id "interaction-replay-001"
    And the webhook with id "webhook-id-007" has already been processed
    When the webhook request is sent to the listener
    Then the response status code is 200
    And no new processing task is enqueued for the duplicate request
