Feature: Python Audit Hook Auto-Bootstrap
  As Blackwall Core running on macOS
  I want a global Python audit hook attached before user code executes
  So that rogue scripts cannot escape through raw OS or subprocess calls

  Scenario: Install injects a non-destructive bootstrap snippet
    Given a mock Python site-packages directory with existing sitecustomize logic
    When the user runs "blackwall hook install"
    Then the sitecustomize file contains the marked bootstrap and preserves the original logic

  Scenario: Uninstall restores sitecustomize byte-for-byte
    Given a mock Python site-packages directory with existing sitecustomize logic
    When the user uninstalls the audit hook bootstrap
    Then the sitecustomize file is byte-for-byte identical to the original

  Scenario: Clean subprocess blocks a malicious Popen attempt
    Given a bootstrapped Python environment in an isolated home
    When a clean Python subprocess attempts "subprocess.Popen"
    Then the attempt raises "PermissionError" before the OS executes it
