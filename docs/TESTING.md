# Testing

Tests are located in `tests/test_alert_rule_lint.py`. They exercise the public API and simulate various rule file scenarios.

## Coverage

- **Safety Checks**: Verifies rejection of anchors, aliases, large inputs, and deeply nested structures.
- **Policy Enforcement**: Verifies ALR001 through ALR009, asserting accurate identification of missing labels, invalid severities, bad durations, and unknown keys.
- **CLI Interaction**: Exercises the CLI entry point, confirming correct exit codes for successful linting, errors, and invalid I/O.
- **Edge Cases**: Validates behavior on empty files, invalid YAML, and multi-document YAML inputs.