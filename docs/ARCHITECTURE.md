# Architecture

`alert-rule-lint` is a lightweight policy linter for Prometheus rules.

## Components

1. **Pre-processor**: Enforces input size limits and performs an `AnchorToken`/`AliasToken` scan.
2. **YAML Parser**: Uses `yaml.safe_load_all` to build a document representation, failing on multi-document files.
3. **Validator**: Traverses the document iteratively, ensuring the tree depth <= 20.
4. **Rule Engine**: Validates every group and rule against the defined policies:
    - `ALR001`: Validates group names.
    - `ALR002`: Validates rule `expr`.
    - `ALR003`: Validates rule type (alert/record).
    - `ALR004-006`: Validates labels, severity values, and annotations.
    - `ALR007`: Validates durations.
    - `ALR008`: Validates alert names.
    - `ALR009`: Validates rule keys.
5. **Post-processor**: Sorts findings by path (`groups[i].rules[j]`) and error code.