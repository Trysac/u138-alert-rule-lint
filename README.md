# alert-rule-lint

[![CI](https://github.com/Trysac/u138-alert-rule-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u138-alert-rule-lint/actions)

Lint Prometheus alerting and recording rule files for structural compliance and team-defined policies.

## Overview

Prometheus rule files often pass syntax checks via `promtool` but fail in production or page the wrong team due to missing labels, annotations, or misconfigured durations. `alert-rule-lint` enforces organization policies (required labels, annotations, naming, and key validation) without needing a Prometheus binary.

## Installation

```bash
pip install alert-rule-lint
```

## Usage

```python
from alert_rule_lint import lint_text

rules = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        labels: {severity: critical}
        annotations: {summary: High latency}
"""
findings = lint_text(rules)
print(f"Found {len(findings)} issues")
```

### CLI

```bash
python -m alert_rule_lint rules.yml
```

- Exit `0`: No error-level findings (warnings permitted).
- Exit `1`: Linting errors found.
- Exit `2`: Usage error, I/O error, or invalid YAML syntax.

## Why not promtool?

`promtool` only validates syntax (e.g., valid PromQL). `alert-rule-lint` validates team-specific policy: it ensures mandatory labels (like `severity`) and annotations (like `summary`) are present, enforces alert naming conventions, and detects unknown configuration keys.

## API Summary

- `lint_text(text: str, config: LintConfig = ..., max_bytes: int = 5242880) -> list[Finding]`
- `lint_file(path: str | Path, config: LintConfig = ...) -> list[Finding]`
- `LintConfig`: Configures `required_labels`, `severities`, `required_annotations`, and `alert_name_pattern`.
- `Finding`: Returned with `code`, `severity` ('error' | 'warning'), `path`, and `message`.

Safety limits: Max 5 MiB input size, 20-level max document depth. For more, see [docs/SECURITY.md](docs/SECURITY.md).