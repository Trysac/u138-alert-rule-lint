# alert-rule-lint

[![PyPI version](https://img.shields.io/pypi/v/trysac-alert-rule-lint)](https://pypi.org/project/trysac-alert-rule-lint/)
[![License: MIT](https://img.shields.io/pypi/l/trysac-alert-rule-lint)](LICENSE)
[![CI](https://github.com/Trysac/u138-alert-rule-lint/actions/workflows/ci.yml/badge.svg)](https://github.com/Trysac/u138-alert-rule-lint/actions/workflows/ci.yml)

Lint Prometheus alerting rule files for structure and team policy: required labels and annotations, severity values, durations, unknown keys and naming

## Problem

Describe in two or three sentences the concrete problem this utility solves, who hits it, and what
they do today without it. Replace this paragraph when the first real feature lands.

## Install

```sh
pip install trysac-alert-rule-lint
# or
uv add trysac-alert-rule-lint
```

Requires Python 3.10 or newer. No runtime dependencies.

## Usage

```python
import alert_rule_lint

# normalize() trims surrounding whitespace and lower-cases the text.
print(alert_rule_lint.normalize("  Hello World "))  # -> "hello world"

# Blank input is rejected explicitly instead of returning an empty string.
try:
    alert_rule_lint.normalize("   ")
except ValueError as exc:
    print(f"rejected: {exc}")
```

## Documentation

- [Architecture](docs/ARCHITECTURE.md) and [decisions](docs/decisions/)
- [Testing](docs/TESTING.md) and [security](docs/SECURITY.md)
- [Project record](docs/PROJECT.md) and [stack](docs/STACK.md)
- [Changelog](CHANGELOG.md) and [contributing guide](CONTRIBUTING.md)

## License

[MIT](LICENSE) (c) 2026 Miguel Gomez
