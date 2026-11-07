"""CLI entrypoint for alert_rule_lint."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from alert_rule_lint import LintConfig, LintError, lint_file


def main(argv: list[str] | None = None) -> int:
    """CLI main function."""
    parser = argparse.ArgumentParser(
        prog="alert-rule-lint",
        description="Lint Prometheus alerting rule files for structure and team policy.",
    )
    parser.add_argument(
        "files",
        nargs="+",
        help="Rule YAML files to lint",
    )

    try:
        args = parser.parse_args(argv if argv is not None else sys.argv[1:])
    except SystemExit as exc:
        # argparse uses 2 for argument errors or 0 for --help
        return int(exc.code) if isinstance(exc.code, int) else 2

    config = LintConfig()
    has_errors = False

    for file_str in args.files:
        p = Path(file_str)
        try:
            findings = lint_file(p, config=config)
        except LintError as err:
            sys.stderr.write(f"{file_str}: error: {err}\n")
            return 2
        except Exception as exc:
            sys.stderr.write(f"{file_str}: error: {exc}\n")
            return 2

        for f in findings:
            print(f"{file_str}:{f.path}: {f.code} {f.severity} {f.message}")
            if f.severity == "error":
                has_errors = True

    return 1 if has_errors else 0


if __name__ == "__main__":
    sys.exit(main())
