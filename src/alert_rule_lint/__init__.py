"""alert_rule_lint: Prometheus alert and recording rule linter."""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml  # type: ignore[import-untyped]
from yaml.tokens import AliasToken, AnchorToken  # type: ignore[import-untyped]

__all__ = [
    "Finding",
    "LintConfig",
    "LintError",
    "lint_file",
    "lint_text",
]

__version__ = "0.1.0"

logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

ErrorCode = Literal[
    "input_too_large",
    "aliases_not_allowed",
    "invalid_document",
    "invalid_yaml",
    "too_deep",
]
FindingSeverity = Literal["error", "warning"]

DEFAULT_MAX_BYTES: int = 5_242_880  # 5 MiB
MAX_DOC_DEPTH: int = 20


class LintError(Exception):
    """Base exception raised when rule file content or structure cannot be processed."""

    def __init__(self, code: ErrorCode, message: str) -> None:
        super().__init__(message)
        self.code: ErrorCode = code
        self.message: str = message

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class LintConfig:
    """Configuration options for alerting rule linting rules."""

    required_labels: tuple[str, ...] = ("severity",)
    severities: tuple[str, ...] = ("critical", "warning", "info")
    required_annotations: tuple[str, ...] = ("summary",)
    alert_name_pattern: str = "^[A-Z][A-Za-z0-9]*$"


@dataclass(frozen=True)
class Finding:
    """Represents a lint rule finding."""

    code: str
    severity: FindingSeverity
    path: str
    message: str


def _truncate_msg(raw: str) -> str:
    return raw[:200]


def _validate_depth(data: Any, max_depth: int = MAX_DOC_DEPTH) -> None:
    """Iteratively check that nesting depth does not exceed max_depth."""
    # Stack holds (current_object, current_depth)
    stack: list[tuple[Any, int]] = [(data, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            raise LintError(
                "too_deep", f"Document depth exceeds maximum allowed depth of {max_depth}"
            )
        if isinstance(current, dict):
            for val in current.values():
                if isinstance(val, (dict, list)):
                    stack.append((val, depth + 1))
        elif isinstance(current, list):
            for item in current:
                if isinstance(item, (dict, list)):
                    stack.append((item, depth + 1))


_DURATION_RE = re.compile(
    r"^(?:(?:[0-9]+y)?(?:[0-9]+w)?(?:[0-9]+d)?(?:[0-9]+h)?"
    r"(?:[0-9]+m)?(?:[0-9]+s)?(?:[0-9]+ms)?|0)$"
)


def _is_valid_duration(val: Any) -> bool:
    if not isinstance(val, str):
        return False
    if not val:
        return False
    if val == "0":
        return True
    m = _DURATION_RE.match(val)
    if not m:
        return False
    # Ensure it's not empty match
    return len(m.group(0)) > 0


ALLOWED_RULE_KEYS = frozenset(
    {"alert", "record", "expr", "for", "keep_firing_for", "labels", "annotations"}
)


def lint_text(
    text: str, *, config: LintConfig | None = None, max_bytes: int = DEFAULT_MAX_BYTES
) -> list[Finding]:
    """Lint Prometheus alerting and recording rules YAML text."""
    cfg = config if config is not None else LintConfig()

    text_bytes = text.encode("utf-8")
    if len(text_bytes) > max_bytes:
        raise LintError(
            "input_too_large",
            f"Input size ({len(text_bytes)} bytes) exceeds limit of {max_bytes} bytes",
        )

    # Check for empty / whitespace only
    if not text.strip():
        raise LintError("invalid_document", "YAML document is empty")

    # Token scan to reject anchors and aliases and catch syntax errors safely
    try:
        for token in yaml.scan(text, Loader=yaml.SafeLoader):
            if isinstance(token, (AnchorToken, AliasToken)):
                raise LintError(
                    "aliases_not_allowed",
                    "YAML anchors and aliases are not permitted",
                )
    except LintError:
        raise
    except Exception as exc:
        raise LintError("invalid_yaml", _truncate_msg(f"YAML parsing error: {exc}")) from exc

    # Check multi-document
    try:
        docs = list(yaml.safe_load_all(text))
    except Exception as exc:
        raise LintError("invalid_yaml", _truncate_msg(f"YAML parsing error: {exc}")) from exc

    if len(docs) > 1:
        raise LintError("invalid_document", "Multi-document YAML is not supported")
    if not docs or docs[0] is None:
        raise LintError("invalid_document", "YAML document is empty")

    data = docs[0]
    if not isinstance(data, dict):
        raise LintError("invalid_document", "Top level YAML must be a mapping")

    _validate_depth(data, MAX_DOC_DEPTH)

    if "groups" not in data or not isinstance(data["groups"], list):
        raise LintError("invalid_document", "Top level mapping must contain a 'groups' list")

    findings: list[Finding] = []
    groups = data["groups"]
    seen_groups: set[str] = set()
    compiled_alert_pattern = re.compile(cfg.alert_name_pattern)

    for group_idx, group in enumerate(groups):
        group_path = f"groups[{group_idx}]"
        if not isinstance(group, dict):
            continue

        # ALR001: group name missing, not a string, or duplicate
        group_name = group.get("name")
        if not isinstance(group_name, str) or not group_name:
            findings.append(
                Finding(
                    code="ALR001",
                    severity="error",
                    path=group_path,
                    message="group name is missing, empty, or not a string",
                )
            )
        elif group_name in seen_groups:
            findings.append(
                Finding(
                    code="ALR001",
                    severity="error",
                    path=group_path,
                    message=f"duplicate group name '{group_name}'",
                )
            )
        else:
            seen_groups.add(group_name)

        # ALR007 on group interval
        if "interval" in group:
            interval_val = group["interval"]
            if not _is_valid_duration(str(interval_val)):
                findings.append(
                    Finding(
                        code="ALR007",
                        severity="error",
                        path=group_path,
                        message=f"invalid duration '{interval_val}'",
                    )
                )

        rules = group.get("rules")
        if rules is None:
            continue
        if not isinstance(rules, list):
            continue

        for rule_idx, rule in enumerate(rules):
            rule_path = f"{group_path}.rules[{rule_idx}]"
            if not isinstance(rule, dict):
                continue

            # ALR009: unknown key in rule
            # We sort unknown keys for deterministic finding order
            for key in sorted(rule.keys()):
                if key not in ALLOWED_RULE_KEYS:
                    findings.append(
                        Finding(
                            code="ALR009",
                            severity="error",
                            path=rule_path,
                            message=f"unknown key '{key}'",
                        )
                    )

            # ALR003: exactly one of alert and record required
            has_alert = "alert" in rule and rule["alert"] is not None
            has_record = "record" in rule and rule["record"] is not None
            if (has_alert and has_record) or (not has_alert and not has_record):
                findings.append(
                    Finding(
                        code="ALR003",
                        severity="error",
                        path=rule_path,
                        message="rule must have exactly one of 'alert' or 'record'",
                    )
                )

            # ALR002: expr missing or empty
            expr = rule.get("expr")
            if expr is None or (isinstance(expr, str) and not expr.strip()) or not expr:
                findings.append(
                    Finding(
                        code="ALR002",
                        severity="error",
                        path=rule_path,
                        message="expr is missing or empty",
                    )
                )

            # ALR007: duration checks on for and keep_firing_for
            if "for" in rule:
                for_val = rule["for"]
                if not _is_valid_duration(str(for_val)):
                    findings.append(
                        Finding(
                            code="ALR007",
                            severity="error",
                            path=rule_path,
                            message=f"invalid duration '{for_val}'",
                        )
                    )

            if "keep_firing_for" in rule:
                kff_val = rule["keep_firing_for"]
                if not _is_valid_duration(str(kff_val)):
                    findings.append(
                        Finding(
                            code="ALR007",
                            severity="error",
                            path=rule_path,
                            message=f"invalid duration '{kff_val}'",
                        )
                    )

            # Alert-rule specific checks
            if has_alert:
                alert_name = str(rule.get("alert"))

                # ALR008: alert name pattern
                if not compiled_alert_pattern.match(alert_name):
                    findings.append(
                        Finding(
                            code="ALR008",
                            severity="warning",
                            path=rule_path,
                            message=(
                                f"alert name '{alert_name}' does not match "
                                f"pattern '{cfg.alert_name_pattern}'"
                            ),
                        )
                    )

                # Labels checks
                labels = rule.get("labels")
                labels_dict = labels if isinstance(labels, dict) else {}

                # ALR004: missing required label
                for req_lbl in cfg.required_labels:
                    if req_lbl not in labels_dict:
                        findings.append(
                            Finding(
                                code="ALR004",
                                severity="error",
                                path=rule_path,
                                message=f"missing label {req_lbl}",
                            )
                        )

                # ALR005: severity label value not in severities
                if "severity" in labels_dict:
                    sev_val = str(labels_dict["severity"])
                    if sev_val not in cfg.severities:
                        valid_sevs = ", ".join(cfg.severities)
                        findings.append(
                            Finding(
                                code="ALR005",
                                severity="error",
                                path=rule_path,
                                message=f"severity '{sev_val}' not in {valid_sevs}",
                            )
                        )

                # Annotations checks
                annotations = rule.get("annotations")
                annotations_dict = annotations if isinstance(annotations, dict) else {}

                # ALR006: missing required annotation
                for req_ann in cfg.required_annotations:
                    if req_ann not in annotations_dict:
                        findings.append(
                            Finding(
                                code="ALR006",
                                severity="warning",
                                path=rule_path,
                                message=f"missing annotation {req_ann}",
                            )
                        )

    # Order: findings sorted by path in document order (we walked in doc order),
    # then code. To ensure consistent stable sorting:
    # Key: group index, rule index (if any), then code.
    def sort_key(f: Finding) -> tuple[int, int, str]:
        # Path is either 'groups[i]' or 'groups[i].rules[j]'
        m = re.match(r"^groups\[(\d+)\](?:\.rules\[(\d+)\])?", f.path)
        if m:
            g_idx = int(m.group(1))
            r_idx = int(m.group(2)) if m.group(2) is not None else -1
            return (g_idx, r_idx, f.code)
        return (0, 0, f.code)

    findings.sort(key=sort_key)
    return findings


def lint_file(
    path: str | Path, *, config: LintConfig | None = None, max_bytes: int = DEFAULT_MAX_BYTES
) -> list[Finding]:
    """Lint a Prometheus alerting rule file."""
    p = Path(path)
    try:
        content = p.read_text(encoding="utf-8")
    except Exception as exc:
        raise LintError("invalid_document", f"Cannot read file {p}: {exc}") from exc
    return lint_text(content, config=config, max_bytes=max_bytes)
