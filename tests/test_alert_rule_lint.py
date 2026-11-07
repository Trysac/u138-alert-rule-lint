"""Tests for alert_rule_lint."""

from __future__ import annotations

from pathlib import Path

import pytest

from alert_rule_lint import (
    Finding,
    LintConfig,
    LintError,
    lint_file,
    lint_text,
)
from alert_rule_lint.__main__ import main


def test_acceptance_missing_labels_and_severity() -> None:
    """Alert rule without labels yields ALR004, and invalid severity yields ALR005."""
    raw_no_labels = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        annotations:
          summary: High latency observed
"""
    findings = lint_text(raw_no_labels)
    assert any(
        f
        == Finding(
            code="ALR004",
            severity="error",
            path="groups[0].rules[0]",
            message="missing label severity",
        )
        for f in findings
    )

    raw_page_sev = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        labels:
          severity: page
        annotations:
          summary: High latency observed
"""
    findings2 = lint_text(raw_page_sev)
    assert any(
        f.code == "ALR005" and f.message == "severity 'page' not in critical, warning, info"
        for f in findings2
    )


def test_acceptance_durations() -> None:
    """Durations: invalid yields ALR007, valid durations pass."""
    invalid_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        for: 5x
        labels:
          severity: critical
        annotations:
          summary: High latency observed
"""
    findings = lint_text(invalid_raw)
    assert any(f.code == "ALR007" and f.message == "invalid duration '5x'" for f in findings)

    for valid_dur in ["1h30m", "90s", "0", "500ms"]:
        valid_raw = f"""
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        for: '{valid_dur}'
        labels:
          severity: critical
        annotations:
          summary: High latency observed
"""
        dur_findings = [f for f in lint_text(valid_raw) if f.code == "ALR007"]
        assert len(dur_findings) == 0, f"Failed for valid duration: {valid_dur}"


def test_acceptance_rule_structure_and_keys() -> None:
    """Check rule structure, both/neither alert and record (ALR003), unknown keys and expr."""
    both_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        record: job:metric:rate
        expr: latency > 10
"""
    findings = lint_text(both_raw)
    assert any(f.code == "ALR003" for f in findings)

    neither_raw = """
groups:
  - name: test
    rules:
      - expr: latency > 10
"""
    findings2 = lint_text(neither_raw)
    assert any(f.code == "ALR003" for f in findings2)

    unknown_key_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        labelz: foo
        labels:
          severity: critical
        annotations:
          summary: ok
"""
    findings3 = lint_text(unknown_key_raw)
    assert any(f.code == "ALR009" and f.message == "unknown key 'labelz'" for f in findings3)

    missing_expr_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        labels:
          severity: critical
        annotations:
          summary: ok
"""
    findings4 = lint_text(missing_expr_raw)
    assert any(f.code == "ALR002" for f in findings4)

    empty_expr_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: "   "
        labels:
          severity: critical
        annotations:
          summary: ok
"""
    findings5 = lint_text(empty_expr_raw)
    assert any(f.code == "ALR002" for f in findings5)


def test_acceptance_group_and_naming_and_annotation() -> None:
    """Duplicate groups yield ALR001, alert naming yields ALR008, missing summary yields ALR006."""
    dup_groups_raw = """
groups:
  - name: api
    rules: []
  - name: api
    rules: []
"""
    findings = lint_text(dup_groups_raw)
    assert any(f.code == "ALR001" and f.path == "groups[1]" for f in findings)

    naming_raw = """
groups:
  - name: test
    rules:
      - alert: high_latency
        expr: latency > 10
        labels:
          severity: critical
        annotations:
          summary: High latency
"""
    findings2 = lint_text(naming_raw)
    assert any(f.code == "ALR008" and f.severity == "warning" for f in findings2)

    valid_name_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        labels:
          severity: critical
        annotations:
          summary: High latency
"""
    findings3 = [f for f in lint_text(valid_name_raw) if f.code == "ALR008"]
    assert len(findings3) == 0

    missing_summary_raw = """
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        labels:
          severity: critical
"""
    findings4 = lint_text(missing_summary_raw)
    assert any(f.code == "ALR006" and f.severity == "warning" for f in findings4)


def test_acceptance_safety_and_limits() -> None:
    """Safety checks: reject aliases, limit input size, require groups list."""
    with pytest.raises(LintError) as exc1:
        lint_text("groups:\n  - name: &a api\n  - name: *a")
    assert exc1.value.code == "aliases_not_allowed"

    huge_text = "x" * 5_242_881
    with pytest.raises(LintError) as exc2:
        lint_text(huge_text)
    assert exc2.value.code == "input_too_large"

    with pytest.raises(LintError) as exc3:
        lint_text("foo: bar")
    assert exc3.value.code == "invalid_document"


def test_acceptance_main_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """CLI prints finding, returns 1 for errors, 0 for warnings only, 2 for IO/YAML errors."""
    rule_file = tmp_path / "rules.yml"
    rule_file.write_text("""
groups:
  - name: test
    rules:
      - alert: HighLatency
        expr: latency > 10
        annotations:
          summary: Latency alert
""")

    exit_code = main([str(rule_file)])
    captured = capsys.readouterr()
    assert exit_code == 1
    assert f"{rule_file}:groups[0].rules[0]: ALR004 error missing label severity" in captured.out
    assert "rules.yml:groups[0].rules[0]: ALR004 error missing label severity" in captured.out

    # Only warnings -> exit code 0
    warn_file = tmp_path / "warn.yml"
    warn_file.write_text("""
groups:
  - name: test
    rules:
      - alert: highLatency
        expr: latency > 10
        labels:
          severity: critical
""")
    exit_code_warn = main([str(warn_file)])
    assert exit_code_warn == 0

    # Unreadable file -> exit code 2
    exit_code_io = main([str(tmp_path / "non_existent.yml")])
    assert exit_code_io == 2

    # Invalid YAML -> exit code 2
    bad_yaml_file = tmp_path / "bad.yml"
    bad_yaml_file.write_text("groups: [ { unclosed: ")
    exit_code_bad_yaml = main([str(bad_yaml_file)])
    assert exit_code_bad_yaml == 2


def test_edge_cases_and_coverage(tmp_path: Path) -> None:
    """Edge cases: empty file, multi-doc, depth limit, immutable dataclasses, interval, numbers."""
    with pytest.raises(LintError) as exc_empty:
        lint_text("   \n  ")
    assert exc_empty.value.code == "invalid_document"

    with pytest.raises(LintError) as exc_multidoc:
        lint_text("groups: []\n---\ngroups: []")
    assert exc_multidoc.value.code == "invalid_document"

    with pytest.raises(LintError) as exc_scalar:
        lint_text("hello world")
    assert exc_scalar.value.code == "invalid_document"

    # Group interval duration and keep_firing_for duration
    dur_check_yaml = """
groups:
  - name: test
    interval: bad_interval
    rules:
      - alert: TestAlert
        expr: up == 0
        keep_firing_for: 10bad
        labels:
          severity: 123
        annotations:
          summary: Some summary
"""
    findings = lint_text(dur_check_yaml)
    assert any(f.code == "ALR007" and f.path == "groups[0]" for f in findings)
    assert any(f.code == "ALR007" and f.path == "groups[0].rules[0]" for f in findings)
    assert any(f.code == "ALR005" and "123" in f.message for f in findings)

    # Missing group name or not string
    bad_group_yaml = """
groups:
  - interval: 10s
    rules: []
  - name: 12345
    rules: []
"""
    findings_grp = lint_text(bad_group_yaml)
    assert any(f.code == "ALR001" and f.path == "groups[0]" for f in findings_grp)
    assert any(f.code == "ALR001" and f.path == "groups[1]" for f in findings_grp)

    # Depth check
    nested: dict = {"groups": []}
    curr = nested
    for _ in range(25):
        curr["child"] = {}
        curr = curr["child"]
    import yaml

    deep_yaml = yaml.dump(nested)
    with pytest.raises(LintError) as exc_deep:
        lint_text(deep_yaml)
    assert exc_deep.value.code == "too_deep"

    # Recording rule pass check without alert labels
    rec_yaml = """
groups:
  - name: recording
    rules:
      - record: job:metric:rate5m
        expr: rate(metric[5m])
"""
    rec_findings = lint_text(rec_yaml)
    assert len(rec_findings) == 0

    # lint_file valid test
    good_file = tmp_path / "good.yml"
    good_file.write_text(rec_yaml)
    assert len(lint_file(good_file)) == 0

    # Immutability and representation
    cfg = LintConfig()
    assert repr(cfg).startswith("LintConfig(")
    assert cfg == LintConfig()
    assert cfg != "not a config"
    with pytest.raises(AttributeError):
        cfg.severities = ("warn",)  # type: ignore[misc]

    finding = Finding(code="ALR001", severity="error", path="groups[0]", message="msg")
    assert repr(finding).startswith("Finding(")
    assert finding == Finding(code="ALR001", severity="error", path="groups[0]", message="msg")
    assert finding != "different"
    with pytest.raises(AttributeError):
        finding.code = "ALR002"  # type: ignore[misc]

    err = LintError("input_too_large", "too large")
    assert str(err) == "too large"
