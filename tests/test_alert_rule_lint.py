"""Behavior tests for the public API of alert_rule_lint."""

from __future__ import annotations

import pytest

import alert_rule_lint


def test_normalize_trims_and_lowercases() -> None:
    assert alert_rule_lint.normalize("  Hello World ") == "hello world"


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_normalize_rejects_blank_input(value: str) -> None:
    with pytest.raises(ValueError, match="must not be empty"):
        alert_rule_lint.normalize(value)


def test_version_is_semver() -> None:
    parts = alert_rule_lint.__version__.split(".")
    assert len(parts) == 3
    assert all(part.isdigit() for part in parts)
