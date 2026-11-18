"""Tests for the shared env-coercion helpers."""

from __future__ import annotations

import pytest

from kag_common.env import _get_bool, _get_env, _get_float, _get_int


def test_get_env_default_and_override(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KC_X", raising=False)
    assert _get_env("KC_X", "fallback") == "fallback"
    monkeypatch.setenv("KC_X", "set")
    assert _get_env("KC_X", "fallback") == "set"


def test_get_int_parses_and_falls_back(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KC_N", raising=False)
    assert _get_int("KC_N", 7) == 7
    monkeypatch.setenv("KC_N", "42")
    assert _get_int("KC_N", 7) == 42
    monkeypatch.setenv("KC_N", "not-an-int")
    assert _get_int("KC_N", 7) == 7


def test_get_float_parses_and_falls_back(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KC_F", raising=False)
    assert _get_float("KC_F", 1.5) == 1.5
    monkeypatch.setenv("KC_F", "2.25")
    assert _get_float("KC_F", 1.5) == 2.25
    monkeypatch.setenv("KC_F", "nope")
    assert _get_float("KC_F", 1.5) == 1.5


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("1", True),
        ("true", True),
        ("YES", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("No", False),
        ("off", False),
    ],
)
def test_get_bool_recognized_values(monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool):
    monkeypatch.setenv("KC_B", raw)
    assert _get_bool("KC_B", not expected) is expected


def test_get_bool_default_and_unrecognized(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("KC_B", raising=False)
    assert _get_bool("KC_B", True) is True
    monkeypatch.setenv("KC_B", "maybe")
    assert _get_bool("KC_B", True) is True
