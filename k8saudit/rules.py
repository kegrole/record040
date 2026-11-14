"""File-driven rule model and generic rule evaluation engine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from . import yamlmini
from .workload import CONTAINER_SCOPES, _get_path

SUPPORTED_SCOPES = (
    "pod",
    "container",
    "init_container",
    "any_container",
    "capability",
    "volume",
)


class RuleError(ValueError):
    """Raised when a rule file is malformed."""


@dataclass
class Rule:
    rule_id: str
    description: str
    severity: str
    scope: str | list[str]
    path: str
    operator: str
    value: Any
    evidence: str

    @property
    def scopes(self) -> tuple[str, ...]:
        if isinstance(self.scope, list):
            return tuple(self.scope)
        return (self.scope,)


class _SafeDict(dict):
    """Dict whose missing keys render as an empty string in ``str.format``."""

    def __missing__(self, key: str) -> str:
        return ""


def load_rules(path: str) -> list[Rule]:
    with open(path, "r", encoding="utf-8") as handle:
        document = yamlmini.loads(handle.read())
    if not isinstance(document, dict) or not isinstance(
        document.get("rules"), list
    ):
        raise RuleError(f"{path}: expected a top-level 'rules' sequence")
    rules: list[Rule] = []
    for entry in document["rules"]:
        if not isinstance(entry, dict):
            raise RuleError(f"{path}: every rule must be a mapping")
        try:
            rule = Rule(
                rule_id=entry["rule"],
                description=entry.get("description", ""),
                severity=entry.get("severity", "medium"),
                scope=entry["scope"],
                path=entry["path"],
                operator=entry["operator"],
                value=entry.get("value"),
                evidence=entry["evidence"],
            )
        except KeyError as error:
            raise RuleError(
                f"{path}: rule is missing required field {error.args[0]!r}"
            ) from error
        unknown = [scope for scope in rule.scopes if scope not in SUPPORTED_SCOPES]
        if unknown:
            raise RuleError(
                f"{path}: rule {rule.rule_id!r} has unsupported scope {unknown!r}"
            )
        rules.append(rule)
    return rules


def _equals(actual: Any, expected: Any) -> bool:
    return actual == expected


def _not_equals(actual: Any, expected: Any) -> bool:
    return actual != expected


def _in(actual: Any, expected: Any) -> bool:
    return isinstance(expected, (list, tuple, set)) and actual in expected


def _not_in(actual: Any, expected: Any) -> bool:
    return isinstance(expected, (list, tuple, set)) and actual not in expected


def _contains(actual: Any, expected: Any) -> bool:
    try:
        return expected in actual
    except TypeError:
        return False


def _not_contains(actual: Any, expected: Any) -> bool:
    try:
        return expected not in actual
    except TypeError:
        return True


OPERATORS = {
    "equals": _equals,
    "not_equals": _not_equals,
    "in": _in,
    "not_in": _not_in,
    "contains": _contains,
    "not_contains": _not_contains,
}


def _applies(rule: Rule, target_scope: str) -> bool:
    for scope in rule.scopes:
        if scope == "any_container" and target_scope in CONTAINER_SCOPES:
            return True
        if scope == target_scope:
            return True
    return False


def _flatten(prefix: str, value: Any, sink: dict) -> None:
    if isinstance(value, dict):
        for key, nested in value.items():
            if key == "_context":
                continue
            next_prefix = f"{prefix}_{key}" if prefix else str(key)
            sink[next_prefix] = nested
            _flatten(next_prefix, nested, sink)


def _format_evidence(template: str, target: dict) -> str:
    context = target.get("_context") or {}
    fields = _SafeDict(target)
    _flatten("", target, fields)
    for key, value in context.items():
        fields.setdefault(key, value)
        fields.setdefault(f"context_{key}", value)
    try:
        return template.format_map(fields)
    except (IndexError, AttributeError, ValueError):
        return template


def evaluate(rule: Rule, target: dict) -> dict | None:
    """Return a finding when *rule* matches *target*, otherwise ``None``."""
    context = target.get("_context") or {}
    target_scope = context.get("scope", "pod")
    if not _applies(rule, target_scope):
        return None
    operator = OPERATORS.get(rule.operator)
    if operator is None:
        raise RuleError(
            f"rule {rule.rule_id!r} uses unsupported operator {rule.operator!r}"
        )
    actual = _get_path(target, rule.path)
    if not operator(actual, rule.value):
        return None
    return {
        "rule": rule.rule_id,
        "severity": rule.severity,
        "evidence": _format_evidence(rule.evidence, target),
    }


def evaluate_targets(rules: list[Rule], targets: list[dict]) -> list[dict]:
    findings: list[dict] = []
    for target in targets:
        for rule in rules:
            finding = evaluate(rule, target)
            if finding is not None:
                findings.append(finding)
    return findings
