"""Run rules against workloads and build JSON-serializable audit reports."""

from __future__ import annotations

import json
from collections import Counter
from typing import Any

from .manifest import Workload
from .rules import Rule, evaluate_targets
from .workload import build_targets


def audit_workload(workload: Workload, rules: list[Rule]) -> dict:
    findings = evaluate_targets(rules, build_targets(workload))
    return {
        "workload": workload.name,
        "kind": workload.kind,
        "namespace": workload.namespace,
        "findings": findings,
    }


def build_report(workloads: list[Workload], rules: list[Rule]) -> dict[str, Any]:
    entries = [audit_workload(workload, rules) for workload in workloads]
    distribution: Counter[str] = Counter()
    total_findings = 0
    for entry in entries:
        for finding in entry["findings"]:
            distribution[finding["rule"]] += 1
            total_findings += 1

    # Preserve rule-file order for the hit distribution, then any unexpected ids.
    ordered_distribution = {
        rule.rule_id: distribution[rule.rule_id]
        for rule in rules
        if distribution[rule.rule_id]
    }
    for rule_id, count in distribution.items():
        ordered_distribution.setdefault(rule_id, count)

    return {
        "summary": {
            "workloads": len(entries),
            "workloads_with_findings": sum(
                1 for entry in entries if entry["findings"]
            ),
            "findings": total_findings,
            "rule_hits": ordered_distribution,
        },
        "workload_reports": entries,
    }


def write_report(report: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


def summary_line(report: dict) -> str:
    summary = report["summary"]
    distribution = ", ".join(
        f"{rule_id}={count}"
        for rule_id, count in summary["rule_hits"].items()
    ) or "no rule hits"
    return (
        f"workloads={summary['workloads']} findings={summary['findings']} "
        f"rule_hits: {distribution}"
    )
