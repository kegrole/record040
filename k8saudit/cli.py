"""Command line entry point for the Kubernetes manifest auditor."""

from __future__ import annotations

import argparse
import os
import sys

from .manifest import load_workloads
from .report import build_report, summary_line, write_report
from .rules import load_rules


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m k8saudit.cli",
        description="Audit Kubernetes workload manifests using a YAML rule file.",
    )
    parser.add_argument(
        "--manifests",
        required=True,
        help="directory (or single file) containing workload YAML manifests",
    )
    parser.add_argument(
        "--rules", required=True, help="YAML file describing the audit rules"
    )
    parser.add_argument(
        "--out", required=True, help="path of the JSON report to write"
    )
    return parser


def run(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    rules = load_rules(args.rules)
    workloads = load_workloads(args.manifests)
    report = build_report(workloads, rules)

    out_dir = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(out_dir, exist_ok=True)
    write_report(report, args.out)
    print(summary_line(report))
    return 0


def main() -> None:
    sys.exit(run())


if __name__ == "__main__":
    main()
