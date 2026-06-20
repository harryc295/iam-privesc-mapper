#!/usr/bin/env python3
"""CLI: collect IAM state (live AWS account or offline fixture), run the
privilege-escalation graph analysis, write an HTML report to ./output.

Usage:
    python main.py --fixture demo/sample_account.json      # zero AWS setup needed
    python main.py --profile my-readonly-profile
"""
import argparse
import json
import sys

import boto3

from iam_privesc_mapper.collector import collect_account_iam
from iam_privesc_mapper.graph import analyze
from iam_privesc_mapper.report import generate_report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--profile", help="AWS CLI profile to scan (read-only IAM calls only)")
    source.add_argument("--fixture", help="Path to an offline IAM fixture JSON, e.g. demo/sample_account.json")
    parser.add_argument("--out", default="output", help="Output directory (default: ./output)")
    args = parser.parse_args()

    if args.fixture:
        with open(args.fixture, encoding="utf-8") as fh:
            account = json.load(fh)
    else:
        account = collect_account_iam(boto3.Session(profile_name=args.profile))

    graph, findings = analyze(account)
    report_path = generate_report(graph, findings, account.get("account_id", "unknown"), out_dir=args.out)

    severities = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for f in findings:
        severities[f["severity"]] = severities.get(f["severity"], 0) + 1
    print(f"{len(findings)} findings -> {report_path}")
    print(", ".join(f"{k}: {v}" for k, v in severities.items() if v) or "no findings")

    return 1 if severities["Critical"] else 0


if __name__ == "__main__":
    sys.exit(main())
