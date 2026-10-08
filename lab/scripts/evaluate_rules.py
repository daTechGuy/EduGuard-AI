#!/usr/bin/env python3
"""
GrizzDog-AI: Standalone Rule Evaluator & Classroom Grader
=========================================================
Independent academic cybersecurity lab developed by a Butler Community College
Cyber Defense faculty member. Strictly for educational research and testing;
not an official Butler Community College service or endorsement.

Adapted from foundational cybersecurity architecture created by SixFiveMil (https://github.com/SixFiveMil/Securing-AI).

Evaluates lab/scripts/filter_rules.py against the shared classroom benchmark
(benchmark.py: visible ingress + egress tests, plus the held-out
generalization suite) without needing Docker or Flask running.

Usage:
    python lab/scripts/evaluate_rules.py
    python lab/scripts/evaluate_rules.py --verbose
"""

import sys
from pathlib import Path

from benchmark import run_benchmark
from rules_loader import RulesError, load_rules_file


def run_evaluation(verbose=False):
    repo_root = Path(__file__).resolve().parents[2]
    rules_path = repo_root / "lab" / "scripts" / "filter_rules.py"
    try:
        rules = load_rules_file(rules_path)  # parsed as data, never executed
    except (OSError, RulesError) as e:
        print(f"ERROR: {rules_path}: {e}")
        return 2

    blacklist = rules["INGRESS_BLACKLIST"]
    secrets = rules["EGRESS_SECRETS"]
    patterns = rules["EGRESS_PATTERNS"]
    bm = run_benchmark(blacklist, secrets, patterns)

    print("\n" + "=" * 70)
    print("GrizzDog-AI: Classroom Defense Benchmark Evaluation")
    print("=" * 70)
    print(f"Target file: {rules_path}")
    print(f"Active Rules: {len(blacklist)} ingress triggers | {len(secrets)} secrets | {len(patterns)} egress patterns\n")

    print(f"{'Category':<42} {'Layer/Type':<15} {'Status':<8} {'Detail'}")
    print("-" * 70)
    for d in bm["details"]:
        print(f"{d['category']:<42} {d['layer'] + '/' + d['type']:<15} {'[' + d['status'] + ']':<8} {d['action']}")
        if verbose:
            print(f"   Text: \"{d['prompt']}\"\n")

    print("-" * 70)
    print(f"Security (Attack Catch Rate):        {bm['attack_catch_rate']}% ({bm['attacks_caught']}/{bm['total_attacks']})")
    print(f"Usability (Benign Pass Rate):        {bm['benign_usability_rate']}% ({bm['benign_allowed']}/{bm['total_benign']})")
    print(f"Overall Composite Defense Score:     {bm['composite_score']}% / 100.0%")

    gen = bm["generalization"]
    print("\n" + "-" * 70)
    if gen["available"]:
        print(f"Held-out Generalization Suite ({len(gen['details'])} tests from {gen['source']}; text withheld)")
        for t in gen["by_technique"]:
            print(f"  {t['technique']:<30} {t['passed']}/{t['total']}")
        print(f"Held-out Attack Catch Rate:          {gen['attack_catch_rate']}% ({gen['attacks_caught']}/{gen['total_attacks']})")
        print(f"Held-out Benign Pass Rate:           {gen['benign_usability_rate']}% ({gen['benign_allowed']}/{gen['total_benign']})")
        print(f"Generalization Score:                {gen['composite_score']}% / 100.0%")
    else:
        print(f"Held-out Generalization Suite: not found ({gen['source']})")
    print("=" * 70 + "\n")

    return 0 if bm["composite_score"] >= 80.0 else 1


if __name__ == "__main__":
    verbose_flag = "--verbose" in sys.argv or "-v" in sys.argv
    sys.exit(run_evaluation(verbose=verbose_flag))
