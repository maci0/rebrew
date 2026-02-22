#!/usr/bin/env python3
"""
Train a mutation guidance model from GA training data.

Usage:
    uv run python tools/train_mutation_model.py training_data.jsonl --output model.pkl
"""

import argparse
import json
import pickle
from pathlib import Path
from collections import defaultdict


def load_training_data(jsonl_path: Path) -> list:
    """Load training data from JSONL file."""
    records = []
    with open(jsonl_path, "r") as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))
    return records


def analyze_mutations(records: list) -> dict:
    """Analyze which mutations are most effective."""
    stats = defaultdict(lambda: {"total": 0, "improved": 0, "score_delta_sum": 0})

    for record in records:
        mut_type = record.get("mutation_type", "unknown")
        improved = record.get("improved", False)
        parent_score = record.get("parent_score", 0)
        child_score = record.get("child_score", 0)

        stats[mut_type]["total"] += 1
        if improved:
            stats[mut_type]["improved"] += 1
        stats[mut_type]["score_delta_sum"] += parent_score - child_score

    # Calculate success rates
    for mut_type, data in stats.items():
        data["success_rate"] = (
            data["improved"] / data["total"] if data["total"] > 0 else 0
        )
        data["avg_improvement"] = (
            data["score_delta_sum"] / data["total"] if data["total"] > 0 else 0
        )

    return dict(stats)


def print_mutation_report(stats: dict):
    """Print mutation effectiveness report."""
    print("\n=== Mutation Effectiveness Report ===\n")
    print(
        f"{'Mutation Type':<40} {'Total':<8} {'Improved':<10} {'Success %':<12} {'Avg Improvement'}"
    )
    print("-" * 100)

    # Sort by success rate
    sorted_stats = sorted(
        stats.items(), key=lambda x: x[1]["success_rate"], reverse=True
    )

    for mut_type, data in sorted_stats:
        print(
            f"{mut_type:<40} {data['total']:<8} {data['improved']:<10} "
            f"{data['success_rate'] * 100:>6.1f}%     {data['avg_improvement']:>8.2f}"
        )

    print("-" * 100)
    total = sum(d["total"] for d in stats.values())
    total_improved = sum(d["improved"] for d in stats.values())
    print(
        f"{'TOTAL':<40} {total:<8} {total_improved:<10} "
        f"{total_improved / total * 100 if total > 0 else 0:>6.1f}%"
    )


def create_simple_model(stats: dict) -> dict:
    """Create a simple model that predicts mutation success probability."""
    # For now, just return the stats as the model
    # In the future, this could be a trained ML model
    return {
        "mutation_weights": {k: v["success_rate"] for k, v in stats.items()},
        "stats": stats,
    }


def main():
    parser = argparse.ArgumentParser(description="Train mutation guidance model")
    parser.add_argument("training_data", type=Path, help="Training data JSONL file")
    parser.add_argument(
        "--output",
        "-o",
        type=Path,
        default=Path("mutation_model.pkl"),
        help="Output model file",
    )
    parser.add_argument(
        "--report-only", action="store_true", help="Only print report, don't save model"
    )

    args = parser.parse_args()

    if not args.training_data.exists():
        print(f"Error: Training data file not found: {args.training_data}")
        return 1

    print(f"Loading training data from {args.training_data}...")
    records = load_training_data(args.training_data)
    print(f"Loaded {len(records)} training records")

    if not records:
        print("Error: No training records found")
        return 1

    print("\nAnalyzing mutations...")
    stats = analyze_mutations(records)
    print_mutation_report(stats)

    if not args.report_only:
        print(f"\nSaving model to {args.output}...")
        model = create_simple_model(stats)
        with open(args.output, "wb") as f:
            pickle.dump(model, f)
        print(f"Model saved!")

    return 0


if __name__ == "__main__":
    exit(main())
