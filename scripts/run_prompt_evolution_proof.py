import argparse
import os
import sys


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from lima.evolution_proof import (  # noqa: E402
    generate_prompt_evolution_cases,
    run_prompt_evolution_proof,
    write_jsonl,
    write_report,
)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run an auditable feedback-driven prompt evolution replay."
    )
    parser.add_argument("--dataset", default="")
    parser.add_argument(
        "--output-dir", default=os.path.join("output", "prompt-evolution-proof")
    )
    args = parser.parse_args()
    os.makedirs(args.output_dir, exist_ok=True)
    dataset_path = args.dataset or os.path.join(
        args.output_dir, "prompt-evolution-cases.jsonl"
    )
    if not args.dataset:
        write_jsonl(generate_prompt_evolution_cases(), dataset_path)
    database_path = os.path.join(args.output_dir, "prompt-evolution-proof.db")
    if os.path.exists(database_path):
        raise SystemExit(
            "proof database already exists; choose a fresh --output-dir for an immutable run"
        )
    report = run_prompt_evolution_proof(dataset_path, database_path)
    paths = write_report(report, args.output_dir)
    print("decision:", report["evolution_run"]["decision"])
    print("run_id:", report["evolution_run"]["run_id"])
    print("json:", paths["json"])
    print("markdown:", paths["markdown"])


if __name__ == "__main__":
    main()
