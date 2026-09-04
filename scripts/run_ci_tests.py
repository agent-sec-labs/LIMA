"""Cross-platform unittest runner that preserves a UTF-8 CI evidence log."""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True)
    arguments = parser.parse_args()
    command = [
        sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v",
    ]
    completed = subprocess.run(
        command, capture_output=True, text=True, encoding="utf-8", errors="replace",
        check=False,
    )
    rendered = completed.stdout + completed.stderr
    output = Path(arguments.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(rendered, encoding="utf-8", newline="\n")
    sys.stdout.write(rendered)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
