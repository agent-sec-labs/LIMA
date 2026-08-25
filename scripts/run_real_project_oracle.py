"""Trusted semantic adapters for isolated real-project evaluation containers."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


def gitpython_unsafe_option_guard(repository: Path) -> bool:
    sys.path.insert(0, str(repository))
    try:
        from git import Git
        from git.exc import UnsafeOptionError

        try:
            Git.check_unsafe_options(["upload_pack"], ["--upload-pack"])
        except UnsafeOptionError:
            return True
        return False
    finally:
        sys.path.pop(0)


ORACLES = {"gitpython-unsafe-option-guard": gitpython_unsafe_option_guard}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Run one isolated real-project oracle.")
    parser.add_argument("--kind", choices=sorted(ORACLES), required=True)
    parser.add_argument("--repository", required=True)
    args = parser.parse_args(argv)
    root = Path(args.repository).expanduser().resolve(strict=True)
    if not root.is_dir():
        raise ValueError("repository must be a directory")
    secure = ORACLES[args.kind](root)
    print(json.dumps({"secure": secure}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
