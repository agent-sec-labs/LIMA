"""Read-only sensitive-artifact audit CLI for one local directory (IP-0020).

Scans the ``*.json`` / ``*.txt`` files directly inside a caller-supplied
target directory and emits a single value-free JSON audit report: positions,
fingerprints, value kinds, lengths, and policy evidence. Audited content is
never printed, logged, or written anywhere.

Read-only contract (Packet §8.3): input files are only ever read; nothing
inside the target directory is created, modified, or deleted. The sole
permitted write is the explicit ``--output`` report file, which must resolve
outside the scanned directory. Files that fail strict UTF-8 decoding or JSON
parsing are skipped with a one-line stderr warning (file name and error
category only) and contribute no findings.

Fingerprints are computed under the documented fixed offline tenant context
(Packet §8.3.8): they are stable only inside that offline context, are not
correlatable with online tenant fingerprints, and must not be used for
cross-tenant comparison. ``tenant_context`` is embedded in every report so
consumers can distinguish the offline fingerprint domain.

Dependencies: standard library plus ``lima.evidence_privacy.audit``; no
subprocess, no network, no shell execution.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Final

_REPO_ROOT: Final[Path] = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from lima.evidence_privacy.audit import (  # noqa: E402
    AuditFinding,
    audit_report_to_json,
    audit_structured,
    audit_text,
    build_audit_report,
)
from lima.evidence_privacy.policy import DEFAULT_POLICY  # noqa: E402

# Packet §8.3.8 (F-1): documented fixed offline tenant context. These are
# identifying constants, not credentials; they never come from the
# environment, files, or the network.
OFFLINE_TENANT_ID: Final[str] = "offline-audit"
OFFLINE_TENANT_KEY: Final[bytes] = b"lima-offline-audit.v1"

_ARTIFACT_SUFFIXES: Final[frozenset[str]] = frozenset({".json", ".txt"})


def _warn(filename: str, category: str) -> None:
    """One-line stderr warning carrying the file name and error category only."""
    print(json.dumps({"file": filename, "error": category}), file=sys.stderr)


def _scan_artifacts(target: Path) -> dict[str, tuple[AuditFinding, ...]]:
    """Read-only scan of ``*.json``/``*.txt`` files directly inside ``target``."""
    findings_by_artifact: dict[str, tuple[AuditFinding, ...]] = {}
    for path in sorted(target.iterdir()):
        if not path.is_file() or path.suffix not in _ARTIFACT_SUFFIXES:
            continue
        data = path.read_bytes()
        if path.suffix == ".json":
            try:
                value = json.loads(data.decode("utf-8"))
            except ValueError:  # strict decode + parse failures -> skip
                _warn(path.name, "unparseable-json")
                continue
            findings_by_artifact[path.name] = audit_structured(
                path.name,
                value,
                DEFAULT_POLICY,
                tenant_id=OFFLINE_TENANT_ID,
                tenant_key=OFFLINE_TENANT_KEY,
            )
        else:
            try:
                text = data.decode("utf-8")
            except UnicodeDecodeError:  # strict decode failure -> skip
                _warn(path.name, "undecodable-text")
                continue
            findings_by_artifact[path.name] = audit_text(
                path.name,
                text,
                DEFAULT_POLICY,
                tenant_id=OFFLINE_TENANT_ID,
                tenant_key=OFFLINE_TENANT_KEY,
            )
    return findings_by_artifact


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="audit_sensitive_artifacts.py",
        description=(
            "Read-only sensitive-artifact audit: scan one directory and print "
            "(or write via --output) a value-free JSON report."
        ),
    )
    parser.add_argument(
        "target_dir",
        metavar="target-dir",
        help="existing local directory to scan (never modified)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=None,
        help="explicit report path; must resolve outside the target directory",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="indent the JSON report instead of the canonical single line",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry: return 0 after a completed scan; parameter/IO errors non-zero."""
    parser = _build_parser()
    args = parser.parse_args(argv)
    target = Path(args.target_dir)
    if not target.is_dir():
        print(
            f"error: target-dir is not an existing local directory: {target}",
            file=sys.stderr,
        )
        return 2
    target_resolved = target.resolve()
    output_resolved: Path | None = None
    if args.output is not None:
        output_resolved = Path(args.output).resolve()
        if output_resolved == target_resolved or target_resolved in output_resolved.parents:
            print(
                "error: --output path must resolve outside the scanned target "
                f"directory: {output_resolved}",
                file=sys.stderr,
            )
            return 2
    report = build_audit_report(_scan_artifacts(target_resolved), DEFAULT_POLICY)
    payload = json.loads(audit_report_to_json(report))
    payload["tenant_context"] = OFFLINE_TENANT_ID
    if args.pretty:
        serialized = json.dumps(payload, ensure_ascii=False, sort_keys=True, indent=2)
    else:
        serialized = json.dumps(
            payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")
        )
    if output_resolved is None:
        print(serialized)
        return 0
    try:
        output_resolved.write_text(serialized + "\n", encoding="utf-8")
    except OSError as exc:
        print(f"error: cannot write report file: {exc.strerror}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
