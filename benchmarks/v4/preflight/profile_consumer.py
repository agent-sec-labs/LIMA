"""Consume the public Profile producer/codec without copying classification rules.

This probe supplies bound role context to a future #93 policy consumer. It does
not qualify findings, infer source control, or treat a non-production role as
proof that a finding is safe.
"""

from __future__ import annotations

import argparse
import json
import tempfile
import unicodedata
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from lima.audit import build_repository_profile
from lima.contracts.profile import (
    decode_profile_envelope,
    encode_profile_envelope,
    encode_profile_payload,
)
from lima.workspace import RepositoryWorkspace


@dataclass(frozen=True)
class ProfileBinding:
    tenant_id: str
    repository_snapshot_digest: str
    task_id: str
    workflow_id: str
    stage_attempt_id: str
    artifact_id: str


def _in_scope(path: str, scope: str) -> bool:
    return path == scope or path.startswith(scope + "/")


def consume_profile(data: bytes, binding: ProfileBinding, path: str) -> dict:
    """Decode, check identity and return all applicable roles and provenance.

    No longest-prefix or first-role preference is justified by this contract.
    Overlapping different roles remain ambiguous. The returned dictionaries are
    independent wire copies, not mutable references into a cached Profile.
    """
    envelope, profile = decode_profile_envelope(data)
    for field in binding.__dataclass_fields__:
        expected = getattr(binding, field)
        if not expected or getattr(envelope, field) != expected:
            raise ValueError("profile binding mismatch: " + field)
    if (
        not isinstance(path, str)
        or not path
        or len(path) > 4096
        or "\\" in path
        or ":" in path
        or any(ord(char) < 32 for char in path)
        or unicodedata.normalize("NFC", path) != path
        or PurePosixPath(path).is_absolute()
        or any(part in {"", ".", ".."} for part in path.split("/"))
    ):
        raise ValueError("query path must be a canonical relative POSIX path")
    if profile.component_path is not None and not _in_scope(path, profile.component_path):
        raise ValueError("query path is outside the profile component")
    payload = encode_profile_payload(profile)
    assignments = [a for a in payload["code_roles"] if _in_scope(path, a["path"])]
    roles = sorted({a["role"] for a in assignments})
    status = "missing" if not roles else "ambiguous" if len(roles) > 1 else "bound"
    return {
        "artifact_id": envelope.artifact_id,
        "content_digest": envelope.content_digest,
        "tenant_id": envelope.tenant_id,
        "repository_snapshot_digest": envelope.repository_snapshot_digest,
        "policy_digest": envelope.policy_digest,
        "toolchain_digest": envelope.toolchain_digest,
        "component_path": profile.component_path,
        "path": path,
        "roles": roles,
        "role_status": status,
        "assignments": assignments,
        "lineage": [reference.to_dict() for reference in envelope.lineage],
        "support_level": profile.support_level.value,
        "coverage_gaps": payload["coverage_gaps"],
        "context_required": (
            status != "bound"
            or bool(profile.coverage_gaps)
            or profile.support_level.value != "supported"
        ),
        "qualification": "not-run",
        "missing_policy_inputs": ["engine-and-rule-policy", "source-control", "path-closure"],
    }


PROFILE_SAMPLE = {
    "pyproject.toml": (
        '[project]\nname = "profile-consumer-probe"\nrequires-python = ">=3.11"\n'
        '[tool.pytest.ini_options]\ntestpaths = ["tests"]\n'
    ),
    "src/probe/__init__.py": "",
    "src/probe/core.py": "def identity(value):\n    return value\n",
    "tests/test_core.py": "def test_identity():\n    assert 1 == 1\n",
    "examples/demo.py": "VALUE = 1\n",
    "docs/readme.md": "# Inert consumption fixture\n",
    "src/probe/auto_pb2.py": "# generated code\nVALUE = 1\n",
}


def run_profile_probe() -> dict:
    """Build and consume a real Profile from an inert, never-executed fixture."""
    with tempfile.TemporaryDirectory(prefix="lima-profile-consumer-") as directory:
        root = Path(directory)
        for relative, source in PROFILE_SAMPLE.items():
            target = root / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(source.encode("utf-8"))
        workspace = RepositoryWorkspace(root)
        before = workspace.inventory().fingerprint()
        binding = ProfileBinding("offline", before, "probe", "probe", "profile", "profile")
        result = build_repository_profile(workspace, **binding.__dict__)
        data = encode_profile_envelope(result.envelope, result.profile)
        contexts = [consume_profile(data, binding, path) for path in PROFILE_SAMPLE]
        after = RepositoryWorkspace(root).inventory().fingerprint()
        if before != after:
            raise RuntimeError("profile producer changed the source fixture")
        return {
            "mode": "offline-public-interface-consumption",
            "status": "PASS",
            "qualification": "not-run",
            "snapshot_digest": before,
            "source_unchanged": True,
            "repository_code_executed": False,
            "profile_envelope": json.loads(data),
            "contexts": contexts,
        }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    record = run_profile_probe()
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(record, stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    print("PASS: public Profile consumption; qualification not run")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
