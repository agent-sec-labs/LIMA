"""Frozen input-identity contract for LIMA v4 baseline runs (IP-0024).

A :class:`BaselineRunSpec` freezes everything that must be identical before a
baseline scan can be replayed: repository identities pinned to full immutable
commit SHAs, dataset fingerprints and data roles, analyzer and config
fingerprints, the random seed, and a declarative machine profile.  Identical
semantic input always produces byte-identical canonical JSON and an identical
SHA-256 digest; moving references, dataset drift, duplicate repositories and
role crossings fail closed with typed errors before any scan starts.

The module is a pure offline library: deterministic, secretless, no network,
no environment reads, and no auto-detection of any machine property.  The
canonical encoding and digest are delegated entirely to
``lima.contracts.codec``; this module never implements its own encoder.
"""

import dataclasses
import enum
import json
import re
from typing import NoReturn

from lima.contracts.codec import JSONValue, canonical_encode, compute_content_digest

__all__ = [
    "BaselineRunSpec",
    "BaselineRunSpecError",
    "BaselineRunSpecErrorCode",
    "from_mapping",
    "load_baseline_run_spec",
    "validate_baseline_manifest",
]

_SCHEMA_VERSION = 1
_INT64_MIN = -(2**63)
_INT64_MAX = 2**63 - 1

_TOP_LEVEL_FIELDS = (
    "schema_version",
    "repositories",
    "datasets",
    "analyzer_fingerprint",
    "config_digest",
    "seed",
    "machine_profile",
)
_REPOSITORY_FIELDS = ("identity", "commit_sha")
_DATASET_FIELDS = ("name", "fingerprint", "role")
_MANIFEST_DATASET_FIELDS = ("name", "fingerprint", "role", "entries")
_MANIFEST_ENTRY_FIELDS = ("repository", "commit_sha")

_MACHINE_PROFILE_FIELDS = (
    "profile_id",
    "cpu_arch",
    "cpu_model",
    "cores",
    "ram_gb",
    "os_family",
    "python_version",
    "gpu_summary",
)
_MACHINE_PROFILE_INT_FIELDS = ("cores", "ram_gb")
_MACHINE_PROFILE_ENUM_FIELDS = {
    "cpu_arch": ("x86_64", "aarch64"),
    "os_family": ("linux", "windows", "darwin"),
}
_DATASET_ROLES = ("external-holdout", "calibration", "development")

_FINGERPRINT_PATTERN = re.compile(r"[0-9a-f]{64}")
_FULL_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{40}")
_ABBREVIATED_COMMIT_SHA_PATTERN = re.compile(r"[0-9a-f]{7,39}")
_ANY_CASE_HEX40_PATTERN = re.compile(r"[0-9a-fA-F]{40}")

_GITHUB_HOST = "github.com"
_GITHUB_OWNER_PATTERN = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?")
_GITHUB_REPOSITORY_PATTERN = re.compile(r"[A-Za-z0-9._-]{1,100}")
_URL_SCHEME_PATTERN = re.compile(r"[A-Za-z][A-Za-z0-9+.\-]*")


class BaselineRunSpecErrorCode(str, enum.Enum):  # noqa: UP042 -- signature frozen by IP-0024 §5.1
    """Frozen wire values for every deterministic baseline-spec failure."""

    SCHEMA_VERSION_INVALID = "SCHEMA_VERSION_INVALID"
    REQUIRED_FIELD_MISSING = "REQUIRED_FIELD_MISSING"
    UNKNOWN_FIELD = "UNKNOWN_FIELD"
    INVALID_FIELD_TYPE = "INVALID_FIELD_TYPE"
    INVALID_FIELD_VALUE = "INVALID_FIELD_VALUE"
    ABBREVIATED_COMMIT_SHA_REJECTED = "ABBREVIATED_COMMIT_SHA_REJECTED"
    MOVING_REF_REJECTED = "MOVING_REF_REJECTED"
    INVALID_COMMIT_SHA = "INVALID_COMMIT_SHA"
    DUPLICATE_REPOSITORY = "DUPLICATE_REPOSITORY"
    DATASET_FINGERPRINT_MISMATCH = "DATASET_FINGERPRINT_MISMATCH"
    DATASET_ROLE_CONFLICT = "DATASET_ROLE_CONFLICT"
    INVALID_FINGERPRINT = "INVALID_FINGERPRINT"
    MANIFEST_IDENTITY_CONFLICT = "MANIFEST_IDENTITY_CONFLICT"


_STABLE_MESSAGES: dict[BaselineRunSpecErrorCode, str] = {
    BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID: (
        "Baseline run spec schema version is invalid."
    ),
    BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING: (
        "A required baseline run spec field is missing."
    ),
    BaselineRunSpecErrorCode.UNKNOWN_FIELD: (
        "Baseline run spec contains an unknown field for this schema version."
    ),
    BaselineRunSpecErrorCode.INVALID_FIELD_TYPE: "Baseline run spec field has an invalid type.",
    BaselineRunSpecErrorCode.INVALID_FIELD_VALUE: (
        "Baseline run spec field has an invalid value."
    ),
    BaselineRunSpecErrorCode.ABBREVIATED_COMMIT_SHA_REJECTED: (
        "Abbreviated commit SHA does not name an immutable revision."
    ),
    BaselineRunSpecErrorCode.MOVING_REF_REJECTED: (
        "Moving references do not name an immutable revision."
    ),
    BaselineRunSpecErrorCode.INVALID_COMMIT_SHA: "Commit SHA has an invalid shape.",
    BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY: (
        "Repositories must be unique by normalized identity."
    ),
    BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH: (
        "Dataset fingerprint differs from the baseline manifest."
    ),
    BaselineRunSpecErrorCode.DATASET_ROLE_CONFLICT: (
        "One repository crosses the external-holdout and calibration roles."
    ),
    BaselineRunSpecErrorCode.INVALID_FINGERPRINT: (
        "Fingerprint is not a lowercase 64-character hex digest."
    ),
    BaselineRunSpecErrorCode.MANIFEST_IDENTITY_CONFLICT: (
        "Repository identity conflicts with the baseline manifest."
    ),
}


class BaselineRunSpecError(ValueError):
    """Deterministic baseline-spec violation with a stable code and message.

    The shape aligns with ``lima.contracts.errors.ContractError`` while
    remaining an independent class.  The rendered message is exactly the
    catalog entry above; raw payloads, secrets, and field values are never
    embedded.  Use ``field_path`` for structure-only position reporting such
    as ``$.repositories[0].commit_sha``.
    """

    code: BaselineRunSpecErrorCode
    field_path: str

    def __init__(self, code: BaselineRunSpecErrorCode, field_path: str = "") -> None:
        if not isinstance(code, BaselineRunSpecErrorCode):
            raise TypeError("code must be a BaselineRunSpecErrorCode member")
        if not isinstance(field_path, str):
            raise TypeError("field_path must be a str")
        self.code = code
        self.field_path = field_path
        super().__init__(_STABLE_MESSAGES[code])


def _fail(code: BaselineRunSpecErrorCode, field_path: str) -> NoReturn:
    raise BaselineRunSpecError(code, field_path)


def _require_fields(
    container: dict[object, object], fields: tuple[str, ...], prefix: str
) -> None:
    for field in fields:
        if field not in container:
            _fail(BaselineRunSpecErrorCode.REQUIRED_FIELD_MISSING, f"{prefix}.{field}")


def _reject_unknown_fields(
    container: dict[object, object], fields: tuple[str, ...], prefix: str
) -> None:
    allowed = frozenset(fields)
    for key in container:
        if key in allowed:
            continue
        if isinstance(key, str):
            _fail(BaselineRunSpecErrorCode.UNKNOWN_FIELD, f"{prefix}.{key}")
        _fail(BaselineRunSpecErrorCode.UNKNOWN_FIELD, prefix)


def _validate_schema_version(value: object) -> int:
    if type(value) is not int:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
    if value != _SCHEMA_VERSION:
        _fail(BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID, "$.schema_version")
    return value


def _validate_fingerprint(value: object, field_path: str) -> str:
    if not isinstance(value, str):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, field_path)
    if _FINGERPRINT_PATTERN.fullmatch(value) is None:
        _fail(BaselineRunSpecErrorCode.INVALID_FINGERPRINT, field_path)
    return value


def _validate_seed(value: object) -> int:
    if type(value) is not int:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.seed")
    if not _INT64_MIN <= value <= _INT64_MAX:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, "$.seed")
    return value


def _validate_commit_sha(value: object, field_path: str) -> str:
    if not isinstance(value, str):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, field_path)
    if _FULL_COMMIT_SHA_PATTERN.fullmatch(value) is not None:
        return value
    if _ABBREVIATED_COMMIT_SHA_PATTERN.fullmatch(value) is not None:
        _fail(BaselineRunSpecErrorCode.ABBREVIATED_COMMIT_SHA_REJECTED, field_path)
    if len(value) == 40:
        if _ANY_CASE_HEX40_PATTERN.fullmatch(value) is not None:
            _fail(BaselineRunSpecErrorCode.MOVING_REF_REJECTED, field_path)
        _fail(BaselineRunSpecErrorCode.INVALID_COMMIT_SHA, field_path)
    _fail(BaselineRunSpecErrorCode.MOVING_REF_REJECTED, field_path)


def _clean_identity_text(value: str) -> str | None:
    """Mirror the shared required-string gate: no control characters, stripped."""

    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        return None
    stripped = value.strip()
    return stripped or None


def _split_url_scheme(candidate: str) -> tuple[str, str] | None:
    """Return ``(scheme, remainder)`` when a scheme prefix is present."""

    separator = candidate.find(":")
    if separator <= 0:
        return None
    prefix = candidate[:separator]
    if _URL_SCHEME_PATTERN.fullmatch(prefix) is None:
        return None
    return prefix, candidate[separator + 1 :]


def _normalize_github_name(candidate: str) -> str | None:
    """Normalize to a lower-case ``owner/repository`` identity, or ``None``.

    Accepted shapes mirror ``lima.repository_source`` semantics: either the
    plain ``owner/repository`` name or an HTTPS ``github.com`` URL, with a
    conventional trailing ``.git`` suffix removed.  No other transport, host,
    credential, port, query, or fragment is accepted.
    """

    if len(candidate) > 2048:
        return None
    scheme_split = _split_url_scheme(candidate)
    if scheme_split is not None:
        scheme, remainder = scheme_split
        if scheme.lower() != "https" or not remainder.startswith("//"):
            return None
        authority, separator, path = remainder[2:].partition("/")
        if not separator:
            return None
        if "@" in authority or ":" in authority:
            return None
        if authority.lower() != _GITHUB_HOST:
            return None
        if "?" in path or "#" in path:
            return None
        if path.endswith("/"):
            path = path[:-1]
    else:
        if candidate.startswith("/") or candidate.endswith("/"):
            return None
        path = candidate
    parts = path.split("/")
    if len(parts) != 2 or not all(parts):
        return None
    owner, repository = parts
    if repository.lower().endswith(".git"):
        repository = repository[:-4]
    if "--" in owner or _GITHUB_OWNER_PATTERN.fullmatch(owner) is None:
        return None
    if repository in {"", ".", ".."} or _GITHUB_REPOSITORY_PATTERN.fullmatch(repository) is None:
        return None
    return f"{owner.lower()}/{repository.lower()}"


def _normalize_local_key(candidate: str) -> str | None:
    """Normalize to a case-preserving bounded relative key, or ``None``.

    Mirrors ``lima.repository_import`` semantics: forward slashes only, at
    most 16 bounded segments, no absolute paths, no dot segments, and only
    alphanumeric-led segments built from alphanumerics, ``-``, ``_``, ``.``.
    """

    if len(candidate) > 240:
        return None
    if "\\" in candidate or candidate.startswith("/"):
        return None
    parts = [part for part in candidate.split("/") if part not in ("", ".")]
    if not parts or len(parts) > 16:
        return None
    for part in parts:
        if part == ".." or part.startswith(".") or len(part) > 80:
            return None
        if not part[0].isalnum():
            return None
        for character in part:
            if not (character.isalnum() or character in "-_."):
                return None
    return "/".join(parts)


def _normalize_identity(value: str) -> str | None:
    """Apply the frozen github-first identity normalization order."""

    candidate = _clean_identity_text(value)
    if candidate is None:
        return None
    github_name = _normalize_github_name(candidate)
    if github_name is not None:
        return github_name
    return _normalize_local_key(candidate)


def _validate_repositories(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.repositories")
    if not value:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, "$.repositories")
    repositories: list[dict[str, str]] = []
    seen_identities: set[str] = set()
    for index, element in enumerate(value):
        prefix = f"$.repositories[{index}]"
        if not isinstance(element, dict):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, prefix)
        _require_fields(element, _REPOSITORY_FIELDS, prefix)
        _reject_unknown_fields(element, _REPOSITORY_FIELDS, prefix)
        identity = element["identity"]
        if not isinstance(identity, str):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, f"{prefix}.identity")
        normalized = _normalize_identity(identity)
        if normalized is None:
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, f"{prefix}.identity")
        if normalized in seen_identities:
            _fail(BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY, f"{prefix}.identity")
        seen_identities.add(normalized)
        commit_sha = _validate_commit_sha(element["commit_sha"], f"{prefix}.commit_sha")
        repositories.append({"identity": identity, "commit_sha": commit_sha})
    return repositories


def _validate_datasets(value: object) -> list[dict[str, str]]:
    if not isinstance(value, list):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.datasets")
    if not value:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, "$.datasets")
    datasets: list[dict[str, str]] = []
    for index, element in enumerate(value):
        prefix = f"$.datasets[{index}]"
        if not isinstance(element, dict):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, prefix)
        _require_fields(element, _DATASET_FIELDS, prefix)
        _reject_unknown_fields(element, _DATASET_FIELDS, prefix)
        name = element["name"]
        if not isinstance(name, str):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, f"{prefix}.name")
        fingerprint = _validate_fingerprint(element["fingerprint"], f"{prefix}.fingerprint")
        role = element["role"]
        if role not in _DATASET_ROLES:
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, f"{prefix}.role")
        datasets.append({"name": name, "fingerprint": fingerprint, "role": role})
    return datasets


def _validate_machine_profile(value: object) -> dict[str, str | int]:
    if not isinstance(value, dict):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.machine_profile")
    _require_fields(value, _MACHINE_PROFILE_FIELDS, "$.machine_profile")
    _reject_unknown_fields(value, _MACHINE_PROFILE_FIELDS, "$.machine_profile")
    profile: dict[str, str | int] = {}
    for field in _MACHINE_PROFILE_FIELDS:
        item = value[field]
        field_path = f"$.machine_profile.{field}"
        if field in _MACHINE_PROFILE_INT_FIELDS:
            if type(item) is not int:
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, field_path)
        elif field in _MACHINE_PROFILE_ENUM_FIELDS:
            if not isinstance(item, str):
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, field_path)
            if item not in _MACHINE_PROFILE_ENUM_FIELDS[field]:
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, field_path)
        elif not isinstance(item, str):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, field_path)
        profile[field] = item
    return profile


@dataclasses.dataclass(frozen=True)
class BaselineRunSpec:
    """The frozen, replayable input identity of one baseline run.

    Instances are constructed through :func:`from_mapping` (or
    :func:`load_baseline_run_spec`) so that every field carries the validated
    schema-v1 shape.  ``machine_profile`` is declarative (D-1): declared
    values only, never probed from the host.
    """

    schema_version: int
    repositories: list[dict[str, str]]
    datasets: list[dict[str, str]]
    analyzer_fingerprint: str
    config_digest: str
    seed: int
    machine_profile: dict[str, str | int]

    def to_canonical_value(self) -> dict[str, JSONValue]:
        """Return the codec JSONValue subset covering every frozen field."""

        return {
            "schema_version": self.schema_version,
            "repositories": [
                {
                    "identity": repository["identity"],
                    "commit_sha": repository["commit_sha"],
                }
                for repository in self.repositories
            ],
            "datasets": [
                {
                    "name": dataset["name"],
                    "fingerprint": dataset["fingerprint"],
                    "role": dataset["role"],
                }
                for dataset in self.datasets
            ],
            "analyzer_fingerprint": self.analyzer_fingerprint,
            "config_digest": self.config_digest,
            "seed": self.seed,
            "machine_profile": dict(self.machine_profile),
        }

    def canonical_bytes(self) -> bytes:
        """Return the byte-identical canonical JSON via ``lima.contracts.codec``."""

        return canonical_encode(self.to_canonical_value())

    def content_digest(self) -> str:
        """Return the lowercase hex SHA-256 of :meth:`canonical_bytes`."""

        return compute_content_digest(self.canonical_bytes())


def from_mapping(mapping: object) -> BaselineRunSpec:
    """Strictly validate and freeze a baseline run spec mapping (schema v1).

    Required-field presence, unknown-key rejection, exact types, value
    domains, revision triage, identity normalization and duplicate detection
    are all enforced; any violation raises :class:`BaselineRunSpecError`.
    """

    if not isinstance(mapping, dict):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$")
    _require_fields(mapping, _TOP_LEVEL_FIELDS, "$")
    _reject_unknown_fields(mapping, _TOP_LEVEL_FIELDS, "$")
    return BaselineRunSpec(
        schema_version=_validate_schema_version(mapping["schema_version"]),
        repositories=_validate_repositories(mapping["repositories"]),
        datasets=_validate_datasets(mapping["datasets"]),
        analyzer_fingerprint=_validate_fingerprint(
            mapping["analyzer_fingerprint"], "$.analyzer_fingerprint"
        ),
        config_digest=_validate_fingerprint(mapping["config_digest"], "$.config_digest"),
        seed=_validate_seed(mapping["seed"]),
        machine_profile=_validate_machine_profile(mapping["machine_profile"]),
    )


def load_baseline_run_spec(path: str) -> BaselineRunSpec:
    """Load a spec from a UTF-8 JSON file, independent of formatting.

    Indentation, key order and ASCII escaping do not affect the resulting
    spec or its digest.  Malformed JSON fails closed as
    :class:`BaselineRunSpecError`; in-file contract violations surface the
    same typed errors as :func:`from_mapping`.
    """

    with open(path, "rb") as handle:
        data = handle.read()
    try:
        parsed = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, "$")
    return from_mapping(parsed)


def validate_baseline_manifest(manifest: object, spec: BaselineRunSpec) -> None:
    """Fail-closed cross-check of a baseline manifest (schema v1) against a spec.

    Enforces manifest structure, dataset fingerprint consistency, duplicate
    repository detection (by normalized identity), the external-holdout and
    calibration role crossing, and spec-versus-manifest identity agreement.
    Extra manifest fields are tolerated for forward compatibility; every
    violation raises :class:`BaselineRunSpecError` with the frozen code.
    """

    if not isinstance(manifest, dict):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$")
    manifest_version = manifest.get("schema_version")
    if type(manifest_version) is not int:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.schema_version")
    if manifest_version != _SCHEMA_VERSION:
        _fail(BaselineRunSpecErrorCode.SCHEMA_VERSION_INVALID, "$.schema_version")
    manifest_datasets_value = manifest.get("datasets")
    if not isinstance(manifest_datasets_value, list):
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, "$.datasets")
    if not manifest_datasets_value:
        _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, "$.datasets")

    datasets_by_name: dict[str, dict[object, object]] = {}
    identity_roles: dict[str, set[str]] = {}
    identity_commit_shas: dict[str, list[str]] = {}
    for dataset_index, dataset in enumerate(manifest_datasets_value):
        dataset_prefix = f"$.datasets[{dataset_index}]"
        if not isinstance(dataset, dict):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, dataset_prefix)
        _require_fields(dataset, _MANIFEST_DATASET_FIELDS, dataset_prefix)
        role = dataset["role"]
        if role not in _DATASET_ROLES:
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, f"{dataset_prefix}.role")
        entries = dataset["entries"]
        if not isinstance(entries, list):
            _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, f"{dataset_prefix}.entries")
        name = dataset["name"]
        if isinstance(name, str):
            datasets_by_name[name] = dataset
        for entry_index, entry in enumerate(entries):
            entry_prefix = f"{dataset_prefix}.entries[{entry_index}]"
            if not isinstance(entry, dict):
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, entry_prefix)
            _require_fields(entry, _MANIFEST_ENTRY_FIELDS, entry_prefix)
            repository = entry["repository"]
            commit_sha = entry["commit_sha"]
            if not isinstance(repository, str):
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, f"{entry_prefix}.repository")
            if not isinstance(commit_sha, str):
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_TYPE, f"{entry_prefix}.commit_sha")
            normalized = _normalize_identity(repository)
            if normalized is None:
                _fail(BaselineRunSpecErrorCode.INVALID_FIELD_VALUE, f"{entry_prefix}.repository")
            identity_roles.setdefault(normalized, set()).add(role)
            identity_commit_shas.setdefault(normalized, []).append(commit_sha)

    for dataset_index, dataset in enumerate(spec.datasets):
        manifest_dataset = datasets_by_name.get(dataset["name"])
        if manifest_dataset is None or manifest_dataset["fingerprint"] != dataset["fingerprint"]:
            _fail(
                BaselineRunSpecErrorCode.DATASET_FINGERPRINT_MISMATCH,
                f"$.datasets[{dataset_index}]",
            )

    for roles in identity_roles.values():
        if "external-holdout" in roles and "calibration" in roles:
            _fail(BaselineRunSpecErrorCode.DATASET_ROLE_CONFLICT, "$.datasets")

    for commit_shas in identity_commit_shas.values():
        if len(commit_shas) > 1:
            _fail(BaselineRunSpecErrorCode.DUPLICATE_REPOSITORY, "$.datasets")

    for repository_index, repository in enumerate(spec.repositories):
        normalized = _normalize_identity(repository["identity"])
        commit_shas = identity_commit_shas.get(normalized) if normalized is not None else None
        if commit_shas is None or repository["commit_sha"] not in commit_shas:
            _fail(
                BaselineRunSpecErrorCode.MANIFEST_IDENTITY_CONFLICT,
                f"$.repositories[{repository_index}]",
            )
