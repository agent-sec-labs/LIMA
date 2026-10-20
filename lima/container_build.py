"""LIMA full-build CLI, separate from the frozen configure-only context recipe.

Run: python -m lima.container_build --source REPO --recipe full-build.json --output DIR
The same stdlib-only file runs as the worker inside the build image.
"""
# ruff: noqa: S603, S607
# Git/Docker are local toolchain commands; trusted recipes run argv inside the container.

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import time
import uuid
import xml.etree.ElementTree as ET
from pathlib import Path, PurePosixPath

PHASES = ("prepare", "setup", "configure", "build", "test", "install", "verify")


def project_catalog() -> dict[str, Path]:
    root = Path(__file__).resolve().parent.parent / "deploy/build-recipes"
    return {path.parent.name: path for path in sorted(root.glob("*/full-build.json"))}


def resolve_project(name: str) -> Path:
    catalog = project_catalog()
    if name not in catalog:
        raise ValueError(f"Unknown project {name!r}; choose: {', '.join(catalog)}")
    return catalog[name]


def report_paths(value: dict) -> list[str]:
    paths = value.get("test_reports", ["ctest-results.xml"])
    if not isinstance(paths, list) or not paths or len(paths) > 32:
        raise ValueError("test_reports must be a nonempty list of relative JUnit paths")
    for path in paths:
        if (
            not isinstance(path, str)
            or not path
            or "\\" in path
            or ":" in path
            or PurePosixPath(path).is_absolute()
            or ".." in path.split("/")
            or any(ord(c) < 32 for c in path)
        ):
            raise ValueError("Unsafe JUnit report path")
    if len(set(paths)) != len(paths):
        raise ValueError("Duplicate JUnit report path")
    return paths


def validate_recipe(value: dict) -> dict:
    required = {"schema_version", "name", "image", "configure", "build", "test", "install"}
    optional = {"environment", "setup", "verify", "test_reports"}
    if (
        not isinstance(value, dict)
        or not required.issubset(value)
        or set(value) - required - optional
        or type(value["schema_version"]) is not int
        or value["schema_version"] != 1
    ):
        raise ValueError("Invalid full-build recipe schema or fields")
    for key in ("name", "image"):
        if not isinstance(value[key], str) or not re.fullmatch(
            r"[A-Za-z0-9][A-Za-z0-9._:/@-]*", value[key]
        ):
            raise ValueError(f"Invalid {key}")
    for phase in ("setup", "configure", "build", "test", "install", "verify"):
        commands = value.get(phase, [])
        if not isinstance(commands, list) or (phase in required and not commands):
            raise ValueError(f"Missing commands: {phase}")
        for command in commands:
            if (
                not isinstance(command, list)
                or not command
                or any(
                    not isinstance(arg, str) or not arg or any(ord(c) < 32 for c in arg)
                    for arg in command
                )
            ):
                raise ValueError(f"Invalid argv: {phase}")
    environment = value.get("environment", {})
    if not isinstance(environment, dict):
        raise ValueError("environment must be a mapping")
    for key, item in environment.items():
        if (
            not isinstance(key, str)
            or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key)
            or not isinstance(item, str)
            or any(ord(c) < 32 for c in item)
        ):
            raise ValueError("Invalid environment entry")
    report_paths(value)
    return value


def save_record(output: Path, record: dict) -> None:
    temporary = output / "build-result.tmp"
    temporary.write_text(json.dumps(record, indent=2), encoding="utf8")
    temporary.replace(output / "build-result.json")


def record_image_failure(output: Path, recipe: dict, revision: str, returncode: int) -> None:
    save_record(
        output,
        {
            "status": "failed",
            "revision": revision,
            "image": recipe["image"],
            "returncode": returncode,
            "steps": [
                {
                    "phase": "image",
                    "status": "failed",
                    "returncode": returncode,
                    "log": "image-build.log",
                }
            ],
        },
    )


def prepare_output(output: Path) -> None:
    if output.exists() and any(output.iterdir()):
        raise ValueError("Use an empty output directory to preserve previous build evidence")
    output.mkdir(parents=True, exist_ok=True)


def mark_interrupted(output: Path) -> None:
    mark_container_failure(output, 130)


def mark_container_failure(output: Path, returncode: int) -> None:
    path = output / "build-result.json"
    record = json.loads(path.read_text(encoding="utf8")) if path.exists() else {"steps": []}
    status = "interrupted" if returncode == 130 else "failed"
    record.update(status=status, returncode=returncode)
    for step in record["steps"]:
        if step["status"] == "running":
            step.update(status=status, returncode=returncode)
    save_record(output, record)


def validate_cached_checkout(source: Path) -> None:
    try:
        subprocess.run(
            ["git", "-C", str(source), "rev-parse", "--verify", "HEAD"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=True,
        )
        dirty = subprocess.check_output(
            [
                "git",
                "-C",
                str(source),
                "status",
                "--porcelain",
                "--ignore-submodules=none",
                "--ignored",
                "--untracked-files=all",
            ]
        )
    except subprocess.CalledProcessError as exc:
        raise ValueError("Cached checkout is incomplete; use a new volume") from exc
    if dirty.strip():
        raise ValueError("Cached source has modifications or extra files; use a new volume")


def validate_installation(work: Path, output: Path, reports: list[str] | None = None) -> dict:
    install = (work / "install").resolve()
    manifest = work / "build/install_manifest.txt"
    if not manifest.is_file() or not manifest.read_text().strip():
        raise ValueError("Missing installation manifest")
    installed = manifest.read_text().splitlines()
    for line in installed:
        path = Path(line).resolve()
        if not path.is_relative_to(install) or not path.is_file():
            raise ValueError(f"Missing or out-of-prefix installed artifact: {line}")
    totals = summarize_reports(output, reports or ["ctest-results.xml"])
    return dict(totals, installed_files=len(installed))


def summarize_reports(output: Path, reports: list[str]) -> dict:
    totals = dict.fromkeys(("tests", "failures", "errors", "skipped", "disabled"), 0)
    for relative in report_paths({"test_reports": reports}):
        report = output / relative
        if not report.resolve().is_relative_to(output.resolve()) or not report.is_file():
            raise ValueError(f"Missing or out-of-directory JUnit report: {relative}")
        data = report.read_text(encoding="utf8")
        if (
            len(data) > 10 * 1024 * 1024
            or "<!DOCTYPE" in data.upper()
            or "<!ENTITY" in data.upper()
        ):
            raise ValueError("Unsafe or oversized JUnit report")
        root = ET.fromstring(data)  # noqa: S314 - bounded UTF-8, DTD/entities rejected above
        suites = [suite for suite in root.iter("testsuite") if suite.find("testsuite") is None]
        count = dict.fromkeys(totals, 0)
        for suite in suites:
            for field in count:
                number = int(suite.attrib.get(field, 0))
                if number < 0:
                    raise ValueError("Negative JUnit count")
                count[field] += number
        if (
            count["tests"] - count["disabled"] - count["skipped"] <= 0
            or count["failures"]
            or count["errors"]
        ):
            raise ValueError(f"Empty or unsuccessful test report: {relative}")
        for field in totals:
            totals[field] += count[field]
    totals["executed"] = totals["tests"] - totals["disabled"]
    totals["passed"] = totals["executed"] - totals["skipped"]
    return totals


def execute_phases(
    recipe: dict,
    output: Path,
    *,
    jobs: int,
    execute=subprocess.run,
    record: dict | None = None,
    completed_status: str = "completed",
) -> dict:
    """Run argv phases in order. A failed phase prevents all following work."""
    output.mkdir(parents=True, exist_ok=True)
    logs = output / "logs"
    logs.mkdir(exist_ok=True)
    if record is None:
        record = {}
    record.update(status="running", steps=[])
    save_record(output, record)
    for phase in PHASES:
        for index, raw_command in enumerate(recipe.get(phase, [])):
            command = [arg.replace("{jobs}", str(jobs)) for arg in raw_command]
            step = {
                "phase": phase,
                "command": command,
                "status": "running",
                "log": f"logs/{phase}-{index}.log",
            }
            record["steps"].append(step)
            save_record(output, record)
            print(f"LIMA {phase}: {command}", flush=True)
            started = time.monotonic()
            try:
                with (output / step["log"]).open("w", encoding="utf8") as log:
                    result = execute(
                        command,
                        stdout=log,
                        stderr=subprocess.STDOUT,
                        timeout=21600 if phase == "build" else 7200,
                        check=False,
                    )
                step["returncode"] = result.returncode
                step["status"] = "completed" if result.returncode == 0 else "failed"
            except Exception as exc:
                step.update(status="failed", error=str(exc))
            step["seconds"] = round(time.monotonic() - started, 2)
            if step["status"] == "failed":
                record["status"] = "failed"
                save_record(output, record)
                print((output / step["log"]).read_text(errors="replace")[-12000:], flush=True)
                return record
            save_record(output, record)
    record["status"] = completed_status
    save_record(output, record)
    return record


def container_command(
    *,
    image: str,
    name: str,
    volume: str,
    source: Path,
    output: Path,
    recipe: Path,
    worker: Path,
    revision: str,
    jobs: int,
) -> list[str]:
    command = [
        "docker",
        "run",
        "--name",
        name,
        "--init",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges:true",
        "--memory",
        "10g",
        "--cpus",
        "6",
        "--pids-limit",
        "1024",
    ]
    mounts = [
        f"type=bind,source={source},target=/input,readonly",
        f"type=volume,source={volume},target=/work",
        f"type=bind,source={output},target=/output",
        f"type=bind,source={recipe},target=/control/recipe.json,readonly",
        f"type=bind,source={worker},target=/control/worker.py,readonly",
    ]
    for mount in mounts:
        command += ["--mount", mount]
    return command + [
        "--workdir",
        "/work",
        image,
        "python3",
        "/control/worker.py",
        "--worker",
        "--revision",
        revision,
        "--jobs",
        str(jobs),
    ]


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def worker_main(args) -> int:
    output = Path("/output")
    recipe = validate_recipe(json.loads(Path("/control/recipe.json").read_text()))
    source = Path("/work/src")
    record = json.loads((output / "invocation.json").read_text())
    try:
        home = Path("/work/home")
        home.mkdir(exist_ok=True)
        os.environ.update(
            HOME=str(home),
            LANG="C.UTF-8",
            GIT_TERMINAL_PROMPT="0",
            OMP_NUM_THREADS="2",
            CTEST_NO_TESTS_ACTION="error",
        )
        os.environ.update(
            {
                key: value.replace("{jobs}", str(args.jobs))
                for key, value in recipe.get("environment", {}).items()
            }
        )
        provenance = Path("/work/provenance.json")
        identity = {
            "revision": args.revision,
            "source": record["source"],
            "recipe_sha256": record["recipe_sha256"],
            "image_id": record["image_id"],
        }
        if provenance.exists() and json.loads(provenance.read_text()) != identity:
            raise ValueError(
                "Workspace belongs to a different source/recipe/image; use a new volume"
            )
        provenance.write_text(json.dumps(identity))
        prepare = []
        if source.exists():
            validate_cached_checkout(source)
        else:
            prepare.append(
                [
                    "git",
                    "-c",
                    "safe.directory=/input",
                    "clone",
                    "--no-hardlinks",
                    "--no-checkout",
                    "/input",
                    str(source),
                ]
            )
        prepare += [
            ["git", "-C", str(source), "checkout", "--detach", args.revision],
            [
                "git",
                "-C",
                str(source),
                "submodule",
                "update",
                "--init",
                "--recursive",
                "--jobs",
                str(args.jobs),
            ],
            ["git", "-C", str(source), "submodule", "status", "--recursive"],
        ]
        recipe = dict(recipe, prepare=prepare)
        record = execute_phases(
            recipe, output, jobs=args.jobs, record=record, completed_status="exporting"
        )
        if record["status"] != "exporting":
            return 1
        compdb = Path("/work/build/compile_commands.json")
        commands = json.loads(compdb.read_text())
        if not commands or not isinstance(commands, list):
            raise ValueError("Missing or empty compilation database")
        install = Path("/work/install")
        reports = report_paths(recipe)
        record["verification"] = validate_installation(Path("/work"), output, reports)
        shutil.copy2("/work/build/install_manifest.txt", output / "install_manifest.txt")
        shutil.copy2(compdb, output / "compile_commands.json")
        archive = output / "install-linux-x64.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(install, arcname="install")
        testing = Path("/work/build/Testing")
        if testing.is_dir():
            shutil.copytree(testing, output / "Testing", dirs_exist_ok=True)
        record.update(
            status="completed",
            translation_units=len(commands),
            artifacts={
                "install-linux-x64.tar.gz": file_hash(archive),
                "compile_commands.json": file_hash(output / "compile_commands.json"),
                "install_manifest.txt": file_hash(output / "install_manifest.txt"),
                **{path: file_hash(output / path) for path in reports},
            },
        )
    except Exception as exc:
        record.update(status="failed", error=str(exc))
        print(f"LIMA build failed: {exc}", flush=True)
    save_record(output, record)
    return 0 if record["status"] == "completed" else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path)
    selection = parser.add_mutually_exclusive_group()
    selection.add_argument("--recipe", type=Path, help="Custom full-build.json")
    selection.add_argument("--project", help="Built-in project, see --list")
    parser.add_argument("--list", action="store_true", help="List built-in full-build recipes")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--jobs", type=int, default=6)
    parser.add_argument(
        "--volume", help="Reuse only with identical source revision, recipe and image"
    )
    parser.add_argument("--skip-image-build", action="store_true")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--revision", help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.list:
        for name, path in project_catalog().items():
            print(f"{name}\t{path}")
        return 0
    if not 1 <= args.jobs <= 16:
        parser.error("--jobs must be between 1 and 16")
    if args.worker:
        return worker_main(args)
    if args.project:
        try:
            args.recipe = resolve_project(args.project)
        except ValueError as exc:
            parser.error(str(exc))
    if any(value is None for value in (args.source, args.recipe, args.output)):
        parser.error("--source, --output and either --project or --recipe are required")
    source, recipe_path, output = (
        path.resolve() for path in (args.source, args.recipe, args.output)
    )
    if source == output or source in output.parents or output in source.parents:
        parser.error("Output and original source must be separate directories")
    recipe = validate_recipe(json.loads(recipe_path.read_text(encoding="utf8")))
    revision = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    if subprocess.check_output(
        ["git", "-C", str(source), "status", "--porcelain"], text=True
    ).strip():
        parser.error(
            "Source is dirty; refusing to silently omit uncommitted files from the pinned build"
        )
    try:
        prepare_output(output)
    except ValueError as exc:
        parser.error(str(exc))
    if not args.skip_image_build:
        with (output / "image-build.log").open("w", encoding="utf8") as log:
            result = subprocess.run(
                ["docker", "build", "-t", recipe["image"], str(recipe_path.parent)],
                stdout=log,
                stderr=subprocess.STDOUT,
                check=False,
            )
        if result.returncode:
            record_image_failure(output, recipe, revision, result.returncode)
            print(f"Image build failed; see {output / 'image-build.log'}", flush=True)
            return 1
    image_id = subprocess.check_output(
        ["docker", "image", "inspect", recipe["image"], "--format", "{{.Id}}"], text=True
    ).strip()
    suffix = uuid.uuid4().hex[:12]
    name, volume = "lima-build-" + suffix, args.volume or "lima-build-" + suffix
    subprocess.run(["docker", "volume", "create", volume], check=True)
    invocation = {
        "source": str(source),
        "revision": revision,
        "image": recipe["image"],
        "image_id": image_id,
        "recipe_sha256": file_hash(recipe_path),
        "worker_sha256": file_hash(Path(__file__)),
        "recipe": recipe,
        "jobs": args.jobs,
        "container": name,
        "volume": volume,
    }
    (output / "invocation.json").write_text(json.dumps(invocation, indent=2), encoding="utf8")
    command = container_command(
        image=image_id,
        name=name,
        volume=volume,
        source=source,
        output=output,
        recipe=recipe_path,
        worker=Path(__file__).resolve(),
        revision=revision,
        jobs=args.jobs,
    )
    print(f"LIMA build container={name} volume={volume} output={output}", flush=True)
    try:
        result = subprocess.run(command, check=False)
    except KeyboardInterrupt:
        subprocess.run(["docker", "stop", "--timeout", "10", name], check=False)
        mark_interrupted(output)
        return 130
    result_path = output / "build-result.json"
    if result.returncode or not result_path.is_file():
        mark_container_failure(output, result.returncode or 1)
        return result.returncode or 1
    record = json.loads(result_path.read_text(encoding="utf8"))
    print(f"LIMA build status={record['status']}", flush=True)
    return 0 if record["status"] == "completed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
