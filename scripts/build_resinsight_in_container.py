"""Historical standalone build runner; retained for existing containers only.

New builds use ``python -m lima.container_build --project resinsight`` with
``deploy/build-recipes/resinsight/full-build.json``. Do not add features here.

Mount the original repository read-only at /input and a dedicated volume at
/work. This operational runner never writes the original checkout.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", required=True)
    parser.add_argument("--jobs", type=int, default=4)
    args = parser.parse_args()
    work = Path("/work")
    source = work / "src"
    logs = work / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    for directory in ("home", "downloads", "vcpkg-cache"):
        (work / directory).mkdir(exist_ok=True)
    os.environ.update({
        "HOME": str(work / "home"), "GIT_TERMINAL_PROMPT": "0",
        "VCPKG_DISABLE_METRICS": "1", "VCPKG_MAX_CONCURRENCY": str(args.jobs),
        "VCPKG_BINARY_SOURCES": "clear;files,/work/vcpkg-cache,readwrite",
        "VCPKG_DOWNLOADS": "/work/downloads", "CMAKE_BUILD_PARALLEL_LEVEL": str(args.jobs),
        "CC": "gcc", "CXX": "g++",
        "QT_PLUGIN_PATH": "/usr/lib/x86_64-linux-gnu/qt6/plugins",
        "QT_QPA_PLATFORM": "offscreen", "LANG": "C.UTF-8", "OMP_NUM_THREADS": "2",
    })
    record = {"revision": args.revision, "jobs": args.jobs, "steps": [], "status": "running"}

    def save() -> None:
        (work / "build-result.json").write_text(json.dumps(record, indent=2), encoding="utf8")

    def run(name: str, command: list[str], cwd: Path = work, timeout: int = 7200) -> None:
        entry = {"name": name, "command": command, "status": "running", "log": str(logs / (name + ".log"))}
        record["steps"].append(entry)
        save()
        print(json.dumps(entry), flush=True)
        started = time.monotonic()
        try:
            with Path(entry["log"]).open("w", encoding="utf8") as log:
                result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, timeout=timeout)
            entry["returncode"] = result.returncode
            entry["status"] = "completed" if result.returncode == 0 else "failed"
            if result.returncode:
                raise RuntimeError(f"{name} returned {result.returncode}")
        except Exception as exc:
            entry["status"] = "failed"
            entry["error"] = str(exc)
            record["status"] = "failed"
            print(Path(entry["log"]).read_text(encoding="utf8", errors="replace")[-12000:], flush=True)
            raise
        finally:
            entry["seconds"] = round(time.monotonic() - started, 2)
            save()

    try:
        if not (source / ".git").exists():
            run("clone-local", ["git", "-c", "safe.directory=/input", "clone", "--no-hardlinks", "--no-checkout", "/input", str(source)])
        run("checkout", ["git", "checkout", "--detach", args.revision], source)
        run("submodules", ["git", "submodule", "update", "--init", "--recursive", "--jobs", str(args.jobs)], source)
        run("submodule-revisions", ["git", "submodule", "status", "--recursive"], source)
        if not (source / "ThirdParty/vcpkg/vcpkg").is_file():
            run("bootstrap-vcpkg", ["bash", "ThirdParty/vcpkg/bootstrap-vcpkg.sh", "-disableMetrics"], source)
        run("configure", [
            "cmake", "-S", str(source), "-B", "/work/build", "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=Release", "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
            "-DCMAKE_INSTALL_PREFIX=/work/install",
            "-DCMAKE_TOOLCHAIN_FILE=/work/src/ThirdParty/vcpkg/scripts/buildsystems/vcpkg.cmake",
            "-DVCPKG_TARGET_TRIPLET=x64-linux-release", "-DVCPKG_HOST_TRIPLET=x64-linux-release",
            "-DRESINSIGHT_ENABLE_GRPC=OFF", "-DRESINSIGHT_ENABLE_OPENVDS=OFF",
            "-DRESINSIGHT_ENABLE_HDF5=OFF", "-DRESINSIGHT_DOWNLOAD_ODB_FROM_SERVER=OFF",
            "-DRESINSIGHT_USE_EXTERNAL_OCTAVE_PLUGINS=OFF", "-DRESINSIGHT_BUILD_DOCUMENTATION=OFF",
            "-DRESINSIGHT_ENABLE_UNITY_BUILD=OFF", "-DRESINSIGHT_ENABLE_PRECOMPILED_HEADERS=OFF",
            "-DRESINSIGHT_UPDATE_SUBMODULES=OFF", "-DRESINSIGHT_INCLUDE_APPLICATION_UNIT_TESTS=ON",
            "-DRESINSIGHT_TREAT_WARNINGS_AS_ERRORS=OFF",
        ], source, timeout=10800)
        run("build", ["cmake", "--build", "/work/build", "--parallel", str(args.jobs)], timeout=21600)
        run("install", ["cmake", "--install", "/work/build"], timeout=1800)
        run("list-tests", ["ctest", "--test-dir", "/work/build/ApplicationLibCode/UnitTests", "-N"], timeout=120)
        run("application-tests", ["ctest", "--test-dir", "/work/build/ApplicationLibCode/UnitTests",
                                  "--output-on-failure", "--timeout", "600"], timeout=900)
        for test_name in ("roffcpp-tests", "regression-analysis-tests", "opm-parser-tests", "openzgy-tests"):
            run(test_name, [str(work / "build" / test_name)], work / "build", timeout=900)
        run("version", ["/work/install/bin/ResInsight", "--console", "--version"], timeout=120)
        run("ldd", ["ldd", "/work/install/bin/ResInsight"], timeout=120)
        if "not found" in (logs / "ldd.log").read_text(encoding="utf8"):
            raise RuntimeError("Installed ResInsight has unresolved dynamic libraries; see ldd.log")
        run("source-copy-status", ["git", "status", "--short"], source, timeout=120)
        record["status"] = "completed"
        save()
        return 0
    except Exception as exc:
        record["status"] = "failed"
        record["error"] = str(exc)
        save()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
