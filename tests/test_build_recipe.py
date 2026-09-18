"""Declarative build recipe parsing and container execution tests (workstream A, task A2).

A build recipe is the ``recipe.yaml`` contract plus the executor that drives a
per-repository build container.  The executor talks to containers exclusively
through an injected runner, so these tests never invoke Docker: a fake runner
serves the compilation database, the generated headers and the vendored
include-root listings.  The tests freeze the recipe schema validation (strict
keys and path safety), the referenced-header collection filter and the
fail-closed orchestration whose output A1's ``read_package`` fully verifies.
"""

import json
import re
import tempfile
import unittest
from pathlib import Path

from lima.build_recipe import (
    BuildRecipe,
    BuildRecipeError,
    IncludeRoot,
    MountSpec,
    collect_referenced_headers,
    run_recipe_in_container,
)
from lima.context_package import read_package

RECIPE_YAML = """\
schema_version: 1
name: resinsight-fake
image: lima-builder-fake:latest
repository: OPM/ResInsight
source_mount: /src
configure:
  - ["cmake", "-S", ".", "-B", "build",
     "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
     "-DCMAKE_BUILD_TYPE=Debug"]
compdb_path: "build/compile_commands.json"
generated_globs:
  - "build/*.h"
include_roots:
  - {container: "/usr/include/qt5", package: "headers/qt5"}
  - {container: "/usr/include/hdf5", package: "headers/hdf5"}
"""


def make_recipe() -> BuildRecipe:
    return BuildRecipe.from_yaml(RECIPE_YAML)


def make_container_compdb() -> list[dict]:
    """One entry exactly as CMake exports it inside the container: absolute
    ``directory``/``file``/``output`` paths, the source-mount prefix on the
    build include flag, and vendored absolute include flags."""

    return [
        {
            "directory": "/src/ApplicationLibCode/FileInterface",
            "arguments": [
                "/usr/bin/c++",
                "-std=c++17",
                "-I/usr/include/qt5/QtCore",
                "-isystem",
                "/usr/include/hdf5/serial",
                "-I/src/build",
                "-include",
                "/usr/include/qt5/QtGui/qwidget.h",
                "-c",
                "/src/ApplicationLibCode/FileInterface/RifActiveCellsReader.cpp",
                "-o",
                "/src/build/CMakeFiles/ri.dir/RifActiveCellsReader.cpp.o",
            ],
            "file": "/src/ApplicationLibCode/FileInterface/RifActiveCellsReader.cpp",
            "output": "/src/build/CMakeFiles/ri.dir/RifActiveCellsReader.cpp.o",
        }
    ]


def make_container_files() -> dict[str, bytes]:
    """The fake container filesystem the recipe consumes."""

    return {
        "/src/build/config.h": b"#define RI_VERSION 1\n",
        # qt5 root: only QtCore is referenced as a directory; QtGui/qwidget.h
        # is referenced directly via -include; qpainter.h and README are not.
        "/usr/include/qt5/QtCore/qstring.h": b"// qstring\n",
        "/usr/include/qt5/QtCore/qcoreevent.h": b"// qcoreevent\n",
        "/usr/include/qt5/QtGui/qwidget.h": b"// qwidget\n",
        "/usr/include/qt5/QtGui/qpainter.h": b"// qpainter\n",
        "/usr/include/qt5/README": b"not vendored\n",
        # hdf5 root: both files live under the referenced serial directory.
        "/usr/include/hdf5/serial/hdf5.h": b"// hdf5\n",
        "/usr/include/hdf5/serial/H5api.h": b"// h5api\n",
    }


def glob_regex(pattern: str) -> re.Pattern[str]:
    """Translate a container glob (``*``, ``**``, ``?``) to a regex."""

    parts: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char == "*" and index + 1 < len(pattern) and pattern[index + 1] == "*":
            parts.append(".*")
            index += 2
            continue
        if char == "*":
            parts.append("[^/]*")
        elif char == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(char))
        index += 1
    return re.compile("".join(parts) + r"\Z")


class FakeContainerRunner:
    """In-memory ContainerRunner: zero Docker, mirroring the production contract."""

    def __init__(self, files: dict[str, bytes], *, configure_rc: int = 0) -> None:
        self.files: dict[str, bytes] = dict(files)
        self.configure_rc = configure_rc
        self.runs: list[tuple[tuple[str, ...], tuple[MountSpec, ...]]] = []

    def run(self, argv, mounts) -> tuple[int, str]:
        self.runs.append((tuple(argv), tuple(mounts)))
        if self.configure_rc != 0:
            return self.configure_rc, ""
        # The configure step exports the compilation database into the mount.
        self.files["/src/build/compile_commands.json"] = json.dumps(
            make_container_compdb()
        ).encode("utf-8")
        return 0, "configured"

    def read_file(self, container_path: str) -> bytes:
        try:
            return self.files[container_path]
        except KeyError as exc:
            raise BuildRecipeError(f"container-read-failed:{container_path}") from exc

    def list_globs(self, pattern: str) -> list[str]:
        regex = glob_regex(pattern)
        return sorted(path for path in self.files if regex.match(path))


class RecipeParsingTest(unittest.TestCase):
    def test_recipe_yaml_parses_and_validates(self) -> None:
        recipe = BuildRecipe.from_yaml(RECIPE_YAML)

        self.assertEqual(recipe.schema_version, 1)
        self.assertEqual(recipe.name, "resinsight-fake")
        self.assertEqual(recipe.image, "lima-builder-fake:latest")
        self.assertEqual(recipe.repository, "OPM/ResInsight")
        self.assertEqual(recipe.source_mount, "/src")
        self.assertEqual(
            recipe.configure,
            (
                (
                    "cmake",
                    "-S",
                    ".",
                    "-B",
                    "build",
                    "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",
                    "-DCMAKE_BUILD_TYPE=Debug",
                ),
            ),
        )
        self.assertEqual(recipe.compdb_path, "build/compile_commands.json")
        self.assertEqual(recipe.generated_globs, ("build/*.h",))
        self.assertEqual(
            recipe.include_roots,
            (
                IncludeRoot(container="/usr/include/qt5", package="headers/qt5"),
                IncludeRoot(container="/usr/include/hdf5", package="headers/hdf5"),
            ),
        )

        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recipe.yaml"
            path.write_text(RECIPE_YAML, encoding="utf-8")
            self.assertEqual(BuildRecipe.from_file(path), recipe)

    def test_recipe_rejects_unknown_keys(self) -> None:
        with self.assertRaises(BuildRecipeError) as caught:
            BuildRecipe.from_yaml(RECIPE_YAML + "\nextra_key: 1\n")
        self.assertIn("recipe-field-unknown", caught.exception.reason)

        bad_root = RECIPE_YAML.replace(
            '{container: "/usr/include/qt5", package: "headers/qt5"}',
            '{container: "/usr/include/qt5", package: "headers/qt5", extra: 1}',
        )
        with self.assertRaises(BuildRecipeError) as caught_root:
            BuildRecipe.from_yaml(bad_root)
        self.assertIn("include-root-unknown-key", caught_root.exception.reason)

    def test_recipe_rejects_bad_paths(self) -> None:
        cases = {
            "schema-version-unsupported": ("schema_version: 1", "schema_version: 2"),
            "source-mount-relative": ('source_mount: /src', 'source_mount: "src"'),
            "compdb-path-absolute": (
                'compdb_path: "build/compile_commands.json"',
                'compdb_path: "/build/compile_commands.json"',
            ),
            "compdb-path-escape": (
                'compdb_path: "build/compile_commands.json"',
                'compdb_path: "../escape.json"',
            ),
            "generated-glob-absolute": (
                '- "build/*.h"', '- "/build/*.h"'
            ),
            "include-root-container-relative": (
                '{container: "/usr/include/qt5", package: "headers/qt5"}',
                '{container: "usr/include/qt5", package: "headers/qt5"}',
            ),
            "include-root-package-escape": (
                '{container: "/usr/include/qt5", package: "headers/qt5"}',
                '{container: "/usr/include/qt5", package: "../evil"}',
            ),
            "include-root-package-reserved": (
                '{container: "/usr/include/qt5", package: "headers/qt5"}',
                '{container: "/usr/include/qt5", package: "generated/x"}',
            ),
            "include-root-inside-source-mount": (
                '{container: "/usr/include/qt5", package: "headers/qt5"}',
                '{container: "/src/thirdparty", package: "headers/thirdparty"}',
            ),
            "include-root-package-nested": (
                '{container: "/usr/include/hdf5", package: "headers/hdf5"}',
                '{container: "/usr/include/hdf5", package: "headers/qt5/deep"}',
            ),
            "duplicate-yaml-key": (
                'name: resinsight-fake', 'name: resinsight-fake\nname: other'
            ),
        }
        for label, (old, new) in cases.items():
            with self.subTest(label):
                self.assertNotEqual(old, new)
                with self.assertRaises(BuildRecipeError):
                    BuildRecipe.from_yaml(RECIPE_YAML.replace(old, new))

    def test_recipe_rejects_empty_configure(self) -> None:
        bad = RECIPE_YAML.replace(
            'configure:\n  - ["cmake", "-S", ".", "-B", "build",\n'
            '     "-DCMAKE_EXPORT_COMPILE_COMMANDS=ON",\n'
            '     "-DCMAKE_BUILD_TYPE=Debug"]\n',
            "configure: []\n",
        )
        self.assertNotEqual(bad, RECIPE_YAML)
        with self.assertRaises(BuildRecipeError):
            BuildRecipe.from_yaml(bad)


class CollectReferencedHeadersTest(unittest.TestCase):
    def test_collect_referenced_headers_filters_by_compdb(self) -> None:
        compdb = [
            {
                "directory": "/src/app",
                "arguments": [
                    "/usr/bin/c++",
                    "-I/usr/include/qt5/QtCore",
                    "-c",
                    "app/main.cpp",
                ],
                "file": "app/main.cpp",
            }
        ]
        roots = [
            IncludeRoot(container="/usr/include/qt5", package="headers/qt5"),
            IncludeRoot(container="/usr/include/hdf5", package="headers/hdf5"),
        ]
        root_files = {
            "/usr/include/qt5": [
                "QtCore/qstring.h",
                "QtCore/qglobal.h",
                "QtGui/qwidget.h",
                "zlib.h",
                "README",
            ],
            "/usr/include/hdf5": ["serial/hdf5.h"],
        }
        contents = {
            name: f"// {name}\n".encode()
            for listing in root_files.values()
            for name in listing
        }

        collected = collect_referenced_headers(
            json.dumps(compdb),
            roots,
            root_files,
            lambda path: contents[path.removeprefix("/usr/include/qt5/")],
        )

        # Five files live under the root; only the two under the referenced
        # QtCore directory are vendored, and the unreferenced hdf5 root
        # contributes nothing.
        self.assertEqual(
            sorted(collected),
            [
                "headers/qt5/QtCore/qglobal.h",
                "headers/qt5/QtCore/qstring.h",
            ],
        )
        self.assertEqual(
            collected["headers/qt5/QtCore/qstring.h"], b"// QtCore/qstring.h\n"
        )

    def test_collect_referenced_headers_direct_file_in_command_form(self) -> None:
        compdb = [
            {
                "directory": "/src/app",
                "command": (
                    "/usr/bin/c++ -include /usr/include/qt5/QtGui/qwidget.h "
                    "-c app/main.cpp"
                ),
                "file": "app/main.cpp",
            }
        ]
        root = IncludeRoot(container="/usr/include/qt5", package="headers/qt5")
        root_files = {"/usr/include/qt5": ["QtGui/qwidget.h", "QtGui/qpainter.h"]}

        collected = collect_referenced_headers(
            json.dumps(compdb), [root], root_files, lambda _path: b"x\n"
        )

        self.assertEqual(sorted(collected), ["headers/qt5/QtGui/qwidget.h"])


class RunRecipeTest(unittest.TestCase):
    def _write_source_tree(self, tmp: str) -> Path:
        source = Path(tmp) / "repo"
        unit_dir = source / "ApplicationLibCode" / "FileInterface"
        unit_dir.mkdir(parents=True)
        (unit_dir / "RifActiveCellsReader.cpp").write_text("int refactored;\n")
        return source

    def test_run_recipe_produces_valid_package(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self._write_source_tree(tmp)
            pkg_dir = Path(tmp) / "pkg"
            runner = FakeContainerRunner(make_container_files())

            manifest = run_recipe_in_container(
                make_recipe(),
                source,
                work_dir=pkg_dir,
                revision="0123456789abcdef0123456789abcdef01234567",
                container_runner=runner,
            )

            # A1's fail-closed reader accepts the produced package unchanged.
            package = read_package(pkg_dir)
            self.assertEqual(package.manifest, manifest)
            self.assertEqual(manifest.repository, "OPM/ResInsight")
            self.assertEqual(
                manifest.revision, "0123456789abcdef0123456789abcdef01234567"
            )
            self.assertEqual(manifest.created_by, "resinsight-fake")
            self.assertEqual(manifest.compdb.entry_count, 1)
            self.assertEqual(manifest.generated_headers, ("build/config.h",))
            self.assertEqual(manifest.header_roots, ("headers/hdf5", "headers/qt5"))
            self.assertEqual(manifest.totals.header_file_count, 5)

            # Configure ran once, in the container working directory, with the
            # source tree mounted at the recipe's source mount point.
            self.assertEqual(len(runner.runs), 1)
            argv, mounts = runner.runs[0]
            self.assertEqual(argv[0], "cmake")
            self.assertEqual(
                mounts,
                (MountSpec(str(source.resolve()).replace("\\", "/"), "/src"),),
            )

            # Referenced-directory + direct-file filter: QtCore (2 files) and
            # the -include forced qwidget.h are vendored; qpainter.h and the
            # root-level README are not.
            header_names = sorted(
                path.relative_to(pkg_dir).as_posix()
                for root in ("headers/hdf5", "headers/qt5")
                for path in (pkg_dir / root).rglob("*")
                if path.is_file()
            )
            self.assertEqual(
                header_names,
                [
                    "headers/hdf5/serial/H5api.h",
                    "headers/hdf5/serial/hdf5.h",
                    "headers/qt5/QtCore/qcoreevent.h",
                    "headers/qt5/QtCore/qstring.h",
                    "headers/qt5/QtGui/qwidget.h",
                ],
            )

    def test_rewrite_applied_to_compdb(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self._write_source_tree(tmp)
            pkg_dir = Path(tmp) / "pkg"

            run_recipe_in_container(
                make_recipe(),
                source,
                work_dir=pkg_dir,
                container_runner=FakeContainerRunner(make_container_files()),
            )

            entry = json.loads(
                (pkg_dir / "compile_commands.json").read_text(encoding="utf-8")
            )[0]
            arguments = entry["arguments"]
            self.assertIn("-Iheaders/qt5/QtCore", arguments)
            self.assertIn("headers/hdf5/serial", arguments)
            self.assertIn("headers/qt5/QtGui/qwidget.h", arguments)
            self.assertIn("-Ibuild", arguments)
            self.assertEqual(
                entry["file"],
                "ApplicationLibCode/FileInterface/RifActiveCellsReader.cpp",
            )
            self.assertEqual(
                entry["directory"], "ApplicationLibCode/FileInterface"
            )
            text = json.dumps(entry)
            self.assertNotIn("/src", text)
            self.assertNotIn("/usr/include", text)

    def test_configure_failure_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            source = self._write_source_tree(tmp)
            pkg_dir = Path(tmp) / "pkg"
            runner = FakeContainerRunner(
                make_container_files(), configure_rc=127
            )

            with self.assertRaises(BuildRecipeError) as caught:
                run_recipe_in_container(
                    make_recipe(), source, work_dir=pkg_dir, container_runner=runner
                )
            self.assertIn("configure-command-failed", caught.exception.reason)

            # Fail closed: no partial package, no further container calls.
            self.assertFalse(pkg_dir.exists())
            self.assertEqual(len(runner.runs), 1)


if __name__ == "__main__":
    unittest.main()
