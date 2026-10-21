"""Synthetic, test-first contract for the independent Issue #313 exporter."""

from __future__ import annotations

import contextlib
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lima import competition_environment as env


SECRET = "SYNTHETIC_PRIVATE_SENTINEL_313"
COMMIT = "a" * 40
IMAGE = "sha256:" + "b" * 64


class EnvironmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.output = self.root / "environment.json"
        self.calls = []
        self.status = b""
        self.inspect = {"image_id": IMAGE, "image_reference": "registry.example/lima:v1",
                        "limits": {"nano_cpus": 2000000000, "cpu_period": 0,
                                   "cpu_quota": 0, "cpuset_cpus": "0-1",
                                   "memory_bytes": 536870912, "memory_swap_bytes": -1,
                                   "pids_limit": 128}}

    def command(self, argv, *, cwd=None):
        self.calls.append((argv, cwd))
        if argv[0] == "git" and argv[-1] == "--is-inside-work-tree":
            return b"true\n", None
        if argv[0] == "git" and argv[-1] == "--show-toplevel":
            return str(self.repo).encode("utf-8") + b"\n", None
        if argv[0] == "git" and argv[-1] == "HEAD":
            return COMMIT.encode() + b"\n", None
        if argv[0] == "git" and "status" in argv:
            return self.status, None
        if argv[0] == "docker":
            return json.dumps(self.inspect).encode(), None
        versions = {"git": b"git version 2.43.0\n",
                    "clang": b"clang version 18.1.2\n",
                    "clang-14": b"Debian clang version 14.0.6\n",
                    "cmake": b"cmake version 3.25.1\n"}
        return versions[argv[0]], None

    def run_cli(self, *extra, command=None):
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.object(env, "_command", side_effect=command or self.command), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            code = env.main(["--repository", str(self.repo), "--run-label", "synthetic-313",
                             "--output", str(self.output), *extra])
        self.console = stdout.getvalue() + stderr.getvalue()
        return code

    def document(self):
        return json.loads(self.output.read_text(encoding="utf-8"))

    def test_minimal_manifest_clean_and_no_docker(self):
        self.assertEqual(self.run_cli(), 0)
        data = self.document()
        self.assertEqual(data["schema_version"], 1)
        self.assertEqual(data["run_label"], "synthetic-313")
        self.assertRegex(data["generated_at_utc"], r"^\d{4}-\d\d-\d\dT.*Z$")
        self.assertEqual(data["source"]["commit"], COMMIT)
        self.assertIs(data["source"]["dirty"], False)
        self.assertIsNone(data["host"]["memory_total_bytes"])
        self.assertTrue(data["host"]["memory_reason"])
        self.assertFalse(any(argv[0] == "docker" for argv, _ in self.calls))
        self.assertEqual(data["container"]["reason"], "not_selected")
        self.assertIn("not_a_dependency_lock_or_health_check", data["limitations"])

    def test_dirty_tracked_and_untracked_without_filenames(self):
        for status in (b" M tracked.py\n", b"?? " + SECRET.encode() + b"\n"):
            with self.subTest(status=status):
                self.status = status
                self.assertEqual(self.run_cli(), 0)
                self.assertIs(self.document()["source"]["dirty"], True)
                self.assertNotIn(SECRET, self.output.read_text())
                self.output.unlink()
        commands = [argv for argv, _ in self.calls if "status" in argv]
        self.assertTrue(all("--untracked-files=all" in argv for argv in commands))
        self.assertTrue(all("core.fsmonitor=false" in argv for argv in commands))

    def test_missing_git_unknown_never_clean(self):
        def missing(argv, **kwargs):
            return (None, "not_found") if argv[0] == "git" else self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=missing), 0)
        data = self.document()["source"]
        self.assertIsNone(data["commit"])
        self.assertIsNone(data["dirty"])
        self.assertEqual(data["unknown_reasons"]["dirty"], "not_found")

    def test_git_status_failure_commit_failure_and_bad_commit(self):
        for failure in ("timeout", "permission_denied", "nonzero_exit", "output_limit"):
            with self.subTest(failure=failure):
                def failed(argv, **kwargs):
                    if "status" in argv or argv[-1] == "HEAD":
                        return None, failure
                    return self.command(argv, **kwargs)
                self.assertEqual(self.run_cli(command=failed), 0)
                self.assertIsNone(self.document()["source"]["dirty"])
                self.assertIsNone(self.document()["source"]["commit"])
                self.output.unlink()
        def bad(argv, **kwargs):
            return (SECRET.encode(), None) if argv[-1] == "HEAD" else self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=bad), 0)
        self.assertIsNone(self.document()["source"]["commit"])
        self.assertNotIn(SECRET, self.output.read_text())

    def test_missing_or_nonrepository_input_exit_two(self):
        self.repo.rmdir()
        self.assertEqual(self.run_cli(), 2)
        self.assertFalse(self.output.exists())
        self.repo.mkdir()
        def not_repo(argv, **kwargs):
            if argv[-1] == "--is-inside-work-tree":
                return None, "nonzero_exit"
            return self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=not_repo), 2)
        self.assertFalse(self.output.exists())

    def test_host_tool_failures_and_only_version_projection(self):
        for failure in ("not_found", "timeout", "permission_denied", "output_limit"):
            with self.subTest(failure=failure):
                def failed(argv, **kwargs):
                    if argv == ["cmake", "--version"]:
                        return None, failure
                    if argv == ["clang", "--version"]:
                        return b"clang version 18.1.2\n" + SECRET.encode(), None
                    return self.command(argv, **kwargs)
                self.assertEqual(self.run_cli(command=failed), 0)
                tools = self.document()["host_tools"]
                self.assertIsNone(tools["cmake"]["version"])
                self.assertEqual(tools["cmake"]["reason"], failure)
                self.assertEqual(tools["clang"]["version"], "18.1.2")
                self.assertTrue(all(v["source"] == "host" for v in tools.values()))
                self.assertNotIn(SECRET, self.output.read_text() + self.console)
                self.output.unlink()

    def test_unrecognized_version_not_copied(self):
        def malicious(argv, **kwargs):
            if argv == ["clang", "--version"]:
                return (SECRET + " /private/path clang version 18.1.2").encode(), None
            return self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=malicious), 0)
        self.assertIsNone(self.document()["host_tools"]["clang"]["version"])
        self.assertNotIn(SECRET, self.output.read_text())

    def test_docker_exact_selection_projection_and_separate_identity(self):
        self.assertEqual(self.run_cli("--container", "synthetic-sidecar"), 0)
        docker_calls = [argv for argv, _ in self.calls if argv[0] == "docker"]
        self.assertEqual(len(docker_calls), 1)
        argv = docker_calls[0]
        self.assertEqual(argv[:3], ["docker", "inspect", "--type=container"])
        self.assertEqual(argv[-2:], ["--", "synthetic-sidecar"])
        self.assertNotIn("Env", " ".join(argv))
        self.assertNotIn("Mounts", " ".join(argv))
        data = self.document()
        self.assertEqual(data["container"]["image_id"], IMAGE)
        self.assertEqual(data["container"]["limits"], self.inspect["limits"])
        self.assertEqual(data["container"]["tool_versions"], "unknown")
        self.assertEqual(data["host_tools"]["clang-14"]["source"], "host")

    def test_optional_docker_missing_denied_timeout(self):
        for reason in ("not_found", "permission_denied", "nonzero_exit", "timeout"):
            with self.subTest(reason=reason):
                def failed(argv, **kwargs):
                    return (None, reason) if argv[0] == "docker" else self.command(argv, **kwargs)
                self.assertEqual(self.run_cli("--container", "one", command=failed), 0)
                self.assertEqual(self.document()["container"]["reason"], reason)
                self.assertIsNone(self.document()["container"]["image_id"])
                self.output.unlink()

    def test_inspect_extra_secret_fields_never_accessed(self):
        self.inspect.update(Env=[SECRET], Mounts=[{"Source": SECRET}], extra=SECRET)
        self.assertEqual(self.run_cli("--container", "one"), 0)
        text = self.output.read_text() + self.console
        self.assertNotIn(SECRET, text)
        self.assertNotIn("Mounts", text)
        self.assertNotIn('"Env"', text)

    def test_bad_docker_data_and_image_references_are_not_reflected(self):
        for reference in ("https://user:password@registry/repo", "repo:tag?token=" + SECRET,
                          "repo:tag\n" + SECRET, "repo:sk-secret", "/private/" + SECRET):
            with self.subTest(reference=reference):
                self.inspect["image_reference"] = reference
                self.assertEqual(self.run_cli("--container", "one"), 0)
                self.assertIsNone(self.document()["container"]["image_reference"])
                self.assertEqual(self.document()["container"]["reason"], "invalid_projection")
                self.assertNotIn(SECRET, self.output.read_text() + self.console)
                self.output.unlink()
        self.inspect["image_reference"] = "lima:local"
        self.inspect["limits"]["memory_bytes"] = SECRET
        self.assertEqual(self.run_cli("--container", "one"), 0)
        self.assertEqual(self.document()["container"]["reason"], "invalid_projection")

    def test_invalid_inspect_json_duplicate_keys_and_nonfinite(self):
        for raw in (b"not json " + SECRET.encode(), b'[]',
                    b'{"image_id":"a","image_id":"b"}', b'{"limits":NaN}'):
            def invalid(argv, **kwargs):
                return (raw, None) if argv[0] == "docker" else self.command(argv, **kwargs)
            self.assertEqual(self.run_cli("--container", "one", command=invalid), 0)
            self.assertEqual(self.document()["container"]["reason"], "invalid_projection")
            self.assertNotIn(SECRET, self.output.read_text() + self.console)
            self.output.unlink()

    def test_model_is_only_operator_declared(self):
        self.assertEqual(self.run_cli("--model-label", "operator-model-v1"), 0)
        self.assertEqual(self.document()["model"], {
            "label": "operator-model-v1", "source": "operator-declared",
            "backend_version": "unknown"})

    def test_malicious_arguments_exit_three_no_reflection_or_commands(self):
        for option in ("--run-label", "--model-label", "--container"):
            for value in ("../" + SECRET, "https://u:p@host?q=" + SECRET,
                          "ok\n" + SECRET, "sk-" + SECRET, "--all", "\ud800"):
                with self.subTest(option=option, value=repr(value)):
                    self.assertEqual(self.run_cli(option + "=" + value), 3)
                    self.assertFalse(self.output.exists())
                    self.assertNotIn(SECRET, self.console)
                    self.assertEqual(self.calls, [])

    def test_usage_errors_do_not_reflect_input(self):
        for args in (["--unknown=" + SECRET], ["--repository"], []):
            out = io.StringIO()
            with contextlib.redirect_stderr(out), contextlib.redirect_stdout(out):
                self.assertEqual(env.main(args), 3)
            self.assertNotIn(SECRET, out.getvalue())

    def test_output_conflict_missing_parent_and_inside_repository(self):
        self.output.write_text(SECRET)
        self.assertEqual(self.run_cli(), 3)
        self.assertEqual(self.output.read_text(), SECRET)
        self.assertEqual(self.calls, [])
        self.output = self.root / "missing" / "new.json"
        self.assertEqual(self.run_cli(), 3)
        self.output = self.repo / "new.json"
        self.assertEqual(self.run_cli(), 3)
        self.assertFalse(self.output.exists())

    def assert_output_permission_failure_sanitized(self):
        target = self.output.resolve()
        original = Path.open
        def denied(path, *args, **kwargs):
            if path.resolve() == target:
                raise PermissionError(SECRET)
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", denied):
            self.assertEqual(self.run_cli(), 3)
        self.assertFalse(target.exists())
        self.assertNotIn(SECRET, self.console)

    def test_output_permission_failure_sanitized(self):
        self.assert_output_permission_failure_sanitized()

    def test_output_permission_failure_with_noncanonical_path(self):
        self.output = self.repo / ".." / "environment.json"
        self.assert_output_permission_failure_sanitized()

    def test_no_environment_or_configuration_reads(self):
        (self.repo / ".env").write_text(SECRET)
        (self.repo / "config.toml").write_text(SECRET)
        original = Path.open
        def guard(path, *args, **kwargs):
            if path.name in (".env", "config.toml", "credentials"):
                self.fail("configuration read")
            return original(path, *args, **kwargs)
        with patch.object(Path, "open", guard), \
                patch.object(env.os, "environ", new={}):
            self.assertEqual(self.run_cli(), 0)
        text = self.output.read_text() + self.console
        for sensitive in (SECRET, str(self.root), str(self.repo), "sys.path", "hostname"):
            self.assertNotIn(sensitive, text)

    def test_command_missing_denied_timeout_and_large_output(self):
        for exception, reason in ((FileNotFoundError(SECRET), "not_found"),
                                  (PermissionError(SECRET), "permission_denied")):
            with patch.object(env.subprocess, "Popen", side_effect=exception):
                self.assertEqual(env._command(["git", "--version"]), (None, reason))
        with patch.object(env, "COMMAND_TIMEOUT", 0.15):
            self.assertEqual(env._command([sys.executable, "-c", "import time; time.sleep(5)"]),
                             (None, "timeout"))
        raw, reason = env._command([sys.executable, "-c", "print('x'*100000)"])
        self.assertIsNone(raw)
        self.assertEqual(reason, "output_limit")

    def test_command_uses_argv_no_shell_and_never_stderr(self):
        raw, reason = env._command([sys.executable, "-c",
                                   "import sys; print('ok'); print('" + SECRET
                                   + "', file=sys.stderr)"])
        self.assertEqual((raw.splitlines(), reason), ([b"ok"], None))
        with patch.object(env.subprocess, "Popen", side_effect=FileNotFoundError()) as popen:
            env._command(["git", "--version"])
        self.assertIs(popen.call_args.kwargs["shell"], False)
        self.assertIs(popen.call_args.kwargs["stderr"], subprocess.DEVNULL)

    def test_actual_script_entrypoint(self):
        script = Path(__file__).resolve().parents[1] / "scripts/export_competition_environment.py"
        # The fixed Docker test image includes lima/, but not this optional script.
        entry = [str(script)] if script.is_file() else ["-m", "lima.competition_environment"]
        result = subprocess.run([sys.executable, *entry, "--unknown=" + SECRET],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)

    def test_module_entrypoint_without_standalone_script(self):
        result = subprocess.run([sys.executable, "-m", "lima.competition_environment",
                                 "--unknown=" + SECRET],
                                capture_output=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 3)
        self.assertNotIn(SECRET.encode(), result.stdout + result.stderr)

    def test_real_git_roundtrip_input_bytes_unchanged(self):
        if shutil.which("git") is None:
            self.skipTest("git not installed; missing-git behavior tested separately")
        hooks = self.root / "empty-hooks"
        hooks.mkdir()
        def git(*args):
            return subprocess.run([
                "git", "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
                "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(hooks),
                "-c", "init.templateDir=", *args,
            ], cwd=self.repo, check=True, capture_output=True, timeout=10)
        git("init", "-q")
        tracked = self.repo / "tracked.txt"
        tracked.write_text("synthetic\n")
        git("add", "tracked.txt")
        git("commit", "-qm", "synthetic baseline")
        untracked = self.repo / "private-untracked.txt"
        real_command = env._command
        def no_docker(argv, **kwargs):
            self.assertNotEqual(argv[0], "docker")
            return real_command(argv, **kwargs)
        def digest():
            return {str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
                    for p in self.repo.rglob("*") if p.is_file()}
        for index, expected in enumerate((False, True, False, True)):
            if index == 1:
                untracked.write_text(SECRET)
            if index == 2:
                untracked.unlink()
            if index == 3:
                tracked.write_text("changed\n")
            before = digest()
            self.output = self.root / ("actual-" + str(index) + ".json")
            self.assertEqual(self.run_cli(command=no_docker), 0)
            self.assertIs(self.document()["source"]["dirty"], expected)
            self.assertRegex(self.document()["source"]["commit"], r"^[0-9a-f]{40,64}$")
            self.assertEqual(before, digest())
            self.assertNotIn(SECRET, self.output.read_text() + self.console)

    def test_real_nonzero_exit_does_not_return_output(self):
        raw, reason = env._command([sys.executable, "-c",
                                   "print('" + SECRET + "'); raise SystemExit(4)"])
        self.assertEqual((raw, reason), (None, "nonzero_exit"))

    def git_fixture(self, repository, *args):
        return subprocess.run([
            "git", "-c", "user.name=Synthetic", "-c", "user.email=synthetic@example.invalid",
            "-c", "commit.gpgsign=false", "-c", "core.hooksPath=" + str(self.root / "no-hooks"),
            "-c", "init.templateDir=", *args,
        ], cwd=repository, check=True, capture_output=True, timeout=10)

    def init_git_fixture(self, repository, content):
        if shutil.which("git") is None:
            self.skipTest("git not installed; missing-git behavior tested separately")
        self.git_fixture(repository, "init", "-q")
        (repository / "tracked.txt").write_text(content)
        self.git_fixture(repository, "add", "tracked.txt")
        self.git_fixture(repository, "commit", "-qm", content)
        return self.git_fixture(repository, "rev-parse", "HEAD").stdout.decode().strip()

    def test_inherited_git_directory_cannot_impersonate_selected_repository(self):
        expected = self.init_git_fixture(self.repo, "repository A\n")
        other = self.root / "other"
        other.mkdir()
        unexpected = self.init_git_fixture(other, "repository B\n")
        self.assertNotEqual(expected, unexpected)
        with patch.dict(os.environ, GIT_DIR=str(other / ".git"), GIT_WORK_TREE=str(self.repo)):
            self.assertEqual(self.run_cli(command=env._command), 0)
        self.assertEqual(self.document()["source"], {
            "commit": expected, "dirty": False, "unknown_reasons": {}})
        self.assertNotIn(str(other), self.output.read_text() + self.console)

    def test_inherited_git_index_cannot_override_selected_repository_status(self):
        expected = self.init_git_fixture(self.repo, "repository A\n")
        alternate = self.root / "alternate-index"
        with patch.dict(os.environ, GIT_INDEX_FILE=str(alternate)):
            self.git_fixture(self.repo, "read-tree", "--empty")
        index_before = (self.repo / ".git/index").read_bytes()
        alternate_before = alternate.read_bytes()
        with patch.dict(os.environ, GIT_INDEX_FILE=str(alternate)):
            source = env._source(self.repo.resolve())
        self.assertEqual(source, {"commit": expected, "dirty": False, "unknown_reasons": {}})
        self.assertEqual(index_before, (self.repo / ".git/index").read_bytes())
        self.assertEqual(alternate_before, alternate.read_bytes())

    def test_linked_git_worktree_retains_its_own_head_and_status(self):
        primary = self.init_git_fixture(self.repo, "primary worktree\n")
        linked = self.root / "linked"
        self.git_fixture(self.repo, "worktree", "add", "-qb", "synthetic-linked", str(linked))
        self.git_fixture(linked, "commit", "--allow-empty", "-qm", "linked HEAD")
        expected = self.git_fixture(linked, "rev-parse", "HEAD").stdout.decode().strip()
        self.assertNotEqual(primary, expected)
        self.assertTrue((linked / ".git").is_file())
        self.assertEqual(env._source(linked.resolve()), {
            "commit": expected, "dirty": False, "unknown_reasons": {}})
        (linked / "untracked.txt").write_text(SECRET)
        self.assertEqual(env._source(linked.resolve()), {
            "commit": expected, "dirty": True, "unknown_reasons": {}})

    def test_git_subprocess_environment_is_allowlisted_without_enumeration(self):
        class LaunchEnvironment(dict):
            def get(self, key, default=None):
                if key not in ("PATH", "SystemRoot", "TEMP", "TMP", "HOME", "USERPROFILE",
                               "XDG_CONFIG_HOME"):
                    raise AssertionError("unexpected environment lookup")
                return super().get(key, default)

            def __iter__(self):
                raise AssertionError("environment enumeration")

            def keys(self):
                raise AssertionError("environment enumeration")

        launch = LaunchEnvironment(PATH="synthetic-path", SystemRoot="synthetic-system",
                                   XDG_CONFIG_HOME="synthetic-config",
                                   GIT_DIR=SECRET, GIT_CONFIG_COUNT="1", PRIVATE_KEY=SECRET)
        with patch.object(env.os, "environ", launch), \
                patch.object(env.subprocess, "Popen", side_effect=FileNotFoundError) as popen:
            self.assertEqual(env._command(["git", "--version"]), (None, "not_found"))
        child = popen.call_args.kwargs.get("env")
        self.assertIsNotNone(child)
        self.assertEqual(child, {"PATH": "synthetic-path", "SystemRoot": "synthetic-system",
                                 "XDG_CONFIG_HOME": "synthetic-config"})
        self.assertNotIn(SECRET, repr(child))

    def test_xdg_git_config_ignore_rules_preserve_actual_dirty_status(self):
        home = self.root / "synthetic-home"
        config_home = self.root / "synthetic-xdg"
        home.mkdir()
        (config_home / "git").mkdir(parents=True)
        config = config_home / "git/config"
        ignore = config_home / "synthetic-ignore"
        ignore.write_text("ignored.tmp\n")
        with patch.dict(os.environ, HOME=str(home), USERPROFILE=str(home),
                        XDG_CONFIG_HOME=str(config_home)):
            expected = self.init_git_fixture(self.repo, "XDG fixture\n")
            self.git_fixture(self.repo, "config", "--file", str(config),
                             "core.excludesFile", ignore.as_posix())
            ignored = self.repo / "ignored.tmp"
            ignored.write_text(SECRET)
            self.assertEqual(self.git_fixture(
                self.repo, "status", "--porcelain=v1", "--untracked-files=all").stdout, b"")
            watched = (config, ignore, ignored, self.repo / ".git/index")
            before = [path.read_bytes() for path in watched]
            self.assertEqual(self.run_cli(command=env._command), 0)
            self.assertEqual(self.document()["source"], {
                "commit": expected, "dirty": False, "unknown_reasons": {}})
            self.assertEqual(before, [path.read_bytes() for path in watched])
            (self.repo / "unignored.tmp").write_text(SECRET)
            self.assertTrue(self.git_fixture(
                self.repo, "status", "--porcelain=v1", "--untracked-files=all").stdout)
            self.assertEqual(env._source(self.repo.resolve()), {
                "commit": expected, "dirty": True, "unknown_reasons": {}})
        for private in (SECRET, str(home), str(config_home), str(ignore)):
            self.assertNotIn(private, self.output.read_text() + self.console)

    def test_docker_repository_separator_grammar_preserves_container_projection(self):
        for reference in ("registry.example/team/lima__sidecar:v1",
                          "registry.example/team/lima--sidecar:v1",
                          "lima__sidecar:v1", "team--name/lima---sidecar:v1",
                          "registry.example:5000/team__name/lima---sidecar:v1@" + IMAGE):
            with self.subTest(reference=reference):
                self.output.unlink(missing_ok=True)
                self.inspect["image_reference"] = reference
                self.assertEqual(self.run_cli("--container", "one"), 0)
                container = self.document()["container"]
                self.assertIsNone(container["reason"])
                self.assertEqual(container["image_reference"], reference)
                self.assertEqual(container["image_id"], IMAGE)
                self.assertEqual(container["limits"], self.inspect["limits"])
                self.output.unlink()

    def test_docker_invalid_repository_separators_remain_rejected(self):
        for component in ("lima___sidecar", "lima..sidecar", "lima._sidecar",
                          "_sidecar", "sidecar--", "Lima__sidecar"):
            with self.subTest(component=component):
                self.inspect["image_reference"] = "registry.example/team/" + component + ":v1"
                self.assertEqual(self.run_cli("--container", "one"), 0)
                self.assertEqual(self.document()["container"]["reason"], "invalid_projection")
                self.output.unlink()

    def test_resource_types_and_digest_image_reference(self):
        for key, bad in (("pids_limit", True), ("nano_cpus", -1),
                         ("memory_bytes", 1.5), ("cpuset_cpus", SECRET)):
            original = self.inspect["limits"][key]
            self.inspect["limits"][key] = bad
            self.assertEqual(self.run_cli("--container", "one"), 0)
            self.assertEqual(self.document()["container"]["reason"], "invalid_projection")
            self.output.unlink()
            self.inspect["limits"][key] = original
        self.inspect["image_reference"] = "registry.example:5000/lima:v1@" + IMAGE
        self.inspect["limits"]["pids_limit"] = None
        self.assertEqual(self.run_cli("--container", "one"), 0)
        self.assertIsNone(self.document()["container"]["reason"])

    def test_output_created_concurrently_is_preserved(self):
        def race(argv, **kwargs):
            if not self.output.exists():
                self.output.write_text(SECRET)
            return self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=race), 3)
        self.assertEqual(self.output.read_text(), SECRET)
        self.assertNotIn(SECRET, self.console)

    def test_parent_checkout_cannot_impersonate_selected_repository(self):
        def parent(argv, **kwargs):
            if argv[-1] == "--show-toplevel":
                return str(self.root).encode("utf-8") + b"\n", None
            return self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=parent), 2)
        self.assertFalse(self.output.exists())
        self.assertNotIn(str(self.root), self.console)

    def test_unreadable_git_root_is_required_input_error(self):
        def failed(argv, **kwargs):
            if argv[-1] == "--show-toplevel":
                return None, "permission_denied"
            return self.command(argv, **kwargs)
        self.assertEqual(self.run_cli(command=failed), 2)
        self.assertFalse(self.output.exists())

    def test_host_empty_or_failed_metadata_unknown_with_reason(self):
        with patch.object(env.platform, "machine", return_value=""), \
                patch.object(env.platform, "release", side_effect=OSError(SECRET)), \
                patch.object(env.os, "cpu_count", return_value=None):
            self.assertEqual(self.run_cli(), 0)
        host = self.document()["host"]
        for key in ("architecture", "os_version", "logical_cpu_count"):
            self.assertIsNone(host[key])
            self.assertTrue(host["unknown_reasons"][key])
        self.assertNotIn(SECRET, self.output.read_text() + self.console)


if __name__ == "__main__":
    unittest.main()
