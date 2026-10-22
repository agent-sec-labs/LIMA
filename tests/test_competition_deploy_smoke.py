from __future__ import annotations
import json, os, shutil, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from lima.competition_deploy_smoke import RunConfig, SmokeRunner

class FakeDocker:
    def __init__(self, start=0, conflict=False, timeout=False, interrupt=False, stderr="", missing_images=False, replace_volume=False):
        self.calls, self.start, self.conflict, self.timeout, self.interrupt, self.stderr = [], start, conflict, timeout, interrupt, stderr
        self.resources = {"container": {}, "volume": {}, "network": {}}
        self.missing_images, self.replace_volume = missing_images, replace_volume

    def _create_resources(self, args):
        cfg = json.loads(Path(args[args.index("-f")+1]).read_text(encoding="utf-8"))
        self.project = cfg["name"]
        for kind, key in (("volume", "volumes"), ("network", "networks")):
            for name, spec in cfg.get(key, {}).items():
                labels = {**spec.get("labels", {}), "com.docker.compose.project": self.project}
                identity = spec["name"] if kind == "volume" else "network-" + name
                self.resources[kind][identity] = {
                    "Name": spec["name"], "Labels": labels,
                    "CreatedAt": "2026-10-22T00:00:00Z", "Id": identity,
                }
        for name, spec in cfg["services"].items():
            identity = "container-" + name
            self.resources["container"][identity] = {
                "Id": identity, "Image": "sha256:" + name,
                "Name": self.project + "-" + name + "-1",
                "Config": {"Image": spec.get("image", "synthetic:" + name),
                           "Labels": {**spec.get("labels", {}),
                                      "com.docker.compose.project": self.project,
                                      "com.docker.compose.service": name}},
            }

    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if "config" in args:
            config={"name":"lima","services":{"lima":{"env_file":[".env"],"ports":[],"volumes":[],"build":{"context":"."}},"postgres":{"volumes":[{"type":"volume","source":"postgres_data","target":"/data"}]},"redis":{"volumes":[{"type":"volume","source":"redis_data","target":"/data"}]},"cxx-analyzer":{"build":{"context":".","dockerfile":"cxx_analyzer/Dockerfile"}}},"volumes":{name:{"name":name,"external":True} for name in ("postgres_data","redis_data","repository_cache","repair_workspace")}}
            return subprocess.CompletedProcess(args,0,json.dumps(config),"")
        if "--filter" in args and self.conflict:
            return subprocess.CompletedProcess(args,0,"existing-resource\n","")
        kind = "container" if args[1:3] == ["ps", "-a"] else args[1]
        if kind in self.resources and ("ls" in args or args[1] == "ps"):
            records = list(self.resources[kind].values())
            for index, arg in enumerate(args):
                if arg == "--filter" and args[index+1].startswith("label="):
                    key, value = args[index+1][6:].split("=", 1)
                    records = [r for r in records if r.get("Config", r).get("Labels", {}).get(key) == value]
            field = "Name" if "{{.Name}}" in args or kind == "volume" else "Id"
            return subprocess.CompletedProcess(args, 0, "\n".join(r[field] for r in records), "")
        if len(args) > 2 and args[2] == "inspect":
            if kind == "image":
                document = [] if self.missing_images else [{"Id": args[-1], "RepoDigests": ["synthetic@"+args[-1]]}]
            else:
                document = [r for identity, r in self.resources[kind].items()
                            if args[-1] in (identity, r["Name"])]
            return subprocess.CompletedProcess(args, 0 if document else 1, json.dumps(document), "")
        if len(args) > 2 and args[2] == "rm":
            if kind == "container" and self.replace_volume and self.resources["volume"]:
                next(iter(self.resources["volume"].values())).update(
                    Labels={}, CreatedAt="2026-10-22T01:00:00Z")
            self.resources[kind].pop(args[-1], None)
            return subprocess.CompletedProcess(args, 0, "", "")
        if "up" in args:
            self._create_resources(args)
        if "up" in args and self.timeout: raise subprocess.TimeoutExpired(args,kwargs.get("timeout",1))
        if "up" in args and self.interrupt: raise KeyboardInterrupt
        code = self.start if "up" in args else 0
        out = "127.0.0.1:45123" if "port" in args else ""
        return subprocess.CompletedProcess(args, code, out, self.stderr if "up" in args else "")

class SmokeTests(unittest.TestCase):
    def test_success_and_owned_cleanup(self):
        with tempfile.TemporaryDirectory() as d:
            root, fake = Path(d), FakeDocker()
            dockerfile = root / "cxx_analyzer" / "Dockerfile"
            dockerfile.parent.mkdir()
            dockerfile.write_text("FROM pinned AS base\nRUN apt-get update \\\n", encoding="utf-8")
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"), patch("lima.competition_deploy_smoke.urllib.request.urlopen") as urlopen:
                urlopen.return_value.__enter__.return_value.status=200
                urlopen.return_value.__enter__.return_value.read.return_value=b'{"status":"ok"}'
                smoke = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out", base_image_registry="docker.m.daocloud.io", debian_mirror="https://mirrors.tuna.tsinghua.edu.cn"), runner=fake)
                report = smoke.run_smoke()
            self.assertEqual("passed", report["status"]); self.assertEqual("passed", report["cleanup"]["status"])
            self.assertTrue((root/"out"/"smoke.json").is_file())
            self.assertFalse(any("down" in call for call in fake.calls))
            self.assertTrue(any(call[1:3] == ["container", "rm"] for call in fake.calls))
            self.assertTrue(all(not records for records in fake.resources.values()))
            effective=smoke.effective_config
            self.assertEqual("lima-smoke-", report["project"][:11])
            self.assertEqual({"experiment_cache","repository_cache","repair_workspace"},
                             {v["source"] for v in effective["services"]["lima"]["volumes"] if v["type"] == "volume"})
            self.assertTrue(all(v["name"].startswith(report["project"] + "-") for v in effective["volumes"].values()))
            args=effective["services"]["lima"]["build"]["args"]
            self.assertTrue(args["PYTHON_BASE_IMAGE"].startswith("docker.m.daocloud.io/library/python:3.11-slim@sha256:"))
            self.assertTrue(args["NODE_BASE_IMAGE"].startswith("docker.m.daocloud.io/library/node:22-alpine@sha256:"))
            build = effective["services"]["cxx-analyzer"]["build"]
            self.assertNotIn("DEBIAN_MIRROR", build.get("args", {}))
            self.assertTrue(build["dockerfile"].endswith("Dockerfile.cxx-analyzer"))
            self.assertNotIn("DEBIAN_MIRROR", dockerfile.read_text(encoding="utf-8"))
            source_config_call=next(call for call in fake.calls if "config" in call and "--format" in call)
            self.assertLess(source_config_call.index("--profile"), source_config_call.index("config"))

    def test_mirror_dockerfile_is_temporary_and_keeps_runtime_arg_free(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            source = root / "Dockerfile"
            generated = root / "tmp" / "Dockerfile"
            generated.parent.mkdir()
            original = "FROM pinned AS base\nRUN apt-get update \\\n"
            source.write_text(original, encoding="utf-8")
            SmokeRunner._write_mirror_dockerfile(
                source, generated, "https://mirrors.tuna.tsinghua.edu.cn",
            )
            self.assertEqual(original, source.read_text(encoding="utf-8"))
            rendered = generated.read_text(encoding="utf-8")
            self.assertIn("https://mirrors.tuna.tsinghua.edu.cn", rendered)
            self.assertNotIn("ARG ", rendered)
    def test_start_failure_is_port_conflict_and_has_no_down(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out"), runner=FakeDocker(1)).run_smoke()
            self.assertEqual("failed", report["status"]); self.assertEqual("passed", report["cleanup"]["status"])

    def test_port_collision_is_classified(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out"), runner=FakeDocker(1,stderr="bind: address already in use")).run_smoke()
            self.assertEqual("port-conflict", report["checks"][-1]["reason"])

    def test_report_scrubs_repository_paths_and_records_explicit_commit(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            sha="a"*40
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out",source_sha=sha), runner=FakeDocker(1)).run_smoke()
            contents=(root/"out"/"smoke.json").read_text()
            self.assertNotIn(str(root), contents)
            self.assertEqual(sha, report["source"]["commit"])
            self.assertEqual("passed", report["path_scan"]["status"])
    def test_project_collision_fails_before_resources_are_owned(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out"), runner=FakeDocker(conflict=True)).run_smoke()
            self.assertEqual("failed", report["status"]); self.assertEqual("project-conflict", report["checks"][-1]["name"])
    def test_timeout_is_recorded_and_still_cleans_unique_project(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); fake=FakeDocker(timeout=True)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out"), runner=fake).run_smoke()
            self.assertEqual("failed", report["status"]); self.assertEqual("passed", report["cleanup"]["status"])
    def test_interrupt_is_recorded_and_cleans_unique_project(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d); fake=FakeDocker(interrupt=True)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out"), runner=fake).run_smoke()
            self.assertTrue(any(call[1:3] == ["container", "rm"] for call in fake.calls))
            self.assertTrue(all(not records for records in fake.resources.values()))
            self.assertEqual("interrupted", report["status"])
            self.assertEqual("interrupted", json.loads((root/"out"/"smoke.json").read_text())["status"])
    def test_missing_docker_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value=None):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out")).run_smoke()
            self.assertEqual("not-verified", report["status"])

class ReviewRegressionTests(unittest.TestCase):
    def test_fixed_project_does_not_reuse_build_image_tags(self):
        references = []
        for _ in range(2):
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                smoke = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out",
                                               project="lima-smoke-repeated"), runner=FakeDocker())
                smoke._prepare(root)
                references.append(smoke.effective_config["services"]["lima"]["image"])
        self.assertNotEqual(references[0], references[1])

    def test_env_file_is_not_resolved_and_remote_environment_is_forced_off(self):
        class PollutedDocker(FakeDocker):
            def __call__(self, args, **kwargs):
                result = super().__call__(args, **kwargs)
                if "config" in args:
                    cfg = json.loads(result.stdout)
                    cfg["services"]["lima"]["environment"] = {
                        "LIMA_LLM_PROVIDER": "custom",
                        "LIMA_LLM_API_KEY": "synthetic-private-key",
                        "LIMA_LLM_BASE_URL": "https://example.invalid/v1",
                        "LIMA_LLM_MODEL": "remote-model",
                    }
                    result.stdout = json.dumps(cfg)
                return result
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = PollutedDocker()
            smoke = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out"), runner=fake)
            smoke._prepare(root)
            env = smoke.effective_config["services"]["lima"]["environment"]
            self.assertEqual("", env["LIMA_LLM_API_KEY"])
            self.assertEqual("", env["LIMA_LLM_BASE_URL"])
            self.assertEqual("", env["LIMA_LLM_MODEL"])
            self.assertEqual("local", env["LIMA_LLM_PROVIDER"])
            self.assertIn("--no-env-resolution", fake.calls[0])

    def test_unlabelled_same_name_volume_is_rejected_before_up(self):
        class ExistingVolumeDocker(FakeDocker):
            def __call__(self, args, **kwargs):
                if args[1:3] == ["volume", "ls"] and "--filter" not in args:
                    return subprocess.CompletedProcess(args, 0, "lima-smoke-collision-postgres_data\n", "")
                return super().__call__(args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fake = ExistingVolumeDocker()
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"), patch("lima.competition_deploy_smoke.urllib.request.urlopen") as opener:
                opener.return_value.__enter__.return_value.status = 200
                opener.return_value.__enter__.return_value.read.return_value = b'{"status":"ok"}'
                report = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out",
                                               project="lima-smoke-collision"), runner=fake).run_smoke()
            self.assertEqual("project-conflict", report["checks"][-1]["name"])
            self.assertFalse(any("up" in call or "down" in call for call in fake.calls))

    def test_unlabelled_same_name_network_is_rejected_before_up(self):
        class ExistingNetworkDocker(FakeDocker):
            def __call__(self, args, **kwargs):
                if args[1:3] == ["network", "ls"] and "--filter" not in args:
                    return subprocess.CompletedProcess(args, 0, "lima-smoke-collision-default\n", "")
                return super().__call__(args, **kwargs)
        with tempfile.TemporaryDirectory() as directory:
            root, fake = Path(directory), ExistingNetworkDocker()
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"):
                report = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out",
                                               project="lima-smoke-collision"), runner=fake).run_smoke()
            self.assertEqual("project-conflict", report["checks"][-1]["name"])
            self.assertFalse(any("up" in call or "down" in call for call in fake.calls))

    def test_missing_image_evidence_cannot_pass(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"), patch("lima.competition_deploy_smoke.urllib.request.urlopen") as opener:
                opener.return_value.__enter__.return_value.status = 200
                opener.return_value.__enter__.return_value.read.return_value = b'{"status":"ok"}'
                report = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out"),
                                     runner=FakeDocker(missing_images=True)).run_smoke()
            self.assertEqual("failed", report["status"])
            self.assertEqual("failed", report["images"]["status"])

    def test_images_capture_all_services_before_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root, fake = Path(directory), FakeDocker()
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"), patch("lima.competition_deploy_smoke.urllib.request.urlopen") as opener:
                opener.return_value.__enter__.return_value.status = 200
                opener.return_value.__enter__.return_value.read.return_value = b'{"status":"ok"}'
                report = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out"), runner=fake).run_smoke()
            self.assertEqual("passed", report["images"]["status"])
            self.assertEqual({"lima", "postgres", "redis", "cxx-analyzer"},
                             {item["service"] for item in report["images"]["items"]})
            self.assertTrue(all(item["id"].startswith("sha256:") for item in report["images"]["items"]))
            image_calls = [i for i,c in enumerate(fake.calls) if c[1:3] == ["image", "inspect"]]
            removals = [i for i,c in enumerate(fake.calls) if len(c)>2 and c[2]=="rm"]
            self.assertTrue(image_calls)
            self.assertTrue(removals)
            self.assertLess(max(image_calls), min(removals))

    def test_replaced_volume_is_retained_and_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            root, fake = Path(directory), FakeDocker(replace_volume=True)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value="docker"), patch("lima.competition_deploy_smoke.urllib.request.urlopen") as opener:
                opener.return_value.__enter__.return_value.status = 200
                opener.return_value.__enter__.return_value.read.return_value = b'{"status":"ok"}'
                report = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out"), runner=fake).run_smoke()
            self.assertEqual("failed", report["cleanup"]["status"])
            self.assertEqual("failed", report["status"])
            self.assertEqual(1, len(fake.resources["volume"]))


@unittest.skipUnless(
    os.environ.get("LIMA_RUN_DOCKER_SMOKE_REGRESSIONS") == "1" and shutil.which("docker"),
    "opt-in real Docker regression checks (config and disposable empty resources only)",
)
class RealDockerRegressionTests(unittest.TestCase):
    def _smoke(self, root):
        shutil.copyfile(Path(__file__).resolve().parents[1]/"docker-compose.yml", root/"compose.yml")
        smoke = SmokeRunner(RunConfig(root, root/"compose.yml", root/"out"))
        runtime = root/"runtime"
        runtime.mkdir()
        smoke.temp_path = str(runtime)
        smoke._prepare(runtime)
        return smoke

    def _docker(self, *args):
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=30, check=False)

    def test_real_compose_never_reads_malformed_production_dotenv(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            poison = "LIMA_LLM_API_KEY='SYNTHETIC_UNTERMINATED_SECRET\n"
            (root/".env").write_text(poison, encoding="utf-8")
            smoke = self._smoke(root)
            self.assertEqual(poison, (root/".env").read_text(encoding="utf-8"))
            env = smoke.effective_config["services"]["lima"]["environment"]
            self.assertEqual("", env["LIMA_LLM_API_KEY"])
            self.assertEqual("local", env["LIMA_LLM_PROVIDER"])
            self.assertNotIn("env_file", smoke.effective_config["services"]["lima"])
            effective = smoke.compose("config", "--format", "json", save_output=False)
            self.assertEqual(0, effective.returncode, effective.stderr)
            self.assertNotIn("SYNTHETIC_UNTERMINATED_SECRET", effective.stdout)

    def test_real_unlabelled_volume_conflict_preserves_existing_volume(self):
        with tempfile.TemporaryDirectory() as directory:
            smoke = self._smoke(Path(directory))
            name = smoke.project + "-postgres_data"
            self.assertEqual(0, self._docker("volume", "create", name).returncode)
            try:
                self.assertFalse(smoke._existing_resources())
                self.assertEqual(0, self._docker("volume", "inspect", name).returncode)
            finally:
                self._docker("volume", "rm", name)

    def test_real_cleanup_removes_owned_volume_and_retains_foreign_volume(self):
        from lima.competition_deploy_smoke import RUN_LABEL
        with tempfile.TemporaryDirectory() as directory:
            smoke = self._smoke(Path(directory))
            own = smoke.project + "-postgres_data"
            foreign = smoke.project + "-redis_data"
            for name, owner in ((own, smoke.run_id), (foreign, "another-run")):
                created = self._docker("volume", "create", "--label",
                                       "com.docker.compose.project="+smoke.project,
                                       "--label", RUN_LABEL+"="+owner, name)
                self.assertEqual(0, created.returncode, created.stderr)
            try:
                result = smoke._cleanup_owned_resources()
                self.assertEqual("failed", result["status"])
                self.assertNotEqual(0, self._docker("volume", "inspect", own).returncode)
                self.assertEqual(0, self._docker("volume", "inspect", foreign).returncode)
            finally:
                # Both empty volumes are created by this test; names are random.
                for name in (own, foreign):
                    self._docker("volume", "rm", name)


if __name__ == "__main__": unittest.main()
