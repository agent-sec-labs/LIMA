from __future__ import annotations
import json, subprocess, tempfile, unittest
from pathlib import Path
from unittest.mock import patch
from lima.competition_deploy_smoke import RunConfig, SmokeRunner

class FakeDocker:
    def __init__(self, start=0, conflict=False, timeout=False, interrupt=False, stderr=""):
        self.calls, self.start, self.conflict, self.timeout, self.interrupt, self.stderr = [], start, conflict, timeout, interrupt, stderr
    def __call__(self, args, **kwargs):
        self.calls.append(args)
        if "config" in args:
            config={"name":"lima","services":{"lima":{"env_file":[".env"],"ports":[],"volumes":[],"build":{"context":"."}},"postgres":{"volumes":[{"type":"volume","source":"postgres_data","target":"/data"}]},"redis":{"volumes":[{"type":"volume","source":"redis_data","target":"/data"}]},"cxx-analyzer":{"build":{"context":".","dockerfile":"cxx_analyzer/Dockerfile"}}},"volumes":{name:{"name":name,"external":True} for name in ("postgres_data","redis_data","repository_cache","repair_workspace")}}
            return subprocess.CompletedProcess(args,0,json.dumps(config),"")
        if "--filter" in args and self.conflict:
            return subprocess.CompletedProcess(args,0,"existing-resource\n","")
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
            down_call=next(call for call in fake.calls if "down" in call)
            self.assertIn("--profile", down_call)
            self.assertNotIn("-v", down_call)
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
            self.assertTrue(any("down" in call for call in fake.calls))
            self.assertEqual("interrupted", report["status"])
            self.assertEqual("interrupted", json.loads((root/"out"/"smoke.json").read_text())["status"])
    def test_missing_docker_is_unknown(self):
        with tempfile.TemporaryDirectory() as d:
            root=Path(d)
            with patch("lima.competition_deploy_smoke.shutil.which", return_value=None):
                report=SmokeRunner(RunConfig(root,root/"compose.yml",root/"out")).run_smoke()
            self.assertEqual("not-verified", report["status"])

if __name__ == "__main__": unittest.main()
