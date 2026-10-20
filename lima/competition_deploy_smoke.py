"""Auditable Docker Compose smoke test for Issue #298."""
from __future__ import annotations
import argparse, json, os, re, secrets, shutil, subprocess, tempfile, time, urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable
from urllib.parse import urlsplit

PROJECT_RE = re.compile(r"^[a-z][a-z0-9_-]{2,62}$")
REGISTRY_RE = re.compile(r"^[a-z0-9.-]+(?::[0-9]+)?$")
BUILD_TIMEOUT_GRACE_SECONDS = 900
PYTHON_IMAGE_DIGEST = "sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7"
NODE_IMAGE_DIGEST = "sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32"

@dataclass(frozen=True)
class RunConfig:
    repository: Path
    compose_file: Path
    output: Path
    timeout: int = 180
    project: str | None = None
    source_sha: str | None = None
    base_image_registry: str | None = None
    debian_mirror: str | None = None

class SmokeRunner:
    def __init__(self, config: RunConfig, *, runner: Callable[..., subprocess.CompletedProcess] | None = None):
        self.config, self.run = config, runner or subprocess.run
        self.project = config.project or f"lima-smoke-{secrets.token_hex(8)}"
        if not PROJECT_RE.fullmatch(self.project): raise ValueError("invalid project")
        if config.base_image_registry and not REGISTRY_RE.fullmatch(config.base_image_registry):
            raise ValueError("invalid base image registry")
        if config.debian_mirror:
            mirror = urlsplit(config.debian_mirror)
            if mirror.scheme != "https" or not mirror.hostname or mirror.username or mirror.password or mirror.query or mirror.fragment:
                raise ValueError("invalid Debian mirror URL")
        self.commands, self.created, self.secrets = [], False, []
        self.effective_config = None

    def command(self, args, timeout=60, *, save_output=True):
        started, record = time.monotonic(), {"argv": [self._scrub(str(arg)) for arg in args]}
        try:
            child_env = {key:value for key,value in os.environ.items()
                         if not key.startswith(("LIMA_", "EVOAGENT_"))}
            result = self.run(args, cwd=self.config.repository, capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=timeout, check=False, env=child_env)
            record.update(returncode=result.returncode)
            record["stderr"] = self._scrub(result.stderr[-4000:])
            if save_output: record["stdout"] = self._scrub(result.stdout[-4000:])
            return result
        except FileNotFoundError:
            record["error"] = "docker-not-found"; raise
        except subprocess.TimeoutExpired as exc:
            record.update(error="timeout", stdout=self._scrub(str(exc.stdout or "")[-4000:]), stderr=self._scrub(str(exc.stderr or "")[-4000:])); raise
        finally:
            record["duration_seconds"] = round(time.monotonic() - started, 3); self.commands.append(record)

    def _scrub(self, value):
        for path, token in ((str(self.config.repository), "${REPOSITORY}"), (str(self.config.output), "${OUTPUT}"), (getattr(self, "temp_path", ""), "${RUN_DIR}")):
            if path: value=value.replace(path,token).replace(path.replace("\\","/"),token)
        return re.sub(r"[A-Za-z]:\\Users\\[^\\\s]+", "${WINDOWS_USER_PATH}", value)

    def compose(self, *args, timeout=60, save_output=True):
        return self.command(["docker", "compose", "--env-file", str(self.env_file), "-p", self.project,
                             "-f", str(getattr(self, "effective_file", self.config.compose_file)), *args], timeout, save_output=save_output)

    def _prepare(self, temp: Path):
        self.env_file = temp / "smoke.env"
        self.effective_file = temp / "compose.json"
        import_root, output_root = temp / "repositories", temp / "experiments"
        import_root.mkdir(); output_root.mkdir()
        env = {"LIMA_POSTGRES_PASSWORD": secrets.token_urlsafe(32),
               "LIMA_AUTH_SECRET": secrets.token_urlsafe(48),
               "LIMA_BOOTSTRAP_ADMIN_PASSWORD": secrets.token_urlsafe(24),
               "LIMA_BOOTSTRAP_ADMIN_USERNAME": "smoke-admin",
               "LIMA_HTTP_PORT": "18080", "LIMA_LLM_PROVIDER": "local",
               "LIMA_LLM_BASE_URL": "", "LIMA_LLM_API_KEY": "", "LIMA_LLM_MODEL": "",
               "LIMA_CXX_AGENT_MODE": "off", "LIMA_REPOSITORY_SCAN_LLM_MODE": "off",
               "LIMA_REPOSITORY_INVESTIGATION_MODE": "off",
               "LIMA_REPOSITORY_IMPORT_PATH": str(import_root),
               "LIMA_EXPERIMENT_OUTPUT_PATH": str(output_root)}
        self.secrets = list(env.values())
        self.env_file.write_text("".join(f"{k}={v}\n" for k,v in env.items()), encoding="utf-8")
        raw = self.command(["docker", "compose", "--env-file", str(self.env_file), "-p", self.project,
                            "-f", str(self.config.compose_file), "--profile", "cxx", "config", "--format", "json"], 45, save_output=False)
        if raw.returncode: raise RuntimeError("compose-config-failed")
        cfg = json.loads(raw.stdout)
        cfg["name"] = self.project
        if self.config.base_image_registry:
            build = cfg["services"]["lima"].setdefault("build", {})
            args = build.setdefault("args", {})
            if isinstance(args, list): args = dict(item.split("=", 1) for item in args if "=" in item)
            args.update({
                "PYTHON_BASE_IMAGE": f"{self.config.base_image_registry}/library/python:3.11-slim@{PYTHON_IMAGE_DIGEST}",
                "NODE_BASE_IMAGE": f"{self.config.base_image_registry}/library/node:22-alpine@{NODE_IMAGE_DIGEST}",
            })
            build["args"] = args
        if self.config.debian_mirror:
            build = cfg["services"]["cxx-analyzer"].setdefault("build", {})
            args = build.setdefault("args", {})
            if isinstance(args, list): args = dict(item.split("=", 1) for item in args if "=" in item)
            args["DEBIAN_MIRROR"] = self.config.debian_mirror.rstrip("/")
            build["args"] = args
        cfg["services"]["lima"].pop("env_file", None)
        cfg["services"]["lima"]["ports"] = [{"host_ip":"127.0.0.1", "target":8080, "protocol":"tcp"}]
        cfg["services"]["lima"]["volumes"] = [
            {"type":"bind", "source":str(import_root), "target":"/repositories", "read_only":True},
            {"type":"bind", "source":str(output_root), "target":"/experiments"},
            *[{"type":"volume", "source":name, "target":target}
              for name,target in (("experiment_cache","/experiment-cache"),
                                  ("repository_cache","/var/lib/lima/repository-cache"),
                                  ("repair_workspace","/var/lib/lima/repair-workspace"))]
        ]
        for name in ("experiment_cache", "postgres_data", "redis_data", "repository_cache", "repair_workspace"):
            if name not in cfg["volumes"]:
                cfg["volumes"][name] = {}
            volume = cfg["volumes"][name]
            volume.pop("external", None); volume.pop("name", None)
            volume["name"] = f"{self.project}-{name}"
        for service in cfg.get("services", {}).values():
            for mount in service.get("volumes", []):
                if mount.get("type") == "volume" and mount.get("source") in cfg["volumes"]:
                    mount["source"] = mount["source"]
        cfg["services"]["postgres"].setdefault("volumes", [])[0]["source"] = "postgres_data"
        cfg["services"]["redis"].setdefault("volumes", [])[0]["source"] = "redis_data"
        self._assert_isolated_volumes(cfg)
        self.effective_file.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        self.effective_config = cfg
        return temp

    def _existing_resources(self):
        return self._resources_absent()

    def _resources_absent(self):
        checks = (("container", ["ps", "-a"]), ("volume", ["volume", "ls"]), ("network", ["network", "ls"]))
        for _, sub in checks:
            result=self.command(["docker", *sub,
                                 "--filter", f"label=com.docker.compose.project={self.project}", "-q"], 20)
            if result.returncode or result.stdout.strip(): return False
        return True

    def _assert_isolated_volumes(self, cfg):
        for volume in cfg.get("volumes", {}).values():
            if volume.get("external") or not str(volume.get("name", "")).startswith(self.project + "-"):
                raise RuntimeError("compose-volume-isolation-failed")

    def _health(self):
        port=self.compose("port", "lima", "8080", timeout=20).stdout.strip().rsplit(":",1)[-1]
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=8) as response:
            if response.status != 200: raise RuntimeError("app-health-failed")
            return json.loads(response.read(65536).decode("utf-8"))

    def run_smoke(self):
        self.config.output.mkdir(parents=True, exist_ok=False)
        report = {"schema_version": 1, "project": self.project, "status": "unknown", "checks": [],
                  "commands": self.commands, "remote_model_calls": "disabled",
                  "output_directory": str(self.config.output), "cleanup": {"status":"not-needed"},
                  "base_image_registry": self.config.base_image_registry or "docker.io",
                  "debian_mirror": self.config.debian_mirror or "deb.debian.org"}
        tempdir = tempfile.TemporaryDirectory(prefix=f"{self.project}-")
        temp=Path(tempdir.name); self.temp_path=str(temp)
        try:
            if not (shutil.which("docker") or shutil.which("docker.exe")):
                report["status"] = "not-verified"; report["checks"].append({"name":"docker","status":"unknown","reason":"docker-not-found"}); return report
            self._prepare(temp)
            if not self._existing_resources():
                report["status"]="failed"; report["checks"].append({"name":"project-conflict","status":"failed"}); return report
            report["checks"].append({"name":"project-conflict","status":"passed"})
            config = self.compose("config", timeout=30, save_output=False)
            if config.returncode: report["status"]="failed"; report["checks"].append({"name":"compose-config","status":"failed"}); return report
            report["checks"].append({"name":"compose-config","status":"passed"})
            self.created = True
            up = self.compose("--profile", "cxx", "up", "--build", "-d", "--wait", "--wait-timeout", str(self.config.timeout), timeout=self.config.timeout+BUILD_TIMEOUT_GRACE_SECONDS)
            if up.returncode:
                diagnostics = self._port_diagnostics()
                report["status"]="failed"
                report["checks"].append({"name":"start","status":"failed", **diagnostics})
                return report
            report["checks"].append({"name":"start","status":"passed"})
            ps = self.compose("--profile", "cxx", "ps", "--all", timeout=30)
            report["checks"].append({"name":"service-status","status":"passed" if ps.returncode == 0 else "failed"})
            health=self._health(); report["checks"].append({"name":"app-health","status":"passed","response":health})
            sidecar=self.compose("--profile", "cxx", "exec","-T","cxx-analyzer","python","-c",
              "import json,urllib.request; print(json.dumps(json.load(urllib.request.urlopen('http://127.0.0.1:8090/health',timeout=5))))",timeout=15)
            report["checks"].append({"name":"sidecar-health","status":"passed" if sidecar.returncode == 0 else "failed"})
            report["status"]="passed" if ps.returncode == 0 and sidecar.returncode == 0 else "failed"; return report
        except FileNotFoundError: report.update(status="not-verified", error="docker-not-found"); return report
        except subprocess.TimeoutExpired: report.update(status="failed", error="timeout"); return report
        except (RuntimeError, ValueError, json.JSONDecodeError) as exc:
            report.update(status="failed", error=type(exc).__name__, detail=str(exc)); return report
        except KeyboardInterrupt:
            report["status"]="interrupted"
            report["error"]="interrupted-by-user"
        finally:
            if self.created:
                try:
                    cleanup = self.compose("--profile", "cxx", "down", "--remove-orphans", "--volumes", timeout=60)
                    cleaned = cleanup.returncode == 0 and self._resources_absent()
                    for _ in range(3):
                        if cleaned: break
                        self.compose("--profile", "cxx", "down", "--remove-orphans", "--volumes", timeout=60)
                        time.sleep(2)
                        cleaned = self._resources_absent()
                    report["cleanup"]={"status":"passed" if cleaned else "failed", "project":self.project, "command":"compose down --remove-orphans --volumes; verified generated project resources are absent"}
                except Exception as exc: report["cleanup"]={"status":"failed", "error":type(exc).__name__, "project":self.project}
            report["commands"] = self.commands
            report["source"]={"commit":self.config.source_sha or self._source_sha(), "dirty":self._dirty()}
            report["images"]={"status":"unknown","items":[]}
            try:
                image_result=self.compose("--profile", "cxx", "images","--format","json",timeout=30)
                if image_result.returncode == 0:
                    report["images"]={"status":"passed","items":json.loads(image_result.stdout) if image_result.stdout.strip() else []}
                else:
                    report["images"]={"status":"failed","items":[]}
            except Exception as exc: report["images"]={"status":"unknown","items":[],"error":type(exc).__name__}
            for command in report["commands"]:
                for secret in self.secrets:
                    if secret:
                        command["stdout"]=str(command.get("stdout","")).replace(secret,"[REDACTED]")
                        command["stderr"]=str(command.get("stderr","")).replace(secret,"[REDACTED]")
            report["artifact"]="smoke.json"; report.pop("output_directory",None)
            encoded=json.dumps(report,indent=2,ensure_ascii=False)+"\n"
            matches=sorted(set(re.findall(r"(?:[A-Za-z]:\\Users\\[^\\\s]+|/home/[^/\s]+|/Users/[^/\s]+)",encoded)))
            report["path_scan"]={"status":"passed" if not matches else "failed","matches":matches,"scope":["smoke.json"]}
            if report.get("cleanup", {}).get("status") == "failed":
                report["status"] = "failed"
            (self.config.output / "smoke.json").write_text(json.dumps(report, indent=2, ensure_ascii=False)+"\n", encoding="utf-8")
            tempdir.cleanup()
        return report

    def _source_sha(self):
        try:
            value=subprocess.run(["git","rev-parse","HEAD"],cwd=self.config.repository,capture_output=True,text=True,timeout=5,check=False).stdout.strip()
            return value if re.fullmatch(r"[0-9a-f]{40}",value) else None
        except Exception: return None

    def _port_diagnostics(self):
        stderr = next((item.get("stderr", "") for item in reversed(self.commands)
                       if "up" in item.get("argv", [])), "")
        port_conflict = bool(re.search(r"address already in use|port is already allocated|bind:.*in use", stderr, re.I))
        return {"reason": "port-conflict" if port_conflict else "compose-start-failed"}
    def _dirty(self):
        try: return bool(subprocess.run(["git","status","--porcelain"],cwd=self.config.repository,capture_output=True,text=True,timeout=5,check=False).stdout.strip())
        except Exception: return None

def main(argv=None):
    p=argparse.ArgumentParser(); p.add_argument("--repository",type=Path,default=Path.cwd()); p.add_argument("--compose-file",type=Path,required=True); p.add_argument("--output",type=Path,required=True); p.add_argument("--project"); p.add_argument("--source-sha", help="40-character source commit to record when Git metadata is unavailable"); p.add_argument("--base-image-registry", help="temporarily use this registry for the pinned Python and Node build images"); p.add_argument("--debian-mirror", help="temporarily use this HTTPS Debian mirror for the C++ analyzer build"); p.add_argument("--timeout",type=int,default=180); a=p.parse_args(argv)
    if a.timeout < 1: p.error("--timeout must be positive")
    if a.source_sha and not re.fullmatch(r"[0-9a-f]{40}", a.source_sha): p.error("--source-sha must contain 40 lowercase hexadecimal characters")
    report=SmokeRunner(RunConfig(a.repository,a.compose_file,a.output,a.timeout,a.project,a.source_sha,a.base_image_registry,a.debian_mirror)).run_smoke(); print(json.dumps(report,indent=2,ensure_ascii=False)); return 0 if report["status"] == "passed" else 2

if __name__ == "__main__": raise SystemExit(main())
