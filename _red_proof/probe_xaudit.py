"""PKT-IP-0022-XAUDIT probes: replicate main-session five observations @main behavior."""
import json, sys, tempfile, pathlib
sys.path.insert(0, ".")
from tests.audit.fixtures.repo_shapes import workspace_with
from lima.audit import inventory as inv
from lima.audit import ram as ramm

KW = dict(tenant_id="t", task_id="task", workflow_id="w",
          stage_attempt_id="s", artifact_id="a", repository_snapshot_digest="0"*64)

def profile_of(repo):
    with workspace_with(repo) as ws:
        return inv.build_repository_profile(ws, **KW)

print("=== P1: code_roles leak (tests/token_FAKESECRET123.py) ===")
p = profile_of({"tests/token_FAKESECRET123.py": "import os\nos.system('x')\n", "pkg/__init__.py": "x=1\n"})
roles = [(a.role.value, a.path) for a in p.profile.code_roles]
print("code_roles:", roles)
print("leaked:", any("FAKESECRET" in path for _, path in roles))

print("=== P2: secrets/pyproject.toml bad TOML ===")
bad_toml = "definitely ][ not toml {{{"
p2 = profile_of({"secrets/pyproject.toml": bad_toml, "pkg/__init__.py": "x=1\n"})
text2 = json.dumps(p2.profile.to_dict(), default=str)
print("has FAKESECRET:", "FAKESECRET" in text2)
print("gaps:", [(g.gap_code, g.detail) for g in p2.profile.coverage_gaps])
print("word 'secrets' present:", "secrets" in text2.lower())

print("=== P2b: sensitive-named requirements parse error path ===")
# requirements file that fails read (binary/non-utf8)
p2b = profile_of({"requirements-ghp_FAKESECRET1234x.txt": "flag \x00\x01 binary", "pkg/__init__.py": "x=1\n"})
t2b = json.dumps(p2b.profile.to_dict(), default=str)
print("gaps:", [(g.gap_code, g.detail) for g in p2b.profile.coverage_gaps])
print("FAKESECRET in profile:", "FAKESECRET" in t2b)

print("=== P2c: bad-content requirements (normal text) ===")
p2c = profile_of({"requirements-ghp_FAKESECRET1234.txt": "not a valid req line !!! <>\n", "pkg/__init__.py": "x=1\n"})
t2c = json.dumps(p2c.profile.to_dict(), default=str)
print("gaps:", [(g.gap_code, g.detail) for g in p2c.profile.coverage_gaps])
print("FAKESECRET in profile:", "FAKESECRET" in t2c)
print("package_managers:", [d.name for d in p2c.profile.package_managers] if hasattr(p2c.profile,'package_managers') else "n/a")

print("=== P2d: unreadable/py-typed manifest error via missing file? (use directory named pyproject.toml?) skip; try secrets dir w/ FAKESECRET name fixed-name manifest ===")
# fixed-name manifest inside sensitive-named DIRECTORY with parse error
p2d = profile_of({"secrets/setup.cfg": "[metadata]\nname = x\nbad[[[\n", "pkg/__init__.py": "x=1\n"})
t2d = json.dumps(p2d.profile.to_dict(), default=str)
print("gaps:", [(g.gap_code, g.detail) for g in p2d.profile.coverage_gaps])

print("=== P3: RAM facts from secrets/token dir ===")
from lima.audit.ram import build_python_ram_facts
with workspace_with({"secrets/token_apikey.py": SINK if (SINK:="import os\ndef run_command(r):\n    os.system(r.args.get('cmd'))\n") else "", "danger.py": SINK}) as ws:
    rr = build_python_ram_facts(ws)
paths = [e.path for e in rr.facts.sensitive_sinks]
print("sink paths:", paths)
print("token_apikey leaked into RAM:", any("token_apikey" in p_ for p_ in paths))
print("=== P5: entrypoints fixed names ===")
p5 = profile_of({"cli_ghp_FAKESECRET.py": "pass\n"})
print("entrypoints:", [(e.path, e.reason_codes) for e in p5.profile.entrypoints])
