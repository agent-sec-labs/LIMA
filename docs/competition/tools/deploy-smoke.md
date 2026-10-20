# Clean deployment smoke test (Issue #298)

`scripts/smoke_clean_deploy.py` starts the production Compose services in a
fresh, isolated project and records the result in `smoke.json`. It builds the
application and C++ analyzer images, waits for service health, probes the app
and analyzer endpoints, then removes only resources created by that unique
Compose project.

Run it from a source checkout with Docker Desktop or Docker Engine running:

```powershell
$out = Join-Path $env:TEMP ('lima-smoke-' + [guid]::NewGuid().Guid)
python scripts/smoke_clean_deploy.py `
  --repository (Get-Location) `
  --compose-file (Resolve-Path docker-compose.yml) `
  --output $out `
  --base-image-registry docker.m.daocloud.io `
  --debian-mirror https://mirrors.tuna.tsinghua.edu.cn `
  --timeout 180
Get-Content (Join-Path $out smoke.json)
```

The runner supplies temporary credentials and a temporary env file. It removes
the Compose `env_file` entry, uses a loopback-only host port, empty read-only
repository input and temporary experiment output, and rewrites every named
volume to a unique project-scoped name. It does not read the checkout's `.env`
file, send remote model calls, or prune Docker resources globally. The report
omits absolute paths and records source commit, command results, service
health, images, cleanup and a path scan. Use `--source-sha` only when running
from a source archive without Git metadata; its value must be a 40-character
lowercase commit hash.
`--base-image-registry` temporarily overrides only the pinned Python and Node
Dockerfile build arguments in the generated Compose file, which is useful when
Docker Hub is unreachable. It does not edit the Dockerfile or configure Docker
Desktop. `--debian-mirror` supplies a build argument to the C++ analyzer image;
the Dockerfile defaults to Debian's official server when it is omitted.

Exit status is `0` only when the runtime and health probes pass; `2` indicates
failed or unverified. Common report reasons include `docker-not-found`,
`port-conflict`, `compose-start-failed` and `timeout`. A build that cannot
contact its image registry is a real deployment failure, not a passing smoke
test. Unit tests with a fake Docker CLI verify the reporting and cleanup logic,
but do not replace a successful Docker run.
