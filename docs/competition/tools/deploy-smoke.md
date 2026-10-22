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

The runner requires Compose with `config --no-env-resolution` support. It
supplies temporary credentials and a temporary interpolation env file, disables
service env-file resolution **before** parsing the source Compose configuration,
removes all service `env_file` entries and forces the final application's
model/provider credentials empty and agent modes off. A Compose version without
this option fails configuration; there is no fallback that reads user env files.
It uses a loopback-only host port, empty read-only repository input and temporary
experiment output, and rewrites named volumes and networks to unique
project-scoped names. It does not read the checkout's `.env`
file, send remote model calls, or prune Docker resources globally. The report
omits absolute paths and records source commit, command results, service
health, images, cleanup and a path scan. Use `--source-sha` only when running
from a source archive without Git metadata; its value must be a 40-character
lowercase commit hash.

Before starting, the runner checks both Compose project labels and the actual
volume/network names. Any existing resource with those names is a conflict,
including unlabelled resources. Created containers, networks and volumes carry
an unpredictable per-run ownership label. Cleanup records resource identities,
rechecks their project/run labels and identities, then removes only those exact
resources. It never invokes `compose down --volumes`, removes project orphans,
or prunes resources. If a resource was replaced or ownership cannot be verified,
it is retained and cleanup fails visibly in `smoke.json`; inspect the recorded
manifest before any manual cleanup.

Actual container image IDs, references and available registry digests for all
four services are collected **before** cleanup. Missing or incomplete image
evidence prevents a passing result. Built app/analyzer images use unique
project tags so the smoke build cannot overwrite `lima:local` or
`lima-cxx-analyzer:local`. These tagged images/build cache are retained; cleanup's
resource manifest covers containers, networks and volumes, not global image
storage.
`--base-image-registry` temporarily overrides only the pinned Python and Node
Dockerfile build arguments in the generated Compose file, which is useful when
Docker Hub is unreachable. It does not edit the Dockerfile or configure Docker
Desktop. `--debian-mirror` generates a temporary C++ analyzer Dockerfile under
the system temporary directory with the Debian source URL rewritten for that
build. The checked-out Dockerfile is never modified and the temporary file is
removed after the smoke run. When omitted, the analyzer uses Debian's official
server.

Exit status is `0` only when the runtime and health probes pass; `2` indicates
failed or unverified. Common report reasons include `docker-not-found`,
`port-conflict`, `compose-start-failed` and `timeout`. A build that cannot
contact its image registry is a real deployment failure, not a passing smoke
test. Unit tests with a fake Docker CLI verify the reporting and cleanup logic,
but do not replace a successful Docker run.

Regression checks:

```powershell
python -m unittest tests.test_competition_deploy_smoke -v
# Optional real Docker checks: config parsing and disposable empty volumes only.
$env:LIMA_RUN_DOCKER_SMOKE_REGRESSIONS = '1'
python -m unittest tests.test_competition_deploy_smoke.RealDockerRegressionTests -v
Remove-Item Env:LIMA_RUN_DOCKER_SMOKE_REGRESSIONS
```

The opt-in checks never build/start services, use real model credentials or
touch existing deployments. They do not replace a complete deployment run for
the final frozen SHA or the remaining manual acceptance checks in #298.
