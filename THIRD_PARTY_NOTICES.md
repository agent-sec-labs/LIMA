# Third-Party Notices

LIMA's original source code, documentation, tests, UI, annotations, and tooling
are licensed under Apache-2.0. The following external material remains governed
by its own upstream terms.

## Runtime and development dependencies

Direct Python dependencies are declared in `requirements.txt`:

- Psycopg;
- redis-py;
- PyJWT and its cryptography extra;
- OpenTelemetry SDK and OTLP HTTP exporter;
- Bandit.

LIMA does not vendor their source code. Installing or distributing a built
environment may introduce these packages and their transitive dependencies;
consult the package metadata and upstream repositories for the exact version's
license and notices.

Container images are pinned in `Dockerfile` and `docker-compose.yml`, including
Python, PostgreSQL, and Redis images. Their image layers, bundled system
packages, and software retain their respective licenses.

## Public security and repository data

Some evaluation manifests reference public CVE/GHSA records, commits, pull
requests, and upstream source excerpts. Copyright and license terms for upstream
code are not replaced by LIMA's Apache-2.0 license. LIMA's selection,
annotations, Oracles, hashes, and evaluation tooling are licensed under
Apache-2.0; referenced or embedded upstream code remains under its original
license. See [evaluation_data/README.md](evaluation_data/README.md).

When adding a dependency or dataset, include its canonical source, version or
commit, license identifier, and any required attribution in this file or the
dataset manifest. Do not add material whose redistribution terms are unknown.

### C/C++ memory evaluation references

`evaluation_data/cxx_memory_cases.json` references, but does not vendor, source
archives from these upstream projects:

- curl/curl, fixed commit
  `3da249e1f0716c06644ed3522a37a8bf81808012`, curl License;
- podofo/podofo, fixed commit
  `22d16cb142f293bf956f66a4d399cdd65576d36c`, LGPL-2.0-or-later;
- allinurl/goaccess, fixed commits
  `ba813ed97d998dbdcb8d87e178799a4bb2da9e81` and
  `81f90d9dafd6956c188dea9f944d24946d3d3351`, MIT License.

The manifest records repositories, both revisions, archive hashes,
advisory/fix sources, and fixed license URLs. Downloaded source remains under
the upstream license and is kept only in caller-selected cache or temporary
directories.
