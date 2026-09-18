# Build Recipes (`deploy/build-recipes/`)

A build recipe is the declaration of how one repository's compilation
context is produced **once, inside a per-repository build container**, and
exported as a dependency-free "analysis context package" that the LIMA
analysis sandbox consumes.  The build container is the *dirty room*: it may
need network access and root-installed dependencies.  The analysis sandbox
stays the *sterile room*: it never installs anything and only reads the
package.

Each recipe is a directory:

```
deploy/build-recipes/<name>/
    Dockerfile      # the build container image
    recipe.yaml     # how to configure the repo and what to export
```

## Writing a recipe in three steps

1. **Write the `Dockerfile`.** Base it on a slim distro, install the
   repository's configure-time dependencies (toolchain, cmake, third-party
   dev headers), and `WORKDIR` at the mount point (convention: `/src`).
   The image **must ship `python3`** -- the recipe executor lists container
   files with an in-container python3 glob helper.  Build it locally and
   never push it to a registry: `docker build -t lima-builder-<name>:latest
   deploy/build-recipes/<name>`.

2. **Write the `recipe.yaml`** (schema v1, all keys required unless noted):

   | Field | Meaning | Validation |
   |---|---|---|
   | `schema_version` | recipe format version | must be `1` |
   | `name` | recipe identity; becomes the manifest `created_by` | non-empty text |
   | `image` | build container image reference | non-empty text |
   | `repository` | repository identifier; becomes manifest `repository` | non-empty text |
   | `source_mount` | container path the source tree is mounted at | absolute container path |
   | `configure` | argv lists run in order, working directory `source_mount` | non-empty list of non-empty argv lists |
   | `compdb_path` | where configure exports the compdb, relative to the source root | safe relative path, no `..` |
   | `generated_globs` | configure-generated headers, relative to the source root (optional, may be empty) | safe relative globs |
   | `include_roots` | vendored third-party include roots (optional) | `{container: <abs path>, package: <name>}` entries |

   Parsing is strict: unknown keys, duplicate YAML keys, unsafe paths
   (`..`, absolute `compdb_path`), reserved `package` names
   (`generated`, `compile_commands.json`, `context_manifest.json`), nested
   or duplicate `package` roots, and include roots inside `source_mount`
   are all rejected.  The first configure command with `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON`
   is what exports the compilation database; configure-only is the contract,
   never `--build`.

3. **Validate by running it** (main agent, needs Docker):

   ```python
   from pathlib import Path
   from lima.build_recipe import BuildRecipe, run_recipe_in_container

   recipe = BuildRecipe.from_file(Path("deploy/build-recipes/<name>/recipe.yaml"))
   manifest = run_recipe_in_container(
       recipe,
       Path("<repository source tree>"),
       work_dir=Path("<output package directory>"),
       revision="<git sha of the source tree>")
   ```

   `run_recipe_in_container` fails closed: any non-zero configure exit means
   no package is written at all.  Success is defined by A1's
   `read_package(work_dir)` verifying the package end-to-end.

## `include_roots` naming convention

- `container` is the absolute include path inside the build image (for
  Debian multi-arch Qt on amd64: `/usr/include/x86_64-linux-gnu/qt5`; for
  Debian HDF5 the parent `/usr/include/hdf5` covers the `serial/` layout).
- `package` is the package-relative root the prefix is rewritten to.
  Convention: `headers/<library>` (e.g. `headers/qt5`, `headers/hdf5`).
  A compdb flag `-isystem /usr/include/qt5/QtCore` becomes
  `-isystem headers/qt5/QtCore` in the package, and the referenced files
  are vendored at `headers/qt5/...` inside the package.
- Prefer the library's top include directory as `container` so submodule
  layouts (`hdf5/serial`, `qt5/QtCore`) are covered by one root.

Header collection granularity: every include-directory flag under a root
vendors that whole directory subtree (plus directly forced files such as
`-include`).  This over-collects rather than under-collects, so a package
can never miss a transitively included header; do not point `container` at
a giant root (e.g. `/usr/include`) when the compdb only references a few
subdirectories.

## Known limitations

- The build container needs **network and root** for package installation.
  That is by design: the dirty room does the dependency work once; the
  analysis sandbox stays sealed.
- `list_globs` requires **python3 inside the image**.
- Include roots whose files are all unreferenced are dropped from the
  package manifest (empty roots would fail A1's reader); their rewrite
  entries stay, which is harmless.
- Header collection is per-referenced-directory, not per-`#include`; expect
  a few dozen files per referenced directory rather than exactly 30 headers
  for 30 includes.
- Multi-arch container paths differ by architecture (the ResInsight recipe
  hard-codes `x86_64-linux-gnu`).
- Configure may be slow (minutes); the production runner allows one hour
  per container command.
- An include directory referenced by the compdb but not covered by any
  `include_roots` entry stays absolute in the package; the analysis side
  will report those translation units as unresolved rather than crash.
