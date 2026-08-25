# Repository import area

Place only repositories that you are authorized to audit below this directory.
Each immediate or nested subdirectory becomes a logical repository key, for
example repositories/team/project is submitted as team/project.

Docker Compose mounts this directory at /repositories as read-only. The API
rejects absolute paths, parent traversal, hidden path segments, and resolved
paths outside this directory. Repository code is analyzed as data and is not
executed.

To use another host directory, set EVOAGENT_REPOSITORY_IMPORT_PATH in .env and
restart the Compose stack. Do not commit imported repositories.
