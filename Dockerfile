ARG PYTHON_BASE_IMAGE=public.ecr.aws/docker/library/python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7
FROM ${PYTHON_BASE_IMAGE} AS base

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/lima

RUN groupadd --gid "${APP_GID}" lima \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home lima

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install -r requirements.txt

COPY --chown=lima:lima lima ./lima
COPY --chown=lima:lima web ./web
COPY --chown=lima:lima skills ./skills
COPY --chown=lima:lima scripts/scan_repository.py ./scripts/scan_repository.py
COPY --chown=lima:lima scripts/run_repair_evaluation.py ./scripts/run_repair_evaluation.py
COPY --chown=lima:lima scripts/run_real_world_evaluation.py ./scripts/run_real_world_evaluation.py
COPY --chown=lima:lima scripts/run_real_project_oracle.py ./scripts/run_real_project_oracle.py
COPY --chown=lima:lima scripts/probe_llm_triage.py ./scripts/probe_llm_triage.py
COPY --chown=lima:lima evaluation_data ./evaluation_data

FROM base AS test
COPY --chown=lima:lima tests ./tests
COPY --chown=lima:lima Dockerfile pyproject.toml docker-compose.yml .env.example LIMA_ROADMAP.md ./
COPY --chown=lima:lima scripts/lima.ps1 ./scripts/lima.ps1
USER lima:lima
CMD ["python", "-m", "unittest", "discover", "-s", "tests", "-v"]

FROM base AS real-eval
USER root
RUN python -m pip install "gitdb>=4,<5" "smmap>=5,<6"
USER lima:lima

FROM base AS runtime
USER lima:lima
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=5 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).read()"]
CMD ["python", "-m", "lima"]
