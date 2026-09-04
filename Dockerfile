ARG PYTHON_BASE_IMAGE=public.ecr.aws/docker/library/python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7
ARG NODE_BASE_IMAGE=public.ecr.aws/docker/library/node:22-alpine@sha256:c610fcdfb1d5b4740dd70c284ed3cb16bb857e0f7166196e36a5501df7a3aa32

# Node 仅存在于构建期：产出纯静态 dist，生产 runtime 无 Node（T5）。
FROM ${NODE_BASE_IMAGE} AS frontend-build
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY frontend ./
RUN npm run build

FROM ${PYTHON_BASE_IMAGE} AS base

ARG APP_UID=10001
ARG APP_GID=10001

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/lima

RUN groupadd --gid "${APP_GID}" lima \
    && useradd --uid "${APP_UID}" --gid "${APP_GID}" --create-home lima \
    && install -d -o "${APP_UID}" -g "${APP_GID}" \
        /experiments /experiment-cache /var/lib/lima/repository-cache \
        /var/lib/lima/repair-workspace

WORKDIR /app
COPY requirements.txt ./
RUN python -m pip install -r requirements.txt
# React 静态产物随镜像分发；生产容器无需 Node runtime。
COPY --from=frontend-build /build/dist ./frontend/dist

COPY --chown=lima:lima lima ./lima
COPY --chown=lima:lima skills ./skills
COPY --chown=lima:lima scripts/scan_repository.py ./scripts/scan_repository.py
COPY --chown=lima:lima scripts/run_repair_evaluation.py ./scripts/run_repair_evaluation.py
COPY --chown=lima:lima scripts/run_real_world_evaluation.py ./scripts/run_real_world_evaluation.py
COPY --chown=lima:lima scripts/run_real_project_oracle.py ./scripts/run_real_project_oracle.py
COPY --chown=lima:lima scripts/probe_llm_triage.py ./scripts/probe_llm_triage.py
COPY --chown=lima:lima evaluation_data ./evaluation_data

FROM base AS test
# CXX-I01：analyzer 测试在镜像内导入 cxx_analyzer（生产 runtime 不带，Sidecar 独立成镜像）。
COPY --chown=lima:lima cxx_analyzer ./cxx_analyzer
COPY --chown=lima:lima tests ./tests
COPY --chown=lima:lima Dockerfile pyproject.toml docker-compose.yml .env.example LIMA_ROADMAP.md CONTRIBUTING.md ./
COPY --chown=lima:lima .github ./.github
# 契约测试在镜像内校验前端 CI 门禁与产物布局（T9）以及 React 唯一前端
# 结构契约（T10）：带配置与源码原文，不带 e2e 夹具语料（不进任何镜像层）。
COPY --chown=lima:lima frontend/package.json frontend/index.html frontend/vitest.config.ts frontend/playwright.config.ts ./frontend/
COPY --chown=lima:lima frontend/src ./frontend/src
COPY --chown=lima:lima frontend/e2e/audit-lifecycle.spec.ts ./frontend/e2e/
COPY --chown=lima:lima .gitignore README.md ./
COPY --chown=lima:lima docs/DEVELOPER_HANDOFF.md docs/GITHUB_COLLABORATION.md ./docs/
COPY --chown=lima:lima docs/assets ./docs/assets
COPY --chown=lima:lima scripts/lima.ps1 ./scripts/lima.ps1
COPY --chown=lima:lima scripts/run_ci_tests.py ./scripts/run_ci_tests.py
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
