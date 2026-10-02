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
COPY --chown=lima:lima scripts/run_e2e_evaluation.py ./scripts/run_e2e_evaluation.py
COPY --chown=lima:lima scripts/run_real_project_oracle.py ./scripts/run_real_project_oracle.py
COPY --chown=lima:lima scripts/probe_llm_triage.py ./scripts/probe_llm_triage.py
COPY --chown=lima:lima evaluation_data ./evaluation_data

FROM base AS test
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
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0031_Offline_Budget_Gate.md ./docs/
COPY --chown=lima:lima docs/LIMA_PR3d_Real_Run_Budget_Decision_Pack.md ./docs/
COPY --chown=lima:lima docs/LIMA_PR3d_Real_Run_Approval_2026-09-27.md ./docs/
COPY --chown=lima:lima docs/LIMA_PR3d_Real_Run_Approval_2026-09-28.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0032_Real_Run.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0033_Real_Run_Diagnostics.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0034_Identity_SF01.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0035_Time_Governance.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0036_PR3e_Offline_Integration.md ./docs/
COPY --chown=lima:lima docs/LIMA_PR3e_Requirement_Matrix_v2.md ./docs/
COPY --chown=lima:lima docs/LIMA_PR3e_Expert_Review_Package.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0037_Batch_Protocol.md ./docs/
COPY --chown=lima:lima docs/LIMA_PR3e_V5_Field_Source_Table.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0038_Preflight_Calibration.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0039_Real_Pilot_Descriptor.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0040_B1_Source_Wiring.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0041_B1_Real_Entry.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0042_B1_Canonical_Wiring.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0043_LF_Local_Baseline.md ./docs/
COPY --chown=lima:lima docs/LIMA_IP0043_Coverage_Account_and_Dependency_Correction.md ./docs/
COPY --chown=lima:lima docs/LIMA_Expert_Review_Evidence_Pair_Followup_2026-10-02.md ./docs/
COPY --chown=lima:lima docs/LIMA_57_Baseline_Product_Report_2026-10-02.md ./docs/
COPY --chown=lima:lima docs/LIMA_Implementation_Packet_IP-0020_Vault_Audit.md ./docs/
COPY --chown=lima:lima docs/adr ./docs/adr
COPY --chown=lima:lima schemas ./schemas
COPY --chown=lima:lima docs/assets ./docs/assets
COPY --chown=lima:lima scripts/lima.ps1 ./scripts/lima.ps1
COPY --chown=lima:lima scripts/run_ci_tests.py ./scripts/run_ci_tests.py
COPY --chown=lima:lima scripts/run_lf_baseline.py ./scripts/run_lf_baseline.py
COPY --chown=lima:lima scripts/run_expert_review.py ./scripts/run_expert_review.py
COPY --chown=lima:lima scripts/verify_expert_review.py ./scripts/verify_expert_review.py
COPY --chown=lima:lima scripts/audit_sensitive_artifacts.py ./scripts/audit_sensitive_artifacts.py
# C/C++ 分析器包与评估契约随单测进镜像（纯 Python、无额外依赖）。
COPY --chown=lima:lima cxx_analyzer ./cxx_analyzer
COPY --chown=lima:lima scripts/run_cxx_memory_evaluation.py scripts/prepare_cxx_memory_evaluation_case.py ./scripts/
COPY --chown=lima:lima scripts/run_platform_evaluation.py scripts/run_uaf_v2_evaluation.py ./scripts/
COPY --chown=lima:lima evaluation_data/cxx_memory_cases.json ./evaluation_data/cxx_memory_cases.json
COPY --chown=lima:lima benchmarks ./benchmarks
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
