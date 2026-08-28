ARG PYTHON_BASE_IMAGE=public.ecr.aws/docker/library/python:3.11-slim@sha256:9c900dea9e8fb7e16277c179b555cc72d29a352dbc33cff48ad5a0412fd5bfc7
FROM ${PYTHON_BASE_IMAGE} AS base

ARG SEMGREP_VERSION=1.130.0
ARG LLVM_MAJOR=14
ARG CMAKE_MAJOR=3
ARG ANALYZER_UID=10002
ARG ANALYZER_GID=10002

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/analyzer \
    CC=clang-14 \
    CXX=clang++-14

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        "clang-${LLVM_MAJOR}" \
        "clang-tools-${LLVM_MAJOR}" \
        cmake \
        "llvm-${LLVM_MAJOR}" \
    && cmake --version | grep --quiet "^cmake version ${CMAKE_MAJOR}\." \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install "semgrep==${SEMGREP_VERSION}"

RUN groupadd --gid "${ANALYZER_GID}" analyzer \
    && useradd --uid "${ANALYZER_UID}" --gid "${ANALYZER_GID}" \
        --create-home --shell /usr/sbin/nologin analyzer \
    && mkdir --parents /app /work/snapshots /work/tmp \
    && chown --recursive analyzer:analyzer /app /work

WORKDIR /app
COPY --chown=analyzer:analyzer cxx_analyzer ./cxx_analyzer

FROM base AS runtime
USER analyzer:analyzer
CMD ["python", "-m", "cxx_analyzer.server"]

FROM base AS test
COPY --chown=analyzer:analyzer lima ./lima
COPY --chown=analyzer:analyzer tests ./tests
USER analyzer:analyzer
