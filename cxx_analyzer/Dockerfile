FROM public.ecr.aws/docker/library/python:3.11-slim@sha256:b1add8a6f2aca6bcfcf0b9c9b522352f7ce0d62a3d556a2f2f32511aa0cca250 AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1 \
    HOME=/home/analyzer \
    CC=clang-14 \
    CXX=clang++-14

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        autoconf \
        automake \
        "clang-14" \
        "clang-tools-14" \
        cmake \
        libclang-rt-14-dev \
        libfreetype6-dev \
        libgsasl7-dev \
        libssl-dev \
        libtool \
        libxml2-dev \
        "llvm-14" \
        make \
        pkg-config \
        zlib1g-dev \
    && cmake --version | grep --quiet "^cmake version 3\." \
    && mkdir --parents /usr/local/share/lima \
    && dpkg-query --show --showformat='${binary:Package}\t${Version}\n' \
        | LC_ALL=C sort > /usr/local/share/lima/analyzer-toolchain-packages.txt \
    && rm -rf /var/lib/apt/lists/*

RUN python -m pip install "semgrep==1.130.0" \
    && python -m pip freeze --all \
        | LC_ALL=C sort > /usr/local/share/lima/analyzer-python-packages.txt

RUN groupadd --gid 10002 analyzer \
    && useradd --uid 10002 --gid 10002 \
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
