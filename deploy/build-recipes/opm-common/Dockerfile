FROM debian:trixie-slim
RUN apt-get update && apt-get install --yes --no-install-recommends \
    build-essential cmake ninja-build python3 git ca-certificates curl \
    libboost-filesystem-dev libboost-regex-dev libboost-test-dev \
    libcjson-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
