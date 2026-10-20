# Canonical ResInsight build image for LIMA full-build.json.
# Also supplies the optional configure-only analysis-context workflow.
#
# Build (local only, never pushed to a registry):
#   docker build -t lima-builder-resinsight:full-build deploy/build-recipes/resinsight
#
# python3 is required: the recipe executor lists container files with an
# in-container python3 glob helper.
FROM debian:trixie-slim

# Current ResInsight requires GCC >=13, CMake >=3.26 and Qt6 (C++23).
RUN apt-get update && apt-get install --yes --no-install-recommends \
        build-essential \
        ca-certificates \
        cmake \
        ninja-build \
        curl zip unzip tar \
        qt6-base-dev \
        qt6-base-dev-tools \
        libgl1-mesa-dev \
        libhdf5-dev \
        libboost-all-dev \
        libeigen3-dev \
        libblas-dev \
        liblapack-dev \
        zlib1g-dev \
        python3 \
        git \
    && cmake --version | head -1 \
    && ninja --version \
    && rm -rf /var/lib/apt/lists/*

# The recipe executor mounts the repository source tree here and runs every
# configure command with /src as the working directory.
WORKDIR /src

RUN apt-get update && apt-get install --yes --no-install-recommends \
        qt6-svg-dev qt6-networkauth-dev qt6-base-private-dev \
        pkg-config autoconf automake libtool bison flex \
        libglu1-mesa-dev libxkbcommon-x11-dev xvfb xauth \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /work
