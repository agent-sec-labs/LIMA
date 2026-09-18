# ResInsight build container (LIMA workstream A, task A3).
#
# This image is the "dirty room": it exists only to run the repository's
# configure step once and export an analysis context package.  It is never
# the analysis sandbox.  Network access and root package installation are
# expected here; the produced package keeps the analysis side dependency-free.
#
# Build (local only, never pushed to a registry):
#   docker build -t lima-builder-resinsight:latest deploy/build-recipes/resinsight
#
# python3 is required: the recipe executor lists container files with an
# in-container python3 glob helper.
FROM debian:bookworm-slim

# ResInsight CMake configure requirements: Qt5 (base + OpenGL + SVG for the
# gui module), HDF5, Boost, Eigen3, BLAS/LAPACK, zlib, plus the C++ toolchain
# and CMake.  When in doubt, listed over missing -- report gaps to the recipe.
RUN apt-get update && apt-get install --yes --no-install-recommends \
        build-essential \
        cmake \
        qtbase5-dev \
        libqt5opengl5-dev \
        libqt5svg5-dev \
        libhdf5-dev \
        libboost-all-dev \
        libeigen3-dev \
        libblas-dev \
        liblapack-dev \
        zlib1g-dev \
        python3 \
        git \
    && rm -rf /var/lib/apt/lists/*

# The recipe executor mounts the repository source tree here and runs every
# configure command with /src as the working directory.
WORKDIR /src
