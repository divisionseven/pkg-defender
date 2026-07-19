# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

# ClusterFuzzLite fuzzing image for pkg-defender
# Used by OSS-Fuzz/ClusterFuzzLite to fuzz lock file parsers.

FROM gcr.io/oss-fuzz-base/base-builder-python@sha256:5a4612c556e795e67b19d748dbe74a4fd0535ef0e268086bf4ddd7437d70eb4e

# The OSS-Fuzz base image provides the build infrastructure.
# We only need to copy the source code and setup the build script.

COPY . /src/pkg-defender
WORKDIR /src/pkg-defender

# Build the fuzz target
COPY .clusterfuzzlite/build.sh /src/build.sh

ENV FUZZING_LANGUAGE=python
ENV PROJECT=pkg-defender
