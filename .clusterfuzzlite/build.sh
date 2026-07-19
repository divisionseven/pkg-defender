#!/bin/bash
# Copyright (c) 2026 DIVISION 7 | MI-7 (@divisionseven)
# SPDX-License-Identifier: Apache-2.0

# Build script for ClusterFuzzLite fuzzing.
# Compiles the atheris-based fuzz target.

set -euo pipefail

cd /src/pkg-defender

# Install the project and atheris
pip install "uv==0.5.1" --hash=sha256:4d1ec4a1bc19b523a84fc1bf2a92e9c4d982c831d3da450af71fc3057999d456 --require-hashes
uv pip install --system --no-deps .
uv pip install --system "atheris==2.3.0"
