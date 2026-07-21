# Build stage
FROM python:3.11-alpine@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4 AS builder
ARG TARGETPLATFORM
ARG BUILDPLATFORM
WORKDIR /app

# Install build dependencies for C extensions
RUN apk add --no-cache gcc musl-dev python3-dev libffi-dev

# Copy project files
COPY . .

# Install uv (single binary, no Python deps)
COPY --from=ghcr.io/astral-sh/uv@sha256:eb2843a1e56fd9e30c7276ce1a52cba86e64c7b385f5e3279a0e08e02dd058fc /uv /usr/local/bin/uv

# Pin wheel to fix CVE-2026-24049 (privilege escalation)
RUN uv pip install --system --no-cache --upgrade "wheel>=0.46.2"

# Install the package (non-editable — copies files into site-packages)
RUN uv pip install --system --no-cache .

# Production stage
FROM python:3.11-alpine@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4
ARG TARGETPLATFORM
ARG BUILDPLATFORM
WORKDIR /app

COPY --from=builder /usr/local/bin/pkgd /usr/local/bin/pkgd
COPY --from=builder /usr/local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/

# Remove build tools not needed at runtime (fixes CVE-2026-23949, CVE-2026-24049)
RUN pip uninstall -y pip setuptools wheel 2>/dev/null || true; \
    find /usr/local/lib/python3.11/site-packages -name "__pycache__" -type d -exec rm -rf {} + 2>/dev/null || true

# Create non-root user for security
RUN addgroup -g 1000 pquser && \
    adduser -u 1000 -G pquser -D pquser && \
    mkdir -p /home/pquser/.config/pkg-defender /home/pquser/.local/share/pkg-defender && \
    chown -R pquser:pquser /home/pquser

USER pquser

# Persistent data directories (mounted as volumes at runtime)
VOLUME ["/home/pquser/.config/pkg-defender", "/home/pquser/.local/share/pkg-defender"]

WORKDIR /home/pquser

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD pkgd health -o json || exit 1

# Default command
CMD ["pkgd", "daemon", "run"]
