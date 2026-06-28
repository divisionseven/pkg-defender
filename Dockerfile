# Build stage
FROM python:3.11-alpine AS builder
ARG TARGETPLATFORM
ARG BUILDPLATFORM
WORKDIR /app

# Install build dependencies for C extensions
RUN apk add --no-cache gcc musl-dev python3-dev libffi-dev

# Copy project files
COPY . .

# Pin wheel to fix CVE-2026-24049 (privilege escalation)
RUN pip install --no-cache-dir --upgrade "wheel>=0.46.2"

# Install the package (non-editable — copies files into site-packages)
RUN pip install --no-cache-dir --user .

# Production stage
FROM python:3.11-alpine
ARG TARGETPLATFORM
ARG BUILDPLATFORM
WORKDIR /app

COPY --from=builder /root/.local/bin/pkgd /usr/local/bin/pkgd
COPY --from=builder /root/.local/lib/python3.11/site-packages/ /usr/local/lib/python3.11/site-packages/

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
