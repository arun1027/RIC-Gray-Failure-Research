# G1 Privileged Chaos Helper Container Package
# Phase F.2.1 — Reproducible build definition (NOT built or pushed in this phase).
# Base image pinned to Debian 12 (bookworm-slim). During an approved build, resolve and
# pin the exact multi-arch/amd64 @sha256 digest in CI/build logs.

FROM python:3.11.9-slim-bookworm@sha256:2856e6af199e8128161abd320575eb9b341f3b76f017b5d0c9cd364f60d8a050

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    G1_HELPER_LOG_FORMAT=json

# Install only minimal Linux networking and namespace tools from pinned Debian Bookworm snapshot.
RUN sed -i \
      -e 's|URIs: http://deb.debian.org/debian$|URIs: http://snapshot.debian.org/archive/debian/20240904T090000Z|' \
      -e 's|URIs: http://deb.debian.org/debian-security|URIs: http://snapshot.debian.org/archive/debian-security/20240904T090000Z|' \
      /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && apt-get install -y --no-install-recommends \
       iproute2=6.1.0-3 \
       util-linux=2.38.1-5+deb12u1 \
       procps=2:4.0.2-3 \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged user for default non-root execution.
# Privileged boundary: Kubernetes Pod/Container securityContext overrides runAsUser: 0
# with capabilities NET_ADMIN + SYS_ADMIN ONLY during an approved chaos Job run.
RUN groupadd --gid 65532 g1helper \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home g1helper

WORKDIR /opt/g1-helper

# Copy only helper runtime code (no AWS credentials, no TLS private keys, no Secrets).
COPY benchmark/scripts/cockroachdb/g1/g1_fault_controller.py /opt/g1-helper/g1/g1_fault_controller.py
COPY benchmark/scripts/cockroachdb/g1/g1_linux_runtime.py /opt/g1-helper/g1/g1_linux_runtime.py
COPY benchmark/scripts/cockroachdb/g1/g1_helper_daemon.py /opt/g1-helper/g1/g1_helper_daemon.py
COPY benchmark/scripts/cockroachdb/g1/g1_recovery_authorizer.py /opt/g1-helper/g1/g1_recovery_authorizer.py
COPY benchmark/scripts/cockroachdb/g1/g1_helper_authorizer.py /opt/g1-helper/g1/g1_helper_authorizer.py
COPY docker/g1-helper/g1_helper_entrypoint.py /opt/g1-helper/g1_helper_entrypoint.py

RUN touch /opt/g1-helper/g1/__init__.py \
    && chown -R 65532:65532 /opt/g1-helper

USER 65532:65532

EXPOSE 8081

ENTRYPOINT ["python3", "/opt/g1-helper/g1_helper_entrypoint.py"]

