# G2 Privileged Chaos Helper Container Package - Hardened Remediation
# Base image pinned to Debian 12 (bookworm-slim) with latest security updates enabled.

FROM python:3.11.9-slim-bookworm@sha256:2856e6af199e8128161abd320575eb9b341f3b76f017b5d0c9cd364f60d8a050

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    G2_HELPER_LOG_FORMAT=json

# Apply Debian 12 security updates and install minimal networking tools required for netem packet loss
RUN apt-get update \
    && apt-get upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
       iproute2 \
       util-linux \
       procps \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Create dedicated unprivileged user for default non-root execution.
# Security boundary: Runs as non-root UID 65532:65532 by default.
# Privileged boundary: In Kubernetes, pod securityContext overrides runAsUser: 0
# with capabilities NET_ADMIN + SYS_ADMIN ONLY during an approved chaos Job run.
RUN groupadd --gid 65532 g2helper \
    && useradd --uid 65532 --gid 65532 --shell /usr/sbin/nologin --no-create-home g2helper

WORKDIR /opt/g2-helper

# Copy G2 helper runtime code (zero credentials, zero TLS keys, zero secrets)
COPY g2_packet_loss_runtime.py /opt/g2-helper/g2_packet_loss_runtime.py
COPY g2_authorizer.py /opt/g2-helper/g2_authorizer.py
COPY g2_process_discovery.py /opt/g2-helper/g2_process_discovery.py
COPY g2_helper_daemon.py /opt/g2-helper/g2_helper_daemon.py
COPY g2_helper_entrypoint.py /opt/g2-helper/g2_helper_entrypoint.py

RUN chown -R 65532:65532 /opt/g2-helper

USER 65532:65532

EXPOSE 8081

ENTRYPOINT ["python", "/opt/g2-helper/g2_helper_entrypoint.py"]
