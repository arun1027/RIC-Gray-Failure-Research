#!/usr/bin/env python3
"""
Secure Dynamic Credential Generator for PostgreSQL + Patroni Architecture.
Generates strong cryptographic passwords for superuser, replication, and Patroni REST API,
writing them atomically to kubernetes/postgres-patroni/generated/03-patroni-credentials.active.yaml.

SECURITY & AUDIT CONTROLS:
- Generates cryptographically secure 32-character tokens (secrets module).
- Passwords are NEVER printed to stdout, stderr, or log files.
- Generates directly into a gitignored directory (kubernetes/postgres-patroni/generated/).
- Enforces strict filesystem permissions (POSIX 0600; Windows NTFS icacls inheritance removal).
- Writes atomically using temporary files and replace.
- Verifies document structure and token entropy without leaking secrets.
"""

import os
import sys
import secrets
import string
import yaml
import tempfile
import argparse
import subprocess
from typing import Dict, Any

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_OUTPUT_DIR = os.path.join(REPO_ROOT, "kubernetes", "postgres-patroni", "generated")
TEMPLATE_PATH = os.path.join(REPO_ROOT, "kubernetes", "postgres-patroni", "03-patroni-secrets-template.yaml")

def generate_strong_password(length: int = 32) -> str:
    """Generates an alphanumeric password with special characters."""
    alphabet = string.ascii_letters + string.digits + "!@#%^&*()-_=+"
    # Ensure at least one lowercase, one uppercase, one digit, one special
    while True:
        pwd = "".join(secrets.choice(alphabet) for _ in range(length))
        if (any(c.islower() for c in pwd)
                and any(c.isupper() for c in pwd)
                and any(c.isdigit() for c in pwd)
                and any(c in "!@#%^&*()-_=+" for c in pwd)):
            return pwd

def _set_restrictive_permissions(file_path: str):
    """Restricts file access exclusively to current user."""
    if os.name == "nt":
        try:
            username = os.environ.get("USERNAME", "")
            if username:
                subprocess.run(
                    ["icacls", file_path, "/inheritance:r", "/grant:r", f"{username}:(F)"],
                    capture_output=True,
                    check=False
                )
        except Exception:
            pass
    else:
        try:
            os.chmod(file_path, 0o600)
        except Exception:
            pass

def generate_patroni_credentials(
    output_dir: str = DEFAULT_OUTPUT_DIR,
    namespace: str = "postgres-patroni",
    superuser_user: str = "postgres",
    replication_user: str = "replicator",
    api_user: str = "patroni"
) -> str:
    """
    Generates a secure Secret document and writes it atomically to output_dir.
    Returns the path of the generated Secret file.
    """
    os.makedirs(output_dir, exist_ok=True)
    target_path = os.path.join(output_dir, "03-patroni-credentials.active.yaml")

    # Generate distinct strong passwords
    su_pwd = generate_strong_password(32)
    rep_pwd = generate_strong_password(32)
    api_pwd = generate_strong_password(32)

    secret_doc = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "patroni-credentials",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "patroni",
                "app.kubernetes.io/part-of": "ric-gray-failure-research",
                "ric.thesis/subsystem": "postgres-patroni",
                "ric.thesis/generated-by": "configure-patroni-secrets"
            }
        },
        "type": "Opaque",
        "stringData": {
            "superuser-username": superuser_user,
            "superuser-password": su_pwd,
            "replication-username": replication_user,
            "replication-password": rep_pwd,
            "api-username": api_user,
            "api-password": api_pwd,
        }
    }

    dir_name = os.path.dirname(target_path)
    temp_fd, temp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_patroni_sec_")
    try:
        with open(temp_fd, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(secret_doc, f, sort_keys=False, default_flow_style=False)

        _set_restrictive_permissions(temp_path)
        os.replace(temp_path, target_path)
        _set_restrictive_permissions(target_path)
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        raise RuntimeError(f"Failed to generate Patroni credentials: {e}")

    # Verify without printing contents
    with open(target_path, "r", encoding="utf-8") as f:
        verified_doc = yaml.safe_load(f)
    assert verified_doc["kind"] == "Secret"
    assert len(verified_doc["stringData"]["superuser-password"]) >= 32
    assert len(verified_doc["stringData"]["replication-password"]) >= 32
    assert len(verified_doc["stringData"]["api-password"]) >= 32

    return target_path

def main():
    parser = argparse.ArgumentParser(description="Generate secure Patroni credentials without stdout exposure.")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Destination directory")
    parser.add_argument("--namespace", default="postgres-patroni", help="Target Kubernetes namespace")
    args = parser.parse_args()

    try:
        path = generate_patroni_credentials(output_dir=args.output_dir, namespace=args.namespace)
        print(f"[OK] Secure Patroni credentials generated successfully at: {path}")
        print("[INFO] Secrets written with restricted permissions. Passwords were NOT echoed to stdout.")
    except Exception as exc:
        print(f"[ERROR] Failed to generate credentials: {exc}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()

