#!/usr/bin/env python3
"""
Dynamic Kubernetes Configuration Generator for Amazon Aurora PostgreSQL-Compatible.
Reads actual Terraform outputs from terraform/aws-eks and generates active Kubernetes
ConfigMaps and Secrets into a dedicated deployment directory (default: kubernetes/aurora/generated).

HARDENED SECURITY & VALIDATION CONTROLS:
- Validates Terraform output JSON structures, types, and non-empty dictionaries.
- Validates Aurora endpoint hostnames against expected AWS RDS regex formats.
- Rejects static development placeholders and invalid cluster identifiers.
- Uses PyYAML serialization with safe_dump (no raw string interpolation or injection).
- Restricts generated secret file permissions (POSIX chmod 0600; Windows NTFS icacls inheritance removal).
- Writes files atomically using temporary files and safe atomic rename.
- Preserves original placeholder template files completely unmodified.
- Generated active secrets are explicitly excluded from Git by .gitignore (*.active.yaml).
"""

import os
import sys
import json
import re
import yaml
import tempfile
import argparse
import subprocess
from typing import Dict, Any, Optional, Tuple

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
TF_DIR = os.path.join(REPO_ROOT, "terraform", "aws-eks")
DEFAULT_OUTPUT_DIR = os.path.join(REPO_ROOT, "kubernetes", "aurora", "generated")

RDS_ENDPOINT_REGEX = re.compile(
    r"^[a-zA-Z0-9-]+(\.cluster-[a-zA-Z0-9]+|\.cluster-ro-[a-zA-Z0-9]+)\.[a-z0-9-]+\.rds\.amazonaws\.com$"
)
PLACEHOLDER_DOMAIN = "cluster-c12345678901.us-east-1.rds.amazonaws.com"
DEVELOPMENT_PASSWORD_TOKEN = "auroraPostgresSecureToken14!"

class ConfigurationError(Exception):
    """Raised when configuration values are invalid or fail closed."""
    pass

def read_terraform_outputs(tf_dir: str = TF_DIR, terraform_binary: Optional[str] = None) -> Dict[str, Any]:
    """
    Reads actual Terraform outputs using `terraform output -json`.
    Validates output structure and fails closed if invalid or empty.
    """
    if not os.path.isdir(tf_dir):
        raise ConfigurationError(f"Terraform directory does not exist: {tf_dir}")

    if not terraform_binary:
        local_app_data = os.environ.get("LOCALAPPDATA", "")
        candidate = os.path.join(local_app_data, "Programs", "Terraform", "terraform.exe")
        terraform_binary = candidate if os.path.exists(candidate) else "terraform"

    cmd = [terraform_binary, f"-chdir={tf_dir}", "output", "-json"]
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, check=True)
        raw_outputs = json.loads(res.stdout)
    except Exception as e:
        raise ConfigurationError(f"Failed to read Terraform outputs from {tf_dir}: {e}")

    if not isinstance(raw_outputs, dict) or not raw_outputs:
        raise ConfigurationError(f"Terraform output JSON is empty or not a valid dictionary: {raw_outputs}")

    extracted: Dict[str, str] = {}
    for k, v in raw_outputs.items():
        if isinstance(v, dict) and "value" in v:
            val = v["value"]
            if not isinstance(val, (str, int, float, bool)):
                raise ConfigurationError(f"Unexpected data type for Terraform output '{k}': {type(val)}")
            extracted[k] = str(val).strip()
        elif isinstance(v, (str, int, float, bool)):
            extracted[k] = str(v).strip()
        else:
            raise ConfigurationError(f"Invalid structure for Terraform output key '{k}': {type(v)}")

    return extracted

def validate_aurora_endpoints(outputs: Dict[str, Any], expected_prefix: str = "ric-") -> Tuple[str, str]:
    """
    Validates cluster_endpoint and reader_endpoint from Terraform outputs.
    Enforces format, expected prefix, and rejects template placeholders.
    """
    if not isinstance(outputs, dict):
        raise ConfigurationError("Outputs must be provided as a dictionary.")

    writer = outputs.get("cluster_endpoint", "")
    reader = outputs.get("reader_endpoint", "")

    if not isinstance(writer, str) or not isinstance(reader, str):
        raise ConfigurationError("Endpoints must be strings.")

    writer = writer.strip()
    reader = reader.strip()

    if not writer or not reader:
        raise ConfigurationError(
            "Missing required Aurora endpoints in Terraform output: "
            f"cluster_endpoint='{writer}', reader_endpoint='{reader}'"
        )

    # Reject known template placeholder strings
    if PLACEHOLDER_DOMAIN in writer or PLACEHOLDER_DOMAIN in reader:
        raise ConfigurationError(
            f"Terraform output returned template placeholder endpoint: '{writer}'. "
            "Must be real AWS RDS endpoint."
        )

    # Validate RDS hostname format
    if not RDS_ENDPOINT_REGEX.match(writer):
        raise ConfigurationError(f"Invalid Aurora writer endpoint hostname format: '{writer}'")
    if not RDS_ENDPOINT_REGEX.match(reader):
        raise ConfigurationError(f"Invalid Aurora reader endpoint hostname format: '{reader}'")

    if not writer.startswith(expected_prefix) or not reader.startswith(expected_prefix):
        raise ConfigurationError(
            f"Endpoint hostnames must start with expected project prefix '{expected_prefix}'. "
            f"Got writer='{writer}', reader='{reader}'"
        )

    return writer, reader

def get_database_credentials(
    password_env_var: str = "AURORA_MASTER_PASSWORD",
    password_file: Optional[str] = None
) -> str:
    """
    Retrieves database credentials from an environment variable or secure local file.
    Never accepts credentials via command-line arguments to avoid process-list exposure.
    Fails closed if password is missing or empty.
    """
    password = ""
    if password_file:
        if not os.path.exists(password_file):
            raise ConfigurationError(f"Specified password file does not exist: {password_file}")
        with open(password_file, "r", encoding="utf-8") as f:
            password = f.read().strip()
    elif password_env_var in os.environ:
        password = os.environ[password_env_var].strip()

    if not password:
        raise ConfigurationError(
            f"Database password not supplied. Set environment variable '{password_env_var}' "
            "or provide a secure password file path."
        )

    if password == DEVELOPMENT_PASSWORD_TOKEN:
        raise ConfigurationError(
            "Rejected static placeholder password from development template. "
            "A secure, unique password is required."
        )

    return password

def _set_restrictive_permissions(file_path: str):
    """
    Applies strict permissions restricted exclusively to the current user.
    - POSIX: chmod 0600
    - Windows NTFS: icacls command resetting inheritance and granting current user :F
    """
    if os.name == "nt":
        try:
            username = os.environ.get("USERNAME", "")
            if username:
                # Remove inheritance and grant full control exclusively to current user
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

def _atomic_write_yaml(target_path: str, data: Dict[str, Any], is_secret: bool = False):
    """
    Writes YAML document atomically with restrictive permissions (0600 for secrets, 0644 for configs).
    """
    dir_name = os.path.dirname(target_path)
    os.makedirs(dir_name, exist_ok=True)

    temp_fd, temp_path = tempfile.mkstemp(dir=dir_name, prefix=".tmp_k8s_")

    try:
        with open(temp_fd, "w", encoding="utf-8", newline="\n") as f:
            yaml.safe_dump(data, f, sort_keys=False, default_flow_style=False)

        if is_secret:
            _set_restrictive_permissions(temp_path)
        else:
            try:
                os.chmod(temp_path, 0o644)
            except Exception:
                pass

        os.replace(temp_path, target_path)

        # Re-apply permission lock on final file
        if is_secret:
            _set_restrictive_permissions(target_path)
    except Exception as e:
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception:
                pass
        raise ConfigurationError(f"Failed to write configuration file atomically to {target_path}: {e}")

def generate_kubernetes_manifests(
    writer_endpoint: str,
    reader_endpoint: str,
    password: str,
    database_name: str = "benchdb",
    username: str = "postgres",
    namespace: str = "aurora-benchmark",
    output_dir: str = DEFAULT_OUTPUT_DIR
) -> Dict[str, str]:
    """
    Generates dynamic ConfigMap and Secret manifests using safe YAML serialization without modifying templates.
    """
    if not isinstance(database_name, str) or not database_name:
        raise ConfigurationError("Invalid database_name")
    if not isinstance(username, str) or not username:
        raise ConfigurationError("Invalid username")
    if not isinstance(namespace, str) or not namespace:
        raise ConfigurationError("Invalid namespace")

    # Safety: Refuse to write inside template directory directly
    abs_output = os.path.abspath(output_dir)
    template_dir = os.path.abspath(os.path.join(REPO_ROOT, "kubernetes", "aurora"))
    if abs_output == template_dir:
        raise ConfigurationError("output_dir cannot be the root template directory; must be a dedicated output folder (e.g. 'generated')")

    configmap_doc = {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "aurora-cluster-config",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "aurora-benchmark",
                "app.kubernetes.io/part-of": "ric-gray-failure-research",
                "ric.thesis/subsystem": "aurora-postgresql",
                "ric.thesis/generated-by": "configure-k8s-endpoints"
            }
        },
        "data": {
            "aurora_engine_version": "14.9",
            "aurora_cluster_identifier": "ric-aurora-cluster",
            "aurora_instance_class": "db.r6g.xlarge",
            "aurora_allocated_instances": "2",
            "aurora_region": "us-east-1",
            "aurora_writer_endpoint": writer_endpoint,
            "aurora_reader_endpoint": reader_endpoint,
            "aurora_port": "5432",
            "aurora_database": database_name,
            "ssl_mode": "verify-full",
            "ssl_root_cert_url": "https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem"
        }
    }

    secret_doc = {
        "apiVersion": "v1",
        "kind": "Secret",
        "metadata": {
            "name": "aurora-credentials",
            "namespace": namespace,
            "labels": {
                "app.kubernetes.io/name": "aurora-benchmark",
                "app.kubernetes.io/part-of": "ric-gray-failure-research",
                "ric.thesis/subsystem": "aurora-postgresql",
                "ric.thesis/generated-by": "configure-k8s-endpoints"
            }
        },
        "type": "Opaque",
        "stringData": {
            "database-user": username,
            "database-password": password,
            "database-name": database_name
        }
    }

    cm_path = os.path.join(output_dir, "03-aurora-cluster-config.active.yaml")
    sec_path = os.path.join(output_dir, "02-aurora-credentials.active.yaml")

    _atomic_write_yaml(cm_path, configmap_doc, is_secret=False)
    _atomic_write_yaml(sec_path, secret_doc, is_secret=True)

    return {"configmap": cm_path, "secret": sec_path}

def main():
    parser = argparse.ArgumentParser(
        description="Safely generate active Kubernetes manifests from Terraform outputs."
    )
    parser.add_argument("--tf-dir", default=TF_DIR, help="Path to Terraform directory")
    parser.add_argument("--output-dir", default=DEFAULT_OUTPUT_DIR, help="Path to write active manifests")
    parser.add_argument("--password-file", help="Path to file containing DB password")
    args = parser.parse_args()

    try:
        outputs = read_terraform_outputs(args.tf_dir)
        writer, reader = validate_aurora_endpoints(outputs)
        password = get_database_credentials(password_file=args.password_file)
        paths = generate_kubernetes_manifests(
            writer_endpoint=writer,
            reader_endpoint=reader,
            password=password,
            output_dir=args.output_dir
        )
        print(f"Generated active ConfigMap at: {paths['configmap']}")
        print(f"Generated active Secret at: {paths['secret']}")
        print("Preflight validation: OK. Endpoints and credentials dynamically bound safely.")
    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()
