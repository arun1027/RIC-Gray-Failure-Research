"""
g1_manifest_validator.py - Static Container & Kubernetes Manifest Image Integrity Validator.

Workstream 7:
- Refuses placeholder image references (<...>), mutable tags (:latest, :3.11.9-slim-bookworm without @sha256),
  and missing @sha256:[0-9a-f]{64} digests in deployment manifests.
"""

import re
from typing import List


class ImageIntegrityError(Exception):
    """Raised when a container or Kubernetes manifest uses a mutable or placeholder image reference."""
    pass


DIGEST_PATTERN = re.compile(r"^[^\s<>]+@sha256:[0-9a-f]{64}$")


def validate_immutable_image_ref(image_ref: str) -> None:
    ref = image_ref.strip()
    if not ref or "<" in ref or ">" in ref or "REQUIRED" in ref or "PLACEHOLDER" in ref:
        raise ImageIntegrityError(f"Placeholder or incomplete image reference rejected: '{image_ref}'.")
    if not DIGEST_PATTERN.fullmatch(ref):
        raise ImageIntegrityError(
            f"Mutable or unpinned image reference rejected: '{image_ref}'. Expected '<repo>@sha256:<64-hex>'."
        )


def validate_manifest_images(yaml_text: str) -> List[str]:
    """Extracts all `image:` lines from a Kubernetes YAML manifest and validates each is digest-pinned."""
    found: List[str] = []
    for line in yaml_text.splitlines():
        stripped = line.strip()
        if stripped.startswith("image:"):
            ref = stripped.split(":", 1)[1].strip().strip('"').strip("'")
            validate_immutable_image_ref(ref)
            found.append(ref)
    if not found:
        raise ImageIntegrityError("No image references found in manifest.")
    return found

