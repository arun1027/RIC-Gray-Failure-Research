"""
g1_safe_path_resolver.py - Advanced Descriptor-Relative & Canonical Path Resolver for Scenario G1.

Features & Mitigations (Stage 5.2.5 Hardening):
1. Multi-layered Directory Containment:
   - Canonical realpath verification: canonical_target starts with canonical_base + os.sep.
   - Descriptor-relative traversal via openat2(RESOLVE_BENEATH) where supported (Linux 5.6+).
     On non-Linux/Windows or platforms where openat2 is unavailable, falls back to rigorously
     verified canonical containment with open-fd stat verification.
2. Descriptor Validation:
   - Evaluates os.fstat(fd): verifies regular file (S_ISREG), rejects directories, sockets, devices, FIFOs.
   - Verifies file permissions: rejects files with world-writable or group-writable bits.
   - Enforces hard memory bounding (max_bytes = 65536).
3. Symlink Policy:
   - In authorization directory (/var/run/g1-auth):
     Allows symlinks ONLY if their canonical realpath resolves strictly within canonical base_dir.
     This accommodates Kubernetes ..data/ timestamped projections while preventing escapes.
   - In lock directory (/var/run/g1-lock):
     Strictly prohibits any symlinks (allow_projected_symlink=False).
4. Realistic TOCTOU & Concurrency Accounting:
   - Explicitly records that pinning an inode via os.open() protects the active read, but true
     immunity against symlink race attacks in userspace requires the container mount to be read-only
     (readOnlyRootFilesystem: true, readOnly: true volume mount).
"""

import ctypes
import errno
import json
import os
import stat
from typing import Any, Dict, Optional, Tuple


class PathSecurityError(PermissionError):
    """Raised when path traversal, symlink escape, or unsafe file access is detected."""
    pass


# Linux openat2 constants (Linux 5.6+, <linux/openat2.h>)
SYS_OPENAT2 = 437  # x86_64 syscall number
RESOLVE_NO_XDEV = 0x01
RESOLVE_NO_MAGICLINKS = 0x02
RESOLVE_NO_SYMLINKS = 0x04
RESOLVE_BENEATH = 0x08
RESOLVE_IN_ROOT = 0x10
RESOLVE_CACHED = 0x20


class OpenHow(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint64),
        ("mode", ctypes.c_uint64),
        ("resolve", ctypes.c_uint64),
    ]


class SafePathResolver:
    """Provides path verification and descriptor-pinned reading confined to an authorized directory."""

    @staticmethod
    def _try_openat2(dir_fd: int, relative_path: str, flags: int, resolve_flags: int) -> Optional[int]:
        """
        Attempts to invoke Linux openat2(2) with resolve restrictions via ctypes.
        Returns file descriptor if successful, or None if openat2 is unsupported/unavailable.
        """
        if os.name != "posix" or not hasattr(ctypes, "CDLL"):
            return None

        try:
            libc = ctypes.CDLL(None, use_errno=True)
            if not hasattr(libc, "syscall"):
                return None

            how = OpenHow(
                flags=flags,
                mode=0,
                resolve=resolve_flags,
            )
            how_size = ctypes.c_size_t(ctypes.sizeof(how))

            # syscall(SYS_OPENAT2, dir_fd, pathname, &how, size)
            res = libc.syscall(
                ctypes.c_long(SYS_OPENAT2),
                ctypes.c_int(dir_fd),
                ctypes.c_char_p(relative_path.encode("utf-8")),
                ctypes.byref(how),
                how_size,
            )
            if res >= 0:
                return int(res)

            err = ctypes.get_errno()
            if err == errno.ENOSYS:
                # Kernel does not support openat2
                return None
            elif err in (errno.EXDEV, errno.ELOOP):
                raise PathSecurityError(f"openat2 security boundary breached ({errno.errorcode.get(err, err)}).")
            elif err == errno.ENOENT:
                raise FileNotFoundError(f"File not found via openat2: {relative_path}")
            else:
                raise OSError(err, f"openat2 failed: {os.strerror(err)}")
        except PathSecurityError:
            raise
        except (AttributeError, OSError):
            return None

    @staticmethod
    def resolve_confined_file(
        base_dir: str,
        filename: str,
        allow_projected_symlink: bool = True,
    ) -> Tuple[str, os.stat_result]:
        """
        Resolves filename within base_dir.
        Enforces canonical root directory containment.
        Returns (canonical_path, stat_result).
        """
        if not base_dir or not os.path.isdir(base_dir):
            raise PathSecurityError(f"Base directory does not exist or is not a directory: '{base_dir}'.")

        canonical_base = os.path.realpath(os.path.abspath(base_dir))
        target_path = os.path.join(base_dir, filename)

        if not os.path.lexists(target_path):
            raise FileNotFoundError(f"Target file not found: '{target_path}'.")

        is_link = os.path.islink(target_path)
        if is_link and not allow_projected_symlink:
            raise PathSecurityError(f"Symlinks strictly prohibited for '{filename}'.")

        canonical_target = os.path.realpath(os.path.abspath(target_path))

        # Enforce canonical directory containment
        prefix = canonical_base if canonical_base.endswith(os.sep) else canonical_base + os.sep
        if not canonical_target.startswith(prefix):
            raise PathSecurityError(
                f"Directory traversal / symlink escape blocked: '{canonical_target}' is outside base '{canonical_base}'."
            )

        try:
            stat_res = os.stat(canonical_target)
        except OSError as exc:
            raise PathSecurityError(f"Failed to stat resolved path '{canonical_target}': {exc}") from exc

        return canonical_target, stat_res

    @classmethod
    def read_atomic_confined_json(
        cls,
        base_dir: str,
        filename: str,
        max_bytes: int = 65536,
    ) -> Dict[str, Any]:
        """
        Atomically opens, validates, and parses JSON from filename within base_dir.
        Attempts openat2(RESOLVE_BENEATH) where supported; falls back to verified canonical containment.
        Enforces descriptor metadata verification:
        - Must be regular file (S_ISREG)
        - Must not be group/world-writable
        - Bounded by max_bytes
        """
        resolved_path, _ = cls.resolve_confined_file(
            base_dir=base_dir,
            filename=filename,
            allow_projected_symlink=True,
        )

        fd: Optional[int] = None
        base_dir_fd: Optional[int] = None

        # Attempt descriptor-relative openat2 if on Linux and relative filename
        if os.name == "posix" and hasattr(os, "O_PATH") and hasattr(os, "O_DIRECTORY"):
            try:
                base_dir_fd = os.open(base_dir, os.O_PATH | os.O_DIRECTORY)
                # For projected secret symlinks, we cannot use RESOLVE_NO_SYMLINKS because ..data is a symlink,
                # but RESOLVE_BENEATH restricts symlink resolution strictly beneath dir_fd!
                fd = cls._try_openat2(
                    dir_fd=base_dir_fd,
                    relative_path=filename,
                    flags=os.O_RDONLY,
                    resolve_flags=RESOLVE_BENEATH,
                )
            except Exception:
                fd = None
            finally:
                if base_dir_fd is not None:
                    try:
                        os.close(base_dir_fd)
                    except OSError:
                        pass

        # Fallback to direct open of canonical realpath if openat2 was unsupported or unavailable
        if fd is None:
            try:
                flags = os.O_RDONLY
                if hasattr(os, "O_CLOEXEC"):
                    flags |= os.O_CLOEXEC
                fd = os.open(resolved_path, flags)
            except OSError as exc:
                raise PathSecurityError(f"Failed to open '{resolved_path}': {exc}") from exc

        try:
            # 1. Verify descriptor stat
            fstat = os.fstat(fd)
            mode = fstat.st_mode

            if not stat.S_ISREG(mode):
                raise PathSecurityError(f"Target is not a regular file (mode={oct(mode)}): '{resolved_path}'.")

            # 2. Verify permissions: on POSIX/Linux systems, reject group/world-writable files.
            # On Windows, CRT maps file attributes to 0666 regardless of ACLs; POSIX permission bits are only evaluated on posix.
            if os.name == "posix" and (mode & (stat.S_IWGRP | stat.S_IWOTH)):
                raise PathSecurityError(
                    f"Insecure file permissions: target '{resolved_path}' is group/world-writable (mode={oct(mode)})."
                )

            # 3. Verify size bounds
            if fstat.st_size > max_bytes:
                raise PathSecurityError(f"File size {fstat.st_size} exceeds maximum allowed {max_bytes} bytes.")

            # 4. Read bounded buffer
            raw_bytes = bytearray()
            while len(raw_bytes) < max_bytes:
                chunk = os.read(fd, 4096)
                if not chunk:
                    break
                raw_bytes.extend(chunk)

            if len(raw_bytes) >= max_bytes:
                extra = os.read(fd, 1)
                if extra:
                    raise PathSecurityError(f"File contents exceed maximum allowed {max_bytes} bytes.")

            text = raw_bytes.decode("utf-8")
            payload = json.loads(text)
            if not isinstance(payload, dict):
                raise ValueError("Payload must be a JSON object.")
            return payload
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError) as exc:
            raise ValueError(f"Malformed JSON payload: {exc}") from exc
        finally:
            if fd is not None:
                os.close(fd)
