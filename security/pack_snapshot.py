"""Pack an explicit file list from a trusted, read-only snapshot. POSIX only.

Write JSON to stdout, its exact SHA-256 to stderr. Never walk the target tree,
read target configuration, follow links, execute target code or write target files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import sys

MAX_FILE = 1024 * 1024
MAX_TOTAL = 16 * MAX_FILE
MAX_BUNDLE = 32 * MAX_FILE
MAX_FILES = 1024


def valid_path(path: object) -> bool:
    if not isinstance(path, str) or not path:
        return False
    try:
        size = len(path.encode("utf-8"))
    except UnicodeError:
        return False
    return (size <= 1024 and not any(c in path for c in "\\:")
            and not any(ord(c) < 32 or ord(c) == 127 for c in path)
            and all(part not in ("", ".", "..") for part in path.split("/")))


def read_regular(parent: int, name: str) -> bytes:
    # O_NONBLOCK prevents a FIFO from blocking before fstat rejects it.
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("not_a_single_link_regular_file")
        if before.st_size > MAX_FILE:
            raise ValueError("file_limit_exceeded")
        chunks = []
        size = 0
        while size <= MAX_FILE:
            chunk = os.read(fd, min(65536, MAX_FILE + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
        if size > MAX_FILE:
            raise ValueError("file_limit_exceeded")
        after = os.fstat(fd)
        attrs = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink")
        if any(getattr(before, key) != getattr(after, key) for key in attrs):
            raise ValueError("file_changed_while_reading")
        data = b"".join(chunks)
        if len(data) != before.st_size or b"\0" in data:
            raise ValueError("invalid_source")
        data.decode("utf-8", "strict")
        return data
    finally:
        os.close(fd)


def pack(root: str, paths: list[str]) -> bytes:
    if os.name != "posix" or not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("posix_no_follow_required")
    if not isinstance(paths, list) or len(paths) > MAX_FILES or not all(map(valid_path, paths)):
        raise ValueError("invalid_file_list")
    if len(paths) != len(set(paths)):
        raise ValueError("duplicate_path")
    # The root and its ancestor directories are selected by the trusted operator.
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    root_fd = os.open(root, flags)
    try:
        files = []
        total = 0
        for path in sorted(paths):
            parent = os.dup(root_fd)
            try:
                parts = path.split("/")
                for part in parts[:-1]:
                    child = os.open(part, flags, dir_fd=parent)
                    os.close(parent)
                    parent = child
                data = read_regular(parent, parts[-1])
            finally:
                os.close(parent)
            total += len(data)
            if total > MAX_TOTAL:
                raise ValueError("snapshot_limit_exceeded")
            files.append({"path": path, "sha256": hashlib.sha256(data).hexdigest(),
                          "source": data.decode("utf-8")})
        result = (json.dumps({"schema": "cbm.security-snapshot.v1", "files": files},
                             ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        if len(result) > MAX_BUNDLE:
            raise ValueError("bundle_limit_exceeded")
        return result
    finally:
        os.close(root_fd)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--files", required=True, help="Trusted JSON array of relative paths, not target configuration")
    args = parser.parse_args()
    try:
        # The list location, like --root, is a trusted startup input.
        with open(args.files, "rb") as stream:
            raw = stream.read(2 * MAX_FILE + 1)
        if len(raw) > 2 * MAX_FILE:
            raise ValueError("file_list_limit_exceeded")
        bundle = pack(args.root, json.loads(raw))
        sys.stdout.buffer.write(bundle)
        sys.stdout.buffer.flush()
        print(hashlib.sha256(bundle).hexdigest(), file=sys.stderr)
    except (OSError, ValueError, UnicodeError, RecursionError):
        print("snapshot_pack_failed", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
