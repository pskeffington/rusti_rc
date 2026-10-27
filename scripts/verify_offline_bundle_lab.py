#!/usr/bin/env python3
"""G2g laboratory-only detached-signature and artifact verification.

NEVER installs, executes, activates, signs, or authorizes a release.
Requires a public verification key provisioned separately from the bundle.
The version floor supplied on the command line is not protected persistent
state, and this is not a TUF client. Production deployment remains blocked.

Python 3.8+ standard library and local OpenSSL with Ed25519 support.
No network calls, credentials, private key handling, or external packages.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile

SCHEMA = "rusti-offline-lab-v1"
FILES = frozenset(("manifest.json", "manifest.sig", "rusti_rc.bin"))
FIELDS = frozenset((
    "schema", "sequence", "target", "source_commit",
    "payload_name", "payload_sha256", "payload_size",
))
TARGETS = frozenset((
    "arm-unknown-linux-gnueabihf",
    "armv7-unknown-linux-gnueabihf",
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
    "x86_64-unknown-linux-musl",
    "x86_64-pc-windows-msvc",
    "x86_64-apple-darwin",
    "aarch64-apple-darwin",
))
MAX_MANIFEST = 4096
MAX_BINARY = 64 * 1024 * 1024
MAX_PUBLIC_KEY = 4096


class Refuse(Exception):
    """Fail closed with one non-sensitive diagnostic."""


def regular_nosymlink(path, maximum):
    try:
        before = os.lstat(str(path))
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Refuse("unsafe_file_type")
        if before.st_size > maximum or before.st_size < 1:
            raise Refuse("size_limit")
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(str(path), flags)
        try:
            actual = os.fstat(fd)
            if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                raise Refuse("unsafe_file_type")
            if (before.st_dev, before.st_ino) != (actual.st_dev, actual.st_ino):
                raise Refuse("file_changed")
            if actual.st_size != before.st_size or actual.st_size > maximum:
                raise Refuse("size_limit")
            content = bytearray()
            while len(content) <= maximum:
                data = os.read(fd, min(65536, maximum + 1 - len(content)))
                if not data:
                    break
                content.extend(data)
            if len(content) != before.st_size:
                raise Refuse("file_changed")
            return bytes(content)
        finally:
            os.close(fd)
    except (FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError):
        raise Refuse("missing_or_unreadable_file")


def payload_digest(path):
    try:
        before = os.lstat(str(path))
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise Refuse("unsafe_payload")
        if not 1 <= before.st_size <= MAX_BINARY:
            raise Refuse("payload_size_limit")
        fd = os.open(str(path), os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
        try:
            actual = os.fstat(fd)
            if not stat.S_ISREG(actual.st_mode) or actual.st_nlink != 1:
                raise Refuse("unsafe_payload")
            if (actual.st_dev, actual.st_ino, actual.st_size) != (
                before.st_dev, before.st_ino, before.st_size
            ):
                raise Refuse("payload_changed")
            digest = hashlib.sha256()
            count = 0
            while True:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                count += len(chunk)
                if count > MAX_BINARY:
                    raise Refuse("payload_size_limit")
                digest.update(chunk)
            after = os.fstat(fd)
            if (
                count != before.st_size
                or after.st_size != before.st_size
                or after.st_mtime_ns != before.st_mtime_ns
            ):
                raise Refuse("payload_changed")
            return count, digest.hexdigest()
        finally:
            os.close(fd)
    except (FileNotFoundError, PermissionError, IsADirectoryError, NotADirectoryError):
        raise Refuse("missing_or_unreadable_payload")


def no_duplicate_keys(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise Refuse("duplicate_metadata_key")
        out[key] = value
    return out


def metadata_from_signed_bytes(data):
    try:
        obj = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=no_duplicate_keys,
            parse_constant=lambda _value: (_ for _ in ()).throw(Refuse("invalid_json")),
        )
    except (UnicodeError, json.JSONDecodeError):
        raise Refuse("invalid_json")
    if not isinstance(obj, dict) or frozenset(obj) != FIELDS:
        raise Refuse("unsupported_metadata_schema")
    if obj["schema"] != SCHEMA or obj["payload_name"] != "rusti_rc.bin":
        raise Refuse("unsupported_metadata_schema")
    # Exact type rejects bool masquerading as an integer.
    for key, upper in (("sequence", 2**31 - 1), ("payload_size", MAX_BINARY)):
        if type(obj[key]) is not int or not 1 <= obj[key] <= upper:
            raise Refuse("invalid_numeric_field")
    if (
        type(obj["source_commit"]) is not str
        or not re.fullmatch(r"[0-9a-f]{40}", obj["source_commit"])
        or type(obj["payload_sha256"]) is not str
        or not re.fullmatch(r"[0-9a-f]{64}", obj["payload_sha256"])
        or type(obj["target"]) is not str
        or obj["target"] not in TARGETS
    ):
        raise Refuse("invalid_identity_or_digest")
    return obj


def verify_ed25519(manifest_bytes, signature, public_key):
    if len(signature) != 64:
        raise Refuse("invalid_signature_format")
    # OpenSSL requires seekable input for Ed25519 one-shot pkeyutl. Work
    # exclusively on snapshots created from checked, bounded source bytes.
    with tempfile.TemporaryDirectory(prefix="rusti-lab-verify-") as folder:
        base = Path(folder)
        (base / "manifest").write_bytes(manifest_bytes)
        (base / "signature").write_bytes(signature)
        (base / "public.pem").write_bytes(public_key)
        try:
            kind = subprocess.run(
                ["openssl", "pkey", "-pubin", "-in", str(base / "public.pem"),
                 "-text", "-noout"],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                timeout=8, check=False,
            )
            if kind.returncode != 0 or b"ED25519 Public-Key:" not in kind.stdout:
                raise Refuse("invalid_trust_root_type")
            result = subprocess.run(
                ["openssl", "pkeyutl", "-verify", "-pubin",
                 "-inkey", str(base / "public.pem"), "-rawin",
                 "-in", str(base / "manifest"), "-sigfile", str(base / "signature")],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                timeout=8, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            raise Refuse("crypto_provider_unavailable")
        if result.returncode != 0:
            raise Refuse("signature_rejected")


def verify(bundle, trusted_key, target, minimum):
    if not bundle.is_dir() or bundle.is_symlink():
        raise Refuse("invalid_bundle_directory")
    if target not in TARGETS or minimum < 1 or minimum > 2**31 - 1:
        raise Refuse("invalid_local_policy")
    if frozenset(item.name for item in bundle.iterdir()) != FILES:
        raise Refuse("unknown_or_missing_bundle_entry")
    # Trust anchor MUST come from independent, pre-provisioned storage.
    # Bundles do not get to supply their own public verification key.
    if not trusted_key.is_file() or trusted_key.is_symlink():
        raise Refuse("no_independent_trust_root")
    try:
        if os.path.commonpath((str(bundle.resolve()), str(trusted_key.resolve()))) == str(bundle.resolve()):
            raise Refuse("trust_root_inside_bundle")
    except ValueError:
        raise Refuse("invalid_trust_root_location")

    manifest = regular_nosymlink(bundle / "manifest.json", MAX_MANIFEST)
    signature = regular_nosymlink(bundle / "manifest.sig", 64)
    key = regular_nosymlink(trusted_key, MAX_PUBLIC_KEY)
    verify_ed25519(manifest, signature, key)  # First authenticate signed bytes.
    record = metadata_from_signed_bytes(manifest)
    if record["target"] != target:
        raise Refuse("target_mismatch")
    if record["sequence"] < minimum:
        raise Refuse("sequence_below_supplied_floor")
    size, digest = payload_digest(bundle / "rusti_rc.bin")
    if size != record["payload_size"] or digest != record["payload_sha256"]:
        raise Refuse("payload_integrity_rejected")
    # The caller-supplied floor is NOT protected against attacker rollback.
    # No known secure clock, key revocation, TUF metadata or host ABI proof.
    return "lab_signature_target_payload_and_floor=verified\ndeployment=blocked\n"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--lab-only", action="store_true", required=True,
                    help="Mandatory acknowledgement: this does not deploy or certify a device")
    ap.add_argument("--bundle", required=True, type=Path)
    ap.add_argument("--trusted-public-key", required=True, type=Path)
    ap.add_argument("--expected-target", required=True)
    ap.add_argument("--minimum-sequence", required=True, type=int)
    args = ap.parse_args()
    try:
        sys.stdout.write(verify(
            args.bundle, args.trusted_public_key,
            args.expected_target, args.minimum_sequence,
        ))
        return 0
    except (Refuse, OSError) as error:
        code = str(error) if isinstance(error, Refuse) else "io_failed"
        print("lab_verification=refused:" + code, file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
