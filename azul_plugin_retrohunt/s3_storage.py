"""S3-backed storage for completed Retrohunt .bgi files.

Stage 1: standalone/opt-in only. No production caller uses this module yet.
The BigGrep tools still require locally accessible .bgi files.

Object keys are content-addressed for safe future index publication: uploading
identical contents results in the same object key; changed indexes get new keys.
A later stage will add manifests and pin active versions for workers.
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from azul_plugin_retrohunt.settings import S3IndexSettings

_CHUNK_SIZE = 1024 * 1024
_SAFE_INDEXER = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]*$")


class S3IndexError(RuntimeError):
    """A completed index could not be stored or retrieved safely."""


class S3IndexNotFound(S3IndexError):
    """The requested object does not exist."""


class S3IndexIntegrityError(S3IndexError):
    """The downloaded or uploaded object does not match its expected metadata."""


@dataclass(frozen=True, slots=True)
class S3IndexObject:
    """A versioned, published-object *candidate* (not an active manifest entry)."""

    key: str
    size: int
    sha256: str


def file_digest(path: Path) -> tuple[int, str]:
    """Hash an index in chunks instead of loading the entire file into memory."""
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        while chunk := stream.read(_CHUNK_SIZE):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def _missing_object(exc: Exception) -> bool:
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return False
    code = str(response.get("Error", {}).get("Code", ""))
    return code in {"404", "NoSuchKey", "NotFound"}


class S3IndexStorage:
    """Upload and cache versioned BGI objects in an S3-compatible store.

    The client parameter permits testing without credentials or live S3.
    When omitted, Boto3 uses its standard credential chain (including IRSA).
    """

    def __init__(self, config: S3IndexSettings, *, client: Any = None):
        if not config.bucket:
            raise ValueError("S3 bucket is required")
        self.bucket = config.bucket
        self.prefix = config.prefix.strip("/")
        if client is None:
            import boto3  # Lazy import so non-S3 deployments don't need boto3.

            client = boto3.client(
                "s3",
                region_name=config.region,
                endpoint_url=config.endpoint_url,
                verify=config.verify_tls,
            )
        self.client = client

    def index_key(self, indexer: str, filename: str, sha256: str) -> str:
        """Construct a stable key with a version derived from the index content."""
        if not _SAFE_INDEXER.fullmatch(indexer) or indexer in {".", ".."}:
            raise ValueError(f"Invalid indexer name: {indexer!r}")
        if Path(filename).name != filename or not filename.endswith(".bgi") or filename in {".", ".."}:
            raise ValueError(f"Invalid .bgi filename: {filename!r}")
        if not re.fullmatch(r"[a-f0-9]{64}", sha256):
            raise ValueError("Expected a hexadecimal SHA256 digest")
        stem = filename[:-4]
        if not stem or stem in {".", ".."} or "/" in stem or "\\" in stem:
            raise ValueError(f"Invalid .bgi filename: {filename!r}")
        parts = [self.prefix, indexer, "bgi", f"{stem}-{sha256}.bgi"]
        return "/".join(part for part in parts if part)

    def upload_index(self, indexer: str, local_file: Path) -> S3IndexObject:
        """Upload an index, then verify stored length and digest metadata.

        This does NOT update an active-index manifest, modify the source, or
        delete a PVC file. Publication will be handled in a later phase.
        """
        path = Path(local_file)
        if not path.is_file() or path.suffix != ".bgi":
            raise ValueError(f"Expected an existing .bgi file: {path}")
        size, sha256 = file_digest(path)
        key = self.index_key(indexer, path.name, sha256)
        try:
            self.client.upload_file(
                str(path),
                self.bucket,
                key,
                ExtraArgs={
                    "ContentType": "application/octet-stream",
                    "Metadata": {"sha256": sha256},
                },
            )
            info = self.client.head_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            raise S3IndexError(f"Could not upload/verify index {key}: {exc}") from exc
        if info.get("ContentLength") != size or info.get("Metadata", {}).get("sha256") != sha256:
            raise S3IndexIntegrityError(f"Uploaded index failed metadata validation: {key}")
        return S3IndexObject(key=key, size=size, sha256=sha256)

    def download_index(self, obj: S3IndexObject, destination: Path) -> Path:
        """Download, verify SHA256, and atomically replace the cache destination.

        This can safely run alongside existing files: a partial or corrupted
        download is never exposed at the final path.
        """
        destination = Path(destination)
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.is_file() and file_digest(destination) == (obj.size, obj.sha256):
            return destination
        fd, temp_name = tempfile.mkstemp(prefix=f".{destination.name}.", suffix=".part", dir=destination.parent)
        os.close(fd)
        temp = Path(temp_name)
        try:
            try:
                self.client.download_file(self.bucket, obj.key, str(temp))
            except Exception as exc:
                if _missing_object(exc):
                    raise S3IndexNotFound(f"S3 index not found: {obj.key}") from exc
                raise S3IndexError(f"Could not download S3 index {obj.key}: {exc}") from exc
            if file_digest(temp) != (obj.size, obj.sha256):
                raise S3IndexIntegrityError(f"Downloaded index checksum/size mismatch: {obj.key}")
            os.replace(temp, destination)
            return destination
        finally:
            temp.unlink(missing_ok=True)

    def exists(self, key: str) -> bool:
        """Check object existence; permission/server errors are not 'not found'."""
        try:
            self.client.head_object(Bucket=self.bucket, Key=key)
            return True
        except Exception as exc:
            if _missing_object(exc):
                return False
            raise S3IndexError(f"Could not inspect S3 object {key}: {exc}") from exc

    def list_keys(self, prefix: str = "") -> list[str]:
        """List keys under the configured prefix, across all S3 pages."""
        path = "/".join(part for part in (self.prefix, prefix.strip("/")) if part)
        if path:
            path += "/"
        try:
            pages = self.client.get_paginator("list_objects_v2").paginate(Bucket=self.bucket, Prefix=path)
            return [item["Key"] for page in pages for item in page.get("Contents", [])]
        except Exception as exc:
            raise S3IndexError(f"Could not list indexes under {path}: {exc}") from exc

    def delete(self, key: str) -> None:
        """Explicit deletion only. Never invoked by existing PVC workflows."""
        expected_prefix = f"{self.prefix}/" if self.prefix else ""
        if not key.startswith(expected_prefix) or "/bgi/" not in key:
            raise ValueError("Refusing to delete an object outside the managed BGI prefix")
        try:
            self.client.delete_object(Bucket=self.bucket, Key=key)
        except Exception as exc:
            raise S3IndexError(f"Could not delete index {key}: {exc}") from exc
