"""Small read-only object-store shim for Retroindexer-published BigGrep files.

Only the publisher writes blobs.  The consumer uses the existing layout:
``<prefix>/<sha256>.bgi`` and ``<prefix>/<sha256>.ready``.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager
from typing import Protocol


class IndexStorageError(RuntimeError):
    """Object storage is unavailable or misconfigured."""


class IndexStorage(Protocol):
    """Read-only operations needed to list and fetch published BigGrep indexes."""

    def list_keys(self, prefix: str) -> Iterator[str]:
        """Yield object keys under the requested prefix."""
        ...

    def object_size(self, key: str) -> int:
        """Return the object size in bytes without downloading the object."""
        ...

    @contextmanager
    def read_chunks(self, key: str) -> Iterator[Iterator[bytes]]:
        """Yield a chunk iterator and close any network resources on exit."""
        ...


def _enabled(value: str) -> bool:
    return value.strip().lower() in {"true", "1", "yes", "on"}


class S3IndexStorage:
    """Read published indexes from AWS S3 or an S3-compatible endpoint."""

    def __init__(self):
        try:
            import boto3
            from botocore.config import Config
        except ImportError as exc:
            raise IndexStorageError("S3 backend requires boto3") from exc

        self.bucket = os.getenv("AZUL_INDEX_S3_BUCKET", "").strip()
        if not self.bucket:
            raise IndexStorageError("AZUL_INDEX_S3_BUCKET is required for S3 storage")
        endpoint = os.getenv("AZUL_INDEX_S3_ENDPOINT", "").strip()
        if endpoint and not endpoint.startswith(("http://", "https://")):
            secure = _enabled(os.getenv("AZUL_INDEX_S3_SECURE", "true"))
            endpoint = ("https://" if secure else "http://") + endpoint
        access = os.getenv("AZUL_INDEX_S3_ACCESS_KEY", "").strip()
        secret = os.getenv("AZUL_INDEX_S3_SECRET_KEY", "").strip()
        if bool(access) != bool(secret):
            raise IndexStorageError("Both S3 access and secret keys must be provided together")
        kwargs = {
            "region_name": os.getenv("AZUL_INDEX_S3_REGION") or None,
            "endpoint_url": endpoint or None,
            "config": Config(connect_timeout=30, read_timeout=60, retries={"mode": "standard", "max_attempts": 3}),
        }
        if access:
            kwargs.update(aws_access_key_id=access, aws_secret_access_key=secret)
        self.client = boto3.client("s3", **kwargs)

    def list_keys(self, prefix: str) -> Iterator[str]:
        """List S3 object keys below the requested prefix."""
        paginator = self.client.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=self.bucket, Prefix=prefix):
            for item in page.get("Contents", []):
                yield item["Key"]

    def object_size(self, key: str) -> int:
        """Read the S3 object size from its HEAD response."""
        return int(self.client.head_object(Bucket=self.bucket, Key=key)["ContentLength"])

    @contextmanager
    def read_chunks(self, key: str) -> Iterator[Iterator[bytes]]:
        """Stream S3 bytes in chunks, closing the response afterwards."""
        result = self.client.get_object(Bucket=self.bucket, Key=key)
        body = result["Body"]
        try:
            yield body.iter_chunks(chunk_size=1024 * 1024)
        finally:
            body.close()


class AzureIndexStorage:
    """Read published indexes from Azure Blob, using a key or workload identity."""

    def __init__(self):
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            raise IndexStorageError("Azure backend requires azure-storage-blob") from exc

        container = os.getenv("AZUL_INDEX_AZURE_CONTAINER", "").strip()
        account = os.getenv("AZUL_INDEX_AZURE_ACCOUNT", "").strip()
        endpoint = os.getenv("AZUL_INDEX_AZURE_ENDPOINT", "").strip()
        key = os.getenv("AZUL_INDEX_AZURE_KEY", "").strip()
        if not container:
            raise IndexStorageError("AZUL_INDEX_AZURE_CONTAINER is required")
        if not endpoint:
            if not account:
                raise IndexStorageError("Set AZUL_INDEX_AZURE_ENDPOINT or AZUL_INDEX_AZURE_ACCOUNT")
            endpoint = f"https://{account}.blob.core.windows.net"
        elif not endpoint.startswith(("http://", "https://")):
            endpoint = "https://" + endpoint

        credential = key or None
        if not credential:
            try:
                from azure.identity import DefaultAzureCredential
            except ImportError as exc:
                raise IndexStorageError("Azure keyless authentication requires azure-identity") from exc
            credential = DefaultAzureCredential()
        self.container = BlobServiceClient(account_url=endpoint, credential=credential).get_container_client(container)

    def list_keys(self, prefix: str) -> Iterator[str]:
        """List Azure blob names below the requested prefix."""
        for blob in self.container.list_blobs(name_starts_with=prefix):
            yield blob.name

    def object_size(self, key: str) -> int:
        """Read the Azure blob length from its properties."""
        return int(self.container.get_blob_client(key).get_blob_properties().size)

    @contextmanager
    def read_chunks(self, key: str) -> Iterator[Iterator[bytes]]:
        """Stream Azure blob bytes in bounded chunks."""
        stream = self.container.download_blob(key, max_concurrency=1)
        yield stream.chunks()


def create_storage() -> IndexStorage:
    """Construct the configured Azure Blob or S3 read-only storage client."""
    backend = os.getenv("AZUL_INDEX_BACKEND", "").strip().lower()
    if backend == "azure":
        return AzureIndexStorage()
    if backend == "s3":
        return S3IndexStorage()
    raise IndexStorageError("AZUL_INDEX_BACKEND must be 'azure' or 's3'")


def index_prefix() -> str:
    """Return the validated object-store prefix ending in a slash."""
    raw = os.getenv("AZUL_INDEX_PREFIX", "retrohunt/indices").strip().strip("/")
    if not raw or any(segment in (".", "..") for segment in raw.split("/")):
        raise IndexStorageError("Invalid AZUL_INDEX_PREFIX")
    return raw + "/"
