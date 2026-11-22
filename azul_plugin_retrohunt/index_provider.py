"""Read-only, bounded local batches for Retroindexer-published indexes.

Uses native Python Azure Blob / S3 clients: no Retroindexer executable is needed.
"""

from __future__ import annotations

import fcntl
import hashlib
import logging
import os
import re
import shutil
import tempfile
import time
from pathlib import Path

from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.index_storage import IndexStorage, IndexStorageError, create_storage, index_prefix
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.index_provider")
INDEX_ID = re.compile(r"^[0-9a-f]{64}$")
index_fetch_count = Counter("retrohunt_index_fetch_total", "Published index cache fetch attempts", ["status"])
index_fetch_seconds = Histogram("retrohunt_index_fetch_seconds", "Seconds spent ensuring a local .bgi")


class IndexUnavailable(RuntimeError):
    """Raised when Retrohunt cannot obtain the complete published index snapshot."""


class ObjectIndexProvider:
    """List one published snapshot, verify SHA-256 and download atomically."""

    def __init__(self, settings: RetrohuntSettings, storage: IndexStorage | None = None):
        self.cache_dir = Path(settings.index_cache_dir).expanduser().resolve()
        self.max_cache_bytes = settings.index_cache_max_bytes
        self.list_timeout = settings.index_list_timeout_seconds
        self.fetch_timeout = settings.index_fetch_timeout_seconds
        try:
            self.prefix = index_prefix()
            self.storage = storage if storage is not None else create_storage()
        except IndexStorageError as exc:
            raise IndexUnavailable(str(exc)) from exc

    def list_indexes(self) -> list[str]:
        """Only expose full SHA-256 IDs with both .bgi and .ready objects."""
        try:
            start = time.monotonic()
            available: set[str] = set()
            ready: set[str] = set()
            for key in self.storage.list_keys(self.prefix):
                if time.monotonic() - start > self.list_timeout:
                    raise IndexUnavailable("Timed out listing published indexes")
                if not key.startswith(self.prefix):
                    continue
                name = key[len(self.prefix) :]
                if name.endswith(".bgi") and INDEX_ID.fullmatch(name[:-4]):
                    available.add(name[:-4])
                elif name.endswith(".ready") and INDEX_ID.fullmatch(name[:-6]):
                    ready.add(name[:-6])
            ids = sorted(ready & available)
            if not ids:
                raise IndexUnavailable("No published BigGrep indexes found in object storage")
            logger.info("Found %d published BigGrep indexes", len(ids))
            return ids
        except IndexUnavailable:
            raise
        except Exception as exc:
            logger.error("Unable to list published indexes: %s", type(exc).__name__)
            raise IndexUnavailable("Failed to list published BigGrep indexes") from exc

    def _download_into(self, index_id: str, destination: Path, size_limit: int) -> int:
        """Download a single immutable index, enforcing the budget while streaming."""
        if not INDEX_ID.fullmatch(index_id):
            raise IndexUnavailable("Invalid BigGrep index identifier")
        started = time.monotonic()
        digest = hashlib.sha256()
        written = 0
        tmp_name = None
        with index_fetch_seconds.time():
            try:
                with tempfile.NamedTemporaryFile(
                    prefix=f".{index_id}.", suffix=".tmp", dir=destination.parent, delete=False
                ) as tmp:
                    tmp_name = tmp.name
                    with self.storage.read_chunks(self.prefix + f"{index_id}.bgi") as chunks:
                        for block in chunks:
                            if time.monotonic() - started > self.fetch_timeout:
                                raise IndexUnavailable(f"Timed out downloading index {index_id}")
                            if not block:
                                continue
                            written += len(block)
                            if written > size_limit:
                                raise IndexUnavailable(f"Index {index_id} exceeds configured local index budget")
                            tmp.write(block)
                            digest.update(block)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                if digest.hexdigest() != index_id:
                    raise IndexUnavailable(f"Published index checksum mismatch: {index_id}")
                os.replace(tmp_name, destination)
                tmp_name = None
                index_fetch_count.labels("success").inc()
                return written
            except Exception as exc:
                index_fetch_count.labels("failed").inc()
                if isinstance(exc, IndexUnavailable):
                    raise
                logger.error("Index fetch failed for %s: %s", index_id, type(exc).__name__)
                raise IndexUnavailable(f"Failed to fetch published index {index_id}") from exc
            finally:
                if tmp_name is not None:
                    Path(tmp_name).unlink(missing_ok=True)

    def iter_search_batches(self):
        """Yield local index batches, never retaining more than the byte budget.

        The cache lock serialises hunts sharing a volume. Each batch is kept
        alive until its broad-phase search finishes, then removed before the
        next batch is downloaded. No complete local copy is ever prepared.
        """
        ids = self.list_indexes()  # Fixed published snapshot, not live listing per batch.
        if self.max_cache_bytes <= 0:
            raise IndexUnavailable("Index cache budget must be positive")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.cache_dir / ".batch-search.lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                # Previous crashes can leave temporary batches on an emptyDir.
                # Remove them only while holding the same inter-hunt lock.
                for orphan in self.cache_dir.glob(".hunt-batch-*"):
                    if orphan.is_dir() and not orphan.is_symlink():
                        shutil.rmtree(orphan)
                # Old versions stored persistent .bgi objects directly in the
                # cache. Refuse to exceed the budget invisibly; require an
                # operator to review/remove those files instead.
                if any(self.cache_dir.glob("*.bgi")):
                    raise IndexUnavailable(
                        "Legacy .bgi files found in index cache; clear them before using bounded batches"
                    )
                offset = 0
                while offset < len(ids):
                    with tempfile.TemporaryDirectory(prefix=".hunt-batch-", dir=self.cache_dir) as dirname:
                        batch_dir = Path(dirname)
                        batch_bytes = 0
                        batch_count = 0
                        for index_id in ids[offset:]:
                            # Object metadata lets us decide *before* downloading
                            # whether an index fits in the remaining budget.
                            try:
                                size = self.storage.object_size(self.prefix + f"{index_id}.bgi")
                            except Exception as exc:
                                raise IndexUnavailable(f"Cannot determine size for index {index_id}") from exc
                            if size <= 0 or size > self.max_cache_bytes:
                                raise IndexUnavailable(
                                    f"Published index {index_id} ({size} bytes) cannot fit "
                                    f"within index cache budget ({self.max_cache_bytes} bytes)"
                                )
                            if batch_count and batch_bytes + size > self.max_cache_bytes:
                                break
                            destination = batch_dir / f"{index_id}.bgi"
                            actual_size = self._download_into(
                                index_id, destination, self.max_cache_bytes - batch_bytes
                            )
                            if actual_size != size:
                                raise IndexUnavailable(f"Published index changed size during download: {index_id}")
                            batch_bytes += actual_size
                            batch_count += 1
                        if not batch_count:
                            raise IndexUnavailable("Unable to make progress preparing index batches")
                        offset += batch_count
                        logger.info(
                            "Searching index batch of %d files (%d bytes); %d/%d indexes completed",
                            batch_count,
                            batch_bytes,
                            offset,
                            len(ids),
                        )
                        yield batch_dir, offset - batch_count, batch_count, len(ids)
                    # The batch is deleted here, after the caller has finished bgparse.
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
