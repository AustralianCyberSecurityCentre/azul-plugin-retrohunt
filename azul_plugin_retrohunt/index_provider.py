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
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.index_storage import IndexStorage, IndexStorageError, create_storage, index_prefix
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.index_provider")
INDEX_ID = re.compile(r"^[0-9a-f]{64}$")
index_fetch_count = Counter("retrohunt_index_fetch_total", "Published index cache fetch attempts", ["status"])
index_fetch_seconds = Histogram("retrohunt_index_fetch_seconds", "Seconds spent ensuring a local .bgi")


@dataclass
class PreparedBatch:
    """Metadata for a downloaded batch of verified indexes."""

    batch_dir: Path
    batch_bytes: int
    batch_count: int


class IndexUnavailable(RuntimeError):
    """Raised when Retrohunt cannot obtain the complete published index snapshot."""


class ObjectIndexProvider:
    """List one published snapshot, verify SHA-256 and download atomically."""

    def __init__(self, settings: RetrohuntSettings, storage: IndexStorage | None = None):
        self.cache_dir = Path(settings.index_cache_dir).expanduser().resolve()
        self.max_cache_bytes = settings.index_cache_max_bytes
        # Smaller custom cache limits retain a proportional low watermark.
        self.target_cache_bytes = min(settings.index_cache_target_bytes, self.max_cache_bytes * 8 // 9)
        self.min_free_bytes = settings.index_cache_free_bytes
        self.list_timeout = settings.index_list_timeout_seconds
        self.fetch_timeout = settings.index_fetch_timeout_seconds
        try:
            self.prefix = index_prefix()
            self.storage = storage if storage is not None else create_storage()
        except IndexStorageError as exc:
            raise IndexUnavailable(str(exc)) from exc

    def _cached_files(self):
        """Return complete cache entries; temporary downloads are never reused."""
        return [path for path in self.cache_dir.glob("*.bgi") if INDEX_ID.fullmatch(path.stem) and path.is_file()]

    def _make_room(self, incoming: int) -> None:
        """Evict least recently used indexes before opening a download."""
        entries = self._cached_files()
        used = sum(path.stat().st_size for path in entries)
        available = shutil.disk_usage(self.cache_dir).free
        if used + incoming <= self.max_cache_bytes and available >= incoming + self.min_free_bytes:
            return
        # Once eviction starts, aim for the 80 GiB low watermark to avoid churn.
        target = min(self.target_cache_bytes, self.max_cache_bytes - incoming)
        for path in sorted(entries, key=lambda item: item.stat().st_mtime_ns):
            stat = path.stat()
            # A hardlinked index is still part of a running search batch.
            if stat.st_nlink > 1:
                continue
            size = stat.st_size
            path.unlink()
            used -= size
            available += size
            if used <= target and available >= incoming + self.min_free_bytes:
                break
        if used + incoming > self.max_cache_bytes or available < incoming + self.min_free_bytes:
            raise IndexUnavailable("Insufficient free PVC space for index download; refusing to download")

    def _ensure_cached(self, index_id: str, expected_size: int, report_download=None) -> Path:
        """Reuse verified index bytes, or atomically publish a new SHA-checked download."""
        path = self.cache_dir / f"{index_id}.bgi"
        if path.is_file():
            if path.stat().st_size == expected_size:
                digest = hashlib.sha256()
                with path.open("rb") as cached:
                    for block in iter(lambda: cached.read(1024 * 1024), b""):
                        digest.update(block)
                if digest.hexdigest() == index_id:
                    os.utime(path, None)
                    index_fetch_count.labels("hit").inc()
                    if report_download:
                        report_download(expected_size)
                    return path
            logger.warning("Discarding stale or damaged cached index %s", index_id)
            path.unlink()
        self._make_room(expected_size)
        self._download_into(index_id, path, expected_size, report_download)
        return path

    def _prepare_batch(self, ids: list[str], offset: int, report_download) -> PreparedBatch:
        """Create lightweight hardlinks to retained indexes for one search batch."""
        batch_dir = Path(tempfile.mkdtemp(prefix=".hunt-batch-", dir=self.cache_dir))
        batch_bytes = 0
        count = 0
        try:
            for index_id in ids[offset:]:
                try:
                    size = self.storage.object_size(self.prefix + f"{index_id}.bgi")
                except Exception as exc:
                    raise IndexUnavailable(f"Cannot determine size for index {index_id}") from exc
                if size <= 0 or size > self.max_cache_bytes:
                    raise IndexUnavailable(f"Published index {index_id} cannot fit in the local cache")
                if count and batch_bytes + size > self.max_cache_bytes // 2:
                    break
                position = offset + count
                path = self._ensure_cached(
                    index_id,
                    size,
                    lambda received, number=position, expected=size: report_download(number, received, expected),
                )
                os.link(path, batch_dir / path.name)
                batch_bytes += size
                count += 1
            if not count:
                raise IndexUnavailable("Unable to prepare any index for searching")
            return PreparedBatch(batch_dir, batch_bytes, count)
        except Exception:
            shutil.rmtree(batch_dir, ignore_errors=True)
            raise

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

    def _download_into(
        self,
        index_id: str,
        destination: Path,
        expected_size: int,
        progress_callback=None,
    ) -> int:
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
                            if written > expected_size:
                                raise IndexUnavailable(f"Published index changed size during download: {index_id}")
                            tmp.write(block)
                            digest.update(block)
                            if progress_callback is not None:
                                progress_callback(written)
                    tmp.flush()
                    os.fsync(tmp.fileno())
                if written != expected_size:
                    raise IndexUnavailable(f"Published index changed size during download: {index_id}")
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
        # Downloads precede bgparse, so report their progress separately from
        # broad-phase search TASK completion. Never claim an index was searched
        # just because its bytes have arrived.
        next_download_percent = 10
        download_progress_lock = Lock()
        logger.info("Broad-phase index download starting: 0/%d indexes", len(ids))

        def report_download(
            index_offset: int,
            received: int,
            expected: int,
        ) -> None:
            nonlocal next_download_percent

            fraction = min(received / expected, 1.0) if expected else 0.0

            current_percent = int(100 * (index_offset + fraction) / len(ids))

            with download_progress_lock:
                while current_percent >= next_download_percent and next_download_percent <= 100:
                    logger.info(
                        "Broad-phase index download %d%% complete: %d/%d full indexes downloaded",
                        next_download_percent,
                        index_offset,
                        len(ids),
                    )
                    next_download_percent += 10

        if self.max_cache_bytes <= 0:
            raise IndexUnavailable("Index cache budget must be positive")
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.cache_dir / ".batch-search.lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                # Previous crashes can leave temporary batches on an emptyDir.
                # Remove them only while holding the same inter-hunt lock.
                for partial in self.cache_dir.glob(".*.tmp"):
                    if partial.is_file():
                        partial.unlink()
                for orphan in self.cache_dir.glob(".hunt-batch-*"):
                    if orphan.is_dir() and not orphan.is_symlink():
                        shutil.rmtree(orphan)
                offset = 0
                while offset < len(ids):
                    batch = self._prepare_batch(ids, offset, report_download)
                    batch_offset = offset
                    offset += batch.batch_count
                    logger.info(
                        "Searching index batch of %d files (%d bytes); %d/%d indexes prepared",
                        batch.batch_count,
                        batch.batch_bytes,
                        offset,
                        len(ids),
                    )
                    try:
                        yield (batch.batch_dir, batch_offset, batch.batch_count, len(ids))
                    finally:
                        shutil.rmtree(batch.batch_dir, ignore_errors=True)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
