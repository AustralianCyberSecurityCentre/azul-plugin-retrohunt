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
from concurrent.futures import ThreadPoolExecutor
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
        self.list_timeout = settings.index_list_timeout_seconds
        self.fetch_timeout = settings.index_fetch_timeout_seconds
        try:
            self.prefix = index_prefix()
            self.storage = storage if storage is not None else create_storage()
        except IndexStorageError as exc:
            raise IndexUnavailable(str(exc)) from exc

    def _prepare_batch(
        self,
        ids: list[str],
        offset: int,
        report_download,
    ) -> PreparedBatch:
        """Download and verify a cache-bounded batch of indexes.

        Downloads indexes in parallel, verifies integrity, and returns a
        temporary batch directory ready for broad-phase searching. The caller
        is responsible for deleting the batch directory after use.
        """
        batch_dir = Path(tempfile.mkdtemp(prefix=".hunt-batch-", dir=self.cache_dir))

        logger.info(
            "Preparing index batch starting at offset %d",
            offset,
        )

        try:
            batch_bytes = 0
            batch_count = 0
            downloads = []

            with ThreadPoolExecutor(max_workers=4) as executor:
                prefetch_budget = self.max_cache_bytes // 2
                for index_id in ids[offset:]:
                    try:
                        size = self.storage.object_size(self.prefix + f"{index_id}.bgi")
                    except Exception as exc:
                        raise IndexUnavailable(f"Cannot determine size for index {index_id}") from exc

                    if size <= 0 or size > self.max_cache_bytes:
                        raise IndexUnavailable(
                            f"Published index {index_id} ({size} bytes) "
                            f"cannot fit within index cache budget "
                            f"({self.max_cache_bytes} bytes)"
                        )

                    if batch_count and batch_bytes + size > prefetch_budget:
                        break

                    destination = batch_dir / f"{index_id}.bgi"

                    current_index_offset = offset + batch_count
                    current_size = size

                    future = executor.submit(
                        self._download_into,
                        index_id,
                        destination,
                        current_size,
                        lambda received, index_offset=current_index_offset, expected=current_size: report_download(
                            index_offset,
                            received,
                            expected,
                        ),
                    )
                    downloads.append((future, index_id, size))

                    batch_bytes += size
                    batch_count += 1

                if not batch_count:
                    raise IndexUnavailable("Unable to make progress preparing index batches")

                actual_bytes = 0

                for future, index_id, expected_size in downloads:
                    actual_size = future.result()

                    if actual_size != expected_size:
                        raise IndexUnavailable(f"Published index changed size during download: {index_id}")

                    actual_bytes += actual_size

                logger.info(
                    "Prepared batch of %d indexes (%d bytes)",
                    batch_count,
                    actual_bytes,
                )

                return PreparedBatch(
                    batch_dir=batch_dir,
                    batch_bytes=actual_bytes,
                    batch_count=batch_count,
                )

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

                with ThreadPoolExecutor(max_workers=1) as prefetch_pool:
                    next_batch_future = prefetch_pool.submit(
                        self._prepare_batch,
                        ids,
                        offset,
                        report_download,
                    )

                    while next_batch_future is not None:
                        batch = next_batch_future.result()

                        batch_offset = offset
                        offset += batch.batch_count

                        if offset < len(ids):
                            next_batch_future = prefetch_pool.submit(
                                self._prepare_batch,
                                ids,
                                offset,
                                report_download,
                            )
                        else:
                            next_batch_future = None

                        logger.info(
                            "Searching index batch of %d files (%d bytes); %d/%d indexes completed",
                            batch.batch_count,
                            batch.batch_bytes,
                            offset,
                            len(ids),
                        )

                        try:
                            yield (
                                batch.batch_dir,
                                batch_offset,
                                batch.batch_count,
                                len(ids),
                            )
                        finally:
                            shutil.rmtree(
                                batch.batch_dir,
                                ignore_errors=True,
                            )
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)
