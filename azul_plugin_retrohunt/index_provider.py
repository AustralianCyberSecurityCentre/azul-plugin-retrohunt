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
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from threading import Lock

from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.index_storage import IndexStorage, IndexStorageError, create_storage, index_prefix
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.index_provider")
INDEX_ID = re.compile(r"^[0-9a-f]{64}$")
# Match Retroindexer's partition identifiers; legacy flat objects remain valid.
FILE_TYPES = frozenset(
    {
        "windows",
        "elf",
        "macho",
        "mobile",
        "bytecode",
        "document",
        "archive",
        "script",
        "image",
        "audio",
        "video",
        "executable-other",
        "unknown",
        "other",
        "mixed",
    }
)
SIZE_CLASSES = frozenset({"lt1m", "1m-10m", "10m-100m", "gte100m", "mixed"})


def _index_object_name(relative_key: str, suffix: str) -> tuple[str, str] | None:
    """Validate a legacy or partitioned index key and return its ID and path."""
    if not relative_key.endswith(suffix):
        return None
    parts = relative_key[: -len(suffix)].split("/")
    if not INDEX_ID.fullmatch(parts[-1]):
        return None
    if len(parts) == 1:
        return parts[-1], parts[-1]
    if (
        len(parts) == 3
        and parts[0] in FILE_TYPES
        and parts[1] in SIZE_CLASSES
        and ((parts[0] == "mixed") == (parts[1] == "mixed"))
    ):
        return parts[-1], "/".join(parts)
    return None


index_fetch_count = Counter("retrohunt_index_fetch_total", "Published index cache fetch attempts", ["status"])
index_fetch_seconds = Histogram("retrohunt_index_fetch_seconds", "Seconds spent downloading an index")
index_cache_verify_seconds = Histogram(
    "retrohunt_index_cache_verify_seconds", "Seconds spent hashing a local cached index"
)
index_download_bytes = Counter("retrohunt_index_download_bytes_total", "Bytes downloaded from index object storage")


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
        self.fetch_workers = getattr(settings, "index_download_workers", 2)
        self.cache_lock = Lock()
        self.reserved_bytes = 0
        self.inflight_ids: set[str] = set()
        self.cache_hits = 0
        self.cache_downloads = 0
        # IDs remain the unit of sharding/cache identity; keys locate the blob.
        self.index_keys: dict[str, str] = {}
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
        if (
            used + incoming + self.reserved_bytes <= self.max_cache_bytes
            and available >= incoming + self.reserved_bytes + self.min_free_bytes
        ):
            return
        # Once eviction starts, aim for the 80 GiB low watermark to avoid churn.
        target = min(self.target_cache_bytes, self.max_cache_bytes - incoming - self.reserved_bytes)
        for path in sorted(entries, key=lambda item: item.stat().st_mtime_ns):
            stat = path.stat()
            # A hardlinked index is still part of a running search batch.
            if stat.st_nlink > 1 or path.stem in self.inflight_ids:
                continue
            size = stat.st_size
            path.unlink()
            used -= size
            available += size
            if used <= target and available >= incoming + self.reserved_bytes + self.min_free_bytes:
                break
        if (
            used + incoming + self.reserved_bytes > self.max_cache_bytes
            or available < incoming + self.reserved_bytes + self.min_free_bytes
        ):
            raise IndexUnavailable("Insufficient free PVC space for index download; refusing to download")

    def _ensure_cached(
        self,
        index_id: str,
        expected_size: int,
        report_download=None,
        report_cache_hit=None,
        batch_dir: Path | None = None,
    ) -> Path:
        """Verify/cache one immutable index, reserving capacity before any concurrent transfer.

        The per-provider mutex protects eviction, reservations and creation of hardlinks.
        Each active search batch hardlink pins its cache entry against LRU eviction.
        """
        path = self.cache_dir / f"{index_id}.bgi"
        with self.cache_lock:
            if path.is_file():
                started = time.monotonic()
                valid = path.stat().st_size == expected_size
                if valid:
                    digest = hashlib.sha256()
                    with path.open("rb") as cached:
                        for block in iter(lambda: cached.read(1024 * 1024), b""):
                            digest.update(block)
                    valid = digest.hexdigest() == index_id
                verify_seconds = time.monotonic() - started
                index_cache_verify_seconds.observe(verify_seconds)
                if valid:
                    os.utime(path, None)
                    if batch_dir is not None:
                        os.link(path, batch_dir / path.name)
                    index_fetch_count.labels("hit").inc()
                    self.cache_hits += 1
                    logger.info(
                        "Index cache HIT id=%s bytes=%d verify_seconds=%.3f downloaded_bytes=0",
                        index_id,
                        expected_size,
                        verify_seconds,
                    )
                    if report_cache_hit:
                        report_cache_hit(expected_size)
                    return path
                logger.warning("Discarding stale or damaged cached index %s", index_id)
                path.unlink()
            self._make_room(expected_size)
            self.reserved_bytes += expected_size
            self.inflight_ids.add(index_id)

        logger.info("Index download START id=%s bytes=%d", index_id, expected_size)
        started = time.monotonic()
        try:
            self._download_into(index_id, path, expected_size, report_download)
            with self.cache_lock:
                if batch_dir is not None:
                    os.link(path, batch_dir / path.name)
                self.cache_downloads += 1
            elapsed = max(time.monotonic() - started, 0.000001)
            logger.info(
                "Index download COMPLETE id=%s bytes=%d elapsed_seconds=%.3f throughput_MiBps=%.2f sha256_verified=true",
                index_id,
                expected_size,
                elapsed,
                expected_size / (1024**2) / elapsed,
            )
            return path
        finally:
            with self.cache_lock:
                self.reserved_bytes -= expected_size
                self.inflight_ids.discard(index_id)

    def _object_key(self, index_id: str) -> str:
        """Resolve a snapshot index ID to its published object key."""
        if not INDEX_ID.fullmatch(index_id):
            raise IndexUnavailable("Invalid BigGrep index identifier")
        relative = self.index_keys.get(index_id, f"{index_id}.bgi")
        if _index_object_name(relative, ".bgi") != (index_id, relative[:-4]):
            raise IndexUnavailable(f"Invalid published object path for index {index_id}")
        return self.prefix + relative

    def _prepare_batch(self, ids: list[str], offset: int, report_download, report_cache_hit=None) -> PreparedBatch:
        """Prepare one budget-bounded batch, downloading indexes concurrently.

        Select the complete batch before starting transfers; all concurrent cache
        misses reserve their bytes under a lock, so no two threads overcommit disk.
        """
        batch_dir = Path(tempfile.mkdtemp(prefix=".hunt-batch-", dir=self.cache_dir))
        selected = []
        batch_bytes = 0
        try:
            for index_id in ids[offset:]:
                try:
                    size = self.index_sizes.get(index_id) if hasattr(self, "index_sizes") else None
                    if size is None:
                        size = self.storage.object_size(self._object_key(index_id))
                except Exception as exc:
                    raise IndexUnavailable(f"Cannot determine size for index {index_id}") from exc
                if size <= 0 or size > self.max_cache_bytes:
                    raise IndexUnavailable(f"Published index {index_id} cannot fit in the local cache")
                if selected and batch_bytes + size > self.max_cache_bytes // 2:
                    break
                selected.append((index_id, size, offset + len(selected)))
                batch_bytes += size
            if not selected:
                raise IndexUnavailable("Unable to prepare any index for searching")

            with ThreadPoolExecutor(max_workers=min(self.fetch_workers, len(selected))) as executor:
                futures = [
                    executor.submit(
                        self._ensure_cached,
                        idx,
                        size,
                        lambda received, pos=pos, sz=size: report_download(pos, received, sz),
                        lambda cached_size, pos=pos: (
                            report_cache_hit(pos, cached_size) if report_cache_hit is not None else None
                        ),
                        batch_dir,
                    )
                    for idx, size, pos in selected
                ]
                errors = []
                for future in as_completed(futures):
                    try:
                        future.result()
                    except Exception as exc:
                        errors.append(exc)
                if errors:
                    raise errors[0]
            return PreparedBatch(batch_dir, batch_bytes, len(selected))
        except Exception:
            shutil.rmtree(batch_dir, ignore_errors=True)
            raise

    def list_indexes(self) -> list[str]:
        """Snapshot committed legacy and partitioned indexes without reading bodies.

        Match .bgi and .ready in the *same* partition. A duplicate hash can
        occur under more than one prefix; the content is identical, so select
        one deterministic key and preserve unique SHA IDs for work splitting.
        """
        try:
            start = time.monotonic()
            available: set[str] = set()
            ready: set[str] = set()
            for key in self.storage.list_keys(self.prefix):
                if time.monotonic() - start > self.list_timeout:
                    raise IndexUnavailable("Timed out listing published indexes")
                if not key.startswith(self.prefix):
                    continue
                relative = key[len(self.prefix) :]
                index = _index_object_name(relative, ".bgi")
                if index is not None:
                    available.add(index[1])
                    continue
                index = _index_object_name(relative, ".ready")
                if index is not None:
                    ready.add(index[1])

            # Keep the snapshot immutable for batch preparation and shard manifests.
            selected: dict[str, str] = {}
            for relative in sorted(ready & available):
                index_id = relative.rsplit("/", 1)[-1]
                selected.setdefault(index_id, relative + ".bgi")
            if not selected:
                raise IndexUnavailable("No published BigGrep indexes found in object storage")
            self.index_keys = selected
            ids = sorted(selected)
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
                    with self.storage.read_chunks(self._object_key(index_id)) as chunks:
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
                            index_download_bytes.inc(len(block))
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
        self.index_sizes = getattr(self, "index_sizes", {})
        download_progress_lock = Lock()
        logger.info("Broad-phase index preparation starting: %d indexes (checking persistent cache)", len(ids))

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
                        "Broad-phase transfer progress %d%%: %d/%d indexes examined (cache hits excluded)",
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
