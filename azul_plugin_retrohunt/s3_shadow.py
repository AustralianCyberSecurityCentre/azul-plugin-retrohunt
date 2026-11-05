"""Opt-in, non-authoritative replication of PVC BGI indexes to S3.

S3 failures never affect indexing, the local index files, or BigGrep searches.
No S3 object is made active for searches here; that requires a later manifest stage.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Any

from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.s3_storage import S3IndexObject, S3IndexStorage, file_digest

logger = logging.getLogger(__name__)

shadow_uploads = Counter("retrohunt_s3_shadow_uploads_total", "Shadow S3 index upload attempts", ["index", "result"])
shadow_upload_seconds = Histogram(
    "retrohunt_s3_shadow_upload_seconds", "Duration of S3 index shadow upload", ["index"]
)
shadow_pending = Counter(
    "retrohunt_s3_shadow_pending_files_total", "Indexes found without a verified upload receipt", ["index"]
)


class S3ShadowMirror:
    """Reconcile local completed indexes with immutable S3 objects.

    A small receipt file prevents reuploading all historical indexes on every
    scan/restart. Receipts are advisory and never used by the PVC search path.
    """

    def __init__(self, indexer: str, bgi_directory: Path, state_directory: Path, store: S3IndexStorage):
        self.indexer = indexer
        self.bgi_directory = Path(bgi_directory)
        self.state_directory = Path(state_directory)
        self.store = store
        self.receipts_path = self.state_directory / "s3_shadow_receipts.json"
        self.receipts = self._load_receipts()

    def _load_receipts(self) -> dict[str, dict[str, Any]]:
        try:
            raw = json.loads(self.receipts_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict) and raw.get("version") == 1 and isinstance(raw.get("indexes"), dict):
                return raw["indexes"]
        except FileNotFoundError:
            pass
        except (OSError, ValueError, TypeError) as exc:
            logger.warning("Cannot load S3 shadow receipts %s: %s; rechecking indexes", self.receipts_path, exc)
        return {}

    def _save_receipts(self) -> None:
        self.state_directory.mkdir(parents=True, exist_ok=True)
        fd, name = tempfile.mkstemp(prefix=".s3-shadow-", suffix=".tmp", dir=self.state_directory)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump({"version": 1, "indexes": self.receipts}, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(name, self.receipts_path)
        finally:
            Path(name).unlink(missing_ok=True)

    def sync_file(self, path: Path) -> bool:
        """Best-effort upload; return success/failure, never raise for S3 faults."""
        path = Path(path)
        if path.suffix != ".bgi" or path.name.startswith(".") or not path.is_file():
            return False
        try:
            # Avoid reading every large index every 10 seconds when unchanged.
            stat = path.stat()
            existing = self.receipts.get(path.name)
            if existing and existing.get("size") == stat.st_size and existing.get("mtime_ns") == stat.st_mtime_ns:
                return True
            # Hash changed files (especially periodic.bgi) before uploading.
            size, sha256 = file_digest(path)
            if existing and existing.get("sha256") == sha256 and existing.get("size") == size:
                self.receipts[path.name]["mtime_ns"] = stat.st_mtime_ns
                self._save_receipts()
                return True
            shadow_pending.labels(self.indexer).inc()
            started = time.monotonic()
            obj: S3IndexObject = self.store.upload_index(self.indexer, path)
            shadow_upload_seconds.labels(self.indexer).observe(time.monotonic() - started)
            # If the file was replaced during upload, record no receipt. A future
            # reconciliation will upload whichever version is now on disk.
            if file_digest(path) != (size, sha256) or path.stat().st_mtime_ns != stat.st_mtime_ns:
                raise RuntimeError(f"Index changed during S3 shadow upload: {path}")
            if obj.sha256 != sha256 or obj.size != size:
                raise RuntimeError(f"S3 upload returned inconsistent metadata for {path}")
            self.receipts[path.name] = {"key": obj.key, "sha256": sha256, "size": size, "mtime_ns": stat.st_mtime_ns}
            try:
                self._save_receipts()
            except OSError as exc:
                # Upload succeeded, but a missing receipt means safe reupload later.
                logger.warning("S3 upload worked but receipt persistence failed: %s", exc)
            shadow_uploads.labels(self.indexer, "success").inc()
            logger.info("S3 shadow index uploaded: %s => %s", path, obj.key)
            return True
        except Exception:
            shadow_uploads.labels(self.indexer, "failure").inc()
            logger.exception("S3 shadow index upload failed (PVC remains authoritative): %s", path)
            return False

    def reconcile(self) -> tuple[int, int]:
        """Retry missed indexes from local PVC without invoking bgindex."""
        successful = failed = 0
        for path in sorted(self.bgi_directory.glob("*.bgi")):
            if path.name.startswith(".") or not path.is_file():
                continue
            if self.sync_file(path):
                successful += 1
            else:
                failed += 1
        return successful, failed
