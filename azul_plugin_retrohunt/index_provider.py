"""Read-only access to indexes published by the external Retroindexer.

The Bedrock ``azul-index`` CLI is the only object-store client. It discovers
published indexes and fetches verified, immutable .bgi files into a local cache.
There is deliberately no upload, ingest, indexing, or PVC fallback here.
"""

import logging
import re
import subprocess
import tempfile
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from prometheus_client import Counter, Histogram

from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.index_provider")

# The Bedrock CLI's object key is the full lowercase SHA-256 of the .bgi bytes.
INDEX_ID = re.compile(r"^[0-9a-f]{64}$")

# Count expensive external calls separately from successful hunts.
index_fetch_count = Counter("retrohunt_index_fetch_total", "Bedrock index fetch attempts", ["status"])
index_fetch_seconds = Histogram("retrohunt_index_fetch_seconds", "Seconds spent ensuring a local .bgi")


class IndexUnavailable(RuntimeError):
    """Raised when Retrohunt cannot obtain the complete index snapshot."""


class ObjectIndexProvider:
    """Resolve one immutable published-index snapshot for a hunt.

    Instantiating the provider has no side effects. ``prepare`` takes a fresh
    published index listing once per hunt; the list is not refreshed while
    broad-phase tasks run. This ensures indexes published halfway through a
    hunt are not inconsistently included.
    """

    def __init__(self, settings: RetrohuntSettings):
        self.cache_dir = Path(settings.index_cache_dir).expanduser().resolve()
        self.cli = settings.index_cli_path
        self.fetch_workers = settings.index_fetch_workers
        self.list_timeout = settings.index_list_timeout_seconds
        self.fetch_timeout = settings.index_fetch_timeout_seconds

    def _run_cli(self, *args: str, timeout: int) -> str:
        """Run Bedrock without a shell; never include storage secrets in argv.

        The CLI inherits AZUL_INDEX_* environment variables and the pod's
        storage credentials. Capture only bounded output to avoid noisy logs.
        """
        try:
            result = subprocess.run(
                [self.cli, *args],
                check=True,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired, subprocess.CalledProcessError) as exc:
            # Avoid serialising the entire environment or CLI traceback: both
            # could expose credentials in diagnostics.
            logger.error("Bedrock index command %s failed: %s", args[0], type(exc).__name__)
            raise IndexUnavailable(f"Bedrock index {args[0]} failed ({type(exc).__name__})") from exc
        return result.stdout

    def list_indexes(self) -> list[str]:
        """Return unique immutable IDs; reject malformed or empty listings.

        An empty listing must fail, rather than making a hunt appear to
        succeed with zero matches while an index publisher is unavailable.
        """
        lines = self._run_cli("list", timeout=self.list_timeout).splitlines()
        ids = sorted(set(line.strip() for line in lines if line.strip()))
        if any(not INDEX_ID.fullmatch(index_id) for index_id in ids):
            raise IndexUnavailable("Bedrock listed an invalid index ID")
        if not ids:
            raise IndexUnavailable("No published BigGrep indexes found in object storage")
        logger.info("Found %d published BigGrep indexes", len(ids))
        return ids

    def fetch(self, index_id: str) -> Path:
        """Ensure that a Bedrock-verified index is locally available.

        Always call the CLI, even on a local cache hit. Its Go implementation
        uses a filesystem lock, validates the checksum and atomically replaces
        incomplete downloads, so two workers never read a partially written
        file. Only use the returned path after the subprocess succeeds.
        """
        if not INDEX_ID.fullmatch(index_id):
            raise IndexUnavailable("Invalid BigGrep index identifier")
        destination = self.cache_dir / f"{index_id}.bgi"
        with index_fetch_seconds.time():
            try:
                self._run_cli(
                    "fetch", "--id", index_id, "--output", str(destination),
                    timeout=self.fetch_timeout,
                )
                if not destination.is_file() or destination.stat().st_size == 0:
                    raise IndexUnavailable(f"Bedrock returned no local index for {index_id}")
                index_fetch_count.labels("success").inc()
            except Exception:
                index_fetch_count.labels("failed").inc()
                raise
        return destination

    def prepare(self) -> list[Path]:
        """Fetch the complete listing with bounded concurrency, then search.

        A hunt cannot proceed with a partial index set: that would silently
        produce false negatives. The completion order is irrelevant; sorted
        paths make search task ordering deterministic.
        """
        ids = self.list_indexes()
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        paths = []
        with ThreadPoolExecutor(max_workers=self.fetch_workers) as pool:
            futures = {pool.submit(self.fetch, index_id): index_id for index_id in ids}
            for future in as_completed(futures):
                try:
                    paths.append(future.result())
                except Exception as exc:
                    for remaining in futures:
                        remaining.cancel()
                    raise IndexUnavailable(f"Cannot prepare complete index snapshot: {futures[future]}") from exc
        logger.info("Prepared %d BigGrep indexes from Bedrock object storage", len(paths))
        return sorted(paths)

    @contextmanager
    def search_snapshot(self):
        """Expose *only* this hunt's published indexes to the search engine.

        A shared cache may contain old objects from earlier hunts. BigGrep
        searches every .bgi in a directory, so using the cache directory itself
        would incorrectly include old or unpublished-for-this-hunt indexes.
        Cheap per-hunt symlinks create a fixed search directory without
        copying index bytes, and are removed after the hunt finishes.
        """
        paths = self.prepare()
        # The snapshot directory lives alongside cache contents on the same
        # filesystem; the temporary links point only to verified .bgi files.
        with tempfile.TemporaryDirectory(prefix=".snapshot-", dir=self.cache_dir) as directory:
            snapshot = Path(directory)
            for path in paths:
                (snapshot / path.name).symlink_to(path)
            yield snapshot
