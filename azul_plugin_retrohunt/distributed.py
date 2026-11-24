"""Opt-in, Redis-coordinated distribution of a Retrohunt over index shards.

One stream and consumer group carry both hunt submissions and shard tasks, so a
worker always takes the next available unit of work. Each shard runs the full
broad/narrow search against its assigned immutable .bgi index IDs.

No worker writes its local hunt snapshot over another worker's results. Shard
snapshots are fenced with a Redis lease, and the public hunt is rebuilt under
WATCH from all shard snapshots. Redis remains the only coordination service.
"""

from __future__ import annotations

import fcntl
import json
import logging
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from io import StringIO
from time import monotonic, time
from uuid import uuid4

import pendulum
from azul_bedrock import models_network as azm
from redis.exceptions import WatchError

from azul_plugin_retrohunt.index_provider import ObjectIndexProvider
from azul_plugin_retrohunt.retrohunt import CancelException

logger = logging.getLogger("retrohunt.distributed")
MATCH_LIMIT = 200
# Public hunt logs are deliberately small; technical logs stay in pod stdout.
PUBLIC_LOG_MAX_CHARS = 64000
PROGRESS_UPDATE_INTERVAL_SECONDS = 1.0
BAR_WIDTH = 16


def _progress_bar(done, total):
    """Render a bounded progress bar; an unknown total is not 100%."""
    if not isinstance(total, (int, float)) or total <= 0:
        return "[" + "-" * BAR_WIDTH + "]  --%"
    fraction = min(1.0, max(0.0, done / total))
    filled = min(BAR_WIDTH, int(fraction * BAR_WIDTH))
    return f"[{'#' * filled}{'-' * (BAR_WIDTH - filled)}] {fraction * 100:3.0f}%"


def _elapsed_text(seconds):
    """Format hunt elapsed time with no misleading fractional seconds."""
    seconds = max(0, int(seconds or 0))
    hours, remainder = divmod(seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    return f"{hours:02d}:{minutes:02d}:{seconds:02d}"


def _time_text(value):
    """Render a timestamp explicitly in UTC for consistent multi-pod logs."""
    if value is None:
        return "unknown"
    return pendulum.instance(value).in_timezone("UTC").format("YYYY-MM-DD HH:mm:ss [UTC]")


def _shard_summary(number, state):
    """Describe the active shard phase without inventing a hunt-wide ETA."""
    status = state.get("status", "pending")
    count = state.get("index_count", 0)
    progress = state.get("progress") or {}
    downloaded = state.get("download") or {}
    if status == "completed":
        matches = sum(len(items) for items in state.get("results", {}).values())
        return f"Shard {number}: {_progress_bar(1, 1)} Completed | {count} indexes | {matches} matches"
    if status == "failed":
        error = str(state.get("error") or "Unknown error").replace("\n", " ")[:160]
        return f"Shard {number}: FAILED | {count} indexes | {error}"
    if status == "retrying":
        return f"Shard {number}: Retry pending | {count} indexes"
    if status == "downloading":
        done = downloaded.get("done", 0)
        total = downloaded.get("total", count)
        return f"Shard {number}: {_progress_bar(done, total)} Downloading indexes ({done:.1f}/{total})"
    if status == "broad":
        done = progress.get("index_searches_done", 0)
        total = progress.get("index_searches_total", 0)
        return f"Shard {number}: {_progress_bar(done, total)} Broad search ({done}/{total or '?'} tasks)"
    if status == "narrow":
        done = progress.get("tool_matches_done", 0)
        total = progress.get("tool_matches_total", 0)
        return f"Shard {number}: {_progress_bar(done, total)} YARA-X ({done}/{total or '?'} files)"
    if status == "starting":
        return f"Shard {number}: Starting | {count} indexes"
    return f"Shard {number}: Waiting | {count} indexes"


class AssignedIndexProvider(ObjectIndexProvider):
    """Use the existing bounded, SHA-verified downloader for one shard."""

    def __init__(self, settings, index_ids):
        super().__init__(settings)
        self._assigned_index_ids = list(index_ids)
        self.progress_callback = None

    def list_indexes(self):
        """Return only the immutable index IDs assigned to this shard."""
        return list(self._assigned_index_ids)

    def iter_search_batches(self):
        """Download only assigned IDs, bounded even for an oversized single file.

        Per-shard downloads retain parallel fetching and SHA verification. We do
        not prefetch a second batch because a single file may exceed half the
        cache budget; distributed workers provide inter-shard concurrency.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.cache_dir / ".batch-search.lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                ids = self.list_indexes()
                offset = 0
                while offset < len(ids):
                    callback = self.progress_callback or (lambda *_: None)
                    prepared = self._prepare_batch(ids, offset, callback)
                    try:
                        logger.info("Shard index download: %d/%d complete", offset + prepared.batch_count, len(ids))
                        if self.progress_callback is not None:
                            for index_offset in range(offset, offset + prepared.batch_count):
                                self.progress_callback(index_offset, 1, 1)
                        yield (prepared.batch_dir, offset, prepared.batch_count, len(ids))
                    finally:
                        shutil.rmtree(prepared.batch_dir, ignore_errors=True)
                    offset += prepared.batch_count
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)


def _key(hunt_id, suffix):
    return f"retrohunt:{hunt_id}:{suffix}"


def _text(value):
    return value.decode() if isinstance(value, bytes) else str(value)


def _load(raw):
    return json.loads(raw) if raw is not None else None


def _identity(rule, value):
    """Retain distinct source/label identities for the same SHA-256."""
    return (rule, value.get("sha256") or value.get("sample"), value.get("stream_source"), value.get("stream_label"))


def _public_result(value):
    """Expose the exact match shape used by the original single-worker hunts.

    The shard keeps ``sha256`` privately for reliable deduplication across
    batches, but the public RetrohuntEvent result schema is unchanged.
    """
    return {
        "stream_label": value["stream_label"],
        "stream_source": value["stream_source"],
        "sample": value["sample"],
    }


def partition_indexes(sized_indexes, requested):
    """Greedy size-balancing, deterministic assignment, no duplicate index IDs."""
    if not sized_indexes:
        raise ValueError("Cannot shard an empty index snapshot")
    count = min(requested, len(sized_indexes))
    shards = [{"ids": [], "bytes": 0} for _ in range(count)]
    for idx, size in sorted(sized_indexes, key=lambda item: (-item[1], item[0])):
        shard = min(enumerate(shards), key=lambda entry: (entry[1]["bytes"], entry[0]))[1]
        shard["ids"].append(idx)
        shard["bytes"] += size
    return shards


def _snapshot(redis_client, hunt_id):
    raw = redis_client.get(_key(hunt_id, "manifest"))
    return _load(raw)


def enqueue_hunt(redis_client, hunt_id, message_id, settings, service):
    """Expand one submitted hunt into shard messages, once, transactionally."""
    raw = redis_client.get(hunt_id)
    if raw is None:
        redis_client.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
        return
    event = azm.RetrohuntEvent.model_validate_json(raw)
    if event.entity.status in {azm.HuntState.CANCELLED, azm.HuntState.COMPLETED, azm.HuntState.FAILED}:
        redis_client.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
        return
    if _snapshot(redis_client, hunt_id):
        redis_client.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
        return

    init_key = _key(hunt_id, "initializing")
    init_token = uuid4().hex
    if not redis_client.set(init_key, init_token, nx=True, ex=300):
        # Leave the submission pending: the owner will commit and ACK it, or
        # another worker will reclaim it if initialization crashes.
        return
    try:
        if _snapshot(redis_client, hunt_id):
            redis_client.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
            return
        provider = ObjectIndexProvider(settings)
        ids = provider.list_indexes()
        # Bounded parallel HEAD requests; no sample bytes or index bytes copied.
        with ThreadPoolExecutor(max_workers=min(8, settings.index_fetch_workers * 2)) as pool:
            sizes = list(pool.map(lambda idx: provider.storage.object_size(provider.prefix + idx + ".bgi"), ids))
        if any(size <= 0 or size > settings.index_cache_max_bytes for size in sizes):
            raise ValueError("An index is empty or exceeds the local index cache budget")
        requested_raw = redis_client.get(_key(hunt_id, "requested_shards"))
        requested = int(requested_raw) if requested_raw is not None else settings.hunt_shards
        if not 1 <= requested <= 128:
            raise ValueError("Requested shard count must be between 1 and 128")
        shards = partition_indexes(list(zip(ids, sizes, strict=True)), requested)
        manifest = {"v": 1, "shards": shards, "created": time(), "index_count": len(ids)}

        # All shard records, stream messages, manifest and public state are
        # published atomically: no worker can see a partially initialized hunt.
        with redis_client.pipeline() as pipe:
            pipe.watch(_key(hunt_id, "manifest"), hunt_id)
            if pipe.get(_key(hunt_id, "manifest")) is not None:
                pipe.unwatch()
                redis_client.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
                return
            current = azm.RetrohuntEvent.model_validate_json(pipe.get(hunt_id))
            if current.entity.status == azm.HuntState.CANCELLED:
                pipe.unwatch()
                redis_client.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
                return
            started_at = pendulum.now("UTC")
            current.entity.status = azm.HuntState.STARTING
            if not current.entity.processing_start:
                current.entity.processing_start = started_at
            current.entity.logs = (
                f"[{_time_text(started_at)}] Distributed hunt started: "
                f"{len(shards)} shards across {len(ids)} indexes\n"
            )
            current.entity.updated = started_at
            pipe.multi()
            pipe.set(_key(hunt_id, "manifest"), json.dumps(manifest))
            pipe.set(hunt_id, current.model_dump_json())
            initial = min(len(shards), settings.hunt_max_parallel_shards)
            pipe.set(_key(hunt_id, "next_shard"), initial)
            for number, shard in enumerate(shards):
                pipe.set(
                    _key(hunt_id, f"shard:{number}"),
                    json.dumps(
                        {
                            "status": "pending",
                            "index_count": len(shard["ids"]),
                            "index_bytes": shard["bytes"],
                            "progress": {},
                            "results": {},
                            "error": "",
                        }
                    ),
                )
                if number < initial:
                    pipe.xadd(
                        service.RETROHUNT_JOB,
                        {
                            "hunt_id": hunt_id,
                            "action": "Shard",
                            "shard": str(number),
                        },
                    )
            pipe.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, message_id)
            pipe.execute()
        logger.info("Hunt %s split into %d shards over %d indexes", hunt_id, len(shards), len(ids))
    except WatchError:
        # Another initializer/user update won; re-claim will handle if needed.
        logger.info("Hunt %s changed while shard manifest was being created", hunt_id)
    except Exception:
        logger.exception("Failed to initialize distributed hunt %s", hunt_id)
        # Preserve the pending submission for retry instead of losing the hunt.
        raise
    finally:
        # Do not accidentally remove a new owner's lock after TTL expiry.
        redis_client.eval(
            "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) end return 0",
            1,
            init_key,
            init_token,
        )


def _schedule_next(redis_client, hunt_id, shard_id, manifest, service):
    """Replace a finished shard with one more, fairly queued after other hunts.

    Lua makes the once-only completion token, cursor increment, and XADD atomic.
    A completed shard reprocessed after a crash cannot schedule twice.
    """
    script = """
    if redis.call('EXISTS', KEYS[3]) ~= 0 then return -1 end
    if redis.call('SADD', KEYS[1], ARGV[1]) == 0 then return 0 end
    local next = tonumber(redis.call('GET', KEYS[2]) or '0')
    if next >= tonumber(ARGV[2]) then return 0 end
    redis.call('SET', KEYS[2], next + 1)
    redis.call('XADD', KEYS[4], '*', 'hunt_id', ARGV[3], 'action', 'Shard', 'shard', tostring(next))
    return 1
    """
    return redis_client.eval(
        script,
        4,
        _key(hunt_id, "scheduled_after"),
        _key(hunt_id, "next_shard"),
        _key(hunt_id, "cancel"),
        service.RETROHUNT_JOB,
        str(shard_id),
        len(manifest["shards"]),
        hunt_id,
    )


def _aggregate(redis_client, hunt_id):
    """Derive the public RetrohuntEvent from all committed shard snapshots."""
    manifest = _snapshot(redis_client, hunt_id)
    if manifest is None:
        return
    keys = [_key(hunt_id, f"shard:{i}") for i in range(len(manifest["shards"]))]
    for _ in range(32):
        try:
            with redis_client.pipeline() as pipe:
                pipe.watch(hunt_id, *keys)
                raw = pipe.get(hunt_id)
                if raw is None:
                    pipe.unwatch()
                    return
                event = azm.RetrohuntEvent.model_validate_json(raw)
                statuses = [_load(item) for item in pipe.mget(keys)]
                if any(x is None for x in statuses):
                    pipe.unwatch()
                    raise RuntimeError("Incomplete shard state")
                # A user cancellation or a previously terminal result is final.
                if event.entity.status in {azm.HuntState.CANCELLED, azm.HuntState.COMPLETED, azm.HuntState.FAILED}:
                    pipe.unwatch()
                    return
                finished = sum(x["status"] == "completed" for x in statuses)
                failed = [x for x in statuses if x["status"] == "failed"]
                values = {}
                for item in statuses:
                    for key, value in item.get("progress", {}).items():
                        if key == "atom_count" or key.startswith("rules_parsed_"):
                            values[key] = max(values.get(key, 0), value)
                        else:
                            values[key] = values.get(key, 0) + value
                for key, value in values.items():
                    setattr(event.entity, key, value)
                merged, seen = {}, set()
                for item in statuses:
                    for rule, matches in item.get("results", {}).items():
                        for result in matches:
                            signature = _identity(rule, result)
                            if signature in seen:
                                continue
                            seen.add(signature)
                            if len(seen) <= MATCH_LIMIT:
                                merged.setdefault(rule, []).append(_public_result(result))
                event.entity.results = merged
                event.entity.tool_match_count = min(len(seen), MATCH_LIMIT)
                now = pendulum.now("UTC")
                event.entity.updated = now
                if not event.entity.processing_start:
                    event.entity.processing_start = now
                stop_reason = None
                if failed:
                    event.entity.status = azm.HuntState.FAILED
                    stop_reason = "failed"
                    event.entity.error = failed[0]["error"]
                elif len(seen) >= MATCH_LIMIT:
                    event.entity.status = azm.HuntState.CANCELLED
                    stop_reason = "match-limit"
                    event.entity.error = (
                        f"Match count hit threshold of {MATCH_LIMIT}. Please refine your search terms."
                    )
                elif finished == len(statuses):
                    event.entity.status = azm.HuntState.COMPLETED
                elif any(x["status"] in {"narrow", "completed"} for x in statuses):
                    event.entity.status = azm.HuntState.SEARCHING_NARROW
                else:
                    event.entity.status = azm.HuntState.SEARCHING_WIDE
                terminal = event.entity.status in {
                    azm.HuntState.CANCELLED,
                    azm.HuntState.COMPLETED,
                    azm.HuntState.FAILED,
                }
                if terminal:
                    event.action = azm.RetrohuntEvent.RetrohuntAction.Completed
                    event.entity.processing_end = now
                else:
                    event.action = azm.RetrohuntEvent.RetrohuntAction.Running
                event.timestamp = now
                # Preserve the original duration field for the API/UI.
                elapsed = max(
                    0.0, (pendulum.instance(now) - pendulum.instance(event.entity.processing_start)).total_seconds()
                )
                event.entity.duration = elapsed
                # User-facing progress is a replaceable status snapshot.
                # Full technical logs still go to Kubernetes pod stdout.
                header = (
                    f"Distributed hunt: {len(statuses)} shards across "
                    f"{manifest['index_count']} indexes | "
                    f"{event.entity.tool_match_count} confirmed matches"
                )
                timing = (
                    f"Started: {_time_text(event.entity.processing_start)}\n"
                    f"Last updated: {_time_text(now)}\n"
                    f"Elapsed: {_elapsed_text(elapsed)}"
                )
                summary = "\n".join(_shard_summary(i + 1, state) for i, state in enumerate(statuses))
                if terminal:
                    timing += (
                        f"\nFinished: {_time_text(event.entity.processing_end)}\n"
                        f"Total hunt duration: {_elapsed_text(elapsed)}"
                    )
                    logger.info(
                        "Distributed hunt %s %s in %s (%d confirmed matches)",
                        hunt_id,
                        event.entity.status,
                        _elapsed_text(elapsed),
                        event.entity.tool_match_count,
                    )
                event.entity.logs = (header + "\n" + timing + "\n\n" + summary + "\n")[-PUBLIC_LOG_MAX_CHARS:]
                pipe.multi()
                pipe.set(hunt_id, event.model_dump_json())
                if stop_reason:
                    pipe.set(_key(hunt_id, "cancel"), stop_reason)
                pipe.execute()
                return
        except WatchError:
            continue
    raise RuntimeError("Excessive contention updating distributed hunt")


def _write_shard(redis_client, hunt_id, shard_id, token, snapshot):
    """Fenced shard write. An expired/reassigned worker cannot commit state."""
    lease = _key(hunt_id, f"lease:{shard_id}")
    target = _key(hunt_id, f"shard:{shard_id}")
    for _ in range(32):
        try:
            with redis_client.pipeline() as pipe:
                pipe.watch(lease, target, _key(hunt_id, "cancel"), hunt_id)
                if pipe.get(lease) != token.encode():
                    pipe.unwatch()
                    raise CancelException("Shard ownership lost")
                if pipe.get(_key(hunt_id, "cancel")):
                    pipe.unwatch()
                    raise CancelException("Hunt has been stopped")
                if pipe.get(hunt_id) is None:
                    pipe.unwatch()
                    raise CancelException("Hunt was deleted")
                pipe.multi()
                pipe.set(target, json.dumps(snapshot))
                pipe.execute()
            _aggregate(redis_client, hunt_id)
            return
        except WatchError:
            continue
    raise RuntimeError("Excessive contention recording shard progress")


def _heartbeat(redis_client, lease_key, token, stream, group, worker_id, msg_id, stop, interval, ttl):
    script = "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('EXPIRE',KEYS[1],ARGV[2]) end return 0"
    while not stop.wait(interval):
        try:
            if not redis_client.eval(script, 1, lease_key, token, ttl):
                return
            # Refresh Redis stream pending-entry idle time as well as our lease.
            redis_client.xclaim(stream, group, worker_id, min_idle_time=0, message_ids=[msg_id], justid=True)
        except Exception:
            logger.exception("Shard lease heartbeat failed")
            return


def run_shard(redis_client, payload, msg_id, worker_id, settings, service, execute):
    """Run exactly one shard, then return to the shared stream for other hunts."""
    hunt_id = _text(payload[b"hunt_id"])
    shard_id = int(payload[b"shard"])
    manifest = _snapshot(redis_client, hunt_id)
    stream, group = service.RETROHUNT_JOB, service.RETROHUNT_GROUP
    if not manifest or shard_id < 0 or shard_id >= len(manifest["shards"]):
        redis_client.xack(stream, group, msg_id)
        return
    if redis_client.get(_key(hunt_id, "cancel")) or not redis_client.exists(hunt_id):
        redis_client.xack(stream, group, msg_id)
        return
    previous = _load(redis_client.get(_key(hunt_id, f"shard:{shard_id}")))
    if previous and previous["status"] == "completed":
        _schedule_next(redis_client, hunt_id, shard_id, manifest, service)
        redis_client.xack(stream, group, msg_id)
        return
    lease_key = _key(hunt_id, f"lease:{shard_id}")
    token = uuid4().hex
    if not redis_client.set(lease_key, token, nx=True, ex=settings.hunt_shard_lease_seconds):
        # Another pod is working on this shard; leave the entry pending.
        return
    stop = threading.Event()
    interval = max(1, min(settings.hunt_shard_lease_seconds // 4, settings.redis.ttl // 3, 10))
    heart = threading.Thread(
        target=_heartbeat,
        args=(
            redis_client,
            lease_key,
            token,
            stream,
            group,
            worker_id,
            msg_id,
            stop,
            interval,
            settings.hunt_shard_lease_seconds,
        ),
        daemon=True,
    )
    heart.start()
    try:
        attempt = redis_client.incr(_key(hunt_id, f"attempts:{shard_id}"))
        state = {
            "status": "starting",
            "index_count": len(manifest["shards"][shard_id]["ids"]),
            "progress": {},
            "results": {},
            "error": "",
            "attempt": attempt,
        }
        if attempt > settings.hunt_shard_max_retries:
            state.update(
                status="failed",
                error=f"Shard {shard_id} exceeded {settings.hunt_shard_max_retries} attempts",
            )
            _write_shard(redis_client, hunt_id, shard_id, token, state)
            redis_client.xack(stream, group, msg_id)
            return
        _write_shard(redis_client, hunt_id, shard_id, token, state)
        raw = redis_client.get(hunt_id)
        if raw is None:
            return
        shard_job = azm.RetrohuntEvent.model_validate_json(raw)
        # Parent counters/results are aggregated from every shard. A shard must
        # start from zero rather than inherit totals from another shard.
        shard_job.entity.results = {}
        shard_job.entity.tool_match_count = 0
        for field in (
            "atom_count",
            "rules_parsed_total",
            "rules_parsed_done",
            "index_searches_total",
            "index_searches_done",
            "index_match_count",
            "tool_matches_total",
            "tool_matches_done",
        ):
            setattr(shard_job.entity, field, 0)
        provider = AssignedIndexProvider(settings, manifest["shards"][shard_id]["ids"])
        logs = StringIO()
        index_count = state["index_count"]
        download_fractions = {}
        publish_lock = threading.RLock()
        last_download_publish = 0.0
        last_download_percent = -1

        def report_download(index_offset, received, expected):
            """Publish throttled, index-weighted progress from download threads."""
            nonlocal last_download_publish, last_download_percent
            with publish_lock:
                fraction = min(1.0, max(0.0, received / expected)) if expected else 0.0
                download_fractions[index_offset] = max(download_fractions.get(index_offset, 0), fraction)
                done = min(float(index_count), sum(download_fractions.values()))
                percent = int(100 * done / index_count) if index_count else 0
                now = monotonic()
                if percent < 100 and now - last_download_publish < PROGRESS_UPDATE_INTERVAL_SECONDS:
                    return
                if percent == last_download_percent:
                    return
                state["download"] = {"done": round(done, 2), "total": index_count}
                state["status"] = "downloading"
                _write_shard(redis_client, hunt_id, shard_id, token, state)
                last_download_publish = now
                last_download_percent = percent

        provider.progress_callback = report_download

        def writer(job, _logs):
            if redis_client.get(_key(hunt_id, "cancel")):
                raise CancelException("Distributed hunt cancelled")
            with publish_lock:
                # Keep the download phase visible until BigGrep actually starts.
                if job.entity.status == azm.HuntState.SEARCHING_NARROW:
                    state["status"] = "narrow"
                elif job.entity.status == azm.HuntState.SEARCHING_WIDE:
                    state["status"] = "broad"
                elif state["status"] != "downloading":
                    state["status"] = "starting"
                state["progress"] = {
                    key: getattr(job.entity, key, 0) or 0
                    for key in (
                        "atom_count",
                        "rules_parsed_total",
                        "rules_parsed_done",
                        "index_searches_total",
                        "index_searches_done",
                        "index_match_count",
                        "tool_matches_total",
                        "tool_matches_done",
                    )
                }
                state["results"] = job.entity.results or {}
                _write_shard(redis_client, hunt_id, shard_id, token, state)

        logger.info(
            "Worker %s executing hunt %s shard %d/%d (%d indexes)",
            worker_id,
            hunt_id,
            shard_id + 1,
            len(manifest["shards"]),
            len(manifest["shards"][shard_id]["ids"]),
        )
        # worker.py and BigGrep already write detailed logs to pod stdout.
        # Do not copy those logs into the public RetrohuntEvent.
        execute(shard_job, logs, provider, writer)
        # hunt() captures ordinary exceptions as FAILED in its final local event.
        if shard_job.entity.status == azm.HuntState.FAILED:
            state["error"] = shard_job.entity.error or "Shard search failed"
            if attempt < settings.hunt_shard_max_retries:
                state["status"] = "retrying"
                _write_shard(redis_client, hunt_id, shard_id, token, state)
                return  # Leave message pending for XAUTOCLAIM after idle timeout.
            state["status"] = "failed"
        elif shard_job.entity.status == azm.HuntState.CANCELLED:
            # One shard can reach the 200-match cap before siblings.
            state["status"] = "completed"
        else:
            state["status"] = "completed"
        state["results"] = shard_job.entity.results or {}
        _write_shard(redis_client, hunt_id, shard_id, token, state)
        if state["status"] == "completed":
            _schedule_next(redis_client, hunt_id, shard_id, manifest, service)
        redis_client.xack(stream, group, msg_id)
    except CancelException:
        # Losing a lease is NOT an acknowledgement. Another consumer may own
        # and be processing this stream entry now; keep it recoverable.
        if redis_client.get(_key(hunt_id, "cancel")) or not redis_client.exists(hunt_id):
            redis_client.xack(stream, group, msg_id)
    except Exception:
        logger.exception("Hunt %s shard %d failed; leaving for retry", hunt_id, shard_id)
        # The pending stream entry will be reclaimed by another idle worker.
    finally:
        stop.set()
        heart.join(timeout=2)
        redis_client.eval(
            "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
            1,
            lease_key,
            token,
        )
