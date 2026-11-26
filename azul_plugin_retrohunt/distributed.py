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


def worker_quotas(worker_count: int, hunts: list[str]) -> dict[str, int]:
    """Give each waiting hunt two slots where possible; older hunts get the surplus.

    With one worker, the minimum becomes one. With three workers, two
    hunts receive 2/1 and a third waits. Rebalance only between shards.
    """
    remaining = worker_count
    minimum = min(2, worker_count)
    quotas = {hunt: 0 for hunt in hunts}
    for hunt in hunts:
        if remaining == 0:
            break
        allotted = min(minimum, remaining)
        quotas[hunt] = allotted
        remaining -= allotted
    if remaining and hunts:
        quotas[hunts[0]] += remaining
    return quotas


def _pool_keys(settings):
    pool = settings.hunt_worker_pool
    if not pool or any(
        char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-" for char in pool
    ):
        raise ValueError("PLUGIN_HUNT_WORKER_POOL must contain only letters, digits, '-' or '_'")
    return f"retrohunt:pool:{pool}:hunts", f"retrohunt:pool:{pool}:slots"


def _reserve_worker(redis_client, hunt_id, token, settings):
    """Atomically enforce job quotas using expiring Redis reservations."""
    active, slots = _pool_keys(settings)
    lua = """
    redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', ARGV[1])
    local hunts = redis.call('ZRANGE', KEYS[1], 0, -1)
    for _, hunt in ipairs(hunts) do
      if redis.call('EXISTS', hunt) == 0 or redis.call('EXISTS', 'retrohunt:' .. hunt .. ':cancel') == 1 then
        redis.call('ZREM', KEYS[1], hunt)
      end
    end
    hunts = redis.call('ZRANGE', KEYS[1], 0, -1)
    local count = tonumber(ARGV[2])
    local baseline = math.min(2, count)
    local remaining = count
    local allowed = 0
    for _, hunt in ipairs(hunts) do
      local q = math.min(baseline, remaining)
      remaining = remaining - q
      if hunt == ARGV[3] then allowed = q end
    end
    if #hunts > 0 and hunts[1] == ARGV[3] then allowed = allowed + remaining end
    if allowed == 0 then return 0 end
    local current = 0
    for _, item in ipairs(redis.call('ZRANGE', KEYS[2], 0, -1)) do
      if string.sub(item, 1, string.len(ARGV[3]) + 1) == ARGV[3] .. ':' then
        current = current + 1
      end
    end
    if current >= allowed or redis.call('ZCARD', KEYS[2]) >= count then return 0 end
    redis.call('ZADD', KEYS[2], ARGV[4], ARGV[3] .. ':' .. ARGV[5])
    return 1
    """
    now = time()
    return bool(
        redis_client.eval(
            lua,
            2,
            active,
            slots,
            now,
            settings.hunt_worker_count,
            hunt_id,
            now + settings.hunt_shard_lease_seconds,
            token,
        )
    )


def register_submitted_hunt(redis_client, hunt_id, settings):
    """Advertise a submitted hunt before any worker is free to initialise it.

    This must not wait for the ordinary consumer group: all workers may be busy
    running shards and the group's backlog can contain older shard messages.
    Registration is idempotent and is performed only for live, submitted hunts.
    """
    raw = redis_client.get(hunt_id)
    if raw is None or redis_client.exists(_key(hunt_id, "cancel")):
        return False
    event = azm.RetrohuntEvent.model_validate_json(raw)
    if event.entity.status in {azm.HuntState.COMPLETED, azm.HuntState.FAILED, azm.HuntState.CANCELLED}:
        return False
    active, _ = _pool_keys(settings)
    # Score is the submission timestamp (not the time a worker picked up the
    # message), preserving FIFO ordering when multiple hunts arrive together.
    submitted = event.entity.submitted_time
    score = submitted.timestamp() if submitted is not None else time()
    added = redis_client.zadd(active, {hunt_id: score}, nx=True)
    if added:
        logger.info(
            "Registered pending hunt %s for fair worker allocation (pool=%s)", hunt_id, settings.hunt_worker_pool
        )
    return bool(added)


def watch_hunt_submissions(redis_client, settings, service, stop):
    """Watch the stream independently of the busy shard consumer loop.

    XREAD (not XREADGROUP) observes submissions without consuming or ACKing
    their messages. Any worker can continue the expensive manifest setup later.
    A separate watcher on each worker is safe because registration uses ZADD NX.
    """
    stream = service.RETROHUNT_JOB
    # Replay a bounded recent tail so restarts can observe queued submissions
    # without scanning an unbounded historical stream on every worker boot.
    cursor = "0-0"
    try:
        recent = redis_client.xrevrange(stream, count=500)
        if recent:
            cursor = recent[0][0]
            for _, payload in reversed(recent):
                action = payload.get(b"action", payload.get("action"))
                if action in (b"Submitted", "Submitted"):
                    raw_id = payload.get(b"hunt_id", payload.get("hunt_id"))
                    if raw_id is not None:
                        register_submitted_hunt(redis_client, _text(raw_id), settings)
    except Exception:
        logger.exception("Initial hunt-admission scan failed")
    while not stop.is_set():
        try:
            events = redis_client.xread({stream: cursor}, count=100, block=1000)
            for _, messages in events:
                for message_id, payload in messages:
                    cursor = message_id
                    if payload.get(b"action", payload.get("action")) not in (b"Submitted", "Submitted"):
                        continue
                    raw_id = payload.get(b"hunt_id", payload.get("hunt_id"))
                    if raw_id is not None:
                        register_submitted_hunt(redis_client, _text(raw_id), settings)
        except Exception:
            logger.exception("Hunt admission watcher failed; retrying")
            stop.wait(2)


def _release_worker(redis_client, hunt_id, token, settings):
    _, slots = _pool_keys(settings)
    redis_client.zrem(slots, f"{hunt_id}:{token}")


def _defer_shard(redis_client, hunt_id, shard_id, msg_id, settings, service):
    """ACK an over-quota stream item only after saving its durable queue entry."""
    queue = f"retrohunt:pool:{settings.hunt_worker_pool}:waiting"
    with redis_client.pipeline(transaction=True) as pipe:
        pipe.zadd(queue, {f"{hunt_id}:{shard_id}": time()}, nx=True)
        pipe.xack(service.RETROHUNT_JOB, service.RETROHUNT_GROUP, msg_id)
        pipe.execute()


def pump_waiting(redis_client, settings, service):
    """Reissue one deferred shard when a worker looks for more work.

    If admission is still unavailable the consumer safely defers it again.
    No executing shard is interrupted or forcibly reassigned.
    """
    queue = f"retrohunt:pool:{settings.hunt_worker_pool}:waiting"
    active, slots = _pool_keys(settings)
    lua = """
    redis.call('ZREMRANGEBYSCORE', KEYS[4], '-inf', ARGV[1])
    local hunts = redis.call('ZRANGE', KEYS[3], 0, -1)
    local capacity = tonumber(ARGV[2])
    local baseline = math.min(2, capacity)
    local quotas, remaining = {}, capacity
    for _, hunt in ipairs(hunts) do
      local allocation = math.min(baseline, remaining)
      quotas[hunt] = allocation
      remaining = remaining - allocation
    end
    if #hunts > 0 then quotas[hunts[1]] = quotas[hunts[1]] + remaining end
    if redis.call('ZCARD', KEYS[4]) >= capacity then return 0 end
    for _, item in ipairs(redis.call('ZRANGE', KEYS[1], 0, -1)) do
      local hunt, shard = string.match(item, '^([^:]+):([0-9]+)$')
      if not hunt or not quotas[hunt] or redis.call('EXISTS', hunt) == 0 or
         redis.call('EXISTS', 'retrohunt:' .. hunt .. ':cancel') == 1 then
        redis.call('ZREM', KEYS[1], item)
      else
        local in_use = 0
        for _, slot in ipairs(redis.call('ZRANGE', KEYS[4], 0, -1)) do
          if string.sub(slot, 1, string.len(hunt) + 1) == hunt .. ':' then
            in_use = in_use + 1
          end
        end
        if in_use < quotas[hunt] then
          redis.call('ZREM', KEYS[1], item)
          redis.call('XADD', KEYS[2], '*', 'hunt_id', hunt,
                     'action', 'Shard', 'shard', shard)
          return 1
        end
      end
    end
    return 0
    """
    redis_client.eval(lua, 4, queue, service.RETROHUNT_JOB, active, slots, time(), settings.hunt_worker_count)


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
        cached, fetched = state.get("cache_hits", 0), state.get("cache_downloads", 0)
        return (
            f"Shard {number}: {_progress_bar(1, 1)} Completed | {count} indexes "
            f"({cached} cached, {fetched} downloaded) | {matches} matches"
        )
    if status == "failed":
        error = str(state.get("error") or "Unknown error").replace("\n", " ")[:160]
        return f"Shard {number}: FAILED | {count} indexes | {error}"
    if status == "retrying":
        return f"Shard {number}: Retry pending | {count} indexes"
    if status == "downloading":
        done = downloaded.get("done", 0)
        total = downloaded.get("total", count)
        cached = state.get("cache_hits", 0)
        return (
            f"Shard {number}: {_progress_bar(done, total)} Downloading indexes "
            f"({done:.1f}/{total} transferred; {cached} cache hits)"
        )
    if status == "preparing":
        cached = state.get("cache_hits", 0)
        return f"Shard {number}: Preparing indexes | {cached} verified cache hits / {count} indexes"
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
        self.cache_hit_callback = None

    def list_indexes(self):
        """Return only the immutable index IDs assigned to this shard."""
        return list(self._assigned_index_ids)

    def iter_search_batches(self):
        """Use retained local indexes for only the IDs assigned to this shard.

        Per-shard downloads retain parallel fetching and SHA verification. We do
        not prefetch a second batch because a single file may exceed half the
        cache budget; distributed workers provide inter-shard concurrency.
        """
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        lock_path = self.cache_dir / ".batch-search.lock"
        with lock_path.open("a+b") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            try:
                # Clean up interrupted searches while the PVC lock is held.
                for partial in self.cache_dir.glob(".*.tmp"):
                    if partial.is_file():
                        partial.unlink()
                for orphan in self.cache_dir.glob(".hunt-batch-*"):
                    if orphan.is_dir() and not orphan.is_symlink():
                        shutil.rmtree(orphan)
                ids = self.list_indexes()
                offset = 0
                while offset < len(ids):
                    callback = self.progress_callback or (lambda *_: None)
                    prepared = self._prepare_batch(ids, offset, callback, self.cache_hit_callback)
                    try:
                        logger.info(
                            "Shard index preparation: %d/%d ready; %d cache hits, %d downloads",
                            offset + prepared.batch_count,
                            len(ids),
                            self.cache_hits,
                            self.cache_downloads,
                        )
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
            # Registration and shard publication must be atomic.
            active, _ = _pool_keys(settings)
            pipe.zadd(
                active,
                {hunt_id: (current.entity.submitted_time.timestamp() if current.entity.submitted_time else time())},
                nx=True,
            )
            pipe.set(_key(hunt_id, "pool"), settings.hunt_worker_pool)
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
                if terminal:
                    pool = redis_client.get(_key(hunt_id, "pool"))
                    if pool is not None:
                        pipe.zrem(f"retrohunt:pool:{_text(pool)}:hunts", hunt_id)
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


def _heartbeat(
    redis_client, lease_key, token, stream, group, worker_id, msg_id, stop, interval, ttl, hunt_id, settings
):
    script = "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('EXPIRE',KEYS[1],ARGV[2]) end return 0"
    while not stop.wait(interval):
        try:
            if not redis_client.eval(script, 1, lease_key, token, ttl):
                return
            # Slot expires with the same TTL if the pod dies unexpectedly.
            _, slots = _pool_keys(settings)
            redis_client.zadd(slots, {f"{hunt_id}:{token}": time() + ttl}, xx=True)
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
    # A worker that finishes a shard can switch jobs; running shards never move.
    if not _reserve_worker(redis_client, hunt_id, token, settings):
        logger.info(
            "Worker %s deferring hunt %s shard %d: current fair-share quota is full", worker_id, hunt_id, shard_id + 1
        )
        _defer_shard(redis_client, hunt_id, shard_id, msg_id, settings, service)
        return
    logger.info("Worker %s admitted to hunt %s shard %d", worker_id, hunt_id, shard_id + 1)
    if not redis_client.set(lease_key, token, nx=True, ex=settings.hunt_shard_lease_seconds):
        # Another pod is working on this shard; leave the entry pending.
        _release_worker(redis_client, hunt_id, token, settings)
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
            hunt_id,
            settings,
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
        state["cache_hits"] = 0

        def report_cache_hit(index_offset, size):
            """Record verified local reuse; never label this as a network download."""
            with publish_lock:
                state["cache_hits"] += 1
                logger.info(
                    "Hunt %s shard %d: cache HIT for index %d (%d bytes)",
                    hunt_id,
                    shard_id + 1,
                    index_offset + 1,
                    size,
                )
                if state["status"] != "downloading":
                    state["status"] = "preparing"
                _write_shard(redis_client, hunt_id, shard_id, token, state)

        def report_download(index_offset, received, expected):
            """Only real object-store byte transfers enter the download phase."""
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
        provider.cache_hit_callback = report_cache_hit

        def writer(job, _logs):
            if redis_client.get(_key(hunt_id, "cancel")):
                raise CancelException("Distributed hunt cancelled")
            with publish_lock:
                # Keep the download phase visible until BigGrep actually starts.
                if job.entity.status == azm.HuntState.SEARCHING_NARROW:
                    state["status"] = "narrow"
                elif job.entity.status == azm.HuntState.SEARCHING_WIDE:
                    state["status"] = "broad"
                elif state["status"] not in {"downloading", "preparing"}:
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
        # Preserve the actual cache/download counts in the shard's final snapshot.
        state["cache_hits"] = provider.cache_hits
        state["cache_downloads"] = provider.cache_downloads
        logger.info(
            "Worker %s finished hunt %s shard %d: %d verified cache hits, %d object-store downloads",
            worker_id,
            hunt_id,
            shard_id + 1,
            provider.cache_hits,
            provider.cache_downloads,
        )
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
        _release_worker(redis_client, hunt_id, token, settings)
        redis_client.eval(
            "if redis.call('GET',KEYS[1]) == ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0",
            1,
            lease_key,
            token,
        )
