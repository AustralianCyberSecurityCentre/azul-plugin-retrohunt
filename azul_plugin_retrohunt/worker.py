"""A simple synchronous worker for running BigYara retrohunts."""

import json
import logging
import os
import socket
import sys
import threading
import uuid
from io import StringIO
from time import monotonic, sleep

import pendulum
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from prometheus_client import Counter, Summary, start_http_server
from redis.exceptions import ResponseError, WatchError

from azul_plugin_retrohunt.bigyara.search import (
    QueryTypeEnum,
    SearchPhaseEnum,
    clear_stop_event,
    release_unused_memory,
    search,
    trigger_stop_event,
)
from azul_plugin_retrohunt.retrohunt import CancelException, FatalException, RetrohuntService
from azul_plugin_retrohunt.settings import BGI_DIR_NAME, RetrohuntSettings

prom_jobs_run = Counter(
    "retrohunt_worker_jobs_run",
    "Total jobs run by prometheus and their final status",
    ["status"],
)
prom_worker_runtime = Summary("retrohunt_worker_runtime", "Total runtime for a workers run.")

PLUGIN_NAME = "RetroHunter"
PLUGIN_VERSION = "2026.07.23"
DISPATCHER_EVENT_WAIT_TIME_SECONDS = 10
MATCH_LIMIT = 200
CANCELLATION_CHECK_INTERVAL_SECONDS = 0.5

dp: dispatcher.DispatcherAPI = None

# hash => metadata
MatchMetadata = dict[str, dict[bytes, bytes]]

logger = logging.getLogger("retrohunt.worker")

log_root = logging.getLogger()
log_root.level = logging.INFO
log_root_handler = logging.StreamHandler(sys.stdout)
log_root_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)-7s- %(name)-20s - %(message)s", "%d/%m/%Y %H:%M:%S")
)
log_root.addHandler(log_root_handler)

MAX_LOG_CHARS = 1024 * 500  # Assuming each char is worth a byte (utf-8) - max of 500kB of logs

rs = RetrohuntService()


def check_is_cancelled(job_id: str):
    """Raise CancelledException if the hunt is cancelled."""
    raw = rs.redis.get(job_id)
    if not raw:
        return  # treat missing as not cancelled

    try:
        event = azm.RetrohuntEvent(**json.loads(raw))
    except Exception:
        return  # corrupted or missing, not considered cancelled

    if event.entity.status == azm.HuntState.CANCELLED:
        trigger_stop_event()
        raise CancelException(f"Hunt {job_id} cancelled by user")


def capture_logs(level: int = logging.INFO) -> StringIO:
    """Return a StringIO that will capture relevant logs."""
    log_format = "%(asctime)s %(message)s"
    log_date_format = "%d/%m/%Y %H:%M:%S"

    logging.basicConfig(
        stream=sys.stderr,
        level=level,
        format=log_format,
        datefmt=log_date_format,
    )

    logs: StringIO = StringIO()
    log_handler = logging.StreamHandler(logs)
    log_handler.setFormatter(logging.Formatter(log_format, log_date_format))

    tracked_loggers: list[logging.Logger] = [
        logging.getLogger("retrohunt.worker"),
        logging.getLogger("bigyara"),
    ]

    for logger in tracked_loggers:
        logger.setLevel(level)
        logger.addHandler(log_handler)
    return logs


def _update_progress(job: azm.RetrohuntEvent, logs: StringIO) -> azm.RetrohuntEvent:
    """Update with latest job status and publish."""
    job.timestamp = pendulum.now()

    if job.action == azm.RetrohuntEvent.RetrohuntAction.Running:
        if not job.entity.processing_start:
            job.entity.processing_start = job.timestamp

    if job.entity.processing_start:
        start = pendulum.instance(job.entity.processing_start)
        end = pendulum.instance(job.timestamp)
        job.entity.duration = (end - start).total_seconds()

    if logs:
        logs.seek(0, os.SEEK_END)
        log_total_chars = logs.tell()
        # We have too many logs. - drop all early logs
        if log_total_chars > MAX_LOG_CHARS:
            # Note we actually drop slightly more logs because this line is appended to the logs.
            logger.warning(
                f"Dropping {log_total_chars - MAX_LOG_CHARS}/{log_total_chars} chars of the oldest logs because there "
                + "is too many."
            )
            logs.seek(0)
            logs.write(logs.getvalue()[-MAX_LOG_CHARS:])
            logs.truncate(MAX_LOG_CHARS)
            # Jump to end again
            logs.seek(0, os.SEEK_END)
        job.entity.logs = logs.getvalue()
    serialized_job = json.dumps(job.model_dump())

    # Do not overwrite a cancellation written by the API between progress
    # updates. WATCH makes the read/check/write atomic with respect to changes.
    while True:
        try:
            with rs.redis.pipeline() as pipe:
                pipe.watch(job.entity.id)
                current_raw = pipe.get(job.entity.id)

                if current_raw and job.entity.status != azm.HuntState.CANCELLED:
                    try:
                        current_event = azm.RetrohuntEvent(**json.loads(current_raw))
                    except Exception:
                        current_event = None

                    if current_event and current_event.entity.status == azm.HuntState.CANCELLED:
                        pipe.unwatch()
                        trigger_stop_event()
                        raise CancelException(f"Hunt {job.entity.id} cancelled by user")

                pipe.multi()
                pipe.set(job.entity.id, serialized_job)
                pipe.execute()
                break
        except WatchError:
            # The API or another process changed the job while we were writing.
            # Re-read it and preserve cancellation if that was the change.
            continue

    return job


def hunt(index_dirs: list[str], job: azm.RetrohuntEvent, logs: StringIO):
    """Execute the given retrohunt."""
    match_metadata: MatchMetadata = {}
    last_update: float | None = None
    last_cancel_check = 0.0
    cancel_check_lock = threading.Lock()

    def periodic_check_is_cancelled(force: bool = False) -> None:
        """Throttle Redis cancellation checks across narrow-phase threads."""
        nonlocal last_cancel_check

        now = monotonic()
        if not force and now - last_cancel_check < CANCELLATION_CHECK_INTERVAL_SECONDS:
            return

        with cancel_check_lock:
            now = monotonic()
            if not force and now - last_cancel_check < CANCELLATION_CHECK_INTERVAL_SECONDS:
                return

            check_is_cancelled(job.entity.id)
            last_cancel_check = now

    # clear logs
    if logs:
        logs.truncate(0)
        logs.seek(0)

    def update_job(phase: int, done: int, total: int, new_match: tuple[str, list[str | bytes]]):
        nonlocal job, last_update
        periodic_check_is_cancelled()

        if phase == SearchPhaseEnum.ATOM_PARSE:
            job.entity.status = azm.HuntState.PARSING_RULES
            job.entity.rules_parsed_total = total
            job.entity.rules_parsed_done = done
            if new_match:
                job.entity.atom_count += len(new_match[1])
        elif phase == SearchPhaseEnum.BROAD_PHASE:
            job.entity.status = azm.HuntState.SEARCHING_WIDE
            job.entity.index_searches_total = total
            job.entity.index_searches_done = done
            if new_match:
                job.entity.index_match_count += len(new_match[1])
        elif phase == SearchPhaseEnum.NARROW_PHASE:
            job.entity.status = azm.HuntState.SEARCHING_NARROW
            job.entity.tool_matches_total = total
            job.entity.tool_matches_done = done

            # we know that there will only be one match at a time.
            if new_match and len(new_match[1]) == 1:
                job.entity.tool_match_count += 1

                match_path = new_match[1][0]
                metadata = match_metadata[match_path]
                sample = metadata.get(b"sample")
                match_result_dict = {
                    "stream_label": metadata[b"stream_label"].decode(),
                    "stream_source": metadata[b"stream_source"].decode(),
                    "sample": sample.decode() if sample is not None else match_path.rsplit("/", 1)[-1],
                }

                job.entity.results.setdefault(new_match[0], []).append(match_result_dict)

                # Stop the search immediately when the result limit is
                # reached. Setting the shared event before raising ensures
                # in-flight narrow workers abort and release their file buffers
                # instead of continuing to scan the remainder of the batch.
                if job.entity.tool_match_count >= MATCH_LIMIT:
                    job.entity.status = azm.HuntState.CANCELLED
                    trigger_stop_event()
                    raise Exception(
                        f"Match count hit threshold of {MATCH_LIMIT}. "
                        "Please try to refine your search terms to match less content."
                    )
        # try not to spam update messages
        now = monotonic()
        if last_update is None or now - last_update >= 1.0:
            job.action = azm.RetrohuntEvent.RetrohuntAction.Running
            job = _update_progress(job, logs)
            last_update = now

    def get_data_from_azul(match_path: str, config: dict[bytes, bytes]) -> bytes:
        periodic_check_is_cancelled()
        data: bytes = None
        response = None
        match_hash = match_path.rsplit("/", 1)[-1]

        if not config:
            logger.error("Missing index metadata for %s", match_hash)
            return None

        label_raw = config.get(b"stream_label")
        source_raw = config.get(b"stream_source")

        if not label_raw or not source_raw:
            logger.error(
                "Failed to retrieve metadata label and/or source for %s: %s",
                match_hash,
                config,
            )
            return None

        label = label_raw.decode()
        source = source_raw.decode()

        try:
            response = dp.get_binary(source=source, label=label, sha256=match_hash)
            data = response.content

            # This entry now exists only while the file is in flight. The
            # search layer removes it immediately after all rule callbacks for
            # this file have completed.
            match_metadata[match_path] = config
        except dispatcher.DispatcherApiException:
            pass
        finally:
            close_response = getattr(response, "close", None)
            if close_response is not None:
                close_response()
            response = None

        # The API may have cancelled the hunt while get_binary was blocked.
        periodic_check_is_cancelled()
        return data

    def release_data_from_azul(match_path: str, _matched: bool) -> None:
        """Release per-file metadata once its progress callbacks are complete."""
        match_metadata.pop(match_path, None)

    try:
        # add path info to job
        logger.info(f"Executing retrohunt {job.entity.id}")

        job.entity.status = azm.HuntState.STARTING
        job.action = azm.RetrohuntEvent.RetrohuntAction.Starting
        job.entity.results = {}
        job = _update_progress(job, logs)
        search_type_str = job.entity.search_type
        search_query: str = job.entity.search

        # convert from string to enum
        search_enum_type: int = -1

        # convert from string to enum
        if search_type_str == "Yara":
            search_enum_type = QueryTypeEnum.YARA

        elif search_type_str == "Suricata":
            search_enum_type = QueryTypeEnum.SURICATA
            # FUTURE should target just the PCAP index.
            # index_dirs = os.path.join(index_dirs, "pcap")
        else:
            raise Exception("Unknown search type.")

        periodic_check_is_cancelled(force=True)

        search(
            search_query,
            search_enum_type,
            index_dirs,
            get_data_from_azul,
            update_job,
            recursive=True,
            data_release_callback=release_data_from_azul,
        )

        periodic_check_is_cancelled(force=True)
        logger.info("Successfully completed job.")
        job.entity.status = azm.HuntState.COMPLETED
        prom_jobs_run.labels(azm.HuntState.COMPLETED.name).inc()
        logger.debug(job.entity)
    except CancelException as ex:
        trigger_stop_event()
        job.entity.status = azm.HuntState.CANCELLED
        prom_jobs_run.labels(azm.HuntState.CANCELLED.name).inc()
        logger.info("Hunt cancelled: %s", ex)
        raise
    except Exception as ex:
        exception_str = str(repr(ex))
        if ex.__cause__:
            exception_str += f": {str(repr(ex.__cause__))}"
        if job.entity.status == azm.HuntState.CANCELLED:
            prom_jobs_run.labels(azm.HuntState.CANCELLED.name).inc()
            logger.warning(f"Job cancelled: {exception_str}")
        else:
            logger.warning(f"Job failed: {exception_str}")
            prom_jobs_run.labels(azm.HuntState.FAILED.name).inc()
            job.entity.status = azm.HuntState.FAILED
            job.entity.error = exception_str
    finally:
        try:
            job.action = azm.RetrohuntEvent.RetrohuntAction.Completed
            job = _update_progress(job, logs)
        finally:
            # Cleanup must not depend on the final Redis progress write
            # succeeding.
            match_metadata.clear()
            release_unused_memory()


def acquire_lock(redis_client, job_id: str, worker_id: str, ttl_seconds: int) -> bool:
    """Helper to aquire lock on retrohunt job."""
    lock_key = f"retrohunt:{job_id}:lock"
    return redis_client.set(lock_key, worker_id, nx=True, ex=ttl_seconds)


def start_heartbeat(job_id: str, worker_id: str, ttl_seconds: int, stop_event: threading.Event):
    """Starts a background heartbeat thread that periodically refreshes the lock TTL.

    The heartbeat stops when stop_event is set.
    """
    lock_key = f"retrohunt:{job_id}:lock"
    refresh_interval = ttl_seconds // 3  # refresh every 1/3 of TTL

    def beat():
        while not stop_event.is_set():
            # Check if we still own the lock
            current_owner = rs.redis.get(lock_key)

            if not current_owner or current_owner.decode() != worker_id:
                # Lost the lock — stop heartbeating
                return

            # Refresh TTL
            rs.redis.expire(lock_key, ttl_seconds)

            # Sleep until next refresh or until stop_event is set
            stop_event.wait(refresh_interval)

    thread = threading.Thread(target=beat, daemon=True)
    thread.start()
    return thread


def main():
    """Start the retrohunt worker."""
    global dp
    worker_id = f"{socket.gethostname()}-{os.getpid()}-{uuid.uuid4().hex}"
    logs: StringIO = capture_logs(logging.INFO)
    settings = RetrohuntSettings()
    LOCK_TTL = settings.redis.ttl
    exception_sleep = settings.redis.exception_wait
    start_http_server(settings.prometheus_port_worker)

    dp = dispatcher.DispatcherAPI(
        events_url=settings.events_url,
        data_url=settings.data_url,
        retry_count=10,  # High retry count as if dispatcher reboots we don't want to reboot too quickly.
        timeout=60,
        author_name=PLUGIN_NAME,
        author_version=PLUGIN_VERSION,
        deployment_key=settings.deployment_key,
    )
    prom_jobs_run.labels(azm.HuntState.COMPLETED.name)
    prom_jobs_run.labels(azm.HuntState.CANCELLED.name)
    prom_jobs_run.labels(azm.HuntState.FAILED.name)

    try:
        rs.redis.xgroup_create(rs.RETROHUNT_JOB, rs.RETROHUNT_GROUP, id="$", mkstream=True)
    except ResponseError as e:
        if "BUSYGROUP" in str(e):
            pass  # already exists
        else:
            raise

    # poll for retrohunt submissions to work on
    while True:
        try:
            # Claim any stale jobs first
            try:
                result = rs.redis.xautoclaim(
                    rs.RETROHUNT_JOB,
                    rs.RETROHUNT_GROUP,
                    worker_id,
                    min_idle_time=LOCK_TTL * 1000,  # min_idle_time is in milliseconds
                    start_id="0-0",
                    count=1,
                )

                # fakeredis returns 2 values, redis-py returns 3
                if len(result) == 3:
                    next_id, messages, deleted = result
                else:
                    # fakeredis doesn't support deleted entries
                    next_id, messages = result

            except ResponseError as e:
                if "NOGROUP" in str(e):
                    logger.info("Job stream or consumer group not created yet. Waiting...")
                    sleep(5)
                    continue
                raise

            if messages:
                msg_id, payload = messages[0]
            else:
                # no stale jobs, read new ones
                try:
                    events = rs.redis.xreadgroup(
                        groupname=rs.RETROHUNT_GROUP,
                        consumername=worker_id,
                        streams={rs.RETROHUNT_JOB: ">"},
                        count=1,
                        block=5000,
                    )
                except ResponseError as e:
                    if "NOGROUP" in str(e):
                        logger.info("Job stream or consumer group not created yet. Waiting...")
                        sleep(5)
                        continue
                    raise

                if not events:
                    sleep(15)
                    logger.debug("No events waiting. Retrying...")
                    continue

                # Redis Streams structure: [(stream_name, [(msg_id, payload_dict)])]

                _, msgs = events[0]
                msg_id, payload = msgs[0]

            # Load the full event from Redis
            event_json = rs.redis.get(payload[b"hunt_id"])
            if not event_json:
                logger.error(f"Missing or corrupted event data for hunt_id={payload[b'hunt_id']}. Skipping.")
                rs.redis.xack(rs.RETROHUNT_JOB, rs.RETROHUNT_GROUP, msg_id)
                continue

            job = azm.RetrohuntEvent(**json.loads(event_json))
            job_id = job.entity.id

            # these will be cleaned up by the cronjob later
            if job.entity.status in {
                azm.HuntState.COMPLETED,
                azm.HuntState.FAILED,
            }:
                rs.redis.xack(rs.RETROHUNT_JOB, rs.RETROHUNT_GROUP, msg_id)
                rs.redis.delete(f"retrohunt:{job_id}:lock")
                continue

            if not acquire_lock(rs.redis, job_id, worker_id, ttl_seconds=LOCK_TTL):
                # Another worker is running this hunt
                continue

            # Start heartbeat. It must be explicitly stopped after the hunt;
            # otherwise one sleeping thread can linger per completed job.
            heartbeat_stop_event = threading.Event()
            heartbeat_thread = start_heartbeat(
                job_id,
                worker_id,
                ttl_seconds=LOCK_TTL,
                stop_event=heartbeat_stop_event,
            )

            bgi_folders = []
            for _name, indexer_cfg in settings.indexers.items():
                path_to_bgi_folder = os.path.join(settings.root_path, indexer_cfg.name, BGI_DIR_NAME)
                bgi_folders.append(path_to_bgi_folder)

            try:
                # The search cancellation Event is module-global, so reset it
                # before every new hunt.
                clear_stop_event()

                # Check cancellation before starting work
                check_is_cancelled(job_id)

                with prom_worker_runtime.time():
                    hunt(bgi_folders, job, logs)
                # Acknowledge the message
                logger.info(f"Acknowledging job {rs.RETROHUNT_JOB} {rs.RETROHUNT_GROUP} {msg_id}")
                rs.redis.xack(rs.RETROHUNT_JOB, rs.RETROHUNT_GROUP, msg_id)
            except CancelException:
                logger.info(f"Finalising cancelled hunt {job_id}")
                rs.redis.xack(rs.RETROHUNT_JOB, rs.RETROHUNT_GROUP, msg_id)
                continue
            finally:
                clear_stop_event()
                heartbeat_stop_event.set()
                heartbeat_thread.join(timeout=1.0)
                rs.redis.delete(f"retrohunt:{job_id}:lock")
                release_unused_memory()
        # used by tests
        except FatalException:
            raise
        except Exception as e:
            logger.exception(f"[worker={worker_id}] worker error, sleeping {exception_sleep}s: {e}")
            sleep(exception_sleep)
            continue


if __name__ == "__main__":
    main()
