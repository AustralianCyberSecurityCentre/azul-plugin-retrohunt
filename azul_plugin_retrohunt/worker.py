"""A simple synchronous worker for running BigYara retrohunts."""

import json
import logging
import os
import socket
import sys
import threading
from datetime import datetime
from io import StringIO
from time import sleep

import pendulum
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from prometheus_client import Counter, Summary, start_http_server

from azul_plugin_retrohunt.bigyara.search import QueryTypeEnum, SearchPhaseEnum, search
from azul_plugin_retrohunt.redis import get_redis
from azul_plugin_retrohunt.settings import BGI_DIR_NAME, RetrohuntSettings

prom_jobs_run = Counter(
    "retrohunt_worker_jobs_run",
    "Total jobs run by prometheus and their final status",
    ["status"],
)
prom_worker_runtime = Summary("retrohunt_worker_runtime", "Total runtime for a workers run.")

PLUGIN_NAME = "RetroHunter"
PLUGIN_VERSION = "2025.10.10"
DISPATCHER_EVENT_WAIT_TIME_SECONDS = 10
# hunt job lock is 6 hours
LOCK_TTL = 21600000
MATCH_LIMIT = 200

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
    redis = get_redis()
    job.timestamp = pendulum.now()
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
    redis.set(job.entity.id, json.dumps(job.model_dump()), ex=redis.REDIS_EXPIRATION)
    # dp.submit_events(events=[job], model=azm.ModelType.Retrohunt)
    return job


def hunt(index_dirs: list[str], job: azm.RetrohuntEvent, logs: StringIO):
    """Execute the given retrohunt."""
    match_metadata: MatchMetadata = {}
    last_update: datetime = None

    # clear logs
    if logs:
        logs.truncate(0)
        logs.seek(0)

    def update_job(phase: int, done: int, total: int, new_match: tuple[str, list[str | bytes]]):
        nonlocal job

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

                # convert config to string dict.
                match_result_dict: dict[str, str] = {}
                match_result_dict["stream_label"] = match_metadata[new_match[1][0]][b"stream_label"].decode()
                match_result_dict["stream_source"] = match_metadata[new_match[1][0]][b"stream_source"].decode()
                # if sample isn't set, use the hash generated for the filename
                if b"sample" in match_metadata[new_match[1][0]]:
                    match_result_dict["sample"] = match_metadata[new_match[1][0]][b"sample"].decode()
                else:
                    match_result_dict["sample"] = new_match[1][0].split("/")[-1]

                if new_match[0] not in job.entity.results:
                    job.entity.results[new_match[0]] = []
                job.entity.results[new_match[0]].append(match_result_dict)

                # cancel if the number of matches has exceeded the limit.
                if job.entity.tool_match_count >= MATCH_LIMIT:
                    job.entity.status = azm.HuntState.CANCELLED
                    raise Exception(
                        f"Match count hit threshold of {MATCH_LIMIT}. "
                        "Please try to refine your search terms to match less content."
                    )
        # try not to spam update messages
        if last_update is None or (pendulum.now() - last_update).seconds >= 1:
            job.action = azm.RetrohuntEvent.RetrohuntAction.Running
            job = _update_progress(job, logs)

    def get_data_from_azul(match_path: str, config: dict[bytes, bytes]) -> bytes:
        data: bytes = None
        match_hash: str = match_path.split("/")[-1]

        configd = {x.decode(): y.decode() for x, y in config.items()}

        label = configd.get("stream_label")
        source = configd.get("stream_source")
        if not label or not source:
            logger.error(f"Failed to retrieve metadata label and/or source for {match_hash}: {configd}")
            return None

        try:
            response = dp.get_binary(source=source, label=label, sha256=match_hash)
        except dispatcher.DispatcherApiException:
            pass
        else:
            data = response.content
            match_metadata[match_path] = config
        return data

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
        if search_type_str == "Yara":
            search_enum_type = QueryTypeEnum.YARA

        elif search_type_str == "Suricata":
            search_enum_type = QueryTypeEnum.SURICATA
            # FUTURE should target just the PCAP index.
            # index_dirs = os.path.join(index_dirs, "pcap")
        else:
            raise Exception("Unknown search type.")

        search(
            search_query,
            search_enum_type,
            index_dirs,
            get_data_from_azul,
            update_job,
            recursive=True,
        )

        logger.info("Successfully completed job.")
        job.entity.status = azm.HuntState.COMPLETED
        prom_jobs_run.labels(azm.HuntState.COMPLETED.name).inc()
        logger.debug(job.entity)

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
        job.action = azm.RetrohuntEvent.RetrohuntAction.Completed
        job = _update_progress(job, logs)


def acquire_lock(redis_client, job_id: str, worker_id: str, ttl_seconds: int) -> bool:
    """Helper to aquire lock on retrohunt job."""
    lock_key = f"retrohunt:{job_id}:lock"
    return redis_client.set(lock_key, worker_id, nx=True, ex=ttl_seconds)


def start_heartbeat(job_id: str, worker_id: str, ttl_seconds: int, stop_event: threading.Event):
    """Starts a background heartbeat thread that periodically refreshes the lock TTL.

    The heartbeat stops when stop_event is set.
    """
    redis = get_redis()
    lock_key = f"retrohunt:{job_id}:lock"
    refresh_interval = ttl_seconds // 3  # refresh every 1/3 of TTL

    def beat():
        while not stop_event.is_set():
            # Check if we still own the lock
            current_owner = redis.client.get(lock_key)
            if current_owner != worker_id:
                # Lost the lock — stop heartbeating
                return

            # Refresh TTL
            redis.client.expire(lock_key, ttl_seconds)

            # Sleep until next refresh or until stop_event is set
            stop_event.wait(refresh_interval)

    thread = threading.Thread(target=beat, daemon=True)
    thread.start()
    return thread


def main():
    """Start the retrohunt worker."""
    redis = get_redis()
    global dp
    worker_id = f"{socket.gethostname()}-{os.getpid()}"
    logs: StringIO = capture_logs(logging.INFO)
    settings = RetrohuntSettings()
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

    # poll for retrohunt submissions to work on
    while True:
        # Claim any stale jobs first
        stream, messages = redis.xautoclaim(
            "retrohunt-jobs",
            "retrohunt-workers",
            worker_id,
            min_idle_time=LOCK_TTL * 1000,
            start_id="0-0",
            count=1,
        )

        if messages:
            msg_id, payload = messages[0]
        else:
            # no stale jobs, read new ones
            events = redis.xreadgroup(
                groupname="retrohunt-workers",
                consumername=worker_id,
                streams={"retrohunt-jobs": ">"},
                count=1,
                block=5000,
            )

            if not events:
                sleep(15)
                logger.debug("No events waiting. Retrying...")
                continue

            # Redis Streams structure: [(stream_name, [(msg_id, payload_dict)])]

            _, msgs = events[0]
            msg_id, payload = msgs[0]

        # Load the full event from Redis
        event_json = redis.get(payload["hunt_id"])
        if not event_json:
            raise RuntimeError(f"Missing event data for hunt_id={payload['hunt_id']}")

        job = azm.RetrohuntEvent(**json.loads(event_json))

        job_id = job.entity.id
        if job.action != azm.RetrohuntEvent.RetrohuntAction.Submitted:
            continue

        if not acquire_lock(redis.client, job_id, worker_id, ttl_seconds=LOCK_TTL):
            # Another worker is running this hunt
            continue

        # 3. Start heartbeat
        stop_event = threading.Event()
        start_heartbeat(job_id, worker_id, ttl_seconds=LOCK_TTL, stop_event=stop_event)

        bgi_folders = []
        for _name, indexer_cfg in settings.indexers.items():
            path_to_bgi_folder = os.path.join(settings.root_path, indexer_cfg.name, BGI_DIR_NAME)
            bgi_folders.append(path_to_bgi_folder)

        try:
            with prom_worker_runtime.time():
                hunt(bgi_folders, job, logs)
            # Acknowledge the message
            redis.xack("retrohunt-jobs", "retrohunt-workers", msg_id)
        finally:
            stop_event.set()
            redis.client.delete(f"retrohunt:{job_id}:lock")


if __name__ == "__main__":
    main()
