"""A simple synchronous worker for running BigYara retrohunts."""

import logging
import os
import sys
from datetime import datetime
from io import StringIO
from time import sleep

import pendulum
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from prometheus_client import Counter, Summary, start_http_server

from azul_plugin_retrohunt.bigyara.search import QueryTypeEnum, SearchPhaseEnum, search
from azul_plugin_retrohunt.settings import BGI_DIR_NAME, RetrohuntSettings

prom_jobs_run = Counter("retrohunt_worker_jobs_run", "Total jobs run by prometheus and their final status", ["status"])
prom_worker_runtime = Summary("retrohunt_worker_runtime", "Total runtime for a workers run.")

PLUGIN_NAME = "RetroHunter"
PLUGIN_VERSION = "2025.10.10"
DISPATCHER_EVENT_WAIT_TIME_SECONDS = 10

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

    tracked_loggers: list[logging.Logger] = [logging.getLogger("retrohunt.worker"), logging.getLogger("bigyara")]

    for logger in tracked_loggers:
        logger.setLevel(level)
        logger.addHandler(log_handler)
    return logs


def _update_progress(job: azm.RetrohuntEvent, logs: StringIO) -> azm.RetrohuntEvent:
    """Update with latest job status and publish."""
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
    dp.submit_events(events=[job], model=azm.ModelType.Retrohunt)
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

        search(search_query, search_enum_type, index_dirs, get_data_from_azul, update_job, recursive=True)

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


def main():
    """Start the retrohunt worker."""
    global dp
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
        # this code doesn't handle events 'actively' so use passive mode
        _, events = dp.get_generic_events(
            model="retrohunt", is_task=False, count=1, require_live=True, deadline=DISPATCHER_EVENT_WAIT_TIME_SECONDS
        )

        if events:
            job = azm.RetrohuntEvent(**events[0])
            if job.action != azm.RetrohuntEvent.RetrohuntAction.Submitted:
                # can't filter these actions on dispatcher so we do it here
                # retrohunt is low-rate so this should be fine
                continue
            bgi_folders = []
            for _name, indexer_cfg in settings.indexers.items():
                path_to_bgi_folder = os.path.join(settings.root_path, indexer_cfg.name, BGI_DIR_NAME)
                bgi_folders.append(path_to_bgi_folder)

            with prom_worker_runtime.time():
                hunt(bgi_folders, job, logs)
        else:
            sleep(15)
            logger.debug("No events waiting. Retrying...")


if __name__ == "__main__":
    main()
