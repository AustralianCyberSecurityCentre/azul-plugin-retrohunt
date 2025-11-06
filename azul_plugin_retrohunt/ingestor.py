"""Retrohunt Indexer.

Responsible for generating BigGrep indexes from incoming binary events.
"""

import logging
import os
import sys
import time
import traceback
from collections import deque
from datetime import timedelta

import pendulum
from azul_bedrock.models_network import BinaryAction
from azul_runner import BinaryPlugin, Job, State, add_settings, cmdline_run, settings
from prometheus_client import Counter, Gauge, start_http_server

from azul_plugin_retrohunt.bigyara.ingest import (
    BigYaraIngestor,
    IngestFileSizeException,
)
from azul_plugin_retrohunt.models import FileMetadata
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.ingestor")

log_root = logging.getLogger()
log_root.level = logging.INFO
log_root_handler = logging.StreamHandler(sys.stdout)
log_root_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)-7s- %(name)-20s - %(message)s", "%d/%m/%Y %H:%M:%S")
)
log_root.addHandler(log_root_handler)

prom_bytes_ingested = Counter("retrohunt_bytes_ingested", "Total bytes ingested by retrohunt")
prom_bytes_in_cache = Gauge("retrohunt_bytes_in_cache", "Total bytes in indexer cache", ["indexer"])


class RetrohuntIngestor(BinaryPlugin):
    """Retrohunt indexing plugin."""

    # FUTURE must not index binaries from sources that age off artifacts

    VERSION = "2024.06.18"
    NAME = "RetrohuntIngestor"
    SETTINGS = add_settings(
        require_historic=False,
        filter_allow_event_types=[BinaryAction.Sourced.value, BinaryAction.Extracted.value],
        filter_data_types={"content": []},  # Take everything and filter it at the index level.
        hash_cache_size=(int, 16_000),  # Number of hashes to store for de-duping.
    )

    def __init__(self, config: settings.Settings | dict = None) -> None:
        """Custom plugin config."""
        super().__init__(config)

        self.downloaded_streams = 0
        self.last_periodic_index_time = pendulum.now()

        print(os.environ.get("plugin_indexers"))
        self.retrohunt_settings = RetrohuntSettings()
        # Setup all the ingestors
        self.ingestors: list[BigYaraIngestor] = list()
        for _indexer_name, indexer_cfg in self.retrohunt_settings.indexers.items():
            new_ingestor = BigYaraIngestor(
                self.retrohunt_settings.root_path,
                indexer_cfg.name,
                indexer_cfg.max_bytes_before_indexing,
                indexer_cfg.stream_labels,
                indexer_cfg.periodic_index_frequency_min,
            )
            self.ingestors.append(new_ingestor)
            prom_bytes_in_cache.labels(new_ingestor._processor_name).set(new_ingestor.bytes_in_cache)

        # Cleanup any old ingest directories.
        for ingest in self.ingestors:
            ingest.cleanup_old_ingest_dirs()

        # LRU cache of seen hashes
        self.hash_cache: deque = RetrohuntIngestor._create_hash_cache(self.cfg.hash_cache_size)

    @staticmethod
    def _create_hash_cache(size: int):
        """Used to create the hash cache to simplify testing."""
        return deque([], size)

    def execute(self, job: Job) -> State:
        """Save an input file to index caches ready to be processed by BigGrep."""
        start = time.time()
        for data in job.get_all_data():
            logger.debug(f"Starting job '{data.file_info.sha256}' at {time.time() - start}")
            # check if LRU cache to see if hash already processed
            if data.file_info.sha256:
                skip: bool = False
                try:
                    hash_index = self.hash_cache.index(data.file_info.sha256)
                except ValueError:
                    pass
                else:
                    skip = True
                    del self.hash_cache[hash_index]
                self.hash_cache.appendleft(data.file_info.sha256)
                if skip:
                    logger.info("In cache, skipping.")
                    continue

            metadata: FileMetadata = FileMetadata(
                stream_label=data.file_info.label or "content", stream_source=job.event.source.name
            )
            # Skip a file is it has no stream label or stream source as it's invalid.
            if not metadata.stream_label or not metadata.stream_source:
                self.logger.warning(
                    f"Ignoring file {job.event.entity.sha256} as it has an invalid source "
                    + f"('{metadata.stream_source}') or invalid stream label ('{metadata.stream_label}')"
                )
                continue
            # The sample hash is different to the hash of indexed data for non-content streams.
            # This could be a label=network_capture, label=safe_png or label=assemblyline etc...
            if metadata.stream_label != "content":
                metadata.job_id = job.id
            try:
                raw_bytes = None
                for ingest in self.ingestors:
                    # Infrequently delete old ingest directories
                    if self.downloaded_streams > 10000:
                        self.completed_jobs = 0
                        logger.info("cleaning up and old ingest directories.")
                        ingest.cleanup_old_ingest_dirs()

                    if metadata.stream_label in ingest.stream_labels:
                        # FUTURE - filter on file type.
                        logger.debug(f"Saving file {job.id} to cache for ingestor {ingest._processor_name}")
                        # If the file has already been loaded into raw_bytes for one ingestor it doesn't need to be
                        # loaded again.
                        if raw_bytes is None:
                            with data.get_tempfile() as temp_file:
                                raw_bytes = temp_file.read()
                        # If there is no binary content don't add the file
                        if not raw_bytes:
                            self.logger.warning(
                                f"Ignoring file {job.event.entity.sha256} as it's content length is zero"
                            )
                            break
                        try:
                            added_data = ingest.add_data_to_index_cache(raw_bytes, metadata)
                            if added_data:
                                prom_bytes_ingested.inc(len(raw_bytes))
                                prom_bytes_in_cache.labels(ingest._processor_name).set(ingest.bytes_in_cache)
                            # Trigger periodic indexer and reset periodic trigger.
                            if (
                                ingest.periodic_index_frequency_min > 0
                                and pendulum.now()
                                >= self.last_periodic_index_time
                                + timedelta(minutes=ingest.periodic_index_frequency_min)
                            ):
                                ingest.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)
                                self.last_periodic_index_time = pendulum.now()
                        except IngestFileSizeException as e:
                            logger.info(
                                f"The ingestor '{ingest._processor_name}' could not ingest the job with id '{job.id}'"
                                + f" because it's content was too big or too small, with error message {e}"
                            )
                        logger.info(f"Successfully saved file {job.id} to cache.")
                        self.downloaded_streams += 1

            except Exception as ex:
                logger.info(ex)
                logger.info(traceback.format_exc())


def main():
    """Run plugin via command-line."""
    settings = RetrohuntSettings()
    start_http_server(settings.prometheus_port_ingestor)
    cmdline_run(plugin=RetrohuntIngestor)


if __name__ == "__main__":
    main()
