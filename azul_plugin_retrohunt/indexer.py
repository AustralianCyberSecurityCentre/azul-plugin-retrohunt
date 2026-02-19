"""Retrohunt Indexer.

Responsible for generating BigGrep indexes from incoming binary events.
"""

import logging
import sys
import time
import traceback

import click
from prometheus_client import Counter, Gauge, start_http_server
from pydantic.types import ByteSize

#from azul_plugin_retrohunt.bigyara.index import BigYaraIndexer
def get_bigyara_indexer():
    from azul_plugin_retrohunt.bigyara.index import BigYaraIndexer
    return BigYaraIndexer

from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.indexer")

log_root = logging.getLogger()
log_root.level = logging.INFO
log_root_handler = logging.StreamHandler(sys.stdout)
log_root_handler.setFormatter(
    logging.Formatter("%(asctime)s %(levelname)-7s- %(name)-20s - %(message)s", "%d/%m/%Y %H:%M:%S")
)
log_root.addHandler(log_root_handler)

prom_number_of_indexes_created = Counter(
    "retrohunt_bgis_created",
    "Total number of bgi indices that retrohunt indexer has created.",
    ["index", "type"],
)
prom_bgi_directory_bytes = Gauge(
    "retrohunt_indexer_bytes_in_bgi_directory",
    "Total bytes in bgi directory for a particular index.",
    ["index"],
)
PERIODIC_INDEX_NAME = "periodic"
SIZE_BASED_INDEX_NAME = "sizebased"


def run_indexer(
    index_root_path: str,
    periodic_folder_name: str,
    periodic_bgi_name: str,
    indexerSettings: RetrohuntSettings.Indexer,
):
    """Run an indexer of the provided type with the provided root_path."""
    # Future allow for multiple indexer types at once. - as long as the indexer isn't overworked this will save lots
    # of RAM/CPU allocations.
    indexer = get_bigyara_indexer()(
        index_root_path,
        indexerSettings.name,
        int(indexerSettings.max_bytes_before_indexing),
    )
    prom_number_of_indexes_created.labels(indexer._processor_name, PERIODIC_INDEX_NAME)
    prom_number_of_indexes_created.labels(indexer._processor_name, SIZE_BASED_INDEX_NAME)
    prom_bgi_directory_bytes.labels(indexer._processor_name).set(indexer.count_bytes_for_dir(indexer.bgi_directory))
    logger.info(
        f"Starting to run the indexer with path '{indexer.base_directory}' and max indexing size of "
        f"{indexerSettings.max_bytes_before_indexing.human_readable()}"
    )
    while True:
        index_occurred = False
        for path_to_index in indexer.get_folders_ready_for_indexing():
            bytes_being_indexed = ByteSize(indexer.count_bytes_for_dir(path_to_index)).human_readable()
            logger.info(
                f"Starting to index the directory {path_to_index} which has a content size of {bytes_being_indexed}"
            )
            start = time.time()
            try:
                index_occurred = True
                # Split the directory that will be indexed because it failed indexing last time.
                if (
                    indexer.has_dir_failed_to_index_before(path_to_index)
                    and indexerSettings.allow_splitting_and_deletion
                ):
                    indexer.split_or_delete_indexing_dir(path_to_index)
                    if not path_to_index.exists():
                        # FUTURE - raise a status message to dispatcher when this happens.
                        logger.error(
                            f"Skip indexing {path_to_index} because the directory was deleted while splitting."
                        )
                        continue
                # Save the name path of the directory we are trying to index in case retrohunt crashes mid indexing.
                indexer.save_indexing_dir(path_to_index)
                # Periodic indexing name or a split periodic index so override the name so it can be overridden.
                if periodic_folder_name in path_to_index.name:
                    indexer.generate_index(
                        path_to_index,
                        periodic_bgi_name,
                        indexerSettings.timeout_minutes,
                    )
                    prom_number_of_indexes_created.labels(indexer._processor_name, PERIODIC_INDEX_NAME).inc()
                # Normal indexing, file will be named based on time of indexing.
                else:
                    indexer.generate_index(path_to_index, None, indexerSettings.timeout_minutes)
                    prom_number_of_indexes_created.labels(indexer._processor_name, SIZE_BASED_INDEX_NAME).inc()
                # Clear the last indexed folder because we've succeeded and don't want to indicate this directory.
                # Failed to index potentially creating a bug.
                indexer.clear_indexing_dir()
                prom_bgi_directory_bytes.labels(indexer._processor_name).set(
                    indexer.count_bytes_for_dir(indexer.bgi_directory)
                )

                logger.info(f"Finished generating index, it took {time.time() - start:.2f}s")
            except Exception as ex:
                logger.warning(f"Incomplete index generation, it took {time.time() - start:.2f}s")
                logger.warning(ex)
                logger.warning(traceback.format_exc())
                # Stop this iteration and try again if there is an exception, to allow a retry of the failed directory.
                # This will also trigger deletion if the directory has failed to be indexed multiple times.
                break

        if indexerSettings.run_once is True:
            break
        # Sleep for 10 seconds if no indexing happened.
        if not index_occurred:
            logger.info("No folders to index sleeping for 10seconds.")
            time.sleep(10)


@click.command()
@click.option("--indexer-name", help="Name of the indexer, which is used to find it's config.")
def main(indexer_name: str):
    """Main method for starting run indexer to index all the files in an indexers cache."""
    settings = RetrohuntSettings()
    start_http_server(settings.prometheus_port_indexer)
    indexer_cfg = settings.indexers.get(indexer_name, None)
    if not indexer_cfg:
        raise Exception(
            f"Could not find config for indexer '{indexer_name}' available indexer "
            + f"configs are {','.join(settings.indexers.keys())}"
        )
    run_indexer(
        settings.root_path,
        settings.periodic_index_folder_name,
        settings.periodic_bgi_name,
        indexer_cfg,
    )
