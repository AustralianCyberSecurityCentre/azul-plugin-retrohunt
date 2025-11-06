"""BigYara time-period based index generation."""

import logging
import pathlib
from datetime import datetime

from azul_plugin_retrohunt.settings import BGI_DIR_NAME, CACHE_DIR_NAME, STATE_DIR_NAME

logger = logging.getLogger(__file__)


FOLDER_DATE_FORMAT = "%Y%m%d"
INDEX_DATE_FORMAT = FOLDER_DATE_FORMAT + "T%H%M"
METADATA_SUFFIX = "-meta"
SPLIT_DIR_SUFFIX = "-split"


class BaseYaraProcessor:
    """Core processor that handles common tasks for both the yara indexer and ingestor."""

    def __init__(self, root_path: str, processor_name: str, max_bytes_before_indexing: int):
        """Ingest files ready for bigyara to index."""
        self._root_path = root_path
        self._processor_name = processor_name
        self._max_bytes_before_indexing = max_bytes_before_indexing

    @property
    def base_directory(self) -> pathlib.Path:
        """Get the root path for this indexer/ingestor."""
        return pathlib.Path(self._root_path, self._processor_name)

    @staticmethod
    def count_bytes_for_dir(dir: pathlib.Path, exclude_files_with_str_in_name: str = None):
        """Get the number of bytes in a directory."""
        size = 0
        if dir.exists():
            for f in dir.iterdir():
                if f.is_file:
                    if exclude_files_with_str_in_name is None or not (exclude_files_with_str_in_name in f.name):
                        size += f.stat().st_size
                else:
                    logger.warning(f"Ignoring the directory '{f}' when checking the size of directory '{dir}'")
        return size

    def _iter_parent_index_dirs(self):
        """Iterate through the available index directories."""
        # Find all the top level folders labelled with the date.
        dirs_for_indexing = []
        for dir in self.base_directory.iterdir():
            # Ignore built-in directories.
            if dir.name in [CACHE_DIR_NAME, STATE_DIR_NAME, BGI_DIR_NAME]:
                continue
            try:
                dir_as_date = datetime.strptime(dir.name, FOLDER_DATE_FORMAT)
                dirs_for_indexing.append(dir_as_date)
            except ValueError:
                # If strptime fails to pass the folder format.
                logger.warning(
                    f"Ignoring the folder '{dir}' for indexing because it's name is invalid."
                    + f"\nIt should be in the form '{FOLDER_DATE_FORMAT}'"
                )
                continue
        # Sort oldest to newest and then list out child directories as they are found.
        dirs_for_indexing.sort()
        for parent_date in dirs_for_indexing:
            yield self.base_directory.joinpath(datetime.strftime(parent_date, FOLDER_DATE_FORMAT))
