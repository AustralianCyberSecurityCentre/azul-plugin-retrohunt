"""BigYara time-period based index generation."""

import hashlib
import logging
import pathlib
import shutil

import pendulum

from azul_plugin_retrohunt.bigyara.base_processor import FOLDER_DATE_FORMAT, METADATA_SUFFIX, BaseYaraProcessor
from azul_plugin_retrohunt.models import FileMetadata
from azul_plugin_retrohunt.settings import CACHE_DIR_NAME, STATE_DIR_NAME

from . import INDEX_DATA_SIZE_MIN

logger = logging.getLogger(__file__)


class BiggrepException(Exception):
    """Error when running bgindex."""

    pass


class IngestFileSizeException(Exception):
    """Exception that occurs when the ingested file is too big or too small."""

    pass


class BigYaraIngestor(BaseYaraProcessor):
    """Ingestor manages the ingesting and deletion of content for a BigYara Indexer to index."""

    @property
    def cache_directory(self) -> pathlib.Path:
        """Get the path to the cache directory for this indexer/ingestor.

        The cache directory holds all files that have been pulled in by the ingestor.
        """
        return self.base_directory.joinpath(CACHE_DIR_NAME)

    @property
    def periodic_cache_directory(self) -> pathlib.Path:
        """Get the path to the directory to temporarily store the periodic index data while it's being copied."""
        return self.base_directory.joinpath(self.base_directory, STATE_DIR_NAME, "periodic-stash")

    def __init__(
        self,
        root_path: str,
        processor_name: str,
        max_bytes_before_indexing: int,
        stream_labels: list[str],
        periodic_index_frequency_min: int,
    ):
        """Ingest files ready for bigyara to index."""
        super().__init__(root_path, processor_name, max_bytes_before_indexing)
        self.stream_labels = stream_labels
        self.create_cache_dir()
        self.bytes_in_cache = self._count_number_of_bytes_in_cache_dir()
        self.periodic_index_frequency_min = periodic_index_frequency_min

    def create_cache_dir(self) -> pathlib.Path:
        """Create the cache directory if it doesn't exist."""
        cache_dir = self.cache_directory
        if cache_dir.exists():
            return
        cache_dir.mkdir(parents=True, exist_ok=True)

    def add_data_to_index_cache(self, file_bytes: bytes, metadata: FileMetadata) -> bool:
        """Add raw data bytes to the indexes cache.

        return: true if file successfully added and false if the file already existed.
        """
        size_of_file = len(file_bytes)
        self._can_file_size_can_be_added(size_of_file)

        # File already exists
        new_file_path = self._create_path_to_file_in_cache(hashlib.sha256(file_bytes).hexdigest())
        if new_file_path.exists():
            return False

        # Move the cache as the new file is greater than the max.
        if self.bytes_in_cache + size_of_file > self._max_bytes_before_indexing:
            if self._move_cache_for_indexer():
                self.create_cache_dir()
                self.bytes_in_cache = 0

        with open(new_file_path, "wb") as data_file:
            data_file.write(file_bytes)
        # Write metadata as well as file contents.
        with open(new_file_path.with_name(new_file_path.name + METADATA_SUFFIX), "w") as meta_file:
            meta_file.write(metadata.model_dump_json(round_trip=True))

        self.bytes_in_cache += size_of_file

        return True

    def _create_path_to_file_in_cache(self, sha256: str) -> pathlib.Path:
        """Get the path to the file that should be added to the cache."""
        return self.cache_directory.joinpath(sha256)

    def _count_number_of_bytes_in_cache_dir(self):
        """Count all file sizes in the cache directory, excluding metadata files and return the number of bytes."""
        return self.count_bytes_for_dir(self.cache_directory, METADATA_SUFFIX)

    def cleanup_old_ingest_dirs(self):
        """Delete any ingest directories that are empty.

        NOTE - indexer can't do this because it might delete a directory ingestor just created.
        """
        for parent_folder in self._iter_parent_index_dirs():
            if parent_folder.is_dir() and len(list(parent_folder.iterdir())) == 0:
                parent_folder.rmdir()

    def _can_file_size_can_be_added(self, file_size: int):
        """Verify that the provided file size is not too big or too small to be added to the cache."""
        if file_size < INDEX_DATA_SIZE_MIN:
            raise IngestFileSizeException(
                f"Can't add file with file size {file_size}bytes as it must be at least {INDEX_DATA_SIZE_MIN} "
                + "bytes to be compatible with biggrep indexing."
            )
        elif file_size > self._max_bytes_before_indexing:
            raise IngestFileSizeException(f"Can't add file with {file_size}bytes as it is more than can be indexed.")

    def get_path_of_next_ingest_ready_dir(self) -> pathlib.Path:
        """Get the Path that should be used for the next directory ready for indexation.

        Parent folder will be todays date in form YYYYMMDD
        Child folder will be number incrementing that doesn't exist (e.g 1,2,3,4)
        just list all sub folders get max and increment by 1.
        """
        now = pendulum.now()
        formatted_date = now.strftime(FOLDER_DATE_FORMAT)
        parent_folder_path = self.base_directory.joinpath(formatted_date)
        parent_folder = pathlib.Path(parent_folder_path)
        parent_folder.mkdir(parents=True, exist_ok=True)
        # Child folders should always have integer names (except the split directories).
        child_folders = [
            int(child_folder.name) for child_folder in parent_folder.iterdir() if child_folder.name.isdigit()
        ]
        new_child_folder = max(child_folders + [0]) + 1
        new_child_folder = parent_folder_path.joinpath(str(new_child_folder))
        return self.base_directory.joinpath(new_child_folder)

    def _move_cache_for_indexer(self) -> bool:
        """Rename the cache directory to mark it ready for ingestion by the corresponding indexer."""
        shutil.move(self.cache_directory, self.get_path_of_next_ingest_ready_dir())
        return True

    def copy_cache_for_indexer(self, dest_dir_name: str):
        """Rename the cache directory to mark it ready for ingestion by the corresponding indexer."""
        target_dir = self.get_path_of_next_ingest_ready_dir()
        target_dir = target_dir.with_name(dest_dir_name)  # Set different name but still but in timed directory.
        # Don't do anything because the previous periodic index still exists and may still be being indexed.
        if target_dir.exists():
            logger.warning("Couldn't generate a periodic index because one is still in progress.")
            return

        # Divided by 2 because every file has itself and a metadata file.
        source_files = len(list(self.cache_directory.iterdir())) // 2
        # If there is not more than one file theres nothing to index.
        if source_files == 0:
            logger.info("Not running periodic indexer because there are no files.")
            return
        # If there is exactly one file add a dummy file so that indexing can still occur.
        elif source_files == 1:
            successful = self.add_data_to_index_cache(
                b"dummy-file",
                FileMetadata(stream_label="content", stream_source="testing"),
            )
            if not successful:
                logger.info(
                    "Not running periodic indexer because there are"
                    + "not enough files and the dummy file couldn't be added."
                )
                return

        # Remove any old copies that failed.
        if self.periodic_cache_directory.exists():
            shutil.rmtree(self.periodic_cache_directory)
        # Copy all the files currently ingested to an intermediate directory.
        shutil.copytree(self.cache_directory, self.periodic_cache_directory)

        # Move all files ready for indexing into a directory the indexer can see.
        shutil.move(self.periodic_cache_directory, target_dir)
