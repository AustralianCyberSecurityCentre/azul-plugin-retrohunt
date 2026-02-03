"""BigYara time-period based index generation."""

import logging
import os
import pathlib
import re
import shutil
import subprocess  # noqa: S404  # nosec: B404
import tempfile
import traceback
from typing import Iterator

import pendulum
from prometheus_client import Counter

from azul_plugin_retrohunt.bigyara.base_processor import (
    INDEX_DATE_FORMAT,
    METADATA_SUFFIX,
    SPLIT_DIR_SUFFIX,
    BaseYaraProcessor,
)
from azul_plugin_retrohunt.models import FileMetadata
from azul_plugin_retrohunt.settings import BGI_DIR_NAME, STATE_DIR_NAME

from .env import executables

prom_number_of_bgi_fails = Counter(
    "retrohunt_index_fails", "Number of index failures of different types (split,delete)", ["index", "type"]
)
# FUTURE: investigate whether there is an alternative to biggrep that allows index merging.
# FUTURE: if searching has a command line interface, then indexing should have one too.

logger = logging.getLogger(__file__)


class BiggrepException(Exception):
    """Error when running bgindex."""

    pass


class BigYaraIndexer(BaseYaraProcessor):
    """Index folders that have been ingested by the BigYaraIngestor."""

    _last_dir_read_filename = "last_attempted_dir.state"

    def __init__(self, root_path: str, processor_name: str, max_bytes_before_indexing: int):
        """Index folders with biggrep indexing."""
        super().__init__(root_path, processor_name, max_bytes_before_indexing)
        # Increment by 0 to create metrics.
        prom_number_of_bgi_fails.labels(processor_name, "delete")
        prom_number_of_bgi_fails.labels(processor_name, "split")
        self.files_ignored_while_indexing = 0
        if not self.bgi_directory.exists():
            self.bgi_directory.mkdir(parents=True, exist_ok=True)
        if not self.state_directory.exists():
            self.state_directory.mkdir(parents=True, exist_ok=True)

    @property
    def last_dir_read_state_file_path(self) -> pathlib.Path:
        """Get the path to the state file for the last directory that was attempted to be indexed by indexer."""
        return self.state_directory.joinpath(self._last_dir_read_filename)

    @property
    def bgi_directory(self) -> pathlib.Path:
        """Path to the directory where all BGI index files are stored for the content type."""
        return pathlib.Path(self.base_directory, BGI_DIR_NAME)

    @property
    def state_directory(self) -> pathlib.Path:
        """Get the path to the state directory for this indexer/ingestor.

        The state directory holds
        """
        return pathlib.Path(self.base_directory, STATE_DIR_NAME)

    def get_folders_ready_for_indexing(self) -> Iterator[pathlib.Path]:
        """Get a generator that gives the oldest folder ready for indexing (oldest date, smallest number)."""
        # Find all the top level folders labelled with the date.
        for parent_folder in self._iter_parent_index_dirs():
            # Child folders should always have integer names. (except the split directories and periodic index dirs).
            child_folders = [
                int(child_folder.name) for child_folder in parent_folder.iterdir() if child_folder.name.isdigit()
            ]
            child_folders.sort()

            # Get all split directories and folders that are not integers and put them at the end.
            special_child_folders = [
                child_folder.name for child_folder in parent_folder.iterdir() if not child_folder.name.isdigit()
            ]
            special_child_folders.sort()
            for sub_folder in child_folders + special_child_folders:
                path_to_folder = pathlib.Path(parent_folder.joinpath(str(sub_folder)))
                if path_to_folder.exists():
                    yield path_to_folder
                else:
                    logger.warning(f"Found the path '{path_to_folder}' for indexing but it doesn't exist.")

    def _get_next_index_path(self) -> pathlib.Path:
        """Returns the path of the first available bgi file without the bgi extension because biggrep adds .bgi."""
        index_file_count: int = 1
        base_new_index_path = self.bgi_directory.joinpath(pendulum.now().strftime(INDEX_DATE_FORMAT))
        available_new_path = base_new_index_path
        # Searches for a new bgi filename that doesn't already exist.
        # E.g filename is 20240624T2218 and we check if 20240624T2218.bgi exists and then add a postfix in order e.g:
        # 20240624T2218.001.bgi
        # 20240624T2218.002.bgi
        # 20240624T2218.003.bgi
        # And keeps going until if finds a valid name that doesn't already exist.
        while available_new_path.with_name(available_new_path.name + ".bgi").exists():
            available_new_path = base_new_index_path.with_name(base_new_index_path.name + f".{index_file_count:03d}")
            index_file_count += 1

        return available_new_path

    def _get_files_to_index_with_meta(self, folder_path: pathlib.Path) -> Iterator[str]:
        """Loads all the absolute paths to the files to index and appends their metadata."""
        # Matches only the start of the regex because the files are named as <sha256>-meta and <sha256>
        # should all match.
        sha256_regex = re.compile("^[a-fA-F0-9]{64}")
        meta_dict: dict[pathlib.Path, FileMetadata] = dict()

        # Sorting here allow consistency for testing.
        for f in sorted(folder_path.iterdir(), key=lambda k: k.name, reverse=True):
            if sha256_regex.search(f.name) is None:
                logger.warning(f"Ignoring the file {f.name} while indexing, because it doesn't have a sha256 name.")
                self.files_ignored_while_indexing += 1

            if f.name.endswith(METADATA_SUFFIX):
                try:
                    with open(f, "rb") as meta_file:
                        meta = FileMetadata.model_validate_json(meta_file.read())
                        target_file = f.with_name(f.name.removesuffix(METADATA_SUFFIX))
                        meta_dict[target_file] = meta
                except Exception as e:
                    logger.warning(f"Ignoring file with bad metadata {f} and error {e}")
                    traceback.print_exc()
                    continue

        for file_path, metadata in meta_dict.items():
            if file_path.exists():
                yield str(file_path) + "," + metadata.format_metadata()
            else:
                logger.warning("Ignoring file {file_path} because it has metadata but no corresponding data file.")

    def generate_index(self, folder_path: pathlib.Path, bgi_name_override: str = None, timeout_minutes: int = 60):
        """Generate a bgi index for the added files."""
        self._cleanup_old_bgis()
        if not folder_path.exists():
            raise Exception(f"Cannot index contents of folder {folder_path} as it does not exist.")

        # Determine name for the big index file.
        if bgi_name_override:
            index_file = self.bgi_directory.joinpath(bgi_name_override)
        else:
            index_file = self._get_next_index_path()
        logger.info(f"Generating index: {index_file}.bgi")

        # write to a hidden file then rename when done to prevent file use while writing.
        # note that bgindex adds the .bgi file extension for us.
        hidden_index_file = index_file.with_name("." + index_file.name)

        # A temporary file is being used to allow for the cat command to be used.
        # If the file names are passed directly into the command they can cause a too many args error periodically.
        with tempfile.NamedTemporaryFile() as tmp_file:
            with open(tmp_file.name, "w+") as tmp_file_write:
                tmp_file_write.writelines("\n".join(self._get_files_to_index_with_meta(folder_path)))

            # NOTE - adding the -d and -v flags to bgindex causes it to fail when processing binaries.
            process: subprocess.CompletedProcess[bytes] = subprocess.run(  # noqa: S602
                f"cat '{tmp_file.name}' | '{executables['bgindex']}' -p '{hidden_index_file}' -z -L",
                shell=True,  # noqa: S602
                timeout=timeout_minutes * 60,
                stderr=subprocess.PIPE,
            )

        if process.returncode != 0:
            # FUTURE: find a bgindex error that we don't prevent to test this
            raise BiggrepException(f"bgindex error: {process.stderr.decode()}")

        # rename from hidden now that the write is complete
        os.rename(str(hidden_index_file) + ".bgi", str(index_file) + ".bgi")
        shutil.rmtree(folder_path)

    # --------------------------------------------------------------------- Handle OOM failures
    def has_dir_failed_to_index_before(self, folder_path: pathlib.Path) -> bool:
        """Return True if the directory has been attempted to be indexed before."""
        if self.last_dir_read_state_file_path.exists():
            with open(self.last_dir_read_state_file_path, "r") as sf:
                path = sf.read()
                return path == str(folder_path)
        return False

    def save_indexing_dir(self, folder_path: pathlib.Path):
        """Save the fact that we are trying to index the provided directory."""
        with open(self.last_dir_read_state_file_path, "w+") as sf:
            sf.write(str(folder_path))

    def clear_indexing_dir(self):
        """Delete the last indexed directory reference."""
        self.last_dir_read_state_file_path.unlink(missing_ok=True)

    def split_or_delete_indexing_dir(self, folder_path: pathlib.Path):
        """Split a directory in half or delete it if it's been split before."""
        if SPLIT_DIR_SUFFIX in folder_path.name:
            prom_number_of_bgi_fails.labels(self._processor_name, "delete").inc()
            logger.warning(f"Failed to index the directory {folder_path} after splitting dropping all contents.")
            shutil.rmtree(folder_path)
            return

        logger.info(f"Splitting directory {folder_path}")
        files = list(folder_path.iterdir())
        # sort so metadata and files are all side by side.
        files.sort(key=lambda f: f.name)

        # Take half the files and then ensure it's even to get all the metadata and data files for the half you got.
        half_files = len(files) // 2
        half_files += half_files % 2

        # Move all files to split directories.
        first_half_base_dir = folder_path.with_name(folder_path.name + SPLIT_DIR_SUFFIX + "-part1")
        first_half_base_dir.mkdir(parents=True, exist_ok=True)
        for i in range(half_files):
            files[i].rename(first_half_base_dir.joinpath(files[i].name))

        second_half_base_dir = folder_path.with_name(folder_path.name + SPLIT_DIR_SUFFIX + "-part2")
        second_half_base_dir.mkdir(parents=True, exist_ok=True)
        for i in range(half_files, len(files)):
            files[i].rename(second_half_base_dir.joinpath(files[i].name))

        prom_number_of_bgi_fails.labels(self._processor_name, "split").inc()
        # Delete original directory.
        shutil.rmtree(folder_path)

    def _cleanup_old_bgis(self):
        """Remove any hidden bgi files as they are assumed to be orphaned."""
        for f in self.bgi_directory.iterdir():
            if f.name.startswith(".") and f.name.endswith(".bgi"):
                f.unlink(missing_ok=True)
