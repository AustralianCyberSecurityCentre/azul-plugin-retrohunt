"""Common methods used throughout all tests.

This file is in the core library because the way bigyara installs makes it fail to import when
placed in the tests directory.
"""

import json
import os
import shutil
import tempfile
import unittest

# Prevent BigYara from trying to find real binaries during tests
from azul_plugin_retrohunt.models import FileMetadata
from azul_plugin_retrohunt.settings import RetrohuntSettings


def get_indexer_class():
    """Lazily import and return the BigYaraIndexer class.

    BigYara's environment module performs executable discovery at import time,
    which can raise errors during testing when the real bgindex/bgdump binaries
    are not available. By deferring the import until this function is called,
    tests can safely patch or mock BigYara before the module is loaded.

    Returns:
    -------
    type
        The BigYaraIndexer class from azul_plugin_retrohunt.bigyara.index.
    """
    from azul_plugin_retrohunt.bigyara.index import BigYaraIndexer
    return BigYaraIndexer

def get_ingestor_class():
    """Lazily import and return the BigYaraIngestor class.

    Similar to get_indexer_class(), this function avoids importing the BigYara
    ingestion module at test collection time. The BigYara environment performs
    binary lookup during import, so delaying the import allows tests to apply
    mocks or environment overrides before the module is loaded.

    Returns:
    -------
    type
        The BigYaraIngestor class from azul_plugin_retrohunt.bigyara.ingest.
    """
    from azul_plugin_retrohunt.bigyara.ingest import BigYaraIngestor
    return BigYaraIngestor


class RetrohuntBaseTest:
    """Base tests that can be used in generic unit tests and the azul-plugin unit tests."""

    def _setUp(self):
        """Mandatory."""
        self.base_temp_dir = tempfile.mkdtemp(prefix="retrohunt_")
        self.dispatcher_url = "http://localhost:8000"
        os.environ["plugin_root_path"] = self.base_temp_dir
        os.environ["plugin_events_url"] = self.dispatcher_url
        os.environ["plugin_data_url"] = self.dispatcher_url
        self.indexer_cfg_name = "content"
        self.indexers_cfg = {
            self.indexer_cfg_name: RetrohuntSettings.Indexer(
                name=self.indexer_cfg_name,
                stream_labels=["content"],
                max_bytes_before_indexing="10GiB",
                timeout_minutes=60,
                periodic_index_frequency_min=60,
                allow_splitting_and_deletion=True,
                seconds_between_gathering_cpu_and_ram_metrics=0.1,  # Make this small so the tests run faster.
                run_once=True,
            )
        }
        self.retrohunt_settings = RetrohuntSettings()
        self._reapply_indexer_cfg()

    def _reapply_indexer_cfg(self):
        """Create or update the environment variable that sets the indexers for retrohunt settings."""
        dict_indexer_config = {}
        for x in self.indexers_cfg:
            dict_indexer_config[x] = self.indexers_cfg[x].model_dump()
        os.environ["plugin_indexers"] = json.dumps(dict_indexer_config)

    def _tearDown(self):
        """Mandatory."""
        # Delete the temp directory being used by indexer/ingestor.
        shutil.rmtree(self.base_temp_dir)


class BaseIngestorIndexerTest(RetrohuntBaseTest, unittest.TestCase):
    """Mandatory."""

    def setUp(self):
        """Mandatory."""
        self._setUp()
        self.reapply_indexer_cfg()
        super().setUp()

    def tearDown(self):
        """Mandatory."""
        self._tearDown()
        super().tearDown()

    def reapply_indexer_cfg(self):
        """Reapply the current indexer config and re-create the ingestor and indexer.."""
        self._reapply_indexer_cfg()
        self.recreate_content_ingestor()
        self.recreate_content_indexer()

    def recreate_content_ingestor(self):
        """Recreate the ingestor with the current config."""
        self.ingestor = get_ingestor_class()(
            self.base_temp_dir,
            self.indexer_cfg_name,
            self.indexers_cfg[self.indexer_cfg_name].max_bytes_before_indexing,
            [],
            self.indexers_cfg[self.indexer_cfg_name].periodic_index_frequency_min,
        )

    def recreate_content_indexer(self):
        """Recreate the indexer with the current config."""
        self.indexer = get_indexer_class()(
            self.base_temp_dir,
            self.indexer_cfg_name,
            self.indexers_cfg[self.indexer_cfg_name].max_bytes_before_indexing,
        )


    def modify_content_stream_label_config(self, new_labels: list[str]):
        """Modify the labels for the indexer and ingestor."""
        self.indexers_cfg[self.indexer_cfg_name].stream_labels = new_labels
        self.reapply_indexer_cfg()

    def modify_content_max_bytes_indexing_config(self, si_bytes: str):
        """Modify the max_bytes_before indexing for the indexer and ingestor."""
        self.indexers_cfg[self.indexer_cfg_name].max_bytes_before_indexing = si_bytes
        self.reapply_indexer_cfg()

    def add_data_to_ingestor(self, data: list[bytes]):
        """Add data to the ingestor cache."""
        for d in data:
            self.ingestor.add_data_to_index_cache(d, FileMetadata(stream_label="content", stream_source="testing"))

    def add_data_to_ingestor_and_ready_it_for_indexing(self, data: list[bytes]):
        """Add data to the ingestor cache."""
        self.add_data_to_ingestor(data)
        self.ingestor._move_cache_for_indexer()
        self.ingestor.create_cache_dir()

    def add_data_to_ingestor_and_ready_it_for_periodic_indexing(self, data: list[bytes]):
        """Add data to the ingestor cache and add some to the periodic indexer."""
        self.add_data_to_ingestor(data)
        self.ingestor.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)
