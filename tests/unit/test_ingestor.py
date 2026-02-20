import hashlib
import json
import os
import pathlib
import tempfile
from collections import deque
from hashlib import sha256
from unittest import mock

import pendulum
from azul_runner import JobResult, State, coordinator
from azul_runner import settings as azr_settings
from azul_runner import test_template

from azul_plugin_retrohunt.bigyara.base_processor import BaseYaraProcessor
from azul_plugin_retrohunt.indexer import run_indexer
from azul_plugin_retrohunt.ingestor import RetrohuntIngestor
from azul_plugin_retrohunt.settings import CACHE_DIR_NAME, RetrohuntSettings
from azul_plugin_retrohunt.test_utils import RetrohuntBaseTest


class TestSettingsNoEnv:
    def test_settings_with_no_env(self):
        """Just don't want to see an exception for either of these cases."""
        os.environ["plugin_root_path"] = "dummy"
        settings_work = RetrohuntSettings()
        print(settings_work)

        # default indexer settings.
        indexers_cfg = {
            "customWithDefaults": RetrohuntSettings.Indexer(
                name="customWithDefaults",
            )
        }

        dict_indexer_config = {}
        for x in indexers_cfg:
            dict_indexer_config[x] = indexers_cfg[x].model_dump()
        os.environ["plugin_indexers"] = json.dumps(dict_indexer_config)
        settings_work = RetrohuntSettings()
        print(settings_work)


@mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z"))
class TestExecute(test_template.TestPlugin, RetrohuntBaseTest):
    PLUGIN_TO_TEST = RetrohuntIngestor

    def setUp(self):
        self._setUp()
        self.base_dir_path = pathlib.Path(self.base_temp_dir)
        self.ingestor_cache_directory = self.base_dir_path.joinpath(self.indexer_cfg_name, CACHE_DIR_NAME)
        return super().setUp()

    def tearDown(self):
        # Delete the temp directory being used by indexer/ingestor.
        self._tearDown()
        super().tearDown()

    def test_hash_cache(self):
        """Test LRU hash cache evicts correctly."""
        with tempfile.TemporaryDirectory(prefix="retrotest_") as tmp_dir:
            CACHE_SIZE = 2
            config = {"index_path": tmp_dir, "name_suffix": "test", "hash_cache_size": CACHE_SIZE}

            data: list[bytes] = [
                b"here is some content to index",
                b"here is more content to index",
                b"here is even more content!",
            ]

            hashes: list[str] = []
            for d in data:
                hashes.append(sha256(d).hexdigest())

            cache_object = RetrohuntIngestor._create_hash_cache(CACHE_SIZE)

            def mock_create_hash_cache(size):
                self.assertEqual(CACHE_SIZE, size)
                return cache_object

            with mock.patch(
                "azul_plugin_retrohunt.ingestor.RetrohuntIngestor._create_hash_cache", mock_create_hash_cache
            ):
                local_coordinator = coordinator.Coordinator(
                    self.PLUGIN_TO_TEST, azr_settings.parse_config(self.PLUGIN_TO_TEST, config)
                )
                result = self.do_execution(
                    data_in=[("content", data[0]), ("content", data[1]), ("content", data[0]), ("content", data[2])],
                    provided_coordinator=local_coordinator,
                )
                self.assertJobResult(result, JobResult(state=State(State.Label.COMPLETED_EMPTY)))

                # what should have happened is:
                #     data[0] added, cache miss                     - [hashes[0]]
                #     data[1] added, cache miss                     - [hashes[1], hashes[0]]
                #     data[0] added, cache hit and moved to front   - [hashes[0], hashes[1]]
                #     data[2] added, cache miss and hash[1] evicted - [hashes[2], hashes[0]]
                self.assertEqual(cache_object, deque([hashes[2], hashes[0]], 2))

    def test_add_the_same_file_lots(self):
        """Add two files lots of times but the hash cache should filter out the duplicates."""
        data1: bytes = b"here is some content to index"
        data2: bytes = b"Some other content"
        self.do_execution(
            data_in=[
                ("content", data1),
                ("content", data2),
                ("content", data1),
                ("content", data2),
                ("content", data1),
                ("content", data1),
                ("content", data1),
                ("content", data2),
                ("content", data1),
                ("content", data1),
                ("content", data2),
            ]
        )
        cache_dir = [f.name for f in self.ingestor_cache_directory.iterdir()]
        self.assertEqual(len(cache_dir), 4)
        self.assertIn(hashlib.sha256(data1).hexdigest(), cache_dir)
        self.assertIn(hashlib.sha256(data2).hexdigest(), cache_dir)

    def test_run_indexer_multiple_cases(self):
        """Ingest a couple of files and then run the indexer once."""
        # Start indexing at 100 bytes.
        self.indexers_cfg[self.indexer_cfg_name].max_bytes_before_indexing = "100"
        self._reapply_indexer_cfg()
        data1: bytes = b"here is some content to index"
        data2: bytes = b"lets try and make sure it's over the hundred bytes"
        data3: bytes = b"But it can't be all in one file because that won't get indexed!"
        data4: bytes = b"This won't be added to the cache at all because it is over 100 bytes and therefore can't be indexed. Enough content to push it over 100 bytes."
        # Verify 3 files get ingested. (Note 1 file generates itself + a metadata file)
        # First two files will get indexed without issue.
        self.do_execution(data_in=[("content", data1)], no_multiprocessing=True)
        self.assertEqual(len(list(self.ingestor_cache_directory.iterdir())), 2)
        self.do_execution(data_in=[("content", data2)], no_multiprocessing=True)
        self.assertEqual(len(list(self.ingestor_cache_directory.iterdir())), 4)
        # Should have triggered a move of the first two files to the indexer and add itself to cache
        self.do_execution(data_in=[("content", data3)], no_multiprocessing=True)
        cache_dir = [f.name for f in self.ingestor_cache_directory.iterdir()]
        self.assertEqual(len(cache_dir), 2)
        self.assertIn(hashlib.sha256(data3).hexdigest(), cache_dir)
        # can't add content because data4 is more than 100 bytes long so can never be indexed.
        self.do_execution(data_in=[("content", data4)], no_multiprocessing=True)
        # Cache directory is unchanged and still just contains data3.
        cache_dir = [f.name for f in self.ingestor_cache_directory.iterdir()]
        self.assertEqual(len(cache_dir), 2)
        self.assertIn(hashlib.sha256(data3).hexdigest(), cache_dir)

        # New index ready directory should exist
        self.assertIn("20020108", list(dir.name for dir in self.ingestor_cache_directory.parent.iterdir()))

        mini_data = b"abcdef"
        aug_stream_data = b"djafksdjfksadfjksdkfjskdfjskdfjksdfkjsdkfj"
        # check that only one file is added when using multiple labels
        self.do_execution(data_in=[("content", mini_data), ("assemblyline", aug_stream_data)], no_multiprocessing=True)
        self.assertEqual(len(list(self.ingestor_cache_directory.iterdir())), 4)

    def test_run_indexer_on_a_non_content_stream_type(self):
        self.indexers_cfg[self.indexer_cfg_name].stream_labels = ["content", "assemblyline"]
        self._reapply_indexer_cfg()

        mini_data = b"abcdef"
        aug_stream_data = b"djafksdjfksadfjksdkfjskdfjskdfjksdfkjsdkfj"
        # check that only one file is added when using multiple labels
        self.do_execution(data_in=[("content", mini_data), ("assemblyline", aug_stream_data)], no_multiprocessing=True)
        f_names = [f.name for f in self.ingestor_cache_directory.iterdir()]

        # Check that both content labels had their content added.
        self.assertIn(
            hashlib.sha256(mini_data).hexdigest(),
            f_names,
            "The content label wasn't added to the cache and should have been",
        )
        self.assertIn(
            hashlib.sha256(aug_stream_data).hexdigest(),
            f_names,
            "The label 'assemblyline' wasn't be added to the cache and should have been.'",
        )
        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names), 4)

    def test_just_non_content_stream(self):
        """Check just an augmented stream can be added."""
        self.indexers_cfg[self.indexer_cfg_name].stream_labels = ["assemblyline"]
        self._reapply_indexer_cfg()

        mini_data = b"abcdef"
        aug_stream_data = b"djafksdjfksadfjksdkfjskdfjskdfjksdfkjsdkfj"
        # check that only one file is added when using multiple labels
        self.do_execution(data_in=[("content", mini_data), ("assemblyline", aug_stream_data)], no_multiprocessing=True)
        f_names = [f.name for f in self.ingestor_cache_directory.iterdir()]

        # Check just augmented stream data was added.
        self.assertIn(
            hashlib.sha256(aug_stream_data).hexdigest(),
            f_names,
            "The label 'assemblyline' wasn't be added to the cache and should have been.'",
        )
        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names), 2)

    def test_just_non_content_stream_bad_config(self):
        """Check when just an augmented stream exists everything fails."""
        aug_stream_data = b"djafksdjfksadfjksdkfjskdfjskdfjksdfkjsdkfj"
        # check that only one file is added when using multiple labels
        self.do_execution(data_in=[("assemblyline", aug_stream_data)], no_multiprocessing=True)
        f_names = [f.name for f in self.ingestor_cache_directory.iterdir()]

        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names), 0)

    def test_adding_content_for_two_indexers(self):
        """Double the data, one for each indexer out of the ingestor."""
        alt_indexer_name = "alternateIndexer"
        self.indexers_cfg[alt_indexer_name] = RetrohuntSettings.Indexer(name=alt_indexer_name)
        self._reapply_indexer_cfg()

        data = b"ajksdfjkasdfkljsadfljkdfljksf"
        self.do_execution(data_in=[("content", data)], no_multiprocessing=True)
        f_names_content_cache = [f.name for f in self.ingestor_cache_directory.iterdir()]
        alt_indexer_path = self.base_dir_path.joinpath(alt_indexer_name, CACHE_DIR_NAME)
        f_names_alt_indexer_cache = [f.name for f in alt_indexer_path.iterdir()]

        # Check just augmented stream data was added.
        self.assertIn(hashlib.sha256(data).hexdigest(), f_names_content_cache)
        self.assertIn(hashlib.sha256(data).hexdigest(), f_names_alt_indexer_cache)
        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names_content_cache), 2)
        self.assertEqual(len(f_names_alt_indexer_cache), 2)

    def test_adding_content_for_two_indexers_but_data_is_too_large_for_one(self):
        """Double the data, one for each indexer out of the ingestor."""
        # Set original indexer to only take 100bytes.
        self.indexers_cfg[self.indexer_cfg_name].max_bytes_before_indexing = "100"

        # add a new indexer.
        alt_indexer_name = "alternateIndexer"
        self.indexers_cfg[alt_indexer_name] = RetrohuntSettings.Indexer(name=alt_indexer_name)

        # path to new indexers cache.
        alt_indexer_cache_path = self.base_dir_path.joinpath(alt_indexer_name, CACHE_DIR_NAME)
        self._reapply_indexer_cfg()

        # Add data to both caches with the file being too large for one but still add it to the other.
        data = b"ajksdfjkasdfkljsadfljkdfljksfaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa this content is too long for the base cache. because it's more than 100 bytes."
        self.do_execution(data_in=[("content", data)], no_multiprocessing=True)
        f_names_content_cache = [f.name for f in self.ingestor_cache_directory.iterdir()]
        f_names_alt_indexer_cache = [f.name for f in alt_indexer_cache_path.iterdir()]

        # Check just augmented stream data was added.
        self.assertIn(hashlib.sha256(data).hexdigest(), f_names_alt_indexer_cache)
        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names_content_cache), 0)
        self.assertEqual(len(f_names_alt_indexer_cache), 2)

    def test_adding_content_for_two_indexers_but_one_filters_the_data(self):
        """Have two indexers but one only accepts alt streams and there is no alt stream."""
        # Set original indexer to only take alt-streams.
        self.indexers_cfg[self.indexer_cfg_name].stream_labels = ["assemblyline"]

        # add a new indexer.
        alt_indexer_name = "alternateIndexer"
        self.indexers_cfg[alt_indexer_name] = RetrohuntSettings.Indexer(name=alt_indexer_name)

        # path to new indexers cache.
        alt_indexer_cache_path = self.base_dir_path.joinpath(alt_indexer_name, CACHE_DIR_NAME)
        self._reapply_indexer_cfg()

        # Add data to both caches with the file being too large for one but still add it to the other.
        data = b"ajksdfjkasdfkljsadfljkdfljksfaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa this content is too long for the base cache. because it's more than 100 bytes."
        self.do_execution(data_in=[("content", data)], no_multiprocessing=True)
        f_names_content_cache = [f.name for f in self.ingestor_cache_directory.iterdir()]
        f_names_alt_indexer_cache = [f.name for f in alt_indexer_cache_path.iterdir()]

        # Check just augmented stream data was added.
        self.assertIn(hashlib.sha256(data).hexdigest(), f_names_alt_indexer_cache)
        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names_content_cache), 0)
        self.assertEqual(len(f_names_alt_indexer_cache), 2)

    def test_adding_content_for_two_indexers_but_one_filters_one_label_and_one_filters_the_other(self):
        """Have two indexers but one only accepts alt streams and there is an alt stream."""
        # Set original indexer to only take alt-streams.
        self.indexers_cfg[self.indexer_cfg_name].stream_labels = ["assemblyline"]

        # add a new indexer.
        alt_indexer_name = "alternateIndexer"
        self.indexers_cfg[alt_indexer_name] = RetrohuntSettings.Indexer(name=alt_indexer_name)

        # path to new indexers cache.
        alt_indexer_cache_path = self.base_dir_path.joinpath(alt_indexer_name, CACHE_DIR_NAME)
        self._reapply_indexer_cfg()

        # Add data to both caches with the file being too large for one but still add it to the other.
        data = b"ajksdfjkasdfkljsadfljkdfljksfaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa this content is too long for the base cache. because it's more than 100 bytes."
        aug_data = b"aug data!"
        self.do_execution(data_in=[("content", data), ("assemblyline", aug_data)], no_multiprocessing=True)
        f_names_content_cache = [f.name for f in self.ingestor_cache_directory.iterdir()]
        f_names_alt_indexer_cache = [f.name for f in alt_indexer_cache_path.iterdir()]

        # Check just augmented stream data was added.
        self.assertIn(hashlib.sha256(aug_data).hexdigest(), f_names_content_cache)
        self.assertIn(hashlib.sha256(data).hexdigest(), f_names_alt_indexer_cache)
        # Verify all metadata and files went into cache.
        self.assertEqual(len(f_names_content_cache), 2)
        self.assertEqual(len(f_names_alt_indexer_cache), 2)

    def test_periodic_index_generated(self):
        """Test if the periodic indexer triggers after an hour.

        NOTE - if this test breaks it's possible it's due to the way mock_pendulum is written.

        It assumes the first time pendulum.now() is called is in the Ingestors init.
        and the second time it's called is in the ingestors execute method.
        """
        data1: bytes = b"here is some content to index"
        data2: bytes = b"Some other content"
        data3: bytes = b"Some other content that is different to the other 2."
        data4: bytes = b"Random other content just for fun."
        data4: bytes = b"Random other content just for fun2."
        self.indexers_cfg[self.indexer_cfg_name].periodic_index_frequency_min = 60
        # Reapply config to allow config changes to affect the plugin run
        self._reapply_indexer_cfg()
        first_call = True

        def mock_pendulum():
            """Pass the previously mocked time + 70minutes."""
            return pendulum.parse("2002-01-08T11:20:10Z")  # Increase time by 1hour and ten minutes

        local_coordinator = coordinator.Coordinator(
            self.PLUGIN_TO_TEST, azr_settings.parse_config(self.PLUGIN_TO_TEST, {})
        )

        # Add Run plugin against 2 files and a periodic index should be created.
        print(local_coordinator.cfg)
        self.do_execution(data_in=[("content", data1)], provided_coordinator=local_coordinator)
        self.do_execution(data_in=[("content", data2)], provided_coordinator=local_coordinator)
        with mock.patch("pendulum.now", lambda: mock_pendulum()):
            self.do_execution(data_in=[("content", data3)], provided_coordinator=local_coordinator)
        self.do_execution(data_in=[("content", data4)], provided_coordinator=local_coordinator)

        cache_dir = [f.name for f in self.ingestor_cache_directory.iterdir()]
        self.assertEqual(len(cache_dir), 8)
        self.assertIn(hashlib.sha256(data1).hexdigest(), cache_dir)
        self.assertIn(hashlib.sha256(data2).hexdigest(), cache_dir)

        base_processor = BaseYaraProcessor(self.retrohunt_settings.root_path, self.indexer_cfg_name, 10000)
        index_dirs = list(base_processor._iter_parent_index_dirs())
        # Should just be the periodic directory
        self.assertEqual(len(index_dirs), 1)
        periodic_dir = list(index_dirs[0].iterdir())[0]
        self.assertEqual(periodic_dir.name, self.retrohunt_settings.periodic_index_folder_name)
        # Three metadata files plus the three contents indexed. - 4th content is ignored because it happens after
        # Periodic is triggered.
        self.assertEqual(len(list(periodic_dir.iterdir())), 6)

    def test_periodic_index_doesnt_work_when_set_less_than_0(self):
        data1: bytes = b"here is some content to index"
        data2: bytes = b"Some other content"
        data3: bytes = b"Some other content that is different to the other 2."
        self.indexers_cfg[self.indexer_cfg_name].periodic_index_frequency_min = 0
        # Reapply config to allow config changes to affect the plugin run
        self._reapply_indexer_cfg()
        # Add Run plugin against 2 files and a periodic index should be created.
        self.do_execution(
            data_in=[("content", data1), ("content", data2), ("content", data3)], no_multiprocessing=True
        )

        cache_dir = [f.name for f in self.ingestor_cache_directory.iterdir()]
        self.assertEqual(len(cache_dir), 6)
        self.assertIn(hashlib.sha256(data1).hexdigest(), cache_dir)
        self.assertIn(hashlib.sha256(data2).hexdigest(), cache_dir)

        base_processor = BaseYaraProcessor(self.retrohunt_settings.root_path, self.indexer_cfg_name, 10000)
        index_dirs = list(base_processor._iter_parent_index_dirs())
        # Periodic directory doesn't exist because periodic frequency is less than 0
        self.assertEqual(len(index_dirs), 0)
