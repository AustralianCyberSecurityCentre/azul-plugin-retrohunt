import os
import pathlib
import re
from typing import Callable
from unittest import mock

import pendulum

from azul_plugin_retrohunt import test_utils
from azul_plugin_retrohunt.bigyara.base_processor import METADATA_SUFFIX, SPLIT_DIR_SUFFIX
from azul_plugin_retrohunt.settings import BGI_DIR_NAME, STATE_DIR_NAME


# Set fixed date for all tests.
@mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z"))
class TestBigYaraIndexing(test_utils.BaseIngestorIndexerTest):
    def test_directories_are_correct(self):
        self.assertEqual(
            str(self.indexer.base_directory),
            os.path.join(self.base_temp_dir, self.indexer._processor_name),
        )
        self.assertEqual(
            str(self.indexer.bgi_directory),
            os.path.join(self.indexer.base_directory, BGI_DIR_NAME),
        )

        self.assertEqual(
            str(self.indexer.state_directory),
            os.path.join(self.indexer.base_directory, STATE_DIR_NAME),
        )

    def _setup_standard_ingested_content(self):
        # hashes for this folder are:
        # fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13
        # 60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752
        # 1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014
        self.add_data_to_ingestor_and_ready_it_for_indexing([b"test1", b"test2", b"test3"])

        self.add_data_to_ingestor_and_ready_it_for_indexing([b"test4", b"test5", b"test6"])
        self.add_data_to_ingestor_and_ready_it_for_indexing([b"test7", b"test8", b"test9"])

    def test_get_folders_ready_for_indexing(self):
        # Setup a reasonable folder structure by ingesting data.
        self._setup_standard_ingested_content()
        self.assertEqual(
            list(self.indexer.get_folders_ready_for_indexing()),
            [
                pathlib.Path(self.base_temp_dir, self.indexer_cfg_name, "20020108", "1"),
                pathlib.Path(self.base_temp_dir, self.indexer_cfg_name, "20020108", "2"),
                pathlib.Path(self.base_temp_dir, self.indexer_cfg_name, "20020108", "3"),
            ],
        )

    def test_get_folders_ready_for_indexing_only_one_folder(self):
        # Setup a reasonable folder structure by ingesting data.
        self.add_data_to_ingestor_and_ready_it_for_indexing([b"test1", b"test2", b"test3"])
        self.assertEqual(
            list(self.indexer.get_folders_ready_for_indexing()),
            [pathlib.Path(self.base_temp_dir, self.indexer_cfg_name, "20020108", "1")],
        )

    def test_get_next_index_path(self):
        new_bgi_path = self.indexer._get_next_index_path()
        expected_bgi_path = pathlib.Path(self.indexer.bgi_directory, "20020108T1010")
        self.assertEqual(str(new_bgi_path), str(expected_bgi_path))

        # increment by 1
        expected_bgi_path.with_name(expected_bgi_path.name + ".bgi").touch()
        new_bgi_path = self.indexer._get_next_index_path()
        expected_second_bgi_path = expected_bgi_path.with_name(expected_bgi_path.name + ".001")
        self.assertEqual(str(new_bgi_path), str(expected_second_bgi_path))

        # increment by 2
        expected_second_bgi_path.with_name(expected_second_bgi_path.name + ".bgi").touch()
        new_bgi_path = self.indexer._get_next_index_path()
        expected_third_bgi_path = expected_bgi_path.with_name(expected_bgi_path.name + ".002")
        self.assertEqual(str(new_bgi_path), str(expected_third_bgi_path))

    def test_get_files_to_index_with_meta(self):
        self._setup_standard_ingested_content()
        folder_iter = self.indexer.get_folders_ready_for_indexing()
        first_folder = next(folder_iter)
        first_folder_path = os.path.join(self.base_temp_dir, self.indexer_cfg_name, "20020108", "1")
        print(f"Checking first folder {first_folder} which should be '{first_folder_path}'")
        # Base dir for content
        abs_path_list = list(self.indexer._get_files_to_index_with_meta(first_folder))
        self.assertCountEqual(
            abs_path_list,
            [
                os.path.join(
                    first_folder_path,
                    "fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13,stream_label=content,stream_source=testing",
                ),
                os.path.join(
                    first_folder_path,
                    "60303ae22b998861bce3b28f33eec1be758a213c86c93c076dbe9f558c11c752,stream_label=content,stream_source=testing",
                ),
                os.path.join(
                    first_folder_path,
                    "1b4f0e9851971998e732078544c96b36c3d01cedf7caa332359d6f1d83567014,stream_label=content,stream_source=testing",
                ),
            ],
        )

        # /tmp/tmpo_4990olretrohunt_/content/20020108/1/fd61a03af4f77d870fc21e05e7e80678095c92d808cfb3b5c279ee04c74aca13

    def test_generate_index(self):
        self._setup_standard_ingested_content()

        for f in self.indexer.get_folders_ready_for_indexing():
            self.indexer.generate_index(f)

        self.assertCountEqual(
            [bgi_file.name for bgi_file in self.indexer.bgi_directory.iterdir()],
            ["20020108T1010.bgi", "20020108T1010.001.bgi", "20020108T1010.002.bgi"],
        )

        # Verify BGI isn't empty
        bgi_file = pathlib.Path(self.indexer.bgi_directory, "20020108T1010.bgi")
        self.assertGreater(bgi_file.stat().st_size, 5000)

    def test_generate_index_with_bad_file(self):
        self._setup_standard_ingested_content()

        for f in self.indexer.get_folders_ready_for_indexing():
            # Add a bad file during indexing (should be ignored with a warning.)
            f.joinpath("BadFile.txt").touch()
            self.indexer.generate_index(f)

        # Verify that all the indexed directories were deleted.
        self.assertEqual(len(list(self.indexer.get_folders_ready_for_indexing())), 0)

        # Verify only the 3 bad text files were skipped while indexing.
        self.assertEqual(self.indexer.files_ignored_while_indexing, 3)

        self.assertCountEqual(
            [bgi_file.name for bgi_file in self.indexer.bgi_directory.iterdir()],
            ["20020108T1010.bgi", "20020108T1010.001.bgi", "20020108T1010.002.bgi"],
        )

        # Verify BGI isn't empty
        bgi_file = pathlib.Path(self.indexer.bgi_directory, "20020108T1010.bgi")
        self.assertGreater(bgi_file.stat().st_size, 5000)

    def test_generate_index_with_periodic_file(self):
        self.add_data_to_ingestor_and_ready_it_for_periodic_indexing([b"test1", b"test2", b"test3"])
        print(list(pathlib.Path("/tmp").iterdir()))

        for f in self.indexer.get_folders_ready_for_indexing():
            self.indexer.generate_index(f, self.retrohunt_settings.periodic_bgi_name)

        x_test = [bgi_file.name for bgi_file in self.indexer.bgi_directory.iterdir()]
        self.assertCountEqual(
            [bgi_file.name for bgi_file in self.indexer.bgi_directory.iterdir()],
            [self.retrohunt_settings.periodic_bgi_name + ".bgi"],
        )

        # Verify BGI isn't empty
        bgi_file = pathlib.Path(
            self.indexer.bgi_directory,
            self.retrohunt_settings.periodic_bgi_name + ".bgi",
        )
        self.assertGreater(bgi_file.stat().st_size, 5000)

    def test_save_and_load_a_directory_has_been_indexed(self):
        path_that_has_been_indexed = pathlib.Path(self.base_temp_dir, self.indexer._processor_name, "random-folder")
        state_file_path = self.indexer.last_dir_read_state_file_path
        # State file doesn't exist yet.
        self.assertFalse(state_file_path.exists())
        self.assertFalse(self.indexer.has_dir_failed_to_index_before(path_that_has_been_indexed))
        # Set it to having been indexed and check value.
        self.indexer.save_indexing_dir(path_that_has_been_indexed)
        # File now exists.
        self.assertTrue(state_file_path.exists())
        self.assertTrue(self.indexer.has_dir_failed_to_index_before(path_that_has_been_indexed))
        self.indexer.save_indexing_dir(
            path_that_has_been_indexed.with_name(path_that_has_been_indexed.name + "-changed")
        )
        self.assertFalse(self.indexer.has_dir_failed_to_index_before(path_that_has_been_indexed))

    def test_clear_directory_has_been_indexed(self):
        """Verify that clearing the fact a directory has been indexed means has_dir_been_indexed if false."""
        path_that_has_been_indexed = pathlib.Path(self.base_temp_dir, self.indexer._processor_name, "random-folder")
        self.indexer.save_indexing_dir(path_that_has_been_indexed)
        self.assertTrue(self.indexer.has_dir_failed_to_index_before(path_that_has_been_indexed))
        self.indexer.clear_indexing_dir()
        self.assertFalse(self.indexer.has_dir_failed_to_index_before(path_that_has_been_indexed))

    def test_split_or_delete_indexing_dir(self):
        # Setup a single directory ready to index.
        data_to_add_for_indexing = [
            b"test1",
            b"test2",
            b"test3",
            b"test4",
            b"test5",
            b"test6",
            b"test7",
            b"test8",
            b"test9",
        ]
        self.add_data_to_ingestor_and_ready_it_for_indexing(data_to_add_for_indexing)
        index_ready_folder = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(index_ready_folder), 1)
        index_ready_folder_path = index_ready_folder[0]
        # Split the one file
        self.indexer.split_or_delete_indexing_dir(index_ready_folder_path)
        # Check that all hashes and metadata split appropriately.
        split_dir1 = index_ready_folder_path.with_name(index_ready_folder_path.name + SPLIT_DIR_SUFFIX + "-part1")
        files = list(split_dir1.iterdir())
        self.assertEqual(len(files), 10)  # 5 files + 5 metadata files
        split_dir2 = index_ready_folder_path.with_name(index_ready_folder_path.name + SPLIT_DIR_SUFFIX + "-part2")
        self.assertEqual(len(list(split_dir2.iterdir())), 8)  # 4 files + 4 metadata files

        # Check that every raw binary has it's metadata.
        sha256_regex = re.compile("^[a-fA-F0-9]{64}$")
        matches = 0
        all_files = [str(f) for f in files]
        for f in files:
            # If the file name is just the sha256.
            if sha256_regex.fullmatch(f.name) is not None:
                matches += 1
                self.assertIn(str(f.with_name(f.name + METADATA_SUFFIX)), all_files)
        self.assertEqual(matches, 5)

        # Check what happens on reloading indexers
        index_ready_folder = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(index_ready_folder), 2)
        first_split_dir = index_ready_folder[0]
        # Verify this is a split dir.
        self.assertIn(SPLIT_DIR_SUFFIX, str(first_split_dir))
        self.indexer.split_or_delete_indexing_dir(first_split_dir)

        # Verify rather than being split directory was deleted, because it was already split once.
        self.assertFalse(first_split_dir.exists())
        index_ready_folder = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(index_ready_folder), 1)

    def test_split_then_index_the_two_dirs(self):
        # Setup a single directory ready to index.
        data_to_add_for_indexing = [
            b"test1",
            b"test2",
            b"test3",
            b"test4",
            b"test5",
            b"test6",
            b"test7",
            b"test8",
            b"test9",
        ]
        self.add_data_to_ingestor_and_ready_it_for_indexing(data_to_add_for_indexing)
        index_ready_folder = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(index_ready_folder), 1)
        index_ready_folder_path = index_ready_folder[0]
        # Split the one file
        self.indexer.split_or_delete_indexing_dir(index_ready_folder_path)
        for f in self.indexer.get_folders_ready_for_indexing():
            self.indexer.generate_index(f)

        # Indexed both part directories.
        self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 2)

    def _base_cleanup_test(self, cleanup_method: Callable):
        """Base test for checking if bgi cleanup works on init and on direct method call."""
        self._setup_standard_ingested_content()
        # Good bgi files that shouldn't get deleted.
        for f in self.indexer.get_folders_ready_for_indexing():
            self.indexer.generate_index(f)
        # Random hidden bgi file we want to get cleaned up and deleted.
        hidden_bgi = ".20201231T1111.bgi"
        self.indexer.bgi_directory.joinpath(hidden_bgi).touch()

        bgi_file_names = list(bgi_file.name for bgi_file in self.indexer.bgi_directory.iterdir())
        self.assertIn(hidden_bgi, bgi_file_names)
        self.assertEqual(len(bgi_file_names), 4)

        cleanup_method()

        # Expected bgi files after purge.
        bgi_files = [bgi_file.name for bgi_file in self.indexer.bgi_directory.iterdir()]
        self.assertEqual(len(bgi_files), 3)
        self.assertCountEqual(
            bgi_files,
            ["20020108T1010.bgi", "20020108T1010.001.bgi", "20020108T1010.002.bgi"],
        )

    def test_cleanup_old_bgis(self):
        self._base_cleanup_test(self.indexer._cleanup_old_bgis)

    def test_cleanup_old_bgis_at_index_time(self):
        called = False

        def wrap_index_call():
            nonlocal called
            called = True
            self.assertRaises(
                Exception,
                self.indexer.generate_index,
                pathlib.Path(self.base_temp_dir, "Random-path-that-shouldn't-exist"),
            )

        self._base_cleanup_test(wrap_index_call)
        # Verify the test method was called.
        self.assertTrue(called)
