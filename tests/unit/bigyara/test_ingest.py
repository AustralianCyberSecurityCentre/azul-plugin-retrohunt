import os
import shutil
from unittest import mock

import pendulum

from azul_plugin_retrohunt import test_utils
from azul_plugin_retrohunt.bigyara.base_processor import METADATA_SUFFIX
from azul_plugin_retrohunt.bigyara.ingest import IngestFileSizeException
from azul_plugin_retrohunt.models import FileMetadata
from azul_plugin_retrohunt.settings import CACHE_DIR_NAME


class TestBigYaraIngest(test_utils.BaseIngestorIndexerTest):
    def test_cache_dir_exists(self):
        self.assertEqual(
            str(self.ingestor.cache_directory),
            os.path.join(self.ingestor.base_directory, CACHE_DIR_NAME),
        )
        # Cache directory should exist
        self.assertTrue(self.ingestor.cache_directory.exists())
        # Attempts to re-create cause no harm to the cache dir.
        self.ingestor.create_cache_dir()
        self.assertTrue(self.ingestor.cache_directory.exists())

    def test_add_data_to_index_cache(self):
        self.ingestor.add_data_to_index_cache(
            b"abcdefghijklmnopqrstuvwxyz",
            FileMetadata(stream_label="content", stream_source="testing"),
        )
        # Should have the original file and it's metadata added.
        data = list(self.ingestor.cache_directory.iterdir())
        self.assertEqual(len(data), 2)
        # Check if both files have the appropriate content.
        for f in data:
            with open(f, "r") as rf:
                raw_str = rf.read()
            if METADATA_SUFFIX in f.name:
                meta = FileMetadata.model_validate_json(raw_str)
                self.assertEqual(meta.stream_label, "content")
                self.assertEqual(meta.stream_source, "testing")
            else:
                self.assertEqual(raw_str, "abcdefghijklmnopqrstuvwxyz")

    def test_create_path_to_file_in_cache(self):
        path = self.ingestor._create_path_to_file_in_cache("random_not_actually_sha256")
        self.assertEqual(path.name, "random_not_actually_sha256")

    def test_count_number_of_bytes_in_cache_dir(self):
        self.ingestor.add_data_to_index_cache(
            b"abcdefghijklmnopqrstuvwxyz",
            FileMetadata(stream_label="content", stream_source="testing"),
        )
        self.ingestor.add_data_to_index_cache(
            b"random-other-data",
            FileMetadata(stream_label="content", stream_source="testing"),
        )
        bytes_in_cache_dir = self.ingestor._count_number_of_bytes_in_cache_dir()
        # Number of bytes in directory excluding metadata
        self.assertEqual(bytes_in_cache_dir, 43)
        bytes_in_cache_dir_alt = self.indexer.count_bytes_for_dir(self.ingestor.cache_directory)
        # Number of bytes in directory including metadata
        self.assertEqual(bytes_in_cache_dir_alt, 175)

    def test_cleanup_old_ingest_dirs(self):
        with mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z")):
            self.ingestor.create_cache_dir()
            self.ingestor._move_cache_for_indexer()
            # Create an empty directory.
            folders_ready_for_indexing = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(len(folders_ready_for_indexing), 1)

            parent = None
            for f in folders_ready_for_indexing:
                parent = f.parent
                f.rmdir()

            self.assertTrue(parent.exists())
            # Cleanup the empty parent directory
            self.ingestor.cleanup_old_ingest_dirs()
            self.assertFalse(parent.exists())

    def test_can_file_size_can_be_added(self):
        self.modify_content_max_bytes_indexing_config(100)
        self.recreate_content_ingestor()
        # check a file too big too small and in the range.
        basic_meta = FileMetadata(stream_label="content", stream_source="testing")
        self.assertRaises(IngestFileSizeException, self.ingestor._can_file_size_can_be_added, 3)
        self.assertRaises(
            IngestFileSizeException,
            self.ingestor.add_data_to_index_cache,
            b"abc",
            basic_meta,
        )
        self.ingestor._can_file_size_can_be_added(40)
        self.ingestor.add_data_to_index_cache(b"abcdefghijklmnopqrstuvwxyz", basic_meta)
        self.assertRaises(IngestFileSizeException, self.ingestor._can_file_size_can_be_added, 500)
        self.assertRaises(
            IngestFileSizeException,
            self.ingestor.add_data_to_index_cache,
            b"kjlasdfjasdkfjkasdfkjaskjdfjskdjf askdjf kajsdfjkasdf jkasdfkjasdfkjasdkfj aksdfj akjsdfk jasdfkjaskdfjskadjfjkasdf jkasdf jkasjdfk jasdfjkasdk fsajd fkasdfjkksajd jksa fedksajdkfkjasdfkjsa kdfjkasd fkjasdk fjaskjdf jksd",
            basic_meta,
        )

    def test_get_path_of_next_ingest_ready_dir(self):
        with mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z")):
            path = self.ingestor.get_path_of_next_ingest_ready_dir()
            self.add_data_to_ingestor_and_ready_it_for_indexing([b"abcdef"])
            self.assertEqual(str(path), os.path.join(self.ingestor.base_directory, "20020108", "1"))

            path = self.ingestor.get_path_of_next_ingest_ready_dir()
            self.add_data_to_ingestor_and_ready_it_for_indexing([b"abcdef"])
            self.assertEqual(str(path), os.path.join(self.ingestor.base_directory, "20020108", "2"))

            path = self.ingestor.get_path_of_next_ingest_ready_dir()
            self.add_data_to_ingestor_and_ready_it_for_indexing([b"abcdefd"])
            self.assertEqual(str(path), os.path.join(self.ingestor.base_directory, "20020108", "3"))

    def test_order_of_child_directories_when_getting_index_directories(self):
        """Verify that the child directories ready for indexing are in the correct order.

        Correct order is oldest date folder.
        all child folders in numerical order followed by non-numeric directories
        """
        one_to_two_hund = list(str(i) for i in range(1, 201))
        newer_one_to_ten = list(str(i) for i in range(1, 11))
        with mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z")):
            # Create 200 sub directories for the current date.
            for _i in one_to_two_hund:
                self.add_data_to_ingestor_and_ready_it_for_indexing([b"abcdef"])

        # one day newer
        with mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-09T10:10:10Z")):
            # Create 200 sub directories for the current date.
            for _i in newer_one_to_ten:
                self.add_data_to_ingestor_and_ready_it_for_indexing([b"abcdef"])

        dirs = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual([d.name for d in dirs], one_to_two_hund + newer_one_to_ten)

        # create a string folder in the second directory
        dirs[-1].parent.joinpath("string-folder").touch()
        # re-read the directory with the new file added.
        dirs = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(
            [d.name for d in dirs],
            one_to_two_hund + newer_one_to_ten + ["string-folder"],
        )

    def test_copy_cache_directory(self):
        one_to_ten = list(str(i) for i in range(1, 10))
        with mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z")):
            self.add_data_to_ingestor_and_ready_it_for_periodic_indexing(
                [b"abcdef", b"ghijklmn", b"opqrstu", b"vwxyz"]
            )
            # Check contents of cache directory is equal to contents of periodic directory.
            dirs = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(
                [d.name for d in dirs],
                [self.retrohunt_settings.periodic_index_folder_name],
            )
            self.assertEqual(len(dirs), 1)
            self.assertCountEqual(
                [x.name for x in dirs[0].iterdir()],
                [y.name for y in self.ingestor.cache_directory.iterdir()],
            )

            # Attempt to create multiple sub directories which should fail because the periodic index already exists.
            for i in one_to_ten:
                self.add_data_to_ingestor_and_ready_it_for_periodic_indexing([b"jdsklfjawceiascmei" + str(i).encode()])

            # Verify the cache now holds more files than the periodic directory due to more files being added to cache
            # And the files failing to copy to the periodic because it already exists
            self.assertGreater(
                len(list(self.ingestor.cache_directory.iterdir())),
                len(list(dirs[0].iterdir())),
            )

            # Remove the old periodic index file
            target_dir = self.ingestor.get_path_of_next_ingest_ready_dir()
            target_dir = target_dir.with_name(self.retrohunt_settings.periodic_index_folder_name)
            shutil.rmtree(target_dir)

            # Should be equal now because we re-copied.
            self.ingestor.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)
            self.assertEqual(
                len(list(self.ingestor.cache_directory.iterdir())),
                len(list(dirs[0].iterdir())),
            )
