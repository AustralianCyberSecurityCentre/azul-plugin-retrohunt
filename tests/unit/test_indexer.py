from unittest import mock

import pendulum

from azul_plugin_retrohunt import test_utils
from azul_plugin_retrohunt.indexer import run_indexer
from azul_plugin_retrohunt.settings import RetrohuntSettings


def raise_exception(*args, **kwargs):
    raise Exception()


@mock.patch("pendulum.now", lambda: pendulum.parse("2002-01-08T10:10:10Z"))
class TestIndexer(test_utils.BaseIngestorIndexerTest):
    def _run_indexer_like_indexer_main(self):
        settings = RetrohuntSettings()
        indexer_cfg = settings.indexers.get(self.indexer_cfg_name, None)
        run_indexer(
            settings.root_path,
            settings.periodic_index_folder_name,
            settings.periodic_bgi_name,
            indexer_cfg,
        )

    def test_index_small_number_of_files(self):
        self.add_data_to_ingestor_and_ready_it_for_indexing(
            [b"file1", b"random other file2", b"a third for good luck"]
        )
        folder_to_be_indexed = next(self.indexer.get_folders_ready_for_indexing())
        self.assertTrue(folder_to_be_indexed.exists())
        self._run_indexer_like_indexer_main()
        # Verify bgi file was created and index dir was deleted.
        self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 1)
        self.assertFalse(folder_to_be_indexed.exists())

        # Verify that the directory isn't flagged as being indexed because it was successful.
        self.assertFalse(self.indexer.has_dir_failed_to_index_before(folder_to_be_indexed))

    def _base_periodic_indexing(self, data: list[bytes]):
        self.add_data_to_ingestor(data)
        self.ingestor.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)
        folder_to_be_indexed = next(self.indexer.get_folders_ready_for_indexing())
        self.assertTrue(folder_to_be_indexed.exists())
        self._run_indexer_like_indexer_main()

        # Verify bgi file was created and index dir was deleted.
        bgis = list(self.indexer.bgi_directory.iterdir())
        self.assertEqual(len(bgis), 1)
        self.assertEqual(bgis[0].name, self.retrohunt_settings.periodic_bgi_name + ".bgi")
        self.assertFalse(folder_to_be_indexed.exists())

        # Verify that the directory isn't flagged as being indexed because it was successful.
        self.assertFalse(self.indexer.has_dir_failed_to_index_before(folder_to_be_indexed))

    def test_indexing_periodically(self):
        """Check when the file name is periodic the bgi file created is periodic.bgi when indexing two files"""
        self._base_periodic_indexing([b"file1", b"random other file2"])

    def test_indexing_periodically_one_file(self):
        """Check when the file name is periodic the bgi file created is periodic.bgi when indexing a single file"""
        self._base_periodic_indexing([b"file1"])

    def test_indexing_periodically_with_dummy_file(self):
        """Test that when you attempt to index the dummy-file after it was already added nothing happens."""
        self.add_data_to_ingestor(
            [b"dummy-file"]
        )  # Should be the same value as the dummy file in the method copy_cache_for_indexer.
        self.ingestor.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)
        folder_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(0, len(folder_to_be_indexed))

    def test_indexing_periodically_no_files(self):
        """Test that when we attempt to create a periodic index with no files so it doesn't work."""
        self.add_data_to_ingestor([])
        self.ingestor.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)
        folder_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(0, len(folder_to_be_indexed))

    def _base_failing_to_index(self, data):
        """Fail enough times to cause an index to split."""
        with mock.patch("azul_plugin_retrohunt.bigyara.index.BigYaraIndexer.generate_index") as mock_gen_index:
            self.add_data_to_ingestor_and_ready_it_for_indexing(data)

            mock_gen_index.side_effect = raise_exception
            folder_to_be_indexed = next(self.indexer.get_folders_ready_for_indexing())
            self.assertTrue(folder_to_be_indexed.exists())
            self._run_indexer_like_indexer_main()
            # Verify bgi file failed to create due to the exception and that the original index dir still exists.
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            self.assertTrue(folder_to_be_indexed.exists())

            # Re-run and files should be split and then nothing indexed.
            self._run_indexer_like_indexer_main()
            # Nothing indexed because files were split and are ready for indexing next run.
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(len(folders_to_be_indexed), 2)

    def test_indexing_fails_multiple_times(self):
        """If the indexer fails to index multiple times the files failing to index should be deleted."""
        self._base_failing_to_index(
            [
                b"file1",
                b"random other file2",
                b"a third for good luck",
                b"forth for splitting",
                b"fifth because I can",
                b"six for saftey",
            ]
        )
        with mock.patch("azul_plugin_retrohunt.bigyara.index.BigYaraIndexer.generate_index") as mock_gen_index:
            mock_gen_index.side_effect = raise_exception

            # Another run should have no change except marking the first split dir for deletion.
            self._run_indexer_like_indexer_main()
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(len(folders_to_be_indexed), 2)
            self.assertTrue(self.indexer.has_dir_failed_to_index_before(folders_to_be_indexed[0]))

            # Another run should delete the first split directory
            self._run_indexer_like_indexer_main()
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(len(folders_to_be_indexed), 1)

            # two more runs should delete both split dirs.
            self._run_indexer_like_indexer_main()
            self._run_indexer_like_indexer_main()
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(len(folders_to_be_indexed), 0)

    def test_successful_index_after_split(self):
        """Get exceptions until an index ready directory is split and then successfully index the directory."""
        self._base_failing_to_index(
            [
                b"file1",
                b"random other file2",
                b"a third for good luck",
                b"forth for splitting",
                b"fifth because I can",
                b"six for saftey",
            ]
        )
        # Successfully index the split directories.
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(folders_to_be_indexed), 2)
        self._run_indexer_like_indexer_main()
        self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 2)
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(folders_to_be_indexed), 0)

    def test_successful_index_one_directory_after_split(self):
        """Get exceptions until an index ready directory is split and then successfully index one of the splits.

        The second split will fail to index because there is only one file and biggrep won't index a single file.
        """
        self._base_failing_to_index(
            [
                b"file1",
                b"random other file2",
                b"a third for good luck",
            ]
        )
        # Successfully index the first split directories.
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(folders_to_be_indexed), 2)
        self._run_indexer_like_indexer_main()
        self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 1)
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(folders_to_be_indexed), 1)

        # Fail to index the second split directory because there is only one file in it.
        # It is then deleted.
        self._run_indexer_like_indexer_main()
        self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 1)
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(folders_to_be_indexed), 0)

    def test_successful_index_one_directory_after_periodic_split(self):
        """Get exceptions until an index ready directory is split and then successfully index both of the splits into once periodic.bgi file."""
        with mock.patch("azul_plugin_retrohunt.bigyara.index.BigYaraIndexer.generate_index") as mock_gen_index:
            self.add_data_to_ingestor(
                [
                    b"file1",
                    b"random other file2",
                    b"a third for good luck",
                    b"fourth? a third for good luck",
                ]
            )
            self.ingestor.copy_cache_for_indexer(self.retrohunt_settings.periodic_index_folder_name)

            mock_gen_index.side_effect = raise_exception
            folder_to_be_indexed = next(self.indexer.get_folders_ready_for_indexing())
            self.assertTrue(folder_to_be_indexed.exists())
            self._run_indexer_like_indexer_main()
            # Verify bgi file failed to create due to the exception and that the original index dir still exists.
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            self.assertTrue(folder_to_be_indexed.exists())

            # Re-run and files should be split and then nothing indexed.
            self._run_indexer_like_indexer_main()
            # Nothing indexed because files were split and are ready for indexing next run.
            self.assertEqual(len(list(self.indexer.bgi_directory.iterdir())), 0)
            folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
            self.assertEqual(len(folders_to_be_indexed), 2)

        # Successfully index the split directories and override periodic.bgi until there is only one copy.
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertIn(
            self.retrohunt_settings.periodic_index_folder_name,
            folders_to_be_indexed[0].name,
        )
        self.assertIn(
            self.retrohunt_settings.periodic_index_folder_name,
            folders_to_be_indexed[1].name,
        )
        self.assertEqual(len(folders_to_be_indexed), 2)
        self._run_indexer_like_indexer_main()
        bgi_indices = list(self.indexer.bgi_directory.iterdir())
        self.assertEqual(len(bgi_indices), 1)
        self.assertEqual(bgi_indices[0].name, self.retrohunt_settings.periodic_bgi_name + ".bgi")
        folders_to_be_indexed = list(self.indexer.get_folders_ready_for_indexing())
        self.assertEqual(len(folders_to_be_indexed), 0)
