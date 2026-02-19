import pytest
from prometheus_client import REGISTRY
from unittest import mock
from pathlib import Path
import shutil


# ------------------------------------------------------------
# FIX 1: Reset Prometheus registry before every test
# ------------------------------------------------------------
@pytest.fixture(autouse=True)
def reset_prometheus_registry():
    """
    Prometheus metrics are global singletons. The indexer module registers
    counters at import time, so running multiple tests causes duplicate
    metric registration unless we clear the registry each time.
    """
    collectors = list(REGISTRY._collector_to_names.keys())
    for c in collectors:
        try:
            REGISTRY.unregister(c)
        except KeyError:
            pass

    yield


# ------------------------------------------------------------
# FIX 2: BigYara mock with correct behavior
# ------------------------------------------------------------
@pytest.fixture(autouse=True, scope="function")
def mock_bigyara():
    """
    Fully-correct BigYara mock that:
    - Fails on single-file directories (size-based split behavior)
    - Writes periodic indexes to periodic.bgi
    - Writes size-based indexes to <folder>.bgi
    - Deletes the folder after successful indexing
    - Ignores metadata files when counting content
    """

    # Prevent env import side effects
    with mock.patch.dict(
        "sys.modules",
        {"azul_plugin_retrohunt.bigyara.env": mock.MagicMock()}
    ):

        def count_content_files(folder_path: Path) -> int:
            """Count only real content files (exclude BigYara metadata)."""
            return sum(
                1
                for p in folder_path.iterdir()
                if p.is_file()
                and not p.name.startswith(".")
                and not p.name.endswith("-meta")
            )

        def fake_generate_index(self, folder_path, bgi_name_override=None, *_):
            folder_path = Path(folder_path)
            print("DEBUG FILES IN", folder_path)
            for p in folder_path.iterdir():
                print("   ", p.name)

            # FAIL if only one real content file (size-based split behavior)
            if count_content_files(folder_path) <= 1:
                raise Exception("BigYara cannot index a single file")

            # PERIODIC INDEXING: override name
            if bgi_name_override:
                index_file = Path(self.bgi_directory) / bgi_name_override
            else:
                index_file = Path(self.bgi_directory) / folder_path.name

            # Create the .bgi file
            Path(self.bgi_directory).mkdir(parents=True, exist_ok=True)
            (index_file.with_suffix(".bgi")).touch()

            # Delete the folder (real BigYara behavior)
            shutil.rmtree(folder_path)

            return True

        with mock.patch(
            "azul_plugin_retrohunt.bigyara.index.BigYaraIndexer.generate_index",
            new=fake_generate_index
        ):
            yield