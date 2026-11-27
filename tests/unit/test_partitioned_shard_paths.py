"""Partitioned object paths must survive sharding without changing work splitting."""

import hashlib
from contextlib import contextmanager
from types import SimpleNamespace

from azul_plugin_retrohunt import distributed, index_provider


def test_assigned_shard_uses_partitioned_manifest_keys(tmp_path, monkeypatch):
    """A shard fetches its assigned objects by manifest path, not flat SHA path."""
    blobs = (b"windows-shard", b"elf-shard")
    payloads = {hashlib.sha256(blob).hexdigest(): blob for blob in blobs}
    ids = list(payloads)
    keys = {
        ids[0]: f"windows/lt1m/{ids[0]}.bgi",
        ids[1]: f"elf/1m-10m/{ids[1]}.bgi",
    }
    requested = []

    class Storage:
        def object_size(self, key):
            raise AssertionError("manifest sizes should avoid HEAD")

        @contextmanager
        def read_chunks(self, key):
            requested.append(key)
            assert key.startswith("retrohunt/indices/")
            yield [payloads[key.rsplit("/", 1)[-1][:-4]]]

    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    monkeypatch.setattr(index_provider, "create_storage", Storage)
    settings = SimpleNamespace(
        index_cache_dir=str(tmp_path),
        index_cache_max_bytes=100,
        index_cache_target_bytes=80,
        index_cache_free_bytes=0,
        index_list_timeout_seconds=30,
        index_fetch_timeout_seconds=30,
        index_download_workers=2,
    )
    shard = distributed.AssignedIndexProvider(
        settings, ids, {ident: len(payloads[ident]) for ident in ids}, keys
    )
    seen = set()
    for batch, *_ in shard.iter_search_batches():
        seen.update(path.stem for path in batch.glob("*.bgi"))
    assert seen == set(ids)
    assert set(requested) == {"retrohunt/indices/" + key for key in keys.values()}


def test_partition_paths_do_not_change_shard_assignment():
    """Assignment remains deterministic and balanced by size, not S3 prefixes."""
    indexes = [("a" * 64, 100), ("b" * 64, 70), ("c" * 64, 40), ("d" * 64, 20)]
    first = distributed.partition_indexes(indexes, 2)
    second = distributed.partition_indexes(indexes, 2)
    assert first == second
    assigned = [ident for shard in first for ident in shard["ids"]]
    assert sorted(assigned) == sorted(ident for ident, _ in indexes)
    assert len(assigned) == len(set(assigned))
