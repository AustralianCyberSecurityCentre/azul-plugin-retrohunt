"""Offline tests for bounded, read-only index batch downloads."""

import hashlib
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from azul_plugin_retrohunt.index_provider import IndexUnavailable, ObjectIndexProvider


class FakeStorage:
    def __init__(self, payloads, keys=None):
        self.payloads = payloads
        self.keys = (
            keys
            if keys is not None
            else [
                key
                for index_id in payloads
                for key in (
                    f"retrohunt/indices/{index_id}.bgi",
                    f"retrohunt/indices/{index_id}.ready",
                )
            ]
        )
        self.reads = 0

    def list_keys(self, prefix):
        return (key for key in self.keys if key.startswith(prefix))

    def object_size(self, key):
        return len(self.payloads[Path(key).stem])

    @contextmanager
    def read_chunks(self, key):
        self.reads += 1
        data = self.payloads[Path(key).stem]
        yield iter([data[:5], data[5:]])


def provider(tmp_path, store, limit=50):
    settings = SimpleNamespace(
        index_cache_dir=str(tmp_path),
        index_fetch_workers=2,
        index_cache_max_bytes=limit,
        index_cache_target_bytes=limit * 8 // 9,
        index_cache_free_bytes=0,
        index_list_timeout_seconds=30,
        index_fetch_timeout_seconds=30,
    )
    return ObjectIndexProvider(settings, storage=store)


def test_listing_requires_ready_and_bgi(tmp_path, monkeypatch):
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)

    data = b"sample-index-bytes"
    digest = hashlib.sha256(data).hexdigest()
    store = FakeStorage({digest: data})

    result = provider(tmp_path, store)
    assert result.list_indexes() == [digest]

    store.keys = [f"retrohunt/indices/{digest}.bgi"]

    with pytest.raises(IndexUnavailable, match="No published"):
        result.list_indexes()


def test_batches_enforce_limit_and_cleanup_before_next(tmp_path, monkeypatch):
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)

    payloads = {hashlib.sha256(bytes([i]) * 12).hexdigest(): bytes([i]) * 12 for i in range(5)}

    result = provider(tmp_path, FakeStorage(payloads), limit=25)
    seen = []

    for batch, before, count, total in result.iter_search_batches():
        assert sum(p.stat().st_size for p in batch.glob("*.bgi")) <= 25
        assert len(list(batch.glob("*.bgi"))) == count
        assert total == 5
        assert before == len(seen)

        seen.extend(p.stem for p in batch.glob("*.bgi"))
        assert sorted(p.read_bytes() for p in batch.glob("*.bgi"))

    assert sorted(seen) == sorted(payloads)
    assert not list(tmp_path.glob(".hunt-batch-*"))
    # Verified indexes persist between hunts, bounded by the cache budget.
    assert 0 < sum(p.stat().st_size for p in tmp_path.glob("*.bgi")) <= 25


def test_corrupt_index_never_exposed_and_cleans_up(tmp_path, monkeypatch):
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)

    key = hashlib.sha256(b"real bytes").hexdigest()
    result = provider(tmp_path, FakeStorage({key: b"fake bytes"}))

    with pytest.raises(IndexUnavailable, match="checksum mismatch"):
        list(result.iter_search_batches())

    assert not list(tmp_path.glob(".hunt-batch-*"))
    assert not list(tmp_path.rglob("*.bgi"))


def test_oversize_index_fails_before_fetch(tmp_path, monkeypatch):
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)

    value = b"too-large-data"
    key = hashlib.sha256(value).hexdigest()
    store = FakeStorage({key: value})

    result = provider(tmp_path, store, limit=5)

    with pytest.raises(IndexUnavailable, match="cannot fit"):
        list(result.iter_search_batches())

    assert store.reads == 0


def test_stale_indexes_not_in_snapshot(tmp_path, monkeypatch):
    """Unlisted cached indexes are not searched or silently deleted."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)

    value = b"current"
    digest = hashlib.sha256(value).hexdigest()
    stale = hashlib.sha256(b"old").hexdigest()

    stale_path = tmp_path / f"{stale}.bgi"
    stale_path.write_bytes(b"old")

    result = provider(tmp_path, FakeStorage({digest: value}))

    batches = []
    for batch_dir, _, _, _ in result.iter_search_batches():
        batches.extend(p.stem for p in batch_dir.glob("*.bgi"))
    assert batches == [digest]

    # Existing data must not be silently deleted.
    assert stale_path.read_bytes() == b"old"

    # No new batch should have been retained.
    assert not list(tmp_path.glob(".hunt-batch-*"))


def test_verified_cache_is_reused_across_hunts(tmp_path, monkeypatch):
    """A second hunt should reuse a verified index from its worker's persistent cache."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    data = b"persistent-index"
    digest = hashlib.sha256(data).hexdigest()
    store = FakeStorage({digest: data})
    result = provider(tmp_path, store, limit=50)

    for batch, *_ in result.iter_search_batches():
        assert (batch / f"{digest}.bgi").read_bytes() == data
    assert store.reads == 1
    assert (tmp_path / f"{digest}.bgi").read_bytes() == data

    for batch, *_ in result.iter_search_batches():
        assert (batch / f"{digest}.bgi").read_bytes() == data
    assert store.reads == 1  # Not downloaded again.


def test_mixed_legacy_and_partitioned_indexes_use_correct_keys(tmp_path, monkeypatch):
    """Legacy and partitioned indexes are all downloaded without type filtering."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    payloads = {hashlib.sha256(blob).hexdigest(): blob for blob in (b"legacy-index", b"windows-index", b"elf-index")}
    legacy, windows, elf = list(payloads)
    paths = {
        legacy: legacy,
        windows: f"windows/1m-10m/{windows}",
        elf: f"elf/lt1m/{elf}",
    }
    prefix = "retrohunt/indices/"
    keys = [prefix + path + suffix for path in paths.values() for suffix in (".bgi", ".ready")]

    class TrackingStorage(FakeStorage):
        def __init__(self):
            super().__init__(payloads, keys)
            self.head_keys = []
            self.download_keys = []

        def object_size(self, key):
            self.head_keys.append(key)
            return super().object_size(key)

        @contextmanager
        def read_chunks(self, key):
            self.download_keys.append(key)
            with super().read_chunks(key) as chunks:
                yield chunks

    store = TrackingStorage()
    result = provider(tmp_path, store, limit=100)
    assert result.list_indexes() == sorted(payloads)
    assert result.index_keys == {ident: path + ".bgi" for ident, path in paths.items()}

    seen = set()
    for batch, *_ in result.iter_search_batches():
        seen.update(path.stem for path in batch.glob("*.bgi"))
    assert seen == set(payloads)
    assert set(store.head_keys) == {prefix + path + ".bgi" for path in paths.values()}
    assert set(store.download_keys) == {prefix + path + ".bgi" for path in paths.values()}


def test_partition_ready_must_match_bgi_location(tmp_path, monkeypatch):
    """A marker in another partition cannot publish an incomplete index."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    data = b"unpublished"
    ident = hashlib.sha256(data).hexdigest()
    prefix = "retrohunt/indices/"
    store = FakeStorage(
        {ident: data},
        [
            f"{prefix}windows/lt1m/{ident}.bgi",
            f"{prefix}elf/lt1m/{ident}.ready",
        ],
    )
    with pytest.raises(IndexUnavailable, match="No published"):
        provider(tmp_path, store).list_indexes()


def test_duplicate_index_hash_downloaded_once(tmp_path, monkeypatch):
    """The same content in two partitions is a single sharding/cache identity."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    data = b"same-index"
    ident = hashlib.sha256(data).hexdigest()
    prefix = "retrohunt/indices/"
    keys = [
        prefix + path + suffix
        for path in (f"windows/lt1m/{ident}", f"elf/lt1m/{ident}")
        for suffix in (".bgi", ".ready")
    ]
    store = FakeStorage({ident: data}, keys)
    result = provider(tmp_path, store)
    assert result.list_indexes() == [ident]
    assert result.index_keys[ident] == f"elf/lt1m/{ident}.bgi"
    assert sum(batch[2] for batch in result.iter_search_batches()) == 1
    assert store.reads == 1


def test_rejects_unrecognised_partition_paths(tmp_path, monkeypatch):
    """Ignore unexpected nested keys instead of treating them as indexes."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    data = b"index"
    ident = hashlib.sha256(data).hexdigest()
    prefix = "retrohunt/indices/"
    keys = [
        prefix + path + suffix
        for path in (f"../../{ident}", f"windows/wrong-size/{ident}", f"badtype/lt1m/{ident}")
        for suffix in (".bgi", ".ready")
    ]
    with pytest.raises(IndexUnavailable, match="No published"):
        provider(tmp_path, FakeStorage({ident: data}, keys)).list_indexes()
