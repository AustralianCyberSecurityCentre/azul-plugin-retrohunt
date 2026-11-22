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
    assert not list(tmp_path.glob("*.bgi"))


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
    """Legacy cache files must be detected rather than silently ignored."""
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)

    value = b"current"
    digest = hashlib.sha256(value).hexdigest()
    stale = hashlib.sha256(b"old").hexdigest()

    stale_path = tmp_path / f"{stale}.bgi"
    stale_path.write_bytes(b"old")

    result = provider(tmp_path, FakeStorage({digest: value}))

    with pytest.raises(IndexUnavailable, match=r"Legacy .bgi files found"):
        list(result.iter_search_batches())

    # Existing data must not be silently deleted.
    assert stale_path.read_bytes() == b"old"

    # No new batch should have been retained.
    assert not list(tmp_path.glob(".hunt-batch-*"))
