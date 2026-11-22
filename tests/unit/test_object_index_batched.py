"""Regression checks for bounded cloud-index search and storage adapters."""

import hashlib
import os
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from azul_plugin_retrohunt.index_provider import IndexUnavailable, ObjectIndexProvider
from azul_plugin_retrohunt.index_storage import S3IndexStorage, index_prefix


class MemoryStorage:
    def __init__(self, payloads):
        self.payloads = payloads
        self.sizes = []
        self.reads = []

    def list_keys(self, prefix):
        for name in self.payloads:
            yield prefix + name + ".bgi"
            yield prefix + name + ".ready"

    def object_size(self, key):
        self.sizes.append(key)
        return len(self.payloads[key.rsplit("/", 1)[-1][:-4]])

    def read_chunks(self, key):
        from contextlib import contextmanager

        @contextmanager
        def read():
            self.reads.append(key)
            payload = self.payloads[key.rsplit("/", 1)[-1][:-4]]
            yield iter([payload[:3], payload[3:]])

        return read()


class Settings:
    index_cache_max_bytes = 10
    index_list_timeout_seconds = 120
    index_fetch_timeout_seconds = 120

    def __init__(self, path):
        self.index_cache_dir = str(path)


def make_storage():
    blobs = [b"1234567", b"abcdefg", b"xyz1234"]
    return MemoryStorage({hashlib.sha256(blob).hexdigest(): blob for blob in blobs})


def test_s3_head_object_size():
    storage = object.__new__(S3IndexStorage)
    storage.bucket = "test-bucket"
    storage.client = MagicMock()
    storage.client.head_object.return_value = {"ContentLength": 1234}
    assert storage.object_size("prefix/hash.bgi") == 1234
    storage.client.head_object.assert_called_once_with(Bucket="test-bucket", Key="prefix/hash.bgi")


def test_bounded_batches_leave_no_files(tmp_path):
    storage = make_storage()
    provider = ObjectIndexProvider(Settings(tmp_path), storage=storage)
    seen = []
    for batch_path, offset, count, total in provider.iter_search_batches():
        entries = sorted(batch_path.glob("*.bgi"))
        assert count == len(entries) == 1
        assert sum(p.stat().st_size for p in entries) <= 10
        seen.extend(p.name for p in entries)
    assert len(seen) == 3
    assert not list(tmp_path.glob(".hunt-batch-*"))
    assert len(storage.reads) == 3


def test_index_too_large_fails_without_partial_success(tmp_path):
    blob = b"x" * 11
    storage = MemoryStorage({hashlib.sha256(blob).hexdigest(): blob})
    provider = ObjectIndexProvider(Settings(tmp_path), storage=storage)
    with pytest.raises(IndexUnavailable, match="cannot fit"):
        list(provider.iter_search_batches())
    assert not storage.reads


def test_corrupt_download_fails_closed(tmp_path):
    blob = b"valid"
    ident = hashlib.sha256(blob).hexdigest()

    class Corrupt(MemoryStorage):
        def read_chunks(self, key):
            from contextlib import contextmanager

            @contextmanager
            def read():
                yield iter([b"other"])

            return read()

    provider = ObjectIndexProvider(Settings(tmp_path), storage=Corrupt({ident: blob}))
    with pytest.raises(IndexUnavailable, match="checksum mismatch"):
        list(provider.iter_search_batches())
    assert not list(tmp_path.rglob("*.bgi"))


def test_removes_orphan_batches_but_retains_unknown_files(tmp_path):
    orphan = tmp_path / ".hunt-batch-orphan"
    orphan.mkdir()
    (orphan / "old.bgi").write_bytes(b"old")
    provider = ObjectIndexProvider(Settings(tmp_path), storage=make_storage())
    list(provider.iter_search_batches())
    assert not orphan.exists()
    (tmp_path / "legacy.bgi").write_bytes(b"legacy")
    with pytest.raises(IndexUnavailable, match="Legacy"):
        list(provider.iter_search_batches())
    assert (tmp_path / "legacy.bgi").exists()


def test_prefix_defaults(monkeypatch):
    monkeypatch.delenv("AZUL_INDEX_PREFIX", raising=False)
    assert index_prefix() == "retrohunt/indices/"
