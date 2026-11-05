"""S3 index adapter tests. No AWS account or credentials required."""

from pathlib import Path

import pytest

from azul_plugin_retrohunt.s3_settings import S3IndexSettings
from azul_plugin_retrohunt.s3_storage import (
    S3IndexError,
    S3IndexIntegrityError,
    S3IndexNotFound,
    S3IndexObject,
    S3IndexStorage,
    file_digest,
)


class FakeClientError(Exception):
    def __init__(self, code: str):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakePager:
    def __init__(self, objects):
        self.objects = objects

    def paginate(self, *, Bucket, Prefix):
        matches = [{"Key": k} for k in self.objects if k.startswith(Prefix)]
        for pos in range(0, len(matches), 2):
            yield {"Contents": matches[pos : pos + 2]}


class FakeS3:
    def __init__(self):
        self.objects = {}
        self.upload_calls = 0
        self.download_calls = 0
        self.corrupt_download = False
        self.fail_upload = False

    def upload_file(self, filename, bucket, key, ExtraArgs):
        if self.fail_upload:
            raise OSError("upload failed")
        self.upload_calls += 1
        self.objects[key] = (Path(filename).read_bytes(), ExtraArgs["Metadata"])

    def head_object(self, *, Bucket, Key):
        if Key not in self.objects:
            raise FakeClientError("404")
        data, metadata = self.objects[Key]
        return {"ContentLength": len(data), "Metadata": metadata}

    def download_file(self, bucket, key, filename):
        if key not in self.objects:
            raise FakeClientError("NoSuchKey")
        self.download_calls += 1
        data = self.objects[key][0]
        Path(filename).write_bytes(data + b"corrupt" if self.corrupt_download else data)

    def get_paginator(self, name):
        assert name == "list_objects_v2"
        return FakePager(self.objects)

    def delete_object(self, *, Bucket, Key):
        self.objects.pop(Key, None)


@pytest.fixture
def setup_store():
    client = FakeS3()
    settings = S3IndexSettings(_env_file=None, bucket="test-bucket", prefix="retrohunt/indices")
    return S3IndexStorage(settings, client=client), client


def test_upload_has_content_addressed_key_and_does_not_touch_source(setup_store, tmp_path):
    store, client = setup_store
    path = tmp_path / "periodic.bgi"
    path.write_bytes(b"index-content")
    first = store.upload_index("content", path)
    assert first.key.startswith("retrohunt/indices/content/bgi/periodic-")
    assert first.key.endswith(".bgi")
    assert first.size == len(b"index-content")
    assert first.sha256 == file_digest(path)[1]
    assert path.read_bytes() == b"index-content"
    assert store.upload_index("content", path) == first
    path.write_bytes(b"new-periodic-content")
    second = store.upload_index("content", path)
    assert second.key != first.key
    assert first.key in client.objects
    assert second.key in client.objects


def test_download_reuses_cache_and_preserves_valid_file(setup_store, tmp_path):
    store, client = setup_store
    source = tmp_path / "my.bgi"
    source.write_bytes(b"expected index")
    obj = store.upload_index("content", source)
    destination = tmp_path / "cache" / "my.bgi"
    assert store.download_index(obj, destination) == destination
    assert destination.read_bytes() == b"expected index"
    assert store.download_index(obj, destination) == destination
    assert client.download_calls == 1


def test_corrupted_download_does_not_replace_existing_cache(setup_store, tmp_path):
    store, client = setup_store
    path = tmp_path / "index.bgi"
    path.write_bytes(b"expected")
    obj = store.upload_index("content", path)
    destination = tmp_path / "cache.bgi"
    destination.write_bytes(b"old cache")
    client.corrupt_download = True
    with pytest.raises(S3IndexIntegrityError):
        store.download_index(obj, destination)
    assert destination.read_bytes() == b"old cache"
    assert not list(tmp_path.glob(".cache.bgi.*.part"))


def test_missing_and_permission_errors_are_distinct(setup_store, tmp_path, monkeypatch):
    store, client = setup_store
    assert not store.exists("retrohunt/indices/content/bgi/missing.bgi")
    obj = S3IndexObject("retrohunt/indices/content/bgi/missing.bgi", 12, "0" * 64)
    with pytest.raises(S3IndexNotFound):
        store.download_index(obj, tmp_path / "missing.bgi")

    def denied(**kwargs):
        raise FakeClientError("AccessDenied")

    monkeypatch.setattr(client, "head_object", denied)
    with pytest.raises(S3IndexError):
        store.exists(obj.key)


def test_upload_failure_keeps_source_file(setup_store, tmp_path):
    store, client = setup_store
    path = tmp_path / "index.bgi"
    path.write_bytes(b"original")
    client.fail_upload = True
    with pytest.raises(S3IndexError):
        store.upload_index("content", path)
    assert path.read_bytes() == b"original"


def test_listing_multiple_pages_and_explicit_delete(setup_store, tmp_path):
    store, client = setup_store
    objects = []
    for number in range(5):
        file = tmp_path / f"part{number}.bgi"
        file.write_bytes(f"part-{number}".encode())
        objects.append(store.upload_index("content", file))
    assert set(store.list_keys("content")) == {obj.key for obj in objects}
    with pytest.raises(ValueError):
        store.delete("unrelated/key")
    store.delete(objects[0].key)
    assert not store.exists(objects[0].key)
    assert len(store.list_keys("content")) == 4


def test_bad_indexer_or_file_names_rejected(setup_store):
    store, _ = setup_store
    for indexer in ("../bad", "a/b", ""):
        with pytest.raises(ValueError):
            store.index_key(indexer, "good.bgi", "a" * 64)
    for filename in ("../bad.bgi", "bad.txt", "", "\\bad.bgi"):
        with pytest.raises(ValueError):
            store.index_key("content", filename, "a" * 64)


def test_settings_off_by_default(monkeypatch):
    monkeypatch.delenv("PLUGIN_S3_ENABLED", raising=False)
    settings = S3IndexSettings(_env_file=None)
    assert settings.enabled is False
    with pytest.raises(ValueError, match="PLUGIN_S3_BUCKET"):
        S3IndexSettings(_env_file=None, enabled=True, bucket="")
