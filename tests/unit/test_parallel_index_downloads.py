"""Concurrent download and manifest-size regression tests."""

import hashlib
import threading
import time
from contextlib import contextmanager
from types import SimpleNamespace

from azul_plugin_retrohunt.index_provider import ObjectIndexProvider


def test_concurrent_fetches_and_warm_reuse(tmp_path):
    blobs = [bytes([i]) * 128 for i in range(1, 5)]
    payloads = {hashlib.sha256(blob).hexdigest(): blob for blob in blobs}

    class Storage:
        def __init__(self):
            self.active = 0
            self.peak = 0
            self.reads = 0
            self.lock = threading.Lock()

        def object_size(self, key):
            return len(payloads[key.rsplit("/", 1)[-1][:-4]])

        def list_keys(self, prefix):
            for ident in payloads:
                yield prefix + ident + ".bgi"
                yield prefix + ident + ".ready"

        @contextmanager
        def read_chunks(self, key):
            with self.lock:
                self.active += 1
                self.peak = max(self.peak, self.active)
                self.reads += 1
            try:
                time.sleep(0.03)
                yield [payloads[key.rsplit("/", 1)[-1][:-4]]]
            finally:
                with self.lock:
                    self.active -= 1

    storage = Storage()
    settings = SimpleNamespace(
        index_cache_dir=str(tmp_path),
        index_cache_max_bytes=2048,
        index_cache_target_bytes=1800,
        index_cache_free_bytes=0,
        index_list_timeout_seconds=30,
        index_fetch_timeout_seconds=30,
        index_download_workers=3,
    )
    first = ObjectIndexProvider(settings, storage=storage)
    assert sum(batch[2] for batch in first.iter_search_batches()) == 4
    assert storage.peak >= 2
    assert storage.reads == 4
    second = ObjectIndexProvider(settings, storage=storage)
    assert sum(batch[2] for batch in second.iter_search_batches()) == 4
    assert storage.reads == 4
    assert second.cache_hits == 4


def test_manifest_sizes_skip_redundant_head(tmp_path):
    data = b"content"
    ident = hashlib.sha256(data).hexdigest()

    class Storage:
        def object_size(self, key):
            raise AssertionError("unexpected HEAD")

        @contextmanager
        def read_chunks(self, key):
            yield [data]

    settings = SimpleNamespace(
        index_cache_dir=str(tmp_path),
        index_cache_max_bytes=100,
        index_cache_target_bytes=80,
        index_cache_free_bytes=0,
        index_list_timeout_seconds=30,
        index_fetch_timeout_seconds=30,
        index_download_workers=2,
    )
    provider = ObjectIndexProvider(settings, storage=Storage())
    provider.index_sizes = {ident: len(data)}
    batch = provider._prepare_batch([ident], 0, lambda *_: None)
    assert batch.batch_count == 1
    assert (batch.batch_dir / (ident + ".bgi")).read_bytes() == data
