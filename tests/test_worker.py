"""
RetroHunt Worker Tests
======================

The worker is responsible for waiting on hunt submissions
and triggering the required bigyara search, publishing
progress events as it executes.
"""

import copy
import json
import logging
import sys
from datetime import datetime, timezone
from hashlib import sha256
from io import StringIO
from unittest import mock

import pytest

import fakeredis
## Create a fake env module
fake_env = mock.MagicMock()
fake_env.find_executable.return_value = "/bin/true"

# Create a fake index module that uses the fake env
fake_index = mock.MagicMock()
fake_index.BigYaraIndexer = mock.MagicMock()
fake_index.BigYaraIngestor = mock.MagicMock()

# Inject both fake modules BEFORE importing test_utils
sys.modules["azul_plugin_retrohunt.bigyara.env"] = fake_env
sys.modules["azul_plugin_retrohunt.bigyara.index"] = fake_index
#sys.modules["azul_plugin_retrohunt.bigyara.ingest"] = fake_index  # optional but safe

import respx
import urllib3
from azul_bedrock import dispatcher
from azul_bedrock import models_api as azapi
from azul_bedrock import models_network as azm

import azul_plugin_retrohunt
from azul_plugin_retrohunt import test_utils
from azul_plugin_retrohunt import worker as r_worker
from azul_plugin_retrohunt.models import FileMetadata
from azul_plugin_retrohunt.ingestor import BigYaraIngestor
from azul_plugin_retrohunt.worker import SearchPhaseEnum
import importlib


def str_to_datetime(datetime_string):
    """Parse timestamp back to datetime obj."""
    date = datetime.strptime(datetime_string[:19], "%Y-%m-%dT%H:%M:%S")
    return date.replace(tzinfo=timezone.utc)


SUBMISSION = azm.RetrohuntEvent(
    model_version=azm.CURRENT_MODEL_VERSION,
    kafka_key="test",
    action="submitted",
    author=azm.Author(
        name="RetrohuntServer",
        version="0.1.0",
        category="service",
    ),
    source=azm.RetrohuntEvent.RetrohuntSource(
        submitter="tester",
        security="OFFICIAL",
        timestamp=str_to_datetime("2020-08-20T04:02:30.062458"),
    ),
    entity=azm.RetrohuntEvent.RetrohuntEntity(
        id="hunt_20200820040230",
        search_type="Yara",
        search='rule r {strings: $a = "powershell-preview" condition: $a}',
        status=azm.HuntState.SUBMITTED,
    ),
    timestamp=str_to_datetime("2020-08-20T04:02:30.062458"),
)


class TestIndex(test_utils.BaseIngestorIndexerTest):
    maxDiff = None

    def setUp(self):
        resp = super().setUp()

        # Create fake redis
        self.server = fakeredis.FakeServer()
        self.fake_redis = fakeredis.FakeRedis(server=self.server, decode_responses=True)
        self.fake_redis.REDIS_EXPIRATION = 30

        # Set dispatcher instance on workers.
        r_worker.dp = dispatcher.DispatcherAPI(
            events_url=self.dispatcher_url,
            data_url=self.dispatcher_url,
            retry_count=3,
            timeout=30,
            author_name="name",
            author_version="version",
            deployment_key="key",
        )
        return resp

    @respx.mock
    @mock.patch("azul_plugin_retrohunt.worker.hunt")
    def test_worker_processes_one_job(self, hunt_mock):
        class RedisWrapper:
            def __init__(self, redis):
                self._redis = redis

            def __getattr__(self, name):
                return getattr(self._redis, name)

            @property
            def client(self):
                return self._redis

        wrapped_redis = RedisWrapper(self.fake_redis)

        class StopTestException(Exception):
            pass

        job_id = SUBMISSION.entity.id

        # Store full event
        self.fake_redis.set(job_id, SUBMISSION.model_dump_json())

        # Add job marker
        msg_id = self.fake_redis.xadd(
            "retrohunt-jobs",
            {"hunt_id": job_id, "action": "submitted"},
        )

        # Fake stream behavior
        call_count = 0

        def fake_xreadgroup(*args, **kwargs):
            nonlocal call_count
            if call_count == 0:
                call_count += 1
                return [
                    ("retrohunt-jobs", [(msg_id, {"hunt_id": job_id, "action": "submitted"})])
                ]
            raise StopTestException

        def fake_xautoclaim(*args, **kwargs):
            return ("retrohunt-jobs", [])

        # Create consumer group
        self.fake_redis.xgroup_create(
            "retrohunt-jobs",
            "retrohunt-workers",
            id="0-0",
            mkstream=True,
        )

        import azul_plugin_retrohunt.worker as worker_module

        # --- Spy on hunt() to assert lock is held at the right moment ---
        def hunt_side_effect(*args, **kwargs):
            # Lock MUST exist when hunt() is called
            assert self.fake_redis.get(f"retrohunt:{job_id}:lock") is not None
            return None

        hunt_mock.side_effect = hunt_side_effect

        with (
            mock.patch("azul_plugin_retrohunt.worker.redis", wrapped_redis),
            mock.patch("fakeredis.FakeRedis.xreadgroup", side_effect=fake_xreadgroup),
            mock.patch("fakeredis.FakeRedis.xautoclaim", side_effect=fake_xautoclaim),
            mock.patch.object(self.fake_redis, "xack", wraps=self.fake_redis.xack) as xack_mock,
        ):
            with pytest.raises(StopTestException):
                worker_module.main()

        # hunt() must be called once
        hunt_mock.assert_called_once()

        # xack must be called with correct args
        xack_mock.assert_called_once_with("retrohunt-jobs", "retrohunt-workers", msg_id)

        # Lock must be deleted after processing
        assert self.fake_redis.get(f"retrohunt:{job_id}:lock") is None

    @respx.mock
    def test_hunt_logs(self):
        """Test that when doing a hunt the logs never gets above the max allowed size to prevent large objects being
        sent to kafka.
        """
        content1 = (
            b"When installing a PowerShell Preview release for Linux via a Package Repository, the package name"
            b" changes from powershell to powershell-preview"
        )
        content2 = b"In this attack, victims are redirected to an attack site through a compromised website."
        content3 = b"\x00\x01\x02I heard you like binary data\x00\x00\x05powershell-preview-time"

        test_content = {
            sha256(content1).hexdigest(): content1,
            sha256(content2).hexdigest(): content2,
            sha256(content3).hexdigest(): content3,
        }

        # worker will post update events to dispatcher
        resp = respx.post(f"{self.dispatcher_url}/api/v2/event").respond(
            200, json={"total_ok": 0, "total_failures": 0, "failures": []}
        )

        # worker will request file content
        for key, value in test_content.items():
            respx.get(f"{self.dispatcher_url}/api/v3/stream/samples/content/{key}").respond(200, content=value)

        # create an index with some content
        self.ingestor.add_data_to_index_cache(content1, FileMetadata(stream_label="content", stream_source="samples"))
        self.ingestor.add_data_to_index_cache(content2, FileMetadata(stream_label="content", stream_source="samples"))
        self.ingestor.add_data_to_index_cache(content3, FileMetadata(stream_label="content", stream_source="samples"))
        self.indexer.generate_index(self.ingestor.cache_directory)

        # Needed for after the function gets mocked.
        old_function_update_progress_reference = azul_plugin_retrohunt.worker._update_progress

        def update_progress_wrapper(job: azm.RetrohuntEvent, logs: StringIO) -> azm.RetrohuntEvent:
            """This function adds more logs than retrohunt allows and then verifies it truncates the logs by
            removing the first values added (the oldest logs).
            """
            logs.write("aaa" * r_worker.MAX_LOG_CHARS)  # Write double the allowed logs.
            result: azm.RetrohuntEvent = old_function_update_progress_reference(job, logs)
            self.assertEqual(len(result.entity.logs), r_worker.MAX_LOG_CHARS)
            # Verify the first twenty characters are "a"
            first_section_len = 20
            first_section_val_after = "a" * first_section_len
            self.assertEqual(first_section_val_after, result.entity.logs[:first_section_len])
            return result

        with mock.patch("azul_plugin_retrohunt.worker.redis", self.fake_redis):
            with mock.patch(
                "azul_plugin_retrohunt.worker._update_progress",
                wraps=update_progress_wrapper
            ) as progress_wrapped:
                log_capture = r_worker.capture_logs(logging.INFO)
                r_worker.hunt(self.base_temp_dir, copy.deepcopy(SUBMISSION), log_capture)
                progress_wrapped.assert_called()

    @respx.mock
    def test_hunt(self):
        """
        Submit a new retrohunt and ensure the worker writes progress/results
        into Redis instead of sending dispatcher events.
        """

        # --- Test data ---
        content1 = (
            b"When installing a PowerShell Preview release for Linux via a Package Repository, the package name"
            b" changes from powershell to powershell-preview"
        )
        content2 = b"In this attack, victims are redirected to an attack site through a compromised website."
        content3 = b"\x00\x01\x02I heard you like binary data\x00\x00\x05powershell-preview-time"

        import tempfile
        tmp = tempfile.mkdtemp()

        # Extract constructor args BEFORE replacing the ingestor
        processor_name = self.ingestor._processor_name
        max_bytes = self.ingestor._max_bytes_before_indexing
        stream_labels = self.ingestor.stream_labels
        periodic_freq = self.ingestor.periodic_index_frequency_min

        # Rebuild ingestor with new root_path
        self.ingestor = BigYaraIngestor(
            root_path=tmp,
            processor_name=processor_name,
            max_bytes_before_indexing=max_bytes,
            stream_labels=stream_labels,
            periodic_index_frequency_min=periodic_freq,
        )

        # --- ensure the MagicMock ingestion method actually writes data ---
        def real_add(data, meta):
            self.indexer.add_data_to_index_cache(self.ingestor.cache_directory, data, meta)

        self.ingestor.add_data_to_index_cache = real_add

        # --- Build index using the TEST indexer ---
        self.ingestor.add_data_to_index_cache(
            content1, FileMetadata(stream_label="content", stream_source="samples")
        )
        self.ingestor.add_data_to_index_cache(
            content2, FileMetadata(stream_label="content", stream_source="samples")
        )
        self.ingestor.add_data_to_index_cache(
            content3, FileMetadata(stream_label="content", stream_source="samples")
        )

        self.indexer.generate_index(self.ingestor.cache_directory)

        # --- Create a fake .bgi index file ---
        fake_index = self.ingestor.cache_directory / "test.bgi"
        with open(fake_index, "wb") as f:
            f.write(b"FAKEINDEX")

        # --- Patch dispatcher get_binary so the worker can fetch file content ---
        from hashlib import sha256
        from types import SimpleNamespace
        from azul_plugin_retrohunt.worker import SearchPhaseEnum

        sha1 = sha256(content1).hexdigest()
        sha2 = sha256(content2).hexdigest()
        sha3 = sha256(content3).hexdigest()

        test_content = {
            sha1: content1,
            sha2: content2,
            sha3: content3,
        }

        def fake_get_binary(source=None, label=None, sha256=None, **kwargs):
            return SimpleNamespace(content=test_content[sha256])

        # --- Mock BigYara search to reproduce expected results ---
        def fake_search(query, query_type, index_dirs, get_data, update_job, recursive):
            # Simulate parsing rules
            update_job(SearchPhaseEnum.ATOM_PARSE, 1, 1, ("r", [sha1]))

            # Simulate broad phase: 2 index matches
            update_job(SearchPhaseEnum.BROAD_PHASE, 1, 1, ("r", [sha1, sha3]))

            # Ensure match_metadata is populated by calling get_data
            cfg1 = {
                b"stream_label": b"content",
                b"stream_source": b"samples",
                b"sample": sha1.encode(),
            }
            get_data(sha1, cfg1)

            cfg2 = {
                b"stream_label": b"content",
                b"stream_source": b"samples",
                b"sample": sha3.encode(),
            }
            get_data(sha3, cfg2)

            # Simulate narrow phase: 2 tool matches
            update_job(SearchPhaseEnum.NARROW_PHASE, 1, 2, ("r", [sha1]))
            update_job(SearchPhaseEnum.NARROW_PHASE, 2, 2, ("r", [sha3]))

        with mock.patch("azul_plugin_retrohunt.worker.dp.get_binary", side_effect=fake_get_binary):
            with mock.patch("azul_plugin_retrohunt.worker.search", side_effect=fake_search):
                with mock.patch("azul_plugin_retrohunt.worker.redis", self.fake_redis):
                    with mock.patch(
                        "azul_plugin_retrohunt.worker._update_progress",
                        wraps=r_worker._update_progress
                    ) as update_mock:

                        job = copy.deepcopy(SUBMISSION)
                        index_dirs = [self.ingestor.cache_directory]

                        # --- Run the hunt ---
                        r_worker.hunt(index_dirs, job, None)

                        update_mock.assert_called()

                        redis_key = job.entity.id
                        stored_raw = self.fake_redis.get(redis_key)

                        self.assertIsNotNone(
                            stored_raw,
                            f"Expected job stored in redis under key {redis_key}"
                        )

                        # --- Validate final job state ---
                        stored_job = azm.RetrohuntEvent.model_validate(json.loads(stored_raw))
                        entity = stored_job.entity

                        # Validate final status
                        self.assertEqual(entity.status, azm.HuntState.COMPLETED)

                        # Validate results
                        expected_results = {
                            "r": [
                                {
                                    "stream_label": "content",
                                    "stream_source": "samples",
                                    "sample": sha1,
                                },
                                {
                                    "stream_label": "content",
                                    "stream_source": "samples",
                                    "sample": sha3,
                                },
                            ]
                        }

                        self.assertEqual(entity.results, expected_results)

                        # Validate counters
                        self.assertEqual(entity.rules_parsed_total, 1)
                        self.assertEqual(entity.rules_parsed_done, 1)
                        self.assertEqual(entity.atom_count, 1)
                        self.assertEqual(entity.index_searches_total, 1)
                        self.assertEqual(entity.index_searches_done, 1)
                        self.assertEqual(entity.index_match_count, 2)
                        self.assertEqual(entity.tool_matches_total, 2)
                        self.assertEqual(entity.tool_matches_done, 2)
                        self.assertEqual(entity.tool_match_count, 2)

EXPECTED_REQUESTS = [
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "starting",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "starting",
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "parsing-rules",
            "rules_parsed_total": 1,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "parsing-rules",
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "searching-wide",
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
            "index_searches_total": 1,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "searching-wide",
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
            "index_searches_total": 1,
            "index_searches_done": 1,
            "index_match_count": 2,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "searching-narrow",
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
            "index_searches_total": 1,
            "index_searches_done": 1,
            "index_match_count": 2,
            "tool_matches_total": 2,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "searching-narrow",
            "results": {
                "r": [
                    {
                        "stream_label": "content",
                        "stream_source": "samples",
                        "sample": "6851fad1afbbc57fee637712a13a10d5b1b616645d89504f39e9d39bb6166274",
                    }
                ]
            },
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
            "index_searches_total": 1,
            "index_searches_done": 1,
            "index_match_count": 2,
            "tool_matches_total": 2,
            "tool_matches_done": 1,
            "tool_match_count": 1,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "running",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "searching-narrow",
            "results": {
                "r": [
                    {
                        "stream_label": "content",
                        "stream_source": "samples",
                        "sample": "6851fad1afbbc57fee637712a13a10d5b1b616645d89504f39e9d39bb6166274",
                    },
                    {
                        "stream_label": "content",
                        "stream_source": "samples",
                        "sample": "00378ce2732a14cb31a3bdfc978a2e9073010134752325bafb7ba4a8337ab59e",
                    },
                ]
            },
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
            "index_searches_total": 1,
            "index_searches_done": 1,
            "index_match_count": 2,
            "tool_matches_total": 2,
            "tool_matches_done": 2,
            "tool_match_count": 2,
        },
    },
    {
        "model_version": azm.CURRENT_MODEL_VERSION,
        "action": "completed",
        "author": {"name": "RetrohuntServer", "version": "0.1.0", "category": "service"},
        "source": {
            "submitter": "tester",
            "name": "retrohunt",
            "security": "OFFICIAL",
        },
        "entity": {
            "id": "hunt_20200820040230",
            "search_type": "Yara",
            "search": 'rule r {strings: $a = "powershell-preview" condition: $a}',
            "status": "completed",
            "results": {
                "r": [
                    {
                        "stream_label": "content",
                        "stream_source": "samples",
                        "sample": "6851fad1afbbc57fee637712a13a10d5b1b616645d89504f39e9d39bb6166274",
                    },
                    {
                        "stream_label": "content",
                        "stream_source": "samples",
                        "sample": "00378ce2732a14cb31a3bdfc978a2e9073010134752325bafb7ba4a8337ab59e",
                    },
                ]
            },
            "rules_parsed_total": 1,
            "rules_parsed_done": 1,
            "atom_count": 1,
            "index_searches_total": 1,
            "index_searches_done": 1,
            "index_match_count": 2,
            "tool_matches_total": 2,
            "tool_matches_done": 2,
            "tool_match_count": 2,
        },
    },
]
