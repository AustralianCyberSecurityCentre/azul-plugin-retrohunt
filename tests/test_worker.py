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
from datetime import datetime, timezone
from hashlib import sha256
from io import StringIO
from unittest import mock

import respx
import urllib3
from azul_bedrock import dispatcher
from azul_bedrock import models_api as azapi
from azul_bedrock import models_network as azm

import azul_plugin_retrohunt
from azul_plugin_retrohunt import test_utils
from azul_plugin_retrohunt import worker as r_worker
from azul_plugin_retrohunt.models import FileMetadata


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
    def test_hunt_main(self, hunt_mock: mock.MagicMock):
        """Test that hunt can startup and call the hunt function (useful for verifying settings are loaded correctly)."""

        class StopTestException(Exception):
            pass

        def raise_exception(*args):
            raise StopTestException()

        hunt_mock.side_effect = raise_exception
        respInfo = azapi.GetEventsInfo(filtered=5, fetched=1, ready=True)
        respEvents = {"events": [copy.deepcopy(SUBMISSION).model_dump()]}
        content, header = urllib3.encode_multipart_formdata(
            {
                "info": (None, respInfo.model_dump_json()),
                "events": (None, json.dumps(respEvents)),
            }
        )
        respx.get(url__regex=rf"{self.dispatcher_url}/api/v2/event/.*").respond(
            200, headers={"Content-Type": header}, content=content
        )
        self.assertRaises(StopTestException, r_worker.main)
        hunt_mock.assert_called_once()

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

        with mock.patch(
            "azul_plugin_retrohunt.worker._update_progress", wraps=update_progress_wrapper
        ) as progress_wrapped:
            progress_wrapped.side_effect
            log_capture = r_worker.capture_logs(logging.INFO)
            r_worker.hunt(self.base_temp_dir, copy.deepcopy(SUBMISSION), log_capture)
            progress_wrapped.assert_called()

    @respx.mock
    def test_hunt(self):
        """
        Submit a new retrohunt via the API and ensure we can pull the same hunt back.
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
        r_worker.hunt(self.base_temp_dir, copy.deepcopy(SUBMISSION), None)

        result_list: list[azm.RetrohuntEvent] = []
        idx = 0
        for call in resp.calls:
            if call.request.content is not None:
                body = call.request.content
                events = json.loads(body)
                self.assertEqual(len(events), 1)
                request_data = azm.RetrohuntEvent.model_validate(events[0])

                cur_expected_result = EXPECTED_REQUESTS[idx]
                print(f"processing expected request {idx+1}")

                cur_expected_result["source"]["timestamp"] = request_data.source.timestamp
                cur_expected_result["kafka_key"] = request_data.kafka_key
                cur_expected_result["timestamp"] = request_data.timestamp

                expected_data = azm.RetrohuntEvent.model_validate(cur_expected_result)

                # Check results are expected
                print(request_data.model_dump())
                self.assertEqual(request_data.model_dump(), expected_data.model_dump())
                # Append to ensure all assertions were carried out
                result_list.append(request_data)
                idx += 1
        # Ensure all assertions actually occurred.
        self.assertEqual(len(result_list), len(EXPECTED_REQUESTS))
        self.assertEqual(idx, len(EXPECTED_REQUESTS))


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
