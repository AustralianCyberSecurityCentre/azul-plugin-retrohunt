"""
RetroHunt Server Tests
======================

The webserver presents an interface to submit and monitor retrohunt jobs.
These tests exercise some of the api entrypoints.
"""

import copy
import json
import unittest
from datetime import datetime, timezone

import respx
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from fastapi import BackgroundTasks

from azul_plugin_retrohunt import server

server.dp = dispatcher.DispatcherAPI(
    events_url="http://localhost:8111",
    data_url="http://localhost:8111",
    retry_count=3,
    timeout=30,
    author_name="name",
    author_version="version",
    deployment_key="key",
)


def str_to_datetime(datetime_string):
    """Parse timestamp back to datetime obj."""
    date = datetime.strptime(datetime_string[:19], "%Y-%m-%dT%H:%M:%S")
    return date.replace(tzinfo=timezone.utc)


class TestIndex(unittest.IsolatedAsyncioTestCase):
    @respx.mock
    async def test_submit(self):
        """Submit a new retrohunt via the API and ensure we can pull the same hunt back."""
        # server will post an event to dispatcher
        resp = respx.post("http://localhost:8111/api/v2/event").respond(
            200, json={"total_ok": 0, "total_failures": 0, "failures": []}
        )

        request = server.RetrohuntSubmission
        request.search_type = "Yara"
        request.search = "rule r {strings: $a=" " condition: $a}"
        request.submitter = "tester"
        request.security = "OFFICIAL"
        background_tasks = BackgroundTasks()
        hunt = server.submit_hunt_v1(request, background_tasks)["data"]
        # Force background task to run now
        await background_tasks.tasks[0].func(*background_tasks.tasks[0].args)
        msgs = json.loads(resp.calls[0].request.content)
        self.assertEqual(len(msgs), 1)
        msg = msgs[0]
        self.assertEqual(hunt.id, msg["entity"]["id"])
        self.assertEqual(hunt.search_type, request.search_type)
        self.assertEqual(hunt.search, request.search)
        self.assertEqual(hunt.submitter, request.submitter)
        self.assertEqual(msg["action"], azm.RetrohuntEvent.RetrohuntAction.Submitted)
        self.assertEqual(msg["source"]["security"], "OFFICIAL")

        hunt2 = server.hunt_results_v1(hunt.id)["data"]
        self.assertEqual(hunt.search, hunt2.search)
        self.assertEqual(hunt.search_type, hunt2.search_type)
        self.assertEqual(hunt.submitter, hunt2.submitter)

        hunts = server.list_hunts_v1()
        self.assertEqual(len(hunts), 1)


class TestIndexUpdate(unittest.TestCase):
    def test_update(self):
        """Trigger the lifecyle of a hunt in the server and confirm that it tracks state correctly."""
        event = azm.RetrohuntEvent(
            kafka_key="retrohunt",
            model_version=azm.CURRENT_MODEL_VERSION,
            action=azm.RetrohuntEvent.RetrohuntAction.Submitted,
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
                search="rule r {strings: $a=" " condition: $a}",
                status=azm.HuntState.SUBMITTED,
            ),
            timestamp=str_to_datetime("2020-08-20T04:02:30.062458"),
        )

        server.update_hunt(event)
        hunt = server.hunt_results_v1(event.entity.id)["data"]
        self.assertEqual(hunt.status, azm.HuntState.SUBMITTED)
        self.assertIsNone(hunt.duration)

        # give some progress update
        event.action = azm.RetrohuntEvent.RetrohuntAction.Running
        event.timestamp = str_to_datetime("2020-08-20T04:03:30.062458")
        # copy to prevent sharing references
        event.entity = copy.deepcopy(event.entity)
        event.entity.status = azm.HuntState.STARTING
        event.entity.results = {}
        server.update_hunt(event)
        hunt = server.hunt_results_v1(event.entity.id)["data"]
        self.assertEqual(hunt.status, azm.HuntState.STARTING)
        self.assertEqual(hunt.processing_start, datetime(2020, 8, 20, 4, 3, 30, tzinfo=timezone.utc))
        # duration is from start of processing, not submission
        self.assertEqual(hunt.duration, 0.0)

        # completed progress update
        event.action = azm.RetrohuntEvent.RetrohuntAction.Completed
        event.timestamp = str_to_datetime("2020-08-20T04:05:30.062458")
        event.entity = copy.deepcopy(event.entity)
        event.entity.results = {"r": ["abcdef1", "abcdef2"]}
        event.entity.status = azm.HuntState.COMPLETED
        server.update_hunt(event)
        hunt = server.hunt_results_v1(event.entity.id)["data"]
        self.assertEqual(hunt.status, azm.HuntState.COMPLETED)
        self.assertEqual(hunt.processing_end, datetime(2020, 8, 20, 4, 5, 30, tzinfo=timezone.utc))
        self.assertEqual(hunt.duration, 120.0)
        self.assertIn("r", hunt.results)
