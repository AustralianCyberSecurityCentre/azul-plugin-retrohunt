"""
RetroHunt Tests
======================

The webserver presents an interface to submit and monitor retrohunt jobs.
These tests exercise some of the api entrypoints.
Note: we are removing the server in favour of fastapi endpoints in future.
"""

import json
import unittest
from datetime import datetime, timezone
from unittest.mock import patch

import fakeredis
from azul_bedrock import dispatcher

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
    """Submit a new retrohunt via the API and ensure we can pull the same hunt back."""

    async def asyncSetUp(self):
        # Create a fake Redis instance for each test
        self.fake_redis = fakeredis.FakeRedis()
        self.fake_redis.REDIS_EXPIRATION = 30
        # Patch the module-level redis client in retrohunt.py
        self.patcher = patch("azul_plugin_retrohunt.retrohunt.redis", self.fake_redis)
        self.patcher.start()

    async def asyncTearDown(self):
        self.patcher.stop()

    async def test_submit(self):
        request = server.RetrohuntSubmission(
            search_type="Yara",
            search="rule r {strings: $a= condition: $a}",
            submitter="tester",
            security="OFFICIAL",
        )

        # submit new hunt to redis
        result = server.submit_hunt_v1(request)
        hunt_id = result
        # verify submission
        raw = self.fake_redis.get(hunt_id)
        self.assertIsNotNone(raw)

        event_dict = json.loads(raw)
        entity = event_dict["entity"]

        self.assertEqual(entity["id"], hunt_id)
        self.assertEqual(entity["search_type"], request.search_type)
        self.assertEqual(entity["search"], request.search)
        self.assertEqual(entity["submitter"], request.submitter)
        self.assertEqual(entity["security"], request.security)

        # verify job was added to retro-hunt job stream
        entries = self.fake_redis.xrange("retrohunt-jobs")
        self.assertEqual(len(entries), 1)

        _, msg = entries[0]
        msg = {k.decode(): v.decode() for k, v in msg.items()}

        self.assertEqual(msg["hunt_id"], hunt_id)
        self.assertEqual(msg["action"], "Submitted")

        hunt2 = server.hunt_results_v1(hunt_id)["data"]
        self.assertEqual(hunt2.search, hunt2.search)
        self.assertEqual(hunt2.search_type, hunt2.search_type)
        self.assertEqual(hunt2.submitter, hunt2.submitter)

        hunts = server.list_hunts_v1()
        self.assertEqual(len(hunts), 1)
