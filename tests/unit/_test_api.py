"""
RetroHunt Tests
======================

The webserver presents an interface to submit and monitor retrohunt jobs.
These tests exercise some of the api entrypoints.
Note: we are removing the server in favour of fastapi endpoints in future.
"""

import json
from unittest.mock import patch

import fakeredis

from azul_plugin_retrohunt import test_utils

from fastapi.testclient import TestClient
from azul_plugin_retrohunt import test_utils

client = TestClient(test_utils.app)


class TestIndex(test_utils.BaseIngestorIndexerTest):
    async def asyncSetUp(self):
        self.fake_redis = fakeredis.FakeRedis()

    @patch("azul_plugin_retrohunt.retrohunt.redis.Redis")
    async def test_submit(self, mock_redis):
        mock_redis.return_value = self.fake_redis

        payload = {
            "search_type": "Yara",
            "search": "rule r {strings: $a= condition: $a}",
            "submitter": "tester",
            "security": None,
        }

        # POST /v0/retrohunt/retrohunts
        r = client.post("/v0/retrohunt/retrohunts", json=payload)
        assert r.status_code == 200

        hunt_id = r.json()["data"]["retrohunt_id"]

        raw = self.fake_redis.get(hunt_id)
        assert raw is not None

        event_dict = json.loads(raw)
        entity = event_dict["entity"]

        assert entity["id"] == hunt_id
        assert entity["search_type"] == payload["search_type"]
        assert entity["search"] == payload["search"]
        assert entity["submitter"] == payload["submitter"]
        assert entity["security"] == payload["security"]

        # verify job was added to retro-hunt job stream
        entries = self.fake_redis.xrange("retrohunt-jobs")
        assert len(entries) == 1

        _, msg = entries[0]
        msg = {k.decode(): v.decode() for k, v in msg.items()}

        assert msg["hunt_id"] == hunt_id
        assert msg["action"] == "Submitted"

        # GET /v0/retrohunt/retrohunts/{hunt_id}
        hunt2 = client.get(f"/v0/retrohunt/retrohunts/{hunt_id}").json()["data"]

        assert hunt2["search"] == payload["search"]
        assert hunt2["search_type"] == payload["search_type"]
        assert hunt2["submitter"] == payload["submitter"]

        # GET /v0/retrohunt/retrohunts
        hunts = client.get("/v0/retrohunt/retrohunts").json()["data"]
        assert len(hunts) == 1
