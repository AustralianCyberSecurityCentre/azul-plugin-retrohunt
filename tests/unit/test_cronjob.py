import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import fakeredis

from azul_plugin_retrohunt.retrohunt import RetrohuntService


class FakeRedisProvider:
    def __init__(self, client):
        self.client = client


class TestCronjobCleanup(unittest.TestCase):
    """Test cleanup of old Retrohunt entries and stream items."""

    def setUp(self):
        """Setup function for test."""
        self.fake_redis = fakeredis.FakeRedis()
        self.fake_provider = FakeRedisProvider(self.fake_redis)

        self.patcher = patch("azul_plugin_retrohunt.redis.get_redis", return_value=self.fake_provider)
        self.patcher.start()

        self.service = RetrohuntService()

        # Time helpers
        self.now = datetime.now(timezone.utc)
        self.old = self.now - timedelta(days=31)
        self.new = self.now - timedelta(days=5)

    def tearDown(self):
        """Teardown function for test."""
        self.patcher.stop()

    def test_cleanup_old_hunts_and_stream(self):
        """ "Test removal of old entries and streams from redis."""
        # Insert hunt entries
        old_entity = {"submitted_time": self.old.isoformat()}
        new_entity = {"submitted_time": self.new.isoformat()}

        self.fake_redis.set("retrohunt_old", json.dumps(old_entity))
        self.fake_redis.set("retrohunt_new", json.dumps(new_entity))

        # Insert stream entries
        old_ms = int(self.old.timestamp() * 1000)
        new_ms = int(self.new.timestamp() * 1000)

        self.fake_redis.xadd("retrohunt-jobs", {"foo": "bar"}, id=f"{old_ms}-0")
        self.fake_redis.xadd("retrohunt-jobs", {"foo": "bar"}, id=f"{new_ms}-0")

        # Run cleanup logic
        self.service.run_periodic_tasks()

        # KV checks
        self.assertIsNone(self.fake_redis.get("retrohunt_old"))
        self.assertIsNotNone(self.fake_redis.get("retrohunt_new"))

        # Stream checks
        entries = self.fake_redis.xrange("retrohunt-jobs")
        ids = [entry_id for entry_id, _ in entries]

        self.assertFalse(any(entry_id.decode().startswith(str(old_ms)) for entry_id in ids))
        self.assertTrue(any(entry_id.decode().startswith(str(new_ms)) for entry_id in ids))
