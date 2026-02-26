import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import fakeredis
import os

# stop pydantic flagging an issue when no env vars exist.
os.environ["REDIS_HOST"] = "localhost"
os.environ["REDIS_PORT"] = "6379"
os.environ["REDIS_USERNAME"] = "testuser"
os.environ["REDIS_PASSWORD"] = "testpass"
os.environ["REDIS_DB"] = "0"
os.environ["REDIS_CLEANUP_DELAY"] = "30"

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
        """Test removal of old entries, stale entries, and stream items from redis."""

        # --- Hunt timestamps ---
        old_31d = self.now - timedelta(days=31)  # should be deleted (30-day rule)
        old_5d = self.now - timedelta(days=5)  # should be deleted if not completed (3-day rule)
        old_5d_completed = self.now - timedelta(days=5)  # should NOT be deleted (completed)
        recent_1d = self.now - timedelta(days=1)  # should NOT be deleted

        # --- Hunt entities ---
        entity_31d = {"submitted_time": old_31d.isoformat(), "status": "submitted"}
        entity_5d_stale = {
            "submitted_time": old_5d.isoformat(),
            "status": "searching-wide",  # not completed → should be deleted
        }
        entity_5d_completed = {
            "submitted_time": old_5d_completed.isoformat(),
            "status": "completed",  # should survive
        }
        entity_1d = {"submitted_time": recent_1d.isoformat(), "status": "submitted"}

        # Insert KV entries
        self.fake_redis.set("retrohunt_31d", json.dumps(entity_31d))
        self.fake_redis.set("retrohunt_5d_stale", json.dumps(entity_5d_stale))
        self.fake_redis.set("retrohunt_5d_completed", json.dumps(entity_5d_completed))
        self.fake_redis.set("retrohunt_1d", json.dumps(entity_1d))

        # --- Stream entries ---
        ms_31d = int(old_31d.timestamp() * 1000)
        ms_5d = int(old_5d.timestamp() * 1000)
        ms_5d_completed = int(old_5d_completed.timestamp() * 1000)
        ms_1d = int(recent_1d.timestamp() * 1000)

        # Add stream entries with hunt IDs
        self.fake_redis.xadd("retrohunt-jobs", {"id": "retrohunt_31d"}, id=f"{ms_31d}-0")
        self.fake_redis.xadd("retrohunt-jobs", {"id": "retrohunt_5d_stale"}, id=f"{ms_5d}-1")
        self.fake_redis.xadd("retrohunt-jobs", {"id": "retrohunt_5d_completed"}, id=f"{ms_5d_completed}-2")
        self.fake_redis.xadd("retrohunt-jobs", {"id": "retrohunt_1d"}, id=f"{ms_1d}-0")

        # Run cleanup logic
        self.service.run_periodic_tasks()

        # --- KV checks ---
        self.assertIsNone(self.fake_redis.get("retrohunt_31d"))  # 30-day rule
        self.assertIsNone(self.fake_redis.get("retrohunt_5d_stale"))  # 3-day stale rule
        self.assertIsNotNone(self.fake_redis.get("retrohunt_5d_completed"))  # completed survives
        self.assertIsNotNone(self.fake_redis.get("retrohunt_1d"))  # recent survives

        # --- Stream checks ---
        entries = self.fake_redis.xrange("retrohunt-jobs")
        ids = [entry_id.decode() for entry_id, _ in entries]

        # 31-day entry removed
        self.assertFalse(any(id.startswith(str(ms_31d)) for id in ids))

        # 5-day stale entry removed
        self.assertFalse(any("retrohunt_5d_stale" in entry[1].get(b"id", b"").decode() for entry in entries))

        # 5-day completed entry survives
        self.assertTrue(any(id.startswith(str(ms_5d_completed)) for id in ids))

        # 1-day entry survives
        self.assertTrue(any(id.startswith(str(ms_1d)) for id in ids))
