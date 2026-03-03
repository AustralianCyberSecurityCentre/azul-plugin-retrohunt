import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import patch
from azul_bedrock import models_network as azm
import fakeredis
import uuid

from azul_plugin_retrohunt import base  # noqa: F401
from azul_plugin_retrohunt.retrohunt import RetrohuntService
from azul_plugin_retrohunt import server


class FakeRedisProvider:
    def __init__(self, client):
        self.client = client


class TestCronjobCleanup(unittest.TestCase):
    """Test cleanup of old Retrohunt entries and stream items."""

    def setUp(self):
        """Setup function for test."""
        self.fake_redis = fakeredis.FakeRedis()

        self.service = RetrohuntService()

        # Time helpers
        self.now = datetime.now(timezone.utc)
        self.old = self.now - timedelta(days=31)
        self.new = self.now - timedelta(days=5)

    @patch("azul_plugin_retrohunt.retrohunt.redis.Redis")
    def test_cleanup_old_hunts_and_stream(self, mock_redis):
        """Test removal of old entries, stale entries, and stream items from redis."""
        mock_redis.return_value = self.fake_redis
        # --- Hunt timestamps ---
        old_31d = self.now - timedelta(days=31)  # should be deleted (30-day rule)
        old_5d = self.now - timedelta(days=5)  # should be deleted if not completed (3-day rule)
        old_5d_completed = self.now - timedelta(days=5)  # should NOT be deleted (completed)
        recent_1d = self.now - timedelta(days=1)  # should NOT be deleted

        # --- Hunt entities ---
        entity_31d = self.create_event(old_31d.isoformat(), azm.HuntState.SUBMITTED)
        entity_5d_stale = self.create_event(old_5d.isoformat(), azm.HuntState.SEARCHING_WIDE)
        entity_5d_completed = self.create_event(old_5d_completed.isoformat(), azm.HuntState.COMPLETED)
        entity_1d = self.create_event(recent_1d.isoformat(), azm.HuntState.SUBMITTED)

        # Insert KV entries
        self.fake_redis.set("retrohunt_31d", entity_31d.model_dump_json())
        self.fake_redis.set("retrohunt_5d_stale", entity_5d_stale.model_dump_json())
        self.fake_redis.set("retrohunt_5d_completed", entity_5d_completed.model_dump_json())
        self.fake_redis.set("retrohunt_1d", entity_1d.model_dump_json())

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

    def create_event(self, submit_time, status):
        """helper function to build retrohunt event."""
        submitter = "tester"
        search = "rule r {strings: $a= condition: $a}"
        search_type = "Yara"
        security = "OFFICIAL"

        retrohunt_id = f"hunt_{uuid.uuid4().hex}"
        event = azm.RetrohuntEvent(
            model_version=azm.CURRENT_MODEL_VERSION,
            kafka_key="retrohunt",
            action=azm.RetrohuntEvent.RetrohuntAction.Submitted,
            timestamp=submit_time,
            source=azm.RetrohuntEvent.RetrohuntSource(
                timestamp=submit_time,
                security=security,
                submitter=submitter,
            ),
            author=azm.Author(
                name="RETRO",
                version="01.01.01",
                category="service",
            ),
            entity=azm.RetrohuntEvent.RetrohuntEntity(
                id=retrohunt_id,
                search_type=search_type,
                search=search,
                status=status,
                submitted_time=submit_time,
                updated=submit_time,
                submitter=submitter,
                security=security,
                duration=None,
            ),
        )

        return event
