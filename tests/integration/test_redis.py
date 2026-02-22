import json
import pytest
import unittest

@pytest.mark.usefixtures("monkeypatch")
class TestRedis(unittest.TestCase):
    def setUp(self):
        """setup function for integration tests. We do this to allow running integration tests locally."""
        import pytest
        mp = pytest.MonkeyPatch()
        mp.setenv("REDIS_HOST", "localhost")
        mp.setenv("REDIS_PORT", "6379")
        mp.setenv("REDIS_USERNAME", "")
        mp.setenv("REDIS_PASSWORD", "")
        mp.setenv("REDIS_DB", "0")
        self._mp = mp

        # Import AFTER env vars are set
        from azul_plugin_retrohunt.models import RetrohuntSubmission
        from azul_plugin_retrohunt.redis import get_redis
        from azul_plugin_retrohunt.retrohunt import RetrohuntService

        self.RetrohuntSubmission = RetrohuntSubmission
        self.get_redis = get_redis
        self.RetrohuntService = RetrohuntService

    def tearDown(self):
        """tear down function for integration tests."""
        self._mp.undo()

    def test_submit_hunt_creates_event_and_stream_entry(self):
        """Submit a hunt and stream entry."""
        rs = self.RetrohuntService()
        redis = self.get_redis()
        redis.flush()

        submission = self.RetrohuntSubmission(
            search_type="wide",
            search="foo",
            submitter="tester",
            security="security",
        )

        hunt_id = rs.submit_hunt(submission)

        # 1. Check KV store
        raw = redis.get(hunt_id)
        self.assertIsNotNone(raw)

        event = json.loads(raw)
        self.assertEqual(event["entity"]["search"], "foo")
        self.assertEqual(event["entity"]["search_type"], "wide")

        # 2. Check stream
        entries = redis.client.xread({"retrohunt-jobs": "0-0"})
        self.assertTrue(entries, "Expected a job entry in the stream")

        stream_name, messages = entries[0]
        msg_id, msg_data = messages[0]

        self.assertEqual(msg_data["hunt_id"], hunt_id)
