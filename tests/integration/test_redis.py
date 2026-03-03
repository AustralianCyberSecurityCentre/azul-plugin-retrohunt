import json
import pytest
import os


# Ensure Redis env vars exist BEFORE importing the service
@pytest.fixture(autouse=True)
def redis_env(monkeypatch):
    """
    If CI provides REDIS_* env vars, use them.
    If not (local dev), fall back to localhost.
    """
    if "REDIS_HOST" not in os.environ:
        monkeypatch.setenv("REDIS_HOST", "localhost")
        monkeypatch.setenv("REDIS_PORT", "6379")
        monkeypatch.setenv("REDIS_USERNAME", "")
        monkeypatch.setenv("REDIS_PASSWORD", "")
        monkeypatch.setenv("REDIS_DB", "0")
        monkeypatch.setenv("REDIS_CLEANUP_DELAY", "30")


@pytest.fixture
def service():
    # Import AFTER env vars are patched
    from azul_plugin_retrohunt.models import RetrohuntSubmission
    from azul_plugin_retrohunt.retrohunt import RetrohuntService

    return RetrohuntService(), RetrohuntSubmission


def test_submit_hunt_creates_event_and_stream_entry(service):
    rs, RetrohuntSubmission = service

    # Flush Redis before test
    rs.redis.flushdb()

    submission = RetrohuntSubmission(
        search_type="wide",
        search="foo",
        submitter="tester",
        security="security",
    )

    hunt_id = rs.submit_hunt(submission)

    # 1. Check KV store
    raw = rs.redis.get(hunt_id)
    assert raw is not None

    event = json.loads(raw)
    assert event["entity"]["search"] == "foo"
    assert event["entity"]["search_type"] == "wide"

    # 2. Check stream
    entries = rs.redis.xread({"retrohunt-jobs": "0-0"})
    assert entries, "Expected a job entry in the stream"

    stream_name, messages = entries[0]
    msg_id, msg_data = messages[0]
    assert msg_data[b"hunt_id"] == hunt_id.encode()
