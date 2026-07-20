import json
import pytest
import os
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
import pathlib
import tempfile
import shutil


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
        monkeypatch.setenv("CONTAINER_MEMORY_LIMIT_MI", "16000")


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
        security=None,
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


def test_cronjob_cleanup_runs_and_cleans(service):
    rs, RetrohuntSubmission = service

    rs.redis.flushdb()

    # Create a stale timestamp (40 days old)
    stale_dt = datetime.now(timezone.utc) - timedelta(days=40)
    stale_iso = stale_dt.isoformat()

    # Build a realistic RetrohuntEvent JSON
    event = {
        "model_version": "1",
        "kafka_key": "hunt_stale",
        "timestamp": stale_iso,
        "author": {
            "name": "tester",
            "category": "user",
            "version": "1.0",
            "security": None,
        },
        "entity": {
            "id": "hunt_stale",
            "search_type": "wide",
            "search": "foo",
            "security": None,
            "status": "completed",
            "submitter": "tester",
            "submitted_time": stale_iso,
            "updated": None,
            "processing_start": None,
            "processing_end": None,
            "duration": None,
            "logs": "",
            "index_searches_total": 0,
            "index_searches_done": 0,
            "rules_parsed_total": 0,
            "rules_parsed_done": 0,
            "atom_count": 0,
            "index_match_count": 0,
            "tool_matches_total": 0,
            "tool_matches_done": 0,
            "tool_match_count": 0,
            "results": {},
            "error": "",
        },
        "action": "submitted",
        "source": {
            "submitter": "tester",
            "security": None,
            "timestamp": stale_iso,
        },
    }

    # Store the hunt in Redis
    rs.redis.set("hunt_stale", json.dumps(event))

    # Add a stream entry
    rs.redis.xadd("retrohunt-jobs", {"hunt_id": "hunt_stale", "action": "submitted"})

    # Run cron.py
    CRON_PATH = pathlib.Path(__file__).resolve().parents[2] / "azul_plugin_retrohunt" / "cron.py"

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        shutil.copyfile(CRON_PATH, tmp.name)
        tmp_path = tmp.name

    result = subprocess.run(
        [sys.executable, "-m", "azul_plugin_retrohunt.cron"],
        capture_output=True,
        text=True,
        timeout=10,
        env=os.environ.copy(),
    )

    assert result.returncode == 0, f"Cronjob failed: {result.stderr}"

    # Hunt should be deleted
    assert rs.redis.get("hunt_stale") is None

    # Stream entry should be deleted
    entries = rs.redis.xrange("retrohunt-jobs", "-", "+")
    assert len(entries) == 0


def test_cleanup_locks_removes_invalid(service):
    rs, RetrohuntSubmission = service

    # Create a healthy lock (expires in 60 seconds)
    healthy = "retrohunt:hunt_123:lock"
    rs.redis.set(healthy, "1", ex=60)

    # Create a broken lock (no TTL)
    broken = "retrohunt:hunt_456:lock"
    rs.redis.set(broken, "1")  # no expiration → ttl = -1

    # Create a missing lock (deleted before cron runs)
    missing = "retrohunt:hunt_789:lock"
    rs.redis.set(missing, "1", ex=1)
    rs.redis.delete(missing)

    # Run cron.py
    CRON_PATH = pathlib.Path(__file__).resolve().parents[2] / "azul_plugin_retrohunt" / "cron.py"

    with tempfile.NamedTemporaryFile(suffix=".py", delete=False) as tmp:
        shutil.copyfile(CRON_PATH, tmp.name)
        tmp_path = tmp.name

    result = subprocess.run(
        [sys.executable, "-m", "azul_plugin_retrohunt.cron"],
        capture_output=True,
        text=True,
        timeout=10,
        env=os.environ.copy(),
    )

    # Reload keys after cleanup
    remaining = rs.redis.keys("retrohunt:hunt_*:lock")

    # Assertions
    assert healthy.encode() in remaining
    assert broken.encode() not in remaining
    assert missing.encode() not in remaining
