"""Web UI/API for Retrohunt searches."""

import json
import logging
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

import pendulum
from azul_bedrock import models_network as azm
from fastapi import HTTPException

from azul_plugin_retrohunt.models import SERVICE_NAME, SERVICE_VERSION, RetrohuntSubmission
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.service")


class RetrohuntService:
    """Service to manage hunt getters and setters."""

    def __init__(self, redis_client=None):
        self._redis = redis_client

    @property
    def redis(self):
        """Lazy loader."""
        if self._redis is None:
            from .redis import get_redis

            self._redis = get_redis()
        return self._redis

    def get_hunts(self, hunt_id: str):
        """Get details of requested retrohunt."""
        raw_event = self.redis.get(hunt_id)
        if raw_event is None:
            raise HTTPException(
                status_code=404,
                detail=f"Retrohunt with id {hunt_id} not found",
            )
        try:
            event = azm.RetrohuntEvent.model_validate(json.loads(raw_event))
        except Exception as err:
            logger.exception("Corrupted retrohunt data for id %s", hunt_id)
            logger.debug("Raw data for %s: %.300r", hunt_id, raw_event)
            raise HTTPException(
                status_code=500,
                detail="Stored retrohunt data is invalid",
            ) from err

        entity = event.entity

        return {"data": entity}

    def list_hunts(self, limit: int = 100):
        """Get the latest list of retrohunts by submission time."""
        cursor = 0
        hunts: OrderedDict[str, azm.RetrohuntEvent.RetrohuntEntity] = OrderedDict()

        while True:
            cursor, keys = self.redis.scan(cursor=cursor, match="hunt_*", count=limit)

            for key in keys:
                raw_data = self.redis.get(key)
                if raw_data is None:
                    continue
                try:
                    event = azm.RetrohuntEvent.model_validate(json.loads(raw_data))
                except Exception:
                    # corrupted data
                    logger.exception("Corrupted retrohunt data for id %s", key)
                    logger.debug("Raw data for %s: %.300r", key, raw_data)
                    continue

                hunts[key] = event.entity

                if len(hunts) >= limit:
                    break

            if cursor == 0 or len(hunts) >= limit:
                break

        if not hunts:
            raise HTTPException(
                status_code=404,
                detail="No Retrohunts found.",
            )

        sorted_hunts = sorted(
            hunts.values(),
            key=lambda x: (x.submitted_time is not None, x.submitted_time),
            reverse=True,
        )

        return {"data": sorted_hunts[:limit]}

    def submit_hunt(self, submission: RetrohuntSubmission):
        """Create a new hunt and return it."""
        submitter = submission.submitter
        search = submission.search
        search_type = submission.search_type
        security = submission.security

        now = pendulum.now()
        retrohunt_id = f"hunt_{uuid.uuid4().hex}"
        event = azm.RetrohuntEvent(
            model_version=azm.CURRENT_MODEL_VERSION,
            kafka_key="retrohunt",
            action=azm.RetrohuntEvent.RetrohuntAction.Submitted,
            timestamp=now,
            source=azm.RetrohuntEvent.RetrohuntSource(
                timestamp=now,
                security=security,
                submitter=submitter,
            ),
            author=azm.Author(
                name=SERVICE_NAME,
                version=SERVICE_VERSION,
                category="service",
            ),
            entity=azm.RetrohuntEvent.RetrohuntEntity(
                id=retrohunt_id,
                search_type=search_type,
                search=search,
                status=azm.HuntState.SUBMITTED,
                submitted_time=now,
                updated=now,
                submitter=submitter,
                security=security,
                duration=None,
            ),
        )

        event_dict = event.model_dump()

        self.redis.set(retrohunt_id, json.dumps(event_dict))
        self.redis.xadd("retrohunt-jobs", {"hunt_id": retrohunt_id, "action": "Submitted"})

        if retrohunt_id is None:
            raise HTTPException(
                status_code=404,
                detail="There was an issue submitting the hunt.",
            )
        return retrohunt_id

    def run_periodic_tasks(self):
        """Used in cronjob to remove redis jobs and entries older than cleanup_delay days."""
        redis = self.redis
        now = datetime.now(timezone.utc)
        cutoff_long = RetrohuntSettings().RedisSettings().cleanup_delay
        cutoff_30d = now - timedelta(days=cutoff_long)
        cutoff_3d = now - timedelta(days=3)

        self._cleanup_hunts(redis, cutoff_30d, cutoff_3d)
        self._cleanup_stream(redis, cutoff_30d, cutoff_3d)

    def _cleanup_hunts(self, redis, cutoff_30d, cutoff_3d):
        """Remove RetrohuntEntity entries older than cleanup_delay days, or older than 3 days if not completed."""
        cursor = 0
        pattern = "retrohunt_*"

        while True:
            cursor, keys = redis.client.scan(cursor=cursor, match=pattern, count=100)

            for key in keys:
                # Normalize all key forms
                key_str = key.decode() if isinstance(key, bytes) else key
                key_bytes = key_str.encode()

                # Try all forms when reading
                raw = redis.client.get(key) or redis.client.get(key_str) or redis.client.get(key_bytes)

                if not raw:
                    redis.client.delete(key)
                    redis.client.delete(key_str)
                    redis.client.delete(key_bytes)
                    continue

                try:
                    entity = json.loads(raw)
                    ts_str = entity.get("submitted_time")
                    status = entity.get("status")
                    if not ts_str:
                        redis.client.delete(key)
                        redis.client.delete(key_str)
                        redis.client.delete(key_bytes)
                        continue

                    submitted = datetime.fromisoformat(ts_str)
                except Exception:
                    redis.client.delete(key)
                    redis.client.delete(key_str)
                    redis.client.delete(key_bytes)
                    continue

                if submitted < cutoff_30d:
                    redis.client.delete(key)
                    redis.client.delete(key_str)
                    redis.client.delete(key_bytes)
                    continue

                if submitted < cutoff_3d and status != "completed":
                    redis.client.delete(key)
                    redis.client.delete(key_str)
                    redis.client.delete(key_bytes)
                    continue

            if cursor == 0:
                break

    def _cleanup_stream(self, redis, cutoff_30d, cutoff_3d):
        """Remove stream entries older than cleanup_delay days or whose hunts are stale or missing."""
        stream = "retrohunt-jobs"

        entries = redis.client.xrange(stream, min="-", max="+")

        for entry_id, fields in entries:
            entry_id = entry_id.decode()

            # Parse timestamp from stream ID "<ms>-<seq>"
            ms_str, _ = entry_id.split("-")
            ts = datetime.fromtimestamp(int(ms_str) / 1000, tz=timezone.utc)

            if ts < cutoff_30d:
                redis.client.xdel(stream, entry_id)
                continue

            # Normalize keys + values (fakeredis uses bytes)
            fields = {
                (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
                for k, v in fields.items()
            }

            hunt_id = fields.get("id")
            if not hunt_id:
                redis.client.xdel(stream, entry_id)
                continue

            raw = redis.client.get(hunt_id) or redis.client.get(hunt_id.encode())

            if not raw:
                redis.client.xdel(stream, entry_id)
                continue

            try:
                entity = json.loads(raw)
                status = entity.get("status")
                submitted = datetime.fromisoformat(entity.get("submitted_time"))
            except Exception:
                redis.client.xdel(stream, entry_id)
                continue

            if submitted < cutoff_3d and status != "completed":
                redis.client.xdel(stream, entry_id)
                continue
