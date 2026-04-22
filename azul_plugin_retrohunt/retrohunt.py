"""Web UI/API for Retrohunt searches."""

import json
import logging
import uuid
from collections import OrderedDict
from datetime import datetime, timedelta, timezone

import pendulum
import redis
from azul_bedrock import models_network as azm
from fastapi import HTTPException
from pydantic_core import ValidationError
from redis.exceptions import ResponseError

from azul_plugin_retrohunt.models import SERVICE_NAME, SERVICE_VERSION, RetrohuntSubmission
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.service")


class FatalException(Exception):
    """Custom exception used by tests."""

    pass


class RetrohuntService:
    """Service to manage hunt getters and setters."""

    RETROHUNT_JOB = "retrohunt-jobs"
    RETROHUNT_GROUP = "retrohunt-workers"

    def __init__(self, redis_client=None):
        self._redis_client = redis_client

    @property
    def redis(self):
        """Start redis client if not in memory. Returns client."""
        if self._redis_client is None:
            settings = RetrohuntSettings().RedisSettings()
            self._redis_client = redis.Redis(
                host=settings.endpoint,
                port=settings.port,
                username=settings.username,
                password=settings.password,
                db=settings.db,
            )
        return self._redis_client

    def get_hunts(self, hunt_id: str):
        """Get details of requested retrohunt."""
        raw_event = self.redis.get(hunt_id)
        if raw_event is None:
            raise HTTPException(
                status_code=404,
                detail=f"Retrohunt with id {hunt_id} not found",
            )
        try:
            event = azm.RetrohuntEvent.model_validate_json(raw_event)
        except ValidationError as err:
            logger.exception("Corrupted retrohunt data for id %s", hunt_id)
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
                if isinstance(key, bytes):
                    key = key.decode()
                raw_data = self.redis.get(key)

                if raw_data is None:
                    continue
                try:
                    event = azm.RetrohuntEvent.model_validate_json(raw_data)
                except ValidationError:
                    # corrupted data
                    logger.exception("Corrupted retrohunt data for id %s", key)
                    continue

                hunts[key] = event.entity

                if len(hunts) >= limit:
                    break

            if cursor == 0 or len(hunts) >= limit:
                break

        if not hunts:
            return {"data": []}

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

        if retrohunt_id is None:
            raise HTTPException(
                status_code=404,
                detail="There was an issue submitting the hunt.",
            )

        try:
            self.redis.xgroup_create(self.RETROHUNT_JOB, self.RETROHUNT_GROUP, id="$", mkstream=True)
        except ResponseError as e:
            if "BUSYGROUP" in str(e):
                pass  # already exists
            else:
                raise

        event_dict = event.model_dump()
        self.redis.set(retrohunt_id, json.dumps(event_dict))
        self.redis.xadd(self.RETROHUNT_JOB, {"hunt_id": retrohunt_id, "action": "Submitted"})

        return retrohunt_id

    def cancel_hunt(self, hunt_id: str):
        # Load raw JSON from Redis
        raw_event = self.redis.get(hunt_id)
        if raw_event is None:
            raise HTTPException(
                status_code=404,
                detail=f"Retrohunt with id {hunt_id} not found",
            )

        # Parse into RetrohuntEvent
        try:
            event = azm.RetrohuntEvent.model_validate_json(raw_event)
        except ValidationError as err:
            logger.exception("Corrupted retrohunt data for id %s", hunt_id)
            raise HTTPException(
                status_code=500,
                detail="Stored retrohunt data is invalid",
            ) from err

        entity = event.entity

        # If terminal delete immediately
        if entity.status in (
            azm.HuntState.COMPLETED,
            azm.HuntState.FAILED,
            azm.HuntState.CANCELLED,
        ):
            logger.info(f"Deleting hunt {hunt_id} immediately (status={entity.status})")
            self.redis.delete(hunt_id)
            self.redis.delete(f"retrohunt:{hunt_id}:lock")
            return entity

        # Otherwise mark as cancelled
        now = datetime.now(timezone.utc)
        entity.status = azm.HuntState.CANCELLED
        entity.updated = now

        # Update event metadata
        event.timestamp = now
        event.action = azm.RetrohuntEvent.RetrohuntAction.Cancelled
        event.source.timestamp = now

        # Save updated event back to Redis
        self.redis.set(hunt_id, event.model_dump_json())

        return entity


    def run_periodic_tasks(self):
        """Used in cronjob to remove redis jobs and entries older than cleanup_delay days."""
        now = datetime.now(timezone.utc)
        cutoff_long = RetrohuntSettings().RedisSettings().cleanup_delay
        cutoff_short = RetrohuntSettings().RedisSettings().cleanup_running_delay
        cutoff_30d = now - timedelta(days=cutoff_long)
        cutoff_3d = now - timedelta(days=cutoff_short)
        self._cleanup_hunts(cutoff_30d, cutoff_3d)
        self._cleanup_stream(cutoff_30d, cutoff_3d)
        self._cleanup_locks()

    from datetime import datetime

    def _cleanup_hunts(self, cutoff_30d, cutoff_3d):
        """Remove RetrohuntEntity entries older than cleanup_delay days, or older than 3 days if not completed."""
        # Only match hunt keys, not streams or other retrohunt_* keys
        logger.info("Cleaning hunts...")
        pattern = "hunt_*"
        cursor = 0
        while True:
            cursor, keys = self.redis.scan(cursor=cursor, match=pattern, count=100)

            for key in keys:
                # Redis always returns bytes for keys
                key_str = key.decode()

                raw = self.redis.get(key_str)
                if not raw:
                    self.redis.delete(key_str)
                    continue

                try:
                    event = azm.RetrohuntEvent.model_validate_json(raw)
                    ts_str = event.entity.submitted_time
                    status = event.entity.status

                    if not ts_str:
                        self.redis.delete(key_str)
                        continue

                    submitted = event.entity.submitted_time
                    if submitted.tzinfo is None:
                        submitted = submitted.replace(tzinfo=timezone.utc)

                except Exception as e:
                    logger.error(f"Error parsing hunt {e}")
                    continue
                # Delete if older than 30 days
                if submitted < cutoff_30d:
                    logger.info(f"Ageing off {key_str}")
                    self.redis.delete(key_str)
                    continue

                # Delete if older than 3 days AND not completed
                if submitted < cutoff_3d and status != azm.RetrohuntEvent.RetrohuntAction.COMPLETED:
                    logger.info(f"Ageing off incomplete entry {key_str}")
                    self.redis.delete(key_str)
                    continue

            if cursor == 0:
                break

    def _cleanup_stream(self, cutoff_30d, cutoff_3d):
        """Remove stream entries older than cleanup_delay days or whose hunts are stale or missing."""
        logger.info("Cleaning streams...")
        stream = "retrohunt-jobs"

        # xrange returns a list of (entry_id, {field: value})
        entries = self.redis.xrange(stream, min="-", max="+")

        for entry_id, fields in entries:
            # entry_id is already a string in real Redis
            entry_id = entry_id.decode() if isinstance(entry_id, bytes) else entry_id

            ms_str, _ = entry_id.split("-")
            ts = datetime.fromtimestamp(int(ms_str) / 1000, tz=timezone.utc)

            # Drop entries older than 30 days
            if ts < cutoff_30d:
                logger.info(f"Ageing off stream {entry_id}")
                self.redis.xdel(stream, entry_id)
                continue

            # Decode fields once (real Redis returns bytes)
            decoded = {k.decode(): v.decode() for k, v in fields.items()}

            hunt_id = decoded.get("hunt_id")
            if not hunt_id:
                self.redis.xdel(stream, entry_id)
                continue

            # Get the hunt record
            raw = self.redis.get(hunt_id)
            if not raw:
                self.redis.xdel(stream, entry_id)
                continue

            try:
                event = azm.RetrohuntEvent.model_validate_json(raw)
                status = event.entity.status
                submitted = event.entity.submitted_time
                if submitted.tzinfo is None:
                    submitted = submitted.replace(tzinfo=timezone.utc)
            except Exception as e:
                logger.error(f"Error parsing hunt {hunt_id}: {e}")
                continue

            # Drop stale or incomplete hunts older than 3 days
            if submitted < cutoff_3d and status != azm.RetrohuntEvent.RetrohuntAction.COMPLETED:
                logger.info(f"Ageing off incomplete stream {entry_id}")
                self.redis.xdel(stream, entry_id)
                continue

    def _cleanup_locks(self):
        """Remove retrohunt job locks that are invalid."""
        logger.info("Cleaning locks...")
        cursor = 0
        pattern = "retrohunt:hunt_*:lock"

        while True:
            cursor, keys = self.redis.scan(cursor=cursor, match=pattern, count=100)

            for key in keys:
                # Normalize key
                key_str = key.decode() if isinstance(key, bytes) else key

                # Check TTL
                ttl = self.redis.ttl(key_str)

                # lock has no expiration (broken)
                if ttl == -1:
                    logger.info(f"Removing broken lock {key} no expiration")
                    self.redis.delete(key_str)
                    continue

                # key does not exist (cleanup)
                if ttl == -2:
                    logger.info(f"Removing broken lock {key} Key does not exist.")
                    self.redis.delete(key_str)
                    continue
            # healthy lock
            if cursor == 0:
                break
