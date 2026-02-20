"""Web UI/API for Retrohunt searches."""

import json
import logging
import uuid
from collections import OrderedDict

import pendulum
from azul_bedrock import models_network as azm
from fastapi import HTTPException

from azul_plugin_retrohunt.models import SERVICE_NAME, SERVICE_VERSION, RetrohuntSubmission
from azul_plugin_retrohunt.redis import get_redis
from azul_plugin_retrohunt.settings import RetrohuntSettings

logger = logging.getLogger("retrohunt.service")

settings = RetrohuntSettings()


class RetrohuntService:
    """Service to manage hunt getters and setters."""

    def __init__(self):
        # Retrohunt uses DB 15 (DBs 0–3 are used by dispatcher.)
        # Work your way down if you require more redis db's for retrohunt. ie. db=14
        self.redis = get_redis()

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

        self.redis.set(retrohunt_id, json.dumps(event_dict), ex=self.redis.REDIS_EXPIRATION)
        self.redis.xadd("retrohunt-jobs", {"hunt_id": retrohunt_id, "action": "Submitted"})

        if retrohunt_id is None:
            raise HTTPException(
                status_code=404,
                detail="There was an issue submitting the hunt.",
            )
        return retrohunt_id


_retrohunt_service = None


def get_retrohunt_service():
    """Return a singleton RetrohuntService instance."""
    global _retrohunt_service
    if _retrohunt_service is None:
        _retrohunt_service = RetrohuntService()
    return _retrohunt_service
