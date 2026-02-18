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

# Retrohunt uses DB 15 (DBs 0–3 are used by dispatcher.)
# Work your way down if you require more redis db's for retrohunt. ie. db=14
redis = get_redis()

settings = RetrohuntSettings()


class RetrohuntService:
    """Service to manage hunt getters and setters."""

    def get_hunts(self, hunt_id: str):
        """Get details of requested retrohunt."""
        raw_event = redis.get(hunt_id)
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
            cursor, keys = redis.scan(cursor=cursor, match="hunt_*", count=limit)

            for key in keys:
                raw_data = redis.get(key)
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
        hunt_id = submit_retrohunt(
            submission.search_type,
            submission.search,
            submission.submitter,
            submission.security,
        )

        if hunt_id is None:
            raise HTTPException(
                status_code=404,
                detail="There was an issue submitting the hunt.",
            )
        return hunt_id


def submit_retrohunt(
    query_type: str,
    query: str,
    submitter: str = SERVICE_NAME,
    security: str | None = None,
) -> str:
    """Submit a new retrohunt. Saves the hunt to Redis and adds to redis stream."""
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
            search_type=query_type,
            search=query,
            status=azm.HuntState.SUBMITTED,
            submitted_time=now,
            updated=now,
            submitter=submitter,
            security=security,
            duration=None,
        ),
    )

    event_dict = event.model_dump()

    redis.set(retrohunt_id, json.dumps(event_dict), ex=redis.REDIS_EXPIRATION)
    redis.xadd("retrohunt-jobs", {"hunt_id": retrohunt_id, "action": "Submitted"})

    return retrohunt_id
