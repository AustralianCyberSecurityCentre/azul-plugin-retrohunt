"""AZUL3 RestAPI Plugin.

Provides a proxy API for AZUL to query the Retrohunt service and enrich/filter
results based on requesting user, etc.

This is to be installed/deployed in the azul-restapi-server.
"""

from azul_bedrock.exceptions_bedrock import BaseError
from azul_metastore.query.binary2.binary_read import check_binaries
from azul_metastore.restapi.quick import qr
from fastapi import APIRouter, Depends, Response

from azul_plugin_retrohunt.models import (
    RetrohuntResponse,
    RetrohuntsResponse,
    RetrohuntSubmission,
    RetrohuntSubmitResponse,
)
from azul_plugin_retrohunt.retrohunt import RetrohuntService

router = APIRouter()
service = RetrohuntService()


@router.get(
    "/v0/retrohunt/retrohunts/{hunt_id}",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "The retrohunt was not found"}},
    **qr.kw,
)
def hunt_results_route(response: Response, hunt_id: str, ctx=Depends(qr.ctx)):
    """Fetch details of specified hunt."""
    r = service.get_hunts(hunt_id)

    hunt = r["data"]

    security = ""

    # FUTURE add security if needed

    hunt.security = security

    hashes = []
    results = hunt.results or {}

    for matches in results.values():
        if not matches:
            continue

        # Normalise
        for m in matches:
            if isinstance(m, dict) and "sha256" in m:
                hashes.append(m["sha256"])
            elif isinstance(m, str):
                hashes.append(m)
            else:
                pass

    if hashes:
        summaries = check_binaries(ctx, hashes)

        sumdict = {s["sha256"]: s for s in summaries}

        hunt.tool_matches_total = sum(1 for s in summaries if s["exists"])
    else:
        sumdict = {}
        hunt.tool_matches_total = 0

    new_results = {}

    for term, matches in results.items():
        new_results[term] = [sumdict[x] for x in matches if x in sumdict and sumdict[x]["exists"]]

    hunt.results = new_results

    # Convert model to dict for API response
    return qr.fr(ctx, hunt.model_dump(), response)


@router.get(
    "/v0/retrohunt/retrohunts",
    response_model=RetrohuntsResponse,
    responses={404: {"model": BaseError, "description": "No retrohunts found"}},
    **qr.kw,
)
def list_hunts_route(response: Response, ctx=Depends(qr.ctx), limit: int = 50):
    """Return list of hunts."""
    r = service.list_hunts(limit)

    hunts = r["data"]

    for hunt in hunts:
        # FUTURE add security if needed
        security = ""
        hunt.security = security

        hashes = []
        results = hunt.results or {}

        for matches in results.values():
            if not matches:
                continue

            # Normalise
            for m in matches:
                if isinstance(m, dict) and "sha256" in m:
                    hashes.append(m["sha256"])
                elif isinstance(m, str):
                    hashes.append(m)
                else:
                    pass

        if hashes:
            summaries = check_binaries(ctx, hashes)

            visible = [s["sha256"] for s in summaries if s["exists"]]

            hunt.tool_matches_total = len(visible)

            hunt.results = {}
        else:
            hunt.tool_matches_total = 0

    # Convert models to dicts for JSON response
    return qr.fr(ctx, [h.model_dump() for h in hunts], response)


@router.post(
    "/v0/retrohunt/retrohunts",
    response_model=RetrohuntSubmitResponse,
    responses={404: {"model": BaseError, "description": "Issue submitting hunt"}},
    **qr.kw,
)
def submit_hunt_route(response: Response, submission: RetrohuntSubmission, ctx=Depends(qr.ctx)):
    """Submit a new retrohunt for processing."""
    enriched = submission.model_copy(update={"submitter": ctx.user_info.username})
    # submit the hunt and get the id
    hunt_id = service.submit_hunt(enriched)

    return qr.fr(ctx, {"retrohunt_id": hunt_id}, response)


@router.post(
    "/v0/retrohunt/retrohunts/{hunt_id}/cancel",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "Hunt not found"}},
    **qr.kw,
)
def cancel_hunt_route(response: Response, hunt_id: str, ctx=Depends(qr.ctx)):
    """Cancel a retrohunt."""
    hunt = service.cancel_hunt(hunt_id)
    return qr.fr(ctx, hunt.model_dump(), response)
