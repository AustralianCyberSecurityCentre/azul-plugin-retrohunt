"""AZUL3 RestAPI Plugin.

Provides a proxy API for AZUL to query the Retrohunt service and enrich/filter
results based on requesting user, etc.

This is to be installed/deployed in the azul-restapi-server.
"""

import os

import httpx
from azul_bedrock.exceptions_bedrock import BaseError
from azul_metastore import query
from azul_metastore.restapi.quick import qr
from fastapi import APIRouter, Depends, HTTPException

from azul_plugin_retrohunt.models import RetrohuntResponse, RetrohuntsResponse, RetrohuntSubmission
from azul_plugin_retrohunt.retrohunt import RetrohuntService

router = APIRouter()
service = RetrohuntService()

# keep the old server up while we prepare to integrate retrohunt with the webui
retrohunt_server = os.getenv("RETROHUNT_SERVER", "http://localhost:8852")


@router.get(
    "/retrohunts/{hunt_id}",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "The retrohunt was not found"}},
    **qr.kw,
)
def hunt_results(hunt_id: str, ctx=Depends(qr.ctx)):
    """Fetch details of specified hunt."""
    try:
        response = httpx.get(retrohunt_server + f"/api/v1/hunts/{hunt_id}", timeout=120)
        if response.status_code == 404:
            raise HTTPException(status_code=404, detail="Retrohunt Id not found")
        response.raise_for_status()
    except Exception as ex:  # FUTURE specific exception types
        raise HTTPException(
            status_code=500,
            detail=f"Error contacting upstream retrohunt service. {str(ex)}",
        ) from ex

    # enrich/filter based on metastore
    hunt = response.json()["data"]
    # mismatch in field namings between webapi/metastore and messaging/retrohunt api
    if "markings" in hunt.get("security", {}):
        hunt["security"]["other"] = hunt["security"].pop("markings")

    hashes = []
    for matches in hunt.get("results", {}).values():
        if matches:
            hashes.extend(matches)
    if hashes:
        # query as one aggregated multisearch
        entities = list(zip(["binary"] * len(hashes), hashes, strict=False))
        summaries = query.read_entities(ctx, entities=entities)
        sumdict = {s.id: s for s in summaries}
        hunt["tool_matches_total"] = len(summaries)
    else:
        sumdict = {}
        hunt["tool_matches_total"] = 0

    # now override back into right term buckets
    for term, matches in hunt.get("results", {}).items():
        hunt["results"][term] = [sumdict[x] for x in matches if x in sumdict]

    return qr.fr(ctx, hunt)


@router.get("/retrohunts", response_model=RetrohuntsResponse, **qr.kw)
def list_hunts(ctx=Depends(qr.ctx), limit: int = 50):
    """Return list of hunts."""
    try:
        r = httpx.get(retrohunt_server + "/api/v1/hunts?limit=%d" % limit, timeout=120)
        if r.status_code == 404:
            raise HTTPException(status_code=404, detail="Retrohunt Id not found")
        r.raise_for_status()
    except Exception as ex:
        raise HTTPException(
            status_code=500,
            detail="Error contacting upstream retrohunt service. %s" % str(ex),
        ) from ex

    # enrich/filter based on metastore
    results = r.json()["data"]

    # need to filter counts based on what user can actually see
    for hunt in results:
        # mismatch in field namings between webapi/metastore and messaging/retrohunt api
        if "markings" in hunt.get("security", {}):
            hunt["security"]["other"] = hunt["security"].pop("markings")

        hashes = []
        for matches in hunt.get("results", {}).values():
            if matches:
                hashes.extend(matches)
        if hashes:
            entities = list(zip(["binary"] * len(hashes), hashes, strict=False))
            hunt["tool_matches_total"] = len([x.id for x in query.check_entities(ctx, entities=entities) if x.exists])
            hunt.pop("results", None)

    return qr.fr(ctx, results)


@router.post("/retrohunts", response_model=RetrohuntResponse, **qr.kw)
def submit_hunt(submission: RetrohuntSubmission, ctx=Depends(qr.ctx)):
    """Submit a new retrohunt for processing."""
    request = {
        "submitter": ctx.user_info.username,
        "search_type": submission.search_type,
        "search": submission.search,
        "security": {},
    }
    request["security"] = submission.security
    try:
        response = httpx.post(retrohunt_server + "/api/v1/hunts", json=request, timeout=120)
        response.raise_for_status()
    except Exception as ex:
        raise HTTPException(
            status_code=500,
            detail="Error contacting upstream retrohunt service. %s" % str(ex),
        ) from ex

    submission = response.json()

    return submission


# restapi endpoints will be for webui integration
@router.get(
    "/v0/retrohunt/retrohunts/{hunt_id}",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "The retrohunt was not found"}},
    **qr.kw,
)
def hunt_results_route(hunt_id: str, ctx=Depends(qr.ctx)):
    """Fetch details of specified hunt."""
    response = RetrohuntService.get_hunts(hunt_id)

    # enrich/filter based on metastore
    hunt = response["data"]
    # mismatch in field namings between webapi/metastore and messaging/retrohunt api
    if "markings" in hunt.get("security", {}):
        hunt["security"]["other"] = hunt["security"].pop("markings")

    hashes = []
    for matches in hunt.get("results", {}).values():
        if matches:
            hashes.extend(matches)
    if hashes:
        # query as one aggregated multisearch
        entities = list(zip(["binary"] * len(hashes), hashes, strict=False))
        summaries = query.read_entities(ctx, entities=entities)
        sumdict = {s.id: s for s in summaries}
        hunt["tool_matches_total"] = len(summaries)
    else:
        sumdict = {}
        hunt["tool_matches_total"] = 0

    # now override back into right term buckets
    for term, matches in hunt.get("results", {}).items():
        hunt["results"][term] = [sumdict[x] for x in matches if x in sumdict]

    return qr.fr(ctx, hunt)


@router.get(
    "/v0/retrohunt/retrohunts",
    response_model=RetrohuntsResponse,
    responses={404: {"model": BaseError, "description": "No retrohunts found"}},
    **qr.kw,
)
def list_hunts_route(ctx=Depends(qr.ctx), limit: int = 50):
    """Return list of hunts."""
    r = RetrohuntService.list_hunts(limit)

    # enrich/filter based on metastore
    results = r["data"]

    # need to filter counts based on what user can actually see
    for hunt in results:
        # mismatch in field namings between webapi/metastore and messaging/retrohunt api
        if "markings" in hunt.get("security", {}):
            hunt["security"]["other"] = hunt["security"].pop("markings")

        hashes = []
        for matches in hunt.get("results", {}).values():
            if matches:
                hashes.extend(matches)
        if hashes:
            entities = list(zip(["binary"] * len(hashes), hashes, strict=False))
            hunt["tool_matches_total"] = len([x.id for x in query.check_entities(ctx, entities=entities) if x.exists])
            hunt.pop("results", None)

    return qr.fr(ctx, results)


@router.post(
    "/v0/retrohunt/retrohunts",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "Issue submitting hunt"}},
    **qr.kw,
)
def submit_hunt_route(submission: RetrohuntSubmission, ctx=Depends(qr.ctx)):
    """Submit a new retrohunt for processing."""
    enriched = submission.model_copy(update={"submitter": ctx.user_info.username})
    # submit the hunt and get the id
    hunt_id = RetrohuntService.submit_hunt(enriched)
    # get the hunt entity
    hunt = RetrohuntService.get_hunts(hunt_id)

    return qr.fr(ctx, hunt["data"])
