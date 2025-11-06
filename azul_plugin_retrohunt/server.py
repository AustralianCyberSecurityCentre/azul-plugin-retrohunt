"""Web UI/API for Retrohunt searches."""

import logging
import os
import socket
import threading
import traceback
from collections import OrderedDict
from contextlib import asynccontextmanager
from datetime import datetime

import click
import pendulum
import pkg_resources
import semantic_version
import uvicorn
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from azul_bedrock.exceptions import BaseError
from fastapi import BackgroundTasks, FastAPI, Form
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.staticfiles import StaticFiles
from starlette.templating import Jinja2Templates
from starlette_exporter import PrometheusMiddleware, handle_metrics

from azul_plugin_retrohunt.models import (
    SERVICE_NAME,
    SERVICE_VERSION,
    RetrohuntResponse,
    RetrohuntsResponse,
    RetrohuntSubmission,
)
from azul_plugin_retrohunt.settings import RetrohuntSettings

DISPATCHER_EVENT_WAIT_TIME_SECONDS = 10


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Do some required processing when server starts."""
    start_updating()
    yield


app = FastAPI(
    title="Retrohunt Server",
    version=str(semantic_version.Version(SERVICE_VERSION)),
    openapi_url="/api/openapi.json",
    docs_url=None,
    redoc_url=None,
    lifespan=lifespan,
)
app.mount("/static", StaticFiles(directory=pkg_resources.resource_filename(__name__, "static/")))
app.add_middleware(
    PrometheusMiddleware,
    app_name="retrohunt_server",
    prefix="retrohunt_server",
    group_paths=True,
)
app.add_route("/metrics", handle_metrics)

templates = Jinja2Templates(directory=pkg_resources.resource_filename(__name__, "templates/"))

hunts = OrderedDict[str, azm.RetrohuntEvent.RetrohuntEntity]()

START_STATES: list[str] = [azm.HuntState.SUBMITTED]
END_STATES: list[str] = [azm.HuntState.COMPLETED, azm.HuntState.FAILED, azm.HuntState.CANCELLED]

dp: dispatcher.DispatcherAPI = None
settings = RetrohuntSettings()


def start_updating():
    """Start background updating retrohunt details from dispatcher events.

    Non-blocking call.
    """
    # Asyncio/Background tasks wouldn't work so using threading instead.
    update_thread = threading.Thread(target=update_hunts, name="update_thread", daemon=True)
    update_thread.start()

    # some template helpers
    def format_duration(secs):
        """Make time durations more human readable."""
        days = 60 * 60 * 24
        hours = 60 * 60
        minutes = 60
        if secs is None:
            return "unknown"
        if secs / days > 1:
            return "%02.1f days" % (secs / days)
        if secs / hours > 1:
            return "%02.1f hours" % (secs / hours)
        if secs / minutes > 1:
            return "%02.1f mins" % (secs / minutes)
        return "%i secs" % secs

    templates.env.filters["duration"] = format_duration


def update_hunts():
    """Blocking call to start polling for updates on retrohunt events."""
    # constantly poll for updated info
    while True:
        try:
            _, events = dp.get_generic_events(
                model=azm.ModelType.Retrohunt,
                count=100,
                require_live=True,
                deadline=DISPATCHER_EVENT_WAIT_TIME_SECONDS,
            )
            if events:
                for event in events:
                    retrohunt_event = azm.RetrohuntEvent(**event)
                    update_hunt(retrohunt_event)
            else:
                logging.debug("No events waiting, retrying")
        except Exception:
            logging.error(f"Error occurred when updating status of events from dispatcher! {traceback.format_exc()}")


def update_hunt(event: azm.RetrohuntEvent):
    """Update the in-memory list of retrohunts based off details in the supplied event."""
    entity = event.entity
    entity.duration = None
    entity.submitted_time = event.source.timestamp
    entity.updated = event.timestamp if event.timestamp else pendulum.now().isoformat()
    entity.submitter = event.source.submitter
    entity.security = event.source.security

    if event.action == azm.RetrohuntEvent.RetrohuntAction.Running:
        entity.processing_start = event.timestamp

    elif entity.status in END_STATES:
        entity.processing_end = event.timestamp

    existing = hunts.get(entity.id)
    # ignore possible out of order arrival of updates
    if not (existing and existing.status in END_STATES and entity.status not in END_STATES + START_STATES):
        # propagate state and calculated attributes
        if existing and existing.processing_start:
            entity.processing_start = existing.processing_start

        if entity.processing_start and event.timestamp:
            entity.duration = (event.timestamp - entity.processing_start).total_seconds()

        logging.info(f"Received Update for {entity.id} - {entity.status}")
        # store whole event so we have source info/times
        hunts[entity.id] = entity


@app.get(
    "/api/v1/hunts/{hunt_id}",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "The retrohunt was not found"}},
)
def hunt_results_v1(hunt_id: str):
    """Get details of requested retrohunt."""
    if hunt_id not in hunts:
        return JSONResponse(
            status_code=404,
            content={
                "id": 1,
                "status": "404",
                "code": "missing_id",
                "detail": f"Retrohunt with id {hunt_id} not found",
            },
        )
    return {"data": hunts[hunt_id]}


@app.get(
    "/api/v1/hunts",
    response_model=RetrohuntsResponse,
)
def list_hunts_v1(limit: int = 100):
    """Get the latest list of retrohunts by submission time."""
    return {
        "data": sorted(hunts.values(), key=lambda x: (x.submitted_time is not None, x.submitted_time), reverse=True)[
            :limit
        ]
    }


@app.post(
    "/api/v1/hunts",
    response_model=RetrohuntResponse,
)
def submit_hunt_v1(
    submission: RetrohuntSubmission,
    background_tasks: BackgroundTasks,
):
    """Submit a new retrohunt to process."""
    hunt_id = submit_retrohunt(
        background_tasks, submission.search_type, submission.search, submission.submitter, submission.security
    )
    return {"data": hunts[hunt_id]}


@app.get("/submit", include_in_schema=False)
async def form(request: Request) -> HTMLResponse:
    """Get a retrohunt submission form."""
    return templates.TemplateResponse("submit.html", {"request": request})


@app.post("/submit", include_in_schema=False)
async def submit(
    background_tasks: BackgroundTasks, *, search_type: str = Form(...), search: str = Form(...)
) -> HTMLResponse:
    """Submit a new retrohunt to process via form post."""
    logging.info(f"Search Type: {search_type}, Search: {search}")
    huntid = submit_retrohunt(background_tasks, search_type, search)

    return RedirectResponse(url=f"/hunts/{huntid}", status_code=302)  # POST -> GET


def submit_retrohunt(
    background_tasks: BackgroundTasks,
    query_type: str,
    query: str,
    submitter: str = SERVICE_NAME,
    security: str | None = None,
) -> str:
    """Submit a new retrohunt as a background task with the given search details.

    The function will immediately return the retrohunt ID and start a background task to run the search.
    If an exception occurs the search will be deleted and removed from the dictionary of retrohunts.
    """
    if not security:
        security = security
    now = pendulum.now()
    retrohunt_id = "hunt_" + now.strftime("%Y%m%d%H%M%S")
    retrohunt_event = azm.RetrohuntEvent(
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
        ),
    )
    hunts[retrohunt_id] = retrohunt_event.entity

    background_tasks.add_task(_submit_retrohunt, retrohunt_event, retrohunt_id, now, submitter, security)
    return retrohunt_id


async def _submit_retrohunt(
    retrohunt_event: azm.RetrohuntEvent,
    retrohunt_id: str,
    now: datetime,
    submitter: str = SERVICE_NAME,
    security: str | None = None,
):
    """A background task that submits a retrohunt event to dispatcher.

    If dispatcher errors or times out the retrohunt is deleted.
    """
    dp.submit_events([retrohunt_event], model=azm.ModelType.Retrohunt)

    # need to match the sourced state not the event message
    hunts[retrohunt_id].duration = None
    hunts[retrohunt_id].submitted_time = now
    hunts[retrohunt_id].submitter = submitter
    hunts[retrohunt_id].updated = now
    hunts[retrohunt_id].security = security


@app.get("/", include_in_schema=False)
@app.get("/hunts", include_in_schema=False)
async def list_hunts(req: Request, limit: int = 100) -> HTMLResponse:
    """List the latest retrohunts by submission time."""
    ordered_hunts = sorted(
        hunts.values(), key=lambda x: (x.submitted_time is not None, x.submitted_time), reverse=True
    )[:limit]
    return templates.TemplateResponse("hunts.html", {"request": req, "hunts": ordered_hunts})


@app.get("/hunts/{id}", include_in_schema=False)
async def hunt_results(request: Request) -> HTMLResponse:
    """Get the details/results of the specified retrohunt."""
    hunt = hunts.get(request.path_params["id"], {})
    # return 404 if not available.
    return templates.TemplateResponse(
        "results.html", {"request": request, "hunt": hunt, "links": os.environ.get("RETROHUNT_HASH_LINKS")}
    )


# provide offline access to swagger doc and redoc instead of via a cdn
@app.get("/api/docs", include_in_schema=False)
async def swagger_doc_html(req: Request) -> HTMLResponse:
    """Get Swagger API Documentation."""
    return get_swagger_ui_html(
        openapi_url=app.openapi_url,
        title=app.title + " - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="/static/swagger-ui-bundle.js",
        swagger_css_url="/static/swagger-ui.css",
        swagger_favicon_url="/static/favicon-32x32.png",
    )


@app.get("/api/redoc", include_in_schema=False)
async def redoc_html(req: Request) -> HTMLResponse:
    """Get ReDoc documentation."""
    return get_redoc_html(
        openapi_url=app.openapi_url,
        title=app.title + " - ReDoc",
        redoc_js_url="/static/redoc.standalone.js",
        redoc_favicon_url="/static/favicon-32x32.png",
        with_google_fonts=False,
    )


@click.command()
@click.option(
    "--host", help="The network interface address to listen on (all by default).", default="0.0.0.0"  # nosec B104
)
@click.option("--port", help="The port number to listen on.", default=8852)
@click.option("--workers", help="Number of http workers to handling incoming requests.", default=1)
@click.option("--reload", help="Should the server reload when code changes are detected?", default=False)
@click.option("--events-url", help="Azul Dispatcher Events URL.", default="http://localhost:8111")
@click.option("--data-url", help="Azul Dispatcher data URL.", default="http://localhost:8111")
@click.option("--links", help="A url to prefix any sample hashes to turn into hyperlinks.")
def main(host, port, workers, reload, events_url, data_url, links):
    """Start the Retrohunt web server.

    :param host: The network interface address to listen on (all by default).
    :param port: The port number to listen on.
    :param workers: Number of http workers to handling incoming requests.
    :param reload: Should the server reload when code changes are detected?
    :param events-url: Azul Dispatcher events URL.
    :param data-url: Azul Dispatcher data URL.
    :param links: A url to prefix any sample hashes to turn into hyperlinks.
    """
    global dp
    click.echo(f"Starting server on: {host}:{port} with dispatcher events {events_url} and dispatcher data {data_url}")
    name = f"{SERVICE_NAME}-{socket.gethostname()}-{pendulum.now().timestamp()}"
    dp = dispatcher.DispatcherAPI(
        events_url=events_url,
        data_url=data_url,
        retry_count=3,
        timeout=30,
        author_name=name,
        author_version=SERVICE_VERSION,
        deployment_key=settings.deployment_key,
    )
    if links:
        os.environ["RETROHUNT_HASH_LINKS"] = links

    headers: list[str, str] = []
    for header_label, header_val in settings.headers.items():
        headers.append((header_label.strip(), header_val.strip()))

    uvicorn.run(
        "azul_plugin_retrohunt.server:app", host=host, port=port, workers=workers, reload=reload, headers=headers
    )


if __name__ == "__main__":
    main()
