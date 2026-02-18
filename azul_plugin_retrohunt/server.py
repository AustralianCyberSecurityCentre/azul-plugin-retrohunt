"""Web UI/API for Retrohunt searches."""

import logging
import os
from collections import OrderedDict
from importlib.resources import files

import click
import semantic_version
import uvicorn
from azul_bedrock import dispatcher
from azul_bedrock import models_network as azm
from azul_bedrock.exceptions_bedrock import BaseError
from fastapi import FastAPI, Form, HTTPException
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.templating import Jinja2Templates
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse
from starlette.staticfiles import StaticFiles
from starlette_exporter import PrometheusMiddleware, handle_metrics

from azul_plugin_retrohunt.models import (
    SERVICE_NAME,
    SERVICE_VERSION,
    RetrohuntResponse,
    RetrohuntsResponse,
    RetrohuntSubmission,
)
from azul_plugin_retrohunt.retrohunt import RetrohuntService
from azul_plugin_retrohunt.settings import RetrohuntSettings

DISPATCHER_EVENT_WAIT_TIME_SECONDS = 10


app = FastAPI(
    title="Retrohunt Server",
    version=str(semantic_version.Version(SERVICE_VERSION)),
    openapi_url="/api/openapi.json",
    docs_url=None,
    redoc_url=None,
)

static_dir = files(__name__).joinpath("static")
templates_dir = files(__name__).joinpath("templates")

app.mount("/static", StaticFiles(directory=str(static_dir)))
templates = Jinja2Templates(directory=str(templates_dir))

app.add_middleware(
    PrometheusMiddleware,
    app_name="retrohunt_server",
    prefix="retrohunt_server",
    group_paths=True,
)
app.add_route("/metrics", handle_metrics)

hunts = OrderedDict[str, azm.RetrohuntEvent.RetrohuntEntity]()

START_STATES: list[str] = [azm.HuntState.SUBMITTED]
END_STATES: list[str] = [
    azm.HuntState.COMPLETED,
    azm.HuntState.FAILED,
    azm.HuntState.CANCELLED,
]

dp: dispatcher.DispatcherAPI = None
settings = RetrohuntSettings()

rs = RetrohuntService()


@app.get(
    "/api/v1/hunts/{hunt_id}",
    response_model=RetrohuntResponse,
    responses={404: {"model": BaseError, "description": "The retrohunt was not found"}},
)
def hunt_results_v1(hunt_id: str):
    """Get details of requested retrohunt."""
    return rs.get_hunts(hunt_id)


@app.get(
    "/api/v1/hunts",
    response_model=RetrohuntsResponse,
)
def list_hunts_v1(limit: int = 100):
    """Get the latest list of retrohunts by submission time."""
    return rs.list_hunts(limit)


@app.post(
    "/api/v1/hunts",
    response_model=RetrohuntResponse,
)
def submit_hunt_v1(
    submission: RetrohuntSubmission,
):
    """Submit a new retrohunt to process."""
    return rs.submit_hunt(submission)


@app.get("/submit", include_in_schema=False)
async def form(request: Request) -> HTMLResponse:
    """Get a retrohunt submission form."""
    return templates.TemplateResponse("submit.html", {"request": request})


@app.post("/submit", include_in_schema=False)
async def submit(*, search_type: str = Form(...), search: str = Form(...)) -> HTMLResponse:
    """Submit a new retrohunt to process via form post."""
    logging.info(f"Search Type: {search_type}, Search: {search}")
    submission = RetrohuntSubmission(
        search_type=search_type,
        search=search,
        submitter=SERVICE_NAME,
        security=None,
    )
    huntid = rs.submit_hunt(submission)

    return RedirectResponse(url=f"/hunts/{huntid}", status_code=302)  # POST -> GET


@app.get("/", include_in_schema=False)
@app.get("/hunts", include_in_schema=False)
async def list_hunts(req: Request, limit: int = 100) -> HTMLResponse:
    """List the latest retrohunts by submission time."""
    ordered_hunts = rs.list_hunts(limit)
    return templates.TemplateResponse("hunts.html", {"request": req, "hunts": ordered_hunts})


@app.get("/hunts/{id}", include_in_schema=False)
async def hunt_results(request: Request) -> HTMLResponse:
    """Get the details/results of the specified retrohunt."""
    hunt = rs.get_hunts(request.path_params["id"])
    if hunt is None:
        raise HTTPException(status_code=404, detail="Hunt not found")
    # return 404 if not available.
    return templates.TemplateResponse(
        "results.html",
        {
            "request": request,
            "hunt": hunt,
            "links": os.environ.get("RETROHUNT_HASH_LINKS"),
        },
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
    "--host",
    help="The network interface address to listen on (all by default).",
    default="0.0.0.0",  # noqa: S104
)
@click.option("--port", help="The port number to listen on.", default=8852)
@click.option("--workers", help="Number of http workers to handling incoming requests.", default=1)
@click.option(
    "--reload",
    help="Should the server reload when code changes are detected?",
    default=False,
)
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
    click.echo(f"Starting server on: {host}:{port} with dispatcher events {events_url} and dispatcher data {data_url}")

    if links:
        os.environ["RETROHUNT_HASH_LINKS"] = links

    headers: list[str, str] = []
    for header_label, header_val in settings.headers.items():
        headers.append((header_label.strip(), header_val.strip()))

    uvicorn.run(
        "azul_plugin_retrohunt.server:app",
        host=host,
        port=port,
        workers=workers,
        reload=reload,
        headers=headers,
    )


if __name__ == "__main__":
    main()
