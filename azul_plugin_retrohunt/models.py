"""Models common to Retrohunt Api and Server."""

from azul_bedrock import models_network as azm
from pydantic import BaseModel

from azul_plugin_retrohunt.version import __version__

SERVICE_NAME = "RetrohuntServer"
SERVICE_VERSION = __version__


class RetrohuntResponse(BaseModel):
    """Retrohunt message response."""

    data: azm.RetrohuntEvent.RetrohuntEntity


class RetrohuntsResponse(BaseModel):
    """Retrohunts list message response."""

    data: list[azm.RetrohuntEvent.RetrohuntEntity]


class RetrohuntSubmission(BaseModel):
    """Retrohunt submission request model."""

    search_type: str
    search: str
    submitter: str = SERVICE_NAME
    security: str = ""


class FileMetadata(BaseModel):
    """Store metadata about an ingested file so it can be used to download a file from dispatcher later."""

    stream_label: str
    stream_source: str
    job_id: str | None = None

    def format_metadata(self) -> str:
        """Format metadata into a string that can be added in for biggrep indexing."""
        base_metadata = f"stream_label={self.stream_label},stream_source={self.stream_source}"
        if self.job_id:
            base_metadata += f",job_id={self.job_id}"
        return base_metadata
