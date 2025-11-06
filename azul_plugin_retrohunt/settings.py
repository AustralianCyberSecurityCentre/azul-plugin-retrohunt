"""Settings for all retrohunt subcommands."""

import tempfile

from annotated_types import Gt, Lt
from pydantic import BaseModel, ByteSize
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing_extensions import Annotated

CACHE_DIR_NAME = "cache"
PERIODIC_CACHE_DIR_NAME = "periodic-cache"
BGI_DIR_NAME = "bgi"
STATE_DIR_NAME = "state"


class RetrohuntSettings(BaseSettings):
    """Centeralised Retrohunt specific settings."""

    model_config = SettingsConfigDict(env_prefix="plugin_", extra="ignore")

    class Indexer(BaseModel):
        """Nested configuration for indexers."""

        name: str = "content"
        stream_labels: list[str] = ["content"]
        # FUTURE - file type (e.g only take executables, pngs, ELFs...)
        max_bytes_before_indexing: ByteSize = 10_737_418_240  # 10GiB
        timeout_minutes: int = 60
        # Create a temporary index once every hour. (0 or less disables periodic indexing)
        periodic_index_frequency_min: int = 60
        allow_splitting_and_deletion: bool = True
        # seconds between getting the CPU and RAM stats while indexing (must be greater than 0 and less than 30)
        seconds_between_gathering_cpu_and_ram_metrics: Annotated[float, Gt(0), Lt(30)] = 5
        run_once: bool = False

    # should be common for all indexers/ingestors.
    root_path: str = tempfile.gettempdir()
    indexers: dict[str, Indexer] = dict()
    # NOTE - these settings are identical to the value taken from azul_runner's settings to
    # allow for easier config.
    # dispatcher to use for event interaction
    events_url: str = ""
    # dispatcher to use for file data interaction
    data_url: str = ""

    periodic_bgi_name: str = "periodic"
    periodic_index_folder_name: str = "periodic"

    prometheus_port_ingestor: int = 8900
    prometheus_port_indexer: int = 8901
    prometheus_port_worker: int = 8902

    deployment_key: str = "plugin-retrohunt"
    # Security headers applied to the uvicorn server
    headers: dict[str, str] = dict()
