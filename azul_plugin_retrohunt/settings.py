"""Settings for all retrohunt subcommands."""

from pydantic import Field, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class RetrohuntSettings(BaseSettings):
    """Centeralised Retrohunt specific settings."""

    model_config = SettingsConfigDict(env_prefix="plugin_", extra="ignore")

    class SearchSettings(BaseSettings):
        """Settings for the BigGrep and Narrow phase search."""

        max_thread_count: int = Field(5, alias="MAX_THREAD_COUNT")
        max_required_strings_per_and_search: int = Field(10, alias="MAX_REQUIRED_STRINGS_PER_AND_SEARCH")
        max_required_string_searches_per_index: int = Field(64, alias="MAX_REQUIRED_STRING_SEARCHES_PER_INDEX")
        max_required_broad_phase_workers: int = Field(2, alias="MAX_BROAD_PHASE_WORKERS")
        max_broad_phase_tasks: int = Field(10000, alias="MAX_BROAD_PHASE_TASKS")
        default_narrow_phase_cleanup_multiplier: int = Field(4, alias="DEFAULT_NARROW_PHASE_CLEANUP_MULTIPLIER")
        max_retries: int = Field(10, alias="MAX_RETRIES")

    class RedisSettings(BaseSettings):
        """Nested configuration for RedisProvider."""

        endpoint: str = Field(..., alias="REDIS_HOST")
        port: int = Field(..., alias="REDIS_PORT")
        ttl: int = Field(30, alias="REDIS_TTL")
        exception_wait: int = Field(60, alias="REDIS_EXCEPTION_WAIT")

        @model_validator(mode="before")
        def split_host_and_port(cls, values):
            """Live uses endpoint:port. Integration tests have host + port separated."""
            endpoint = values.get("endpoint")
            if endpoint and ":" in endpoint:
                host, port_str = endpoint.split(":", 1)
                values["endpoint"] = host
                values["port"] = int(port_str)

            return values

        username: str = Field(..., alias="REDIS_USERNAME")
        password: str = Field(..., alias="REDIS_PASSWORD")
        db: int = Field(..., alias="REDIS_DB")
        cleanup_delay: int = Field(30, alias="REDIS_CLEANUP_DELAY")
        cleanup_running_delay: int = Field(7, alias="REDIS_CLEANUP_RUNNING_DELAY")

        model_config = SettingsConfigDict(
            extra="ignore",
            populate_by_name=True,
        )

    redis: RedisSettings = Field(default_factory=lambda: RetrohuntSettings.RedisSettings())
    search_settings: SearchSettings = Field(default_factory=lambda: RetrohuntSettings.SearchSettings())
    # The index files are exclusively produced by the external Retroindexer.
    # Retrohunt never writes to the object store or creates BigGrep indexes.
    index_cache_dir: str = "/data/index-cache"
    index_fetch_workers: int = Field(4, ge=1, le=16)
    index_cache_max_bytes: int = Field(90 * 1024**3, ge=1)
    index_cache_target_bytes: int = Field(80 * 1024**3, ge=1)
    index_cache_free_bytes: int = Field(10 * 1024**3, ge=0)
    index_list_timeout_seconds: int = Field(120, ge=1)
    index_fetch_timeout_seconds: int = Field(1800, ge=1)

    # Opt-in distributed hunts. Only enable after all worker pods run the same version.
    distributed_hunts: bool = False
    hunt_shards: int = Field(32, ge=1, le=128)
    hunt_max_parallel_shards: int = Field(32, ge=1, le=128)
    hunt_shard_lease_seconds: int = Field(180, ge=30)
    hunt_shard_max_retries: int = Field(3, ge=1, le=20)
    # Set identically for all workers sharing a scheduling pool.
    hunt_worker_count: int = Field(1, ge=1)
    hunt_worker_pool: str = "default"

    # NOTE - these settings are identical to the value taken from azul_runner's settings to
    # allow for easier config.
    # dispatcher to use for event interaction
    events_url: str = ""
    # dispatcher to use for file data interaction
    data_url: str = ""

    prometheus_port_worker: int = 8902

    deployment_key: str = "plugin-retrohunt"
    # Security headers applied to the uvicorn server
    headers: dict[str, str] = dict()
