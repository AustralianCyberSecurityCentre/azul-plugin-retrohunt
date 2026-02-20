"""Redis provider utilities for managing connections, locks, and simple Redis operations."""

import redis
from redis.exceptions import RedisError

from .settings import RetrohuntSettings


class RedisProvider:
    """Redis provider class."""

    REDIS_EXPIRATION = 30

    def __init__(self, db: int, settings: RetrohuntSettings | None = None):
        settings = settings or RetrohuntSettings()
        redis_cfg = settings.redis

        if not redis_cfg.endpoint:
            raise ValueError("REDIS_HOST is required but not set")

        # Determine host + port
        if redis_cfg.port is not None:
            # Normal case: port provided explicitly (integration tests)
            host = redis_cfg.endpoint
            port = redis_cfg.port
        else:
            if ":" in redis_cfg.endpoint:
                # Production-style "host:port"
                host, port_str = redis_cfg.endpoint.split(":", 1)
                port = int(port_str)
            else:
                # Production or integration CI must provide a port
                raise ValueError(
                    "REDIS_PORT is required unless running in test mode. "
                    "Endpoint must be host:port or REDIS_PORT must be set."
                )

        # Determine DB (env var overrides constructor)
        selected_db = redis_cfg.db if redis_cfg.db is not None else db

        try:
            self.client = redis.Redis(
                host=host,
                port=port,
                username=redis_cfg.username,
                password=redis_cfg.password,
                db=selected_db,
                decode_responses=True,
            )
            self.client.ping()

        except RedisError as e:
            raise RuntimeError(f"Failed to connect to Redis at {host}:{port}") from e

    def get(self, key):
        """Retrieve a value from Redis by key."""
        return self.client.get(key)

    def set(self, key, value, ex=None):
        """Set a value in Redis with an optional expiration."""
        if ex is not None:
            return self.client.set(key, value, ex)
        else:
            return self.client.set(key, value)

    def delete(self, key):
        """Delete a key from Redis."""
        return self.client.delete(key)

    def scan(self, cursor=0, match=None, count=None):
        """Scan Redis keys using an optional match pattern and count."""
        return self.client.scan(cursor=cursor, match=match, count=count)

    def getall(self, key):
        """Return all fields and values from a Redis hash."""
        return self.client.hgetall(key)

    def xadd(self, stream: str, fields: dict):
        """Add an entry to a Redis stream."""
        return self.client.xadd(stream, fields)

    def xack(self, stream: str, group: str, msg_id: str):
        """Acknowledge processing of a message in a Redis stream group."""
        return self.client.xack(stream, group, msg_id)

    def flush(self):
        """Flush all keys in the selected Redis database."""
        return self.client.flushdb()


_redis_instance = None


def get_redis():
    """Return a singleton RedisProvider instance."""
    global _redis_instance
    if _redis_instance is None:
        settings = RetrohuntSettings()
        # db = 15. db 0 to 3 is used by dispatcher.
        _redis_instance = RedisProvider(db=15, settings=settings)
    return _redis_instance
