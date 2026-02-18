"""Redis provider utilities for managing connections, locks, and simple Redis operations."""

import os

import redis


class RedisProvider:
    """Redis provider class."""

    REDIS_EXPIRATION = 30

    def __init__(self, db: int):
        """Initialize the Redis client using environment variables or localhost defaults."""
        endpoint = os.getenv("REDIS_ENDPOINT", "localhost:6379")
        username = os.getenv("REDIS_USERNAME", None)
        password = os.getenv("REDIS_PASSWORD", None)

        if endpoint:
            host, port = endpoint.split(":")
        else:
            host = "localhost"
            port = 6379

        self.client = redis.Redis(
            host=host,
            port=int(port),
            username=username,
            password=password,
            db=db,
            decode_responses=True,
        )

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
        _redis_instance = RedisProvider(db=15)
    return _redis_instance
