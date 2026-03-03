"""File used to set env vars in unit tests."""

import os

os.environ["REDIS_HOST"] = "localhost"
os.environ["REDIS_PORT"] = "6379"
os.environ["REDIS_USERNAME"] = "testuser"
os.environ["REDIS_PASSWORD"] = "testpass"  # noqa: S105
os.environ["REDIS_DB"] = "0"
os.environ["REDIS_CLEANUP_DELAY"] = "30"
