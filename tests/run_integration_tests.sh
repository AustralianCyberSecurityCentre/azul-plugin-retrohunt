#!/usr/bin/env bash

# Environment variables for Retrohunt RedisProvider local testing

export REDIS_HOST="localhost"
export REDIS_PORT=6379
export REDIS_USERNAME=""
export REDIS_PASSWORD=""
export REDIS_DB="15"   # matches RedisProvider(db=15)

echo "Redis environment variables configured:"
echo "  REDIS_HOST=$REDIS_HOST"
echo "  REDIS_PORT=$REDIS_PORT"
echo "  REDIS_USERNAME=$REDIS_USERNAME"
echo "  REDIS_PASSWORD=****"
echo "  REDIS_DB=$REDIS_DB"

echo ""
echo "Running integration tests..."
pytest ./tests/integration/
