"""The module is an entrypoint for a periodic task expected to be run by a Kubernetes CronJob.

It cleans up old Redis events.
"""

import logging
import sys

from azul_plugin_retrohunt.retrohunt import RetrohuntService

log = logging.getLogger("retrohunt.cron")


def run_cron():
    """Entry point for the Kubernetes CronJob."""
    log.info("Starting Retrohunt cronjob task")

    service = RetrohuntService()

    try:
        service.run_periodic_tasks()
        log.info("Retrohunt cronjob completed successfully")
    except Exception as exc:
        log.exception("Retrohunt cronjob failed: %s", exc)
        raise


def main():
    """Dispatch based on CLI args."""
    if len(sys.argv) < 2:
        raise SystemExit("No command provided")

    command = sys.argv[1]

    if command == "cronjob":
        run_cron()
    else:
        raise SystemExit(f"Unknown command: {command}")


if __name__ == "__main__":
    """Main."""
    main()
