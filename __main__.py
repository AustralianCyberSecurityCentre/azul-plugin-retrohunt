"""Dispatcher for cronjob as retrohunt.server uses click and will not accept positional args."""

import sys


def main():
    """Dispatcher for cronjob."""
    # If called with "cronjob", run the cron task instead of the server
    if len(sys.argv) > 1 and sys.argv[1] == "cronjob":
        from cron import main as cron_main

        cron_main()
        return

    # Otherwise run the server (Click)
    from azul_plugin_retrohunt.server import main as server_main

    server_main()
