"""Build retrohunt and yara ready to be bundled for install."""

# hatch_build.py
import subprocess
import sys

from hatchling.builders.hooks.plugin.interface import BuildHookInterface


class CustomBuildHook(BuildHookInterface):
    """Build hook for running actions at build time."""

    def initialize(self, version, build_data):
        """Build retrohunt and yara ready to be bundled for install."""
        # Runs before build
        print("Running custom build steps...")
        protoc_command = ["make", "compile"]
        if subprocess.call(protoc_command) != 0:
            sys.exit(-1)
