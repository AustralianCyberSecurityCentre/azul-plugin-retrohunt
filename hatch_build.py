import os
import subprocess
import sys
from hatchling.builders.hooks.plugin.interface import BuildHookInterface

class CustomBuildHook(BuildHookInterface):
    def initialize(self, version, build_data):
        # Skip build steps when running inside tox
        if os.environ.get("TOX_ENV_NAME"):
            print("Skipping custom build steps inside tox...")
            return

        print("Running custom build steps...")
        if subprocess.call(["make", "compile"]) != 0:
            sys.exit(-1)