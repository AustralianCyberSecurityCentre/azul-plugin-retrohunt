#!/usr/bin/env python3
"""Setup script."""
import os
import subprocess  # noqa S404  # nosec: B404
import sys

from setuptools import setup
from setuptools.command.build_py import build_py


class Build(build_py):
    """Helper to build."""

    def run(self):
        """Run make compile."""
        protoc_command = ["make", "compile"]
        if subprocess.call(protoc_command) != 0:  # noqa: S603  # nosec: B603
            sys.exit(-1)
        build_py.run(self)


def open_file(fname):
    """Open and return a file-like object for the relative filename."""
    return open(os.path.join(os.path.dirname(__file__), fname))


setup(
    name="azul-plugin-retrohunt",
    description="AZUL plugins for indexing and searching historical samples efficiently",
    author="Azul",
    cmdclass={"build_py": Build},
    author_email="azul@asd.gov.au",
    url="https://www.asd.gov.au/",
    packages=["azul_plugin_retrohunt"],
    include_package_data=True,
    python_requires=">=3.12",
    classifiers=[],
    entry_points={
        "console_scripts": [
            "azul-plugin-retroingestor = azul_plugin_retrohunt.ingestor:main",
            "azul-plugin-retroindexer = azul_plugin_retrohunt.indexer:main",
            "azul-plugin-retroserver = azul_plugin_retrohunt.server:main",
            "azul-plugin-retroworker = azul_plugin_retrohunt.worker:main",
        ],
        # plugins for restapi
        "azul_restapi.plugin": [
            "retrohunt = azul_plugin_retrohunt.api:router",
        ],
    },
    # needs to be defined as not source controlled
    data_files=[
        (
            "bin",
            [
                "azul_plugin_retrohunt/bigyara/bin/bgindex",
                "azul_plugin_retrohunt/bigyara/bin/bgdump",
                "azul_plugin_retrohunt/bigyara/bin/bgparse",
                "azul_plugin_retrohunt/bigyara/bin/yarac-small",
                "azul_plugin_retrohunt/bigyara/bin/yarac-large",
            ],
        ),
    ],
    use_scm_version=True,
    setup_requires=["setuptools_scm"],
    install_requires=[r.strip() for r in open_file("requirements.txt") if not r.startswith("#")],
)
