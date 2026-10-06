```dockerfile
ARG REGISTRY="docker.io/library"
ARG BUILD_IMAGE='python'
ARG BUILD_TAG='3.12-trixie@sha256:3528d5830ec8b7c8729a2a9961154061c7d34e114089ab5c6b1da707ed581c87'
ARG BASE_IMAGE='python'
ARG BASE_TAG='3.12-slim-trixie@sha256:02108f5d322dd89f1c9e552442c25acb0543dfdbc455693a5599624f20d9155d'


FROM $REGISTRY/$BUILD_IMAGE:$BUILD_TAG AS builder
ENV DEBIAN_FRONTEND=noninteractive
ENV PIP_DISABLE_PIP_VERSION_CHECK=yes
ARG PIP_CERT
ARG PIP_CLIENT_CERT
ARG PIP_TRUSTED_HOST
ARG PIP_INDEX_URL
ARG PIP_EXTRA_INDEX_URL
ARG GIT_BRANCH_NAME

# expected to be public registry (e.g pypi.org)
ARG UV_DEFAULT_INDEX

# expected to be private registry
ARG UV_INDEX_URL
ARG UV_INSECURE_HOST

# Ensure uv installs to the correct directory
ENV UV_PROJECT_ENVIRONMENT=/usr/local

COPY debian.txt /tmp/src/
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*

# copy all files not in .dockerignore
COPY ./ /tmp/src
RUN pip install uv

# build and install package
WORKDIR /tmp/src

# Install all dependencies
RUN uv sync --frozen --no-editable

# Install package with version attached.
# (hatchling and hatch-vcs installed after sync to avoid being uninstalled)
RUN uv pip install --system hatchling hatch-vcs

RUN uv build . --out-dir /tmp/

RUN uv pip uninstall --system azul-plugin-retrohunt

RUN uv pip install --system --find-links /tmp/ \
    azul-plugin-retrohunt[runtime]==$(hatchling version)

# Upgrade to dev azul dependencies or upgrade non-dev azul dependencies depending on branch.
RUN if [ "$GIT_BRANCH_NAME" = "refs/heads/dev" ]; then \
    uv pip freeze | grep 'azul-.*==' | grep -v '^azul-plugin-retrohunt' | cut -d "=" -f 1 | xargs -I {} uv pip install --extra-index-url=$UV_INDEX_URL --system --upgrade --no-deps --prerelease allow '{}>=0.0.0-dev'; \
    else \
    uv pip freeze | grep 'azul-.*==' | grep -v '^azul-plugin-retrohunt' | cut -d "=" -f 1 | xargs -I {} uv pip install --extra-index-url=$UV_INDEX_URL --system --upgrade --no-deps '{}>=0.0.0'; \
    fi


FROM $REGISTRY/$BASE_IMAGE:$BASE_TAG AS base
ENV DEBIAN_FRONTEND=noninteractive

COPY debian.txt /tmp/src/

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
    $(grep -vE "^\s*(#|$)" /tmp/src/debian.txt | tr "\n" " ") && \
    rm -rf /tmp/src/debian.txt /var/lib/apt/lists/*

ARG UID=21000
ARG GID=21000

RUN groupadd -g $GID