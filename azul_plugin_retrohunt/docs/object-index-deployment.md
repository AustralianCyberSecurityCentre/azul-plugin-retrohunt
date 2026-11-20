# Production object-index Retrohunt

This variant assumes **Retroindexer is already deployed**, the Retroindexer-owned
`azul-index` CLI is built into the Retroindexer image, and indexes are continuously
published to the same configured storage backend. This repository is a **read-only
search consumer**; there are no ingestion/indexer entry points or shared PVC
index directories.

## Required runtime and build contract

* **Bedrock remains unchanged.** Retroindexer owns the `cmd` Go CLI, builds the
  `/usr/local/bin/azul-index` executable, and publishes SHA-256-named `.bgi`
  objects with `.ready` markers. Its existing Bedrock dependency provides the
  S3 and Azure Blob Storage clients.
* Build Retrohunt using a **version-pinned Retroindexer image** as the binary
  source. The CLI binary is copied into Retrohunt, not run as a separate
  Retroindexer service. Example Dockerfile fragment (apply this to the real
  Retrohunt Dockerfile, which was **not included** in the uploaded ZIP):

  ```dockerfile
  ARG RETROINDEXER_CLI_IMAGE
  FROM ${RETROINDEXER_CLI_IMAGE} AS retroindexer-cli
  # In the final Retrohunt image stage:
  COPY --from=retroindexer-cli /usr/local/bin/azul-index /usr/local/bin/azul-index
  ```

  Build with a pinned release/digest, for example
  `--build-arg RETROINDEXER_CLI_IMAGE=<registry>/retroindexer@sha256:<digest>`.
  The image **must** contain the built CLI at that exact path. Setting this build
  argument in values.yaml alone does not add a binary to an existing image.
* The CLI supports `list` (one SHA-256 ID per line), `fetch --id ID --output
  PATH`, and `put --file PATH`. Retrohunt invokes **only** `list` and `fetch`;
  indexing and publication remain exclusively Retroindexer's responsibility.
* **Match the publisher's namespace:** both deployments need the same
  `AZUL_INDEX_PREFIX` (default `retrohunt/indices`), backend, container/bucket,
  and endpoint. The CLI is configured independently inside each pod.
* Keep `bgparse` and YARA-X in Retrohunt; BigGrep continues to mmap local
  cached files. No shared index PVC or Retrohunt index writer is needed.
* The uploaded ZIP contains the Python package only, so applying this archive
  does **not** modify your real Retrohunt Dockerfile or Helm templates.

## S3 / SeaweedFS environment (example)

```yaml
# Helm deployment template values; adapt to your chart / Secret references.
env:
  - name: AZUL_INDEX_BACKEND
    value: s3
  - name: AZUL_INDEX_S3_BUCKET
    value: retrohunt-indexes
  - name: AZUL_INDEX_S3_ENDPOINT
    value: seaweedfs-retrohunt-s3:8333  # example, use real service DNS
  - name: AZUL_INDEX_S3_SECURE
    value: "false"  # only for in-cluster non-TLS dev endpoint
  - name: AZUL_INDEX_S3_REGION
    value: ap-southeast-2
  - name: AZUL_INDEX_S3_ACCESS_KEY
    valueFrom:
      secretKeyRef:
        name: retrohunt-object-store
        key: access-key
  - name: AZUL_INDEX_S3_SECRET_KEY
    valueFrom:
      secretKeyRef:
        name: retrohunt-object-store
        key: secret-key
  - name: PLUGIN_INDEX_CACHE_DIR
    value: /var/cache/retrohunt/indexes
  - name: PLUGIN_INDEX_FETCH_WORKERS
    value: "4"
```

**AWS IAM:** do not inject keys; configure workload credentials and allow the
Retroindexer CLI to use its IAM path. The Retroindexer CLI allows an empty
endpoint for the default AWS S3 endpoint.

**Azure Blob:** use `AZUL_INDEX_BACKEND=azure`,
`AZUL_INDEX_AZURE_ENDPOINT`, `AZUL_INDEX_AZURE_CONTAINER`, and the supported
`AZUL_INDEX_AZURE_ACCOUNT` and `AZUL_INDEX_AZURE_KEY` (or Azure workload
identity supported by the underlying Bedrock storage client).

Other worker settings:

| Environment | Default | Meaning |
|---|---|---|
| `PLUGIN_INDEX_CLI_PATH` | `azul-index` | Installed Retroindexer executable |
| `PLUGIN_INDEX_CACHE_DIR` | `/tmp/retrohunt-index-cache` | Local verified cache, not a PVC |
| `PLUGIN_INDEX_FETCH_WORKERS` | `4` | Concurrent index fetch subprocesses |
| `PLUGIN_INDEX_LIST_TIMEOUT_SECONDS` | `120` | List deadline |
| `PLUGIN_INDEX_FETCH_TIMEOUT_SECONDS` | `1800` | Per-index fetch deadline |

## Kubernetes storage

```yaml
volumes:
  - name: index-cache
    emptyDir:
      sizeLimit: 100Gi  # EXAMPLE ONLY: size from production index footprint
containers:
  - name: retrohunt-worker
    volumeMounts:
      - name: index-cache
        mountPath: /var/cache/retrohunt/indexes
    resources:
      requests:
        ephemeral-storage: 100Gi  # illustrative; account for pod/node budgets
```

The CLI caches **full** indexes because `bgparse` requires local files for
`mmap()`. The store must support reading all published `.bgi` objects. The
actual disk size and download concurrency must be measured on real data before
production deployment. Each pod has its own cache; no downloads are shared
between pods. The Retroindexer CLI re-hashes a cache hit on every fetch,
which adds sequential disk I/O but protects cache integrity.

## Consistency and failure behaviour

* `azul-index list` observes only indexes with their `.ready` marker. The
  process snapshots the IDs once per hunt.
* The worker invokes `azul-index fetch` for every ID (also for cache hits).
  Fetch verifies SHA-256, performs file-level locking and atomic publication.
* A hunt-specific directory of **symlinks** exposes precisely the listed IDs
  to BigGrep, excluding stale cached indexes without copying index bytes.
* If listing or **any** fetch fails, the hunt fails instead of reporting a
  misleading empty result. No fallback to PVC or local indexing exists.
* No automatic cache eviction is included. This is important for long-lived
  pods; use a node/pod capacity policy and implement safe eviction based on
  active snapshots before enabling unbounded retention in production.
* Fetch currently cannot be cancelled midway: the subprocess has a timeout,
  and job cancellation is checked before and after preparation. This should be
  improved for larger deployments.

## Manual verification in the worker container

```bash
azul-index list | head
azul-index fetch --id '<published-sha256>' --output /var/cache/retrohunt/indexes/test.bgi
azul-plugin-retroworker  # normal Redis-driven worker process
```

Verify the command is available at runtime (this fails fast if it is missing):

```bash
command -v azul-index
```

The Redis/API/cron configuration remains unchanged. Retire the Retrohunt
indexer, ingestor, and index PVC manifests **in the separate Helm/Argo
repository**, and deploy Retroindexer independently. None of those external
manifests are included in this source archive.

## Test and integration coverage

```bash
PYTHONPATH=. pytest -q tests/unit
```

The old tests that generated indexes in-process were removed along with the
producer implementation. Add production integration tests using externally
published sample `.bgi` objects, and compare their `bgparse`/YARA-X results
with historical PVC-based runs before activating the new worker in production.
