# Production object-index Retrohunt

This variant assumes **Retroindexer is already deployed**, the Bedrock
`azul-index` CLI is implemented and published, and indexes are continuously
published to the same configured storage backend. This repository is a **read-only
search consumer**; there are no ingestion/indexer entry points or shared PVC
index directories.

## Required runtime and build contract

* Publish a versioned container image from Bedrock containing the `azul-index`
  executable at `/usr/local/bin/azul-index`. Build Retrohunt with
  `--build-arg INDEX_CLI_IMAGE=<registry>/azul-index-cli@sha256:<digest>`.
  `azul-index-cli:latest` is only a developer placeholder, **not** a production
  image. The image must expose the executable in the expected location.
* The source code for `azul-index` must implement `list` returning **one SHA-256
  index ID per line** and `fetch --id ID --output PATH`, as in the Bedrock
  proof of concept. The CLI must use the same backend credentials and namespace
  as Retroindexer's `put` operation.
* Keep `bgparse` and the YARA-X CLI from the existing Retrohunt image. Neither
  is responsible for storage or index creation.
* Ensure Kubernetes injects `AZUL_INDEX_*` settings and storage credentials
  into **the Retrohunt worker**. See below.

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
Bedrock CLI to use its IAM path. The original POC CLI requires an endpoint; use
its documented AWS endpoint format until Bedrock supports optional endpoint.

**Azure Blob:** use `AZUL_INDEX_BACKEND=azure`,
`AZUL_INDEX_AZURE_ENDPOINT`, `AZUL_INDEX_AZURE_CONTAINER`, and the supported
account authentication env vars in the Bedrock implementation.

Other worker settings:

| Environment | Default | Meaning |
|---|---|---|
| `PLUGIN_INDEX_CLI_PATH` | `azul-index` | Installed Bedrock executable |
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
between pods. The existing Bedrock POC re-hashes a cache hit on every fetch,
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
