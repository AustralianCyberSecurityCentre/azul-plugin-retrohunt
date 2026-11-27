# Retrohunt object-index consumer (Python storage shim)

Retroindexer is the **only producer** of `.bgi` indexes. It publishes object keys
`<AZUL_INDEX_PREFIX>/<sha256>.bgi` and a matching `<sha256>.ready` marker. Retrohunt
reads those objects through a small Python shim and downloads checksum-verified local
**batches** for BigGrep mmap searching; it does not store the whole index collection. **No `azul-index` executable or Retroindexer
container image is required in Retrohunt.**

## Required changes outside this archive

The uploaded archive contained only `azul_plugin_retrohunt/`, **not** the root
`Dockerfile`, `pyproject.toml`, `uv.lock`, Helm chart, or pipeline YAML.
Apply these in the real Retrohunt repository:

1. **Dockerfile:** remove the `ARG RETROINDEXER_CLI_IMAGE=...`, the
   `FROM ${RETROINDEXER_CLI_IMAGE} AS index-cli` stage, and the
   `COPY --from=index-cli /usr/local/bin/azul-index /usr/local/bin/azul-index`
   line. Retain all existing Python, YARA-X, and BigGrep build stages.
2. **Python dependencies:** add `azure-storage-blob`, `azure-identity` (required
   only when using Azure keyless credentials), and `boto3`. Pin using the
   project's established versioning conventions, then run `uv lock` and
   `uv sync` to update the lockfile. Installing all three supports both backends.
3. **Helm/Argo:** keep the existing `AZUL_INDEX_*` settings and secret refs,
   and the `PLUGIN_INDEX_CACHE_DIR` volume mount. Remove any obsolete
   `PLUGIN_INDEX_CLI_PATH`. No additional sidecar/pipeline is required.
4. **Publisher:** no code changes. Its existing `.bgi` and `.ready` object
   names are consumed as-is.

## Runtime variables

| Variable | Purpose |
| --- | --- |
| `AZUL_INDEX_BACKEND` | `azure` or `s3` (required) |
| `AZUL_INDEX_PREFIX` | Object prefix, default `retrohunt/indices` |
| `AZUL_INDEX_AZURE_CONTAINER` | Azure Blob container (required for Azure) |
| `AZUL_INDEX_AZURE_ENDPOINT` | Azure account URL; if absent, derived from `AZUL_INDEX_AZURE_ACCOUNT` |
| `AZUL_INDEX_AZURE_ACCOUNT` | Azure storage-account name |
| `AZUL_INDEX_AZURE_KEY` | Azure account key; when absent uses `DefaultAzureCredential` |
| `AZUL_INDEX_S3_BUCKET` | S3 bucket (required for S3) |
| `AZUL_INDEX_S3_ENDPOINT` | Optional endpoint for SeaweedFS/other S3-compatible storage |
| `AZUL_INDEX_S3_SECURE` | `false` only for non-TLS dev endpoints; default `true` |
| `AZUL_INDEX_S3_REGION` | S3 region; optional for default AWS SDK discovery |
| `AZUL_INDEX_S3_ACCESS_KEY`/`AZUL_INDEX_S3_SECRET_KEY` | Optional static keys; absent = AWS default credential chain |
| `PLUGIN_INDEX_CACHE_DIR` | Local disk cache, default `/tmp/retrohunt-index-cache` |
| `PLUGIN_INDEX_CACHE_MAX_BYTES` | Maximum bytes in one active local index batch; default 10737418240 (10 GiB) |
| `PLUGIN_INDEX_FETCH_WORKERS` | Legacy setting; bounded batches currently download sequentially |
| `PLUGIN_INDEX_LIST_TIMEOUT_SECONDS` | Listing deadline (checked while traversing results), default 120 |
| `PLUGIN_INDEX_FETCH_TIMEOUT_SECONDS` | Download deadline (checked between chunks), default 1800 |

The storage backend must be configured consistently with Retroindexer (same
backend, bucket/container, prefix, and endpoint). `AZUL_INDEX_*` environment
variables intentionally use no `PLUGIN_` prefix; `RetrohuntSettings` handles
only the `PLUGIN_*` worker-specific options.

## Safety and consistency

- Only IDs with both `.bgi` and `.ready` are included in the one-time hunt listing.
- The provider asks the object store for each object's size before downloading,
  checks the configured byte budget, streams the index with a byte limit, and
  verifies its SHA-256 before exposing it to BigGrep. A single oversized index
  produces an explicit error; it is never skipped silently.
- The first batch is searched locally, **then deleted before the next batch is
  downloaded**. The whole collection never needs to fit on the local volume.
- The hunt accumulates broad-phase candidate paths and metadata from every batch,
  then runs one narrow-phase YARA-X/Suricata verification across the union.
  A failed index download or BigGrep error fails the hunt, not a partial success.
- `flock` serialises hunts using the same cache volume. Different pods with
  independent volumes can search concurrently. This simple initial design
  prioritises disk safety over overlapping parallel hunts on one volume.
- The per-batch directory is deleted on normal success, cancellation or exception.
  Abrupt container termination may leave orphaned temporary directories;
  remove those only after confirming no hunt is using them.
- No persistent cache reuse is provided in this revision; repeat hunts download
  indexes again. The previous shim's old persistent `*.bgi` files, if any,
  are not touched and must be audited separately before cleanup.
- `PLUGIN_INDEX_CACHE_MAX_BYTES` caps active index-file bytes, not all container
  filesystem usage (logs, other processes, and filesystem overhead still count).
  Choose a value well below the pod's actual available ephemeral-storage budget.
- Broad-phase progress is reported in physical `bgparse` tasks across all
  batches, matching the original search worker's progress semantics.
- The `MAX_BROAD_PHASE_TASKS` hard limit applies to the **entire published index
  snapshot**, not independently to each batch. A hunt exceeding the original
  global safety budget fails rather than circumventing that limit via batching.
- The source-file candidate set is still collected in memory for one final
  narrow phase, as it was in the original search implementation. Extremely
  high candidate counts still need resource monitoring.
- On the next hunt, leftover `.hunt-batch-*` directories from an interrupted
  process are removed while holding the exclusive cache lock. Legacy `.bgi`
  files directly inside the cache directory cause an explicit failure; review
  and remove those files before using the new batching scheme.
- The S3 adapter uses `head_object` to measure file sizes before downloading;
  the Azure adapter uses Blob properties. Neither backend needs the Go CLI.
- The list/fetch timeout is best-effort and checked between SDK operations.

## Validate

From the Retrohunt repository after installing the Python dependencies:

```bash
PYTHONPATH=. pytest -q tests/test_index_storage_shim.py
```

To check an actual store without starting a hunt, set the real `AZUL_INDEX_*`
variables then run:

```bash
python - <<'PY'
from azul_plugin_retrohunt.index_storage import create_storage, index_prefix
p = index_prefix()
print('ready marker keys:', sum(k.endswith('.ready') for k in create_storage().list_keys(p)))
PY
```

This command only lists objects and does not download indexes. A full integration
check should run a Retrohunt with an externally published test index and verify
its search results. Do not log storage secrets.
