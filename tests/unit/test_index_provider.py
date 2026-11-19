"""Bedrock CLI integration tests without object-store credentials or network."""

from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from azul_plugin_retrohunt.index_provider import IndexUnavailable, ObjectIndexProvider

FIRST = "a" * 64
SECOND = "b" * 64


def provider(tmp_path):
    settings = SimpleNamespace(
        index_cache_dir=str(tmp_path), index_cli_path="azul-index",
        index_fetch_workers=2, index_list_timeout_seconds=10,
        index_fetch_timeout_seconds=10,
    )
    return ObjectIndexProvider(settings)


def test_list_rejects_empty_and_malformed_ids(tmp_path):
    instance = provider(tmp_path)
    with patch.object(instance, "_run_cli", return_value=""):
        with pytest.raises(IndexUnavailable, match="No published"):
            instance.list_indexes()
    with patch.object(instance, "_run_cli", return_value="../bad"):
        with pytest.raises(IndexUnavailable, match="invalid"):
            instance.list_indexes()


def test_list_deduplicates_and_sorts(tmp_path):
    instance = provider(tmp_path)
    with patch.object(instance, "_run_cli", return_value=f"{SECOND}\n{FIRST}\n{FIRST}\n"):
        assert instance.list_indexes() == [FIRST, SECOND]


def test_fetch_invokes_cli_and_checks_local_file(tmp_path):
    instance = provider(tmp_path)

    def fake_cli(command, *args, **_kwargs):
        assert command == "fetch"
        output = Path(args[args.index("--output") + 1])
        output.write_bytes(b"valid test bgi placeholder")
        return str(output)

    with patch.object(instance, "_run_cli", side_effect=fake_cli):
        assert instance.fetch(FIRST) == tmp_path / f"{FIRST}.bgi"


def test_prepare_requires_all_indexes(tmp_path):
    instance = provider(tmp_path)
    with patch.object(instance, "list_indexes", return_value=[FIRST, SECOND]):
        with patch.object(instance, "fetch", side_effect=lambda index_id: (
            tmp_path / f"{index_id}.bgi" if index_id == FIRST else (_ for _ in ()).throw(ValueError("missing"))
        )):
            with pytest.raises(IndexUnavailable, match="complete index snapshot"):
                instance.prepare()


def test_prepare_snapshot_order(tmp_path):
    instance = provider(tmp_path)
    with patch.object(instance, "list_indexes", return_value=[SECOND, FIRST]):
        with patch.object(instance, "fetch", side_effect=lambda index_id: tmp_path / f"{index_id}.bgi"):
            assert instance.prepare() == [tmp_path / f"{FIRST}.bgi", tmp_path / f"{SECOND}.bgi"]


def test_search_snapshot_excludes_old_cache_and_cleans_up(tmp_path):
    """A new hunt must not accidentally search an index from an earlier hunt."""
    instance = provider(tmp_path)
    current = tmp_path / f"{FIRST}.bgi"
    stale = tmp_path / f"{SECOND}.bgi"
    current.write_bytes(b"current")
    stale.write_bytes(b"stale")

    with patch.object(instance, "prepare", return_value=[current]):
        with instance.search_snapshot() as snapshot:
            assert sorted(path.name for path in snapshot.glob("*.bgi")) == [f"{FIRST}.bgi"]
            assert (snapshot / f"{FIRST}.bgi").resolve() == current
        assert not snapshot.exists()


def test_cli_failure_does_not_expose_command_stderr(tmp_path):
    """Storage backend errors must not leak secrets in worker-side messages."""
    from subprocess import CalledProcessError

    instance = provider(tmp_path)
    with patch("subprocess.run", side_effect=CalledProcessError(1, "azul-index", stderr="secret-token")):
        with pytest.raises(IndexUnavailable) as error:
            instance.list_indexes()
    assert "secret-token" not in str(error.value)
