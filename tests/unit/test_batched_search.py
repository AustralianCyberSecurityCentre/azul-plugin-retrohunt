"""Regressions for full-hunt semantics across disk-bounded index batches."""

from pathlib import Path

import pytest

pytest.importorskip("yara_x")

from azul_plugin_retrohunt.bigyara import search as module


class Batches:
    def __init__(self, root):
        self.root = root

    def iter_search_batches(self):
        for i in range(3):
            batch = self.root / str(i)
            batch.mkdir()
            (batch / f"{i}.bgi").write_bytes(b"dummy")

            try:
                yield batch, i, 1, 3
            finally:
                for f in batch.iterdir():
                    f.unlink()
                batch.rmdir()


def test_broad_candidates_union_and_single_narrow(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module,
        "_atom_parse",
        lambda *args: (
            {"rule": [b"atom"]},
            "compiled",
            {"rule": "plan"},
        ),
    )

    seen = []
    global_counts = []

    def broad(
        _type,
        indices,
        _plans,
        callback,
        query_hash,
        global_index_count=None,
    ):
        assert len(indices) == 1

        # The global budget must use all indexes, not just this batch.
        assert global_index_count == 3
        global_counts.append(global_index_count)

        i = int(Path(indices[0]).stem)

        callback(
            module.SearchPhaseEnum.BROAD_PHASE,
            1,
            1,
            ("rule", [f"/sample/{i}"]),
        )

        if i == 1:
            raise module.NoIndexMatchesException("none in this batch")

        return (
            {"rule": ["/sample/0", f"/sample/{i}"]},
            {
                "/sample/0": {b"sample": b"0"},
                f"/sample/{i}": {
                    b"sample": str(i).encode(),
                },
            },
        )

    monkeypatch.setattr(module, "_broad_phase_search", broad)

    def narrow(
        _type,
        matches,
        content,
        config,
        data,
        callback,
        query_hash,
        data_release_callback,
    ):
        seen.append((matches, config.copy(), content))
        return matches

    monkeypatch.setattr(module, "_narrow_phase_search", narrow)

    progress = []

    result = module.search_batched(
        "my query",
        module.QueryTypeEnum.YARA,
        Batches(tmp_path),
        lambda *args: b"file",
        lambda *args: progress.append(args),
    )

    assert result == {
        "rule": ["/sample/0", "/sample/2"],
    }

    # Narrow-phase verification must run once for the entire hunt.
    assert len(seen) == 1
    assert seen[0][2] == "compiled"

    # Every batch must use the full index collection for budgeting.
    assert global_counts == [3, 3, 3]

    # Broad-phase progress is now reported using actual task counts,
    # rather than an artificial 0-1000 scale.
    assert [(p[1], p[2]) for p in progress if p[0] == module.SearchPhaseEnum.BROAD_PHASE] == [
        (1, 3),
        (2, 3),
        (3, 3),
    ]

    # All temporary index batches must have been deleted.
    assert not list(tmp_path.iterdir())


def test_no_candidate_in_any_batch_propagates(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module,
        "_atom_parse",
        lambda *args: (
            {"rule": [b"atom"]},
            "compiled",
            {"rule": "plan"},
        ),
    )

    monkeypatch.setattr(
        module,
        "_broad_phase_search",
        lambda *args, **kwargs: (_ for _ in ()).throw(module.NoIndexMatchesException("empty")),
    )

    with pytest.raises(module.NoIndexMatchesException):
        module.search_batched(
            "q",
            module.QueryTypeEnum.STRING,
            Batches(tmp_path),
        )


def test_batch_failure_not_silently_ignored(tmp_path, monkeypatch):
    monkeypatch.setattr(
        module,
        "_atom_parse",
        lambda *args: (
            {"rule": [b"atom"]},
            "compiled",
            {"rule": "plan"},
        ),
    )

    monkeypatch.setattr(
        module,
        "_broad_phase_search",
        lambda *args, **kwargs: (_ for _ in ()).throw(module.BiggrepException("broken index")),
    )

    with pytest.raises(module.BiggrepException, match="broken index"):
        module.search_batched(
            "q",
            module.QueryTypeEnum.STRING,
            Batches(tmp_path),
        )
