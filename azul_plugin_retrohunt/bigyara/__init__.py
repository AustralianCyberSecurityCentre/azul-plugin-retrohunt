"""Bigyara high-level search/API over biggrep."""

from typing import Callable

# bgparse will error if data to search on is less than 3 bytes
SEARCH_ATOM_SIZE_MIN = 3

# type aliases:

# dict[rule name,[list[file path]]
RuleFileMatches = dict[str, list[str]]

# dict[rule name,[list[atom]]
RuleAtoms = dict[str, list[bytes]]

# dict[file path, dict[config key, config value]
FileConfig = dict[str, dict[bytes, bytes]]

# dict[rule name, rule text]
RuleContent = dict[str, bytes]

# data_callback(file path, dict[config key, config value]) -> file data
DataCallback = Callable[[str, dict[bytes, bytes]], bytes]

# progress_callback(searchPhase, done, total, tuple[new match rule, list[match path or atom]])
ProgressCallback = Callable[[int, int, int, tuple[str, list[str | bytes]]], None]


class QueryTypeEnum:
    """Enum for type of search query being run."""

    STRING: int = 0
    YARA: int = 1
    SURICATA: int = 2


class SearchPhaseEnum:
    """Enum for which phase of search we are in."""

    ATOM_PARSE: int = 0
    BROAD_PHASE: int = 1
    NARROW_PHASE: int = 2
