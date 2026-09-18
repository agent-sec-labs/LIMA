"""Canonical C/C++ source and header language mapping for every Sidecar layer."""

from __future__ import annotations

from pathlib import PurePosixPath
from types import MappingProxyType
from typing import Final

CXX_LANGUAGE_BY_SUFFIX: Final = MappingProxyType(
    {
        ".c": "c",
        ".h": "c",
        ".cc": "c++",
        ".cpp": "c++",
        ".cxx": "c++",
        ".hh": "c++",
        ".hpp": "c++",
        ".hxx": "c++",
    }
)
CXX_SOURCE_SUFFIXES: Final = frozenset(CXX_LANGUAGE_BY_SUFFIX)
CXX_HEADER_SUFFIXES: Final = frozenset({".h", ".hh", ".hpp", ".hxx"})


def language_for_path(path: str) -> str:
    """Return the fixed language for a supported safe path suffix."""

    language = CXX_LANGUAGE_BY_SUFFIX.get(PurePosixPath(path).suffix.lower())
    if language is None:
        raise ValueError("path does not identify a supported C/C++ source or header")
    return language
