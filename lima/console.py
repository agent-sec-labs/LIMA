"""Console helpers shared by LIMA command-line entry points."""

from __future__ import annotations

import sys


def configure_utf8_stdio() -> None:
    """Use deterministic UTF-8 output even when the host locale is legacy.

    GitHub's Windows runners and older Windows shells can expose ``cp1252``
    standard streams. LIMA reports contain Chinese human-readable text, so a
    locale-dependent stream would otherwise raise ``UnicodeEncodeError``.
    ``StringIO`` and other test doubles do not provide ``reconfigure`` and are
    intentionally left unchanged.
    """

    streams = (
        (sys.stdin, "strict"),
        (sys.stdout, "backslashreplace"),
        (sys.stderr, "backslashreplace"),
    )
    for stream, errors in streams:
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            reconfigure(encoding="utf-8", errors=errors)
