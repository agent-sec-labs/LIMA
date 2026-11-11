"""Renew one scan's registry lease until its consumer has stopped."""

import threading
from collections.abc import Callable


class VerifiedContextLease:
    def __init__(self, renew: Callable[[], bool], *, interval_seconds: float = 60):
        self.renew = renew
        self.interval_seconds = interval_seconds
        self.stopped = threading.Event()
        self.lost = threading.Event()
        self.thread = threading.Thread(target=self._run, daemon=True, name="verified-view-lease")

    def start(self) -> None:
        self.thread.start()

    def _run(self) -> None:
        while not self.stopped.wait(self.interval_seconds):
            try:
                if self.renew():
                    continue
            except Exception:  # noqa: BLE001 - a failed renewal loses the lease
                self.lost.set()
                return
            self.lost.set()
            return

    def close(self) -> None:
        self.stopped.set()
        # Callers provide a bounded transport. Join before release so a
        # delayed renewal cannot race cleanup or resurrect an ended scan.
        if self.thread.ident is not None:
            self.thread.join()
