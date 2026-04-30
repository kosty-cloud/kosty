"""Scan progress display — ANSI progress bars for kosty audit.

Pure stdlib, no external dependencies. Writes to stderr only so
stdout remains clean for --output json/csv piping.

Renders only when stderr is a TTY. Silent when piped or redirected.

Single account: one bar advancing check by check.
Multi-account:  one bar per account, stacked vertically.
"""

import sys
import threading
from typing import Dict, List

_RESET  = "\033[0m"
_GREEN  = "\033[32m"
_CYAN   = "\033[36m"
_DIM    = "\033[2m"
_BOLD   = "\033[1m"
_CLEAR  = "\033[2K"
_UP     = "\033[1A"

BAR_WIDTH = 30
FILL  = "#"
EMPTY = "-"


def _bar(done: int, total: int) -> str:
    if total == 0:
        return EMPTY * BAR_WIDTH
    filled = int(BAR_WIDTH * done / total)
    return FILL * filled + EMPTY * (BAR_WIDTH - filled)


def _is_tty() -> bool:
    return hasattr(sys.stderr, 'isatty') and sys.stderr.isatty()


class SingleAccountProgress:
    """One progress bar for a single-account scan.

    Example (on TTY):
      Scanning  [##########--------------------]   67/151  IAM
    """

    def __init__(self, total: int):
        self._total = total
        self._done = 0
        self._service = ""
        self._lock = threading.Lock()
        self._active = _is_tty()
        if self._active:
            sys.stderr.write("\n")
            sys.stderr.flush()

    def update(self, service: str = ""):
        if not self._active:
            return
        with self._lock:
            self._done += 1
            self._service = service
            self._draw()

    def _draw(self):
        bar = _bar(self._done, self._total)
        svc = (self._service or "")[:18].ljust(18)
        line = (
            f"\r{_CYAN}Scanning{_RESET}  "
            f"[{_GREEN}{bar}{_RESET}]  "
            f"{_BOLD}{self._done:>4}/{self._total}{_RESET}  "
            f"{_DIM}{svc}{_RESET}"
        )
        sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self):
        if not self._active:
            return
        with self._lock:
            self._draw()
            sys.stderr.write("\n")
            sys.stderr.flush()


class MultiAccountProgress:
    """Stacked progress bars for multi-account scans.

    Example (on TTY):
      123456789012  [##########--------------------]   40/151   26%
      987654321098  [####################----------]   89/151   58%
    """

    def __init__(self, accounts: List[str], total_checks: int):
        self._accounts = list(accounts)
        self._total = total_checks
        self._done: Dict[str, int] = {a: 0 for a in accounts}
        self._lock = threading.Lock()
        self._lines_drawn = 0
        self._active = _is_tty()
        if self._active:
            # Reserve lines
            sys.stderr.write("\n" * len(self._accounts))
            sys.stderr.flush()

    def update(self, account_id: str):
        if not self._active:
            return
        with self._lock:
            self._done[account_id] = self._done.get(account_id, 0) + 1
            self._draw()

    def _draw(self):
        n = len(self._accounts)
        # Move cursor up to overwrite reserved lines
        sys.stderr.write(_UP * n)
        for acc in self._accounts:
            done = self._done.get(acc, 0)
            bar = _bar(done, self._total)
            pct = int(100 * done / self._total) if self._total else 0
            line = (
                f"\r{_CLEAR}"
                f"{_DIM}{acc}{_RESET}  "
                f"[{_GREEN}{bar}{_RESET}]  "
                f"{_BOLD}{done:>4}/{self._total}{_RESET}  "
                f"{_DIM}{pct:>3}%{_RESET}\n"
            )
            sys.stderr.write(line)
        sys.stderr.flush()

    def finish(self):
        if not self._active:
            return
        with self._lock:
            self._draw()
