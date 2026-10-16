"""Subprocess execution that owns, terminates, and reaps a whole process group."""
from __future__ import annotations

import ctypes
import errno
import os
import signal
import subprocess
import sys
import time

_SUBREAPER_ENABLED = False


def _enable_subreaper() -> None:
    """Arrange for orphaned grandchildren to be reparented here on Linux."""
    global _SUBREAPER_ENABLED
    if _SUBREAPER_ENABLED or not sys.platform.startswith("linux"):
        return
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
        error = ctypes.get_errno()
        raise OSError(error, os.strerror(error))
    _SUBREAPER_ENABLED = True


def _reap_group(pgid: int, deadline: float) -> None:
    while time.monotonic() < deadline:
        reaped = False
        while True:
            try:
                pid, _ = os.waitpid(-pgid, os.WNOHANG)
            except ChildProcessError:
                return
            if pid == 0:
                break
            reaped = True
        if not reaped:
            time.sleep(.01)
    while True:
        try:
            pid, _ = os.waitpid(-pgid, os.WNOHANG)
        except ChildProcessError:
            return
        if pid == 0:
            return


def terminate_process_group(process: subprocess.Popen, grace: float = .2) -> None:
    pgid = process.pid
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()
    # Descendants may have been reparented to this subreaper. Kill again after
    # the leader exits, then reap them so PID probes cannot observe zombies.
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    _reap_group(pgid, time.monotonic() + grace)


def run_in_process_group(argv, *, timeout: float, **kwargs) -> subprocess.CompletedProcess:
    """A subprocess.run subset with deterministic process-tree cleanup."""
    _enable_subreaper()
    process = subprocess.Popen(argv, start_new_session=True, **kwargs)
    try:
        returncode = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        terminate_process_group(process)
        raise subprocess.TimeoutExpired(argv, timeout)
    except BaseException:
        terminate_process_group(process)
        raise
    return subprocess.CompletedProcess(argv, returncode)
