"""Tiny logger: stdout plus an optional rotating-free file.

The service writes to stdout so systemd/journald can pick it up, and to
`log/pof.log` (and `log/pof.err` for errors) when a log directory is
configured. Logging must never take the capture loop down, so every file
operation is wrapped.
"""
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

_lock = threading.Lock()
_config = {'dir': None, 'verbose': False, 'quiet': False}


def setup(directory=None, verbose=False, quiet=False):
    """`directory` is a path or None (stdout only)."""
    _config['dir'] = Path(directory) if directory else None
    _config['verbose'] = bool(verbose)
    _config['quiet'] = bool(quiet)
    if _config['dir']:
        try:
            _config['dir'].mkdir(parents=True, exist_ok=True)
        except OSError as err:
            _config['dir'] = None
            print('pof: cannot create log dir: {}'.format(err), file=sys.stderr, flush=True)


def log(message, module='pof', level='INFO'):
    if level == 'DEBUG' and not _config['verbose']:
        return
    if _config['quiet'] and level not in ('ERROR', 'WARNING'):
        return
    stamp = datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')[:-3] + 'Z'
    line = '{} {} {} {}'.format(stamp, level.ljust(5), module.ljust(11), message)
    with _lock:
        print(line, flush=True)
        if _config['dir'] is None:
            return
        try:
            with open(_config['dir'] / 'pof.log', 'a', encoding='utf-8') as handle:
                handle.write(line + '\n')
            if level == 'ERROR':
                with open(_config['dir'] / 'pof.err', 'a', encoding='utf-8') as handle:
                    handle.write(line + '\n')
        except OSError as err:  # a full disk must not stop packet capture
            print('pof: cannot write log file: {}'.format(err), file=sys.stderr, flush=True)
