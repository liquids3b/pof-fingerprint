"""Command line entry point: `python src/pof.py [options]`.

Two modes:
  serve (default)  capture SYN packets, keep them in memory, answer the JSON API
  read             replay a `tcpdump -w` file through the same decoder/scorer

Everything else (`--list-database`, `--print-config`) is a self check.
"""
import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import api                     # noqa: E402
import capture as capture_mod  # noqa: E402
import config as config_mod    # noqa: E402
import database                # noqa: E402
import log                     # noqa: E402
import packet                  # noqa: E402
import pcap                    # noqa: E402
import store as store_mod      # noqa: E402

VERSION = '1.0.0'


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        prog='pof.py',
        description='Passive TCP/IP OS fingerprinting service (JSON API).')
    parser.add_argument('--config', help='path to config.json')
    parser.add_argument('--interface', help='capture interface (default: default route)')
    parser.add_argument('--host', help='API bind address (default 0.0.0.0; '
                                       'use 127.0.0.1 behind nginx)')
    parser.add_argument('--port', type=int, help='API port (default 8351)')
    parser.add_argument('--api-key', dest='api_key', help='require ?key=... for bulk endpoints')
    parser.add_argument('--database', help='fingerprint database json')
    parser.add_argument('--max-ips', dest='max_ips', type=int, help='in-memory IP limit')
    parser.add_argument('--per-ip', dest='per_ip', type=int, help='SYNs kept per IP')
    parser.add_argument('--expire-seconds', dest='expire_seconds', type=int,
                        help='drop IPs unseen for this long (0 = never)')
    parser.add_argument('--log-dir', dest='log_dir', help='write logs here (empty = stdout only)')
    parser.add_argument('--no-bpf', dest='bpf', action='store_false', default=None,
                        help='filter SYNs in Python instead of in the kernel')
    parser.add_argument('--ignore-private', dest='ignore_private_ips', action='store_true',
                        default=None, help='skip RFC1918/ULA sources too')
    parser.add_argument('--capture-only', action='store_true', help='do not start the API')
    parser.add_argument('--api-only', action='store_true', help='do not capture (API on stored data)')
    parser.add_argument('--read', metavar='FILE.pcap', help='offline mode: analyse a capture file')
    parser.add_argument('--json', action='store_true', help='with --read: print JSON')
    parser.add_argument('--list-database', action='store_true',
                        help='print the fingerprint database and exit')
    parser.add_argument('--print-config', action='store_true', help='print the config and exit')
    parser.add_argument('--verbose', action='store_true', default=None)
    parser.add_argument('--quiet', action='store_true', default=None)
    parser.add_argument('--version', action='version', version='pof-fingerprint ' + VERSION)
    return parser.parse_args(argv)


def overrides_from(args):
    names = ('interface', 'api_key', 'database', 'max_ips', 'per_ip', 'expire_seconds',
             'log_dir', 'bpf', 'ignore_private_ips', 'verbose', 'quiet')
    overrides = {name: getattr(args, name) for name in names}
    if args.host is not None:
        overrides['api_host'] = args.host
    if args.port is not None:
        overrides['api_port'] = args.port
    return overrides


def read_pcap(path, db, quiet=False):
    """Replay a capture file; returns a list of `(ip, fingerprint, result)`."""
    rows, frames, skipped = [], 0, 0
    for timestamp, linktype, data in pcap.frames(path):
        frames += 1
        frame = pcap.to_ethernet(data, linktype)
        if frame is None:
            skipped += 1
            continue
        fingerprint = packet.decode_frame(frame, timestamp)
        if fingerprint is None or not packet.is_client_syn(fingerprint):
            continue
        fingerprint['ip_src'] = packet.normalize_ip(fingerprint['ip_src'])
        rows.append((fingerprint['ip_src'], fingerprint, db.classify(fingerprint)))
    if not quiet:
        log.log('{}: {} frames, {} client SYNs, {} unsupported link records'.format(
            path, frames, len(rows), skipped), 'read')
    return rows


def _value(value):
    """Imported profiles may leave a field unknown; print that as a dash."""
    return '-' if value is None else value


def print_database(db):
    print('database : {}'.format(db.path))
    print('entries  : {}'.format(len(db.entries)))
    print('max score: {} fields={}'.format(database.MAX_SCORE, len(database.WEIGHTS) + 1))
    print('{:<14}{:>8}{:>12}'.format('os', 'entries', 'sessions'))
    for name in db.os_names:
        print('{:<14}{:>8}{:>12}'.format(name, db.by_os.get(name, 0), db.sessions.get(name, 0)))
    for entry in db.entries:
        print('  {:<12} n={} ttl={} len={} win={} mss={} opts={}'.format(
            entry.get('os'), entry.get('n', 1), _value(entry.get('ip_ttl_initial')),
            _value(entry.get('ip_total_length')), _value(entry.get('tcp_window_size')),
            _value(entry.get('tcp_mss')), entry.get('tcp_options')))


def print_rows(rows, as_json=False):
    if as_json:
        print(json.dumps([{'ip': ip, 'os': result['os'],
                           'confidence': result['confidence'],
                           'score': result['score'],
                           'possible_score': result['possible_score'],
                           'signature': result['signature'],
                           'scores': result['scores'],
                           'fingerprint': api.public_fingerprint(fingerprint)}
                          for ip, fingerprint, result in rows], indent=2))
        return
    print('{:<40}{:<10}{:>6}{:>7}{:>8}  {}'.format(
        'ip', 'os', 'score', 'conf', 'coverage', 'signature'))
    for ip, _fingerprint, result in rows:
        print('{:<40}{:<10}{:>6}{:>7}{:>8}  {}'.format(
            ip, str(result['os']), result['score'], result['confidence'],
            result['coverage'], result['signature']))


def capture_stats(capture, started):
    return {'interface': capture.interface if capture else None,
            'frames': capture.frames if capture else 0,
            'syns_stored': capture.stored if capture else 0,
            'kernel_bpf': capture.filtered_bpf if capture else False,
            'uptime_seconds': round(time.time() - started, 1),
            'time': time.time()}


def main(argv=None):
    args = parse_args(argv)
    try:
        config = config_mod.load(args.config, overrides_from(args))
    except (OSError, ValueError) as err:
        print('pof: bad configuration: {}'.format(err), file=sys.stderr)
        return 2

    log.setup(config['log_dir'], verbose=config['verbose'], quiet=config['quiet'])
    if args.print_config:
        print(json.dumps(config, indent=2, sort_keys=True, default=str))
        return 0

    try:
        db = database.Database(config['database']).load()
    except (OSError, ValueError, json.JSONDecodeError) as err:
        log.log('cannot load fingerprint database: {}'.format(err), 'pof', level='ERROR')
        return 2

    if args.list_database:
        print_database(db)
        return 0

    if args.read:
        try:
            rows = read_pcap(args.read, db, config['quiet'])
        except OSError as err:
            log.log('cannot read {}: {}'.format(args.read, err), 'pof', level='ERROR')
            return 2
        print_rows(rows, as_json=args.json)
        return 0

    store = store_mod.Store(config['max_ips'], config['per_ip'])
    stop = threading.Event()
    started = time.time()

    capture = None
    if not args.api_only:
        capture = capture_mod.Capture(store, config)
        try:
            capture.open()
        except (OSError, RuntimeError) as err:
            log.log('cannot capture: {}'.format(err), 'pof', level='ERROR')
            log.log('hint: run as root or grant CAP_NET_RAW, or use --read FILE.pcap',
                    'pof')
            return 2

    config['capture_stats'] = capture_stats(capture, started)

    # Порт занимаем до старта потоков: если он занят, сервис должен упасть
    # сразу с понятной ошибкой, а не внутри потока.
    server = None
    if not args.capture_only:
        try:
            server = api.make_server(store, db, config)
        except OSError as err:
            log.log('cannot bind {}:{}: {}'.format(config['api_host'],
                                                  config['api_port'], err), 'pof', level='ERROR')
            if capture:
                capture.close()
            return 2
        api.log_startup(config)

    def refresh_stats():
        while not stop.wait(5.0):
            config['capture_stats'] = capture_stats(capture, started)

    # `main_threads` решают, когда завершать процесс: поток статистики живёт
    # всегда и в этот список не входит.
    main_threads = []
    all_threads = []
    if server is not None:
        main_threads.append(threading.Thread(
            target=server.serve_forever, kwargs={'poll_interval': 0.5},
            daemon=True, name='api'))
    if capture:
        main_threads.append(threading.Thread(target=capture.run,
                                             kwargs={'should_stop': stop.is_set},
                                             daemon=True, name='capture'))
    all_threads = main_threads + [threading.Thread(target=refresh_stats,
                                                   daemon=True, name='stats')]
    for thread in all_threads:
        thread.start()

    log.log('pof-fingerprint {} running ({} thread(s))'.format(VERSION, len(all_threads)), 'pof')
    try:
        while main_threads and all(thread.is_alive() for thread in main_threads):
            time.sleep(0.5)
    except KeyboardInterrupt:
        log.log('interrupted, shutting down', 'pof')
    for thread in main_threads:
        if not thread.is_alive():
            log.log('thread {} stopped on its own'.format(thread.name), 'pof',
                    level='WARNING')
    stop.set()
    if server is not None:
        server.shutdown()
        server.server_close()
    for thread in all_threads:
        thread.join(timeout=3.0)
    if capture:
        capture.close()
    log.log('stopped ({} fingerprints stored)'.format(store.seen), 'pof')
    return 0


if __name__ == '__main__':
    sys.exit(main())
