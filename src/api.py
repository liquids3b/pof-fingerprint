"""JSON over HTTP, served next to the capture loop.

Routes (all GET, CORS open so a browser page can call them directly):

    /                         a small HTML page that calls /fingerprint for you
    /fingerprint             the caller's own IP: fingerprint + OS guess
    /fingerprint?ip=1.2.3.4  another IP in memory (needs the API key)
    /fingerprint?detail=0    slim answer: IP, OS, confidence, signature
    /fingerprints            every IP in memory, newest SYN each (needs the key)
    /stats                   counters (needs the key)
    /health                  liveness probe, no key
    /database                the fingerprint database metadata (needs the key)

Everything except `/` is JSON, so a tool never has to parse HTML: `/` is just a
viewer that fetches `/fingerprint` and prints it.

`X-Real-IP` is honoured only for requests from this host, which is how nginx
running on the same machine hands the real client address to the service after
terminating TLS; a remote client cannot claim somebody else's address that way.
"""
import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

import database
import log
import netutil
import packet

API_VERSION = 1
BULK_ROUTES = {'/fingerprints': 'all_fingerprints', '/stats': 'stats',
               '/database': 'database_info'}
ADDRESS_FIELDS = ('ip_ttl', 'ip_ttl_initial', 'ip_tos', 'ip_total_length', 'ip_id',
                  'ip_id_zero', 'ip_df', 'ip_mf', 'ip_frag_offset', 'ip_version',
                  'ip_header_length', 'ip_checksum', 'ip_traffic_class',
                  'tcp_data_offset', 'tcp_header_length', 'tcp_flags', 'tcp_window_size',
                  'tcp_window_scaling', 'tcp_mss', 'tcp_options', 'tcp_options_ordered',
                  'tcp_timestamp', 'tcp_timestamp_echo', 'tcp_options_length',
                  'tcp_src_port', 'tcp_dst_port')
SLIM_FIELDS = ('ip', 'found', 'os', 'os_group', 'confidence', 'coverage', 'score',
               'signature', 'samples', 'last_seen')

# `/` is a viewer only: it fetches /fingerprint and pretty prints the answer, so
# the endpoints stay pure JSON for scripts. No framework, no build step.
INDEX_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pof-fingerprint</title>
<style>
 body { font: 15px/1.5 system-ui, sans-serif; margin: 2rem auto; max-width: 64rem;
        padding: 0 1rem; }
 pre, code { font-family: ui-monospace, Consolas, monospace; }
 pre { background: #f6f6f6; border: 1px solid #ddd; padding: 1rem; overflow-x: auto; }
 input { font: inherit; padding: .35rem .5rem; }
 .row { display: flex; gap: .5rem; flex-wrap: wrap; margin: 1rem 0; }
 .muted { color: #666; }
</style>
</head>
<body>
<h1>pof-fingerprint</h1>
<p>Your connection looks like: <strong id="os">...</strong></p>
<p class="muted">This page is only a viewer: it fetches <code>/fingerprint</code> and
prints the JSON below. Tools can call that endpoint directly.</p>
<form class="row" id="lookup">
  <input name="ip" size="18" placeholder="another IP (optional)">
  <input name="key" size="14" placeholder="api key (optional)">
  <button type="submit">Look up</button>
</form>
<pre id="out">loading...</pre>
<script>
var out = document.getElementById('out');
var headline = document.getElementById('os');
function show(text) { out.textContent = text; }
function load(ip, key) {
  var query = [];
  if (ip) { query.push('ip=' + encodeURIComponent(ip)); }
  if (key) { query.push('key=' + encodeURIComponent(key)); }
  show('loading...');
  fetch('/fingerprint' + (query.length ? '?' + query.join('&') : ''))
    .then(function (response) { return response.json(); })
    .then(function (data) {
      if (data.os) {
        headline.textContent = data.os + ' (' + Math.round(100 * data.confidence) +
                               '% of the score, ' + data.samples + ' SYN(s))';
      } else {
        headline.textContent = data.message || 'nothing captured for this address yet';
      }
      show(JSON.stringify(data, null, 2));
    })
    .catch(function (error) { show('request failed: ' + error); });
}
document.getElementById('lookup').addEventListener('submit', function (event) {
  event.preventDefault();
  load(this.ip.value.trim(), this.key.value.trim());
});
load('', '');
</script>
</body>
</html>
"""


def public_fingerprint(fingerprint):
    """Only the header fields worth returning, in a stable order."""
    result = {field: fingerprint.get(field) for field in ADDRESS_FIELDS
              if field in fingerprint}
    result['ip_ttl_initial'] = fingerprint.get('ip_ttl_initial')
    return result


def classify_entry(store, db, ip, user_agent=None):
    """The full JSON document for one IP."""
    entry = store.get(ip)
    if entry is None:
        return {'ip': ip, 'found': False,
                'message': 'no SYN captured for this IP yet',
                'tracked_ips': len(store)}, 404
    fingerprint = entry['fingerprints'][-1]
    result = db.classify(fingerprint)
    document = {
        'ip': ip,
        'found': True,
        'os': result['os'],
        'os_group': result['os_group'],
        'confidence': result['confidence'],
        'coverage': result['coverage'],
        'score': result['score'],
        'possible_score': result['possible_score'],
        'max_score': result['max_score'],
        'margin': result['margin'],
        'scores': result['scores'],
        'signature': result['signature'],
        'guess_source': result['guess_source'],
        'cached': result.get('cached', False),
        'samples': entry['count'],
        'first_seen': entry['first_seen'],
        'last_seen': entry['last_seen'],
        'api_version': API_VERSION,
        'fingerprint': public_fingerprint(fingerprint),
    }
    claimed = database.ua_os(user_agent)
    if claimed:
        document['user_agent_os'] = claimed
        document['os_mismatch'] = (
            (result['os_group'] or '') != database.OS_GROUPS.get(claimed, claimed.lower()))
    return document, 200


def _handler_class(store, db, config):
    # Computed once: the addresses that may speak for somebody else via headers.
    trusted = netutil.local_ips(config.get('interface') or None) | {'127.0.0.1', '::1'}

    class Handler(BaseHTTPRequestHandler):
        server_version = 'pof-fingerprint/{}'.format(API_VERSION)
        protocol_version = 'HTTP/1.1'
        timeout = 15

        def log_message(self, *args):  # we do our own logging
            pass

        # -- plumbing --------------------------------------------------------
        def send_body(self, body, content_type, status=200):
            payload = body.encode('utf-8') if isinstance(body, str) else body
            self.send_response(status)
            self.send_header('Content-Type', content_type)
            self.send_header('Content-Length', str(len(payload)))
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Headers', 'X-Real-IP')
            self.end_headers()
            if self.command != 'HEAD':
                self.wfile.write(payload)

        def send_json(self, payload, status=200):
            self.send_body(json.dumps(payload, indent=2, sort_keys=True, default=str),
                           'application/json; charset=utf-8', status)

        def query(self, name):
            values = parse_qs(urlparse(self.path).query).get(name)
            return values[0].strip() if values and values[0].strip() else None

        def key_ok(self):
            """The configured key; access is open while no key is configured."""
            if not config['api_key']:
                return True
            return self.query('key') == config['api_key']

        def client_ip(self):
            address = packet.normalize_ip(self.client_address[0])
            forwarded = self.headers.get('X-Real-IP') or self.headers.get('X-Forwarded-For')
            if forwarded and address in trusted:
                return packet.normalize_ip(forwarded.split(',')[0].strip())
            return address

        # -- routes ----------------------------------------------------------
        def do_GET(self):
            try:
                self.route()
            except Exception as err:  # one bad request must not kill a thread
                log.log('{} failed: {!r}'.format(self.path, err), 'api', level='ERROR')
                self.send_json({'error': 'internal error', 'detail': str(err)}, 500)

        do_HEAD = do_GET

        def do_OPTIONS(self):
            self.send_response(204)
            self.send_header('Access-Control-Allow-Origin', '*')
            self.send_header('Access-Control-Allow-Methods', 'GET, HEAD, OPTIONS')
            self.send_header('Access-Control-Allow-Headers', 'X-Real-IP')
            self.send_header('Content-Length', '0')
            self.end_headers()

        def route(self):
            path = urlparse(self.path).path.rstrip('/') or '/'
            if path == '/':
                return self.send_body(INDEX_PAGE, 'text/html; charset=utf-8')
            if path == '/fingerprint':
                return self.fingerprint()
            if path == '/health':
                return self.health()
            handler = BULK_ROUTES.get(path)
            if handler is None:
                return self.not_found()
            if not self.key_ok():
                return self.send_json({'error': 'forbidden',
                                       'message': 'append ?key=<api_key>'}, 403)
            return getattr(self, handler)()

        def health(self):
            return self.send_json({'status': 'ok', 'database_loaded': db.loaded,
                                   'tracked_ips': len(store)})

        def stats(self):
            return self.send_json(dict(store.stats(), database_loaded=db.loaded,
                                       database_entries=len(db.entries),
                                       database_os=db.by_os,
                                       capture=config.get('capture_stats', {})))

        def database_info(self):
            return self.send_json({'path': str(db.path), 'entries': len(db.entries),
                                   'per_os': db.by_os, 'sessions': db.sessions,
                                   'max_score': database.MAX_SCORE})

        def not_found(self):
            return self.send_json({'error': 'not found',
                                   'paths': ['/', '/fingerprint'] + sorted(BULK_ROUTES)}, 404)


        def fingerprint(self):
            target = self.query('ip') if self.key_ok() else None
            target = packet.normalize_ip(target or self.client_ip())
            if not _valid_address(target):
                return self.send_json({'error': 'not an IP address', 'ip': target}, 400)
            user_agent = self.headers.get('User-Agent')
            document, status = classify_entry(store, db, target, user_agent=user_agent)
            if self.query('detail') in ('0', 'slim', 'false'):
                document = {key: value for key, value in document.items()
                            if key in SLIM_FIELDS}
            return self.send_json(document, status)

        def all_fingerprints(self):
            limit = self.query('limit')
            rows = []
            for entry in store.snapshot(limit=int(limit) if limit and limit.isdigit() else None):
                result = db.classify(entry['fingerprint'])
                rows.append({'ip': entry['ip'], 'os': result['os'], 'score': result['score'],
                             'confidence': result['confidence'],
                             'signature': result['signature'],
                             'samples': entry['count'], 'last_seen': entry['last_seen']})
            return self.send_json({'count': len(rows), 'fingerprints': rows})

    return Handler


def _valid_address(address):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, address)
            return True
        except (OSError, TypeError):
            continue
    return False


def bind_urls(config):
    """Human readable URLs of the API: `0.0.0.0` is not something to click."""
    address = config['api_host']
    port = config['api_port']
    if address not in ('0.0.0.0', '::'):
        return ['http://{}:{}'.format(address, port)]
    hosts = sorted(host for host in netutil.local_ips()
                   if ':' not in host and not host.startswith('127.'))
    return ['http://{}:{}'.format(host, port) for host in hosts]


def log_startup(config):
    """Where the API ended up: one clickable line, plus a warning when public."""
    urls = bind_urls(config) or ['http://{}:{}'.format(config['api_host'],
                                                       config['api_port'])]
    log.log('API on {} (key {})'.format(', '.join(urls),
                                        'set' if config['api_key'] else 'not set'), 'api')
    if config['api_host'] not in ('127.0.0.1', '::1', 'localhost'):
        log.log('the API is reachable from the network: /stats, /fingerprints and '
                '/database need ?key=..., and X-Real-IP is trusted from this host only',
                'api', level='WARNING')


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def make_server(store, db, config):
    """Build the HTTP server without starting it (also used by the tests)."""
    server = Server((config['api_host'], config['api_port']),
                    _handler_class(store, db, config))
    server.store, server.db, server.config = store, db, config
    return server


def serve(store, db, config, ready=None):
    """Run the HTTP API forever. Returns the server object."""
    server = make_server(store, db, config)
    log_startup(config)
    if ready:
        ready()
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        log.log('API interrupted', 'api')
    finally:
        server.server_close()
    return server
