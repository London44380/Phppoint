#!/usr/bin/env python3
"""
PHPPOINT — PHP endpoint discovery scanner.

Companion to PHPVERSE. Given a website, finds its PHP endpoints from two
independent sources: (1) a same-host crawl (HTML, inline/external JS,
robots.txt, sitemap.xml) that extracts every PHP-ish URL and form action,
and (2) a wordlist of common PHP file names (across configurable legacy
extensions), probed with soft-404 baseline detection so catch-all / SPA
sites don't create false hits. Flags backup/config/admin-sounding paths
and suspicious query parameters (LFI/SSRF/command-injection-prone names),
and dedupes endpoints that render byte-identical content.

Authorized use only. Only scan hosts you own or have written permission
to test.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import http.client
import json
import random
import re
import socket
import ssl
import string
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urljoin, urlparse, parse_qs


# ----------------------------------------------------------------------------
# Colors (same palette as phpverse)
# ----------------------------------------------------------------------------
class C:
    RESET  = "\033[0m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RED    = "\033[38;5;196m"
    ORANGE = "\033[38;5;208m"
    YELLOW = "\033[38;5;226m"
    GREEN  = "\033[38;5;46m"
    CYAN   = "\033[38;5;51m"
    GREY   = "\033[38;5;245m"
    WHITE  = "\033[38;5;255m"
    # Blue -> white gradient, one shade per banner row.
    BLUEW  = ["\033[38;5;25m", "\033[38;5;27m", "\033[38;5;33m",
              "\033[38;5;75m", "\033[38;5;255m"]

    @classmethod
    def strip(cls):
        for name in ("RESET", "BOLD", "DIM", "RED", "ORANGE",
                     "YELLOW", "GREEN", "CYAN", "GREY", "WHITE"):
            setattr(cls, name, "")
        cls.BLUEW = [""] * 5


BANNER = r"""
 ____  _   _ ____  ____   ___ ___ _   _ _____
|  _ \| | | |  _ \|  _ \ / _ \_ _| \ | |_   _|
| |_) | |_| | |_) | |_) | | | | ||  \| | | |
|  __/|  _  |  __/|  __/| |_| | || |\  | | |
|_|   |_| |_|_|   |_|    \___/___|_| \_| |_|
"""


def print_banner():
    lines = BANNER.strip("\n").splitlines()
    for i, line in enumerate(lines):
        print(f"{C.BLUEW[i % len(C.BLUEW)]}{C.BOLD}{line}{C.RESET}")
    print(f"{C.WHITE}{C.BOLD}PhpPoint{C.RESET}{C.GREY} — PHP endpoint "
          f"discovery scanner  ·  authorized use only{C.RESET}\n")


SEV_COLOR = {"HIGH": "RED", "MEDIUM": "ORANGE", "LOW": "YELLOW", "INFO": "CYAN"}


def sev(level, msg):
    col = getattr(C, SEV_COLOR.get(level, "GREY"))
    return f"{col}[{level}]{C.RESET} {msg}"


def clean(s):
    """Neutralise control characters (ANSI escapes...) from server data."""
    return "".join(c if c.isprintable() else repr(c)[1:-1] for c in str(s))


# ----------------------------------------------------------------------------
# HTTP helper (same approach as phpverse: no redirects in fetch(), a thin
# same-host follower on top).
# ----------------------------------------------------------------------------
UA = "Mozilla/5.0 (compatible; phppoint/2.0)"
_CTX = ssl._create_unverified_context()

# Set from --delay in main(); fetch() sleeps this long before each request
# (politeness throttle for the wordlist probe + crawl).
DELAY = 0.0


def fetch(host, port, tls, vhost, path, timeout, method="GET"):
    """One request, no redirects. Returns (status, headers_dict_lower,
    cookies_list, body_str) or None on failure."""
    if DELAY:
        time.sleep(DELAY)
    try:
        if tls:
            conn = http.client.HTTPSConnection(host, port, timeout=timeout,
                                               context=_CTX)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=timeout)
        conn.putrequest(method, path, skip_host=True, skip_accept_encoding=True)
        conn.putheader("Host", vhost)
        conn.putheader("User-Agent", UA)
        conn.putheader("Accept", "*/*")
        conn.putheader("Connection", "close")
        conn.endheaders()
        r = conn.getresponse()
        body = r.read(524288).decode("latin-1", "replace")
        heads = {}
        for k, v in r.getheaders():
            if k.lower() != "set-cookie":
                heads[k.lower()] = v
        cookies = r.msg.get_all("Set-Cookie") or []
        status = r.status
        conn.close()
        return status, heads, cookies, body
    except Exception:
        return None


def fetch_follow(host, port, tls, vhost, path, timeout, hops=3):
    """GET with a few same-host redirects (http->https, www, trailing slash).
    Stays in scope: only follows to the same host or its www. variant, and
    only http/https schemes."""
    base = vhost.lower().removeprefix("www.")
    for _ in range(hops + 1):
        res = fetch(host, port, tls, vhost, path, timeout)
        if not res:
            return None, (host, port, tls, vhost)
        status, heads, _, _ = res
        loc = heads.get("location")
        if status // 100 != 3 or not loc:
            return res, (host, port, tls, vhost)
        u = urlparse(loc if "://" in loc else f"//{vhost}{loc}", "http")
        nh = u.hostname or vhost
        if u.scheme not in ("http", "https") or \
           nh.lower().removeprefix("www.") != base:
            return res, (host, port, tls, vhost)
        ntls = u.scheme == "https"
        nport = u.port or (443 if ntls else 80)
        try:
            host = socket.gethostbyname(nh)
        except Exception:
            return res, (host, port, tls, vhost)
        port, tls, vhost = nport, ntls, nh
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    return res, (host, port, tls, vhost)


TLS_PORTS = (443, 4443, 8443, 9443)

# ----------------------------------------------------------------------------
# Extraction regexes (extension-aware: built once per run from --extensions,
# default just "php"; add legacy ones like php3/phtml with that flag).
# ----------------------------------------------------------------------------
PHP_EXTENSIONS = ["php"]
EXT_SUFFIX_RE = None   # compiled in set_extensions(), e.g. r"\.(?:php|phtml)"
LINK_RE = None
BARE_PHP_RE = None


def set_extensions(exts):
    """(Re)compile the extension-aware regexes for this run."""
    global PHP_EXTENSIONS, EXT_SUFFIX_RE, LINK_RE, BARE_PHP_RE
    PHP_EXTENSIONS = exts
    alt = "|".join(re.escape(e) for e in exts)
    EXT_SUFFIX_RE = re.compile(rf"\.(?:{alt})(?:[?#]|$)", re.I)
    LINK_RE = re.compile(
        rf"""(?:href|src|action)\s*=\s*["']([^"'#]*?\.(?:{alt})(?:[?][^"']*)?)["']""",
        re.I)
    BARE_PHP_RE = re.compile(
        rf"""["'(]\s*(/[^"'()\s]*\.(?:{alt})(?:\?[^"'()\s]*)?)["')]""", re.I)


set_extensions(PHP_EXTENSIONS)  # compile the default (.php-only) regexes


def is_php_path(path):
    return bool(EXT_SUFFIX_RE.search(path))


FORM_RE = re.compile(
    r"""<form\b[^>]*\baction\s*=\s*["']([^"'#]*?)["']""", re.I)
SITEMAP_LOC_RE = re.compile(r"<loc>\s*([^<\s]+)\s*</loc>", re.I)
ROBOTS_PATH_RE = re.compile(
    r"^(?:Disallow|Allow)\s*:\s*(\S+)", re.I | re.M)

# A representative set of common PHP endpoint names seen across CMS/apps,
# admin panels, upload/contact handlers, and classic framework front
# controllers. Not exhaustive by design — this targets the common cases.
# Each name is combined with every configured extension (default: php
# only; pass --extensions php,php3,php4,php5,php7,phtml for legacy stacks).
BASE_NAMES = [
    "index", "home", "main", "default",
    "login", "logout", "signin", "signup", "register",
    "admin", "administrator", "admin/index", "admin/login",
    "config", "configuration", "settings", "setup", "install", "upgrade",
    "update",
    "upload", "uploader", "file", "download", "files",
    "contact", "contact-us", "feedback", "mail", "sendmail", "send", "mailer",
    "search", "query", "api", "api/index", "ajax",
    "process", "handler", "action", "actions",
    "user", "users", "profile", "account", "member",
    "cart", "checkout", "payment", "order", "orders",
    "db", "database", "connect", "connection",
    "test", "info", "phpinfo", "debug",
    "backup", "export", "import", "dump",
    "cron", "cronjob", "task", "queue",
    "wp-login", "wp-config", "xmlrpc",
]

# Backup/editor artifacts are literal — multiplying them by every extension
# doesn't add value, so they stay as a fixed list.
EXTRA_LITERAL = [
    "index.php.bak", "config.php.bak", "config.php~", "config.php.old",
    "index.php.save", "config.php.swp", "wp-config.php.bak",
    "wp-config.php~", "wp-config.php.save",
]

# Query-parameter names that commonly point to LFI/RFI, SSRF/open-redirect
# or command-injection sinks. Flagging the name is a heuristic, not proof.
SUSPICIOUS_PARAMS = {
    "file": "LFI/RFI via file-inclusion parameter",
    "page": "possible LFI via page/template include",
    "path": "path parameter — check for path traversal",
    "template": "template parameter — possible LFI",
    "include": "include parameter — classic LFI vector",
    "doc": "document parameter — possible LFI",
    "document": "document parameter — possible LFI",
    "url": "URL parameter — possible SSRF/open redirect",
    "redirect": "redirect parameter — possible open redirect",
    "redirect_to": "redirect parameter — possible open redirect",
    "next": "next/redirect parameter — possible open redirect",
    "return": "return/redirect parameter — possible open redirect",
    "dir": "directory parameter — possible path traversal",
    "folder": "folder parameter — possible path traversal",
    "cmd": "command parameter — possible command injection",
    "exec": "exec parameter — possible command injection",
    "action_cmd": "command parameter — possible command injection",
}


def build_wordlist(extra_words=None):
    words = [f"{name}.{ext}" for name in BASE_NAMES for ext in PHP_EXTENSIONS]
    words += EXTRA_LITERAL
    if extra_words:
        words += [w for w in extra_words if w not in words]
    return words


class Endpoint:
    __slots__ = ("path", "source", "status", "ctype", "length", "digest",
                 "note", "note_level")

    def __init__(self, path, source, status, ctype, length, digest="",
                 note="", note_level="INFO"):
        self.path = path
        self.source = source   # "crawl", "wordlist" or "robots/sitemap"
        self.status = status
        self.ctype = ctype
        self.length = length
        self.digest = digest   # sha1[:10] of the body, for dedupe
        self.note = note
        self.note_level = note_level


def body_digest(body):
    return hashlib.sha1(body.encode("latin-1", "replace")).hexdigest()[:10]


# ----------------------------------------------------------------------------
# Same-host crawl
# ----------------------------------------------------------------------------
def same_host(url, vhost):
    u = urlparse(url)
    if not u.netloc:
        return True
    return u.hostname and u.hostname.lower().removeprefix("www.") == \
        vhost.lower().removeprefix("www.")


def extract_php_links(body, base_url):
    found = set()
    for rx in (LINK_RE, BARE_PHP_RE, FORM_RE):
        for m in rx.finditer(body):
            link = m.group(1)
            if not link or not is_php_path(link):
                continue
            abs_url = urljoin(base_url, link)
            found.add(abs_url)
    return found


def crawl(ctx, timeout, max_pages, workers, same_as_baseline_fn):
    """BFS same-host crawl starting at '/'. Returns a dict of
    {path: (status, ctype, body-length, digest)} for PHP-ish pages found."""
    host, port, tls, vhost = ctx
    base_label = ("https" if tls else "http") + f"://{vhost}:{port}"
    seen_pages = set()
    php_hits = {}
    queue = ["/"]
    pages_fetched = 0

    while queue and pages_fetched < max_pages:
        batch = queue[:workers]
        queue = queue[workers:]
        results = {}
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futs = {}
            for path in batch:
                if path in seen_pages:
                    continue
                seen_pages.add(path)
                futs[ex.submit(fetch, host, port, tls, vhost, path, timeout)] = path
            for f in as_completed(futs):
                results[futs[f]] = f.result()
        for path, res in results.items():
            pages_fetched += 1
            if not res:
                continue
            status, heads, _, body = res
            ctype = heads.get("content-type", "")
            abs_base = urljoin(base_label, path)
            if is_php_path(path) and status == 200 \
               and not same_as_baseline_fn(body):
                php_hits[path] = (status, ctype, len(body), body_digest(body))
            if "text/html" not in ctype.lower() and "javascript" not in ctype.lower():
                continue
            for link in extract_php_links(body, abs_base) | \
                        _extract_crawlable(body, abs_base):
                u = urlparse(link)
                if not same_host(link, vhost):
                    continue
                p = (u.path or "/") + (f"?{u.query}" if u.query else "")
                if is_php_path(p):
                    if p not in php_hits and p not in queue:
                        queue.append(p)
                elif p not in seen_pages and p not in queue and \
                        pages_fetched + len(queue) < max_pages:
                    queue.append(p)
    return php_hits


def _extract_crawlable(body, base_url):
    """Extract plain internal links too (to keep crawling non-.php pages)."""
    found = set()
    for m in re.finditer(r"""(?:href)\s*=\s*["']([^"'#]+)["']""", body, re.I):
        link = m.group(1)
        if link.startswith(("mailto:", "tel:", "javascript:")):
            continue
        found.add(urljoin(base_url, link))
    return found


def fetch_robots_and_sitemap(ctx, timeout, vhost):
    host, port, tls, _ = ctx
    base_label = ("https" if tls else "http") + f"://{vhost}:{port}"
    hits = set()
    res = fetch(host, port, tls, vhost, "/robots.txt", timeout)
    sitemap_urls = []
    if res and res[0] == 200:
        for m in ROBOTS_PATH_RE.finditer(res[3]):
            p = m.group(1)
            if is_php_path(p):
                hits.add(urljoin(base_label, p))
        for m in re.finditer(r"^Sitemap:\s*(\S+)", res[3], re.I | re.M):
            sitemap_urls.append(m.group(1))
    if not sitemap_urls:
        sitemap_urls.append(urljoin(base_label, "/sitemap.xml"))
    for sm_url in sitemap_urls[:3]:
        u = urlparse(sm_url)
        if not same_host(sm_url, vhost):
            continue
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        res = fetch(host, port, tls, u.hostname or vhost, path, timeout)
        if res and res[0] == 200:
            for m in SITEMAP_LOC_RE.finditer(res[3]):
                loc = m.group(1)
                if is_php_path(loc) and same_host(loc, vhost):
                    hits.add(loc)
    return hits


# ----------------------------------------------------------------------------
# Wordlist probe with soft-404 baseline filtering
# ----------------------------------------------------------------------------
def check_baseline(ctx, timeout):
    """Fetch a random nonexistent path. If it answers 200, remember the body
    so wordlist hits that render the same page (catch-all router) are
    filtered out."""
    rnd = "".join(random.choices(string.ascii_lowercase, k=12))
    ext = PHP_EXTENSIONS[0] if PHP_EXTENSIONS else "php"
    res = fetch(*ctx, f"/phppoint-{rnd}.{ext}", timeout)
    if res and res[0] == 200:
        return res[3]
    return None


def same_as_baseline(baseline, body):
    if baseline is None:
        return False
    a, b = baseline[:4000], body[:4000]
    return difflib.SequenceMatcher(None, a, b).quick_ratio() > 0.95


def probe_wordlist(ctx, timeout, workers, baseline, extra_words=None):
    words = build_wordlist(extra_words)

    def one(word):
        path = "/" + word.lstrip("/")
        res = fetch(*ctx, path, timeout)
        if not res:
            return None
        status, heads, _, body = res
        if status not in (200, 403, 401, 500):
            return None
        if status == 200 and same_as_baseline(baseline, body):
            return None
        ctype = heads.get("content-type", "")
        return path, status, ctype, len(body), body_digest(body)

    hits = {}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        for res in ex.map(one, words):
            if res:
                path, status, ctype, length, digest = res
                hits[path] = (status, ctype, length, digest)
    return hits


# ----------------------------------------------------------------------------
# Per-target scan
# ----------------------------------------------------------------------------
def parse_target(t):
    if "://" not in t:
        t = "//" + t
    u = urlparse(t, "")
    return u.hostname, u.port, u.scheme


ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def note_for(path, status):
    """Heuristic severity tags for an endpoint, independent of phpverse.
    Combines path-shape hints with any suspicious query-parameter names;
    the most severe one leads, all are kept in the message."""
    candidates = []
    low = path.split("?")[0].lower()
    if status in (401, 403):
        candidates.append(("INFO", "access restricted (401/403) — "
                                   "still a confirmed endpoint"))
    if re.search(r"\.(bak|old|orig|swp|save)$|~$", low):
        candidates.append(("MEDIUM", "backup/editor artifact — may leak source"))
    if re.search(r"config|setup|install|db|database|connect", low):
        candidates.append(("MEDIUM", "sensitive-sounding name — check for "
                                      "credential/config leakage"))
    if re.search(r"admin|login|wp-login", low):
        candidates.append(("LOW", "admin/auth surface — candidate for "
                                   "brute-force testing"))
    if re.search(r"upload|file|import|export|backup|dump", low):
        candidates.append(("LOW", "file handling endpoint — check for "
                                   "unrestricted upload/path traversal"))
    if re.search(r"xmlrpc\.", low):
        candidates.append(("LOW", "WordPress xmlrpc — brute-force/pingback "
                                   "abuse surface"))

    q = parse_qs(urlparse(path).query)
    for key in q:
        reason = SUSPICIOUS_PARAMS.get(key.lower())
        if reason:
            level = "HIGH" if key.lower() in ("cmd", "exec", "action_cmd") \
                else "MEDIUM"
            candidates.append((level, f"parameter '{key}' — {reason}"))

    if not candidates:
        candidates.append(("INFO", "discovered PHP endpoint"))
    candidates.sort(key=lambda c: ORDER[c[0]])
    level = candidates[0][0]
    msg = "; ".join(c[1] for c in candidates)
    return level, msg


def scan_target(target, timeout, workers, max_pages, no_crawl, no_wordlist,
                 extra_words, web_ports=None):
    name, forced_port, scheme = parse_target(target)
    try:
        ip = socket.gethostbyname(name)
    except Exception:
        return None, name, None

    attempts = []
    if scheme == "http":
        attempts.append((forced_port or 80, False))
    elif scheme == "https":
        attempts.append((forced_port or 443, True))
    elif forced_port:
        attempts.append((forced_port, forced_port in TLS_PORTS))
    elif web_ports:
        attempts += [(p, p in TLS_PORTS) for p in web_ports]
    else:
        attempts += [(443, True), (80, False)]

    home, ctx = None, None
    for port, tls in attempts:
        res, final = fetch_follow(ip, port, tls, name, "/", timeout)
        if res:
            home, ctx = res, final
            break
    if not home:
        return None, name, ip

    host_, port_, tls_, vhost_ = ctx
    label = ("https" if tls_ else "http") + f"://{vhost_}:{port_}"

    baseline = check_baseline(ctx, timeout)

    endpoints = {}

    rs_hits = fetch_robots_and_sitemap(ctx, timeout, vhost_)
    for url in rs_hits:
        u = urlparse(url)
        path = (u.path or "/") + (f"?{u.query}" if u.query else "")
        res = fetch(*ctx, path, timeout)
        if res and res[0] == 200 and not same_as_baseline(baseline, res[3]):
            endpoints[path] = Endpoint(path, "robots/sitemap", res[0],
                                        res[1].get("content-type", ""),
                                        len(res[3]), body_digest(res[3]))

    if not no_crawl:
        crawl_hits = crawl(ctx, timeout, max_pages, workers,
                           lambda body: same_as_baseline(baseline, body))
        for path, (status, ctype, length, digest) in crawl_hits.items():
            if path not in endpoints:
                endpoints[path] = Endpoint(path, "crawl", status, ctype,
                                            length, digest)

    if not no_wordlist:
        wl_hits = probe_wordlist(ctx, timeout, workers, baseline, extra_words)
        for path, (status, ctype, length, digest) in wl_hits.items():
            if path not in endpoints:
                endpoints[path] = Endpoint(path, "wordlist", status, ctype,
                                            length, digest)

    for ep in endpoints.values():
        level, msg = note_for(ep.path, ep.status)
        ep.note = msg
        ep.note_level = level

    # Dedupe: flag endpoints whose body is byte-identical to an earlier one
    # (same catch-all page served under several names, a symlinked alias...).
    seen_digest = {}
    for path in sorted(endpoints):
        ep = endpoints[path]
        if not ep.digest:
            continue
        if ep.digest in seen_digest:
            ep.note += f"; identical content to {seen_digest[ep.digest]}"
        else:
            seen_digest[ep.digest] = path

    return (label, endpoints), name, ip


# ----------------------------------------------------------------------------
# Output
# ----------------------------------------------------------------------------
STATUS_COL = {2: "GREEN", 3: "CYAN", 4: "ORANGE", 5: "RED"}
SRC_LABEL = {"crawl": "crawl", "wordlist": "wordlist", "robots/sitemap": "robots/sitemap"}


def print_report(name, ip, result):
    label, endpoints = result
    head = name if name == ip else f"{name} ({ip})"
    print(f"{C.BOLD}{C.CYAN}▸ {clean(head)}{C.RESET}  {C.GREY}{clean(label)}{C.RESET}")
    if not endpoints:
        print(f"  {C.GREY}no PHP endpoints found (crawl + wordlist "
              f"came up empty){C.RESET}\n")
        return
    print(f"  {C.GREEN}{C.BOLD}{len(endpoints)} PHP endpoint(s) found{C.RESET}")
    for path in sorted(endpoints, key=lambda p: (ORDER[endpoints[p].note_level], p)):
        ep = endpoints[path]
        col = getattr(C, STATUS_COL.get(ep.status // 100, "GREY"))
        print(f"    {col}{ep.status:<3}{C.RESET} "
              f"{C.GREY}{ep.source:<13}{C.RESET} {clean(ep.path):<40} "
              f"{C.DIM}{clean(ep.ctype)}{C.RESET}")
        print(f"        {sev(ep.note_level, clean(ep.note))}")
    print()


def to_dict(name, ip, result):
    label, endpoints = result
    return {
        "target": name, "ip": ip, "landing": label,
        "count": len(endpoints),
        "endpoints": [
            {"path": p, "source": ep.source, "status": ep.status,
             "content_type": ep.ctype, "length": ep.length,
             "severity": ep.note_level, "note": ep.note}
            for p, ep in sorted(endpoints.items())
        ],
    }


# ----------------------------------------------------------------------------
# CLI
# ----------------------------------------------------------------------------
class Tee:
    """Mirrors writes to several streams (used for --output)."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, s):
        for st in self.streams:
            st.write(s)

    def flush(self):
        for st in self.streams:
            st.flush()

    def isatty(self):
        return self.streams[0].isatty()


def main():
    global DELAY
    ap = argparse.ArgumentParser(
        description="PhpPoint — PHP endpoint discovery scanner "
                    "(authorized use only).")
    ap.add_argument("targets", nargs="*",
                    help="host, IP or URL (https://example.com)")
    ap.add_argument("-f", "--file",
                    help="file with one target per line (# comments allowed)")
    ap.add_argument("-p", "--ports",
                    help="comma-separated web ports to try (default 443,80)")
    ap.add_argument("-t", "--timeout", type=float, default=5.0,
                    help="per-request timeout seconds (default 5)")
    ap.add_argument("-w", "--workers", type=int, default=10,
                    help="concurrent probes per host (default 10)")
    ap.add_argument("--max-pages", type=int, default=150,
                    help="max pages to fetch while crawling (default 150)")
    ap.add_argument("--no-crawl", action="store_true",
                    help="skip the same-host crawl, wordlist only")
    ap.add_argument("--no-wordlist", action="store_true",
                    help="skip the wordlist probe, crawl only")
    ap.add_argument("--extra-wordlist",
                    help="file with extra words to add to the built-in wordlist")
    ap.add_argument("--extensions", default="php",
                    help="comma-separated PHP-ish extensions to probe/match "
                         "(default: php; add php3,php4,php5,php7,phtml for "
                         "legacy stacks)")
    ap.add_argument("--delay", type=float, default=0.0,
                    help="seconds to sleep before each request "
                         "(politeness throttle, default 0)")
    ap.add_argument("-o", "--output",
                    help="also write the report to this file (same format "
                         "as stdout; combine with --no-color for a clean "
                         "text file)")
    ap.add_argument("--json", action="store_true",
                    help="machine-readable JSON output (no banner/colors)")
    ap.add_argument("--no-color", action="store_true", help="disable colors")
    args = ap.parse_args()

    targets = list(args.targets)
    if args.file:
        try:
            with open(args.file) as fh:
                targets += [l.strip() for l in fh
                            if l.strip() and not l.lstrip().startswith("#")]
        except OSError as e:
            ap.error(f"cannot read {args.file}: {e}")
    if not targets:
        ap.error("give at least one target (or -f FILE)")

    extra_words = None
    if args.extra_wordlist:
        try:
            with open(args.extra_wordlist) as fh:
                extra_words = [l.strip() for l in fh
                               if l.strip() and not l.lstrip().startswith("#")]
        except OSError as e:
            ap.error(f"cannot read {args.extra_wordlist}: {e}")

    exts = [e.strip().lstrip(".").lower() for e in args.extensions.split(",")
            if e.strip()]
    if not exts:
        ap.error("--extensions needs at least one extension")
    set_extensions(exts)
    DELAY = max(0.0, args.delay)

    out_fh = None
    if args.output:
        try:
            out_fh = open(args.output, "w", encoding="utf-8")
        except OSError as e:
            ap.error(f"cannot write {args.output}: {e}")
        sys.stdout = Tee(sys.__stdout__, out_fh)

    if args.no_color or args.json or not sys.stdout.isatty():
        C.strip()
    try:
        sys.stdout.reconfigure(line_buffering=True)
    except Exception:
        pass

    if not args.json:
        print_banner()
        print(f"{C.GREY}Authorized use only — scan only hosts you own or have "
              f"permission to test.{C.RESET}\n")

    web_ports = [int(p) for p in (args.ports or "").split(",") if p.strip().isdigit()]
    rc = 0
    out = []
    for target in targets:
        result, name, ip = scan_target(target, args.timeout, args.workers,
                                       args.max_pages, args.no_crawl,
                                       args.no_wordlist, extra_words, web_ports)
        if ip is None:
            rc = 1
            if args.json:
                out.append({"target": target, "error": "could not resolve"})
            else:
                print(f"{C.RED}✗ {clean(target)} — could not resolve{C.RESET}\n")
        elif result is None:
            rc = 1
            if args.json:
                out.append({"target": target, "ip": ip,
                            "error": "no HTTP(S) response"})
            else:
                print(f"{C.RED}✗ {clean(target)} ({clean(ip)}) — "
                      f"no HTTP(S) response{C.RESET}\n")
        elif args.json:
            out.append(to_dict(name, ip, result))
        else:
            print_report(name, ip, result)
    if args.json:
        print(json.dumps(out, indent=2))
    else:
        print(f"{C.GREY}Heuristic discovery — verify manually before "
              f"acting.{C.RESET}")
    if out_fh:
        sys.stdout = sys.__stdout__
        out_fh.close()
    return rc


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print(f"\n{C.RED}Interrupted.{C.RESET}")
        sys.exit(130)
