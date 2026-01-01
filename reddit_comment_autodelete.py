#!/usr/bin/env python3
"""
Auto-delete your *new comments* (not posts) within 60 seconds,
except in allowlisted subreddits.

OAuth:
- This script runs a tiny HTTP server to receive the OAuth callback.
- Configure your Reddit app's redirect URI to exactly:
    http://192.168.0.49:8090/callback
  (or whatever you set via env vars)

Behavior:
- Every POLL_SECONDS, fetches your newest comments
- Deletes any of *your* comments created within DELETE_IF_YOUNGER_THAN_SECONDS
- Skips deletion if the comment is in an allowlisted subreddit

Env vars (recommended via docker-compose):
  CLIENT_ID, CLIENT_SECRET, USERNAME
  USER_AGENT (optional)
  REFRESH_TOKEN (optional; if absent, will run OAuth in browser)
  REDIRECT_HOST, REDIRECT_PORT, REDIRECT_PATH
  POLL_SECONDS, DELETE_IF_YOUNGER_THAN_SECONDS, FETCH_LIMIT, SEEN_TTL_SECONDS
  ALLOWED_SUBREDDITS (optional): comma-separated, e.g. "AskReddit,programming,MySub"
"""

from __future__ import annotations

import os
import time
import logging
import threading
import socket
import urllib.parse
import webbrowser
from collections import deque
from http.server import BaseHTTPRequestHandler, HTTPServer

import praw
from prawcore.exceptions import PrawcoreException, ResponseException, RequestException, OAuthException


def getenv_required(name: str) -> str:
    v = os.environ.get(name, "").strip()
    if not v:
        raise SystemExit(f"Missing required environment variable: {name}")
    return v


def getenv_int(name: str, default: int) -> int:
    v = os.environ.get(name, "").strip()
    if not v:
        return default
    try:
        return int(v)
    except ValueError as e:
        raise SystemExit(f"Invalid int for {name}={v!r}: {e}")


def parse_allowed_subreddits(raw: str) -> set[str]:
    """
    Parse comma-separated allowlist from env.
    Normalizes to lowercase subreddit names without leading 'r/'.
    """
    out: set[str] = set()
    for part in (raw or "").split(","):
        s = part.strip()
        if not s:
            continue
        if s.lower().startswith("r/"):
            s = s[2:]
        out.add(s.lower())
    return out


# =========================
# CONFIG (from env)
# =========================
CLIENT_ID = getenv_required("CLIENT_ID")
CLIENT_SECRET = getenv_required("CLIENT_SECRET")
USERNAME = getenv_required("USERNAME")

USER_AGENT = os.environ.get("USER_AGENT", "").strip() or f"comment-autodeleter/1.0 by {USERNAME}"

REDIRECT_HOST = os.environ.get("REDIRECT_HOST", "192.168.0.49").strip()
REDIRECT_PORT = getenv_int("REDIRECT_PORT", 8090)
REDIRECT_PATH = os.environ.get("REDIRECT_PATH", "/callback").strip() or "/callback"
if not REDIRECT_PATH.startswith("/"):
    REDIRECT_PATH = "/" + REDIRECT_PATH
REDIRECT_URI = f"http://{REDIRECT_HOST}:{REDIRECT_PORT}{REDIRECT_PATH}"

REFRESH_TOKEN = os.environ.get("REFRESH_TOKEN", "").strip()

POLL_SECONDS = getenv_int("POLL_SECONDS", 5)
DELETE_IF_YOUNGER_THAN_SECONDS = getenv_int("DELETE_IF_YOUNGER_THAN_SECONDS", 60)
FETCH_LIMIT = getenv_int("FETCH_LIMIT", 25)
SEEN_TTL_SECONDS = getenv_int("SEEN_TTL_SECONDS", 600)

ALLOWED_SUBREDDITS = parse_allowed_subreddits(os.environ.get("ALLOWED_SUBREDDITS", ""))
# =========================


class OAuthCallbackServer:
    """Local server to capture ?code=...&state=... from Reddit redirect."""
    def __init__(self, host: str, port: int, path: str):
        self.host = host
        self.port = port
        self.path = path
        self.code: str | None = None
        self.state: str | None = None
        self.error: str | None = None
        self._event = threading.Event()

        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                parsed = urllib.parse.urlparse(self.path)
                if parsed.path != outer.path:
                    self.send_response(404)
                    self.end_headers()
                    self.wfile.write(b"Not found")
                    return

                qs = urllib.parse.parse_qs(parsed.query)
                outer.code = qs.get("code", [None])[0]
                outer.state = qs.get("state", [None])[0]
                outer.error = qs.get("error", [None])[0]

                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()

                if outer.error:
                    body = f"<h2>OAuth error</h2><p>{outer.error}</p>"
                elif outer.code:
                    body = "<h2>Authorized</h2><p>You can close this tab and return to the script.</p>"
                else:
                    body = "<h2>Missing code</h2><p>No authorization code was provided.</p>"

                self.wfile.write(body.encode("utf-8"))
                outer._event.set()

            def log_message(self, fmt, *args):  # silence server logs
                return

        self._Handler = Handler
        self._httpd: HTTPServer | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._httpd = HTTPServer((self.host, self.port), self._Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def wait_for_callback(self, timeout: float | None = 300) -> None:
        self._event.wait(timeout=timeout)

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()


def ensure_port_bindable(host: str, port: int) -> None:
    """Fail fast if the address/port can't be bound (e.g., wrong IP on this machine)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((host, port))
        except OSError as e:
            raise SystemExit(
                f"Cannot bind to {host}:{port}. "
                f"Is {host} an IP on this machine, and is the port free? ({e})"
            )


def build_reddit(refresh_token: str | None = None) -> praw.Reddit:
    return praw.Reddit(
        client_id=CLIENT_ID,
        client_secret=CLIENT_SECRET,
        redirect_uri=REDIRECT_URI,
        user_agent=USER_AGENT,
        refresh_token=refresh_token,
    )


def obtain_refresh_token_via_local_callback() -> str:
    ensure_port_bindable(REDIRECT_HOST, REDIRECT_PORT)

    reddit = build_reddit(refresh_token=None)

    state = f"autodeleter-{int(time.time())}"
    scopes = ["identity", "edit", "history"]  # edit required to delete

    server = OAuthCallbackServer(REDIRECT_HOST, REDIRECT_PORT, REDIRECT_PATH)
    server.start()

    auth_url = reddit.auth.url(scopes=scopes, state=state, duration="permanent")

    print("\nOpen Reddit OAuth in a browser:")
    print(auth_url)
    print(f"\nCallback listener: {REDIRECT_URI}\n")

    try:
        webbrowser.open(auth_url, new=2)
    except Exception:
        pass

    server.wait_for_callback(timeout=300)
    server.stop()

    if server.error:
        raise SystemExit(f"OAuth error from Reddit: {server.error}")
    if not server.code:
        raise SystemExit("Did not receive an OAuth code. No callback hit the local server.")
    if server.state != state:
        raise SystemExit("State mismatch in OAuth callback. Refusing to continue.")

    refresh_token = reddit.auth.authorize(server.code)

    print("\n✅ Got refresh token. Save it and set REFRESH_TOKEN to skip OAuth next time:\n")
    print(refresh_token)
    return refresh_token


def purge_seen(seen: dict[str, float], seen_q: deque[tuple[str, float]], now: float) -> None:
    cutoff = now - SEEN_TTL_SECONDS
    while seen_q and seen_q[0][1] < cutoff:
        cid, ts = seen_q.popleft()
        if seen.get(cid) == ts:
            del seen[cid]


def is_allowlisted_subreddit(comment) -> tuple[bool, str]:
    """
    Returns (allowlisted, normalized_name).
    If subreddit name can't be determined, treat as not allowlisted.
    """
    try:
        name = getattr(comment.subreddit, "display_name", "") or ""
    except Exception:
        name = ""
    norm = name.strip().lower()
    return (norm in ALLOWED_SUBREDDITS, norm)


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    if ALLOWED_SUBREDDITS:
        logging.info("Allowlisted subreddits (won't delete): %s", ", ".join(sorted(ALLOWED_SUBREDDITS)))
    else:
        logging.info("No allowlisted subreddits configured (ALLOWED_SUBREDDITS empty).")

    refresh = REFRESH_TOKEN or obtain_refresh_token_via_local_callback()
    reddit = build_reddit(refresh_token=refresh)

    # Sanity check identity
    try:
        me = reddit.user.me()
        if not me:
            raise RuntimeError("reddit.user.me() returned None (auth failed).")
        if str(me).lower() != USERNAME.lower():
            logging.warning("Logged in as '%s' but USERNAME is '%s'. Continuing anyway.", me, USERNAME)
        logging.info("Authenticated as: %s", me)
    except Exception as e:
        raise SystemExit(f"Auth check failed: {e}")

    seen: dict[str, float] = {}
    seen_q: deque[tuple[str, float]] = deque()

    logging.info(
        "Starting loop: polling every %ss; deleting comments younger than %ss",
        POLL_SECONDS,
        DELETE_IF_YOUNGER_THAN_SECONDS,
    )

    while True:
        now = time.time()
        purge_seen(seen, seen_q, now)

        try:
            redditor = reddit.redditor(USERNAME)
            for c in redditor.comments.new(limit=FETCH_LIMIT):
                if c.id in seen:
                    continue

                created = float(getattr(c, "created_utc", 0.0))
                age = now - created

                if age < 0:
                    continue
                if age > DELETE_IF_YOUNGER_THAN_SECONDS:
                    break  # newest-first

                allowlisted, sub_norm = is_allowlisted_subreddit(c)
                if allowlisted:
                    seen[c.id] = now
                    seen_q.append((c.id, now))
                    logging.info(
                        "Kept comment %s (age=%.1fs) in allowlisted r/%s",
                        c.id,
                        age,
                        sub_norm or "?",
                    )
                    continue

                # mark handled before attempting delete
                seen[c.id] = now
                seen_q.append((c.id, now))

                try:
                    c.delete()
                    logging.info(
                        "Deleted comment %s (age=%.1fs) in r/%s",
                        c.id,
                        age,
                        sub_norm or getattr(c.subreddit, "display_name", "?"),
                    )
                except PrawcoreException as e:
                    logging.warning("Failed to delete comment %s: %r", c.id, e)

        except (ResponseException, RequestException, OAuthException, PrawcoreException) as e:
            logging.warning("API error: %r", e)

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
