"""Hosted login, session storage and request routing."""
from contextlib import closing
from hmac import compare_digest
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
import json
import os
from pathlib import Path
import secrets
import sqlite3
import time
from urllib.parse import quote, urlsplit

from flask import Flask, Response, abort, g, redirect, render_template, request

from hosted.common import (CSRF_HEADER, INTERNAL_GATEWAY_HEADER, INTERNAL_LOGIN_HEADER,
                           LOGIN_COOKIE, MAX_UPLOAD, SECRET_DIR, TENANTS, csrf_for,
                           digest, origin, password_hash, tenant_cookie)

SESSION_SECONDS = 24 * 60 * 60
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
FORWARDED_HEADERS = {"Accept", "Content-Type", "Range", "If-Range", CSRF_HEADER}
HOP_HEADERS = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailer", "transfer-encoding", "upgrade", "server", "date"}


def create_app(config_path=SECRET_DIR / "gateway.json", data_dir=None, upstreams=None):
    app = Flask(__name__, template_folder="../templates", static_folder=None)
    site = origin()
    public_host = urlsplit(site).netloc
    data_dir = Path(data_dir or os.environ.get("BB_HOME", "/data"))
    users = json.loads(Path(config_path).read_text())
    if len(users) != len(TENANTS) or {u["tenant"] for u in users.values()} != set(TENANTS):
        raise ValueError("The gateway requires one login for each of the two tenants")
    if len({u["token"] for u in users.values()}) != len(TENANTS):
        raise ValueError("Each tenant requires a separate gateway token")
    upstreams = upstreams or {tenant: (tenant, 8000) for tenant in TENANTS}
    app.config.update(MAX_CONTENT_LENGTH=MAX_UPLOAD, TRUSTED_HOSTS=[urlsplit(site).hostname])

    def connect():
        return sqlite3.connect(data_dir / "sessions.db")

    with closing(connect()) as db, db:
        db.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY, username TEXT NOT NULL, credential TEXT NOT NULL,
                expires INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS login_attempts (
                ip TEXT PRIMARY KEY, bucket INTEGER NOT NULL, count INTEGER NOT NULL
            );
        """)

    @app.before_request
    def authenticate():
        if request.host.lower() != public_host.lower():
            abort(400)
        if request.method not in SAFE_METHODS and request.headers.get("Origin") != site:
            abort(403)
        if request.path == "/login":
            return None

        cookie = request.cookies.get(LOGIN_COOKIE)
        if cookie and len(cookie) == 43:
            login_id = digest(cookie)
            with closing(connect()) as db:
                row = db.execute(
                    "SELECT username, credential FROM sessions WHERE id = ? AND expires > ?",
                    (login_id, int(time.time())),
                ).fetchone()
            if row and (user := users.get(row[0])) and compare_digest(row[1], user["hash"]):
                g.user, g.login_id = user, login_id
                if request.path == "/logout":
                    return None
                return proxy(user, login_id)
        if request.path == "/api/bank/callback":
            return render_template("hosted_login.html", callback_expired=True), 401
        if request.method not in SAFE_METHODS:
            abort(401)
        return redirect("/login", code=303)

    @app.after_request
    def private_response(response):
        response.headers["Cache-Control"] = "no-store"
        # Retain only the origin on outbound navigations and keep callback codes out of referers.
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if request.path == "/api/bank/callback":
            response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        return response

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "GET":
            return render_template("hosted_login.html")
        if (request.content_length or 0) > 8192:
            abort(413)
        try:
            # The edge must replace X-Real-IP with the direct client address.
            source = str(ip_address(request.headers.get("X-Real-IP") or request.remote_addr))
        except ValueError:
            source = request.remote_addr
        now = int(time.time())
        bucket = now // 600
        with closing(connect()) as db, db:
            db.execute("DELETE FROM login_attempts WHERE bucket < ?", (bucket,))
            count = db.execute(
                "INSERT INTO login_attempts VALUES (?, ?, 1) "
                "ON CONFLICT(ip) DO UPDATE SET count = count + 1 RETURNING count",
                (source, bucket),
            ).fetchone()[0]
        if count > 12:
            return render_template("hosted_login.html", error="Zu viele Anmeldeversuche. Bitte später erneut versuchen."), 429

        username = request.form.get("username", "").strip().casefold()
        password = request.form.get("password", "")
        user = users.get(username)
        record = user or next(iter(users.values()))
        if len(password) > 128:
            abort(400)
        candidate = password_hash(password, bytes.fromhex(record["salt"]))
        if not compare_digest(candidate, record["hash"]) or user is None:
            return render_template("hosted_login.html", error="Anmeldung fehlgeschlagen."), 401

        session_token = secrets.token_urlsafe(32)
        old_token = request.cookies.get(LOGIN_COOKIE, "")
        with closing(connect()) as db, db:
            db.execute("DELETE FROM sessions WHERE expires <= ? OR id = ?", (now, digest(old_token)))
            db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                       (digest(session_token), username, user["hash"], now + SESSION_SECONDS))
            db.execute("DELETE FROM login_attempts WHERE ip = ?", (source,))
        response = redirect("/", code=303)
        response.set_cookie(LOGIN_COOKIE, session_token, max_age=SESSION_SECONDS,
                            secure=True, httponly=True, samesite="Lax")
        clear_tenant_cookies(response)
        return response

    @app.post("/logout")
    def logout():
        if not compare_digest(request.form.get("_klar_csrf", "").encode(), csrf_for(g.login_id).encode()):
            abort(403)
        with closing(connect()) as db, db:
            db.execute("DELETE FROM sessions WHERE id = ?", (g.login_id,))
        response = redirect("/login", code=303)
        response.delete_cookie(LOGIN_COOKIE, secure=True, httponly=True, samesite="Lax")
        clear_tenant_cookies(response)
        return response

    def proxy(user, login_id):
        tenant = user["tenant"]
        connection = HTTPConnection(*upstreams[tenant], timeout=115)
        target = quote(request.path, safe="/:@!$&'()*+,;=-._~")
        if request.query_string:
            target += "?" + quote(request.query_string, safe="!$&'()*+,-./:;=?@_%~")
        headers = {key: request.headers[key] for key in FORWARDED_HEADERS if key in request.headers}
        referrer = request.headers.get("Referer", "")
        if referrer.startswith(site + "/"):
            headers["Referer"] = referrer
        headers["Host"] = public_host
        headers["X-Forwarded-Proto"] = "https"
        headers[INTERNAL_GATEWAY_HEADER] = user["token"]
        headers[INTERNAL_LOGIN_HEADER] = login_id
        headers["X-Klar-Username"] = user["display"]
        cookie_name = tenant_cookie(tenant)
        app_cookie = request.cookies.get(cookie_name)
        if app_cookie and all(c.isalnum() and c.isascii() or c in "._-" for c in app_cookie):
            headers["Cookie"] = f"{cookie_name}={app_cookie}"
        try:
            body = request.get_data() if request.method not in SAFE_METHODS else None
            connection.request(request.method, target, body=body, headers=headers)
            upstream = connection.getresponse()
        except (HTTPException, OSError):
            connection.close()
            abort(502)
        except Exception:
            connection.close()
            raise
        forwarded = []
        hop_headers = HOP_HEADERS | {
            name.strip().lower() for name in (upstream.getheader("Connection") or "").split(",")
        }
        for key, value in upstream.getheaders():
            if key.lower() in hop_headers:
                continue
            if key.lower() == "set-cookie" and not value.startswith(cookie_name + "="):
                continue
            forwarded.append((key, value))

        response = Response(iter(lambda: upstream.read(65536), b""), status=upstream.status, headers=forwarded)
        response.call_on_close(connection.close)
        return response

    return app


def clear_tenant_cookies(response):
    for tenant in TENANTS:
        response.delete_cookie(tenant_cookie(tenant), secure=True, httponly=True, samesite="Lax")
