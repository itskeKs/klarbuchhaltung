"""Run one bookkeeping instance behind the hosted gateway."""
from hmac import compare_digest
import os
from pathlib import Path
import re
from urllib.parse import urlsplit

from flask import abort, flash, g, redirect, render_template, request, send_file, session, url_for
from werkzeug.middleware.proxy_fix import ProxyFix

import core
from hosted.bank_service import BankingService
from hosted.common import (CSRF_HEADER, INTERNAL_GATEWAY_HEADER, INTERNAL_LOGIN_HEADER,
                           MAX_UPLOAD, SECRET_DIR, TENANTS, csrf_for, digest, origin,
                           tenant_cookie)
from hosted.enable_banking import BankingError

ALLOWED = {
    "banking", "bank_begin", "bank_callback", "bank_credentials", "bank_disconnect", "bank_sync",
    "categories", "customer_delete", "customer_number", "customers", "customers_merge_duplicates",
    "dashboard", "document_confirm", "document_delete", "document_file", "documents_upload",
    "dunning", "expense_delete", "expense_pay", "expense_receipt", "expense_update",
    "expense_vat_kind", "expenses", "files", "import_csv", "import_template",
    "invoice_delete", "invoice_new", "invoice_pay", "invoice_pdf", "invoice_pdf_upload",
    "invoices", "invoices_customer", "recurring", "reports", "reports_close", "settings",
    "setup", "static", "tax_ack", "zahlungen", "zahlungen_bulk", "zahlungen_category",
    "zahlungen_expense", "zahlungen_export", "zahlungen_import", "zahlungen_link",
    "zahlungen_manual", "zahlungen_receipt", "zahlungen_set", "zahlungen_split", "zahlungen_upload",
}


def create_app(secrets_dir=SECRET_DIR, *, client_factory=None):
    from app import app
    tenant = os.environ["KLAR_TENANT"]
    if tenant not in TENANTS:
        raise ValueError("Invalid tenant")
    site = origin()
    gateway_token = (secrets_dir / "gateway-token").read_text().strip()
    if not re.fullmatch(r"[\w-]{43}", gateway_token, re.ASCII):
        raise ValueError("Missing or invalid gateway token")
    # Hosted data always uses this container's fixed root. A profile cookie is never consulted.
    core.use_profile(None)
    service_options = {"client_factory": client_factory} if client_factory else {}
    service = BankingService(core.HOME, secrets_dir, site + "/api/bank/callback", **service_options)
    app.config.update(
        KLAR_HOSTED=True, SECRET_KEY=digest("klar-tenant:" + gateway_token),
        SESSION_COOKIE_NAME=tenant_cookie(tenant), SESSION_COOKIE_SECURE=True,
        SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
        MAX_CONTENT_LENGTH=MAX_UPLOAD, TRUSTED_HOSTS=[urlsplit(site).hostname],
        KLAR_HOSTED_SEND_FILE=send_tenant_file,
        KLAR_START_SCHEDULER=lambda: service.start_worker(app.logger),
    )
    app.wsgi_app = ProxyFix(app.wsgi_app, x_proto=1)

    def require_gateway():
        supplied = request.headers.get(INTERNAL_GATEWAY_HEADER, "").encode()
        if not compare_digest(supplied, gateway_token.encode()) or request.endpoint not in ALLOWED:
            abort(404)
        login = request.headers.get(INTERNAL_LOGIN_HEADER, "")
        if not re.fullmatch("[a-f0-9]{64}", login):
            abort(404)
        g.login_id = login
        g.hosted_csrf = csrf_for(login)
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            token = request.headers.get(CSRF_HEADER) or request.form.get("_klar_csrf", "")
            if not compare_digest(token.encode(), g.hosted_csrf.encode()):
                abort(403)
        if request.endpoint == "static":
            return None
        if session.get("hosted_login") != login:
            session.clear()
            session["hosted_login"] = login
        if not core.config_exists() and request.endpoint != "setup":
            return redirect(url_for("setup"), code=303)
        if request.endpoint == "invoice_new" and request.method == "POST":
            number = request.form.get("number", "")
            if len(number) > 80 or "/" in number or "\\" in number or "\x00" in number:
                abort(400)
        return None

    app.config["KLAR_HOSTED_GUARD"] = require_gateway

    @app.context_processor
    def hosted_context():
        return {"hosted_csrf": g.hosted_csrf,
                "hosted_username": request.headers.get("X-Klar-Username", "Klarbuchhaltung")}

    def bank_page():
        country = request.args.get("country", "DE").strip().upper()
        banks = []
        problem = None
        configured = managed = False
        try:
            configured = service.credentials_configured()
            managed = service.mounted_credentials() is not None
            if configured:
                banks = service.banks(country)
        except BankingError as exc:
            problem = str(exc)
        return render_template("hosted_banking.html", active="banking", country=country,
                               banks=banks, callback=service.callback, configured=configured,
                               managed=managed, consents=service.consents(), problem=problem)

    app.view_functions["banking"] = bank_page

    @app.post("/banking/enable-banking/credentials")
    def bank_credentials():
        file = request.files.get("private_key")
        try:
            service.save_credentials(request.form.get("application_id", ""), file.read(24_001) if file else b"")
            flash("Enable-Banking-Anwendung gespeichert.", "ok")
        except BankingError as exc:
            flash(str(exc), "error")
        return redirect(url_for("banking"), code=303)

    @app.post("/banking/enable-banking/connect")
    def bank_begin():
        country = request.form.get("country", "DE").upper()
        try:
            destination = service.begin(g.login_id, country, request.form.get("bank", ""),
                                        request.form.get("psu_type", ""))
            return redirect(destination, code=303)
        except BankingError as exc:
            flash(str(exc), "error")
            return redirect(url_for("banking", country=country), code=303)

    @app.get("/api/bank/callback")
    def bank_callback():
        try:
            service.finish(g.login_id, request.args.get("state", ""), request.args.get("code", ""),
                           request.args.get("error", ""))
            flash("Bank verbunden. Der erste Umsatzabruf läuft im Hintergrund.", "ok")
        except BankingError as exc:
            flash(str(exc), "error")
        return redirect(url_for("banking"), code=303)

    @app.post("/banking/enable-banking/sync")
    def bank_sync():
        service.request_sync()
        flash("Umsatzabruf im Hintergrund gestartet. Lade die Seite für den aktuellen Stand neu.", "ok")
        return redirect(url_for("banking"), code=303)

    @app.post("/banking/enable-banking/disconnect")
    def bank_disconnect():
        try:
            service.disconnect(request.form.get("session_id", ""))
            flash("Bankverbindung getrennt. Bereits importierte Umsätze bleiben erhalten.", "ok")
        except BankingError as exc:
            flash(str(exc), "error")
        return redirect(url_for("banking"), code=303)

    return app


def send_tenant_file(path, *, download_name=None):
    try:
        path = path.resolve(strict=True)
        if not path.is_relative_to(core.DOC_DIR.resolve()) or not path.is_file():
            abort(404)
        with path.open("rb") as file:
            start = file.read(16)
    except OSError:
        abort(404)
    if start.startswith(b"%PDF-"):
        kind = "application/pdf"
    elif start.startswith(b"\x89PNG\r\n\x1a\n"):
        kind = "image/png"
    elif start.startswith(b"\xff\xd8\xff"):
        kind = "image/jpeg"
    elif start.startswith((b"GIF87a", b"GIF89a")):
        kind = "image/gif"
    elif start.startswith(b"RIFF") and start[8:12] == b"WEBP":
        kind = "image/webp"
    else:
        kind = None
    response = send_file(path, download_name=download_name, as_attachment=not kind,
                         mimetype=kind or "application/octet-stream", conditional=True)
    response.headers["X-Content-Type-Options"] = "nosniff"
    return response
