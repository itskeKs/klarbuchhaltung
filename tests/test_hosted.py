"""Hosted isolation and Enable Banking regression checks using disposable accounts."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from datetime import date, datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from time import monotonic, sleep
from urllib.parse import parse_qs, urlencode, urlsplit
from urllib.request import HTTPError, Request, urlopen

import pytest

from hosted.enable_banking import BankingError, EnableBanking, transaction_rows
from hosted.gateway import create_app
from hosted.provision import provision

SITE = "https://buha.fogu.app"
BANK = "Fixture Bank"
APP_ID = "6d1c834a-4ff2-4914-aba0-5df9d9e16ae7"
SESSION = "f0f0140f-7712-4930-9e24-8f3929083d73"
ACCOUNT = "127660b5-4c2c-4fd8-8dba-dbcfcd2190fe"
ROOT = Path(__file__).resolve().parents[1]


def bank_row(**fields):
    return {"booking_date": date.today().isoformat(), "credit_debit_indicator": "CRDT",
            "status": "BOOK", "transaction_amount": {"currency": "EUR", "amount": "119.00"},
            "remittance_information": ["Fixture bank transfer"], **fields}


class StubProvider(EnableBanking):
    def __init__(self, application_id, pem):
        if application_id != APP_ID or pem != b"fixture-key":
            raise BankingError("Fixture credentials rejected")
        self.application_id = application_id

    def request(self, method, path, *, query=None, data=None):
        if (method, path) == ("GET", "/application"):
            return {"kid": APP_ID, "environment": "PRODUCTION", "active": True, "services": ["AIS"],
                    "redirect_urls": [SITE + "/api/bank/callback"]}
        if (method, path) == ("GET", "/aspsps"):
            return {"aspsps": [{"name": BANK, "psu_types": ["business", "personal"],
                                "maximum_consent_validity": 86400 * 60}]}
        if (method, path) == ("POST", "/auth"):
            assert data["redirect_url"] == SITE + "/api/bank/callback"
            return {"url": "https://auth.enablebanking.com/ais/start?" + urlencode({"state": data["state"]})}
        if (method, path) == ("POST", "/sessions"):
            assert data == {"code": "fixture-code"}
            return {"session_id": SESSION, "accounts": [{"name": "No account identifier"}, {"uid": ACCOUNT,
                                                          "identification_hash": "stable-bank-account",
                                                          "name": "Geschäftskonto"}]}
        if (method, path) == ("DELETE", "/sessions/" + SESSION):
            return {}
        if (method, path) == ("GET", "/accounts/" + ACCOUNT + "/transactions"):
            assert query["transaction_status"] == "BOOK"
            if query.get("continuation_key") == "page-2":
                return {"transactions": [bank_row(transaction_id="temporary-2"),
                                         bank_row(remittance_information=["Another equal amount"])]}
            return {"transactions": [bank_row(entry_reference="official-reference"),
                                     bank_row(transaction_id="temporary-1")],
                    "continuation_key": "page-2"}
        raise AssertionError(f"Unexpected fixture request {method} {path}")


def start_tenant(stack, directory, credentials, tenant):
    directory.mkdir()
    env = {key: value for key, value in os.environ.items() if key != "USER"}
    env.update(BB_HOME=str(directory), KLAR_PUBLIC_ORIGIN=SITE, KLAR_TENANT=tenant, PYTHONPATH=str(ROOT),
               PYTHONDONTWRITEBYTECODE="1")
    process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), str(credentials)],
                               stdout=subprocess.PIPE, text=True, env=env)

    def stop():
        process.terminate()
        process.wait(timeout=10)
        process.stdout.close()

    stack.callback(stop)
    output = process.stdout.readline().strip()
    assert output.isdigit(), "Hosted process failed to start"
    return ("127.0.0.1", int(output))


def csrf(response):
    match = re.search('name="klar-csrf" content="([a-f0-9]+)"', response.get_data(as_text=True))
    assert match
    return match[1]


def post(client, path, data=None, *, token=None, **headers):
    headers.setdefault("Origin", SITE)
    if token:
        headers["X-Klar-CSRF"] = token
    return client.post(path, base_url=SITE, data=data or {}, headers=headers)


def fetch(client, path):
    return client.get(path, base_url=SITE)


def wait_for(client, path, text):
    end = monotonic() + 6
    while monotonic() < end:
        response = fetch(client, path)
        if text in response.get_data(as_text=True):
            return response
        sleep(0.05)
    pytest.fail(f"Expected fixture state did not appear at {path}: {text}")


def test_two_hosted_logins_and_enable_banking(tmp_path, monkeypatch):
    monkeypatch.setenv("KLAR_PUBLIC_ORIGIN", SITE)
    private = tmp_path / "secrets"
    passwords = provision(private, ["Chris", "Kiki"])
    rows = json.loads((private / "gateway.json").read_text())
    assert rows["chris"]["token"] != rows["kiki"]["token"]
    assert passwords["Chris"] != passwords["Kiki"]
    assert all(password not in (private / "gateway.json").read_text() for password in passwords.values())

    with ExitStack() as stack:
        upstreams = {tenant: start_tenant(stack, tmp_path / tenant, private / tenant, tenant)
                     for tenant in ("tenant-a", "tenant-b")}
        gw = create_app(private / "gateway.json", tmp_path, upstreams)
        a, b = gw.test_client(), gw.test_client()
        direct = Request("http://%s:%d/files" % upstreams["tenant-a"], headers={"Host": urlsplit(SITE).netloc})
        with pytest.raises(HTTPError, match="404"):
            urlopen(direct, timeout=3)
        assert fetch(a, "/files").location == "/login"
        assert fetch(a, "/api/bank/callback?state=untrusted").status_code == 401
        assert post(a, "/login", {"username": "Chris", "password": passwords["Chris"]}, Origin="https://evil.invalid").status_code == 403
        assert post(a, "/login", {"username": "Kiki", "password": passwords["Chris"]}).status_code == 401
        for client, name in ((a, "Chris"), (b, "Kiki")):
            response = post(client, "/login", {"username": name.lower(), "password": passwords[name]})
            assert response.location == "/"
            assert "Secure; HttpOnly; Path=/; SameSite=Lax" in response.headers.getlist("Set-Cookie")[0]
            assert fetch(client, "/").location == "/setup"
            token = csrf(fetch(client, "/setup"))
            assert post(client, "/setup", {"name": f"{name} company", "owner": name,
                        "street": "1 Test Street", "city": "10115 Berlin"}, token=token).location == "/"
            assert f"{name} company" in fetch(client, "/settings?tab=profile").get_data(as_text=True)

        token_a, token_b = (csrf(fetch(client, "/zahlungen")) for client in (a, b))
        assert token_a != token_b
        assert post(b, "/zahlungen/manual", {"amount": "50"}, token=token_a).status_code == 403
        assert post(a, "/profile/neu", {"name": "extra"}, token=token_a).status_code == 404
        assert post(a, "/settings", {"section": "llm"}, token=token_a).status_code == 404
        for disabled in ("/terminal", "/pty", "/agent/api", "/chat", "/banking/live", "/restart"):
            assert fetch(a, disabled).status_code == 404
        assert post(a, "/documents/upload", {"file": (io.BytesIO(b"<svg>fixture</svg>"), "private.svg")},
                    token=token_a).location == "/files"
        file_a, file_b = fetch(a, "/documents/1/file"), fetch(b, "/documents/1/file")
        assert file_a.data == b"<svg>fixture</svg>"
        assert file_a.mimetype == "application/octet-stream"
        assert file_a.headers["Content-Disposition"].startswith("attachment")
        assert file_a.headers["Cache-Control"] == "no-store"
        assert file_b.status_code == 404
        path = "/documents/1/confirm?json=1"
        assert post(a, path, token=token_a).status_code == 400
        assert post(a, path, {"document_amount": "12,00", "document_date": date.today().isoformat()},
                    token=token_a).get_json()["ok"]

        invoice = {"new_name": "Chris Client", "issue_date": date.today().isoformat(),
                   "service_from": date.today().isoformat(), "item_desc": "Invoice line", "item_qty": "1",
                   "item_unit": "x", "item_price": "100", "item_rate": "19"}
        assert post(a, "/invoices/new", invoice | {"number": "2026-11-01/../../danger"}, token=token_a).status_code == 400
        assert post(a, "/invoices/new", invoice, token=token_a).location == "/invoices"
        assert fetch(a, "/invoices/1/pdf").data.startswith(b"%PDF")
        assert fetch(b, "/invoices/1/pdf").status_code == 404
        assert "E-Mail vorbereiten" in fetch(a, f"/invoices?dir=out&year={date.today().year}").get_data(as_text=True)

        assert "Enable Banking einrichten" in fetch(a, "/banking").get_data(as_text=True)
        prefix = "/banking/enable-banking/"
        assert post(a, prefix + "credentials", {"application_id": APP_ID,
                    "private_key": (io.BytesIO(b"fixture-key"), "key.pem")}, token=token_a).location == "/banking"
        assert BANK in fetch(a, "/banking").get_data(as_text=True)
        assert BANK not in fetch(b, "/banking").get_data(as_text=True)
        begin = post(a, prefix + "connect", {"country": "DE", "bank": BANK, "psu_type": "business"}, token=token_a)
        state = parse_qs(urlsplit(begin.location).query)["state"][0]
        callback = "/api/bank/callback?" + urlencode({"state": state, "code": "fixture-code"})
        assert fetch(b, callback).location == "/banking"
        assert "konnte nicht zugeordnet werden" in fetch(b, "/banking").get_data(as_text=True)
        assert fetch(a, callback).location == "/banking"
        wait_for(a, "/banking", "4 neue Umsätze importiert.")
        assert "Another equal amount" in fetch(a, "/zahlungen").get_data(as_text=True)
        assert "Another equal amount" not in fetch(b, "/zahlungen").get_data(as_text=True)
        replay = fetch(a, callback)
        assert replay.location == "/banking"
        assert "konnte nicht zugeordnet werden" in fetch(a, "/banking").get_data(as_text=True)

        assert post(a, prefix + "sync", token=token_a).location == "/banking"
        wait_for(a, "/banking", "0 neue Umsätze importiert.")
        with sqlite3.connect(tmp_path / "tenant-a" / "data" / "bookkeeping.db") as ledger:
            actual = ledger.execute("SELECT category, invoice_id FROM transactions").fetchall()
            assert actual == [("offen", None)] * 4
            assert ledger.execute("SELECT paid_date FROM invoices").fetchone()[0] is None
        booking_url = "/zahlungen/tx/1/set"
        page = fetch(a, "/zahlungen").get_data(as_text=True)
        assert "Umsatzsteuer ohne Rechnungszuordnung" in page
        assert post(a, booking_url, {"action": "einnahme_ust19"}, token=token_a).status_code == 302
        with sqlite3.connect(tmp_path / "tenant-a" / "data" / "bookkeeping.db") as ledger:
            assert ledger.execute("SELECT category FROM transactions WHERE id=1").fetchone() == ("einnahme_ust19",)
        assert post(a, booking_url, {"action": "offen"}, token=token_a).status_code == 302
        assert post(a, prefix + "disconnect", {"session_id": SESSION}, token=token_a).location == "/banking"
        assert "Verbindung trennen" not in fetch(a, "/banking").get_data(as_text=True)

        cookie = a.get_cookie("__Host-klar-auth", domain=urlsplit(SITE).netloc)
        assert post(a, "/logout", {"_klar_csrf": token_a}).location == "/login"
        a.set_cookie(cookie.key, cookie.value, domain=urlsplit(SITE).netloc)
        assert fetch(a, "/files").location == "/login"


def test_reference_fallback_and_previous_vendor_matching(sandbox):
    import core

    batch = [bank_row(entry_reference="stable"),
             bank_row(transaction_id="one"),
             bank_row(transaction_id="two"),
             bank_row(remittance_information=["other"]),
             bank_row(status="PDNG"),
             bank_row(booking_date=None)]
    rows, skipped = transaction_rows("account-a", batch)
    repeated, _ = transaction_rows("account-a", batch[:1] + [batch[2], batch[1]] + batch[3:])
    assert skipped == 1
    assert len({row["ref"] for row in rows}) == 4
    assert {row["ref"] for row in rows} == {row["ref"] for row in repeated}
    assert transaction_rows("account-b", [batch[0]])[0][0]["ref"] != rows[0]["ref"]

    conn = core.db()
    core.create_invoice(conn, core.load_config(), customer=core.adhoc_customer("Fixture"),
                        kind="domestic", issue_date=date.today().isoformat(), service_from=date.today().isoformat(),
                        service_to=None, items=[{"description": "Test", "unit_price": "100", "vat_rate": 19}],
                        render=False)
    conn.close()

    def import_concurrently():
        with sqlite3.connect(core.DB_PATH) as ledger:
            ledger.row_factory = sqlite3.Row
            return core.import_bank_rows(ledger, rows, auto_match=False)["imported"]

    with ThreadPoolExecutor(2) as pool:
        assert sum(pool.map(lambda _: import_concurrently(), range(2))) == 4
    with sqlite3.connect(core.DB_PATH) as ledger:
        ledger.row_factory = sqlite3.Row
        assert core._auto_match_transactions(ledger) == 0
        assert ledger.execute("SELECT count(*) FROM transactions WHERE invoice_id IS NULL").fetchone()[0] == 4


def test_daily_sync_catches_up_after_browser_closes(sandbox):
    from hosted.bank_service import BankingService

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=StubProvider)
    service.save_credentials(APP_ID, b"fixture-key")
    begin = service.begin("login-a", "DE", BANK, "business")
    state = parse_qs(urlsplit(begin).query)["state"][0]
    service.finish("login-a", state, "fixture-code", "")
    today = datetime.now(timezone.utc)
    assert service.sync(now=today) == 4
    assert service.sync(now=today + timedelta(minutes=5)) == 0
    assert service.sync(now=today + timedelta(days=1)) == 0
    assert service.consents()[0]["last_synced"] == (today + timedelta(days=1)).date().isoformat()


def test_provider_reference_survives_optional_details_and_detects_conflicts():
    initial = bank_row(entry_reference="stable")
    enriched = initial | {"remittance_information": ["Enriched on later fetch"]}
    other_movement = initial | {"transaction_amount": {"currency": "EUR", "amount": "50"}}
    original = transaction_rows("account", [initial])[0][0]
    assert transaction_rows("account", [enriched])[0][0]["ref"] == original["ref"]
    rows, skipped = transaction_rows("account", [initial, other_movement, enriched])
    assert skipped == 1
    assert len({row["ref"] for row in rows}) == 2


def test_daily_default_range_falls_back_after_partial_response():
    class RangeProvider(StubProvider):
        def __init__(self):
            self.queries = []

        def request(self, method, path, *, query=None, data=None):
            self.queries.append(query)
            if query.get("strategy") == "longest":
                return {"transactions": [bank_row(entry_reference="fresh")]}
            if query.get("continuation_key"):
                raise BankingError("Range unsupported", 422, "WRONG_TRANSACTIONS_PERIOD")
            return {"transactions": [bank_row(entry_reference="partial")], "continuation_key": "more"}

    provider = RangeProvider()
    rows = provider.transactions(ACCOUNT, "2026-10-20", "2026-11-01")
    assert [row["entry_reference"] for row in rows] == ["fresh"]
    assert provider.queries == [
        {"date_from": "2026-10-20", "date_to": "2026-11-01", "transaction_status": "BOOK"},
        {"date_from": "2026-10-20", "date_to": "2026-11-01", "transaction_status": "BOOK",
         "continuation_key": "more"},
        {"date_from": "2026-10-20", "strategy": "longest", "transaction_status": "BOOK"},
    ]


def test_fx_failure_defers_unconverted_foreign_amount(sandbox, monkeypatch):
    import core

    usd = bank_row(transaction_amount={"currency": "USD", "amount": "100"}, entry_reference="foreign")
    rows, _ = transaction_rows("account", [usd])
    ledger = core.db()
    assert core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)["deferred"] == 1
    assert not core.list_transactions(ledger)
    monkeypatch.setattr(core, "fx_rate", lambda *_args: 0.9)
    assert core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)["imported"] == 1
    assert core.list_transactions(ledger)[0]["amount_home"] == 90


def test_direct_taxable_income_reporting_and_reassignment(sandbox):
    from decimal import Decimal

    import core

    conn = core.db()
    cfg = core.load_config()
    assert core.direct_income_available(cfg)
    assert not core.direct_income_available({"tax": {"taxation": "soll"}})
    assert not core.direct_income_available({"tax": {"small_business": True}})
    lo, hi, _ = core.period_bounds(2026, "quarter", 1)
    eur_amounts = [(119, "einnahme_ust19"), (107, "einnahme_ust7")]
    ids = []
    for index, (amount, category) in enumerate(eur_amounts):
        tid = core.create_manual_transaction(conn, "2026-02-20", f"Bank receipt {index}", amount)
        core.set_tx_category(conn, tid, category)
        ids.append(tid)
    conn.execute("UPDATE transactions SET amount_home = 153 WHERE id = ?", (ids[0],))
    conn.commit()
    euer = core.euer(conn, cfg, lo, hi)
    assert (euer["income_net"], euer["umsatz_ust"], euer["betriebseinnahmen"]) == (200, 26, 226)
    vat = core.vat_data(conn, cfg, 2026, 1)
    assert (vat["net19"], vat["ust19"], vat["net7"], vat["ust7"]) == (100, 19, 100, 7)
    assert core.vat_annual(conn, cfg, 2026)["zahllast"] == Decimal("26.00")

    core.reset_tx(conn, ids[0])
    assert core.vat_data(conn, cfg, 2026, 1)["ust19"] == 0
    assert core.euer(conn, cfg, lo, hi)["betriebseinnahmen"] == 107
    invoice = core.create_invoice(conn, cfg, customer=core.adhoc_customer("Fixture"),
                                  kind="domestic", issue_date="2026-02-16", service_from="2026-02-15",
                                  service_to=None, items=[{"description": "Test", "unit_price": "100", "vat_rate": 7}],
                                  render=False)
    core.link_tx_invoice(conn, ids[1], invoice["id"])
    vat = core.vat_data(conn, cfg, 2026, 1)
    assert (vat["ust19"], vat["ust7"]) == (0, 7)
    with pytest.raises(ValueError, match="ungebundene"):
        core.set_tx_category(conn, ids[1], "einnahme_ust7")
    assert core.get_transaction(conn, ids[1])["invoice_id"] == invoice["id"]
    assert core.vat_annual(conn, cfg, 2026)["zahllast"] == Decimal("7.00")
    assert core.euer(conn, cfg, lo, hi)["betriebseinnahmen"] == 107


def test_closed_direct_receipt_is_not_auto_linked_or_reclassified(sandbox):
    import core

    conn = core.db()
    cfg = core.load_config()
    invoice = core.create_invoice(conn, cfg, customer=core.adhoc_customer("Fixture"),
                                  kind="domestic", issue_date="2026-02-16", service_from="2026-02-15",
                                  service_to=None, items=[{"description": "Test", "unit_price": "100", "vat_rate": 19}],
                                  render=False)
    tid = core.create_manual_transaction(conn, "2026-02-20", "Cash receipt", 119)
    core.set_tx_category(conn, tid, "einnahme_ust19")
    core.close_period("2026-Q1")
    result = core.import_bank_csv(conn, (
        "Type,Product,Started Date,Completed Date,Description,Amount,Fee,Currency,State,Balance\n"
        "CARD_PAYMENT,Current,2026-03-01,2026-03-01,Unrelated,-2,0,EUR,COMPLETED,500\n"
    ))
    assert result["imported"] == 1 and result["matched"] == 0
    assert core.get_invoice(conn, invoice["id"])["paid_date"] is None
    for reassign in (
        lambda: core.reset_tx(conn, tid),
        lambda: core.link_tx_invoice(conn, tid, invoice["id"]),
        lambda: core.create_expense_from_tx(conn, tid, "Sonstiges", 0),
    ):
        with pytest.raises(ValueError, match="festgeschrieben"):
            reassign()
    assert core.get_transaction(conn, tid)["category"] == "einnahme_ust19"


@pytest.mark.parametrize(("field", "value", "error"), [
    ("environment", "SANDBOX", "Produktionsanwendung"),
    ("active", False, "noch nicht aktiv"),
    ("services", ["PIS"], "Kontoinformationsdienst"),
    ("redirect_urls", [SITE + "/wrong"], "Rücksprungadresse"),
])
def test_enable_banking_application_must_be_activated_and_registered(tmp_path, field, value, error):
    from hosted.bank_service import BankingService

    class WrongApplication(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            return super().request(method, path, query=query, data=data) | {field: value}

    service = BankingService(tmp_path, tmp_path, SITE + "/api/bank/callback", client_factory=WrongApplication)
    with pytest.raises(BankingError, match=error):
        service.save_credentials(APP_ID, b"fixture-key")
    assert not service.credentials_configured()


if __name__ == "__main__":
    from werkzeug.serving import WSGIRequestHandler, make_server
    from hosted.tenant import create_app as create_tenant

    class QuietHandler(WSGIRequestHandler):
        def log_request(self, *_args, **_kwargs):
            pass

    tenant_app = create_tenant(Path(sys.argv[1]), client_factory=StubProvider)
    tenant_app.config["KLAR_START_SCHEDULER"]()
    server = make_server("127.0.0.1", 0, tenant_app, request_handler=QuietHandler)
    print(server.server_port, flush=True)
    server.serve_forever()
