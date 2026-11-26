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

SITE = "https://ledger.example.test"
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
    auth_origin = "https://auth.enablebanking.com"

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
            return {"url": self.auth_origin + "/ais/start?" + urlencode({"state": data["state"]})}
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
                return {"transactions": [bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                    transaction_amount={"currency": "EUR", "amount": "23.00"},
                    remittance_information=["Fixture supplies"])]}
            return {"transactions": [bank_row(entry_reference="credit"),
                                     bank_row(status="PDNG", remittance_information=["Pending transfer"])],
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
    passwords = provision(private, ["Alex", "Blake"])
    rows = json.loads((private / "gateway.json").read_text())
    assert rows["alex"]["token"] != rows["blake"]["token"]
    assert passwords["Alex"] != passwords["Blake"]
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
        assert post(a, "/login", {"username": "Alex", "password": passwords["Alex"]}, Origin="https://evil.invalid").status_code == 403
        assert post(a, "/login", {"username": "Blake", "password": passwords["Alex"]}).status_code == 401
        for client, name in ((a, "Alex"), (b, "Blake")):
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
        wait_for(a, "/banking", "2 neue Umsätze importiert.")
        def sync_again():
            # Clear only the previous result so the UI must show a fresh completion.
            with sqlite3.connect(tmp_path / "tenant-a" / "enable-banking.db") as state_db:
                state_db.execute("UPDATE consents SET message = NULL")
            assert post(a, prefix + "sync", token=token_a).location == "/banking"
            wait_for(a, "/banking", "0 neue Umsätze importiert.")

        sync_again()
        sync_again()
        page = fetch(a, "/zahlungen").get_data(as_text=True)
        for label in ("Fixture bank transfer", "Fixture supplies", "119,00 €", "-23,00 €", "96,00 €"):
            assert label in page
        assert "Pending transfer" not in page
        assert page.count('title="Offen"') == 2
        other = fetch(b, "/zahlungen").get_data(as_text=True)
        assert "Fixture bank transfer" not in other and "Fixture supplies" not in other
        assert "96,00 €" not in other

        assert fetch(a, callback).location == "/banking"
        assert "konnte nicht zugeordnet werden" in fetch(a, "/banking").get_data(as_text=True)
        assert post(a, "/zahlungen/tx/2/set", {"action": "gebuehr"}, token=token_a).status_code == 302
        sync_again()
        assert fetch(a, "/zahlungen").get_data(as_text=True).count('data-uncat="1"') == 1
        assert post(a, prefix + "disconnect", {"session_id": SESSION}, token=token_a).location == "/banking"
        assert "Verbindung trennen" not in fetch(a, "/banking").get_data(as_text=True)
        with sqlite3.connect(tmp_path / "tenant-a" / "data" / "bookkeeping.db") as ledger:
            assert ledger.execute("SELECT amount, category FROM transactions ORDER BY id").fetchall() == [
                (119.0, "offen"), (-23.0, "gebuehr"),
            ]

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


def test_daily_sync_catches_up_after_browser_closes(sandbox, monkeypatch):
    from hosted.bank_service import BankingService

    monkeypatch.setattr(StubProvider, "auth_origin", "https://tilisy.enablebanking.com")
    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=StubProvider)
    service.save_credentials(APP_ID, b"fixture-key")
    begin = service.begin("login-a", "DE", BANK, "business")
    assert urlsplit(begin).netloc == "tilisy.enablebanking.com"
    state = parse_qs(urlsplit(begin).query)["state"][0]
    with pytest.raises(BankingError, match="zugeordnet"):
        service.finish("another-login-for-ledger-a", state, "fixture-code", "")
    service.finish("login-a", state, "fixture-code", "")
    with pytest.raises(BankingError, match="zugeordnet"):
        service.finish("login-a", state, "fixture-code", "")
    today = datetime.now(timezone.utc)
    assert service.sync(now=today) == 2
    assert service.sync(now=today + timedelta(minutes=5)) == 0
    original = StubProvider.request
    new_references = ["next-day"]

    def with_later_bookings(self, method, path, *, query=None, data=None):
        page = original(self, method, path, query=query, data=data)
        if query and query.get("continuation_key") == "page-2":
            page["transactions"].extend(bank_row(entry_reference=ref) for ref in new_references)
        return page

    monkeypatch.setattr(StubProvider, "request", with_later_bookings)
    tomorrow = today + timedelta(days=1)
    assert service.sync(now=tomorrow) == 1
    new_references.append("same-day")
    assert service.sync(force=True, now=tomorrow) == 1
    assert service.consents()[0]["last_synced"] == (today + timedelta(days=1)).date().isoformat()


@pytest.mark.parametrize("origin", ["http://tilisy.enablebanking.com", "https://other.example",
                                    "https://auth.enablebanking.com:8443"])
def test_consent_requires_provider_https_origin(tmp_path, monkeypatch, origin):
    from hosted.bank_service import BankingService

    monkeypatch.setattr(StubProvider, "auth_origin", origin)
    service = BankingService(tmp_path, tmp_path, SITE + "/api/bank/callback", client_factory=StubProvider)
    service.save_credentials(APP_ID, b"fixture-key")
    with pytest.raises(BankingError, match="Freigabeadresse"):
        service.begin("login-a", "DE", BANK, "business")
    with sqlite3.connect(service.path) as db:
        assert db.execute("SELECT COUNT(*) FROM pending").fetchone()[0] == 0


def test_unreferenced_booking_survives_enrichment_and_new_equal_payments(sandbox):
    import core

    conn = core.db()
    original = bank_row(remittance_information=["Original transfer"])
    other = bank_row(remittance_information=["Another transfer"])

    def ingest(page):
        rows, skipped = transaction_rows("account-a", page)
        assert skipped == 0
        return core.import_bank_rows(conn, rows, auto_match=False)["imported"]

    assert ingest([original, other]) == 2
    core.set_tx_category(conn, 1, "einnahme_sonstige")
    enriched = original | {"balance_after_transaction": {"amount": "300", "currency": "EUR"}}
    assert ingest([other, enriched]) == 0
    third = bank_row(remittance_information=["Third transfer"])
    assert ingest([third, enriched, other]) == 1
    assert ingest([other, third, enriched]) == 0
    assert [tuple(row) for row in conn.execute(
        "SELECT description, category FROM transactions ORDER BY id"
    )] == [("Original transfer", "einnahme_sonstige"), ("Another transfer", "offen"),
           ("Third transfer", "offen")]


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


def test_expired_consent_and_disconnect_preserve_bookings(sandbox, monkeypatch):
    import core
    from hosted.bank_service import BankingService

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=StubProvider)
    service.save_credentials(APP_ID, b"fixture-key")
    state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
    service.finish("login-a", state, "fixture-code", "")
    now = datetime.now(timezone.utc)
    assert service.sync(now=now) == 2

    def expired(*args):
        raise BankingError("Provider error", 401, "EXPIRED_SESSION")

    monkeypatch.setattr(StubProvider, "transactions", expired)
    assert service.sync(force=True, now=now) == 0
    assert "Verbinde das Konto erneut" in service.consents()[0]["message"]

    def stop_if_called(*args):
        pytest.fail("A disconnected or expired account must not be fetched")

    monkeypatch.setattr(StubProvider, "transactions", stop_if_called)
    assert service.sync(force=True, now=now + timedelta(hours=1)) == 0
    assert service.sync(now=now + timedelta(days=65)) == 0
    assert "Verbinde das Konto erneut" in service.consents()[0]["message"]
    service.disconnect(SESSION)
    assert service.sync(force=True, now=now) == 0
    assert len(core.list_transactions(core.db())) == 2


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
    from runpy import run_path
    from types import SimpleNamespace

    worker_hook = run_path(str(ROOT / "hosted" / "gunicorn.conf.py"))["post_worker_init"]
    worker_hook(SimpleNamespace(wsgi=tenant_app))
    server = make_server("127.0.0.1", 0, tenant_app, request_handler=QuietHandler)
    print(server.server_port, flush=True)
    server.serve_forever()
