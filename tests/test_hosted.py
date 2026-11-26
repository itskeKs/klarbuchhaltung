"""Hosted isolation and Enable Banking regression checks using disposable accounts."""
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack, closing
from datetime import date, datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import sqlite3
import subprocess
import sys
from threading import Barrier
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


@pytest.mark.parametrize("initial_ref", ["credit", None])
def test_provider_enrichment_preserves_open_total_and_category(sandbox, initial_ref):
    import core

    conn = core.db()
    first = bank_row(booking_date=None, value_date="2026-11-24", entry_reference=initial_ref)
    debit = bank_row(booking_date="2026-11-24", entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    def ingest(page):
        rows, skipped = transaction_rows("account-a", page)
        assert skipped == 0
        return core.import_bank_rows(conn, rows, auto_match=False)["imported"]

    assert ingest([first, debit]) == 2
    core.set_tx_category(conn, 1, "einnahme_sonstige")
    enriched = first | {"entry_reference": "credit", "booking_date": "2026-11-25"}
    assert ingest([debit, enriched]) == 0
    assert ingest([enriched | {"remittance_information": ["Updated memo"]}, debit]) == 0
    assert ingest([enriched | {"value_date": None}, debit]) == 0
    assert ingest([enriched | {"booking_date": None, "value_date": "2026-11-26", "transaction_date": "2026-11-25"}, debit]) == 0
    assert tuple(conn.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
    assert core.get_transaction(conn, 1)["category"] == "einnahme_sonstige"


def test_new_equal_payment_precedes_enriched_memo(sandbox):
    import core

    conn = core.db()
    rent = bank_row(remittance_information=["Rent"])
    supplies = bank_row(remittance_information=["Supplies"])
    rows, _ = transaction_rows("account-a", [rent])
    core.import_bank_rows(conn, rows, auto_match=False)
    core.set_tx_category(conn, 1, "einnahme_sonstige")
    enriched = rent | {"remittance_information": ["Rent", "November"]}
    for batch, expected in (([supplies, enriched], 1), ([enriched, supplies], 0)):
        rows, _ = transaction_rows("account-a", batch)
        assert core.import_bank_rows(conn, rows, auto_match=False)["imported"] == expected
        assert [tuple(row) for row in conn.execute(
            "SELECT description, category FROM transactions ORDER BY id"
        )] == [("Rent", "einnahme_sonstige"), ("Supplies", "offen")]


@pytest.mark.parametrize("reverse", [True, False])
def test_dated_match_precedes_reused_bank_reference(sandbox, reverse):
    import core

    ledger = core.db()
    first = bank_row(entry_reference="reused", booking_date=None, value_date="2026-11-22")
    later = bank_row(entry_reference="reused", booking_date="2026-11-24", value_date="2026-11-24")
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    rows, _ = transaction_rows("account-a", [first, debit])
    core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    enriched = first | {"booking_date": "2026-11-23"}
    batch = [later, enriched, debit]
    if reverse:
        batch.reverse()
    for expected in (1, 0):
        rows, skipped = transaction_rows("account-a", batch)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
        assert core.get_transaction(ledger, 1)["category"] == "einnahme_sonstige"


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("partial_balance, changes, expected_imports", [
    (None, {"balance_after_transaction": {"amount": "119.00", "currency": "EUR"}}, 0),
    ("119.00", {}, 0),
    (None, {"value_date": "2026-11-22"}, 1),
    ("119.00", {"balance_after_transaction": {"amount": "238.00", "currency": "EUR"}}, 1),
])
def test_partial_date_copy_coexists_with_posted_version(sandbox, reverse, partial_balance, changes, expected_imports):
    import core

    ledger = core.db()
    partial = bank_row(entry_reference="credit", booking_date=None, value_date="2026-11-20",
                       transaction_date="2026-11-19")
    if partial_balance:
        partial["balance_after_transaction"] = {"amount": partial_balance, "currency": "EUR"}
    posted = partial | {"booking_date": "2026-11-21"} | changes
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    rows, _ = transaction_rows("account-a", [partial, debit])
    assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
    core.set_tx_category(ledger, 1, "einnahme_sonstige")

    batch = [posted, partial, debit] if reverse else [partial, posted, debit]
    for page, expected in ((batch, expected_imports), (batch[::-1], 0)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert ledger.execute("SELECT sum(amount) FROM transactions").fetchone()[0] == (215 if expected_imports else 96)
        assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
        assert core.get_transaction(ledger, 1)["category"] == "einnahme_sonstige"


def test_partial_date_copy_alone_replays_fresh_canonical_booking(sandbox):
    import core

    ledger = core.db()
    partial = bank_row(entry_reference="credit", booking_date=None, value_date="2026-11-20")
    posted = partial | {"booking_date": "2026-11-21"}
    for page, expected in (([posted, partial], 1), ([partial], 0), ([posted], 0)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
        assert [tuple(row) for row in ledger.execute("SELECT date, amount FROM transactions")] == [("2026-11-21", 119)]


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("overlap_first", [True, False])
def test_full_booking_learns_dates_from_overlap_for_sparse_replays(sandbox, reverse, overlap_first):
    import core

    posted = bank_row(entry_reference="credit", booking_date="2026-11-21", value_date="2026-11-20",
                      transaction_date="2026-11-19")
    debit = bank_row(entry_reference="debit", booking_date="2026-11-21", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    sparse = posted | {"booking_date": None, "transaction_date": None}
    ledger = core.db()
    rows, _ = transaction_rows("account-a", [posted, debit])
    assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    original = [tuple(row) for row in ledger.execute("SELECT id, ref, date, category FROM transactions ORDER BY id")]
    batch = [sparse, posted, debit] if reverse else [posted, sparse, debit]
    older_date_copy = posted | {"booking_date": None, "value_date": None}
    added_date = posted | {"transaction_date": "2026-11-18"}
    added_date_copy = older_date_copy | {"transaction_date": "2026-11-18"}
    first_page = batch if overlap_first else [sparse, debit]
    for page in (first_page, [sparse, debit], [older_date_copy, debit], [added_date, debit],
                 [added_date_copy, debit], batch[::-1]):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert [tuple(row) for row in ledger.execute("SELECT id, ref, date, category FROM transactions ORDER BY id")] == original


@pytest.mark.parametrize("missing_facts", [(), ("reference_schema",), ("creditor_ref", "reference_schema"), ("counterparty_iban",)])
def test_legacy_banking_schema_opens_concurrently_and_keeps_identity(sandbox, missing_facts):
    import core

    posted = bank_row(entry_reference="credit", booking_date="2026-11-21", value_date="2026-11-20",
                      reference_number=None if "creditor_ref" in missing_facts else "INV123",
                      reference_number_schema=None if "reference_schema" in missing_facts else "SCOR")
    rows, _ = transaction_rows("account-a", [posted])
    with closing(core.db()) as ledger:
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 1
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        ledger.execute("DROP TABLE IF EXISTS bank_import_date_aliases")
        original = tuple(ledger.execute("SELECT * FROM transactions").fetchone())
        identity = tuple(ledger.execute("SELECT * FROM bank_import_identity").fetchone())
        facts = dict(ledger.execute("SELECT * FROM bank_import_facts").fetchone())
        for column in missing_facts:
            ledger.execute(f"ALTER TABLE bank_import_facts DROP COLUMN {column}")

    ready = Barrier(2)

    def open_ledger():
        ready.wait(timeout=5)
        with closing(core.db()) as ledger:
            assert ledger.execute("SELECT count(*) FROM bank_import_date_aliases").fetchone()[0] == 0
            assert dict(ledger.execute("SELECT * FROM bank_import_facts").fetchone()) == facts

    with ThreadPoolExecutor(2) as pool:
        list(pool.map(lambda _: open_ledger(), range(2)))

    sparse = posted | {"booking_date": None}
    with closing(core.db()) as ledger:
        for page in ([posted, sparse], [sparse], [posted]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
        assert [tuple(row) for row in ledger.execute("SELECT * FROM transactions")] == [original]
        assert tuple(ledger.execute("SELECT * FROM bank_import_identity").fetchone()) == identity
        assert dict(ledger.execute("SELECT * FROM bank_import_facts").fetchone()) == facts
        assert ledger.execute("SELECT count(*) FROM bank_import_date_aliases").fetchone()[0] == 2
        assert not ledger.execute("PRAGMA foreign_key_check").fetchall()


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("memo", ["Fixture bank transfer", "Updated bank memo"])
@pytest.mark.parametrize("initial_payment", [True, False])
@pytest.mark.parametrize("display_name", ["ANA  TEST", "Ana Test GmbH"])
def test_unreferenced_credit_learns_provider_reference_from_overlap(sandbox, reverse, memo, initial_payment, display_name):
    import core

    sparse = bank_row(reference_number="INV123", reference_number_schema="SCOR", debtor={"name": "Ana Test"},
                      debtor_account={"iban": "DE00 FIXTURE 0001"},
                      balance_after_transaction={"amount": "119.00", "currency": "EUR"})
    identified = sparse | {"entry_reference": "stable-credit", "remittance_information": [memo],
                           "debtor": {"name": display_name}, "debtor_account": {"iban": "de00fixture0001"}}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    ledger = core.db()
    batch = [identified, sparse, debit] if reverse else [sparse, identified, debit]
    warnings = int(memo != "Fixture bank transfer")
    rows, skipped = transaction_rows("account-a", [sparse, debit] if initial_payment else batch)
    assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
    assert skipped == (0 if initial_payment else warnings)
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    original = [tuple(row) for row in ledger.execute("SELECT id, ref, date, category FROM transactions ORDER BY id")]

    reduced = identified | {"balance_after_transaction": None, "reference_number": None,
                            "remittance_information": ["Reduced bank details"]}
    for page, expected_warnings in ((batch, warnings), ([reduced, debit], 0), ([sparse, debit], 0), (batch[::-1], warnings)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (0, expected_warnings)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert [tuple(row) for row in ledger.execute("SELECT id, ref, date, category FROM transactions ORDER BY id")] == original
    learned = ledger.execute("SELECT provider_ref FROM bank_import_facts WHERE ref = ?", (original[0][1],)).fetchone()[0]
    assert learned == transaction_rows("account-a", [identified])[0][0]["provider_ref"]


@pytest.mark.parametrize("existing_payment", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("counterparty", [
    {"debtor": {"name": "Bert Test"}},
    {"debtor": {"name": "Ana Test"}, "debtor_account": {"iban": "DE00FIXTURE0002"}},
])
def test_shared_invoice_reference_keeps_distinct_counterparties(sandbox, counterparty, reverse, existing_payment):
    import core

    identified = bank_row(entry_reference="first", reference_number="INV123", reference_number_schema="SCOR",
                          debtor={"name": "Ana Test"}, debtor_account={"iban": "DE00FIXTURE0001"},
                          remittance_information=["Part A"])
    sparse = bank_row(reference_number="INV123", reference_number_schema="SCOR", **counterparty,
                      remittance_information=["Part B"])
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    batch = [sparse, identified, debit] if reverse else [identified, sparse, debit]
    ledger = core.db()
    if existing_payment:
        rows, _ = transaction_rows("account-a", [sparse, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")

    for page, count in ((batch, 1 if existing_payment else 3), (batch[::-1], 0), (batch, 0)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
        assert (result["imported"], skipped + result["ambiguous"]) == (count, 0)
        if existing_payment:
            original = core.get_transaction(ledger, 1)
            assert original["description"].endswith("Part B")
            assert original["category"] == "einnahme_sonstige"


@pytest.mark.parametrize("references", [(None, "bert"), ("reused", "reused"), (None, None)])
@pytest.mark.parametrize("split", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
def test_known_payers_keep_distinct_payments_across_sync_batches(sandbox, references, split, reverse):
    import core

    ana = bank_row(entry_reference=references[0], reference_number="INV123", reference_number_schema="SCOR",
                   debtor={"name": "Ana Test"}, debtor_account={"iban": "DE00FIXTURE0001"})
    bert = ana | {"entry_reference": references[1], "debtor": {"name": "Bert Test"},
                  "debtor_account": {"iban": "DE00FIXTURE0002"}}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    first, second = (bert, ana) if reverse else (ana, bert)
    batch = [first, second, debit]
    ledger = core.db()

    def ingest(page, expected_total, warnings=0):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert ledger.execute("SELECT sum(amount) FROM transactions").fetchone()[0] == expected_total
        assert skipped + result["ambiguous"] == warnings
        return result["imported"]

    assert ingest([first, debit] if split else batch, 96 if split else 215) == (2 if split else 3)
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    original = tuple(ledger.execute("SELECT ref, description, category FROM transactions WHERE id = 1").fetchone())
    if split:
        assert ingest([second, debit], 215) == 1
    reduced = first | {"debtor_account": None}
    same_reference = references[0] is not None and references[0] == references[1]
    for page, warnings in (([second, debit], 0), ([first, debit], 0), (batch[::-1], 0),
                           ([second, debit, reduced], int(same_reference)), (batch, 0)):
        assert ingest(page, 215, warnings) == 0
        assert ledger.execute("SELECT count(*) FROM transactions").fetchone()[0] == 3
        assert tuple(ledger.execute("SELECT ref, description, category FROM transactions WHERE id = 1").fetchone()) == original


def test_bank_source_reference_preserves_legacy_occurrence_ids():
    import core

    # Two occurrences of the same source as stored before payer accounts were tracked.
    key = "5e462c8876aa2d6b82cf5c48b51806cce664f9589806553b1f838459dd3ce5bd"
    assert [core.bank_source_reference(key, number) for number in (1, 2)] == [
        "enablebanking:682778baf1f48a6681e0b850388e75c10e95bc890ab866523e2fb7dccf495b24",
        "enablebanking:4a904f2e2152463580f812e4a4403d04114e3fecb119b9618523f38825401ee1",
    ]


def test_occupied_bank_reference_uses_compatible_bank_facts(sandbox):
    import core

    first = bank_row(entry_reference="reused", reference_number="INV123",
                     debtor_account={"iban": "DE00FIXTURE0001"})
    second = first | {"debtor_account": {"iban": "DE00FIXTURE0002"}}
    ledger = core.db()
    rows, _ = transaction_rows("account-a", [first])
    assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 1
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    occupied_ref = rows[0]["ref"]

    for expected in (1, 0):
        rows, _ = transaction_rows("account-a", [second])
        rows[0]["ref"] = occupied_ref
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], result["ambiguous"]) == (expected, 0)
    assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 238)
    assert core.get_transaction(ledger, 1)["category"] == "einnahme_sonstige"


@pytest.mark.parametrize("initial", ["sparse", "referenced", "both"])
@pytest.mark.parametrize("reverse", [True, False])
def test_temporary_id_corroborates_copies_only_inside_one_fetch(sandbox, initial, reverse):
    import core

    sparse = bank_row(transaction_id="fetch-one-credit", debtor={"name": "Fixture Payer"},
                      debtor_account={"iban": "DE00FIXTURE0001"})
    referenced = sparse | {"entry_reference": "credit"}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    batch = [referenced, sparse, debit] if reverse else [sparse, referenced, debit]
    first_page = {"sparse": [sparse, debit], "referenced": [referenced, debit], "both": batch}[initial]
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", first_page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (2, 0)
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone())
        reduced = sparse | {"transaction_id": "next-fetch-credit"}
        for page in (batch, batch[::-1], [reduced, debit], [referenced, debit]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
            assert tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone()) == original


@pytest.mark.parametrize("second_id, other_account, expected", [
    ("one", None, 2), ("two", None, 3), (None, None, 3), ("one", "DE00FIXTURE0002", 3),
])
def test_reference_less_copies_use_temporary_ids_before_assigning_occurrences(sandbox, second_id, other_account, expected):
    import core

    first = bank_row(transaction_id="one" if second_id is not None else None,
                     debtor_account={"iban": "DE00FIXTURE0001"})
    second = first | {"transaction_id": second_id}
    if other_account:
        second["debtor_account"] = {"iban": other_account}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        for page, imported in (([first, second, debit], expected), ([debit, second, first], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (imported, 0)
            total = 96 if expected == 2 else 215
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (expected, total)


@pytest.mark.parametrize("fallback", ["other", "additional-list", "additional-object"])
@pytest.mark.parametrize("split", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
def test_distinct_bban_payers_keep_reused_reference_payments(sandbox, fallback, split, reverse):
    import core

    def payer(identifier):
        data = {"scheme_name": "BBAN", "identification": identifier}
        if fallback == "other":
            return {"debtor_account": {"other": data}}
        return {"debtor_account_additional_identification": [data] if fallback == "additional-list" else data}

    first = bank_row(entry_reference="reused", reference_number="INV123", debtor={"name": "Fixture Payer"},
                     **payer("11111111"))
    second = first | payer("22222222")
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    if reverse:
        first, second = second, first
    batch = [first, second, debit]
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", [first, debit] if split else batch)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (2 if split else 3, 0)
        first_ref = transaction_rows("account-a", [first])[0][0]["ref"]
        first_id = ledger.execute("SELECT id FROM transactions WHERE ref = ?", (first_ref,)).fetchone()[0]
        core.set_tx_category(ledger, first_id, "einnahme_sonstige")
        for page, expected in (([second, debit], int(split)), (batch[::-1], 0), ([first, debit], 0), ([second, debit], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
            assert tuple(ledger.execute("SELECT ref, category FROM transactions WHERE id = ?", (first_id,)).fetchone()) == (
                first_ref, "einnahme_sonstige",
            )


def test_counterparty_iban_enrichment_keeps_prior_alternate_evidence(sandbox):
    import core

    bban = bank_row(entry_reference="reused", reference_number="INV123", debtor={"name": "Fixture Payer"},
                    debtor_account={"other": {"scheme_name": "BBAN", "identification": "11111111"}})
    with_iban = bban | {"debtor_account": {"iban": "DE00FIXTURE0001"}}
    other = bban | {"debtor_account": {"other": {"scheme_name": "BBAN", "identification": "22222222"}}}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        for credit, imported, total in ((bban, 2, 96), (with_iban, 0, 96), (other, 1, 215), (bban, 0, 215)):
            rows, skipped = transaction_rows("account-a", [credit, debit])
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (imported, 0)
            assert ledger.execute("SELECT sum(amount) FROM transactions").fetchone()[0] == total


@pytest.mark.parametrize("initial", ["bare", "enriched", "combined"])
@pytest.mark.parametrize("third_reference", [True, False])
@pytest.mark.parametrize("fields", ["balance", "reference"])
def test_fetch_id_combines_compatible_booking_versions(sandbox, initial, third_reference, fields):
    import core

    bare = bank_row(transaction_id="one-credit", booking_date="2026-11-21",
                    debtor_account={"iban": "DE00FIXTURE0001"})
    balance = {"balance_after_transaction": {"amount": "119", "currency": "EUR"}}
    reference = {"reference_number": "INV123", "reference_number_schema": "SCOR"}
    extra = balance if fields == "balance" else reference
    enriched = bare | extra
    third = bare | {"entry_reference": "stable-credit"} | (reference if fields == "balance" else balance)
    credit_versions = [bare, enriched] + ([third] if third_reference else [])
    debit = bank_row(entry_reference="debit", booking_date="2026-11-21", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    first_page = {"bare": [bare], "enriched": [enriched], "combined": credit_versions}[initial] + [debit]
    batch = credit_versions + [debit]
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", first_page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (2, 0)
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone())
        for page in (batch, batch[::-1], [bare | {"transaction_id": "new-fetch"}, debit], [enriched, debit]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
            assert tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone()) == original
        facts = ledger.execute("SELECT provider_ref, balance_key, creditor_ref FROM bank_import_facts WHERE ref = ?",
                               (original[1],)).fetchone()
        assert tuple(bool(value) for value in facts) == (
            third_reference, third_reference or fields == "balance", third_reference or fields == "reference",
        )


@pytest.mark.parametrize("same_id", [True, False])
def test_fetch_id_keeps_incompatible_and_independent_source_payments(sandbox, same_id):
    import core

    bare = bank_row(transaction_id="one-credit", debtor_account={"iban": "DE00FIXTURE0001"})
    balance = {"amount": "119", "currency": "EUR"}
    enriched = bare | {"balance_after_transaction": balance}
    separate = (enriched | {"balance_after_transaction": balance | {"amount": "238"}} if same_id
                else bare | {"transaction_id": "another-credit"})
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    # A sparse row can be assigned to just one richer version. In the other case the
    # two known movements stay distinct and the sparse version requires review.
    batch = [bare, enriched, separate, debit]
    with closing(core.db()) as ledger:
        for page, expected in ((batch, 3), (batch[::-1], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, int(same_id))
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)


@pytest.mark.parametrize("initial", ["original", "enriched", "both"])
@pytest.mark.parametrize("enrichment", [
    {"balance_after_transaction": {"amount": "119", "currency": "EUR"}},
    {"reference_number": "INV123", "reference_number_schema": "SCOR"},
    {"entry_reference": "stable-credit"},
    {"remittance_information": ["New bank memo"]},
])
def test_fetch_id_and_date_corroborate_sparse_booking_without_payer_or_memo(sandbox, initial, enrichment):
    import core

    original = bank_row(transaction_id="lookup-credit", booking_date="2026-11-21", remittance_information=[])
    enriched = original | enrichment
    debit = bank_row(entry_reference="debit", booking_date="2026-11-21", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    credit_versions = [original, enriched]
    first_page = {"original": [original], "enriched": [enriched], "both": credit_versions}[initial]
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", first_page + [debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original_payment = tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone())
        for credits in (credit_versions, credit_versions[::-1], [original], [enriched], credit_versions):
            page = [credit | {"transaction_id": "later-lookup"} for credit in credits] + [debit]
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert result["imported"] == 0
            if len(credits) == 2:
                assert skipped + result["ambiguous"] == int("remittance_information" in enrichment)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
            assert tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone()) == original_payment


def test_fetch_id_without_corroboration_keeps_disjoint_payments(sandbox):
    import core

    first = bank_row(transaction_id="reused-lookup", booking_date="2026-11-21", remittance_information=[])
    second = first | {"booking_date": None, "value_date": "2026-11-20"}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-21", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        for page, expected in (([first, second, debit], 3), ([debit, second, first], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)


@pytest.mark.parametrize("date_field", ["transaction_date", "value_date"])
@pytest.mark.parametrize("split", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
def test_known_secondary_dates_distinguish_reused_entry_references(sandbox, date_field, split, reverse):
    import core

    shared = bank_row(entry_reference="reused", booking_date="2026-11-22",
                      debtor_account={"iban": "DE00FIXTURE0001"})
    first = shared | {date_field: "2026-11-20", "transaction_id": "one"}
    second = shared | {date_field: "2026-11-21", "transaction_id": "two"}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-22", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    if reverse:
        first, second = second, first
    batch = [first, second, debit]
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", [first, debit] if split else batch)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (2 if split else 3, 0)
        first_ref = transaction_rows("account-a", [first])[0][0]["ref"]
        first_id = ledger.execute("SELECT id FROM transactions WHERE ref = ?", (first_ref,)).fetchone()[0]
        core.set_tx_category(ledger, first_id, "einnahme_sonstige")
        if split:
            rows, _ = transaction_rows("account-a", [second, debit])
            assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
        for page, expected, warnings in ((batch, int(split), 0), (batch[::-1], 0, 0), ([second, debit], 0, 0),
                                         ([first, debit], 0, 0), ([shared, debit], 0, 1)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, warnings)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
            assert tuple(ledger.execute("SELECT ref, category FROM transactions WHERE id = ?", (first_id,)).fetchone()) == (
                first_ref, "einnahme_sonstige",
            )


@pytest.mark.parametrize("evidence, second_is_known", [
    ("description", False), ("balance", False), ("balance", True), ("invoice", False), ("invoice", True),
])
@pytest.mark.parametrize("reverse", [True, False])
def test_coexisting_bookings_keep_identity_with_discriminating_evidence(sandbox, evidence, second_is_known, reverse):
    import core

    shared = bank_row(entry_reference="reused", booking_date="2026-11-22", debtor_account={"iban": "DE00FIXTURE0001"},
                      remittance_information=["Rent"])
    first = shared.copy()
    second = shared | {"transaction_date": "2026-11-21", "transaction_id": "lookup-supplies"}
    if evidence == "description":
        second["remittance_information"] = ["Supplies"]
    else:
        first["transaction_date"] = "2026-11-19"
        if evidence == "balance":
            first["balance_after_transaction"] = {"currency": "EUR", "amount": "119"}
            second["balance_after_transaction"] = {"currency": "EUR", "amount": "238"}
        else:
            first["reference_number"] = "INV119"
            second["reference_number"] = "INV238"
    corrected = first | {"transaction_date": "2026-11-20", "transaction_id": "lookup-rent"}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-22", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [first, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT id, ref, description, category FROM transactions WHERE id = 1").fetchone())
        if second_is_known:
            rows, _ = transaction_rows("account-a", [second, debit])
            assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 1
        batch = [second, corrected, debit] if reverse else [corrected, second, debit]
        for page, expected in ((batch, int(not second_is_known)), (batch[::-1], 0), ([corrected, debit], 0),
                               ([second, debit], 0), (batch, 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], result["ambiguous"] + skipped) == (expected, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
            assert tuple(ledger.execute("SELECT id, ref, description, category FROM transactions WHERE id = 1").fetchone()) == original


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("learned", ["invoice", "balance"])
def test_learned_booking_evidence_outweighs_another_payments_storage_key(sandbox, reverse, learned):
    import core

    rent = bank_row(entry_reference="reused", booking_date="2026-11-23", transaction_date="2026-11-20",
                    debtor_account={"iban": "DE00FIXTURE0001"}, remittance_information=["Rent"])
    corrected = rent | {"transaction_date": "2026-11-19", "transaction_id": "current-rent"}
    if learned == "invoice":
        corrected["reference_number"] = "INV-RENT"
    else:
        corrected["balance_after_transaction"] = {"currency": "EUR", "amount": "119"}
    supplies = rent | {"transaction_id": "current-supplies", "remittance_information": ["Supplies"]}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-23", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"}, remittance_information=["Offset"])
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [rent, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT id, ref FROM transactions WHERE id = 1").fetchone())
        assert transaction_rows("account-a", [supplies])[0][0]["ref"] == original[1]
        rows, skipped = transaction_rows("account-a", [corrected, debit])
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
        assert [tuple(row) for row in ledger.execute("SELECT amount, description, category FROM transactions ORDER BY id")] == [
            (119, "Rent", "einnahme_sonstige"), (-23, "Offset", "offen"),
        ]

        batch = [supplies, corrected, debit] if reverse else [corrected, supplies, debit]
        for page, expected in ((batch, 1), (batch[::-1], 0), ([supplies, debit], 0), ([corrected, debit], 0),
                               ([rent, debit], 0), (batch, 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert [tuple(row) for row in ledger.execute("SELECT amount, description, category FROM transactions ORDER BY id")] == [
                (119, "Rent", "einnahme_sonstige"), (-23, "Offset", "offen"), (119, "Supplies", "offen"),
            ]
            assert tuple(ledger.execute("SELECT id, ref FROM transactions WHERE id = 1").fetchone()) == original


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("direction", ["CRDT", "DBIT"])
@pytest.mark.parametrize("with_sparse_version", [True, False])
@pytest.mark.parametrize("reference_number", ["INV-RENT", None])
def test_same_fetch_financial_evidence_reconciles_acquiring_date_change(
    sandbox, reverse, direction, with_sparse_version, reference_number,
):
    import core

    party_key = "debtor_account" if direction == "CRDT" else "creditor_account"
    first = bank_row(entry_reference="stable", booking_date="2026-11-23", value_date="2026-11-22",
                     transaction_date="2026-11-20", transaction_id="current-rent", credit_debit_indicator=direction,
                     **{party_key: {"iban": "DE00FIXTURE0001"}}, remittance_information=["Rent"],
                     balance_after_transaction={"currency": "EUR", "amount": "119"}, reference_number=reference_number)
    corrected = first | {"transaction_date": "2026-11-21"}
    versions = [first, corrected] + ([first | {"transaction_date": None}] if with_sparse_version else [])
    if reverse:
        versions.reverse()
    opposite = "DBIT" if direction == "CRDT" else "CRDT"
    offset = bank_row(entry_reference="offset", booking_date="2026-11-23", credit_debit_indicator=opposite,
                      transaction_amount={"currency": "EUR", "amount": "23"}, remittance_information=["Offset"])
    sign = 1 if direction == "CRDT" else -1
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", versions + [offset])
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (2, 0)
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT id, ref FROM transactions WHERE id = 1").fetchone())
        for page in ([corrected, offset], [first, offset], versions[::-1] + [offset]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
            assert [tuple(row) for row in ledger.execute("SELECT amount, description, category FROM transactions ORDER BY id")] == [
                (119 * sign, "Rent", "einnahme_sonstige"), (-23 * sign, "Offset", "offen"),
            ]
            assert tuple(ledger.execute("SELECT id, ref FROM transactions WHERE id = 1").fetchone()) == original


def test_fetch_local_invoice_reference_alone_keeps_distinct_known_dates():
    first = bank_row(entry_reference="reused", booking_date="2026-11-23", transaction_date="2026-11-20",
                     debtor_account={"iban": "DE00FIXTURE0001"}, transaction_id="lookup", reference_number="INV123")
    second = first | {"transaction_date": "2026-11-21"}
    for page in ([first, second], [second, first]):
        rows, skipped = transaction_rows("account-a", page)
        assert skipped == 0
        assert len({row["ref"] for row in rows}) == 2
        assert {row["transaction_day"] for row in rows} == {"2026-11-20", "2026-11-21"}


@pytest.mark.parametrize("reverse", [True, False])
def test_first_date_correction_and_new_payment_wait_on_conflicting_historical_evidence(sandbox, reverse):
    import core

    rent = bank_row(entry_reference="reused", booking_date="2026-11-23", transaction_date="2026-11-20",
                    debtor_account={"iban": "DE00FIXTURE0001"}, remittance_information=["Rent"])
    corrected = rent | {"transaction_date": "2026-11-19", "transaction_id": "rent", "reference_number": "INV-RENT"}
    supplies = rent | {"transaction_id": "supplies", "remittance_information": ["Supplies"]}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-23", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"}, remittance_information=["Offset"])
    batch = [supplies, corrected, debit] if reverse else [corrected, supplies, debit]
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [rent, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT id, ref, description, category FROM transactions WHERE id = 1").fetchone())
        for page in (batch, batch[::-1], batch):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 2)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
            assert tuple(ledger.execute("SELECT id, ref, description, category FROM transactions WHERE id = 1").fetchone()) == original
            assert ledger.execute("SELECT creditor_ref FROM bank_import_facts WHERE ref = ?", (original[1],)).fetchone()[0] is None

        rows, _ = transaction_rows("account-a", [corrected, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 0
        for page, expected in ((batch, 1), (batch[::-1], 0), ([corrected, debit], 0), ([supplies, debit], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert [tuple(row) for row in ledger.execute("SELECT amount, description, category FROM transactions ORDER BY id")] == [
                (119, "Rent", "einnahme_sonstige"), (-23, "Offset", "offen"), (119, "Supplies", "offen"),
            ]


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("lookup_ids", [(None, None), ("first", "rotated"), (None, "new")])
def test_independent_lookup_ids_do_not_split_corroborated_dated_copies(sandbox, reverse, lookup_ids):
    import core

    original = bank_row(entry_reference="reused", booking_date="2026-11-23", transaction_date="2026-11-20",
                        transaction_id=lookup_ids[0], debtor_account={"iban": "DE00FIXTURE0001"},
                        balance_after_transaction={"currency": "EUR", "amount": "119"}, reference_number="INV123")
    corrected = original | {"transaction_date": "2026-11-21", "transaction_id": lookup_ids[1]}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-23", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    batch = [corrected, original, debit] if reverse else [original, corrected, debit]
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", batch)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (2, 0)
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        saved = tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone())
        for page in (batch[::-1], [original, debit], [corrected, debit]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
            assert tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone()) == saved


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("evidence", [
    "one-movement", "two-movements", "shared-lookup-and-two-movements", "copy-adds-balance", "posting-dates",
    "early-reversal", "late-reversal", "cycle", "parallel-cycle", "parallel-reused-reference",
    "posting-early-reversal", "posting-late-reversal", "posting-cycle",
    "sparse-reversal", "posting-sparse-reversal", "sparse-reversal-no-entry", "posting-sparse-reversal-no-lookup",
    "sparse-first-day-fee", "posting-sparse-last-day-fee", "posting-complete-and-sparse-last-day-fee",
    "posting-sparse-boundary-fees",
])
def test_intervening_booked_movement_distinguishes_repeated_statement_balances(sandbox, sign, seed, reverse, evidence):
    import core

    direction, opposite = ("CRDT", "DBIT") if sign > 0 else ("DBIT", "CRDT")
    first = bank_row(entry_reference="batch", booking_date="2026-11-23", value_date="2026-11-19",
                     transaction_date="2026-11-19", transaction_id="first", credit_debit_indicator=direction,
                     debtor_account={"iban": "DE00PAYOR"}, creditor_account={"iban": "DE00PAYEE"},
                     reference_number="INV123", remittance_information=["Settlement"],
                     balance_after_transaction={"amount": str(119 * sign), "currency": "EUR"})
    second = first | {"value_date": "2026-11-21", "transaction_date": "2026-11-21", "transaction_id": "second"}
    adjustment = first | {"entry_reference": "reversal", "reference_number": "REV", "transaction_id": "reversal",
                          "value_date": "2026-11-20", "transaction_date": "2026-11-20",
                          "credit_debit_indicator": opposite, "remittance_information": ["Reversal"],
                          "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    offset = adjustment | {"entry_reference": "offset", "transaction_id": "offset", "reference_number": "OFF",
                           "value_date": "2026-11-22", "transaction_date": "2026-11-22",
                           "transaction_amount": {"amount": "23", "currency": "EUR"},
                           "balance_after_transaction": {"amount": str(96 * sign), "currency": "EUR"},
                           "remittance_information": ["Offset"]}
    versions = [first]
    adjustments = [adjustment]
    if evidence == "shared-lookup-and-two-movements":
        second["transaction_id"] = first["transaction_id"]
    if evidence in {"two-movements", "shared-lookup-and-two-movements"}:
        adjustments = [
            adjustment | {"entry_reference": "part-1", "transaction_id": "part-1",
                          "transaction_amount": {"amount": "50", "currency": "EUR"},
                          "balance_after_transaction": {"amount": str(69 * sign), "currency": "EUR"}},
            adjustment | {"entry_reference": "part-2", "transaction_id": "part-2",
                          "transaction_amount": {"amount": "69", "currency": "EUR"}},
        ]
    if evidence == "copy-adds-balance":
        versions = [first | {"balance_after_transaction": None}, first | {"entry_reference": None}]
    trail = evidence.removeprefix("posting-")
    if trail == "sparse-first-day-fee":
        offset.update(value_date="2026-11-19", transaction_date="2026-11-19", balance_after_transaction=None)
    if trail in {"sparse-last-day-fee", "complete-and-sparse-last-day-fee"}:
        offset.update(value_date="2026-11-21", transaction_date="2026-11-21")
        if trail == "sparse-last-day-fee":
            offset["balance_after_transaction"] = None
    offsets = [offset]
    if trail == "sparse-boundary-fees":
        offsets = [
            offset | {"entry_reference": "first-fee", "value_date": "2026-11-19", "transaction_date": "2026-11-19",
                      "transaction_amount": {"amount": "10", "currency": "EUR"}, "balance_after_transaction": None},
            offset | {"entry_reference": "last-fee", "value_date": "2026-11-21", "transaction_date": "2026-11-21",
                      "transaction_amount": {"amount": "13", "currency": "EUR"}, "balance_after_transaction": None},
        ]
    if trail == "early-reversal":
        adjustment.update(value_date="2026-11-19", transaction_date="2026-11-19")
        offset.update(value_date="2026-11-19", transaction_date="2026-11-19",
                      balance_after_transaction={"amount": "0", "currency": "EUR"})
    if trail == "late-reversal":
        adjustment.update(value_date="2026-11-21", transaction_date="2026-11-21")
        offset.update(value_date="2026-11-21", transaction_date="2026-11-21")
    if trail in {"cycle", "parallel-cycle", "parallel-reused-reference"}:
        # First and second share an endpoint. Distinct bank references can have identical edges.
        steps = [(20, 139), (-20, 119), (-119, 0)]
        if trail != "cycle":
            steps = [(20, 139), (-20, 119), (20, 139), (20, 159), (-159, 0)]
        adjustments = [
            adjustment | {"entry_reference": f"step-{index}", "transaction_id": f"step-{index}",
                          "credit_debit_indicator": direction if change > 0 else opposite,
                          "transaction_amount": {"amount": str(abs(change)), "currency": "EUR"},
                          "balance_after_transaction": {"amount": str(balance * sign), "currency": "EUR"}}
            for index, (change, balance) in enumerate(steps)
        ]
        if trail == "parallel-reused-reference":
            for index in (0, 2):
                account = {"iban": f"DE00PART{index}"}
                adjustments[index].update(entry_reference="reused-part", debtor_account=account, creditor_account=account)
    date_field = "transaction_day"
    if evidence.startswith("posting-"):
        date_field = "date"
        shared_dates = {"transaction_date": "2026-11-17", "value_date": "2026-11-18"}
        for row in (first, *adjustments, second, *offsets):
            row["booking_date"] = row["transaction_date"]
        first.update(shared_dates)
        second.update(shared_dates)
    aliases = []
    if trail.startswith("sparse-reversal"):
        alias = adjustment | {"balance_after_transaction": None}
        if trail.endswith("no-entry"):
            alias["entry_reference"] = None
        if trail.endswith("no-lookup"):
            alias["transaction_id"] = None
        aliases.append(alias)
    if trail == "complete-and-sparse-last-day-fee":
        aliases.append(offset | {"balance_after_transaction": None})
    whole = [*versions, *adjustments, *aliases, second, *offsets]
    expected_count = 2 + len(adjustments) + len(offsets)
    if reverse:
        whole.reverse()
    with closing(core.db()) as ledger:
        def sync(page):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert skipped + result["ambiguous"] == 0
            return result["imported"]

        assert sync([first, *adjustments] if seed else whole) == (1 + len(adjustments) if seed else expected_count)
        original = tuple(ledger.execute(
            f"SELECT id, ref FROM transactions JOIN bank_import_facts USING (ref) "
            f"WHERE description = 'Settlement' AND {date_field} = '2026-11-19'",
        ).fetchone())
        core.set_tx_category(ledger, original[0], "einnahme_sonstige")
        for page, expected in ((whole, 1 + len(offsets) if seed else 0), (whole[::-1], 0), ([second, first], 0),
                               ([second, *offsets], 0), ([first, *adjustments], 0), (whole, 0)):
            assert sync(page) == expected
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
                expected_count, 96 * sign,
            )
            assert [tuple(row) for row in ledger.execute(
                f"SELECT {date_field}, category FROM transactions JOIN bank_import_facts USING (ref) "
                f"WHERE description = 'Settlement' ORDER BY {date_field}",
            )] == [("2026-11-19", "einnahme_sonstige"), ("2026-11-21", "offen")]
            assert tuple(ledger.execute("SELECT id, ref FROM transactions WHERE id = ?", (original[0],)).fetchone()) == original


@pytest.mark.parametrize("ending_balance", [None, {"amount": "0", "currency": "USD"}, {"amount": "1", "currency": "EUR"}])
@pytest.mark.parametrize("day", ["2026-11-19", "2026-11-20", "2026-11-21"])
def test_incomplete_statement_balance_chain_does_not_split_a_date_correction(ending_balance, day):
    first = bank_row(entry_reference="batch", booking_date="2026-11-23", transaction_date="2026-11-19",
                     reference_number="INV123", balance_after_transaction={"amount": "119", "currency": "EUR"})
    second = first | {"transaction_date": "2026-11-21"}
    adjustment = bank_row(entry_reference="reversal", booking_date="2026-11-23", transaction_date=day,
                          credit_debit_indicator="DBIT", balance_after_transaction=ending_balance)
    rows, skipped = transaction_rows("account-a", [second, adjustment, first])
    assert skipped == 0
    assert sorted(float(row["amount"]) for row in rows) == [-119, 119]


@pytest.mark.parametrize("identity", [
    {"entry_reference": "other"},
    {"creditor_account": {"iban": "DE00OTHER"}},
    {"entry_reference": None, "reference_number": None},
])
def test_separate_interior_movement_without_balance_keeps_trail_unresolved(identity):
    first = bank_row(entry_reference="batch", booking_date="2026-11-23", transaction_date="2026-11-19",
                     reference_number="INV123", balance_after_transaction={"amount": "119", "currency": "EUR"})
    second = first | {"transaction_date": "2026-11-21"}
    adjustment = second | {"entry_reference": "reversal", "credit_debit_indicator": "DBIT",
                           "transaction_date": "2026-11-20", "creditor_account": {"iban": "DE00REVERSAL"},
                           "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    sparse = adjustment | {"balance_after_transaction": None} | identity
    rows, skipped = transaction_rows("account-a", [second, adjustment, sparse, first])
    assert skipped == 0
    assert sorted(float(row["amount"]) for row in rows) == [-119, -119, 119]


def test_disconnected_same_day_balance_movements_do_not_split_a_date_correction():
    first = bank_row(entry_reference="batch", booking_date="2026-11-23", transaction_date="2026-11-19",
                     reference_number="INV123", balance_after_transaction={"amount": "119", "currency": "EUR"})
    second = first | {"transaction_date": "2026-11-21"}
    adjustment = second | {"entry_reference": "reversal", "credit_debit_indicator": "DBIT",
                           "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    disconnected = [
        second | {"entry_reference": ref, "credit_debit_indicator": direction,
                  "transaction_amount": {"amount": "40", "currency": "EUR"},
                  "balance_after_transaction": {"amount": finish, "currency": "EUR"}}
        for ref, direction, finish in (("up", "CRDT", "240"), ("down", "DBIT", "200"))
    ]
    rows, skipped = transaction_rows("account-a", [second, *disconnected, adjustment, first])
    assert skipped == 0
    assert sorted(float(row["amount"]) for row in rows) == [-119, -40, 40, 119]


@pytest.mark.parametrize("mode", ["initial", "singleton", "overlap"])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("omitted", [(), ("debtor_account",), ("reference_number",),
                                    ("balance_after_transaction",), ("value_date", "transaction_date")])
def test_corroborated_posting_date_conflict_requires_statement_review(sandbox, mode, reverse, omitted):
    import core

    original = bank_row(entry_reference="settlement", booking_date="2026-12-31", value_date="2026-12-29",
                        transaction_date="2026-12-28", transaction_id="old", debtor_account={"iban": "DE00PAYER"},
                        balance_after_transaction={"amount": "119", "currency": "EUR"}, reference_number="INV123",
                        reference_number_schema="SCOR", remittance_information=["Settlement"])
    for field in omitted:
        original.pop(field)
    changed = original | {"booking_date": "2027-01-01", "transaction_id": "current"}
    offset = bank_row(entry_reference="offset", booking_date="2026-12-31", credit_debit_indicator="DBIT",
                      transaction_amount={"amount": "23", "currency": "EUR"}, remittance_information=["Offset"])
    whole = [changed, original, offset] if reverse else [original, changed, offset]
    with closing(core.db()) as ledger:
        if mode != "initial":
            rows, _ = transaction_rows("account-a", [original, offset])
            assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
            saved = tuple(ledger.execute(
                "SELECT id, ref, date FROM transactions WHERE description = 'Settlement'",
            ).fetchone())
            core.set_tx_category(ledger, saved[0], "einnahme_sonstige")
        first_page = [changed, offset] if mode == "singleton" else whole
        for page in (first_page, whole[::-1], whole):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert skipped + result["ambiguous"] > 0
            expected = (1, -23) if mode == "initial" else (2, 96)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == expected
            if mode != "initial":
                assert tuple(ledger.execute(
                    "SELECT id, ref, date, category FROM transactions WHERE description = 'Settlement'",
                ).fetchone()) == (*saved, "einnahme_sonstige")


@pytest.mark.parametrize("different_fact", [
    {"debtor_account": {"iban": "DE00OTHER"}},
    {"reference_number": "INV456"},
    {"balance_after_transaction": {"amount": "238", "currency": "EUR"}},
    {"transaction_date": "2026-12-30"},
])
def test_distinct_bank_facts_allow_reused_entry_reference_on_new_posting_date(sandbox, different_fact):
    import core

    first = bank_row(entry_reference="settlement", booking_date="2026-12-31", value_date="2026-12-29",
                     transaction_date="2026-12-28", debtor_account={"iban": "DE00PAYER"},
                     balance_after_transaction={"amount": "119", "currency": "EUR"}, reference_number="INV123")
    second = first | {"booking_date": "2027-01-01"} | different_fact
    with closing(core.db()) as ledger:
        for page, expected in (([first], 1), ([second], 1), ([second, first], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
        assert [row[0] for row in ledger.execute("SELECT date FROM transactions ORDER BY date")] == ["2026-12-31", "2027-01-01"]


def test_indistinguishable_dated_contenders_leave_old_booking_for_statement_review(sandbox):
    import core

    original = bank_row(entry_reference="reused", booking_date="2026-11-22", debtor_account={"iban": "DE00FIXTURE0001"})
    first = original | {"transaction_date": "2026-11-20", "transaction_id": "lookup-a"}
    second = original | {"transaction_date": "2026-11-21", "transaction_id": "lookup-b"}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-22", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [original, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        for page in ([first, second, debit], [second, debit, first]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], result["ambiguous"] + skipped) == (0, 2)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
            assert core.get_transaction(ledger, 1)["category"] == "einnahme_sonstige"


def test_legacy_reference_learns_secondary_dates_without_replacing_payment(sandbox):
    import core

    original = bank_row(entry_reference="reused", booking_date="2026-11-22",
                        debtor_account={"iban": "DE00FIXTURE0001"})
    first = original | {"transaction_date": "2026-11-20", "value_date": "2026-11-21"}
    second = first | {"transaction_date": "2026-11-21"}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-22", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [original, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        identity = tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone())
        ledger.execute("ALTER TABLE bank_import_facts DROP COLUMN value_day")
        ledger.execute("ALTER TABLE bank_import_facts DROP COLUMN transaction_day")

    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT value_day, transaction_day FROM bank_import_facts WHERE ref = ?",
                                    (identity[1],)).fetchone()) == (None, None)
        for page, expected in (([first, debit], 0), ([first, second, debit], 1), ([second, debit], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
        assert tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone()) == identity
        assert tuple(ledger.execute("SELECT value_day, transaction_day FROM bank_import_facts WHERE ref = ?",
                                    (identity[1],)).fetchone()) == ("2026-11-21", "2026-11-20")


def test_legacy_booking_learns_payer_iban_without_changing_reference(sandbox):
    import core

    old = bank_row(entry_reference="reused", reference_number="INV123", debtor={"name": "Ana Test"})
    ana = old | {"debtor_account": {"iban": "DE00FIXTURE0001"}}
    bert = old | {"debtor_account": {"iban": "DE00FIXTURE0002"}, "debtor": {"name": "Bert Test"}}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [old, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        identity = tuple(ledger.execute("SELECT id, ref, date, description, category FROM transactions WHERE id = 1").fetchone())
        ledger.execute("ALTER TABLE bank_import_facts DROP COLUMN counterparty_iban")

    with closing(core.db()) as ledger:
        assert ledger.execute("SELECT counterparty_iban FROM bank_import_facts WHERE ref = ?", (identity[1],)).fetchone()[0] is None
        for page, expected, total in (([ana, debit], 0, 96), ([bert, debit], 1, 215), ([ana, bert, debit], 0, 215)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert ledger.execute("SELECT sum(amount) FROM transactions").fetchone()[0] == total
            assert tuple(ledger.execute("SELECT id, ref, date, description, category FROM transactions WHERE id = 1").fetchone()) == identity
        payer = ledger.execute("SELECT counterparty_iban FROM bank_import_facts WHERE ref = ?", (identity[1],)).fetchone()[0]
        assert payer == transaction_rows("account-a", [ana])[0][0]["counterparty_iban"]


@pytest.mark.parametrize("late_ana_reference", [None, "ana"])
@pytest.mark.parametrize("historic_account_kind", ["iban", "bban"])
@pytest.mark.parametrize("reverse", [True, False])
def test_legacy_credit_waits_for_identity_when_only_invoice_reference_matches(
    sandbox, late_ana_reference, historic_account_kind, reverse,
):
    import core

    ana = bank_row(reference_number="INV123", reference_number_schema="SCOR", debtor={"name": "Ana Test"},
                   debtor_account={"iban": "DE00FIXTURE0001"})
    bert = ana | {"entry_reference": "bert", "debtor": {"name": "Bert Test"},
                  "debtor_account": {"iban": "DE00FIXTURE0002"}}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    historic_ana = ana if historic_account_kind == "iban" else ana | {
        "debtor_account": {"other": {"identification": "202611210001", "scheme_name": "BBAN"}},
    }
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [historic_ana, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT ref, description, category FROM transactions WHERE id = 1").fetchone())
        ledger.execute("ALTER TABLE bank_import_facts DROP COLUMN counterparty_iban")

    with closing(core.db()) as ledger:
        for page in ([bert, debit], [debit, bert]):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (0, 1)
            assert tuple(ledger.execute("SELECT provider_ref, counterparty_iban FROM bank_import_facts WHERE ref = ?",
                                        (original[0],)).fetchone()) == (None, None)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)

        ana = ana | {"entry_reference": late_ana_reference}
        batch = [bert, ana, debit] if reverse else [ana, bert, debit]
        for page, expected in ((batch, 1), (batch[::-1], 0), ([bert, debit], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
            assert tuple(ledger.execute("SELECT ref, description, category FROM transactions WHERE id = 1").fetchone()) == original
        assert ledger.execute("SELECT counterparty_iban FROM bank_import_facts WHERE ref = ?",
                              (original[0],)).fetchone()[0] == transaction_rows("account-a", [ana])[0][0]["counterparty_iban"]


@pytest.mark.parametrize("legacy", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
def test_prior_description_breaks_tie_on_reused_reference_with_new_payer_evidence(sandbox, legacy, reverse):
    import core

    sparse = bank_row(entry_reference="reused", reference_number="INV123", debtor={"name": "Ana Test"},
                      remittance_information=["Part A"])
    ana = sparse | {"debtor_account": {"iban": "DE00FIXTURE0001"}}
    bert = sparse | {"debtor": {"name": "Bert Test"}, "debtor_account": {"iban": "DE00FIXTURE0002"},
                     "remittance_information": ["Part B"]}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    with closing(core.db()) as ledger:
        rows, _ = transaction_rows("account-a", [sparse, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = tuple(ledger.execute("SELECT ref, description, category FROM transactions WHERE id = 1").fetchone())
        if legacy:
            ledger.execute("ALTER TABLE bank_import_facts DROP COLUMN counterparty_iban")

    batch = [bert, ana, debit] if reverse else [ana, bert, debit]
    with closing(core.db()) as ledger:
        rows, skipped = transaction_rows("account-a", [bert, debit])
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (0, 1)
        assert ledger.execute("SELECT counterparty_iban FROM bank_import_facts WHERE ref = ?",
                              (original[0],)).fetchone()[0] is None
        for page, expected in ((batch, 1), (batch[::-1], 0), ([ana, debit], 0), ([bert, debit], 0)):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
            assert tuple(ledger.execute("SELECT ref, description, category FROM transactions WHERE id = 1").fetchone()) == original
        assert ledger.execute("SELECT counterparty_iban FROM bank_import_facts WHERE ref = ?",
                              (original[0],)).fetchone()[0] == transaction_rows("account-a", [ana])[0][0]["counterparty_iban"]


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("conflicting_copy", [True, False])
def test_same_reference_copies_keep_counterparty_evidence(sandbox, reverse, conflicting_copy):
    import core

    posted = bank_row(entry_reference="first", reference_number="INV123", reference_number_schema="SCOR",
                      debtor={"name": "Zoe Test"}, debtor_account={"iban": "DE00FIXTURE0001"})
    sparse = posted | {"entry_reference": None, "debtor": {"name": "Bert Test"},
                       "debtor_account": {"iban": "DE00FIXTURE0002"}}
    copy = (sparse | {"entry_reference": "first"}) if conflicting_copy else (posted | {"debtor": None, "debtor_account": None})
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    batch = ([copy, posted] if reverse else [posted, copy]) + [sparse, debit]
    ledger = core.db()
    for page, count in ((batch, 3), (batch[::-1], 0)):
        rows, _ = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
        assert (result["imported"], result["ambiguous"]) == (count, 0)


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("original_name", ["Ana Test GmbH", None])
def test_counterparty_name_versions_preserve_payment_without_original_iban(sandbox, reverse, original_name):
    import core

    original = bank_row(reference_number="INV123", reference_number_schema="SCOR",
                        debtor={"name": original_name},
                        balance_after_transaction={"amount": "119.00", "currency": "EUR"})
    identified = original | {"entry_reference": "credit", "debtor_account": {"iban": "DE00FIXTURE0001"},
                             "debtor": {"name": "Ana Test GmbH"}}
    abbreviated = identified | {"debtor": {"name": "Ana Test"}}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    ledger = core.db()
    rows, _ = transaction_rows("account-a", [original, debit])
    assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    payment = tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone())

    batch = [original, identified, abbreviated, debit]
    if reverse:
        batch.reverse()
    for page in (batch, batch[::-1], [abbreviated, debit], [original, debit]):
        rows, _ = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert (result["imported"], result["ambiguous"]) == (0, 0)
        assert tuple(ledger.execute("SELECT id, ref, category FROM transactions WHERE id = 1").fetchone()) == payment


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("sparse_balance", [None, "119.00"])
def test_learned_reference_keeps_two_distinct_provided_payments(sandbox, reverse, sparse_balance):
    import core

    first = bank_row(entry_reference="first", reference_number="INV123", reference_number_schema="SCOR",
                     balance_after_transaction={"amount": "119.00", "currency": "EUR"})
    second = first | {"entry_reference": "second", "balance_after_transaction": {"amount": "238.00", "currency": "EUR"}}
    sparse = first | {"entry_reference": None, "balance_after_transaction": (
        {"amount": sparse_balance, "currency": "EUR"} if sparse_balance else None
    )}
    ledger = core.db()
    batch = [sparse, first, second] if reverse else [second, first, sparse]
    for page, count in ((batch, 2), (batch[::-1], 0)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (count, int(sparse_balance is None))
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 238)
    assert ledger.execute("SELECT count(DISTINCT provider_ref) FROM bank_import_facts").fetchone()[0] == 2


def test_late_reference_does_not_collapse_multiple_unreferenced_payments(sandbox):
    import core

    sparse = bank_row(reference_number="INV123", reference_number_schema="SCOR",
                      balance_after_transaction={"amount": "119.00", "currency": "EUR"})
    identified = sparse | {"entry_reference": "stable-credit"}
    ledger = core.db()
    rows, _ = transaction_rows("account-a", [sparse, sparse])
    assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    original = [tuple(row) for row in ledger.execute("SELECT id, ref, category FROM transactions ORDER BY id")]
    for page in ([sparse, identified, sparse], [identified], [sparse, sparse, identified]):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], skipped + result["ambiguous"]) == (0, 1)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 238)
        assert [tuple(row) for row in ledger.execute("SELECT id, ref, category FROM transactions ORDER BY id")] == original
    assert ledger.execute("SELECT count(provider_ref) FROM bank_import_facts").fetchone()[0] == 0


def test_reference_reused_on_another_booking_date(sandbox):
    import core

    ledger = core.db()
    first = bank_row(entry_reference="monthly", booking_date="2026-11-01")
    second = first | {"booking_date": "2026-11-07"}
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})

    for batch, expected in (([first, debit], 2), ([second, debit, first], 1), ([first, second, debit], 0)):
        rows, skipped = transaction_rows("account-a", batch)
        assert skipped == 0
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == expected
    assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)


def test_daily_overlap_imports_reused_reference_without_a_shared_date(sandbox):
    import core
    from hosted.bank_service import BankingService

    first = bank_row(entry_reference="reused", booking_date=None, value_date="2026-11-01")
    second = first | {"value_date": None, "booking_date": "2026-11-25"}
    debit = bank_row(entry_reference="debit", booking_date="2026-11-24", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})

    class OverlapProvider(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            if path != f"/accounts/{ACCOUNT}/transactions":
                return super().request(method, path, query=query, data=data)
            if query.get("continuation_key") == "debit":
                return {"transactions": [debit]}
            if query.get("date_from"):
                assert query["date_from"] in {"2026-11-10", "2026-11-11"}
                return {"transactions": [second], "continuation_key": "debit"}
            return {"transactions": [first], "continuation_key": "debit"}

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=OverlapProvider)
    service.save_credentials(APP_ID, b"fixture-key")
    state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
    service.finish("login-a", state, "fixture-code", "")
    now = datetime(2026, 11, 24, 12, tzinfo=timezone.utc)
    assert service.sync(now=now) == 2
    ledger = core.db()
    core.set_tx_category(ledger, 1, "einnahme_sonstige")
    assert service.sync(now=now + timedelta(days=1)) == 1
    core.set_tx_category(ledger, 3, "einnahme_sonstige")
    for _ in range(2):
        assert service.sync(now=now + timedelta(days=1), force=True) == 0
        assert service.consents()[0]["skipped"] == 0
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
        assert [tuple(row) for row in ledger.execute("SELECT date, category FROM transactions ORDER BY id")] == [
            ("2026-11-01", "einnahme_sonstige"), ("2026-11-24", "offen"), ("2026-11-25", "einnahme_sonstige"),
        ]


@pytest.mark.parametrize("first_details, second_details", [
    ({}, {"balance_after_transaction": {"amount": "119", "currency": "EUR"}}),
    ({}, {"reference_number": "INV123", "reference_number_schema": "SCOR"}),
    ({"balance_after_transaction": {"amount": "119", "currency": "EUR"}},
     {"reference_number": "INV123", "reference_number_schema": "SCOR"}),
])
@pytest.mark.parametrize("initial_payment", [True, False])
@pytest.mark.parametrize("reverse", [True, False])
def test_dated_reference_batch_collapses_enriched_copy(sandbox, first_details, second_details, initial_payment, reverse):
    import core

    ledger = core.db()
    credit = bank_row(entry_reference="credit")
    first = credit | first_details
    second = credit | second_details
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    if initial_payment:
        rows, _ = transaction_rows("account-a", [first, debit])
        assert core.import_bank_rows(ledger, rows, auto_match=False)["imported"] == 2
        core.set_tx_category(ledger, 1, "einnahme_sonstige")

    batch = [second, first, debit] if reverse else [first, second, debit]
    for page, expected in ((batch, 0 if initial_payment else 2), (batch[::-1], 0), ([first, debit], 0)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert (result["imported"], skipped + result["ambiguous"]) == (expected, 0)
        if initial_payment:
            assert core.get_transaction(ledger, 1)["category"] == "einnahme_sonstige"


@pytest.mark.parametrize("first_details, second_details, sparse_details", [
    ({"balance_after_transaction": {"amount": "119", "currency": "EUR"}},
     {"balance_after_transaction": {"amount": "238", "currency": "EUR"}}, {}),
    ({"reference_number": "INV123", "reference_number_schema": "SCOR"},
     {"reference_number": "INV456", "reference_number_schema": "SCOR"}, {}),
    ({"balance_after_transaction": {"amount": "119", "currency": "EUR"}},
     {"balance_after_transaction": {"amount": "238", "currency": "EUR"}},
     {"reference_number": "INV123", "reference_number_schema": "SCOR"}),
])
@pytest.mark.parametrize("reverse", [True, False])
def test_sparse_copy_does_not_join_conflicting_bookings(sandbox, first_details, second_details, sparse_details, reverse):
    import core

    ledger = core.db()
    credit = bank_row(entry_reference="credit")
    first = credit | first_details
    second = credit | second_details
    sparse = credit | sparse_details
    debit = bank_row(entry_reference="debit", credit_debit_indicator="DBIT",
                     transaction_amount={"currency": "EUR", "amount": "23.00"})
    batch = [second, first, sparse, debit] if reverse else [sparse, first, second, debit]
    for page, expected in ((batch, 3), (batch[::-1], 0), ([sparse, debit], 0)):
        rows, skipped = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)
        assert (result["imported"], skipped + result["ambiguous"]) == (expected, 1)


@pytest.mark.parametrize("reverse", [True, False])
def test_dated_reference_batch_flags_conflicting_memos(sandbox, reverse):
    import core

    ledger = core.db()
    bare = bank_row(entry_reference="credit")
    enriched = bare | {"balance_after_transaction": {"amount": "119", "currency": "EUR"},
                       "remittance_information": ["Another transfer"]}
    batch = [enriched, bare] if reverse else [bare, enriched]
    rows, skipped = transaction_rows("account-a", batch)
    result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
    assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (1, 119)
    assert (result["imported"], skipped + result["ambiguous"]) == (1, 1)


def test_balance_distinguishes_equal_bookings_when_a_memo_arrives(sandbox):
    import core

    ledger = core.db()
    first = bank_row(remittance_information=[], balance_after_transaction={"amount": "119", "currency": "EUR"})
    second = first | {"balance_after_transaction": {"amount": "238", "currency": "EUR"}}
    enriched = first | {"remittance_information": ["Rent"]}
    for batch, expected in (([first], 1), ([second, enriched], 1), ([enriched, second], 0)):
        rows, _ = transaction_rows("account-a", batch)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], result["ambiguous"]) == (expected, 0)
    assert len(core.list_transactions(ledger)) == 2


def test_reconnecting_preserves_account_identity_when_iban_appears(sandbox):
    import core
    from hosted.bank_service import BankingService

    class Reconnected(StubProvider):
        iban = None

        def request(self, method, path, *, query=None, data=None):
            response = super().request(method, path, query=query, data=data)
            if path == "/sessions" and self.iban:
                response["accounts"][1]["account_id"] = {"iban": self.iban}
            return response

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=Reconnected)
    service.save_credentials(APP_ID, b"fixture-key")
    for iban, count in ((None, 2), ("DE00FIXTURE0001", 0), (None, 0)):
        Reconnected.iban = iban
        state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
        service.finish("login-a", state, "fixture-code", "")
        assert service.sync(force=True) == count
        service.disconnect(SESSION)
    ledger = core.db()
    assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)


def test_existing_iban_key_is_retained_after_reauthorization(sandbox):
    from hosted.bank_service import BankingService

    class WithIban(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            response = super().request(method, path, query=query, data=data)
            if path == "/sessions":
                response["accounts"][1]["account_id"] = {"iban": "DE00FIXTURE0001"}
            return response

    from hosted.enable_banking import fingerprint

    callback = SITE + "/api/bank/callback"
    service = BankingService(sandbox, sandbox, callback, client_factory=WithIban)
    service.save_credentials(APP_ID, b"fixture-key")
    def connect():
        state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
        service.finish("login-a", state, "fixture-code", "")
    connect()
    accounts = service.consents()[0]["accounts"]
    accounts[0]["key"] = fingerprint("DE00FIXTURE0001")
    with sqlite3.connect(service.path) as db:
        db.execute("DELETE FROM account_aliases")
        db.execute("UPDATE consents SET accounts = ?", (json.dumps(accounts),))
    assert service.sync(force=True) == 2
    service = BankingService(sandbox, sandbox, callback, client_factory=WithIban)
    connect()
    assert service.consents()[0]["accounts"][0]["key"] == accounts[0]["key"]
    assert service.sync(force=True) == 0


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("history", ["active", "disconnected", "legacy-disconnected", "untyped"])
def test_reconnect_uses_previous_primary_after_account_hash_rotation(sandbox, reverse, history):
    import core
    from hosted.bank_service import BankingService

    previous_hash = ("W1siYWNjb3VudCIsImFjY291bnRfaWQiXV0=.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
                     if history == "legacy-disconnected" else "stable-bank-account")

    class RotatedPrimary(StubProvider):
        rotated = False

        def request(self, method, path, *, query=None, data=None):
            response = super().request(method, path, query=query, data=data)
            if path == "/sessions":
                account = response["accounts"][1]
                account["identification_hash"] = previous_hash
                if self.rotated:
                    hashes = [previous_hash, "not-a-known-primary", "rotated-primary"]
                    account["identification_hash"] = "rotated-primary"
                    account["identification_hashes"] = hashes[::-1] if reverse else hashes
            return response

    callback = SITE + "/api/bank/callback"
    service = BankingService(sandbox, sandbox, callback, client_factory=RotatedPrimary)
    service.save_credentials(APP_ID, b"fixture-key")

    def reconnect():
        state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
        service.finish("login-a", state, "fixture-code", "")
        return service.consents()[0]["accounts"][0]["key"]

    account_key = reconnect()
    assert service.sync(force=True) == 2
    with closing(core.db()) as ledger:
        core.set_tx_category(ledger, 1, "einnahme_sonstige")
        original = [tuple(row) for row in ledger.execute("SELECT id, ref, amount, category FROM transactions ORDER BY id")]
    if history in {"disconnected", "legacy-disconnected"}:
        service.disconnect(SESSION)
    if history in {"legacy-disconnected", "untyped"}:
        with closing(service.connect()) as db, db:
            db.execute("DROP TABLE IF EXISTS primary_account_aliases")
    RotatedPrimary.rotated = True
    service = BankingService(sandbox, sandbox, callback, client_factory=RotatedPrimary)
    if history == "untyped":
        with pytest.raises(BankingError, match="mehrdeutig"):
            reconnect()
        assert service.consents()[0]["accounts"][0]["key"] == account_key
    else:
        assert reconnect() == account_key
    assert service.sync(force=True) == 0
    assert service.sync(force=True) == 0
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert [tuple(row) for row in ledger.execute("SELECT id, ref, amount, category FROM transactions ORDER BY id")] == original


@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("retain_primary", [True, False])
def test_reconnect_does_not_share_one_historical_primary_across_current_accounts(sandbox, reverse, retain_primary):
    import core
    from hosted.bank_service import BankingService

    second_uid = "11841a03-5418-4ec3-9c8a-16c88fcd0fd8"

    class TwoCurrentAccounts(StubProvider):
        reconnecting = False

        def request(self, method, path, *, query=None, data=None):
            if path == "/sessions" and self.reconnecting:
                accounts = [{"uid": uid, "identification_hash": primary, "identification_hashes": ["stable-bank-account"]}
                            for uid, primary in ((ACCOUNT, "stable-bank-account" if retain_primary else "rotated-first"),
                                                 (second_uid, "new-second"))]
                return {"session_id": SESSION, "accounts": accounts[::-1] if reverse else accounts}
            if path == f"/accounts/{second_uid}/transactions":
                return {"transactions": [bank_row(entry_reference="credit")]}
            return super().request(method, path, query=query, data=data)

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=TwoCurrentAccounts)
    service.save_credentials(APP_ID, b"fixture-key")

    def reconnect():
        state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
        service.finish("login-a", state, "fixture-code", "")
        return {account["uid"]: account["key"] for account in service.consents()[0]["accounts"]}

    original_key = reconnect()[ACCOUNT]
    assert service.sync(force=True) == 2
    TwoCurrentAccounts.reconnecting = True
    if retain_primary:
        keys = reconnect()
        assert keys[ACCOUNT] == original_key and keys[second_uid] != original_key
        assert service.sync(force=True) == 1
        expected = (3, 215)
    else:
        with pytest.raises(BankingError, match="mehrdeutig"):
            reconnect()
        assert {account["key"] for account in service.consents()[0]["accounts"]} == {original_key}
        expected = (2, 96)
    assert service.sync(force=True) == 0
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == expected


@pytest.mark.parametrize("entry_ref", ["credit", None])
def test_balance_format_changes_preserve_payment(sandbox, entry_ref):
    import core

    ledger = core.db()
    credit = bank_row(entry_reference=entry_ref)
    for amount, expected in (("238.00", 1), ("238", 0), ("238.0", 0)):
        rows, _ = transaction_rows("account-a", [credit | {
            "balance_after_transaction": {"amount": amount, "currency": "EUR"}
        }])
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], result["ambiguous"]) == (expected, 0)


def test_structured_references_distinguish_equal_payments(sandbox):
    import core

    ledger = core.db()
    first = bank_row(reference_number="INV123", reference_number_schema="SCOR")
    second = first | {"reference_number": "INV456"}
    enriched = first | {"debtor_account": {"iban": "DE00FIXTURE0001"}}
    for page, expected in (([first], 1), ([second, enriched], 1), ([enriched, second], 0)):
        rows, _ = transaction_rows("account-a", page)
        result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
        assert (result["imported"], result["ambiguous"]) == (expected, 0)


@pytest.mark.parametrize("reverse", [True, False])
def test_accounts_with_shared_secondary_hash_keep_separate_payments(sandbox, reverse):
    import core
    from hosted.bank_service import BankingService

    second_uid = "11841a03-5418-4ec3-9c8a-16c88fcd0fd8"

    class TwoAccounts(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            if path == "/sessions":
                accounts = [{"uid": uid, "identification_hash": identifier,
                             "identification_hashes": [identifier, "shared-secondary"]}
                            for uid, identifier in ((ACCOUNT, "first-account"), (second_uid, "second-account"))]
                return {"session_id": SESSION, "accounts": accounts[::-1] if reverse else accounts}
            if path == f"/accounts/{second_uid}/transactions":
                return {"transactions": [bank_row(entry_reference="credit")]}
            return super().request(method, path, query=query, data=data)

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=TwoAccounts)
    service.save_credentials(APP_ID, b"fixture-key")
    state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "personal")).query)["state"][0]
    service.finish("login-a", state, "fixture-code", "")
    assert service.sync(force=True) == 3
    assert service.sync(force=True) == 0
    ledger = core.db()
    assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (3, 215)


def test_ambiguous_overlap_waits_for_bank_details(sandbox):
    import core

    conn = core.db()
    rent = bank_row(remittance_information=["Rent"])
    initial, _ = transaction_rows("account-a", [rent])
    core.import_bank_rows(conn, initial, auto_match=False, require_fx=True)
    core.set_tx_category(conn, 1, "einnahme_sonstige")
    unclear = [bank_row(remittance_information=[memo]) for memo in ("New memo", "Supplies")]
    rows, _ = transaction_rows("account-a", unclear)
    result = core.import_bank_rows(conn, rows, auto_match=False, require_fx=True)
    assert (result["imported"], result["ambiguous"]) == (0, 2)
    assert core.get_transaction(conn, 1)["category"] == "einnahme_sonstige"

    rows, _ = transaction_rows("account-a", [rent, unclear[1]])
    result = core.import_bank_rows(conn, rows, auto_match=False, require_fx=True)
    assert (result["imported"], result["ambiguous"]) == (1, 0)


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
