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
from threading import Barrier, BrokenBarrierError
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


def reported_balance_pair():
    credit = bank_row(booking_date="2026-11-20", transaction_date="2026-11-20", transaction_id="credit",
                      debtor_account={"iban": "DE00PAYER"}, remittance_information=["Fixture receipt"],
                      balance_after_transaction={"amount": "119", "currency": "EUR"})
    debit = bank_row(booking_date="2026-11-21", value_date="2026-11-21", transaction_id="debit",
                     creditor_account={"iban": "DE00PAYEE"}, remittance_information=["Fixture debit"],
                     credit_debit_indicator="DBIT", transaction_amount={"amount": "23", "currency": "EUR"},
                     balance_after_transaction={"amount": "96", "currency": "EUR"})
    return credit, debit


@pytest.mark.parametrize("redact_reference", [False, True])
def test_two_hosted_services_keep_balance_proven_overlap_payments_once(sandbox, monkeypatch, redact_reference):
    import core
    from hosted.bank_service import BankingService

    booked = reported_balance_pair()
    if redact_reference:
        booked = tuple(row | {"entry_reference": row["transaction_id"], "reference_number": "invoice-" + row["transaction_id"]}
                       for row in booked)
    repeated = []

    def overlap_copy(row, lookup):
        copy = row | {"transaction_id": lookup}
        if redact_reference:
            for field in ("entry_reference", "reference_number", "balance_after_transaction"):
                copy.pop(field, None)
        return copy

    class PaginatedBank(StubProvider):
        auth_origin = "https://tilisy.enablebanking.com"

        def request(self, method, path, *, query=None, data=None):
            if method == "GET" and path.endswith("/transactions"):
                assert query["transaction_status"] == "BOOK"
                if query.get("continuation_key"):
                    return {"transactions": repeated}
                return {"transactions": list(booked), "continuation_key": "overlap"}
            return super().request(method, path, query=query, data=data)

    receipts = []
    for index, who in enumerate(("alex", "blake")):
        workspace = sandbox / who
        workspace.mkdir()
        monkeypatch.setattr(core, "DB_PATH", workspace / "bookkeeping.db")
        repeated[:] = [overlap_copy(booked[1], None)] if index else []
        service = BankingService(workspace, workspace, SITE + "/api/bank/callback", client_factory=PaginatedBank)
        service.save_credentials(APP_ID, b"fixture-key")
        begin = service.begin(who, "DE", BANK, "business")
        state = parse_qs(urlsplit(begin).query)["state"][0]
        service.finish(who, state, "fixture-code", "")
        assert service.sync(force=True) == 2
        with closing(core.db()) as ledger:
            payment, debit_id = tuple(row[0] for row in ledger.execute("SELECT id FROM transactions ORDER BY amount DESC"))
            if index == 0:
                core.set_tx_category(ledger, debit_id, "gebuehr")
            receipts.append((core.DB_PATH, payment, debit_id, service))

    for index, (db_path, payment, debit_id, service) in enumerate(receipts):
        monkeypatch.setattr(core, "DB_PATH", db_path)
        repeated[:] = [overlap_copy(booked[0], "renewed"), overlap_copy(booked[1], None)]
        assert service.sync(force=True) == 0
        assert service.consents()[0]["skipped"] == 0
        repeated.clear()
        assert service.sync(force=True) == 0
        with closing(core.db()) as ledger:
            rows = [tuple(row) for row in ledger.execute("SELECT id,amount,category FROM transactions ORDER BY amount DESC")]
            assert rows == [(payment, 119, "offen"), (debit_id, -23, "offen" if index else "gebuehr")]
            assert sum(row[1] for row in rows) == 96
    db_path, payment, _, service = receipts[0]
    monkeypatch.setattr(core, "DB_PATH", db_path)
    credit, debit = booked
    credit = credit | {"value_date": credit["booking_date"]}
    opening = credit | {"booking_date": "2026-11-19", "transaction_date": "2026-11-19", "transaction_id": "opening",
                        "entry_reference": None, "reference_number": None,
                        "remittance_information": ["Opening"], "transaction_amount": {"amount": "10", "currency": "EUR"},
                        "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    booked = (opening, credit, debit)
    assert service.sync(force=True) == 1
    amended = credit | {"value_date": "2026-11-19", "remittance_information": ["Amended bank memo"],
                        "transaction_id": "amended"}
    booked = (opening, amended, debit)
    assert service.sync(force=True) == 0
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (3, 106)
        assert ledger.execute("SELECT id FROM transactions WHERE amount = 119").fetchone()[0] == payment


@pytest.mark.parametrize("change", [
    "lookup", "no lookup", "no payer", "no memo", "sparse fields", "no secondary date", "no booking date", "no booking dates",
])
@pytest.mark.parametrize("credit_copy", [False, True])
@pytest.mark.parametrize("same_day", [False, True])
def test_signed_balance_edge_proves_one_booking_without_optional_references(sandbox, change, credit_copy, same_day):
    import core

    credit, debit = reported_balance_pair()
    if same_day:
        debit["booking_date"] = credit["booking_date"]
    original = credit if credit_copy else debit
    copy = original | {"transaction_id": "renewed"}
    omitted = {"no lookup": ("transaction_id",), "no payer": ("debtor_account", "creditor_account"),
               "no memo": ("remittance_information",), "sparse fields": ("transaction_id", "debtor_account", "creditor_account",
                                                                       "remittance_information"),
               "no secondary date": ("value_date", "transaction_date")}
    for field in omitted.get(change, ()):
        copy.pop(field, None)
    if change in {"no booking date", "no booking dates"}:
        copy.pop("booking_date")
    if change == "no booking dates":
        original.pop("booking_date")
    rows = [credit, debit, copy]
    with closing(core.db()) as ledger:
        for page, expected in ((rows, 2), (rows[::-1], 0), ([credit, debit], 0), ([copy], 0)):
            mapped, warnings = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, mapped, require_fx=True, auto_match=False)
            assert (result["imported"], result["ambiguous"] + warnings) == (expected, 0)
            assert tuple(ledger.execute("SELECT count(*),sum(amount),sum(abs(amount)) FROM transactions").fetchone()) == (2, 96, 142)


@pytest.mark.parametrize("booking_reported", [True, False])
def test_signed_statement_reset_keeps_two_reference_less_equal_movements(sandbox, booking_reported):
    import core

    credit, debit = reported_balance_pair()
    reset = debit | {
        "booking_date": credit["booking_date"], "transaction_id": "reset", "remittance_information": ["Refund"],
        "transaction_amount": {"amount": "119", "currency": "EUR"},
        "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    opening = credit | {
        "booking_date": "2026-11-19", "transaction_date": "2026-11-19", "transaction_id": "opening",
        "remittance_information": ["Opening"], "transaction_amount": {"amount": "10", "currency": "EUR"},
        "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    if not booking_reported:
        credit.pop("booking_date")
    second = credit | {"transaction_id": "current-second"}
    with closing(core.db()) as ledger:
        page = [opening, credit, reset, second, debit]
        for page, expected in ((page, 5), (page[::-1], 0)):
            mapped, _ = transaction_rows("account-a", page)
            assert core.import_bank_rows(ledger, mapped, require_fx=True, auto_match=False)["imported"] == expected
            assert tuple(ledger.execute("SELECT count(*),sum(amount),sum(abs(amount)) FROM transactions").fetchone()) == (5, 106, 390)


@pytest.mark.parametrize("case", [
    "complementary dates", "wrong balance", "unknown opening", "unknown closing",
    "unknown inner balance", "one-step reset", "two-step reset", "repeated witness", "distinct memos", "reused lookup", "sparse receipt",
])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("seed", [False, True])
def test_balance_path_sets_occurrences_independently_of_lookup_ids(sandbox, case, sign, seed):
    import core

    def movement(name, amount, ending, day=20):
        iso = f"2026-11-{day}"
        return bank_row(booking_date=iso, transaction_date=iso, value_date=iso, transaction_id=name,
                        remittance_information=[name], debtor_account={"iban": "DE00PAYER"},
                        creditor_account={"iban": "DE00PAYEE"},
                        credit_debit_indicator="CRDT" if amount * sign > 0 else "DBIT",
                        transaction_amount={"amount": str(abs(amount)), "currency": "EUR"},
                        balance_after_transaction={"amount": str(ending * sign), "currency": "EUR"})

    credit = movement("Receipt", 119, 119)
    copied = credit | {"transaction_id": "renewed"}
    if case == "complementary dates":
        credit.update(booking_date=None, value_date=None)
        copied.update(booking_date=None, transaction_date=None)
        actual = [credit, movement("Fee", -23, 96, 21)]
        total = 96
    elif case in {"wrong balance", "unknown opening", "unknown closing", "unknown inner balance"}:
        actual = [credit, movement("Fee", -23, 96), movement("Settlement", -119, -23)]
        if case != "wrong balance":
            opening = movement("Opening", 10, 0, 19) | {"entry_reference": "opening checkpoint"}
            closing_movement = movement("Closing", -10, -33, 21) | {"entry_reference": "closing checkpoint"}
            missing_balance = {"unknown opening": opening, "unknown closing": closing_movement,
                               "unknown inner balance": actual[1]}
            missing_balance[case]["entry_reference"] = case
            missing_balance[case].pop("balance_after_transaction")
            actual = [opening, *actual, closing_movement]
        total = -23
    elif case == "repeated witness":
        partial = movement("Equal refunds", -50, 69) | {"entry_reference": "partial", "reference_number": "partial"}
        first = movement("First clearing", -69, 0) | {"entry_reference": "first clearing"}
        second = movement("Second clearing", -69, 0) | {"entry_reference": "second clearing"}
        actual = [movement("Opening", 10, 0, 19), credit, partial, first, credit | {"transaction_id": "second receipt"},
                  partial | {"transaction_id": "second refund"}, second, credit | {"transaction_id": "third receipt"},
                  movement("Closing", -23, 96, 21)]
        total = 106
    else:
        opening = movement("Opening", 10, 0, 19)
        reset = ([movement("Refund", -119, 0)] if case in {"one-step reset", "distinct memos", "reused lookup"}
                 else [movement("Partial one", -50, 69), movement("Partial two", -69, 0)])
        second = (movement("Another receipt", 119, 119) if case == "distinct memos"
                  else credit | {"transaction_id": "another booked receipt"})
        if case == "reused lookup":
            second["transaction_id"] = credit["transaction_id"]
        if case == "sparse receipt":
            second["balance_after_transaction"] = None
        actual = [opening, credit, *reset, second, movement("Closing", -23, 96, 21)]
        total = 106
    with closing(core.db()) as ledger:
        repeated_page = [row | {"transaction_id": "renewed-" + row["transaction_id"]} for row in actual]
        pages = ([actual] if seed else []) + [[copied, *actual[::-1]], [*actual, copied], [*actual, *repeated_page], actual]
        if case == "distinct memos":
            pages.insert(int(seed), [*actual, *repeated_page])
        saved = None
        for page in pages:
            rows, warnings = transaction_rows("account-a", page, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False)
            assert result["imported"] == (len(actual) if saved is None else 0)
            assert warnings + result["ambiguous"] == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (len(actual), total * sign)
            if case == "distinct memos":
                assert [row[0] for row in ledger.execute(
                    "SELECT description FROM transactions WHERE amount=? ORDER BY description", (119 * sign,),
                )] == ["Another receipt", "Receipt"]
            paid = [tuple(row) for row in ledger.execute("SELECT id,ref,date FROM transactions WHERE description='Receipt' ORDER BY id")]
            if saved is None:
                saved = paid
                core.set_tx_category(ledger, paid[0][0], "einnahme_sonstige", "Checked")
            else:
                assert paid == saved
                assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (saved[0][0],)).fetchone()) == (
                    "einnahme_sonstige", "Checked",
                )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("opening_balance", [None, 0, 119])
@pytest.mark.parametrize("repeat_first", [False, True])
def test_balance_path_reviews_an_unconfirmed_occurrence_independently_of_pages(sandbox, sign, opening_balance, repeat_first):
    import core

    credit, fee = reported_balance_pair()
    credit = credit | {"booking_date": "2026-11-20", "transaction_date": "2026-11-20", "value_date": "2026-11-20"}
    fee = fee | {"booking_date": "2026-11-21", "transaction_date": "2026-11-21", "value_date": "2026-11-21"}
    opening = credit | {"entry_reference": "opening", "booking_date": "2026-11-19", "remittance_information": ["Opening"],
                        "credit_debit_indicator": "CRDT" if sign > 0 else "DBIT",
                        "transaction_amount": {"amount": "10", "currency": "EUR"}, "balance_after_transaction": None}
    reversal = fee | {"entry_reference": "reversal", "booking_date": "2026-11-20", "remittance_information": ["Reversal"],
                      "transaction_amount": {"amount": "119", "currency": "EUR"},
                      "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    second = credit | {"transaction_id": "second"}
    for row in (credit, reversal, second, fee):
        if sign < 0:
            row["credit_debit_indicator"] = "DBIT" if row["credit_debit_indicator"] == "CRDT" else "CRDT"
            balance = row["balance_after_transaction"]
            row["balance_after_transaction"] = balance | {"amount": str(-int(balance["amount"]))}
    actual = [opening, credit, reversal, second, fee]
    resolved_balance = opening_balance if opening_balance is not None else 119 if repeat_first else 0
    known_opening = opening | {"balance_after_transaction": {"amount": str(resolved_balance * sign), "currency": "EUR"}}
    confirmed_page = [known_opening, *actual[1:]]
    doubled = [*actual, *[row | {"transaction_id": "renewed-" + row["transaction_id"]} for row in actual[::-1]]]
    with closing(core.db()) as ledger:
        def sync(page):
            assessments = []
            rows, skipped = transaction_rows("account-a", page, assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            return result["imported"], skipped + result["ambiguous"]

        def state():
            totals = tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone())
            pending = [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)]
            return totals, pending

        initial = confirmed_page if opening_balance is not None else doubled if repeat_first else actual
        expected = ((5, 106 * sign), []) if opening_balance == 0 else ((4, -13 * sign), [])
        if opening_balance is None:
            expected = ((4, -13 * sign), [("pending", 119 * sign)])
        assert sync(initial)[0] == expected[0][0]
        assert state() == expected
        existing = ledger.execute("SELECT id,ref,date FROM transactions WHERE amount=? ORDER BY id", (119 * sign,)).fetchone()
        core.set_tx_category(ledger, existing[0], "einnahme_sonstige", "Reviewed")
        for page in ([credit | {"transaction_id": "renewed"}, *actual], doubled, actual, [second, fee]):
            assert sync(page)[0] == 0
            assert state() == expected
        if opening_balance is None:
            assert sync(confirmed_page)[0] == int(resolved_balance == 0)
            expected = ((5, 106 * sign), []) if resolved_balance == 0 else ((4, -13 * sign), [])
            for page in (actual, doubled, [second, fee]):
                sync(page)
                assert state() == expected
        assert tuple(ledger.execute(
            "SELECT id,ref,date,category,note FROM transactions WHERE id=?", (existing[0],),
        ).fetchone()) == (*existing, "einnahme_sonstige", "Reviewed")


@pytest.mark.parametrize("boundaries", ["both", "before", "after", "neither"])
def test_closed_balance_path_learns_amended_reference_less_observation(sandbox, boundaries):
    import core

    credit, debit = reported_balance_pair()
    credit["value_date"] = "2026-11-20"
    opening = credit | {"booking_date": "2026-11-19", "value_date": "2026-11-19", "transaction_date": "2026-11-19",
                        "remittance_information": ["Opening"], "transaction_id": "opening",
                        "transaction_amount": {"amount": "10", "currency": "EUR"},
                        "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    amended = credit | {"value_date": "2026-11-19", "remittance_information": ["Amended bank memo"],
                        "transaction_id": "amended"}
    with closing(core.db()) as ledger:
        def sync(items):
            rows, warnings = transaction_rows("account-a", items, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False)
            return result["imported"], warnings + result["ambiguous"]

        assert sync([opening, credit, debit]) == (3, 0)
        old = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE amount=119").fetchone())
        core.set_tx_category(ledger, old[0], "einnahme_sonstige", "Checked")
        page = [amended]
        if boundaries in {"both", "after"}:
            page.insert(0, debit)
        if boundaries in {"both", "before"}:
            page.append(opening)
        assert sync(page) == (0, 1)
        assert sync([amended, credit]) == (0, 1)
        assert sync([amended]) == (0, 1)
        assert sync([debit, amended, opening]) == (0, 1)
        assert sync([opening, credit, debit]) == (0, 0)
        assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE amount=119").fetchone()) == (
            *old, "einnahme_sonstige", "Checked",
        )
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (3, 106)


@pytest.mark.parametrize("position", [0, 1])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("reverse", [False, True])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("referenced", ["neither", "complete", "sparse", "both"])
def test_balance_path_reconciles_a_sparse_page_copy(sandbox, position, seed, reverse, sign, referenced):
    import core

    page = list(reported_balance_pair())
    for row in page:
        if sign < 0:
            row["credit_debit_indicator"] = "DBIT" if row["credit_debit_indicator"] == "CRDT" else "CRDT"
            balance = row["balance_after_transaction"]
            row["balance_after_transaction"] = balance | {"amount": str(-int(balance["amount"]))}
    sparse = page[position] | {"transaction_id": "renewed", "balance_after_transaction": None}
    if referenced in {"complete", "both"}:
        page[position]["entry_reference"] = "bank-ref"
        page[position]["reference_number"] = "creditor-ref"
    if referenced in {"sparse", "both"}:
        sparse["entry_reference"] = "bank-ref"
        sparse["reference_number"] = "creditor-ref"
    overlap = [*page, sparse]
    with closing(core.db()) as ledger:
        def sync(items):
            assessments = []
            rows, warnings = transaction_rows("account-a", items, assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            assert warnings + result["ambiguous"] == 0
            return result["imported"]

        if seed:
            assert sync(page) == 2
        assert sync(overlap[::-1] if reverse else overlap) == (0 if seed else 2)
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (2, 96 * sign)
        saved = [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")]
        core.set_tx_category(ledger, saved[0][0], "einnahme_sonstige", "Checked")
        assert sync([sparse]) == sync(overlap) == sync(page[::-1]) == 0
        assert [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")] == saved
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (saved[0][0],)).fetchone()) == (
            "einnahme_sonstige", "Checked",
        )


@pytest.mark.parametrize("target", [0, -1])
@pytest.mark.parametrize("gaps", [1, 3])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("seed", [False, True])
def test_balance_window_keeps_every_movement_before_the_reported_checkpoint(sandbox, target, gaps, sign, seed):
    import core

    credit, debit = reported_balance_pair()
    debit.update(booking_date=f"2026-11-{21 + gaps}", value_date=f"2026-11-{21 + gaps}")
    middle = [bank_row(booking_date=f"2026-11-{21 + index}", transaction_id=f"mid-{index}", entry_reference=f"mid-{index}",
                       transaction_amount={"amount": str(3 + index), "currency": "EUR"}) for index in range(gaps)]
    total = 96 + sum(range(3, 3 + gaps))
    debit["balance_after_transaction"] = {"amount": str(total), "currency": "EUR"}
    complete = [credit, *middle, debit]
    complete[target]["entry_reference"] = "source"
    sparse = complete[target] | {"entry_reference": None, "transaction_id": "renewed", "balance_after_transaction": None}
    if sign < 0:
        for row in (*complete, sparse):
            row["credit_debit_indicator"] = "DBIT" if row["credit_debit_indicator"] == "CRDT" else "CRDT"
            if balance := row.get("balance_after_transaction"):
                row["balance_after_transaction"] = balance | {"amount": str(-int(balance["amount"]))}
    overlap = [*complete, sparse]
    with closing(core.db()) as ledger:
        def sync(page):
            assessments = []
            rows, skipped = transaction_rows("account-a", page, assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            assert skipped + result["ambiguous"] == 0
            return result["imported"]

        if seed:
            assert sync(complete) == len(complete)
        assert sync(overlap[::-1]) == (0 if seed else len(complete))
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (len(complete), total * sign)
        saved = [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")]
        core.set_tx_category(ledger, saved[0][0], "einnahme_sonstige", "Checked")
        assert sync(overlap) == sync(complete) == sync([sparse]) == 0
        assert not core.pending_bank_statement_amounts(ledger)
        assert [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")] == saved
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (saved[0][0],)).fetchone()) == (
            "einnahme_sonstige", "Checked",
        )


@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("target", [0, 1])
@pytest.mark.parametrize("whole_page", [False, True])
def test_paginated_bank_copy_needs_review_when_the_other_checkpoint_is_missing(sandbox, seed, target, whole_page):
    import core
    from hosted.bank_service import BankingService

    reports = list(reported_balance_pair())
    reports[target]["entry_reference"] = "signed"
    reports[1 - target].pop("balance_after_transaction")
    reports[1 - target]["entry_reference"] = "other-payment"
    candidate = reports[target] | {"entry_reference": None, "transaction_id": "rotated", "balance_after_transaction": None}
    repeated = []
    queries = []

    class PaginatedBank(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            if method == "GET" and path.endswith("/transactions"):
                if query.get("continuation_key"):
                    return {"transactions": list(repeated)}
                queries.append(query)
                return {"transactions": list(reports), "continuation_key": "overlap"}
            return super().request(method, path, query=query, data=data)

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=PaginatedBank)
    service.save_credentials(APP_ID, b"fixture-key")
    state = parse_qs(urlsplit(service.begin("tenant", "DE", BANK, "business")).query)["state"][0]
    service.finish("tenant", state, "fixture-code", "")
    now = datetime.now(timezone.utc)
    if seed:
        assert service.sync(force=True, now=now) == 2
    copies = [reports[target] | {"transaction_id": "repeated-signed"},
              reports[1 - target] | {"transaction_id": "repeated-neighbor"}, candidate | {"transaction_id": "another-copy"}]
    repeated[:] = [candidate, *(copies if whole_page else [])]
    assert service.sync(force=True, now=now + timedelta(days=1)) == (0 if seed else 2)
    if seed:
        assert queries[-1]["date_from"] == (now.date() - timedelta(days=14)).isoformat()
    amount = 119 if target == 0 else -23
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", amount)]
        payment = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE amount=?", (amount,)).fetchone())
        core.set_tx_category(ledger, payment[0], "einnahme_sonstige", "Reviewed")
    assert service.sync(force=True) == 0
    repeated[:] = [candidate, *copies]
    assert service.sync(force=True) == 0
    repeated.clear()
    assert service.sync(force=True) == 0
    with closing(core.db()) as ledger:
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", amount)]
    reports[1 - target]["balance_after_transaction"] = {"amount": "96" if target == 0 else "119", "currency": "EUR"}
    repeated.append(candidate)
    assert service.sync(force=True) == 0
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (2, 96)
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", amount)]
    # The opposite-day balance alone cannot exclude a second copy outside
    # the observed range. Add an actual checkpoint on the open side.
    checkpoint = (_bank_motion("2026-11-19", 10, 0, "Opening", entry_reference="opening") if target == 0
                  else _bank_motion("2026-11-22", -10, 86, "Closing", entry_reference="closing"))
    reports.append(checkpoint)
    assert service.sync(force=True) == 1
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (3, 106 if target == 0 else 86)
        assert not core.pending_bank_statement_amounts(ledger)
        assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE amount=?", (amount,)).fetchone()) == (
            *payment, "einnahme_sonstige", "Reviewed",
        )


@pytest.mark.parametrize("target", [0, 1])
@pytest.mark.parametrize("bookends,repeat_at_resolution", [(False, False), (False, True), (True, False)])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("both_sparse", [False, True])
def test_paginated_copy_of_a_payment_without_any_balance(sandbox, target, bookends, repeat_at_resolution, seed, both_sparse):
    import core

    reports = list(reported_balance_pair())
    subject = reports[target]
    balance = subject.pop("balance_after_transaction")
    subject["entry_reference"] = "bank-entry"
    other = reports[1 - target]
    other["entry_reference"] = "other-entry"
    sparse = subject | {"entry_reference": None, "transaction_id": "rotated"}
    continuation = [sparse]
    if both_sparse:
        other.pop("balance_after_transaction")
        continuation.append(other | {"entry_reference": None, "transaction_id": "other-copy"})
    amount = 119 if target == 0 else -23
    pending = [] if bookends else [("pending", value) for value in ([119, -23] if both_sparse else [amount])]
    opening = bank_row(entry_reference="opening", booking_date="2026-11-19", remittance_information=["Opening"],
                       transaction_amount={"amount": "10", "currency": "EUR"}, balance_after_transaction={"amount": "0", "currency": "EUR"})
    tail = bank_row(entry_reference="tail", booking_date="2026-11-22", remittance_information=["Closing"], credit_debit_indicator="DBIT",
                    transaction_amount={"amount": "10", "currency": "EUR"}, balance_after_transaction={"amount": "86", "currency": "EUR"})
    base = [opening, *reports, tail] if bookends else reports
    pages = [base]

    class PaginatedBank(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            index = int(query.get("continuation_key", "0"))
            result = {"transactions": pages[index]}
            if index + 1 < len(pages):
                result["continuation_key"] = str(index + 1)
            return result

    provider = PaginatedBank(APP_ID, b"fixture-key")
    with closing(core.db()) as ledger:
        def sync():
            assessments = []
            incoming = provider.transactions(ACCOUNT, None, "2026-11-23")
            rows, _ = transaction_rows("account-a", incoming, assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            return result["imported"]

        def state():
            totals = tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone())
            pending = [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)]
            return totals, pending

        if seed:
            assert sync() == len(base)
        pages[:] = [base, continuation, [row | {"transaction_id": "another-" + row["transaction_id"]} for row in continuation]]
        assert sync() == (0 if seed else len(base))
        assert state() == ((len(base), 96), pending)
        original = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE amount=?", (amount,)).fetchone())
        core.set_tx_category(ledger, original[0], "einnahme_sonstige", "Reviewed")
        pages.reverse()
        assert sync() == 0
        pages[:] = [base]
        assert sync() == 0
        assert state() == ((len(base), 96), pending)
        if not bookends:
            if not both_sparse:
                subject["balance_after_transaction"] = balance
            pages[:] = [[opening, *reports, tail], *([continuation] if repeat_at_resolution else [])]
            assert sync() == 2
            assert state() == ((4, 96), [])
        assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE amount=?", (amount,)).fetchone()) == (
            *original, "einnahme_sonstige", "Reviewed",
        )


@pytest.mark.parametrize("separate_on_page", [False, True])
@pytest.mark.parametrize("distinct_reference", [False, True])
def test_paginated_unbalanced_payments_keep_a_proven_second_payment(sandbox, separate_on_page, distinct_reference):
    import core

    first, debit = reported_balance_pair()
    first.pop("balance_after_transaction")
    first["entry_reference"] = "one"
    second = first | {"entry_reference": "two" if distinct_reference else None, "transaction_id": "second"}
    sparse = second | {"entry_reference": None}
    opening = bank_row(entry_reference="opening", booking_date="2026-11-19", transaction_amount={"amount": "10", "currency": "EUR"},
                       balance_after_transaction={"amount": "0", "currency": "EUR"})
    debit["balance_after_transaction"] = {"amount": "215", "currency": "EUR"}
    continuation = sparse if separate_on_page else second
    pages = [[opening, first, *([second] if separate_on_page else []), debit], [continuation | {"transaction_id": "rotated"}]]

    class PaginatedBank(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            if query.get("continuation_key"):
                return {"transactions": list(pages[1])}
            return {"transactions": list(pages[0]), "continuation_key": "more"}

    provider = PaginatedBank(APP_ID, b"fixture-key")
    with closing(core.db()) as ledger:
        for count in (4, 0, 0):
            assessments = []
            rows, _ = transaction_rows("account-a", provider.transactions(ACCOUNT, None, "2026-11-23"),
                                       assessments=assessments, ledger=ledger)
            assert core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)["imported"] == count
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 225)
            assert not core.pending_bank_statement_amounts(ledger)
            pages[1].append(sparse | {"transaction_id": f"another-{len(pages[1])}"})
        if distinct_reference:
            assert ledger.execute(
                "SELECT count(DISTINCT provider_ref) FROM bank_import_facts JOIN transactions USING(ref) WHERE amount=119",
            ).fetchone()[0] == 2


def _bank_page_reports(pages):
    class PaginatedBank(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            index = int(query.get("continuation_key", "0"))
            response = {"transactions": pages[index]}
            if index + 1 < len(pages):
                response["continuation_key"] = str(index + 1)
            return response

    provider = PaginatedBank(APP_ID, b"fixture-key")
    return provider.transactions(ACCOUNT, None, "2026-11-23")


def _sync_bank_pages(ledger, pages):
    import core

    assessments = []
    rows, _ = transaction_rows("account-a", _bank_page_reports(pages), assessments=assessments, ledger=ledger)
    return core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)["imported"]


def _bank_motion(day, amount, balance, label, **fields):
    return bank_row(
        booking_date=day, value_date=day, transaction_date=day,
        credit_debit_indicator="CRDT" if amount > 0 else "DBIT",
        transaction_amount={"amount": str(abs(amount)), "currency": "EUR"},
        balance_after_transaction={"amount": str(balance), "currency": "EUR"} if balance is not None else None,
        transaction_id=label, remittance_information=[label], **fields,
    )


@pytest.mark.parametrize("packet", ["split", "reversed", "single"])
@pytest.mark.parametrize("opening", [False, True])
def test_joint_window_keeps_booked_movements_between_its_checkpoints(sandbox, packet, opening):
    import core

    motions = [
        (18, -119, -129, "First debit"), (19, -23, -152, "Fee A"), (21, -119, -271, "Middle debit"),
        (22, 3, -268, "Receipt"), (23, -23, -291, "Fee B"),
    ]
    reports = [_bank_motion(f"2026-11-{day}", amount, balance, name, entry_reference=name)
               for day, amount, balance, name in motions]
    echoes = [reports[-1] | {"balance_after_transaction": None},
              reports[3] | {"entry_reference": None},
              reports[0] | {"booking_date": None, "balance_after_transaction": None}]
    if opening:
        reports.insert(0, _bank_motion("2026-11-17", 10, -10, "Opening", entry_reference="opening"))
    pages = [[*reports, *echoes]] if packet == "single" else [reports, echoes]
    if packet == "reversed":
        pages.reverse()
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports]) == len(reports)
        payment = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE description='First debit'").fetchone())
        core.set_tx_category(ledger, payment[0], "gebuehr", "Checked")
        for reply in (pages, pages[::-1], [reports]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                len(reports), -271 if opening else -281,
            )
        assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE description='First debit'").fetchone()) == (
            *payment, "gebuehr", "Checked",
        )


@pytest.mark.parametrize("packet", ["split", "reversed", "single"])
@pytest.mark.parametrize("assigned", [False, True])
def test_joint_statement_books_a_proven_extra_with_unknown_purpose(sandbox, packet, assigned):
    import core

    opening = _bank_motion("2026-11-19", 10, 0, "Opening", entry_reference="opening")
    rent = _bank_motion("2026-11-20", 119, 119, "Rent", entry_reference="rent", reference_number="rent-invoice")
    supplies = _bank_motion("2026-11-20", 119, None, "Supplies", entry_reference="supplies", reference_number="supplies-invoice")
    fee = _bank_motion("2026-11-21", -23, 334, "Fee", entry_reference="fee")
    reports = [opening, rent, supplies, fee]
    echoes = [row | {"entry_reference": None, "transaction_id": f"renewed-{index}", "balance_after_transaction": None}
              for index, row in enumerate((rent, supplies))]
    pages = [[*reports, *echoes]] if packet == "single" else [reports, echoes]
    if packet == "reversed":
        pages.reverse()
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, pages) == 5
        review = ledger.execute("SELECT id, ref, date, category FROM transactions WHERE description='Kontoauszug prüfen'").fetchone()
        assert review is not None and tuple(review)[2:] == ("2026-11-20", "offen")
        proof = ledger.execute(
            "SELECT provider_ref, creditor_ref, counterparty_ids FROM bank_import_facts WHERE ref=?", (review["ref"],),
        ).fetchone()
        assert tuple(proof) == (None, None, None)
        rent_id = ledger.execute("SELECT id FROM transactions WHERE description='Rent'").fetchone()[0]
        core.set_tx_category(ledger, rent_id, "einnahme_sonstige", "Rent assigned")
        if assigned:
            core.set_tx_category(ledger, review["id"], "einnahme_sonstige", "Review assigned")
        for reply in (pages[::-1], [reports], pages):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 344)
            assert core.pending_bank_statement_amounts(ledger) == []
        specified = rent | {"entry_reference": "rent-repeat", "transaction_id": "settled-rent",
                            "balance_after_transaction": {"amount": "357", "currency": "EUR"}}
        contradictory = specified | {"balance_after_transaction": {"amount": "500", "currency": "EUR"}}
        assert _sync_bank_pages(ledger, [[opening, rent, supplies, contradictory, fee]]) == 0
        assert ledger.execute("SELECT description FROM transactions WHERE id=?", (review["id"],)).fetchone()[0] == "Kontoauszug prüfen"
        assert ledger.execute("SELECT balance_key FROM bank_import_facts WHERE ref=?", (review["ref"],)).fetchone()[0] is None
        for reply in ([[opening, rent, supplies, specified, fee]], [reports, echoes], [[specified]]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 344)
        settled = ledger.execute("SELECT id,ref,date,description,category,note FROM transactions WHERE id=?", (review["id"],)).fetchone()
        assert tuple(settled) == (
            review["id"], review["ref"], "2026-11-20", "Kontoauszug prüfen" if assigned else "Rent",
            "einnahme_sonstige" if assigned else "offen", "Review assigned" if assigned else None,
        )
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (rent_id,)).fetchone()) == (
            "einnahme_sonstige", "Rent assigned",
        )


def test_joint_statement_counts_an_unplaced_receipt_only_across_its_possible_months(sandbox):
    import core

    opening = _bank_motion("2026-11-29", 10, 0, "Opening", entry_reference="opening")
    rent = _bank_motion("2026-11-30", 119, 119, "Rent", entry_reference="rent", reference_number="rent-invoice")
    supplies = _bank_motion("2026-12-01", 119, None, "Supplies", entry_reference="supplies", reference_number="supplies-invoice")
    fee = _bank_motion("2026-12-02", -23, 334, "Fee", entry_reference="fee")
    reports = [opening, rent, supplies, fee]
    echoes = [row | {"entry_reference": None, "transaction_id": f"renewed-{index}", "balance_after_transaction": None}
              for index, row in enumerate((rent, supplies))]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == 4
        for reply in ([echoes, reports], [reports], [reports, echoes]):
            assert _sync_bank_pages(ledger, reply) == 0
            for start, end, covered in (("2026-11-30", "2026-12-01", 1), ("2026-11-01", "2026-11-30", 0),
                                        ("2026-12-01", "2026-12-31", 0)):
                notices = core.pending_bank_statement_amounts(ledger, start, end)
                assert [(row["state"], row["amount"], row["covered"]) for row in notices] == [("unplaced", 119, covered)]
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 225)
        specified = supplies | {"entry_reference": "supplies-repeat", "transaction_id": "settled-supplies",
                                "balance_after_transaction": {"amount": "357", "currency": "EUR"}}
        assert _sync_bank_pages(ledger, [[opening, rent, supplies, specified, fee]]) == 1
        assert _sync_bank_pages(ledger, [reports, echoes]) == 0
        assert _sync_bank_pages(ledger, [[specified]]) == 0
        assert core.pending_bank_statement_amounts(ledger) == []
        assert [tuple(row) for row in ledger.execute(
            "SELECT substr(date,1,7),count(*),sum(amount) FROM transactions GROUP BY 1 ORDER BY 1",
        )] == [("2026-11", 2, 129), ("2026-12", 3, 215)]


def test_joint_statement_books_the_common_extra_and_keeps_the_remainder_in_review(sandbox):
    import core

    day = "2026-11-20"
    opening = _bank_motion("2026-11-19", 10, 0, "Opening", entry_reference="opening")
    rent = _bank_motion(day, 119, 119, "Rent", entry_reference="rent", reference_number="rent-invoice")
    supplies = _bank_motion(day, 119, None, "Supplies", entry_reference="supplies", reference_number="supplies-invoice")
    fee = _bank_motion(day, -23, 334, "Fee", entry_reference="fee")
    reports = [opening, rent, supplies, fee]
    echoes = [row | {"entry_reference": None, "transaction_id": f"renewed-{index}", "balance_after_transaction": None}
              for index, row in enumerate((rent, supplies))]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == 5
        for reply in ([reports], [echoes, reports]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 344)
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]


def _joint_receipt_count_fixture(*, cross_month=False, close_same_day=False, closing=334):
    day = "2026-11-30" if cross_month else "2026-11-20"
    other_day = "2026-12-01" if cross_month else day
    opening = _bank_motion("2026-11-19", 10, 0, "Opening", entry_reference="opening")
    rent = _bank_motion(day, 119, 119, "Rent", entry_reference="rent", reference_number="rent-invoice")
    supplies = _bank_motion(other_day, 119, None, "Supplies", entry_reference="supplies", reference_number="supplies-invoice")
    fee_day = "2026-12-02" if cross_month else day if close_same_day else "2026-11-21"
    fee = _bank_motion(fee_day, -23, closing, "Fee", entry_reference="fee")
    echoes = [row | {"entry_reference": None, "transaction_id": f"renewed-{index}", "balance_after_transaction": None}
              for index, row in enumerate((rent, supplies))]
    return [opening, rent, supplies, fee], echoes


@pytest.mark.parametrize("assigned", [False, True])
def test_joint_statement_reserves_each_proven_payment(sandbox, assigned):
    import core

    reports, echoes = _joint_receipt_count_fixture(closing=453)
    copies = [*echoes, *(row | {"transaction_id": f"later-{index}"} for index, row in enumerate(echoes))]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, copies]) == 6
        ids = tuple(row[0] for row in ledger.execute("SELECT id FROM transactions WHERE description='Kontoauszug prüfen' ORDER BY id"))
        assert len(ids) == 2
        for reply in ([copies, reports], [reports], [reports, copies]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 463)
            assert tuple(row[0] for row in ledger.execute(
                "SELECT id FROM transactions WHERE description='Kontoauszug prüfen' ORDER BY id",
            )) == ids
        rent = reports[1] | {"entry_reference": "rent-repeat", "balance_after_transaction": {"amount": "357", "currency": "EUR"}}
        supplies = reports[2] | {"entry_reference": "supplies-repeat", "balance_after_transaction": {"amount": "476", "currency": "EUR"}}
        if assigned:
            core.set_tx_category(ledger, ids[0], "einnahme_sonstige", "Do not guess the source")
        assert _sync_bank_pages(ledger, [[*reports[:3], rent, reports[-1]], [echoes[1]]]) == 0
        assert sorted(row[0] for row in ledger.execute("SELECT description FROM transactions WHERE id IN (?, ?)", ids)) == (
            ["Kontoauszug prüfen", "Kontoauszug prüfen"] if assigned else ["Kontoauszug prüfen", "Rent"]
        )
        assert _sync_bank_pages(ledger, [[*reports[:3], rent, supplies, reports[-1]]]) == 0
        assert _sync_bank_pages(ledger, [[supplies], [rent]]) == 0
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 463)
        if assigned:
            assert tuple(ledger.execute("SELECT description,category,note FROM transactions WHERE id=?", (ids[0],)).fetchone()) == (
                "Kontoauszug prüfen", "einnahme_sonstige", "Do not guess the source",
            )
        else:
            assert {row[0] for row in ledger.execute(
                "SELECT description FROM transactions WHERE id IN (?, ?)", ids,
            )} == {"Rent", "Supplies"}


@pytest.mark.parametrize("assigned", [False, True])
def test_joint_statement_preserves_a_reserve_and_imports_a_newly_proven_payment(sandbox, assigned):
    import core

    reports, echoes = _joint_receipt_count_fixture(close_same_day=True)
    rent = reports[1] | {"entry_reference": "rent-repeat", "balance_after_transaction": {"amount": "357", "currency": "EUR"}}
    supplies = reports[2] | {"entry_reference": "supplies-repeat", "balance_after_transaction": {"amount": "453", "currency": "EUR"}}
    settled = [*reports[:3], rent, reports[-1], supplies]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == 5
        slot = ledger.execute("SELECT id,ref FROM transactions WHERE description='Kontoauszug prüfen'").fetchone()
        assert slot is not None
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
        if assigned:
            core.set_tx_category(ledger, slot["id"], "einnahme_sonstige", "Keep this assignment")
        assert _sync_bank_pages(ledger, [settled]) == 1
        for reply in ([settled], [echoes, reports], [reports]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 463)
            assert core.pending_bank_statement_amounts(ledger) == []
        saved = ledger.execute("SELECT ref,description,category,note FROM transactions WHERE id=?", (slot["id"],)).fetchone()
        assert saved["ref"] == slot["ref"]
        if assigned:
            assert tuple(saved)[1:] == ("Kontoauszug prüfen", "einnahme_sonstige", "Keep this assignment")
        else:
            assert sorted(row[0] for row in ledger.execute("SELECT description FROM transactions WHERE amount=119")) == [
                "Rent", "Rent", "Supplies", "Supplies",
            ]


@pytest.mark.parametrize("reported_balance", [False, True])
def test_joint_statement_counts_existing_named_payment_before_reserving_another(sandbox, reported_balance):
    import core

    reports, echoes = _joint_receipt_count_fixture()
    extra = reports[1] | {"entry_reference": "rent-repeat", "balance_after_transaction": {"amount": "357", "currency": "EUR"}}
    if not reported_balance:
        extra["balance_after_transaction"] = None
    named = [*reports[:3], extra, reports[-1]]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [named]) == 5
        existing = ledger.execute("SELECT id FROM transactions WHERE description='Rent' ORDER BY id DESC").fetchone()[0]
        core.set_tx_category(ledger, existing, "einnahme_sonstige", "Named first")
        for reply in ([reports, echoes], [echoes, reports], [named]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 344)
        assert not ledger.execute("SELECT 1 FROM transactions WHERE description='Kontoauszug prüfen'").fetchone()
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (existing,)).fetchone()) == (
            "einnahme_sonstige", "Named first",
        )


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("missing_first", [False, True])
def test_joint_statement_identity_uses_the_known_checkpoint_booking_day(sandbox, cross_month, missing_first):
    import core

    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    first, second = reports[0], reports[0] | {"value_date": "2026-11-18", "transaction_date": "2026-11-17"}
    if missing_first:
        first = first | {"value_date": None, "transaction_date": None}
    before, after = [first, *reports[1:]], [second, *reports[1:]]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [before, echoes]) == (4 if cross_month else 5)
        for reply in ([after, echoes], [echoes, before], [after]):
            assert _sync_bank_pages(ledger, reply) == 0
            expected = (4, 225) if cross_month else (5, 344)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == expected
            assert [(row["state"], row["amount"], row["covered"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119, 1)] if cross_month else []
            )


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("change", ["opening omitted", "opening corrected", "closing omitted", "closing corrected", "running balance", "fee"])
def test_joint_statement_retains_its_slot_when_bank_evidence_changes(sandbox, cross_month, change):
    import core

    reports, copies = _joint_receipt_count_fixture(cross_month=cross_month)
    changed = [row.copy() for row in reports]
    if change == "running balance":
        changed[2]["balance_after_transaction"] = {"amount": "238", "currency": "EUR"}
    elif change == "fee":
        changed.append(_bank_motion(changed[-1]["booking_date"], -20, 314, "New fee", entry_reference="new-fee"))
    else:
        row = changed[0 if change.startswith("opening") else -1]
        row["entry_reference"] = "corrected-checkpoint" if change.endswith("corrected") else None
        row["transaction_id"] = "different-lookup"
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, copies]) == (4 if cross_month else 5)
        if cross_month:
            key = ledger.execute("SELECT review_key FROM bank_statement_assessments WHERE state='unplaced'").fetchone()[0]
        else:
            slot = ledger.execute("SELECT id,ref FROM transactions WHERE description='Kontoauszug prüfen'").fetchone()
            core.set_tx_category(ledger, slot["id"], "einnahme_sonstige", "Keep assigned")
        assert _sync_bank_pages(ledger, [changed, copies]) == int(change == "fee")
        for reply in ([copies, changed], [reports, copies], [changed]):
            assert _sync_bank_pages(ledger, reply) == 0
        count, amount = (4, 225) if cross_month else (5, 344)
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
            count + int(change == "fee"), amount - 20 * int(change == "fee"),
        )
        if cross_month:
            assert [tuple(row) for row in ledger.execute(
                "SELECT review_key,amount FROM bank_statement_assessments WHERE state='unplaced'",
            )] == [(key, 119)]
        else:
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (slot["id"],)).fetchone()) == (
                slot["ref"], "einnahme_sonstige", "Keep assigned",
            )
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("changed", ["subject reference", "opening", "opening with invoice", "combined omissions"])
def test_joint_statement_reuses_proven_payments_on_weaker_reports(sandbox, cross_month, changed):
    import core

    reports, copies = _joint_receipt_count_fixture(cross_month=cross_month)
    if changed == "opening with invoice":
        reports[0]["reference_number"] = "opening-invoice"
    amended = [row.copy() for row in reports]
    if changed in {"subject reference", "combined omissions"}:
        amended[2]["entry_reference"] = "corrected-supplies"
    if changed in {"opening", "opening with invoice", "combined omissions"}:
        amended[0] |= {"entry_reference": None, "balance_after_transaction": None, "transaction_id": "renewed-opening"}
    if changed == "combined omissions":
        amended[1]["balance_after_transaction"] = None

    with closing(core.db()) as ledger:
        total = (4, 225) if cross_month else (5, 344)
        assert _sync_bank_pages(ledger, [reports, copies]) == total[0]
        opening = ledger.execute("SELECT id,ref FROM transactions WHERE description='Opening'").fetchone()
        core.set_tx_category(ledger, opening["id"], "einnahme_sonstige", "Opening checked")
        for reply in ([amended, copies], [copies, amended], [[*amended, *copies]], [reports, copies], [amended]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == total
            assert [(row["state"], row["amount"], row["covered"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119, 1)] if cross_month else []
            )
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (opening["id"],)).fetchone()) == (
                opening["ref"], "einnahme_sonstige", "Opening checked",
            )


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("seeded", [False, True])
@pytest.mark.parametrize("packet", ["split", "reversed", "single"])
def test_joint_statement_bookends_prove_count_with_no_subject_balances(sandbox, cross_month, seeded, packet):
    import core

    reports, copies = _joint_receipt_count_fixture(cross_month=cross_month)
    unsigned = [reports[0], reports[1] | {"balance_after_transaction": None}, *reports[2:]]
    pages = [[*unsigned, *copies]] if packet == "single" else (
        [copies, unsigned] if packet == "reversed" else [unsigned, copies]
    )
    with closing(core.db()) as ledger:
        total = (4, 225) if cross_month else (5, 344)
        if seeded:
            assert _sync_bank_pages(ledger, [reports, copies]) == total[0]
        assert _sync_bank_pages(ledger, pages) == (0 if seeded else total[0])
        for reply in (pages[::-1], [reports, copies], pages):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == total
            assert [(row["state"], row["amount"], row["covered"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119, 1)] if cross_month else []
            )


@pytest.mark.parametrize("change", ["opening value", "opening transaction", "rent typed dates", "opening BOOK", "fee BOOK",
                                    "opening BOOK earlier value", "fee BOOK earlier value"])
@pytest.mark.parametrize("packet", ["split", "single"])
def test_joint_statement_keeps_confirmed_amount_when_bank_omits_dates(sandbox, change, packet):
    import core

    cross_month = "BOOK" in change
    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    checkpoint = 0 if change.startswith("opening") else -1
    if change.endswith("earlier value"):
        end = date.fromisoformat(reports[checkpoint]["booking_date"])
        reports[checkpoint]["value_date"] = (end - timedelta(days=25)).isoformat()
    weaker = [row.copy() for row in reports]
    if change == "rent typed dates":
        weaker[1] |= {"transaction_date": None, "value_date": None}
    elif cross_month:
        weaker[checkpoint]["booking_date"] = None
    else:
        weaker[0] |= {"entry_reference": None, "balance_after_transaction": None,
                      change.rsplit(" ", 1)[-1] + "_date": None}
    with closing(core.db()) as ledger:
        expected = (4, 225) if cross_month else (5, 344)
        assert _sync_bank_pages(ledger, [reports, echoes]) == expected[0]
        opening_id = ledger.execute("SELECT id FROM transactions WHERE description='Opening'").fetchone()[0]
        core.set_tx_category(ledger, opening_id, "einnahme_sonstige", "Checked opening")
        original = [tuple(row) for row in ledger.execute("SELECT id,ref,date,category,note FROM transactions ORDER BY id")]
        pages = [[*weaker, *echoes]] if packet == "single" else [weaker, echoes]
        for reply in (pages, pages[::-1], [weaker], [reports, echoes]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == expected
            assert [tuple(row) for row in ledger.execute("SELECT id,ref,date,category,note FROM transactions ORDER BY id")] == original
            assert [(row["state"], row["amount"], row["covered"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119, 1)] if cross_month else []
            )


@pytest.mark.parametrize("packet", ["split", "single", "reversed"])
@pytest.mark.parametrize("ending_balance", [334, 453])
def test_joint_statement_unsigned_receipts_can_be_proven_before_a_same_day_fee(sandbox, packet, ending_balance):
    import core

    reports, echoes = _joint_receipt_count_fixture(close_same_day=True, closing=ending_balance)
    reports[1]["balance_after_transaction"] = None
    pages = [[*reports, *echoes]] if packet == "single" else ([echoes, reports] if packet == "reversed" else [reports, echoes])
    expected = (5, 344) if ending_balance == 334 else (6, 463)
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, pages) == expected[0]
        for reply in (pages[::-1], pages):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == expected
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("pending", 119)] if ending_balance == 334 else []
            )


@pytest.mark.parametrize("seeded, opening", [(False, "reported"), (True, "reported"), (True, "partial"), (True, "absent")])
def test_joint_statement_later_checkpoints_bound_unsigned_receipts(sandbox, seeded, opening):
    import core

    reports, echoes = _joint_receipt_count_fixture(close_same_day=True)
    reports[1]["balance_after_transaction"] = None
    later = _bank_motion("2026-11-21", -10, 324, "Later checkpoint", entry_reference="later-checkpoint")
    current = [row.copy() for row in reports]
    if opening == "partial":
        for field in ("booking_date", "entry_reference", "balance_after_transaction"):
            del current[0][field]
    elif opening == "absent":
        del current[0]
    full = [[*current, later], echoes]
    with closing(core.db()) as ledger:
        if seeded:
            assert _sync_bank_pages(ledger, [reports, echoes]) == 5
            assert _sync_bank_pages(ledger, [[later]]) == 1
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
        assert _sync_bank_pages(ledger, full) == (0 if seeded else 6)
        for reply in ([reports, echoes], full[::-1], full):
            assert core.pending_bank_statement_amounts(ledger) == []
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 334)
            assert _sync_bank_pages(ledger, reply) == 0
        assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("missing_checkpoint", ["opening", "closing"])
@pytest.mark.parametrize("checkpoint_reference", [False, True])
def test_joint_statement_shortened_reply_keeps_known_movements_and_imports_a_new_fee(
    sandbox, cross_month, missing_checkpoint, checkpoint_reference,
):
    import core

    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    checkpoint = 0 if missing_checkpoint == "opening" else -1
    if not checkpoint_reference:
        del reports[checkpoint]["entry_reference"]
    weaker = [row.copy() for row in reports]
    for field in ("entry_reference", "reference_number", "transaction_date", "value_date"):
        del weaker[1][field]
    del weaker[checkpoint]
    fee = _bank_motion("2026-12-03" if cross_month else "2026-11-22", -20, 314, "New fee", entry_reference="new-fee")
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == (4 if cross_month else 5)
        assert _sync_bank_pages(ledger, [[*weaker, fee], echoes]) == 1
        for reply in ([echoes, [*weaker, fee]], [[*weaker, *echoes, fee]], [[*reports, fee], echoes]):
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                (5, 205) if cross_month else (6, 324)
            )
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119)] if cross_month else []
            )
            assert _sync_bank_pages(ledger, reply) == 0


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("additional_amount", [0, -20, 119])
@pytest.mark.parametrize("detail", ["dated", "partial", "anonymous"])
def test_joint_statement_replay_reconciles_multiple_partial_movements(sandbox, cross_month, additional_amount, detail):
    import core

    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    if detail == "anonymous":
        del reports[0]["entry_reference"]
    weaker = [row.copy() for row in reports]
    for field in ("entry_reference", "balance_after_transaction"):
        del weaker[1][field]
    for field in ("entry_reference", "transaction_date", "value_date"):
        del weaker[2][field]
    if detail != "dated":
        del weaker[1]["booking_date"]
        del weaker[2]["reference_number"]
    if detail == "anonymous":
        for index, fields in enumerate((
            ("booking_date", "remittance_information"),
            ("transaction_date", "remittance_information"),
            ("remittance_information",),
            ("transaction_date", "balance_after_transaction"),
        )):
            for field in fields:
                del weaker[index][field]
    additions = [_bank_motion("2026-12-03" if cross_month else "2026-11-22", additional_amount, 334 + additional_amount,
                              "Separate movement", entry_reference="separate")] if additional_amount else []
    expected = (4, 225) if cross_month else (5, 344)
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == expected[0]
        tx_id = ledger.execute("SELECT id FROM transactions WHERE description='Rent'").fetchone()[0]
        core.set_tx_category(ledger, tx_id, "einnahme_sonstige", "Checked rent")
        old = [tuple(row) for row in ledger.execute("SELECT id,ref,date,category,note FROM transactions ORDER BY id")]
        for delivery, pages in enumerate(([[*weaker, *additions], echoes], [[*echoes, *weaker, *additions]],
                                         [echoes, [*reports, *additions]])):
            assert _sync_bank_pages(ledger, pages) == (len(additions) if delivery == 0 else 0)
            assert [tuple(row) for row in ledger.execute(
                "SELECT id,ref,date,category,note FROM transactions WHERE id <= ? ORDER BY id", (old[-1][0],),
            )] == old
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                expected[0] + len(additions), expected[1] + additional_amount,
            )
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119)] if cross_month else []
            )


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("additional_amount", [None, -20, 119])
@pytest.mark.parametrize("index, omitted", [
    (0, ("booking_date", "entry_reference", "balance_after_transaction")),
    (0, ("booking_date", "transaction_date", "entry_reference", "balance_after_transaction", "remittance_information")),
    (1, ("entry_reference", "transaction_date", "value_date", "reference_number")),
    (1, ("booking_date", "transaction_date", "entry_reference", "reference_number", "remittance_information")),
    (3, ("booking_date", "entry_reference", "balance_after_transaction")),
    (3, ("booking_date", "value_date", "entry_reference", "balance_after_transaction", "remittance_information")),
])
def test_joint_statement_weaker_reports_preserve_booked_and_possible_amounts(sandbox, cross_month, index, omitted, additional_amount):
    import core

    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    weaker = [row.copy() for row in reports]
    for field in omitted:
        del weaker[index][field]
    expected = (4, 225) if cross_month else (5, 344)
    addition = [] if additional_amount is None else [_bank_motion(
        "2026-12-03" if cross_month else "2026-11-22", additional_amount, 344 + additional_amount,
        "New movement", entry_reference="separate",
    )]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == expected[0]
        opening_id = ledger.execute("SELECT id FROM transactions WHERE description='Opening'").fetchone()[0]
        core.set_tx_category(ledger, opening_id, "einnahme_sonstige", "Opening checked")
        before = [tuple(row) for row in ledger.execute("SELECT id,ref,date,category,note FROM transactions ORDER BY id")]
        for delivery, reply in enumerate(([[*weaker, *addition], echoes], [[*weaker, *echoes, *addition]],
                                          [weaker], [echoes, [*reports, *addition]])):
            assert _sync_bank_pages(ledger, reply) == (len(addition) if delivery == 0 else 0)
            assert [tuple(row) for row in ledger.execute(
                "SELECT id,ref,date,category,note FROM transactions WHERE id<=? ORDER BY id", (before[-1][0],),
            )] == before
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                expected[0] + len(addition), expected[1] + (additional_amount or 0),
            )
            assert [(row["state"], row["amount"], row["covered"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("unplaced", 119, 1)] if cross_month else []
            )


@pytest.mark.parametrize("packet", ["single", "split", "reversed"])
@pytest.mark.parametrize("independent_fee", [False, True])
def test_shared_sparse_statement_uses_one_observation_per_proven_witness(sandbox, packet, independent_fee):
    import core

    motions = [(19, 10, 0, "Opening"), (20, 119, 119, "Rent"), (20, 119, 238, "Client"), (22, -23, 215, "Fee")]
    reports = [_bank_motion(f"2026-11-{day}", amount, balance, name, entry_reference=name)
               for day, amount, balance, name in motions]
    echoes = [reports[2] | dict.fromkeys(("entry_reference", "balance_after_transaction", "transaction_id")),
              reports[3] | dict.fromkeys(("booking_date", "transaction_id"))]
    if independent_fee:
        reports.append(_bank_motion("2026-11-22", -23, 192, "Separate fee", entry_reference="separate-fee"))
    pages = [[*reports, *echoes]] if packet == "single" else ([echoes, reports] if packet == "reversed" else [reports, echoes])
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, pages) == len(reports)
        for reply in ([reports], pages[::-1], pages):
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                len(reports), 202 if independent_fee else 225,
            )
            assert core.pending_bank_statement_amounts(ledger) == []
            assert _sync_bank_pages(ledger, reply) == 0
        assert core.pending_bank_statement_amounts(ledger) == []


def test_shared_sparse_statement_resolves_legacy_repeated_witness_notice(sandbox):
    import core

    motions = [(19, 10, 0, "Opening"), (20, 119, 119, "Rent"), (20, 119, 238, "Client"), (22, -23, 215, "Fee")]
    reports = [_bank_motion(f"2026-11-{day}", amount, balance, name, entry_reference=name)
               for day, amount, balance, name in motions]
    echoes = [reports[2] | dict.fromkeys(("entry_reference", "balance_after_transaction", "transaction_id")),
              reports[3] | dict.fromkeys(("booking_date", "transaction_id"))]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == 4
        key, encoded = ledger.execute("SELECT review_key,details FROM bank_statement_assessments WHERE state='confirmed'").fetchone()
        details = json.loads(encoded)
        groups, facts = next((groups, facts) for groups, facts in details["witnesses"]
                             if core._BankBooking(*facts).booked_day == "2026-11-22")
        # This is the earlier format where the same signed fee was stored
        # twice, once without its booking day from the continuation page.
        details["witnesses"].append((groups, core._BankBooking(*facts)._replace(booked_day=None)))
        details["occurrences"] = (2, 3)
        ledger.execute("UPDATE bank_statement_assessments SET state='pending',details=? WHERE review_key=?",
                       (json.dumps(details), key))
        ledger.commit()
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
        for reply in ([reports, echoes], [reports], [echoes, reports]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 225)
            assert core.pending_bank_statement_amounts(ledger) == []


def test_joint_statement_keeps_distinct_episodes_on_the_same_bank_account(sandbox):
    import core

    reports, copies = _joint_receipt_count_fixture()

    def later(row):
        returned = row.copy()
        for field in ("booking_date", "value_date", "transaction_date"):
            returned[field] = (date.fromisoformat(row[field]) + timedelta(days=7)).isoformat()
        for field in ("entry_reference", "reference_number", "transaction_id"):
            if row.get(field):
                returned[field] += "-later"
        if balance := row["balance_after_transaction"]:
            returned["balance_after_transaction"] = balance | {"amount": str(344 + int(balance["amount"]))}
        return returned

    later_reports, later_copies = list(map(later, reports)), list(map(later, copies))
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, copies]) == 5
        assert _sync_bank_pages(ledger, [later_reports, later_copies]) == 5
        assert _sync_bank_pages(ledger, [later_copies, later_reports]) == 0
        assert _sync_bank_pages(ledger, [reports, copies]) == 0
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (10, 688)
        assert ledger.execute("SELECT count(*) FROM transactions WHERE description='Kontoauszug prüfen'").fetchone()[0] == 2


@pytest.mark.parametrize("corrected_opening", [False, True])
def test_joint_statement_clears_possible_overflow_only_after_a_later_checkpoint(sandbox, corrected_opening):
    import core

    reports, echoes = _joint_receipt_count_fixture(close_same_day=True)
    rent = reports[1] | {"entry_reference": "rent-repeat", "balance_after_transaction": {"amount": "357", "currency": "EUR"}}
    resolved = [*reports[:3], rent, reports[-1]]
    closure = _bank_motion("2026-11-21", -10, 324, "Later checkpoint", entry_reference="close-later")
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, echoes]) == 5
        for reply in ([resolved], [[closure]]):
            assert _sync_bank_pages(ledger, reply) == int(reply == [[closure]])
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
        if corrected_opening:
            resolved[0] |= {"entry_reference": "amended-opening"}
        for reply in ([[*resolved, closure]], [reports, echoes], [[*resolved, closure]]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert core.pending_bank_statement_amounts(ledger) == []
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 334)


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("named_first", [False, True])
@pytest.mark.parametrize("assigned", [False, True])
def test_joint_statement_accepts_newly_identified_purpose_for_established_receipt(sandbox, cross_month, named_first, assigned):
    import core

    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    receipt = _bank_motion(reports[2]["booking_date"], 119, 357, "Different transfer",
                           entry_reference="new-bank-ref", reference_number="new-invoice")
    precise = [*reports[:3], receipt, reports[-1]]
    with closing(core.db()) as ledger:
        _sync_bank_pages(ledger, [precise] if named_first else [reports, echoes])
        existing = ledger.execute("SELECT id,ref FROM transactions WHERE description=?", (
            "Different transfer" if named_first else "Kontoauszug prüfen",
        )).fetchone()
        if assigned:
            payment = existing or ledger.execute("SELECT id,ref FROM transactions WHERE description='Rent'").fetchone()
            core.set_tx_category(ledger, payment["id"], "einnahme_sonstige", "Checked")
        for reply in ([precise], [echoes, reports], [[*precise, *echoes]], [precise]):
            _sync_bank_pages(ledger, reply)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 344)
            assert core.pending_bank_statement_amounts(ledger) == []
        if existing:
            row = ledger.execute("SELECT ref,description,category,note FROM transactions WHERE id=?", (existing["id"],)).fetchone()
            assert tuple(row) == (existing["ref"], "Kontoauszug prüfen" if assigned and not named_first else "Different transfer",
                                  "einnahme_sonstige" if assigned else "offen", "Checked" if assigned else None)
        else:
            assert tuple(ledger.execute("SELECT date,amount FROM transactions WHERE description='Different transfer'").fetchone()) == (
                receipt["booking_date"], 119,
            )


@pytest.mark.parametrize("strong_first", [False, True])
@pytest.mark.parametrize("cross_month", [False, True])
def test_earlier_joint_statement_counts_receipts_already_proven_by_a_larger_interval(sandbox, strong_first, cross_month):
    import core

    reports, echoes = _joint_receipt_count_fixture(cross_month=cross_month)
    day = reports[2]["booking_date"]
    receipts = [_bank_motion(day, 119, balance, label, entry_reference=label, reference_number=label)
                for balance, label in ((357, "Different transfer"), (476, "Another transfer"))]
    fee = reports[-1] | {"balance_after_transaction": {"amount": "453", "currency": "EUR"}}
    complete = [*reports[:3], *receipts, fee]
    with closing(core.db()) as ledger:
        _sync_bank_pages(ledger, [complete] if strong_first else [reports, echoes])
        for reply in ([[*complete, *echoes]], [echoes, reports], [complete]):
            _sync_bank_pages(ledger, reply)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 463)
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("strong_first", [False, True])
def test_joint_statement_extends_a_balance_proof_without_reserving_the_same_receipt_twice(sandbox, strong_first):
    import core

    reports, echoes = _joint_receipt_count_fixture(close_same_day=True)
    extra = _bank_motion(reports[-1]["booking_date"], 119, 453, "Separate credit",
                         entry_reference="new-same-day", reference_number="new-invoice")
    old, extended = [reports, echoes], [[*reports, extra], echoes]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, extended if strong_first else old) == (6 if strong_first else 5)
        for reply in (extended, old, extended[::-1], [[*reports, *echoes, extra]]):
            _sync_bank_pages(ledger, reply)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 463)
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
        assert ledger.execute("SELECT count(*) FROM transactions WHERE description='Separate credit'").fetchone()[0] == 1


@pytest.mark.parametrize("sign", [1, -1])
@pytest.mark.parametrize("late_first", [False, True])
@pytest.mark.parametrize("fee_count", [1, 3])
def test_late_bank_posting_explains_a_new_balance_without_duplicating_the_fee(sandbox, sign, late_first, fee_count):
    import core

    def motion(day, amount, balance, label):
        return _bank_motion(f"2026-11-{day}", amount * sign, balance * sign, label, entry_reference=label, reference_number=label)

    opening, rent = motion(19, 10, 0, "Opening"), motion(20, 119, 119, "Rent")
    old = [opening, rent, motion(22, -23, 96, "Fee")]
    precise = [opening, rent, motion(21, 50, 169, "Late movement"),
               *(motion(22, -23, 169 - 23 * step, "Fee") for step in range(1, fee_count + 1))]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [precise if late_first else old]) == (3 + fee_count if late_first else 3)
        existing = ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee' ORDER BY id LIMIT 1").fetchone()
        core.set_tx_category(ledger, existing["id"], "gebuehr", "Checked fee")
        for reply in ([precise[::-1]], [old], [precise[::2], precise[1::2]], [precise]):
            _sync_bank_pages(ledger, reply)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                3 + fee_count, sign * (179 - 23 * fee_count),
            )
            assert core.pending_bank_statement_amounts(ledger) == []
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (existing["id"],)).fetchone()) == (
                existing["ref"], "gebuehr", "Checked fee",
            )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("late_day, late_amount, extra_fee", [(18, 50, 0), (20, 50, 0), (21, 50, 0), (22, 50, 0),
                                                               (22, 23, 0), (22, 23, 1)])
@pytest.mark.parametrize("seed_complete", [False, True])
def test_bank_balance_revision_matches_the_same_fee_in_a_shifted_statement(
    sandbox, sign, late_day, late_amount, extra_fee, seed_complete,
):
    import core

    steps = [(19, 10, "Opening"), (20, 119, "Rent"), (22, -23, "Fee"), (22, -23, "Fee")]

    def statement(include_late):
        entries = [(late_day, late_amount, "Late movement"), *steps, *([(22, -23, "Fee")] * extra_fee)] if include_late else steps
        balance = -10
        reports = []
        for day, amount, name in sorted(entries, key=lambda entry: entry[0]):
            balance += amount
            reports.append(_bank_motion(f"2026-11-{day}", sign * amount, sign * balance, name,
                                        entry_reference=name, reference_number=name))
        return reports

    older, newer = statement(False), statement(True)
    clipped = [report for report in newer if report["booking_date"] >= f"2026-11-{late_day}"]
    with closing(core.db()) as ledger:
        _sync_bank_pages(ledger, [newer if seed_complete else older])
        fees = {row["id"]: row["ref"] for row in ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee'")}
        for fee in fees:
            core.set_tx_category(ledger, fee, "gebuehr", "Checked fee")
        first = [older] if seed_complete else [clipped[1::2], clipped[::2]]
        for pages in (first, [newer], [older[::-1]], [clipped[::-1]], [newer]):
            _sync_bank_pages(ledger, [page for page in pages if page])
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                5 + extra_fee, sign * (83 + late_amount - 23 * extra_fee),
            )
            assert {row["id"]: (row["ref"], row["category"], row["note"]) for row in ledger.execute(
                "SELECT id,ref,category,note FROM transactions WHERE description='Fee' AND category='gebuehr'"
            )} == {ident: (ref, "gebuehr", "Checked fee") for ident, ref in fees.items()}
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("tail_day, tail_balance", [(True, False), (False, False), (False, True)])
def test_bank_balance_revision_preserves_a_short_signed_window_beside_an_unplaced_charge(sandbox, tail_day, tail_balance):
    import core

    def motion(day, amount, balance, label):
        return _bank_motion(f"2026-11-{day}", amount, balance, label, entry_reference=label)

    opening = motion(19, 10, 0, "Opening")
    rent = motion(20, 119, 119, "Rent")
    late = motion(21, 50, 169, "Late movement")
    before, after = motion(22, -23, 96, "Fee"), motion(22, -23, 146, "Fee")
    earlier_tail = motion(25, -3, 93 if tail_balance else None, "Independent charge")
    later_tail = motion(25, -3, 143 if tail_balance else None, "Independent charge")
    if not tail_day:
        del earlier_tail["booking_date"], later_tail["booking_date"]
    with closing(core.db()) as ledger:
        older = [opening, rent, before, earlier_tail]
        _sync_bank_pages(ledger, [older])
        fee = ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee'").fetchone()
        core.set_tx_category(ledger, fee["id"], "gebuehr", "Checked fee")
        for pages in ([[later_tail, after], [late]], [older], [[opening, rent, late, after, later_tail]]):
            _sync_bank_pages(ledger, pages)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 153)
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (fee["id"],)).fetchone()) == (
                fee["ref"], "gebuehr", "Checked fee",
            )
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("complete_first", [False, True])
@pytest.mark.parametrize("day, old_missing, new_missing, clipped, fee_count", [
    (19, (), ("Rent",), True, 1),
    (20, (), ("Late movement",), False, 1),
    (22, (), ("Late movement",), False, 2),
    (19, ("Rent",), ("Rent", "Late movement"), True, 2),
    (18, ("Opening", "Rent"), ("Opening", "Rent"), False, 1),
])
def test_bank_balance_revision_propagates_across_movements_without_balances(
    sandbox, sign, complete_first, day, old_missing, new_missing, clipped, fee_count,
):
    import core

    entries = [(18, 10, "Opening"), (20, 119, "Rent"), *[(22, -23, "Fee")] * fee_count]

    def statement(late=False, omitted=()):
        movements = [*entries, (day, 50, "Late movement")] if late else entries
        # The new movement precedes the earlier reports when it shares their booking day.
        balance = -10
        reports = []
        for booking_day, amount, label in sorted(movements, key=lambda entry: (entry[0], entry[2] != "Late movement")):
            balance += amount
            balance_report = None if label in omitted else balance * sign
            reports.append(_bank_motion(f"2026-11-{booking_day}", amount * sign, balance_report, label,
                                        entry_reference=label, reference_number=label))
        return reports

    previous, sparse, complete = statement(omitted=old_missing), statement(late=True, omitted=new_missing), statement(late=True)
    if clipped:
        sparse = [report for report in sparse if report["booking_date"] >= f"2026-11-{day}"]
    with closing(core.db()) as ledger:
        _sync_bank_pages(ledger, [complete if complete_first else previous])
        assigned = {row["id"]: row["ref"] for row in ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee'")}
        for fee in assigned:
            core.set_tx_category(ledger, fee, "gebuehr", "Checked fee")
        first = [previous[::-1]] if complete_first else [sparse[1::2], sparse[::2]]
        for pages in (first, [sparse[::-1]], [complete], [previous], [complete[::-1]]):
            _sync_bank_pages(ledger, [page for page in pages if page])
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                3 + fee_count, sign * (179 - 23 * fee_count),
            )
            assert {row["id"]: (row["ref"], row["category"], row["note"]) for row in ledger.execute(
                "SELECT id,ref,category,note FROM transactions WHERE description='Fee'"
            )} == {ident: (ref, "gebuehr", "Checked fee") for ident, ref in assigned.items()}
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("initial_balance, affected, legacy", [
    (True, "Fee", False), (True, "Rent", False), (False, "Rent", False), (True, "Fee", True),
])
def test_bank_balance_revision_keeps_the_booking_when_a_later_reply_enriches_it(
    sandbox, sign, initial_balance, affected, legacy,
):
    import core

    def report(day, amount, balance, label):
        return _bank_motion(f"2026-11-{day}", sign * amount, None if balance is None else sign * balance,
                            label, entry_reference=label, reference_number=label)

    opening = report(18, 10, 0, "Opening")
    prior_rent = report(20, 119, 119 if initial_balance else None, "Rent")
    prior_fee = report(22, -23, 96, "Fee")
    late = report(19 if affected == "Rent" else 21, 50, 50 if affected == "Rent" else 169, "Late movement")
    rent = report(20, 119, 169 if affected == "Rent" else 119, "Rent")
    fee = report(22, -23, 146, "Fee")
    prior, complete = [opening, prior_rent, prior_fee], [opening, late, rent, fee]
    sparse = [row | {"balance_after_transaction": None} if row["entry_reference"] == affected else row for row in complete]

    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [prior]) == 3
        original = ledger.execute("SELECT id,ref FROM transactions WHERE description=?", (affected,)).fetchone()
        core.set_tx_category(ledger, original["id"], "gebuehr" if affected == "Fee" else "einnahme_sonstige", "Assigned")
        assert _sync_bank_pages(ledger, [sparse[1::2], sparse[::2]]) == 1
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 156 * sign)
        if legacy:
            # Older versions booked the late movement without remembering
            # the changed balance implied for the already categorized fee.
            ledger.execute("DELETE FROM bank_import_date_aliases WHERE ref=? AND booking_group LIKE ?",
                           (original["ref"], core._bank_balance_revision_key(original["ref"], "%")))
            ledger.commit()
        for pages in ([complete[::-1]], [sparse], [prior], [complete]):
            assert _sync_bank_pages(ledger, pages) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 156 * sign)
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (original["id"],)).fetchone()) == (
                original["ref"], "gebuehr" if affected == "Fee" else "einnahme_sonstige", "Assigned",
            )
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("fee_count", [2, 3])
@pytest.mark.parametrize("strong_first", [False, True])
@pytest.mark.parametrize("old_anchors", [False, True])
def test_bank_balance_revision_preserves_each_proven_fee_after_an_unsigned_booking(sandbox, sign, fee_count, strong_first, old_anchors):
    import core

    opening = _bank_motion("2026-11-18", 10 * sign, 0, "Opening", entry_reference="opening")
    rent = _bank_motion("2026-11-20", 119 * sign, 119 * sign, "Rent", entry_reference="rent")
    unsigned = _bank_motion("2026-11-22", -23 * sign, None, "Fee", entry_reference="fee", reference_number="fees")
    fees = [unsigned | {"transaction_id": f"fee-current-{index}", "balance_after_transaction": {
        "amount": str(sign * (119 - 23 * index)), "currency": "EUR",
    }} for index in range(1, fee_count + 1)]
    sparse, complete = [opening, rent, unsigned], [opening, rent, *fees]
    if not old_anchors:
        sparse = [row | {"balance_after_transaction": None} for row in sparse]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [complete if strong_first else sparse]) == (2 + fee_count if strong_first else 3)
        original = ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee' ORDER BY id LIMIT 1").fetchone()
        core.set_tx_category(ledger, original["id"], "gebuehr", "Assigned")
        assert _sync_bank_pages(ledger, [complete[::-1][::2], complete[::-1][1::2]]) == (0 if strong_first else fee_count - 1)
        for pages in ([sparse], [complete], [complete[::-1]], [sparse]):
            assert _sync_bank_pages(ledger, pages) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                2 + fee_count, sign * (129 - 23 * fee_count),
            )
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (original["id"],)).fetchone()) == (
                original["ref"], "gebuehr", "Assigned",
            )
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
def test_booked_fees_reduce_the_previous_possible_occurrence_count(sandbox, sign):
    import core

    opening = _bank_motion("2026-11-18", 10 * sign, 0, "Opening", entry_reference="opening")
    rent = _bank_motion("2026-11-20", 119 * sign, 119 * sign, "Rent", entry_reference="rent")
    late = _bank_motion("2026-11-22", 50 * sign, 169 * sign, "Late credit", entry_reference="late")
    fee = _bank_motion("2026-11-22", -23 * sign, None, "Fee", entry_reference="fees", reference_number="fees")
    prior = fee | {"balance_after_transaction": {"amount": str(96 * sign), "currency": "EUR"}}
    sparse = [fee | {"transaction_id": f"sparse-{index}"} for index in range(3)]
    complete = [report | {"balance_after_transaction": {"amount": str((169 - 23 * index) * sign), "currency": "EUR"}}
                for index, report in enumerate(sparse, start=1)]

    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [[opening, rent, prior]]) == 3
        original = ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee'").fetchone()
        core.set_tx_category(ledger, original["id"], "gebuehr", "Assigned")
        assert _sync_bank_pages(ledger, [[opening, rent, late, *sparse]]) == 1
        # Replaying the original ambiguity cannot undo booked fees.
        for reports, count, missing in ((complete[:2], 2, 1), (complete, 3, 0), (sparse, 3, 0), (complete[::-1], 3, 0)):
            _sync_bank_pages(ledger, [[opening, rent, late, *reports]])
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                3 + count, sign * (179 - 23 * count),
            )
            assert [row["amount"] for row in core.pending_bank_statement_amounts(ledger)] == ([-23 * sign * missing] if missing else [])
            assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (original["id"],)).fetchone()) == (
                original["ref"], "gebuehr", "Assigned",
            )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("old_balance", [False, True])
def test_distinct_fee_description_disambiguates_reused_running_balance(sandbox, sign, old_balance):
    import core
    from decimal import Decimal

    opening = _bank_motion("2026-11-18", 10 * sign, 0, "Opening", entry_reference="opening")
    rent = _bank_motion("2026-11-20", 119 * sign, 119 * sign, "Rent", entry_reference="rent")
    first_service = _bank_motion("2026-11-22", -23 * sign, 96 * sign if old_balance else None, "Service fee",
                                 entry_reference="same-fee", reference_number="common")
    card = _bank_motion("2026-11-22", -23 * sign, 96 * sign, "Card replacement",
                        entry_reference="same-fee", reference_number="common")
    service = first_service | {"transaction_id": "new-service", "balance_after_transaction": {
        "amount": str(73 * sign), "currency": "EUR",
    }}
    earlier, complete = [opening, rent, first_service], [opening, rent, card, service]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [earlier]) == 3
        original = ledger.execute("SELECT id,ref FROM transactions WHERE description='Service fee'").fetchone()
        core.set_tx_category(ledger, original["id"], "gebuehr", "Assigned service")
        for pages, imported in (([complete[1::2], complete[::2]], 1), ([earlier], 0), ([complete[::-1]], 0)):
            assert _sync_bank_pages(ledger, pages) == imported
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 83 * sign)
            assert tuple(ledger.execute("SELECT ref,description,category,note FROM transactions WHERE id=?", (original["id"],)).fetchone()) == (
                original["ref"], "Service fee", "gebuehr", "Assigned service",
            )
            card_details = ledger.execute("SELECT balance_key FROM transactions JOIN bank_import_facts USING (ref) "
                                          "WHERE description='Card replacement'").fetchone()
            assert card_details and card_details["balance_key"] == core._bank_balance_hash("EUR", Decimal(96 * sign))
            revised = core._bank_balance_revision_key(original["ref"], core._bank_balance_hash("EUR", Decimal(73 * sign)))
            assert ledger.execute("SELECT 1 FROM bank_import_date_aliases WHERE ref=? AND booking_group=?",
                                  (original["ref"], revised)).fetchone()
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("extra", [False, True])
def test_repeated_booked_fees_survive_a_clipped_reply_without_checkpoints(sandbox, sign, extra):
    import core

    opening = _bank_motion("2026-11-18", 10 * sign, 0, "Opening", entry_reference="opening")
    rent = _bank_motion("2026-11-20", 119 * sign, 119 * sign, "Rent", entry_reference="rent")
    late = _bank_motion("2026-11-21", 50 * sign, 169 * sign, "Late credit", entry_reference="late")

    def fees(count, balance):
        return [_bank_motion("2026-11-22", -23 * sign, (balance - 23 * index) * sign, "Fee", entry_reference="same-fee",
                             reference_number="common") | {"transaction_id": f"fee-report-{index}"}
                for index in range(1, count + 1)]

    earlier = [opening, rent, *fees(2, 119)]
    revised_fees = fees(2 + extra, 169)
    sparse = [row | {"balance_after_transaction": None} for row in revised_fees]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [earlier]) == 4
        original = {row["id"]: row["ref"] for row in ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee'")}
        for ident in original:
            core.set_tx_category(ledger, ident, "gebuehr", f"Assigned fee {ident}")
        assert _sync_bank_pages(ledger, [[late, *sparse]]) == 1
        for pages, imported in (([[late, revised_fees[0]], revised_fees[1:]], int(extra)),
                                ([[opening, rent, late, *revised_fees]], 0), ([earlier], 0),
                                ([[late, *sparse]], 0), ([[late, *revised_fees[::-1]]], 0)):
            assert _sync_bank_pages(ledger, pages) == imported
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                5 + extra, (133 - 23 * extra) * sign,
            )
            retained = {row["id"]: (row["ref"], row["note"]) for row in ledger.execute(
                "SELECT id,ref,note FROM transactions WHERE description='Fee' AND category='gebuehr'",
            )}
            assert retained == {ident: (ref, f"Assigned fee {ident}") for ident, ref in original.items()}
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("leading_count, newer_fee", [(0, True), (124, False), (151, True)])
def test_repeated_fees_recover_only_the_earlier_part_of_the_statement(sandbox, sign, leading_count, newer_fee):
    import core

    def movement(day, amount, balance, label, reference):
        return _bank_motion(f"2026-11-{day:02d}", sign * amount, None if balance is None else sign * balance,
                            label, entry_reference=reference) | {"transaction_id": label}

    opening = movement(1, 10, 0, "Opening", "opening")
    unrelated = [movement(1 + index // 12, 1, index + 1, f"Earlier {index}", f"earlier-{index}")
                 for index in range(leading_count)]
    rent_balance = leading_count + 119
    rent = movement(20, 119, rent_balance, "Rent", "rent")
    late = movement(21, 50, rent_balance + 50, "Late credit", "late")
    names = ("Service", "ATM", "Card") if newer_fee else ("Fee", "Fee")
    old_fees = [movement(22, -23, rent_balance - 23 * index, label, "shared-fee") | {"transaction_id": f"old-fee-{index}"}
                for index, label in enumerate(names[:2], start=1)]
    fresh_fees = [movement(22, -23, rent_balance + 50 - 23 * index, label, "shared-fee") | {"transaction_id": f"fresh-fee-{index}"}
                  for index, label in enumerate(names, start=1)]
    sparse = [row | {"balance_after_transaction": None} for row in fresh_fees[:2]] + fresh_fees[2:]
    initial, complete = [opening, *unrelated, rent, *old_fees], [opening, *unrelated, rent, late, *fresh_fees]
    intermediate = [rent, late, *sparse] if not leading_count else [opening, *unrelated, rent, late, *sparse]

    def sync(ledger, rows):
        return _sync_bank_pages(ledger, [rows[index:index + 30] for index in range(0, len(rows), 30)])

    with closing(core.db()) as ledger:
        assert sync(ledger, initial) == leading_count + 4
        booked = {row["id"]: (row["ref"], row["description"]) for row in ledger.execute(
            "SELECT id,ref,description FROM transactions WHERE amount=?", (-23 * sign,),
        )}
        for ident in booked:
            core.set_tx_category(ledger, ident, "gebuehr", f"Assigned fee {ident}")
        assert sync(ledger, intermediate) == 1 + newer_fee
        for reply in (complete, initial, complete[::-1], intermediate, complete):
            assert sync(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                leading_count + 5 + newer_fee, (leading_count + 133 - 23 * newer_fee) * sign,
            )
            assert {row["id"]: (row["ref"], row["description"], row["note"]) for row in ledger.execute(
                "SELECT id,ref,description,note FROM transactions WHERE category='gebuehr'",
            )} == {ident: (*saved, f"Assigned fee {ident}") for ident, saved in booked.items()}
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sale_day, new_sales", [(21, True), (22, False), (23, False)])
def test_signed_sales_do_not_consume_fee_placement_budget(sandbox, sale_day, new_sales):
    import core

    def statement(late, omit_fees=False):
        events = [(18, 10, "Opening", "opening"), (20, 119, "Rent", "rent"),
                  (22, -23, "Service", "same-fee"), (22, -23, "ATM", "same-fee")]
        if late:
            events.append((21, 50, "Late credit", "late"))
        if late or not new_sales:
            events.extend((sale_day + (index // 35 if sale_day > 22 else 0), 1, f"Sale {index}", f"sale-{index}")
                          for index in range(140))
        balance = -10
        reports = []
        for day, amount, label, reference in sorted(events, key=lambda event: event[0]):
            balance += amount
            reports.append(_bank_motion(f"2026-11-{day}", amount, None if omit_fees and reference == "same-fee" else balance,
                                        label, entry_reference=reference))
        return reports

    def sync(ledger, reports):
        return _sync_bank_pages(ledger, [reports[start:start + 30] for start in range(0, len(reports), 30)])

    prior, sparse, complete = statement(False), statement(True, omit_fees=True), statement(True)
    with closing(core.db()) as ledger:
        assert sync(ledger, prior) == (4 if new_sales else 144)
        assert sync(ledger, sparse) == (141 if new_sales else 1)
        for reply in (complete, complete[::-1], prior, complete):
            assert sync(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (145, 273)
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("omitted", ["entry_reference", "booking_date"])
def test_bank_revision_keeps_fee_names_when_an_optional_fact_disappears(sandbox, sign, omitted):
    import core

    def report(day, amount, balance, label, reference):
        return _bank_motion(f"2026-11-{day}", amount * sign, balance * sign, label, entry_reference=reference)

    opening = report(18, 10, 0, "Opening", "opening")
    rent = report(20, 119, 119, "Rent", "rent")
    late = report(21, 50, 169, "Late credit", "late")
    before = [report(22, -23, 96, "Service", "fees"), report(22, -23, 73, "ATM", "fees")]
    after = [report(22, -23, 146, "Service", "fees"), report(22, -23, 123, "ATM", "fees"),
             report(22 if omitted == "entry_reference" else 23, -23, 100, "Extra", "fees")]
    closing_fee = report(24, 15, 115, "Closing", "closing")
    affected = {"Service", "ATM"} if omitted == "entry_reference" else {"Service", "Extra"}
    sparse = [row | {omitted: None, "balance_after_transaction": None}
              if row["remittance_information"][0] in affected else row for row in after]
    prior, full = [opening, rent, *before], [opening, rent, late, *after, closing_fee]

    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [prior]) == 4
        original = {row["id"]: (row["ref"], row["description"]) for row in ledger.execute(
            "SELECT id,ref,description FROM transactions WHERE description IN ('Service','ATM')",
        )}
        for ident in original:
            core.set_tx_category(ledger, ident, "gebuehr", f"Assigned {ident}")
        partial = [opening, rent, late, *sparse, closing_fee]
        for reply, imported in ((partial, 3), (full, 0), (full[::-1], 0), (partial[::-1], 0), (prior, 0), (full, 0)):
            assert _sync_bank_pages(ledger, [reply[:4], reply[4:]] if len(reply) > 4 else [reply]) == imported
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (7, 125 * sign)
            assert [row[0] for row in ledger.execute("SELECT description FROM transactions WHERE amount=? ORDER BY description",
                                                    (-23 * sign,))] == ["ATM", "Extra", "Service"]
            assert {row["id"]: (row["ref"], row["description"], row["note"]) for row in ledger.execute(
                "SELECT id,ref,description,note FROM transactions WHERE category='gebuehr'",
            )} == {ident: (*record, f"Assigned {ident}") for ident, record in original.items()}
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
def test_bank_revision_retains_named_fee_beside_unresolved_equal_occurrences(sandbox, sign):
    import core

    def report(day, amount, balance, label, reference, index):
        return _bank_motion(f"2026-11-{day}", amount * sign, None if balance is None else balance * sign,
                            label, entry_reference=reference) | {"transaction_id": f"report-{index}"}

    sale = report(23, 31, 31, "Sale", "sale", 0)
    fee = report(24, -23, 8, "Fee", "reused", 1)
    next_sale = report(24, 11, 19, "Other sale", "other-sale", 2)
    phone = report(27, -17, 2, "Phone", "phone", 3)
    earlier = [sale, fee, next_sale, phone]
    updated = [report(22, -23, -23, "Fee", "reused", 4),
               report(23, 31, 8, "Sale", "sale", 5),
               report(24, -23, -15, "Fee", "reused", 6),
               report(24, -23, -38, "ATM", "reused", 7),
               report(24, -23, -61, "ATM", "reused", 8),
               report(24, 11, -50, "Other sale", "other-sale", 9),
               report(27, -17, -67, "Phone", "phone", 10)]
    sparse = [row | {"balance_after_transaction": None} if index in {2, 4} else row for index, row in enumerate(updated)]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [earlier]) == 4
        original = ledger.execute("SELECT id,ref FROM transactions WHERE description='Fee'").fetchone()
        core.set_tx_category(ledger, original["id"], "gebuehr", "Assigned")
        for reply, imported in ((sparse, 3), (updated, 0), (updated[::-1], 0), (earlier, 0), (updated, 0)):
            assert _sync_bank_pages(ledger, [reply[:3], reply[3:]]) == imported
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (7, -67 * sign)
            assert tuple(ledger.execute("SELECT ref,date,category,note FROM transactions WHERE id=?", (original["id"],)).fetchone()) == (
                original["ref"], "2026-11-24", "gebuehr", "Assigned",
            )
            assert core.pending_bank_statement_amounts(ledger) == []


def _bank_late_fee_history(sign):
    def movement(day, amount, balance, name, reference):
        return _bank_motion(f"2026-11-{day}", sign * amount, sign * balance, name, entry_reference=reference)

    opening = movement(18, 10, 0, "Opening", "opening")
    rent = movement(20, 119, 119, "Rent", "rent")
    prior = [opening, rent, movement(22, -23, 96, "Service", "fees"), movement(22, -23, 73, "ATM", "fees")]
    latest = [opening, rent, movement(21, 50, 169, "Late", "late"),
              movement(22, -23, 146, "Service", "fees"), movement(22, -23, 123, "ATM", "fees"),
              movement(22, -23, 100, "Extra", "fees"), movement(24, 15, 115, "Closing", "closing")]
    return prior, latest


def _verify_late_fee_replay(ledger, prior, sparse, latest, sign):
    import core

    assert _sync_bank_pages(ledger, [prior]) == 4
    original = {row["id"]: (row["ref"], row["description"], row["date"]) for row in ledger.execute(
        "SELECT id,ref,description,date FROM transactions WHERE abs(amount)=23",
    )}
    for ident in original:
        core.set_tx_category(ledger, ident, "gebuehr", f"Assigned {ident}")
    for phase, (rows, imported) in enumerate(((sparse, 3), (latest, 0), (latest[::-1], 0), (prior, 0), (latest, 0))):
        rows = [row | {"transaction_id": f"replay-{phase}-{index}"} for index, row in enumerate(rows)]
        assert _sync_bank_pages(ledger, [rows[:4], rows[4:]] if len(rows) > 4 else [rows]) == imported
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (7, sign * 125)
        assert [row[0] for row in ledger.execute("SELECT description FROM transactions WHERE abs(amount)=23 ORDER BY description")] == [
            "ATM", "Extra", "Service",
        ]
        assert {row["id"]: (row["ref"], row["description"], row["date"], row["note"]) for row in ledger.execute(
            "SELECT id,ref,description,date,note FROM transactions WHERE category='gebuehr'",
        )} == {ident: (*facts, f"Assigned {ident}") for ident, facts in original.items()}
        assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("optional_dates", [(), ("value_date",), ("transaction_date",), ("value_date", "transaction_date")])
@pytest.mark.parametrize("balance_reported", [False, True])
def test_bank_revision_uses_surviving_typed_dates_in_signed_trail(sandbox, sign, optional_dates, balance_reported):
    import core

    prior, latest = _bank_late_fee_history(sign)
    omitted = dict.fromkeys(("entry_reference", *optional_dates))
    if not balance_reported:
        omitted["balance_after_transaction"] = None
    sparse = [row | omitted if row["remittance_information"] == ["Service"] else row for row in latest]
    with closing(core.db()) as ledger:
        _verify_late_fee_replay(ledger, prior, sparse, latest, sign)


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("unknown_days", [{"Opening", "Rent", "Late"}, {"Rent", "Late"}, {"Opening", "Rent"}])
@pytest.mark.parametrize("sparse_names", [{"ATM", "Extra"}, {"Service", "Extra"}])
def test_bank_revision_checks_old_and_new_undated_movements_together(sandbox, sign, unknown_days, sparse_names):
    import core

    prior, latest = _bank_late_fee_history(sign)

    def strip_days(rows):
        return [row | {"booking_date": None} if row["remittance_information"][0] in unknown_days else row for row in rows]

    prior, latest = strip_days(prior), strip_days(latest)
    sparse = [row | {"balance_after_transaction": None} if row["remittance_information"][0] in sparse_names
              else row for row in latest]
    with closing(core.db()) as ledger:
        _verify_late_fee_replay(ledger, prior, sparse, latest, sign)
        stored = {row["description"]: row["booked_day"] for row in ledger.execute(
            "SELECT description,booked_day FROM transactions JOIN bank_import_facts USING (ref)",
        )}
        assert all(stored[name] is None for name in unknown_days)
        assert stored["ATM"] == stored["Service"] == stored["Extra"] == "2026-11-22"


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("unknown_checkpoint", ["Opening", "Rent"])
def test_bank_occurrence_window_keeps_dated_witnesses_around_undated_checkpoint(sandbox, sign, unknown_checkpoint):
    import core

    prior, latest = _bank_late_fee_history(sign)
    sparse = [row | {"booking_date": None} if row["remittance_information"] == [unknown_checkpoint]
              else row | {"balance_after_transaction": None} if row["entry_reference"] == "fees"
              else row for row in latest]
    with closing(core.db()) as ledger:
        _verify_late_fee_replay(ledger, prior, sparse, latest, sign)


@pytest.mark.parametrize("sign", [-1, 1])
def test_bank_revision_waits_for_witnesses_before_booking_an_unresolved_named_payment(sandbox, sign):
    import core

    prior, latest = _bank_late_fee_history(sign)
    partial = [row | dict.fromkeys(("entry_reference", "value_date", "transaction_date"))
               for row in latest if row["remittance_information"] == ["Service"]]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [prior]) == 4
        service = ledger.execute("SELECT id,ref FROM transactions WHERE description='Service'").fetchone()
        core.set_tx_category(ledger, service["id"], "gebuehr", "Assigned")
        for _ in range(2):
            assessments = []
            rows, skipped = transaction_rows("account-a", _bank_page_reports([partial]), ledger=ledger, assessments=assessments)
            outcome = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True, assessments=assessments)
            assert outcome["imported"] == 0
            assert skipped + outcome["ambiguous"] >= 1
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, sign * 83)
        assert _sync_bank_pages(ledger, [latest[:4], latest[4:]]) == 3
        assert _sync_bank_pages(ledger, [latest[::-1]]) == 0
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (7, sign * 125)
        assert tuple(ledger.execute("SELECT ref,category,note FROM transactions WHERE id=?", (service["id"],)).fetchone()) == (
            service["ref"], "gebuehr", "Assigned",
        )
        assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("shape", ["undated tail", "dense days", "long trail", "unreferenced fee", "undated rent", "undated fee"])
def test_bank_balance_revision_uses_the_evidenced_interval(sandbox, shape):
    import core

    first = date(2026, 11, 19)
    steps = [(0, 10, "Opening"), (1, 119, "Rent"), (2, 50, "Late movement"), (3, -23, "Fee")]
    if shape == "dense days":
        steps = [steps[0], (0, 3, "Second opening movement"), steps[1], (1, -4, "Postage"), *steps[2:]]
    elif shape == "long trail":
        steps = [*steps[:3], *((day, -1, f"Movement {day}") for day in range(3, 135))]

    def statement(with_late):
        balance = -10
        rows = []
        for day, amount, name in steps:
            if name == "Late movement" and not with_late:
                continue
            balance += amount
            report = _bank_motion(str(first + timedelta(days=day)), amount, balance, name, entry_reference=name, reference_number=name)
            if shape == "unreferenced fee" and name == "Fee":
                del report["entry_reference"]
            if (shape, name) in {("undated rent", "Rent"), ("undated fee", "Fee")}:
                del report["booking_date"]
            rows.append(report)
        if shape == "undated tail":
            rows.append(_bank_motion("2026-11-24", -3, None, "Independent charge", entry_reference="tail") | {"booking_date": None})
        return rows

    older, newer = statement(False), statement(True)
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [older]) == len(older)
        for index, reply in enumerate(([newer[::2], newer[1::2]], [older], [newer[::-1]])):
            assert _sync_bank_pages(ledger, reply) == int(index == 0)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                len(newer), sum(amount for _, amount, _ in steps) - (3 if shape == "undated tail" else 0),
            )
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("shape, has_balance", [
    ("shared receipt", True), ("impossible pair", True), ("possible pair", True), ("proven pair", True),
    ("impossible pair", False), ("possible pair", False),
])
def test_related_bank_echoes_share_the_same_balance_history(sandbox, sign, seed, shape, has_balance):
    import core

    if shape == "shared receipt":
        motions = [
            (18, 10, 0, "Opening"), (19, 119, 119, "Receipt A"), (19, -119, 0, "Reversal"),
            (19, 119, 119, "Receipt B"), (19, -23, 96, "Fee"), (23, -10, 86, "Closing"),
        ]
        targets, expected, possible = (1, 2), (6, 96, 248, 152), [-119, 119]
    elif shape == "impossible pair":
        motions = [
            (19, 10, 0, "Opening"), (20, 119, 119, "Receipt"),
            (21, -23, 96, "Debit"), (22, -10, 86, "Closing"),
        ]
        targets, expected, possible = (1, 2), (4, 96, 129, 33), []
    elif shape == "possible pair":
        motions = [
            (19, 10, 0, "Opening"), (20, 119, 119, "Receipt"), (20, -119, 0, "Reversal"),
            (22, -5, -5, "Fee A"), (23, -13, -18, "Fee B"),
        ]
        targets, expected, possible = (1, 2), (5, -8, 129, 137), [-119, 119]
    else:
        motions = [
            (19, 10, 0, "Opening"), (20, 119, 119, "Receipt"), (21, 3, 241, "Checkpoint"),
            (22, -119, 122, "Debit"), (23, -5, -2, "Closing"),
        ]
        targets, expected, possible = (1, 3), (7, 8, 251, 243), []
    reports = [_bank_motion(f"2026-11-{day}", amount * sign, balance * sign, name, entry_reference=name)
               for day, amount, balance, name in motions]
    if not has_balance:
        reports[1]["balance_after_transaction"] = None
    echoes = [reports[index] | {"entry_reference": None, "transaction_id": f"rotated-{index}", "balance_after_transaction": None}
              for index in targets]
    if shape == "shared receipt":
        echoes[1]["entry_reference"] = reports[targets[1]]["entry_reference"]
    count, net, received, paid = expected
    if sign < 0:
        received, paid = paid, received
    pending = sorted(("pending", amount * sign) for amount in possible)

    with closing(core.db()) as ledger:
        def payment():
            return tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE description=? ORDER BY id",
                                        (motions[1][3],)).fetchone())

        def totals():
            return tuple(ledger.execute("SELECT count(*),sum(amount),sum(max(amount,0)),sum(max(-amount,0)) FROM transactions").fetchone())

        def notices():
            return sorted((row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger))

        initial = reports[:1] if shape == "proven pair" else reports
        if seed:
            assert _sync_bank_pages(ledger, [initial]) == len(initial)
            if shape != "proven pair":
                saved = payment()
                core.set_tx_category(ledger, saved[0], "einnahme_sonstige", "Checked")
        assert _sync_bank_pages(ledger, [reports, echoes]) == count - (len(initial) if seed else 0)
        assert totals() == (count, net * sign, received, paid)
        assert notices() == pending
        if not seed or shape == "proven pair":
            saved = payment()
            core.set_tx_category(ledger, saved[0], "einnahme_sonstige", "Checked")
        for reply in ([echoes, reports], [reports[1:], echoes], [reports], [reports, echoes]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert totals() == (count, net * sign, received, paid)
            assert notices() == pending
        assert payment() == saved
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (saved[0],)).fetchone()) == (
            "einnahme_sonstige", "Checked",
        )


def test_coupled_bank_echoes_above_the_search_limit_need_review(sandbox):
    import core

    motions = [
        (19, 10, 0, "Opening"), (20, 119, 119, "Receipt"), (20, -119, 0, "Reversal"),
        (22, -5, -5, "Fee A"), (23, -13, -18, "Fee B"),
    ]
    reports = [_bank_motion(f"2026-11-{day}", amount, balance, name, entry_reference=name)
               for day, amount, balance, name in motions]
    # There are 13 possible counts on each side, including the signed
    # payment. Exhausting the joint search cannot prove extra bookings.
    echo = [row | {"entry_reference": None, "transaction_id": f"{row['transaction_id']}-{n}", "balance_after_transaction": None}
            for row in reports[1:3] for n in range(12)]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports]) == 5
        receipt = ledger.execute("SELECT id FROM transactions WHERE amount=119").fetchone()[0]
        core.set_tx_category(ledger, receipt, "einnahme_sonstige", "Checked")
        for pages in ([reports, echo], [echo, reports]):
            assessments = []
            rows, needs_review = transaction_rows("account-a", _bank_page_reports(pages), assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            assert result["imported"] == 0
            assert needs_review > 0
            assert core.pending_bank_statement_amounts(ledger) == []
            assert tuple(ledger.execute("SELECT count(*),sum(amount),sum(max(amount,0)) FROM transactions").fetchone()) == (5, -8, 129)
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (receipt,)).fetchone()) == (
            "einnahme_sonstige", "Checked",
        )


@pytest.mark.parametrize("balance_mask, canonical", [(1, False), (2, False), (3, False), (3, True)])
def test_reported_balances_leave_a_repeatable_offsetting_cycle_in_review(sandbox, balance_mask, canonical):
    import core

    motions = [
        (19, 10, 0, "Opening"), (20, 119, 119, "Receipt"), (20, -119, 0, "Reversal"),
        (22, -5, -5, "Fee A"), (23, -13, -18, "Fee B"),
    ]
    reports = [_bank_motion(f"2026-11-{day}", amount, balance, name, entry_reference=name)
               for day, amount, balance, name in motions]
    copies = [row | {"entry_reference": row["entry_reference"] if canonical else None,
                     "transaction_id": f"renewed-{index}",
                     "balance_after_transaction": row["balance_after_transaction"] if balance_mask & (1 << index) else None}
              for index, row in enumerate(reports[1:3])]
    expected = [] if canonical else [("pending", -119), ("pending", 119)]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, [reports, copies]) == 5
        source = tuple(ledger.execute("SELECT id,ref FROM transactions WHERE amount=119").fetchone())
        core.set_tx_category(ledger, source[0], "einnahme_sonstige", "Checked")
        for reply in ([copies, reports], [reports], [reports, copies]):
            assert sorted((row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)) == expected
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute(
                "SELECT count(*),sum(amount),sum(max(amount,0)),sum(max(-amount,0)) FROM transactions",
            ).fetchone()) == (5, -8, 129, 137)
        assert sorted((row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)) == expected
        assert tuple(ledger.execute("SELECT id,ref,category,note FROM transactions WHERE amount=119").fetchone()) == (
            *source, "einnahme_sonstige", "Checked",
        )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("ending", [96, 215])
@pytest.mark.parametrize("packet", ["split", "reversed", "single"])
def test_same_day_balance_can_prove_two_paginated_payments_without_balances(sandbox, sign, ending, packet):
    import core

    day = "2026-11-20"
    opening = _bank_motion("2026-11-19", 10 * sign, 0, "Opening", entry_reference="opening")
    receipt = _bank_motion(day, 119 * sign, None, "Payment", entry_reference="payment", reference_number="invoice")
    other = _bank_motion(day, -23 * sign, ending * sign, "Fee", entry_reference="fee")
    echo = receipt | {"entry_reference": None, "transaction_id": "rotated"}
    split = [[opening, receipt, other], [echo]]
    pages = [[opening, receipt, other, echo]] if packet == "single" else split
    if packet == "reversed":
        pages.reverse()
    count = 4 if ending == 215 else 3
    pending = [] if count == 4 else [("pending", 119 * sign)]
    with closing(core.db()) as ledger:
        assert _sync_bank_pages(ledger, pages) == count
        saved = [tuple(row) for row in ledger.execute("SELECT id,ref FROM transactions WHERE amount=? ORDER BY id", (119 * sign,))]
        assert len(saved) == count - 2
        core.set_tx_category(ledger, saved[0][0], "einnahme_sonstige", "Checked")
        for reply in (pages[::-1], split, [[opening, receipt, other]]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
                count, (119 * (count - 2) - 13) * sign,
            )
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == pending
        assert [tuple(row) for row in ledger.execute("SELECT id,ref FROM transactions WHERE amount=? ORDER BY id", (119 * sign,))] == saved
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (saved[0][0],)).fetchone()) == (
            "einnahme_sonstige", "Checked",
        )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("sparse", [False, True])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("packet", ["split", "reversed", "single"])
def test_paginated_balance_proof_uses_a_dated_and_undated_peer_once(sandbox, sign, sparse, seed, packet):
    import core

    subject = _bank_motion("2026-11-20", -119 * sign, -119 * sign, "Payment")
    small = _bank_motion("2026-11-20", 3 * sign, -116 * sign, "Small payment", entry_reference="small")
    peer = _bank_motion("2026-11-22", 119 * sign, 3 * sign, "Later payment", entry_reference="later")
    subject_copy = subject | {"transaction_id": "renewed-one"}
    peer_copy = peer | {"transaction_id": "renewed-two", "booking_date": None}
    if sparse:
        subject_copy["balance_after_transaction"] = None
        peer_copy["entry_reference"] = None
    base = [subject, small, peer]
    split = [base, [subject_copy, peer_copy]]
    pages = [[*base, subject_copy, peer_copy]] if packet == "single" else split
    if packet == "reversed":
        pages.reverse()
    with closing(core.db()) as ledger:
        if seed:
            assert _sync_bank_pages(ledger, [base]) == 3
        assert _sync_bank_pages(ledger, pages) == (0 if seed else 3)
        saved = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE amount=?", (-119 * sign,)).fetchone())
        core.set_tx_category(ledger, saved[0], "einnahme_sonstige", "Checked")
        for reply in (pages[::-1], split, [base]):
            assert _sync_bank_pages(ledger, reply) == 0
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (3, 3 * sign)
            notices = [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)]
            assert notices == ([("pending", -119 * sign)] if sparse else [])
        if sparse:
            opening = _bank_motion("2026-11-19", 10 * sign, 0, "Opening", entry_reference="opening")
            assert _sync_bank_pages(ledger, [[opening, *base]]) == 1
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (4, 13 * sign)
            assert core.pending_bank_statement_amounts(ledger) == []
        assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE amount=?", (-119 * sign,)).fetchone()) == (
            *saved, "einnahme_sonstige", "Checked",
        )


@pytest.mark.parametrize("extra_payment", [False, True])
def test_paginated_bank_copy_can_be_a_copy_of_either_known_payment(sandbox, extra_payment):
    import core

    first, fee = reported_balance_pair()
    second = first | {"transaction_id": "second", "balance_after_transaction": {"amount": "238", "currency": "EUR"}}
    fee["entry_reference"] = "fee"
    fee.pop("balance_after_transaction")
    sparse = first | {"transaction_id": "continuation", "balance_after_transaction": None}
    observations = [first, second, fee]

    class PaginatedBank(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            if query.get("continuation_key"):
                return {"transactions": [sparse]}
            return {"transactions": list(observations), "continuation_key": "more"}

    provider = PaginatedBank(APP_ID, b"fixture-key")
    with closing(core.db()) as ledger:
        def sync():
            assessments = []
            incoming = provider.transactions(ACCOUNT, None, "2026-11-23")
            rows, _ = transaction_rows("account-a", incoming, assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            return result["imported"]

        def state():
            totals = tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone())
            pending = [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)]
            return totals, pending

        assert sync() == 3
        assert state() == ((3, 215), [("pending", 119)])
        credit_ids = [row[0] for row in ledger.execute("SELECT id FROM transactions WHERE amount=119 ORDER BY id")]
        core.set_tx_category(ledger, credit_ids[0], "einnahme_sonstige", "Reviewed")
        sparse["transaction_id"] = "renewed"
        observations.reverse()
        assert sync() == 0
        assert state() == ((3, 215), [("pending", 119)])
        fee["balance_after_transaction"] = {"amount": "334" if extra_payment else "215", "currency": "EUR"}
        assert sync() == int(extra_payment)
        assert sync() == 0
        assert state() == ((4, 334) if extra_payment else (3, 215), [])
        assert tuple(ledger.execute("SELECT category,note FROM transactions WHERE id=?", (credit_ids[0],)).fetchone()) == (
            "einnahme_sonstige", "Reviewed",
        )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("third", [False, True])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("window", ["both", "before", "after"])
def test_signed_balance_family_counts_sparse_reports_without_guessing_their_origin(sandbox, sign, third, seed, window):
    import core

    credit, fee = reported_balance_pair()
    opening = credit | {"entry_reference": "opening", "booking_date": "2026-11-19", "transaction_date": "2026-11-19",
                        "transaction_amount": {"amount": "10", "currency": "EUR"}, "remittance_information": ["Opening"],
                        "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    second = credit | {"transaction_id": "second", "balance_after_transaction": {"amount": "238", "currency": "EUR"}}
    sparse = credit | {"transaction_id": "sparse", "balance_after_transaction": None}
    fee["balance_after_transaction"] = {"amount": "334" if third else "215", "currency": "EUR"}
    for row in (opening, credit, second, sparse, fee):
        if sign < 0:
            row["credit_debit_indicator"] = "DBIT" if row["credit_debit_indicator"] == "CRDT" else "CRDT"
            if balance := row["balance_after_transaction"]:
                row["balance_after_transaction"] = balance | {"amount": str(-int(balance["amount"]))}
    clean = [opening, credit, second, *([sparse] if third else []), fee]
    shown = clean if window == "both" else clean[:-1] if window == "before" else clean[1:]
    repeated = [*shown, sparse | {"transaction_id": "renewed"}]
    reused_lookup = [row if row is opening or row is fee else row | {"transaction_id": credit["transaction_id"]} for row in repeated]
    count = len(clean) if seed else len(shown) - int(third and window == "before")
    amount = 344 if third else 225
    if not seed and window != "both":
        amount += 23 - 119 * int(third) if window == "before" else -10
    with closing(core.db()) as ledger:
        def sync(page):
            assessments = []
            rows, warnings = transaction_rows("account-a", page, assessments=assessments, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)
            assert warnings + result["ambiguous"] == 0
            return result["imported"]

        if seed:
            assert sync(clean) == len(clean)
        assert sync(reused_lookup[::-1]) == (0 if seed else count)
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (count, amount * sign)
        old = [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")]
        assert sync(repeated) == sync(reused_lookup) == 0
        assert [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")] == old
        assert sync(clean) == len(clean) - count
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (
            len(clean), (344 if third else 225) * sign,
        )
        old = [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")]
        assert sync(reused_lookup) == 0
        assert not core.pending_bank_statement_amounts(ledger)
        assert [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount FROM transactions ORDER BY id")] == old


@pytest.mark.parametrize("distinct_payer", [False, True])
@pytest.mark.parametrize("sign", [-1, 1])
def test_equal_signed_payments_can_corroborate_a_sparse_copy(sandbox, distinct_payer, sign):
    import core

    first, _ = reported_balance_pair()
    first["entry_reference"] = "first"
    second = first | {"entry_reference": "second", "transaction_id": "another",
                      "balance_after_transaction": {"amount": "238", "currency": "EUR"}}
    if distinct_payer:
        second["debtor_account"] = {"iban": "DE00OTHER"}
    sparse = first | {"entry_reference": None, "transaction_id": "overlap", "balance_after_transaction": None}
    if sign < 0:
        for row in (first, second, sparse):
            row["credit_debit_indicator"] = "DBIT"
            row["creditor_account"] = row["debtor_account"]
            if balance := row["balance_after_transaction"]:
                row["balance_after_transaction"] = balance | {"amount": str(-int(balance["amount"]))}
    with closing(core.db()) as ledger:
        for page, count in (([first, second, sparse], 2), ([sparse, second, first], 0), ([first, second], 0)):
            rows, warnings = transaction_rows("account-a", page, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False)
            assert (result["imported"], warnings + result["ambiguous"]) == (count, int(not distinct_payer and len(page) == 3))
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (2, 238 * sign)


def test_signed_balance_family_accepts_complementary_dates_on_a_sparse_copy(sandbox):
    import core

    credit, fee = reported_balance_pair()
    opening = credit | {"entry_reference": "opening", "booking_date": "2026-11-19", "transaction_date": "2026-11-19",
                        "transaction_amount": {"amount": "10", "currency": "EUR"}, "remittance_information": ["Opening"],
                        "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    credit["booking_date"] = None
    sparse = credit | {"transaction_id": "renewed", "transaction_date": None, "value_date": "2026-11-20",
                       "balance_after_transaction": None}
    page = [sparse, fee, credit, opening]
    with closing(core.db()) as ledger:
        for statement, count in ((page, 3), (page[::-1], 0), ([credit, opening, fee], 0)):
            rows, warnings = transaction_rows("account-a", statement, ledger=ledger)
            result = core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False)
            assert (result["imported"], warnings + result["ambiguous"]) == (count, 0)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (3, 106)


@pytest.mark.parametrize("opening_balance", [0, 119])
def test_balance_path_resolves_a_pending_occurrence_after_an_amended_witness(sandbox, opening_balance):
    import core

    credit, fee = reported_balance_pair()
    credit["value_date"] = credit["booking_date"]
    opening = credit | {"booking_date": "2026-11-19", "transaction_date": "2026-11-19", "value_date": "2026-11-19",
                        "remittance_information": ["Opening"], "transaction_id": "opening",
                        "transaction_amount": {"amount": "10", "currency": "EUR"}, "balance_after_transaction": None}
    reversal = fee | {"entry_reference": "reversal", "booking_date": "2026-11-20", "value_date": "2026-11-20",
                      "remittance_information": ["Reversal"], "transaction_amount": {"amount": "119", "currency": "EUR"},
                      "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    statement = [opening, credit, reversal, credit | {"transaction_id": "second"}, fee]
    updated = opening | {"transaction_id": "rotated", "remittance_information": ["Amended opening"],
                         "balance_after_transaction": {"amount": str(opening_balance), "currency": "EUR"}}
    confirmed_page = [updated, *statement[1:]]
    with closing(core.db()) as ledger:
        def sync(items):
            assessments = []
            rows, _ = transaction_rows("account-a", items, assessments=assessments, ledger=ledger)
            return core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)["imported"]

        assert sync(statement) == 4
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
        original = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE amount=10").fetchone())
        core.set_tx_category(ledger, original[0], "einnahme_sonstige", "Reviewed")
        assert sync(confirmed_page[::-1]) == int(opening_balance == 0)
        assert not core.pending_bank_statement_amounts(ledger)
        assert sync(confirmed_page) == sync(statement) == 0
        assert not core.pending_bank_statement_amounts(ledger)
        assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE amount=10").fetchone()) == (
            *original, "einnahme_sonstige", "Reviewed",
        )
        expect = (5, 106) if opening_balance == 0 else (4, -13)
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == expect


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
    "anchored-first-gap", "anchored-last-gap", "posting-anchored-inner-gap", "posting-anchored-distinct-days",
    "anchored-two-gaps", "anchored-two-gaps-anchor-day",
    "parallel-unreferenced",
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
    if trail.startswith("anchored-"):
        positions = {
            "anchored-first-gap": [("20", 50, None), ("20", 69, 0)],
            "anchored-last-gap": [("20", 50, 69), ("20", 69, None)],
            "anchored-inner-gap": [("20", 50, 69), ("20", 10, None), ("20", 10, None), ("20", 49, 0)],
            "anchored-distinct-days": [("19", 50, None), ("20", 49, 20), ("21", 20, None)],
            "anchored-two-gaps": [("20", 30, 89), ("20", 10, None), ("20", 40, 39), ("20", 20, None), ("20", 19, 0)],
            "anchored-two-gaps-anchor-day": [("19", 20, None), ("19", 30, 69), ("19", 10, None), ("19", 59, 0)],
        }
        adjustments = [
            adjustment | {"entry_reference": f"reversal-{index}", "transaction_id": f"reversal-{index}",
                          "value_date": "2026-11-" + day, "transaction_date": "2026-11-" + day,
                          "transaction_amount": {"amount": str(amount), "currency": "EUR"},
                          "balance_after_transaction": None if balance is None else
                          {"amount": str(balance * sign), "currency": "EUR"}}
            for index, (day, amount, balance) in enumerate(positions[trail])
        ]
    if trail == "early-reversal":
        adjustment.update(value_date="2026-11-19", transaction_date="2026-11-19")
        offset.update(value_date="2026-11-19", transaction_date="2026-11-19",
                      balance_after_transaction={"amount": "0", "currency": "EUR"})
    if trail == "late-reversal":
        adjustment.update(value_date="2026-11-21", transaction_date="2026-11-21")
        offset.update(value_date="2026-11-21", transaction_date="2026-11-21")
    if trail in {"cycle", "parallel-cycle", "parallel-reused-reference", "parallel-unreferenced"}:
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
        if trail == "parallel-unreferenced":
            for index in (0, 2):
                adjustments[index].update(entry_reference=None, reference_number=None)
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


@pytest.mark.parametrize("day_field", ["booking_date", "transaction_date"])
@pytest.mark.parametrize("context", ["before", "after"])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("reverse", [True, False])
@pytest.mark.parametrize("sparse_gap", [False, True])
def test_neighboring_statement_balance_can_prove_a_single_corrected_booking(
    sandbox, day_field, context, sign, reverse, sparse_gap,
):
    import core

    direction, opposite = ("CRDT", "DBIT") if sign > 0 else ("DBIT", "CRDT")
    first = bank_row(entry_reference="rent", transaction_id="same-fetch", booking_date="2026-11-23",
                     value_date="2026-11-17", transaction_date="2026-11-18", credit_debit_indicator=direction,
                     debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"},
                     reference_number="INV", remittance_information=["Rent"],
                     balance_after_transaction={"amount": str(119 * sign), "currency": "EUR"})
    first[day_field] = "2026-11-19"
    second = first | {day_field: "2026-11-21"}
    reversal = first | {day_field: "2026-11-20", "entry_reference": "reversal", "transaction_id": "reversal",
                        "credit_debit_indicator": opposite, "remittance_information": ["Reversal"],
                        "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    neighboring_day, neighboring_balance = ("2026-11-18", 119) if context == "before" else ("2026-11-22", -23)
    gaps = []
    if sparse_gap:
        gaps.append(reversal | {day_field: neighboring_day, "entry_reference": "gap", "transaction_id": "gap",
                                "transaction_amount": {"amount": "5", "currency": "EUR"},
                                "balance_after_transaction": None, "remittance_information": ["Gap"]})
        neighboring_day, neighboring_balance = ("2026-11-17", 124) if context == "before" else ("2026-11-23", -28)
    neighbor = reversal | {day_field: neighboring_day, "entry_reference": "offset", "transaction_id": "offset",
                          "transaction_amount": {"amount": "23", "currency": "EUR"},
                          "balance_after_transaction": {"amount": str(neighboring_balance * sign), "currency": "EUR"},
                          "remittance_information": ["Offset"]}
    expected, alternative = (second, first) if context == "before" else (first, second)
    whole = [first, reversal, second, neighbor, *gaps]
    if reverse:
        whole.reverse()
    with closing(core.db()) as ledger:
        def sync(page):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        assert sync(whole) == (3 + len(gaps), 0)
        saved = tuple(ledger.execute("SELECT id, ref, date FROM transactions WHERE description = 'Rent'").fetchone())
        assert saved[2] == expected["booking_date"]
        core.set_tx_category(ledger, saved[0], "einnahme_sonstige")
        assert sync(whole[::-1]) == (0, 0)
        assert sync([alternative, neighbor]) == (0, int(day_field == "booking_date"))
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
            3 + len(gaps), (-23 - 5 * len(gaps)) * sign,
        )
        assert tuple(ledger.execute(
            "SELECT id, ref, date, category FROM transactions WHERE description = 'Rent'",
        ).fetchone()) == (*saved, "einnahme_sonstige")


@pytest.mark.parametrize("day_field", ["booking_date", "transaction_date"])
@pytest.mark.parametrize("context", ["before", "after", "long-after", "end-day"])
@pytest.mark.parametrize("outcome,seed", [
    ("one", False), ("one", True), ("one", "both"), ("one", "alternate"),
    ("two", False), ("two", True), ("ambiguous", False), ("ambiguous", True),
])
@pytest.mark.parametrize("sign", [-1, 1])
def test_statement_context_compares_both_payment_counts_without_dropping_sparse_movements(
    sandbox, day_field, context, outcome, sign, seed,
):
    import core

    def payment(day, change, balance, ref, memo, lookup=None):
        if context == "before":
            day = 42 - day
            balance = balance - change if balance is not None else None
            change = -change
        change *= sign
        return bank_row(
            **{
                "booking_date": "2026-11-27",
                "transaction_date": "2026-11-18",
                "value_date": "2026-11-17",
                day_field: f"2026-11-{day:02}",
            },
            entry_reference=ref, reference_number=ref, transaction_id=lookup or ref,
            credit_debit_indicator="CRDT" if change > 0 else "DBIT",
            transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
            debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"},
            remittance_information=[memo],
            balance_after_transaction=None if balance is None else {"amount": str(balance * sign), "currency": "EUR"},
        )

    first = payment(19, 119, 119, "rent", "Rent")
    second = payment(21, 119, 119, "rent", "Rent")
    reversal = payment(20, -119, 0, "reversal", "Reversal")
    boundary = 21 if context == "end-day" else 22
    neighbors = [payment(boundary, 119, None, "supplies", "Supplies"), payment(boundary, -23, 96, "fee", "Fee")]
    net = 96
    if context == "long-after":
        for day in (23, 24):
            neighbors.extend((payment(day, 119, None, f"supplies-{day}", f"Supplies {day}"),
                              payment(day, -10, net + 109, f"fee-{day}", f"Fee {day}")))
            net += 109
    ledger_sign = -sign if context == "before" else sign
    if outcome != "ambiguous":
        net += 119 if outcome == "two" else 0
        neighbors.append(payment(25 if context == "long-after" else 23, -10, net - 10, "tail", "Tail"))
        net -= 10

    batch = [first, reversal, second, *neighbors]
    unanchored_before = outcome == "two" and context == "before" and day_field == "transaction_date"
    unanchored_one = outcome == "one" and day_field == "transaction_date"
    with closing(core.db()) as ledger:
        def sync(page):
            mapper = (_confirmed_statement_rows if outcome == "two" and day_field == "transaction_date" and context != "before"
                      else transaction_rows)
            if unanchored_before or unanchored_one:
                assessments = []
                rows, skipped = mapper("account-a", page, assessments=assessments)
                result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True, assessments=assessments)
                warning = skipped + result["ambiguous"] or len(core.pending_bank_statement_amounts(ledger))
                return result["imported"], warning
            rows, skipped = mapper("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        saved = []
        if seed:
            existing = [first, second] if seed == "both" else [second if seed == "alternate" else first]
            assert sync([*existing, reversal]) == (len(existing) + 1, 0)
            saved = [tuple(row) for row in ledger.execute("SELECT id, ref, date FROM transactions WHERE description = 'Rent'")]
            for booking_id, _, _ in saved:
                core.set_tx_category(ledger, booking_id, "einnahme_sonstige")
            if outcome == "two":
                imported, warnings = sync(batch[:-1])
                assert imported == len(neighbors) - 1 and warnings > 0
        expected_count = 1 + len(neighbors) + (2 if outcome == "two" else 1)
        if unanchored_before:
            expected_count -= 1
            net -= 119
        if seed == "both":
            expected_count += 1
            net += 119
        expected_warning = (outcome == "ambiguous" or seed == "both" or unanchored_before or unanchored_one
                            or (seed == "alternate" and day_field == "booking_date"))
        if outcome == "ambiguous" and day_field == "booking_date" and not seed:
            expected_count -= 1
            net -= 119
        pages = [batch[::-1] if seed else batch, batch if seed else batch[::-1]]
        pages.extend((
            [first, *batch],
            [*batch, second],
            batch + batch,
            [first | {"balance_after_transaction": None}, *batch],
            [*batch, second | {"reference_number": None}],
        ))
        for replay, page in enumerate(pages):
            _, warnings = sync(page)
            actual = tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone())
            assert bool(warnings) == expected_warning, (replay, actual)
            if seed == "alternate":
                assert warnings == int(day_field == "booking_date" or unanchored_one)
            if unanchored_before:
                assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [
                    ("pending", 119 * ledger_sign),
                ]
            assert actual == (expected_count, net * ledger_sign)
            for booking_id, booking_ref, booking_date in saved:
                assert tuple(ledger.execute(
                    "SELECT id, ref, date, category FROM transactions WHERE id = ?", (booking_id,),
                ).fetchone()) == (booking_id, booking_ref, booking_date, "einnahme_sonstige")
        if outcome == "two":
            assert sync([second, first]) == (0, int(unanchored_before))
            assert sync(batch[:-1])[0] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
                expected_count, net * ledger_sign,
            )

    if unanchored_before:
        supplies, fee, tail = neighbors
        lower = [tail, supplies, fee, second, reversal]
        higher = [*lower, first]
        for path, total in ((lower, 86), (higher, 205)):
            running = 205 * sign
            for row in path:
                amount = float(row["transaction_amount"]["amount"])
                running += amount if row["credit_debit_indicator"] == "CRDT" else -amount
                if balance := row["balance_after_transaction"]:
                    assert running == float(balance["amount"])
            assert running - 205 * sign == total * ledger_sign

        closing_checkpoint = tail | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-11-28") | {
            "entry_reference": "closing-checkpoint", "reference_number": "closing-checkpoint", "transaction_id": "closing-checkpoint",
            "remittance_information": ["Closing checkpoint"], "balance_after_transaction": {"amount": str(10 * sign), "currency": "EUR"},
        }
        proved = [*batch[:-1], tail | {"booking_date": "2026-11-19"}, closing_checkpoint]
        decisions = []
        mapped, _ = transaction_rows("account-a", proved, assessments=decisions)
        assert [row["state"] for row in decisions] == ["confirmed"]
        tested = [row for row in mapped if row["description"] != "Closing checkpoint"]
        assert len(tested) == 6 and sum(float(row["amount"]) for row in tested) == 205 * ledger_sign


def ambiguous_reference_statement(sign=1):
    def movement(day, change, balance, ref, description):
        return bank_row(booking_date="2026-11-23", transaction_date=f"2026-11-{day:02}",
                        value_date=f"2026-11-{day:02}", entry_reference=ref, reference_number=f"INV-{ref}",
                        transaction_id=ref, remittance_information=[description], debtor_account={"iban": "DE00PAYER"},
                        creditor_account={"iban": "DE00PAYEE"}, credit_debit_indicator="CRDT" if sign * change > 0 else "DBIT",
                        transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
                        balance_after_transaction=None if balance is None else {"amount": str(balance * sign), "currency": "EUR"})

    rent = movement(19, 119, 119, "rent", "Rent")
    later_rent = movement(21, 119, 119, "rent", "Rent")
    supplies = movement(22, 119, None, "supplies", "Supplies")
    reversal = movement(20, -119, 0, "reversal", "Reversal")
    fee = movement(22, -23, 96, "fee", "Fee")
    closing_fee = movement(23, -10, 205, "closing", "Closing fee")
    return [rent, reversal, later_rent, supplies, fee, closing_fee]


def _confirmed_statement_rows(account, page, *, assessments=None):
    """Give the mapper an independent opening, while testing the disputed period alone."""
    rent = next((row for row in page if row["remittance_information"] == ["Rent"]), None)
    if rent is None:
        return transaction_rows(account, page, assessments=assessments)
    earliest = min(date.fromisoformat(row[field]) for row in page
                   for field in ("booking_date", "value_date", "transaction_date") if row.get(field))
    preceding = []
    for offset, original_direction, ending, label in (
        (2, rent["credit_debit_indicator"], 10 if rent["credit_debit_indicator"] == "CRDT" else -10, "Opening receipt"),
        (1, "DBIT" if rent["credit_debit_indicator"] == "CRDT" else "CRDT", 0, "Opening reversal"),
    ):
        day = (earliest - timedelta(days=offset)).isoformat()
        preceding.append(bank_row(booking_date=day, value_date=day, transaction_date=day, entry_reference=label,
                                  reference_number=label, transaction_id=label, credit_debit_indicator=original_direction,
                                  remittance_information=[label], transaction_amount={"amount": "10", "currency": "EUR"},
                                  balance_after_transaction={"amount": str(ending), "currency": "EUR"}))
    rows, warnings = transaction_rows(account, [*preceding, *page], assessments=assessments)
    return [row for row in rows if row["description"] not in {"Opening receipt", "Opening reversal"}], warnings


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("seed", [None, "known", "unassigned", "assigned"])
def test_statement_counts_proven_payment_without_guessing_its_reference(sandbox, sign, seed):
    import core

    whole = ambiguous_reference_statement(sign)
    rent, reversal, later_rent, supplies, fee, _ = whole
    neutral = "Kontoauszug prüfen"

    with closing(core.db()) as ledger:
        def sync(batch):
            rows, skipped = _confirmed_statement_rows("account-a", batch)
            result = core.import_bank_rows(ledger, rows, auto_match=True, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        saved_rent = saved_extra = None
        if seed:
            batch = [rent, reversal, supplies, fee] if seed == "known" else [rent, reversal, later_rent, supplies]
            assert sync(batch)[0] == 4
            saved_rent = ledger.execute(
                "SELECT id, ref FROM transactions JOIN bank_import_facts USING (ref) "
                "WHERE description = 'Rent' AND value_day = '2026-11-19'",
            ).fetchone()
            core.set_tx_category(ledger, saved_rent[0], "einnahme_sonstige")
            if seed in {"unassigned", "assigned"}:
                saved_extra = ledger.execute("SELECT id, ref FROM transactions WHERE description = 'Rent' AND id <> ?",
                                             (saved_rent[0],)).fetchone()
                if seed == "assigned":
                    core.set_tx_category(ledger, saved_extra[0], "einnahme_sonstige")

        assert sync(whole + whole) == ((2 if seed else 6), int(seed == "assigned"))
        disputed = ledger.execute("SELECT * FROM transactions WHERE description = ?", (neutral,)).fetchone()
        if seed == "assigned":
            assert disputed is None
            disputed = ledger.execute("SELECT * FROM transactions WHERE id = ?", (saved_extra[0],)).fetchone()
            assert (disputed["ref"], disputed["description"], disputed["category"]) == (saved_extra[1], "Rent", "einnahme_sonstige")
        else:
            assert disputed is not None
            if saved_extra:
                assert disputed["id"] == saved_extra[0]
            assert (disputed["amount"], disputed["date"], disputed["category"], disputed["invoice_id"]) == (
                sign * 119, "2026-11-23", "offen", None,
            )
            assert tuple(ledger.execute(
                "SELECT provider_ref, creditor_ref, reference_schema, counterparty_iban, counterparty_ids, value_day, transaction_day "
                "FROM bank_import_facts WHERE ref = ?", (disputed["ref"],),
            ).fetchone()) == (None,) * 7
            assert sorted(row[0] for row in ledger.execute("SELECT description FROM transactions WHERE id <> ?", (disputed["id"],))) == [
                "Closing fee", "Fee", "Rent", "Reversal", "Supplies",
            ]
            core.set_tx_category(ledger, disputed["id"], "einnahme_sonstige")

        sparse_later = later_rent | {"transaction_id": "rotated", "reference_number": None, "balance_after_transaction": None}
        reference_less = later_rent | {"transaction_id": "rotated-again", "entry_reference": None}
        no_posting_day = later_rent | {"booking_date": None}
        pages = ((whole + whole)[::-1], [later_rent, fee], [sparse_later], [reference_less], [no_posting_day],
                 [supplies, fee], whole, whole + whole)
        for page in pages:
            assert sync(page)[0] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (6, 205 * sign)
            assert tuple(ledger.execute("SELECT ref, category FROM transactions WHERE id = ?", (disputed["id"],)).fetchone()) == (
                disputed["ref"], "einnahme_sonstige",
            )
        if saved_rent:
            assert tuple(ledger.execute("SELECT ref, category FROM transactions WHERE id = ?", (saved_rent[0],)).fetchone()) == (
                saved_rent[1], "einnahme_sonstige",
            )
        rent_id, rent_ref = ledger.execute(
            "SELECT id, ref FROM transactions JOIN bank_import_facts USING (ref) WHERE value_day = '2026-11-19'",
        ).fetchone()
        assert ledger.execute("SELECT count(*) FROM bank_import_date_aliases WHERE ref = ?", (rent_ref,)).fetchone()[0] == 2
        if saved_rent:
            assert rent_id == saved_rent[0]
        rows, skipped = _confirmed_statement_rows("different-account", [reference_less])
        assert skipped == 0
        assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 1


@pytest.mark.parametrize("legacy", [False, True])
def test_concurrent_statement_review_imports_one_neutral_payment(sandbox, legacy):
    import core

    statement = ambiguous_reference_statement()
    rows, warnings = _confirmed_statement_rows("account-a", statement * 2)
    assert warnings == 0
    with closing(core.db()) as ledger:
        if legacy:
            seed, _ = _confirmed_statement_rows("account-a", statement[:4])
            assert core.import_bank_rows(ledger, seed)["imported"] == 4
    start = Barrier(2)
    conversion = Barrier(2)

    def import_statement():
        with closing(core.db()) as ledger:
            def overlap(sql):
                if sql.startswith("UPDATE transactions SET description = "):
                    try:
                        conversion.wait(timeout=0.5)
                    except BrokenBarrierError:
                        pass

            ledger.set_trace_callback(overlap)
            start.wait(timeout=5)
            return core.import_bank_rows(ledger, rows, require_fx=True)["imported"]

    with ThreadPoolExecutor(max_workers=2) as pool:
        imported = list(pool.map(lambda _: import_statement(), range(2)))
    assert sorted(imported) == [0, 2 if legacy else 6]
    with closing(core.db()) as ledger:
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (6, 205)
        assert ledger.execute("SELECT count(*) FROM bank_statement_reviews").fetchone()[0] == 1


@pytest.mark.parametrize("variation", [
    {"value_date": None}, {"reference_number": None}, {"transaction_id": "rotated"}, {"transaction_id": None},
    {"entry_reference": None}, {"booking_date": None}, {"debtor_account": None, "creditor_account": None},
    {"remittance_information": ["Supplies details"]},
    {"reference_number": None, "transaction_id": "rotated", "transaction_date": None},
    {"entry_reference": None, "reference_number": None, "transaction_id": "rotated"},
    {"balance_after_transaction": {"amount": "215", "currency": "EUR"}},
])
def test_statement_review_counts_compatible_partial_observations(sandbox, variation):
    import core

    whole = ambiguous_reference_statement()
    extra = whole[3] | variation
    with closing(core.db()) as ledger:
        for page in ([*whole, extra], [extra, *whole[::-1]], whole, [extra]):
            rows, _ = _confirmed_statement_rows("account-a", page)
            core.import_bank_rows(ledger, rows, require_fx=True)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (6, 205)
            assert sorted(row[0] for row in ledger.execute("SELECT description FROM transactions WHERE amount = 119")) == [
                "Kontoauszug prüfen", "Rent", "Supplies",
            ]


@pytest.mark.parametrize("copies", ["rotated-page", "many-pages", "undated-option", "different-payer", "different-invoice", "different-date"])
def test_statement_review_preserves_independent_evidence(sandbox, copies):
    import core

    whole = ambiguous_reference_statement()
    if copies == "rotated-page":
        page = [*whole, *(row | {"transaction_id": f"other-{index}"} for index, row in enumerate(whole))]
    elif copies == "many-pages":
        page = whole * 12
    else:
        changes = {
            "undated-option": {"value_date": None, "transaction_date": None},
            "different-payer": {"debtor_account": {"iban": "DE00OTHER"}},
            "different-invoice": {"reference_number": "another-invoice"},
            "different-date": {"value_date": "2026-11-24"},
        }
        page = [*whole, whole[3] | changes[copies]]
    with closing(core.db()) as ledger:
        for response in (page, page[::-1]):
            decisions = [] if copies == "undated-option" else None
            rows, warnings = _confirmed_statement_rows("account-a", response, assessments=decisions)
            result = core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions or ())
            descriptions = [row[0] for row in ledger.execute("SELECT description FROM transactions WHERE amount = 119")]
            total = tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone())
            if copies in {"rotated-page", "many-pages"}:
                assert total == (6, 205)
                assert sorted(descriptions) == ["Kontoauszug prüfen", "Rent", "Supplies"]
            elif copies == "undated-option":
                assert total == (6, 205)
                assert sorted(descriptions) == ["Kontoauszug prüfen", "Rent", "Supplies"]
                assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
            else:
                assert total == (6, 205)
                assert sorted(descriptions) == ["Rent", "Supplies", "Supplies"]


@pytest.mark.parametrize("correction", ["all-booked", "credit-booked", "later-entry-reference", "split-dates"])
@pytest.mark.parametrize("first_corrected", [False, True])
def test_statement_review_keeps_economic_identity_on_corrected_data(sandbox, correction, first_corrected):
    import core

    original = ambiguous_reference_statement()
    corrected = [row.copy() for row in original]
    if correction.endswith("booked"):
        for row in corrected:
            if correction == "all-booked" or row["credit_debit_indicator"] == "CRDT":
                row["booking_date"] = "2026-11-24"
    elif correction == "later-entry-reference":
        corrected[2]["entry_reference"] = "rent-corrected"
    else:
        corrected[4]["value_date"] = None
        corrected[5]["transaction_date"] = None

    first, second = (corrected, original) if first_corrected else (original, corrected)
    with closing(core.db()) as ledger:
        def sync(page, expected=(6, 205)):
            rows, skipped = _confirmed_statement_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, require_fx=True)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == expected
            return skipped + result["ambiguous"]

        if first_corrected and correction == "credit-booked":
            # No BOOK-ordered path can reach the reported debit balances from
            # the verified opening when all the credits are posted next day.
            assert sync(first * 2, (5, 86)) > 0
            sync(second * 2)
        else:
            sync(first * 2)
        saved = tuple(ledger.execute("SELECT id, ref, date FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone())
        core.set_tx_category(ledger, saved[0], "einnahme_sonstige")
        if correction == "later-entry-reference":
            assert sync([second[2]]) == 1
        for page in (second * 2, (second * 2)[::-1], [second[2]], first[::-1]):
            sync(page)
            assert tuple(ledger.execute("SELECT id, ref, date, category FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone()) == (
                *saved, "einnahme_sonstige",
            )


def test_first_posting_correction_reuses_review_from_legacy_ledger(sandbox):
    import core
    from hosted.enable_banking import fingerprint

    whole = ambiguous_reference_statement()
    rows, warnings = _confirmed_statement_rows("account-a", whole * 2)
    assert warnings == 0
    neutral = next(row for row in rows if row["description"] == "Kontoauszug prüfen")
    references = sorted(row["provider_ref"] for row in rows if row["description"] in {"Rent", "Supplies"})
    raw_key = fingerprint("account-a", "statement-review", "2026-11-23", "119", "EUR", references)
    neutral["ref"] = core.ENABLE_BANKING_REF_PREFIX + raw_key
    with closing(core.db()) as ledger:
        assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 6
        ledger.execute("UPDATE bank_statement_reviews SET alternatives = ?", (json.dumps(neutral["_statement_review_options"]),))
        original = tuple(ledger.execute("SELECT id, ref, date FROM transactions WHERE ref = ?", (neutral["ref"],)).fetchone())
        core.set_tx_category(ledger, original[0], "einnahme_sonstige")

        next_day = [row | {"booking_date": "2026-11-24"} for row in whole]
        for page in (next_day * 2, (next_day * 2)[::-1]):
            mapped, _ = _confirmed_statement_rows("account-a", page)
            assert core.import_bank_rows(ledger, mapped, require_fx=True)["imported"] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (6, 205)
            assert tuple(ledger.execute("SELECT id, ref, date, category FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone()) == (
                *original, "einnahme_sonstige",
            )


@pytest.mark.parametrize("posting_day", ["2026-11-23", "2026-11-30"])
def test_statement_review_distinguishes_later_payments_with_reused_references(sandbox, posting_day):
    import core

    whole = ambiguous_reference_statement()
    later = [row | {"booking_date": posting_day}
             | {field: f"2026-11-{int(row[field][-2:]) + 5}" for field in ("value_date", "transaction_date")}
             for row in whole]
    with closing(core.db()) as ledger:
        initial, _ = _confirmed_statement_rows("account-a", whole * 2)
        assert core.import_bank_rows(ledger, initial, require_fx=True)["imported"] == 6
        stored = ledger.execute("SELECT id FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone()[0]
        core.set_tx_category(ledger, stored, "einnahme_sonstige")
        newer, skipped = _confirmed_statement_rows("account-a", later * 2)
        result = core.import_bank_rows(ledger, newer, require_fx=True)
        legacy_day = posting_day == "2026-11-23"
        assert result["ambiguous"] + skipped == int(legacy_day)
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
            (6, 205) if legacy_day else (12, 410)
        )
        assert ledger.execute("SELECT count(*) FROM bank_statement_reviews").fetchone()[0] == (1 if legacy_day else 2)
        assert ledger.execute("SELECT category FROM transactions WHERE id = ?", (stored,)).fetchone()[0] == "einnahme_sonstige"


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("changed", [(0,), (1,), (2,), (3,), (4,), (5,), (0, 2), tuple(range(6)), "absent", "booking"])
def test_statement_replay_keeps_each_movement_when_references_change(sandbox, sign, changed):
    import core

    whole = ambiguous_reference_statement(sign)
    corrected = [row.copy() for row in whole]
    if changed in {"absent", "booking"}:
        affected = range(6) if changed == "absent" else (1,)
        for index in affected:
            corrected[index]["entry_reference"] = None
        if changed == "booking":
            for row in corrected:
                row["booking_date"] = "2026-11-24"
    else:
        affected = changed
        for index in affected:
            corrected[index]["entry_reference"] += "-corrected"

    with closing(core.db()) as ledger:
        def sync(page):
            rows, skipped = _confirmed_statement_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        assert sync(whole * 2) == (6, 0)
        for (booking_id,) in ledger.execute("SELECT id FROM transactions").fetchall():
            core.set_tx_category(ledger, booking_id, "einnahme_sonstige")
        saved = [tuple(row) for row in ledger.execute(
            "SELECT id, ref, date, amount, description, category FROM transactions ORDER BY id",
        )]
        pages = ([corrected[index] for index in affected], corrected * 2, (corrected * 2)[::-1], whole * 2)
        if changed not in {"booking", "absent"}:
            pages += (whole + corrected, (whole + corrected)[::-1])
        for page in pages:
            imported, warnings = sync(page)
            assert imported == 0
            if len(page) >= len(whole) * 2 and changed != "booking":
                assert warnings == 0
            assert [tuple(row) for row in ledger.execute(
                "SELECT id, ref, date, amount, description, category FROM transactions ORDER BY id",
            )] == saved


@pytest.mark.parametrize("split", [False, True])
@pytest.mark.parametrize("changed", [0, 1])
def test_normal_bank_overlap_uses_confirmed_facts_after_reference_correction(sandbox, split, changed):
    import core

    source = ambiguous_reference_statement()
    whole = [source[0], source[4]]
    corrected = [row.copy() for row in whole]
    corrected[changed]["entry_reference"] += "-corrected"
    with closing(core.db()) as ledger:
        initial, _ = transaction_rows("account-a", whole)
        assert core.import_bank_rows(ledger, initial, require_fx=True)["imported"] == 2
        saved = [tuple(row) for row in ledger.execute("SELECT id, ref, date, amount FROM transactions ORDER BY id")]
        for page in ([corrected[changed]] if split else corrected, corrected[::-1], whole):
            rows, _ = transaction_rows("account-a", page)
            assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 0
            assert [tuple(row) for row in ledger.execute("SELECT id, ref, date, amount FROM transactions ORDER BY id")] == saved
        independent = corrected[changed] | {"reference_number": "distinct-invoice", "entry_reference": "independent"}
        rows, _ = transaction_rows("account-a", [*whole, independent])
        assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 1


@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("reset", [False, True])
@pytest.mark.parametrize("sign", [-1, 1])
def test_reference_versions_share_statement_balance_unless_it_can_recur(sandbox, seed, reset, sign):
    import core

    whole = ambiguous_reference_statement(sign)
    credit, reversal, debit = (whole[index] | {"value_date": "2026-11-23", "transaction_date": "2026-11-23"}
                                for index in (0, 1, 4))
    other = credit | {"entry_reference": "changed-reference", "transaction_id": "another-lookup"}
    page = [credit, debit, other, debit]
    if reset:
        page.append(reversal)
    with closing(core.db()) as ledger:
        if seed:
            initial, _ = transaction_rows("account-a", [credit, debit])
            assert core.import_bank_rows(ledger, initial, require_fx=True)["imported"] == 2
        for response in (page, page[::-1]):
            rows, skipped = transaction_rows("account-a", response)
            result = core.import_bank_rows(ledger, rows, require_fx=True)
            assert skipped + result["ambiguous"] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions").fetchone()) == (
                (4, sign * 96, 380) if reset else (2, sign * 96, 142)
            )


@pytest.mark.parametrize("sign", [-1, 1])
def test_statement_proof_intersects_two_partly_dated_anchor_timelines(sign):
    whole = ambiguous_reference_statement(sign)
    whole[1]["value_date"] = None
    whole[5]["transaction_date"] = None
    for page in (whole * 2, (whole * 2)[::-1]):
        rows, warnings = _confirmed_statement_rows("account-a", page)
        assert warnings == 0
        assert len(rows) == 6
        assert sum(float(row["amount"]) for row in rows) == 205 * sign
        assert sum(row["description"] == "Kontoauszug prüfen" for row in rows) == 1


@pytest.mark.parametrize("sign", [-1, 1])
def test_proven_statement_keeps_movement_counts_without_provider_ids(sandbox, sign):
    import core

    whole = ambiguous_reference_statement(sign)
    bare = [row | {"entry_reference": None, "transaction_id": None} for row in whole]
    with closing(core.db()) as ledger:
        for page in (bare * 2, (bare * 2)[::-1], whole * 2):
            rows, skipped = _confirmed_statement_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, require_fx=True)
            assert skipped + result["ambiguous"] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions").fetchone()) == (
                6, sign * 205, 509,
            )


@pytest.mark.parametrize("sign", [-1, 1])
def test_legacy_statement_replay_keeps_categories_and_imports_independent_future_payment(sandbox, sign):
    import core

    whole = ambiguous_reference_statement(sign)
    with closing(core.db()) as ledger:
        rows, _ = _confirmed_statement_rows("account-a", whole * 2)
        assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 6
        # A historical review stores a reference-based proof without the
        # economic identity used by the current importer.
        ref, encoded = ledger.execute("SELECT review_key, alternatives FROM bank_statement_reviews").fetchone()
        historical = json.loads(encoded)
        historical.pop("economic")
        historical["proof"][0] = "reference-based-review-key"
        ledger.execute("UPDATE bank_statement_reviews SET review_key = ?, alternatives = ? WHERE review_key = ?",
                       ("legacy-review", json.dumps(historical), ref))
        for (booking_id,) in ledger.execute("SELECT id FROM transactions").fetchall():
            core.set_tx_category(ledger, booking_id, "einnahme_sonstige")
        saved = [tuple(row) for row in ledger.execute("SELECT id, ref, date, amount, category FROM transactions ORDER BY id")]
        later = whole[0] | {"booking_date": "2026-11-25", "transaction_date": "2026-11-25", "value_date": "2026-11-25",
                            "entry_reference": "new-payment", "transaction_id": "new", "reference_number": "INV-new",
                            "remittance_information": ["New payment"], "transaction_amount": {"amount": "7", "currency": "EUR"},
                            "balance_after_transaction": {"amount": str(212 * sign), "currency": "EUR"}}
        corrected = [row | {"entry_reference": row["entry_reference"] + "-corrected"} for row in whole]
        for index, page in enumerate((corrected * 2, (corrected * 2)[::-1])):
            rows, skipped = _confirmed_statement_rows("account-a", [*page, later])
            result = core.import_bank_rows(ledger, rows, require_fx=True)
            assert (result["imported"], skipped + result["ambiguous"]) == (1 - index, 0)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (7, 212 * sign)
        assert [tuple(row) for row in ledger.execute(
            "SELECT id, ref, date, amount, category FROM transactions WHERE description <> 'New payment' ORDER BY id",
        )] == saved


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("changes", [
    (3, "debtor_account"), (3, "reference_number"), (1, "balance_after_transaction"),
    (4, "balance_after_transaction"), (5, "balance_after_transaction"),
])
def test_statement_replay_handles_reference_corrections_with_missing_facts(sandbox, sign, changes):
    import core

    whole = ambiguous_reference_statement(sign)
    index, field = changes
    revised = [row.copy() for row in whole]
    revised[index] |= {field: None, "entry_reference": revised[index]["entry_reference"] + "-corrected"}
    with closing(core.db()) as ledger:
        rows, _ = _confirmed_statement_rows("account-a", whole * 2)
        assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 6
        stored = [tuple(row) for row in ledger.execute("SELECT id, ref, date, amount FROM transactions ORDER BY id")]
        for page in ([revised[index]], revised * 2, revised + whole, (revised + whole)[::-1]):
            rows, _ = _confirmed_statement_rows("account-a", page)
            assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 0
            assert [tuple(row) for row in ledger.execute("SELECT id, ref, date, amount FROM transactions ORDER BY id")] == stored


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("variant", ["ordinary", "rotated-identifiers", "later-closing", "undated-same-day"])
def test_scoped_statement_balance_constraints_resolve_sparse_observations(sign, variant):
    whole = ambiguous_reference_statement(sign)
    if variant == "ordinary":
        credit, fee = (whole[index] | {"reference_number": None, "debtor_account": None, "creditor_account": None,
                                     "value_date": "2026-11-23", "transaction_date": "2026-11-23"} for index in (0, 4))
        page = [credit, fee, credit | {"entry_reference": "changed-credit"}, fee]
    else:
        if variant == "rotated-identifiers":
            for index in (0, 2):
                whole[index]["entry_reference"] += f"-changed-{index}"
                whole[index]["transaction_id"] += f"-changed-{index}"
        else:
            whole[5] |= {"value_date": None, "transaction_date": None}
            if variant == "later-closing":
                whole[5]["booking_date"] = "2026-11-24"
        page = whole * 2
    for response in (page, page[::-1]):
        rows, warnings = _confirmed_statement_rows("account-a", response)
        neutral = sum(row["description"] == "Kontoauszug prüfen" for row in rows)
        total = sum(float(row["amount"]) for row in rows)
        if variant == "ordinary":
            assert (len(rows), total, neutral, warnings) == (2, sign * 96, 0, 0)
        elif variant == "undated-same-day":
            assert (len(rows), total, neutral, warnings) == (6, sign * 205, 1, 0)
            assert sorted(row["description"] for row in rows if float(row["amount"]) == 119 * sign) == [
                "Kontoauszug prüfen", "Rent", "Supplies",
            ]
        else:
            assert (len(rows), total, neutral, warnings) == (6, sign * 205, 1, 0)


@pytest.mark.parametrize("opening", [0, 119])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("rotated", [False, True])
def test_uncertain_statement_amount_is_never_booked_until_opening_established(sandbox, sign, opening, rotated):
    import core

    bare = ambiguous_reference_statement(sign)
    if rotated:
        for index in (0, 2):
            bare[index]["entry_reference"] += f"-changed-{index}"
            bare[index]["transaction_id"] += f"-changed-{index}"
    before = [row | {"booking_date": f"2026-11-{day}", "value_date": f"2026-11-{day}",
                     "transaction_date": f"2026-11-{day}", "entry_reference": f"opening-{day}",
                     "reference_number": f"prior-{day}", "transaction_id": f"opening-{day}",
                     "transaction_amount": {"amount": "10", "currency": "EUR"},
                     "balance_after_transaction": {"amount": str(sign * amount), "currency": "EUR"}}
              for row, day, amount in ((bare[0], 17, opening + 10), (bare[1], 18, opening))]
    with closing(core.db()) as ledger:
        for page in (bare, bare[::-1], bare * 2, (bare * 2)[::-1], [bare[2], bare[4]]):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
            assert tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions").fetchone()) == (
                5, sign * 86, 390,
            )
            pending = core.pending_bank_statement_amounts(ledger, "2026-11-01", "2026-11-30")
            assert [(entry["amount"], entry["currency"], entry["date"]) for entry in pending] == [
                (sign * 119, "EUR", "2026-11-23"),
            ]
        for page in (before + bare, (before + bare)[::-1], (before + bare) * 2, bare, bare * 2):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
                (8, sign * 205) if opening == 0 else (7, sign * 86)
            )
            assert core.pending_bank_statement_amounts(ledger, "2026-11-01", "2026-11-30") == []


@pytest.mark.parametrize("assigned", [False, True])
def test_unknown_opening_withdraws_only_untouched_legacy_neutral_booking(sandbox, assigned):
    import core

    bare = ambiguous_reference_statement()
    with closing(core.db()) as ledger:
        rows, _ = _confirmed_statement_rows("account-a", bare * 2)
        assert core.import_bank_rows(ledger, rows, require_fx=True)["imported"] == 6
        legacy = ledger.execute("SELECT id, ref FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone()
        if assigned:
            core.set_tx_category(ledger, legacy["id"], "einnahme_sonstige", "Imported statement checked")
        for page in (bare * 2, (bare * 2)[::-1]):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments)
            assert core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)["imported"] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == ((6, 205) if assigned else (5, 86))
            pending = core.pending_bank_statement_amounts(ledger)
            assert [row["state"] for row in pending] == ["protected" if assigned else "pending"]
        saved = ledger.execute("SELECT category, note FROM transactions WHERE id = ?", (legacy["id"],)).fetchone()
        assert saved is None if not assigned else tuple(saved) == ("einnahme_sonstige", "Imported statement checked")


@pytest.mark.parametrize("mixed_dates", [False, True])
def test_service_retries_pending_statement_and_books_only_after_proven_opening(sandbox, monkeypatch, mixed_dates):
    import core
    from hosted.bank_service import BankingService

    bare = ambiguous_reference_statement()
    if mixed_dates:
        bare[-1]["booking_date"] = "2026-11-24"
        complete = [row.copy() for row in bare]
        bare[3]["booking_date"] = bare[3]["value_date"] = bare[-1]["transaction_date"] = None
    source = bare
    monkeypatch.setattr(StubProvider, "transactions", lambda *_: source)
    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=StubProvider)
    service.save_credentials(APP_ID, b"fixture-key")
    begin = service.begin("login-a", "DE", BANK, "business")
    state = parse_qs(urlsplit(begin).query)["state"][0]
    service.finish("login-a", state, "fixture-code", "")
    now = datetime.now(timezone.utc)
    assert service.sync(now=now) == 5
    source = (bare * 2)[::-1]
    assert service.sync(force=True, now=now) == 0
    assert service.consents()[0]["last_synced"] is None
    source = [*bare[:2]]
    assert service.sync(force=True, now=now) == 0
    with closing(core.db()) as ledger:
        assert [row["amount"] for row in core.pending_bank_statement_amounts(ledger)] == [119]
    opening = bare[1] | {"booking_date": "2026-11-18", "value_date": "2026-11-18", "transaction_date": "2026-11-18",
                        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
                        "transaction_amount": {"amount": "0.01", "currency": "EUR"},
                        "balance_after_transaction": {"amount": "0", "currency": "EUR"}}
    source = [opening, *bare]
    assert service.sync(force=True, now=now) == 2
    assert service.sync(force=True, now=now) == 0
    if mixed_dates:
        assert service.consents()[0]["last_synced"] is None
        with closing(core.db()) as ledger:
            assert [row["amount"] for row in core.pending_bank_statement_amounts(ledger)] == [119]
        source = [opening, *complete]
        assert service.sync(force=True, now=now) == 0
    assert service.consents()[0]["last_synced"] == now.date().isoformat()
    with closing(core.db()) as ledger:
        assert core.pending_bank_statement_amounts(ledger) == []
        assert ledger.execute("SELECT count(*) FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone()[0] == 1


@pytest.mark.parametrize("confirmed_floor", [False, True])
def test_payments_shows_unbooked_amount_separately_in_hosted_period(sandbox, monkeypatch, confirmed_floor):
    import core
    from app import app

    observations = []
    statement = ambiguous_reference_statement()
    if confirmed_floor:
        statement[-1]["booking_date"] = "2026-11-24"
        statement[3]["booking_date"] = statement[3]["value_date"] = statement[-1]["transaction_date"] = None
        statement.insert(0, statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
            "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
            "balance_after_transaction": {"amount": "0", "currency": "EUR"},
        })
    rows, _ = transaction_rows("account-a", statement * 2, assessments=observations)
    with closing(core.db()) as ledger:
        core.import_bank_rows(ledger, rows, require_fx=True, assessments=observations)
    monkeypatch.setitem(app.config, "KLAR_HOSTED", True)
    monkeypatch.setitem(app.jinja_env.globals, "hosted_username", "Alex")
    client = app.test_client()
    page = client.get("/zahlungen?p=2026-11").get_data(as_text=True)
    assert ("6 Buchungen" if confirmed_floor else "5 Buchungen") in page
    assert ("205,00 €" if confirmed_floor else "86,00 €") in page
    assert "Möglicher Bankumsatz über 119,00 € vom 23.11.2026" in page
    assert "Nicht gebucht und nicht in den Summen enthalten" in page
    assert "Möglicher Bankumsatz" not in client.get("/zahlungen?p=2026-10").get_data(as_text=True)
    monkeypatch.setitem(app.config, "KLAR_HOSTED", False)
    assert "Möglicher Bankumsatz" not in client.get("/zahlungen?p=2026-11").get_data(as_text=True)


@pytest.mark.parametrize("missing_primary", [0, 2, 3])
@pytest.mark.parametrize("opening", [None, 0, 119])
def test_full_statement_uses_known_primary_period_when_one_report_omits_it(missing_primary, opening):
    bare = ambiguous_reference_statement()
    bare[missing_primary]["booking_date"] = None
    prior = [bare[1] | {"booking_date": "2026-11-18", "value_date": "2026-11-18", "transaction_date": "2026-11-18",
                       "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
                       "remittance_information": ["Opening"], "transaction_amount": {"amount": "10", "currency": "EUR"},
                       "balance_after_transaction": {"amount": str(opening), "currency": "EUR"}}] if opening is not None else []
    for page in (prior + bare, (prior + bare)[::-1], (prior + bare) * 2):
        assessments = []
        rows, _ = transaction_rows("account-a", page, assessments=assessments)
        disputed_period = [row for row in rows if row["description"] != "Opening"]
        assert (len(disputed_period), sum(float(row["amount"]) for row in disputed_period)) == ((6, 205) if opening == 0 else (5, 86))
        expected = "pending" if opening is None else "confirmed" if opening == 0 else "ruled_out"
        assert [assessment["state"] for assessment in assessments] == [expected]
        assert assessments[0]["date"] == "2026-11-23"
        if missing_primary == 3:
            supplies = next(row for row in disputed_period if row["description"] == "Supplies")
            assert (supplies["booked_day"], supplies["value_day"], supplies["transaction_day"]) == (
                None, "2026-11-22", "2026-11-22",
            )
            assert supplies["date"] == "2026-11-23"


@pytest.mark.parametrize("missing", [0, 3])
@pytest.mark.parametrize("delivery", ["partial", "complete", "legacy", "legacy-assigned", "legacy-closed", "legacy-destination-closed"])
def test_statement_period_uses_proven_booking_day_across_month_boundary(sandbox, missing, delivery):
    import core

    whole = [row | {"booking_date": "2026-12-01"} for row in ambiguous_reference_statement()]
    partial = [row | {"booking_date": None} if index == missing else row for index, row in enumerate(whole)]
    protected = delivery in {"legacy-assigned", "legacy-closed", "legacy-destination-closed"}
    with closing(core.db()) as ledger:
        target = None
        if delivery.startswith("legacy"):
            raw = [transaction_rows("account-a", [row])[0][0] for index, row in enumerate(partial) if index != 2]
            assert core.import_bank_rows(ledger, raw, require_fx=True)["imported"] == 5
            target = ledger.execute("SELECT id, ref, date FROM transactions WHERE date < '2026-12-01'").fetchone()
            if delivery == "legacy-assigned":
                core.set_tx_category(ledger, target["id"], "einnahme_sonstige", "Leave this booking intact")
            elif delivery.endswith("closed"):
                core.close_period("2026-12" if delivery == "legacy-destination-closed" else "2026-11")
        first = whole if delivery == "complete" else partial
        for response in (first, whole, partial[::-1], [whole[missing]], whole[::-1]):
            decisions = []
            rows, _ = transaction_rows("account-a", response, assessments=decisions)
            result = core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions)
            by_month = [tuple(row) for row in ledger.execute(
                "SELECT substr(date, 1, 7), count(*), sum(amount) FROM transactions GROUP BY 1 ORDER BY 1",
            )]
            if protected:
                assert by_month == [("2026-11", 1, 119), ("2026-12", 4, -33)]
                assert result["ambiguous"] > 0
            else:
                assert by_month == [("2026-12", 5, 86)]
            assert [row["amount"] for row in core.pending_bank_statement_amounts(ledger, "2026-12-01", "2026-12-31")] == [119]
        if target:
            assert ledger.execute("SELECT ref, date FROM transactions WHERE id = ?", (target["id"],)).fetchone()[:] == (
                target["ref"], target["date"] if protected else "2026-12-01",
            )


@pytest.mark.parametrize("currency, booking_day", [("EUR", "2026-12-01"), ("USD", "2026-11-23")])
@pytest.mark.parametrize("protection", [None, "assignment", "original period", "booking period"])
def test_first_explicit_booking_day_corrects_only_an_unassigned_fallback(sandbox, monkeypatch, currency, booking_day, protection):
    import core

    monkeypatch.setattr(core, "fx_rate", lambda _, __, ___, day: 1.2 if day == booking_day else 1.0)
    supplies = ambiguous_reference_statement()[3] | {
        "booking_date": None, "transaction_amount": {"amount": "119", "currency": currency},
    }
    with closing(core.db()) as ledger:
        initial, _ = transaction_rows("account-a", [supplies])
        core.import_bank_rows(ledger, initial, require_fx=True)
        before = ledger.execute("SELECT id, ref, date, amount_home FROM transactions").fetchone()
        assert tuple(before)[2:] == ("2026-11-22", 119)
        if protection == "assignment":
            core.set_tx_category(ledger, before["id"], "einnahme_sonstige", "Keep this entry")
        elif protection:
            core.close_period(booking_day[:7] if protection == "booking period" else "2026-11")
        for response in ([supplies | {"booking_date": booking_day}], [supplies]):
            rows, _ = transaction_rows("account-a", response)
            result = core.import_bank_rows(ledger, rows, require_fx=True)
            assert result["imported"] == 0
            actual = ledger.execute("SELECT id, ref, date, amount_home, booked_day FROM transactions "
                                    "JOIN bank_import_facts USING (ref)").fetchall()
            home = 142.8 if currency == "USD" else 119
            expected = tuple(before) if protection else (*tuple(before)[:2], booking_day, home)
            assert [tuple(row) for row in actual] == [(*expected, booking_day)]
            if response[0]["booking_date"]:
                assert bool(result["ambiguous"]) == bool(protection)


@pytest.mark.parametrize("direction", [-1, 1])
@pytest.mark.parametrize("before", [False, True])
def test_same_amount_outside_statement_interval_keeps_its_own_payment(sandbox, direction, before):
    import core

    whole = ambiguous_reference_statement(direction)
    partial = [row | {"booking_date": None} if i == 3 else row for i, row in enumerate(whole)]
    day = "2026-11-17" if before else "2026-11-27"
    independent = whole[0] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), day) | {
        "entry_reference": "other", "reference_number": "other", "transaction_id": "other",
        "remittance_information": ["Independent receipt"], "balance_after_transaction": None if before else
        {"amount": str(324 * direction), "currency": "EUR"},
    }
    with closing(core.db()) as ledger:
        for response in ([*partial, independent], [independent, *whole[::-1]], [independent]):
            decisions = []
            rows, _ = transaction_rows("account-a", response, assessments=decisions)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions)
            assert tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions").fetchone()) == (
                6, 205 * direction, 509,
            )
            assert [row["amount"] for row in core.pending_bank_statement_amounts(ledger)] == [119 * direction]
            assert ledger.execute("SELECT date FROM transactions WHERE description = 'Independent receipt'").fetchone()[0] == day


@pytest.mark.parametrize("missing", range(6))
@pytest.mark.parametrize("direction", [-1, 1])
def test_later_booking_checkpoint_settles_count_with_an_unplaced_typed_observation(sandbox, missing, direction):
    import core

    whole = ambiguous_reference_statement(direction)
    whole[-1]["booking_date"] = "2026-11-24"
    partial = [row | {"value_date": None, "transaction_date": None} if i == missing else row for i, row in enumerate(whole)]
    anchor = whole[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
        "entry_reference": "prior-balance", "reference_number": "prior-balance", "transaction_id": "prior-balance",
        "remittance_information": ["Prior balance"], "transaction_amount": {"amount": "10", "currency": "EUR"},
        "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    with closing(core.db()) as ledger:
        def sync(response):
            decisions = []
            rows, _ = transaction_rows("account-a", response, assessments=decisions)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions)

        sync(whole)
        assert [row["amount"] for row in core.pending_bank_statement_amounts(ledger)] == [119 * direction]
        for response in ([anchor, *partial], [*partial[::-1], anchor], [anchor, *whole], partial):
            sync(response)
            assert tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions "
                                        "WHERE date LIKE '2026-11-%'").fetchone()) == (6, 205 * direction, 509)
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("missing", [0, 1, 2, 4])
@pytest.mark.parametrize("opening", [0, 119])
@pytest.mark.parametrize("direction", [-1, 1])
def test_same_day_balances_settle_count_with_an_unplaced_typed_observation(sandbox, missing, opening, direction):
    import core

    whole = ambiguous_reference_statement(direction)
    partial = [row | {"value_date": None, "transaction_date": None} if i == missing else row
               for i, row in enumerate(whole)]
    anchor = whole[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
        "entry_reference": "prior-balance", "reference_number": "prior-balance", "transaction_id": "prior-balance",
        "remittance_information": ["Prior balance"], "transaction_amount": {"amount": "10", "currency": "EUR"},
        "balance_after_transaction": {"amount": str(opening * direction), "currency": "EUR"},
    }
    expected = (6, 205 * direction) if opening == 0 else (5, 86 * direction)
    with closing(core.db()) as ledger:
        for i, response in enumerate((partial, [anchor, *partial], [*partial[::-1], anchor], [anchor, *whole], partial)):
            decisions = []
            rows, _ = transaction_rows("account-a", response, assessments=decisions)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions)
            booked = tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions "
                                          "WHERE date LIKE '2026-11-%'").fetchone())
            pending = [row["amount"] for row in core.pending_bank_statement_amounts(ledger)]
            if i == 0:
                assert booked == (5, 86 * direction) and pending == [119 * direction]
            else:
                assert booked == expected and pending == []


@pytest.mark.parametrize("direction", [-1, 1])
@pytest.mark.parametrize("opening", [None, 0, 119])
@pytest.mark.parametrize("missing, split", [(0, False), (2, False), (3, False), (3, True)])
def test_later_closing_proves_statement_count_without_supplying_a_booking_day(sandbox, direction, opening, missing, split):
    import core

    whole = ambiguous_reference_statement(direction)
    whole[-1]["booking_date"] = "2026-11-24"
    partial = [row | {"booking_date": None} if i == missing else row.copy() for i, row in enumerate(whole)]
    if split:
        partial[missing]["value_date"] = None
        partial[1]["transaction_date"] = None
    independent_opening = [] if opening is None else [whole[1] | {
        **dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31"),
        "entry_reference": "prior", "reference_number": "prior", "transaction_id": "prior",
        "remittance_information": ["Opening"], "balance_after_transaction": {"amount": str(opening * direction), "currency": "EUR"},
    }]
    with closing(core.db()) as ledger:
        for i, response in enumerate(([*independent_opening, *partial], [*partial[::-1], *independent_opening],
                                      [*independent_opening, *whole], partial)):
            decisions = []
            rows, _ = transaction_rows("account-a", response, assessments=decisions)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions)
            total = tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions "
                                         "WHERE date LIKE '2026-11-%'").fetchone())
            assert total == ((6, 205 * direction, 509) if opening == 0 else (5, 86 * direction, 390))
            purposes = [row[0] for row in ledger.execute("SELECT description FROM transactions ORDER BY description")]
            assert purposes.count("Rent") == 1 and purposes.count("Kontoauszug prüfen") == int(opening == 0)
            assert [(row["amount"], row["state"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [(119 * direction, "pending")] if opening is None else []
            )
            if i == 0 and missing == 3:
                supplies = ledger.execute("SELECT date, booked_day, value_day, transaction_day FROM transactions "
                                          "JOIN bank_import_facts USING (ref) WHERE description = 'Supplies'").fetchone()
                assert tuple(supplies) == ("2026-11-22", None, None if split else "2026-11-22", "2026-11-22")


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("remainder", [False, True])
def test_proven_surplus_counts_only_in_a_period_covering_both_months(sandbox, monkeypatch, sign, late, remainder):
    import core
    from app import app

    complete = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement(sign)]
    complete[-1]["booking_date"] = "2026-12-01"
    partial = [row.copy() for row in complete]
    partial[3]["booking_date"] = None
    if remainder:
        partial[3]["value_date"] = partial[-1]["transaction_date"] = None
    if late:
        complete[3]["booking_date"] = "2026-12-01"
    opening = complete[1] | dict.fromkeys(("booking_date", "transaction_date", "value_date"), "2026-09-30") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        "remittance_information": ["Opening"], "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    monkeypatch.setitem(app.config, "KLAR_HOSTED", True)
    monkeypatch.setitem(app.jinja_env.globals, "hosted_username", "Alex")
    client = app.test_client()
    with closing(core.db()) as ledger:
        rent = None
        reserved = None
        assigned = None
        for page, dated in ((partial, False), (partial[::-1], False), (complete, True), (partial, True)):
            decisions = []
            rows, _ = transaction_rows("account-a", [opening, *page], assessments=decisions)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=decisions)
            if rent is None:
                initial = client.get("/zahlungen?p=2026-Q4").get_data(as_text=True)
                assert "6 Buchungen · 4. Quartal 2026 · 6 offen" in initial
                rent = tuple(ledger.execute("SELECT ref,id,date FROM transactions WHERE description = 'Rent'").fetchone())
                core.set_tx_category(ledger, rent[1], "einnahme_sonstige", "Checked named payment")
            assert tuple(ledger.execute("SELECT ref,id,date,category FROM transactions WHERE id = ?", (rent[1],)).fetchone()) == (
                *rent, "einnahme_sonstige",
            )
            periods = ledger.execute("SELECT substr(date,1,7), count(*), sum(amount) FROM transactions "
                                     "WHERE date >= '2026-11-01' GROUP BY 1 ORDER BY 1").fetchall()
            if dated:
                expected = [("2026-11", 4, sign * 96), ("2026-12", 2, sign * 109)] if late else [
                    ("2026-11", 5, sign * 215), ("2026-12", 1, sign * -10),
                ]
                assert [tuple(row) for row in periods] == expected
                settled = tuple(ledger.execute("SELECT id, ref, date, category FROM transactions "
                                               "JOIN bank_statement_reviews USING (ref) WHERE review_key = ?", (reserved,)).fetchone())
                assert settled[1] == reserved
                if assigned:
                    assert settled == (*assigned, "einnahme_sonstige")
                else:
                    assigned = settled[:3]
                    core.set_tx_category(ledger, settled[0], "einnahme_sonstige", "Checked settled receipt")
            else:
                assert [tuple(row) for row in periods] == [("2026-11", 4, sign * 96), ("2026-12", 1, sign * -10)]
                keys = [row[0] for row in ledger.execute("SELECT review_key FROM bank_statement_assessments WHERE state = 'unplaced'")]
                assert len(keys) == 1 and (reserved is None or keys == [reserved])
                reserved = keys[0]
                for start, end, covered in (("2026-11-30", "2026-12-01", 1), ("2026-11-15", "2026-11-30", 0),
                                            ("2026-12-01", "2026-12-05", 0)):
                    expected = [("unplaced", covered)] + ([("pending", 0)] if remainder else [])
                    assert [(row["state"], row["covered"]) for row in core.pending_bank_statement_amounts(ledger, start, end)] == expected
                assert core.pending_bank_statement_amounts(ledger, "2026-11-01", "2026-11-29") == []

            combined = client.get("/zahlungen?p=2026-Q4").get_data(as_text=True)
            assert "6 Buchungen" in combined and core.eur(205 * sign) in combined
            assert core.eur(357 if sign > 0 else 152) in combined
            assert core.eur(-152 if sign > 0 else -357) in combined
            assert ("Möglicher Bankumsatz" in combined) == (remainder and not dated)
            assert ("Buchungsmonat noch offen" in combined) is not dated
            if not dated:
                assert "In den Summen dieses Zeitraums enthalten" in combined
                for period in ("2026-11", "2026-12"):
                    single = client.get(f"/zahlungen?p={period}").get_data(as_text=True)
                    assert "Buchungsmonat noch offen" in single
                    assert "In den Summen dieses Zeitraums nicht enthalten" in single


@pytest.mark.parametrize("axis", ["value_date", "transaction_date"])
@pytest.mark.parametrize("opening", [None, 0, 119])
def test_secondary_order_cannot_override_posted_balance_chain(sandbox, axis, opening):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement()]
    statement[3]["booking_date"] = None
    statement[-1].update({"booking_date": "2026-12-01", axis: "2026-11-20"})
    if opening is not None:
        statement.insert(0, statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-09-30") | {
            "entry_reference": "prior", "reference_number": "prior", "transaction_id": "prior",
            "balance_after_transaction": {"amount": str(opening), "currency": "EUR"},
        })
    with closing(core.db()) as ledger:
        for page in (statement, statement[::-1], statement * 2):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions WHERE date >= '2026-11-01'").fetchone()) == (5, 86)
            assert ledger.execute("SELECT count(*) FROM transactions WHERE description = 'Rent'").fetchone()[0] == 1
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("pending", 119)] if opening is None else [("unplaced", 119)] if opening == 0 else []
            )


@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("missing", [0, 1, 2, 4, 5])
def test_unplaced_statement_reuses_corroborated_balance_on_resolution(sandbox, late, missing):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement()]
    statement[-1]["booking_date"] = "2026-12-01"
    opening = statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-09-30") | {
        "entry_reference": "prior", "reference_number": "prior", "transaction_id": "prior",
    }
    partial = [row | {"booking_date": None} if index == 3 else row for index, row in enumerate(statement)]
    completed = [row.copy() for row in statement]
    completed[3]["booking_date"] = "2026-12-01" if late else "2026-11-30"
    completed[missing]["balance_after_transaction"] = None
    with closing(core.db()) as ledger:
        for index, page in enumerate((partial, completed, completed[::-1], partial)):
            assessments = []
            rows, _ = transaction_rows("account-a", [opening, *page], assessments=assessments)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
            monthly = [tuple(row) for row in ledger.execute("SELECT substr(date,1,7),sum(amount) FROM transactions "
                                                           "WHERE date >= '2026-11-01' GROUP BY 1 ORDER BY 1")]
            if index == 0:
                assert monthly == [("2026-11", 96), ("2026-12", -10)]
                original = ledger.execute("SELECT id FROM transactions WHERE description='Rent'").fetchone()[0]
                core.set_tx_category(ledger, original, "einnahme_sonstige", "Checked receipt")
                if missing == 0 and not late:
                    original_report = [row for row in rows if row["description"] == "Rent"][0]
                    corrected = statement[0] | {"balance_after_transaction": {"amount": "120", "currency": "EUR"}}
                    changed_date = statement[0] | {"booking_date": "2026-12-02", "balance_after_transaction": None}
                    observed, _ = transaction_rows("account-a", [corrected], ledger=ledger)
                    assert observed[0]["balance_key"] != original_report["balance_key"]
                    unmatched, _ = transaction_rows("account-a", [changed_date], ledger=ledger)
                    assert unmatched[0]["booked_day"] == "2026-12-02" and unmatched[0]["balance_key"] is None
            else:
                expected = [("2026-11", 96), ("2026-12", 109)] if late else [("2026-11", 215), ("2026-12", -10)]
                assert monthly == expected
                assert core.pending_bank_statement_amounts(ledger) == []
                assert core.get_transaction(ledger, original)["category"] == "einnahme_sonstige"


def test_secondary_dates_cannot_make_a_same_day_balance_sequence_impossible():
    statement = ambiguous_reference_statement()
    statement[-1]["booking_date"] = "2026-11-24"
    statement[1]["value_date"] = statement[1]["transaction_date"] = "2026-11-24"
    opening = statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
        "entry_reference": "prior", "reference_number": "prior", "transaction_id": "prior",
    }
    for page in ([opening, *statement], [*statement[::-1], opening]):
        assessments = []
        rows, _ = transaction_rows("account-a", page, assessments=assessments)
        assert [entry["state"] for entry in assessments] == ["confirmed"]
        november = [row for row in rows if row["date"].startswith("2026-11")]
        assert len(november) == 6 and sum(float(row["amount"]) for row in november) == 205
        assert sum(row["description"] == "Rent" for row in november) == 1


@pytest.mark.parametrize("copies", [1, 2])
def test_statement_replay_keeps_the_callers_selected_rows(sandbox, copies):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement()]
    statement[-1]["booking_date"] = "2026-12-01"
    opening = [row | dict.fromkeys(("booking_date", "value_date", "transaction_date"), day) | {
        "entry_reference": day, "reference_number": day, "transaction_id": day,
        "transaction_amount": {"amount": "10", "currency": "EUR"},
        "balance_after_transaction": {"amount": str(amount), "currency": "EUR"},
    } for row, day, amount in ((statement[0], "2026-10-29", 10), (statement[1], "2026-10-30", 0))]
    partial = [row | {"booking_date": None} if index == 3 else row for index, row in enumerate(statement)]
    complete = [row | {"balance_after_transaction": None} if index == 0 else row for index, row in enumerate(statement)]
    with closing(core.db()) as ledger:
        for page, expected in ((partial, 5), (complete, 1), (complete[::-1], 0)):
            assessments = []
            selected = []
            for _ in range(copies):
                mapped, _ = transaction_rows("account-a", [*opening, *page], assessments=assessments)
                selected.extend(row for row in mapped if row["date"] >= "2026-11-01")
            result = core.import_bank_rows(ledger, selected, assessments=assessments, require_fx=True)
            assert result["imported"] == expected
            assert ledger.execute("SELECT count(*) FROM transactions WHERE date < '2026-11-01'").fetchone()[0] == 0
        assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (6, 205)


@pytest.mark.parametrize("cross_month", [False, True])
@pytest.mark.parametrize("balance", [0, 119])
def test_service_can_resolve_pending_amount_when_one_seen_balance_is_omitted(sandbox, monkeypatch, cross_month, balance):
    import core
    from hosted.bank_service import BankingService

    left, right = ("2026-11-30", "2026-12-01") if cross_month else ("2026-11-23", "2026-11-24")
    statement = [row | {"booking_date": left} for row in ambiguous_reference_statement()]
    statement[-1]["booking_date"] = right
    source = [row | {"booking_date": None} if i == 3 else row for i, row in enumerate(statement)]
    opening = statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        "balance_after_transaction": {"amount": str(balance), "currency": "EUR"},
    }

    class Provider(StubProvider):
        def transactions(self, *_):
            return source

    service = BankingService(sandbox, sandbox, SITE + "/api/bank/callback", client_factory=Provider)
    service.save_credentials(APP_ID, b"fixture-key")
    state = parse_qs(urlsplit(service.begin("login-a", "DE", BANK, "business")).query)["state"][0]
    service.finish("login-a", state, "fixture-code", "")
    now = datetime.now(timezone.utc)
    assert service.sync(now=now) == 5
    with closing(core.db()) as ledger:
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
    source = [opening, statement[0] | {"balance_after_transaction": None}, *statement[1:]]
    assert service.sync(force=True, now=now) == (2 if balance == 0 else 1)
    source = source[::-1]
    assert service.sync(force=True, now=now) == 0
    assert service.consents()[0]["last_synced"] == now.date().isoformat()
    with closing(core.db()) as ledger:
        actual = tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions WHERE date >= '2026-11-01'").fetchone())
        assert actual == ((6, 205) if balance == 0 else (5, 86))
        assert core.pending_bank_statement_amounts(ledger) == []


def test_statement_restore_keeps_other_fetch_assessments_for_the_same_account(sandbox):
    import core

    first = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement()]
    first[-1]["booking_date"] = "2026-12-01"
    opening = first[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
        "entry_reference": "previous", "reference_number": "previous", "transaction_id": "previous",
    }
    sparse = [row | {"booking_date": None} if index == 3 else row for index, row in enumerate(first)]
    completed = [row | {"balance_after_transaction": None} if index == 0 else row for index, row in enumerate(first)]
    january = [row | {field: row[field].replace("2026-11-", "2027-01-") for field in
                      ("booking_date", "value_date", "transaction_date")}
               | {field: "jan-" + row[field] for field in ("entry_reference", "reference_number", "transaction_id")}
               for row in ambiguous_reference_statement()]
    with closing(core.db()) as ledger:
        assessments = []
        rows, _ = transaction_rows("account-a", [opening, *sparse], assessments=assessments)
        core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
        for _ in range(2):
            decisions = []
            november, _ = transaction_rows("account-a", [opening, *completed], assessments=decisions)
            next_year, _ = transaction_rows("account-a", january, assessments=decisions)
            core.import_bank_rows(ledger, [*november, *next_year], require_fx=True, assessments=decisions)
            assert [(row["date"], row["amount"], row["state"]) for row in core.pending_bank_statement_amounts(ledger)] == [
                ("2027-01-23", 119, "pending"),
            ]


@pytest.mark.parametrize("late", [False, True])
@pytest.mark.parametrize("missing_witness", [None, 1, 5, "only changed", "only changed and unrelated", "older proof", "new balance"])
def test_overlapping_reply_reuses_only_witnesses_from_the_proven_statement(sandbox, late, missing_witness):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement()]
    statement[-1]["booking_date"] = "2026-12-01"
    opening = statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        "remittance_information": ["Opening checkpoint"],
    }
    partial = [row | {"booking_date": None} if i == 3 else row for i, row in enumerate(statement)]
    complete = [row | {"booking_date": "2026-12-01" if late else "2026-11-30"} if i == 3 else row
                for i, row in enumerate(statement) if i != missing_witness]
    unrelated = missing_witness == "only changed and unrelated"
    legacy = missing_witness == "older proof"
    if isinstance(missing_witness, str):
        complete = [complete[3]]
    if missing_witness == "new balance":
        complete[0]["balance_after_transaction"] = {"amount": "215", "currency": "EUR"}
    if unrelated:
        complete.append(statement[0] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-12-02") | {
            "entry_reference": "separate", "reference_number": "separate", "transaction_id": "separate",
            "remittance_information": ["Separate payment"],
            "balance_after_transaction": {"amount": "324", "currency": "EUR"},
        })
    with closing(core.db()) as ledger:
        def sync(page):
            assessments = []
            rows, _ = transaction_rows("account-a", page, ledger=None if legacy else ledger, assessments=assessments)
            return core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)

        assert sync([opening, *partial])["imported"] == 6
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("unplaced", 119)]
        if legacy:
            ledger.execute("UPDATE bank_statement_assessments SET details = json_remove(details, '$.overlap', '$.balances')")
        old = tuple(ledger.execute("SELECT id,ref,date FROM transactions WHERE description='Rent'").fetchone())
        core.set_tx_category(ledger, old[0], "einnahme_sonstige", "Checked statement")
        for page, new in ((complete, 1 + unrelated), (complete[::-1], 0), (partial, 0)):
            assert sync(page)["imported"] == new
            monthly = [tuple(row) for row in ledger.execute("SELECT substr(date,1,7),count(*),sum(amount) FROM transactions "
                                                           "WHERE date >= '2026-11-01' GROUP BY 1 ORDER BY 1")]
            extra = 119 if unrelated else 0
            assert monthly == ([("2026-11", 4, 96), ("2026-12", 2 + unrelated, 109 + extra)] if late else
                               [("2026-11", 5, 215), ("2026-12", 1 + unrelated, -10 + extra)])
            assert core.pending_bank_statement_amounts(ledger) == []
            assert tuple(ledger.execute("SELECT id,ref,date,category FROM transactions WHERE id=?", (old[0],)).fetchone()) == (
                *old, "einnahme_sonstige",
            )


def statement_overlap_fixture(offset, opening_balance, label, *, closing_day=None, balanced=False):
    def day(value):
        return (date.fromisoformat(value) + timedelta(days=offset)).isoformat()

    rows = ambiguous_reference_statement()
    if balanced:
        for row in rows[-2:]:
            row["transaction_amount"] = {"amount": "119", "currency": "EUR"}
            row["balance_after_transaction"] = {"amount": "0", "currency": "EUR"}
    for row in rows:
        row.update(booking_date=day("2026-11-30"), value_date=day(row["value_date"]),
                   transaction_date=day(row["transaction_date"]))
        for field in ("entry_reference", "transaction_id", "reference_number"):
            row[field] += label
        if balance := row["balance_after_transaction"]:
            row["balance_after_transaction"] = balance | {"amount": str(int(balance["amount"]) + opening_balance)}
        row["remittance_information"] = [f"{row['remittance_information'][0]} {label}"]
    rows[-1]["booking_date"] = closing_day or day("2026-12-01")
    opening = rows[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), day("2026-10-31")) | {
        "entry_reference": f"opening-{label}", "reference_number": f"opening-{label}", "transaction_id": f"opening-{label}",
        "remittance_information": [f"Opening {label}"],
    }
    placed = rows[3] | {"booking_date": rows[-1]["booking_date"]}
    rows[3]["booking_date"] = None
    return [opening, *rows], placed


@pytest.mark.parametrize("shape", [
    "combined", "reversed", "split", "full", "mixed", "selected", "unplaced sibling",
    "contradictory sibling", "shared checkpoint", "older proofs",
])
def test_overlapping_reply_places_each_confirmed_statement_independently(sandbox, shape):
    import core

    first, one = statement_overlap_fixture(-153, 0, "A")
    second, two = statement_overlap_fixture(0, 205, "B")
    if shape == "shared checkpoint":
        second[0] = first[-1]
    unrelated = two | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-12-02") | {
        "entry_reference": "different", "transaction_id": "different", "reference_number": "different",
        "remittance_information": ["Unrelated payment"],
        "transaction_amount": {"amount": "7", "currency": "EUR"},
        "balance_after_transaction": {"amount": "417", "currency": "EUR"},
    }
    with closing(core.db()) as ledger:
        def sync(page, selected=None):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments, ledger=ledger if selected is None else None)
            if selected is not None:
                rows = [row for row in rows if row["description"] in selected]
            return core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)["imported"]

        assert sync(first) == 6
        assert sync(second) == (5 if shape == "shared checkpoint" else 6)
        notices = [(row["date"], row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)]
        assert len(notices) == 2 and all(row[1:] == ("unplaced", 119) for row in notices)
        saved = [tuple(row) for row in ledger.execute(
            "SELECT id, ref, date FROM transactions WHERE description IN ('Rent A', 'Rent B') ORDER BY id",
        )]
        assert len(saved) == 2
        for id_, _, _ in saved:
            core.set_tx_category(ledger, id_, "einnahme_sonstige", "Checked payment")
        if shape == "older proofs":
            ledger.execute("UPDATE bank_statement_assessments SET details = json_remove(details, '$.overlap')")

        selected = None
        expected = 2
        if shape == "split":
            assert sync([one]) == 1
            page, expected = [two], 1
        elif shape == "reversed":
            page = [two, one]
        elif shape == "full":
            page = [*first[:4], one, *first[5:], *second[:4], two, *second[5:]]
        elif shape == "mixed":
            page = [one, *(two if index == 4 else row for index, row in enumerate(second)), unrelated]
            expected = 3
        elif shape == "selected":
            page, selected = [one, two, unrelated], {"Supplies A"}
            expected = 1
        elif shape == "unplaced sibling":
            page, expected = [one, second[4]], 1
        elif shape == "contradictory sibling":
            page, expected = [one, two, two | {"booking_date": "2026-11-30"}], 1
        elif shape == "shared checkpoint":
            page = [one, first[-1], two]
        else:
            page = [one, two]
        assert sync(page, selected) == expected
        assert sync(page[::-1], selected) == 0
        assert sync([first[4], second[4]]) == 0
        unresolved = shape in {"selected", "unplaced sibling", "contradictory sibling"}
        assert [(row["date"], row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
            notices[1:] if unresolved else []
        )
        monthly = [tuple(row) for row in ledger.execute(
            "SELECT substr(date,1,7),count(*),sum(amount) FROM transactions WHERE substr(date,1,7) "
            "IN ('2026-06','2026-07','2026-11','2026-12') GROUP BY 1 ORDER BY 1",
        )]
        december = (1, -10) if unresolved else (3, 116) if shape == "mixed" else (2, 109)
        assert monthly == [("2026-06", 4, 96), ("2026-07", 2, 109), ("2026-11", 4, 96), ("2026-12", *december)]
        for booking in saved:
            assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE id=?", (booking[0],)).fetchone()) == (
                *booking, "einnahme_sonstige", "Checked payment",
            )


@pytest.mark.parametrize("relation", ["touching", "equal", "nested"])
@pytest.mark.parametrize("shape", [
    "corrections", "full", "extra", "selected", "conflict", "split", "copied", "partial copies",
    "renewed fee", "renewed lookup", "absent lookup", "partial renewed",
])
def test_statement_corrections_are_owned_by_payment_evidence(sandbox, relation, shape):
    import core

    touching = relation == "touching"
    first, one = statement_overlap_fixture(0 if relation == "equal" else -30, 0, "A",
                                           closing_day="2026-11-30" if touching else "2026-12-01", balanced=not touching)
    second, two = statement_overlap_fixture(0, 205 if touching else 0, "B", balanced=not touching)
    second[0] = first[-1] if touching else first[0]
    extra = [
        one | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-11-30") | {
            "entry_reference": label, "transaction_id": label, "reference_number": label,
            "transaction_amount": {"amount": "7", "currency": "EUR"},
            "remittance_information": [label], "credit_debit_indicator": indicator,
            "balance_after_transaction": {"amount": str(balance + (205 if touching else 0)), "currency": "EUR"},
        }
        for label, indicator, balance in (("Other receipt", "CRDT", 7), ("Other debit", "DBIT", 0))
    ]

    with closing(core.db()) as ledger:
        def sync(page, selected=None):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments, ledger=ledger if selected is None else None)
            if selected is not None:
                rows = [row for row in rows if row["description"] == selected]
            return core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)["imported"]

        def input_page(page):
            if shape == "copied":
                return (page * 2)[::-1]
            if shape == "partial copies":
                return [*page[:-1], *page[2:]]
            if shape in {"renewed fee", "renewed lookup", "absent lookup", "partial renewed"}:
                copies = [row.copy() for row in page]
                for index, row in enumerate(copies):
                    if shape == "absent lookup":
                        del row["transaction_id"]
                    elif shape != "renewed fee" or index == len(copies) - 2:
                        row["transaction_id"] += "-new"
                return [*page, *copies] if shape != "partial renewed" else [*page[:-1], *copies[2:]]
            return page

        assert sync(input_page(first)) == 6
        assert [row["state"] for row in core.pending_bank_statement_amounts(ledger)] == ["unplaced"]
        assert sync(input_page(second)) == 5
        notices = {(row["date"], row["amount"], row["state"]) for row in core.pending_bank_statement_amounts(ledger)}
        assert [row["state"] for row in core.pending_bank_statement_amounts(ledger)].count("unplaced") == 2
        if relation == "equal":
            assert [tuple(row) for row in ledger.execute(
                "SELECT substr(date,1,7),count(*),sum(amount) FROM transactions "
                "WHERE description NOT LIKE 'Opening %' GROUP BY 1 ORDER BY 1",
            )] == [("2026-11", 8, 0), ("2026-12", 2, -238)]
        saved = [tuple(row) for row in ledger.execute(
            "SELECT id,ref,date FROM transactions WHERE description IN ('Rent A','Rent B') ORDER BY id",
        )]
        assert len(saved) == 2
        for id_, _, _ in saved:
            core.set_tx_category(ledger, id_, "einnahme_sonstige", "Reviewed")

        page = [one, two]
        selected = None
        if shape == "full":
            page = [*first[:4], one, *first[5:], *second[:4], two, *second[5:]]
        elif shape == "extra":
            page = [one, second[0], *extra, two]
        elif shape == "selected":
            selected = "Supplies A"
        elif shape == "conflict":
            page.append(two | {"booking_date": "2026-11-30"})
        kept = shape in {"selected", "conflict"}
        if shape == "split":
            assert sync([two]) == 1
            assert sync([one]) == 1
        else:
            assert sync(page, selected) == (1 if kept else 4 if shape == "extra" else 2)
            assert sync(page[::-1], selected) == 0
        assert sync([first[4], second[4]]) == 0

        months = [tuple(row) for row in ledger.execute(
            "SELECT substr(date,1,7),count(*),sum(amount) FROM transactions WHERE description NOT LIKE 'Opening %' "
            "GROUP BY 1 ORDER BY 1",
        )]
        added = 2 if shape == "extra" else 0
        if touching:
            assert months == [("2026-10", 4, 96), ("2026-11", 6 + added, 205),
                              ("2026-12", 1, -10) if kept else ("2026-12", 2, 109)]
        elif relation == "equal":
            assert months == [("2026-11", 8 + added, 0),
                              ("2026-12", 3, -119) if kept else ("2026-12", 4, 0)]
        else:
            assert months == [("2026-10", 4, 0), ("2026-11", 4 + added, 0),
                              ("2026-12", 3, -119) if kept else ("2026-12", 4, 0)]
        remaining = [(row["date"], row["amount"], row["state"]) for row in core.pending_bank_statement_amounts(ledger)]
        assert len(remaining) == int(kept) * (2 if touching else 1) and set(remaining) <= notices
        for payment in saved:
            assert tuple(ledger.execute("SELECT id,ref,date,category,note FROM transactions WHERE id=?", (payment[0],)).fetchone()) == (
                *payment, "einnahme_sonstige", "Reviewed",
            )


@pytest.mark.parametrize("absent_entry", ["fee", "all", "fee without payer", "fee without invoice"])
@pytest.mark.parametrize("lookup, paginated, extra_count", [
    ("same", False, 1), ("renewed", False, 1), ("absent", False, 1),
    ("renewed", True, 1), ("absent", True, 1), ("renewed", True, 2),
])
def test_overlapping_pages_keep_corroborated_bookings_without_an_entry_reference(sandbox, absent_entry, lookup, paginated, extra_count):
    import core

    def omit_entry(row, name):
        if absent_entry != "all" and name != "Fee":
            return row
        missing = {"entry_reference"}
        if absent_entry == "fee without payer":
            missing.update(("debtor_account", "creditor_account"))
        if absent_entry == "fee without invoice":
            missing.update(("reference_number", "reference_number_schema"))
        return {key: value for key, value in row.items() if key not in missing}

    def fixture(label):
        reports, correction = statement_overlap_fixture(0, 0, label, balanced=True)
        return [omit_entry(row, row["remittance_information"][0].rsplit(" ", 1)[0]) for row in reports], omit_entry(correction, "Supplies")

    first, one = fixture("A")
    second, two = fixture("B")
    if absent_entry == "fee without invoice":
        # A known different payee establishes the separate fee in the second statement.
        second[-2]["creditor_account"] = {"iban": "DE00PAYEEB"}
    second[0] = first[0]
    pages = []

    class PaginatedBank(StubProvider):
        def request(self, method, path, *, query=None, data=None):
            index = int(query.get("continuation_key", "0"))
            result = {"transactions": pages[index]}
            if index + 1 < len(pages):
                result["continuation_key"] = str(index + 1)
            return result

    def overlapping_pages(reports):
        copies = [row.copy() for row in reports]
        for row in copies:
            if lookup == "renewed":
                row["transaction_id"] += "-later"
            elif lookup == "absent":
                del row["transaction_id"]
        if paginated:
            pages[:] = [reports, copies]
            return list(PaginatedBank(APP_ID, b"fixture-key").transactions(ACCOUNT, None, "2026-12-01"))
        return [*reports, *copies]

    with closing(core.db()) as ledger:
        def sync(reports):
            assessments = []
            rows, _ = transaction_rows("account-a", reports, assessments=assessments, ledger=ledger)
            return core.import_bank_rows(ledger, rows, require_fx=True, auto_match=False, assessments=assessments)["imported"]

        assert sync(overlapping_pages(first)) == 6
        assert sync(overlapping_pages(second)[::-1]) == 5
        assert sync(first) == sync(second[::-1]) == 0

        def totals():
            return [tuple(row) for row in ledger.execute(
                "SELECT substr(date,1,7),count(*),sum(amount) FROM transactions "
                "WHERE date >= '2026-11-01' GROUP BY 1 ORDER BY 1",
            )]

        assert totals() == [("2026-11", 8, 0), ("2026-12", 2, -238)]
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("unplaced", 119)] * 2
        assert sync(overlapping_pages([one, two])) == 2
        assert core.pending_bank_statement_amounts(ledger) == []
        categorized = ledger.execute("SELECT id FROM transactions WHERE description='Supplies A' AND date='2026-12-01'").fetchone()[0]
        core.set_tx_category(ledger, categorized, "einnahme_sonstige", "Checked payment")

        def bookings():
            return [tuple(row) for row in ledger.execute("SELECT id,ref,date,amount,description,category,note FROM transactions ORDER BY id")]

        booked = bookings()
        assert sync(overlapping_pages([two, one] * 2) if paginated else [two, one]) == 0
        assert core.pending_bank_statement_amounts(ledger) == []
        assert bookings() == booked
        full = [*first[:4], one, *first[5:], *second[:4], two, *second[5:]]
        assert sync(overlapping_pages(full)[::-1]) == 0
        assert bookings() == booked
        assert totals() == [("2026-11", 8, 0), ("2026-12", 4, 0)]
        assert core.pending_bank_statement_amounts(ledger) == []
        if paginated:
            extra_count = extra_count if absent_entry == "all" else 1
            new_day = "2026-12-01" if absent_entry == "all" else "2026-12-02"
            additional = one | dict.fromkeys(("booking_date", "value_date", "transaction_date"), new_day) | {
                "reference_number": "separate-december-receipt",
                "transaction_id": "additional",
                "remittance_information": ["Separate December receipt"],
                "balance_after_transaction": {"amount": "119", "currency": "EUR"},
            }
            checkpoint = first[-1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-12-03") | {
                "reference_number": "december-checkpoint",
                "transaction_id": "december-checkpoint",
                "transaction_amount": {"amount": "23", "currency": "EUR"},
                "balance_after_transaction": {"amount": str(119 * extra_count - 23), "currency": "EUR"},
            }
            if absent_entry == "all":
                assert sync(overlapping_pages([one, two, additional])) == 1
                assert sync(overlapping_pages([additional, two, one])[::-1]) == 0
                assert totals() == [("2026-11", 8, 0), ("2026-12", 5, 119)]
                assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("pending", 119)]
                assert sync(overlapping_pages([*full, additional, checkpoint])) == extra_count
            else:
                assert sync(overlapping_pages([one, two, additional, checkpoint])) == 2
            assert sync(overlapping_pages([checkpoint, additional, two, one])) == 0
            assert totals() == [("2026-11", 8, 0), ("2026-12", 5 + extra_count, 119 * extra_count - 23)]
            assert bookings()[:len(booked)] == booked
            assert core.pending_bank_statement_amounts(ledger) == []


@pytest.mark.parametrize("changed", ["fee", "later rent"])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("same_day", [False, True])
@pytest.mark.parametrize("anchored", [False, True])
def test_secondary_order_does_not_establish_a_surplus_or_its_purpose(sandbox, changed, sign, same_day, anchored):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement(sign)]
    statement[-1]["booking_date"] = "2026-11-30" if same_day else "2026-12-01"
    if changed == "fee":
        statement[4].update(value_date="2026-11-20", transaction_date="2026-11-21")
    else:
        statement[2].update(value_date="2026-11-23", transaction_date="2026-11-23")
    if anchored:
        statement.insert(0, statement[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-10-31") | {
            "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        })
    with closing(core.db()) as ledger:
        for page in (statement, statement[::-1], statement * 2):
            assessments = []
            rows, _ = transaction_rows("account-a", page, ledger=ledger, assessments=assessments)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
            actual = tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions WHERE date >= '2026-11-01'").fetchone())
            assert actual == ((6, 205 * sign) if anchored else (5, 86 * sign))
            assert ledger.execute("SELECT count(*) FROM transactions WHERE description='Kontoauszug prüfen'").fetchone()[0] == int(anchored)
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [] if anchored else [("pending", 119 * sign)]
            )


def test_confirmed_ambiguous_year_boundary_is_counted_only_in_covering_range(sandbox, monkeypatch):
    import core
    from app import app

    rows = ambiguous_reference_statement()
    for row in rows:
        row["booking_date"] = "2026-12-31"
        row["value_date"] = row["value_date"].replace("2026-11-", "2026-12-")
        row["transaction_date"] = row["transaction_date"].replace("2026-11-", "2026-12-")
    rows[3]["booking_date"] = None
    rows[-1]["booking_date"] = "2027-01-01"
    opening = rows[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-09-30") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        "remittance_information": ["Opening"], "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    assessments = []
    mapped, _ = transaction_rows("account-a", [opening, *rows], assessments=assessments)
    with closing(core.db()) as ledger:
        core.import_bank_rows(ledger, [row for row in mapped if row["description"] != "Opening"],
                              require_fx=True, assessments=assessments)
        assert len(core.list_ledger(ledger, "2026-12-01", "2027-01-31")) == 5
    monkeypatch.setitem(app.config, "KLAR_HOSTED", True)
    monkeypatch.setitem(app.jinja_env.globals, "hosted_username", "Alex")
    client = app.test_client()
    joint = client.get("/zahlungen?p=all").get_data(as_text=True)
    assert "6 Buchungen · Alle Jahre · 6 offen" in joint and "205,00 €" in joint
    for year, count in ((2026, 4), (2027, 1)):
        single = client.get(f"/zahlungen?p={year}").get_data(as_text=True)
        assert f"{count} Buchungen · Gesamtes Jahr {year}" in single
        assert "Buchungsmonat noch offen" in single
        assert "In den Summen dieses Zeitraums nicht enthalten" in single


def test_unplaced_foreign_currency_waits_for_the_confirmed_days_fx_rate(sandbox, monkeypatch):
    import core
    from app import app

    confirmed = [row | {"booking_date": "2026-11-30", "transaction_amount": row["transaction_amount"] | {"currency": "USD"},
                        "balance_after_transaction": balance | {"currency": "USD"} if (balance := row["balance_after_transaction"]) else None}
                 for row in ambiguous_reference_statement()]
    confirmed[-1]["booking_date"] = "2026-12-01"
    partial = [*confirmed[:3], confirmed[3] | {"booking_date": None}, *confirmed[4:]]
    opening = confirmed[1] | dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-09-30") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
    }
    rate_lookups = []
    rate_missing = False

    def rates(_, base, quote, day):
        rate_lookups.append((base, quote, day))
        if rate_missing:
            raise ValueError("Fixture rate is unavailable")
        return 1.0

    monkeypatch.setattr(core, "fx_rate", rates)
    monkeypatch.setitem(app.config, "KLAR_HOSTED", True)
    monkeypatch.setitem(app.jinja_env.globals, "hosted_username", "Alex")
    client = app.test_client()
    with closing(core.db()) as ledger:
        def sync(page):
            assessments = []
            mapped, _ = transaction_rows("account-a", [opening, *page], assessments=assessments)
            return core.import_bank_rows(ledger, mapped, require_fx=True, assessments=assessments)

        sync(partial)
        rate_lookups.clear()
        page = client.get("/zahlungen?p=2026-Q4").get_data(as_text=True)
        assert "6 Buchungen" in page and "86,00 €" in page
        assert "Bestätigter Bankumsatz über 119,00 USD" in page
        assert "Der Wechselkurs für die Summe steht noch aus" in page
        assert rate_lookups == []
        rate_missing = True
        assert sync(confirmed)["deferred"] == 1
        assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == [("unplaced", 119)]
        rate_missing = False
        assert sync(confirmed)["imported"] == 1
        assert core.pending_bank_statement_amounts(ledger) == []
        page = client.get("/zahlungen?p=2026-Q4").get_data(as_text=True)
        assert "6 Buchungen" in page and "205,00 €" in page


@pytest.mark.parametrize("protection", [None, "assigned", "2026-11", "2026-12"])
def test_month_unassigned_replaces_only_untouched_legacy_guess(sandbox, protection):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement()]
    statement[3]["booking_date"] = None
    statement[-1]["booking_date"] = "2026-12-01"
    opening = statement[1] | dict.fromkeys(("booking_date", "transaction_date", "value_date"), "2026-09-30") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        "remittance_information": ["Opening"], "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    with closing(core.db()) as ledger:
        legacy = [transaction_rows("account-a", [row])[0][0] for row in [opening, *statement]]
        assert core.import_bank_rows(ledger, legacy, require_fx=True)["imported"] == 7
        select = "SELECT ref,id,date,category FROM transactions JOIN bank_import_facts USING (ref) WHERE value_day = ?"
        secure = tuple(ledger.execute(select, ("2026-11-19",)).fetchone())
        guess = tuple(ledger.execute(select, ("2026-11-21",)).fetchone())
        if protection == "assigned":
            core.set_tx_category(ledger, guess[1], "einnahme_sonstige", "Checked manually")
        elif protection:
            core.close_period(protection)
        for page in ([opening, *statement], [*statement[::-1], opening]):
            assessments = []
            mapped, _ = transaction_rows("account-a", page, assessments=assessments)
            assert core.import_bank_rows(ledger, mapped, require_fx=True, assessments=assessments)["imported"] == 0
            dated = tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions WHERE date >= '2026-11-01'").fetchone())
            assert dated == ((6, 205) if protection else (5, 86))
            notices = core.pending_bank_statement_amounts(ledger, "2026-11-01", "2026-12-31")
            assert [(item["state"], item["amount"], item["covered"]) for item in notices] == [
                ("protected", 119, 0) if protection else ("unplaced", 119, 1),
            ]
            assert tuple(ledger.execute(select, ("2026-11-19",)).fetchone()) == secure
            retained = ledger.execute(select, ("2026-11-21",)).fetchone()
            if protection == "assigned":
                assert tuple(retained) == (*guess[:3], "einnahme_sonstige")
            elif protection:
                assert tuple(retained) == guess
            else:
                assert retained is None


@pytest.mark.parametrize("sign", [-1, 1])
def test_mixed_dates_book_proven_floor_and_review_one_possible_receipt(sandbox, sign):
    import core

    complete = ambiguous_reference_statement(sign)
    complete[-1]["booking_date"] = "2026-11-24"
    partial = [row.copy() for row in complete]
    partial[3]["booking_date"] = partial[3]["value_date"] = partial[-1]["transaction_date"] = None
    opening = complete[1] | dict.fromkeys(("booking_date", "transaction_date", "value_date"), "2026-10-31") | {
        "entry_reference": "opening", "reference_number": "opening", "transaction_id": "opening",
        "remittance_information": ["Opening"], "balance_after_transaction": {"amount": "0", "currency": "EUR"},
    }
    with closing(core.db()) as ledger:
        original = None
        for i, page in enumerate((partial, [opening, *partial], [*partial[::-1], opening], partial,
                                  [opening, *complete], [opening, *partial])):
            statements = []
            rows, _ = transaction_rows("account-a", page, assessments=statements)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=statements)
            total = tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions "
                                         "WHERE date LIKE '2026-11-%'").fetchone())
            assert total == ((5, 86 * sign, 390) if i == 0 else (6, 205 * sign, 509))
            pending = core.pending_bank_statement_amounts(ledger)
            assert [(row["amount"], row["state"]) for row in pending] == ([(119 * sign, "pending")] if i < 4 else [])
            rent = ledger.execute("SELECT id, ref, category FROM transactions WHERE description = 'Rent'").fetchall()
            assert len(rent) == 1
            if original:
                assert tuple(rent[0]) == (*original, "einnahme_sonstige")
                assert ledger.execute("SELECT count(*) FROM transactions WHERE description = 'Kontoauszug prüfen'").fetchone()[0] == 1
            else:
                original = tuple(rent[0])[:2]
                core.set_tx_category(ledger, original[0], "einnahme_sonstige", "Checked opening")


@pytest.mark.parametrize("protection", [None, "assigned", "closed"])
def test_one_page_replay_corrects_only_an_untouched_legacy_named_extra(sandbox, protection):
    import core

    bare = ambiguous_reference_statement()
    with closing(core.db()) as ledger:
        legacy = [transaction_rows("account-a", [tx])[0][0] for tx in bare]
        assert core.import_bank_rows(ledger, legacy, require_fx=True)["imported"] == 6
        id_ = ledger.execute("SELECT id FROM transactions JOIN bank_import_facts USING (ref) "
                             "WHERE description = 'Rent' AND value_day = '2026-11-21'").fetchone()[0]
        if protection == "assigned":
            core.set_tx_category(ledger, id_, "einnahme_sonstige", "Checked manually")
        if protection == "closed":
            core.close_period("2026-11")
        figures = core.figures_for_period(ledger, core.load_config(), "2026-11")
        for page in (bare, (bare * 2)[::-1]):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments)
            assert core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)["imported"] == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount), sum(abs(amount)) FROM transactions").fetchone()) == (
                (6, 205, 509) if protection else (5, 86, 390)
            )
            assert [row["state"] for row in core.pending_bank_statement_amounts(ledger)] == ["protected" if protection else "pending"]
            assert core.figures_for_period(ledger, core.load_config(), "2026-11") == figures
        if protection == "assigned":
            assert tuple(ledger.execute("SELECT category, note FROM transactions WHERE id = ?", (id_,)).fetchone()) == (
                "einnahme_sonstige", "Checked manually",
            )


@pytest.mark.parametrize("purpose", ["Rent", "Supplies"])
@pytest.mark.parametrize("sign", [-1, 1])
def test_secondary_checkpoints_do_not_assign_the_source_of_a_proven_receipt(sandbox, purpose, sign):
    import core

    bare = ambiguous_reference_statement(sign)

    def anchor(day, change, balance, label):
        iso = f"2026-11-{day}"
        return bank_row(booking_date="2026-11-18" if day == 18 else "2026-11-23", value_date=iso, transaction_date=iso,
                        entry_reference=label, reference_number=label, transaction_id=label, remittance_information=[label],
                        credit_debit_indicator="CRDT" if sign * change > 0 else "DBIT",
                        transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
                        balance_after_transaction={"amount": str(sign * balance), "currency": "EUR"})

    with closing(core.db()) as ledger:
        def sync(page):
            assessments = []
            rows, _ = transaction_rows("account-a", page, assessments=assessments)
            return core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)["imported"]

        assert sync(bare) == 5
        assert len(core.pending_bank_statement_amounts(ledger)) == 1
        baseline = 119 if purpose == "Rent" else 0
        proven = [anchor(18, -10, 0, "Opening"), *bare, anchor(21, -1, baseline - 1, "Checkpoint"),
                  anchor(22, 1, baseline, "Return")]
        assert sync(proven) == 4
        assert sync((proven * 2)[::-1]) == 0
        assert sync(bare) == 0
        assert core.pending_bank_statement_amounts(ledger) == []
        named = [row[0] for row in ledger.execute("SELECT description FROM transactions WHERE amount = ?", (119 * sign,))]
        assert sorted(named) == ["Kontoauszug prüfen", "Rent", "Supplies"]
        assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (9, 195 * sign)

    # When the checkpoints are actual booking days, the source can be known:
    # Rent either happens twice with the reversal between those days, or
    # both Rent observations precede the only movement that lets Rent recur.
    days = (19, 20, 21, 22, 22, 23) if purpose == "Rent" else (19, 21, 19, 21, 21, 23)
    ordered = [row | {"booking_date": f"2026-11-{day}"} for row, day in zip(bare, days)]
    rows, warnings = _confirmed_statement_rows("account-a", ordered)
    assert (len(rows), sum(float(row["amount"]) for row in rows), warnings) == (6, 205 * sign, 0)
    assert sorted(row["description"] for row in rows if float(row["amount"]) == 119 * sign) == sorted((
        "Rent", "Supplies", purpose,
    ))


@pytest.mark.parametrize("same_day", [False, True])
@pytest.mark.parametrize("sign", [-1, 1])
def test_opening_balance_does_not_make_an_intra_day_balance_the_close(sandbox, same_day, sign):
    import core

    statement = [row | {"booking_date": "2026-11-30"} for row in ambiguous_reference_statement(sign)]
    statement[-1].update(booking_date="2026-11-30" if same_day else "2026-12-01",
                         balance_after_transaction={"amount": str(86 * sign), "currency": "EUR"})
    with closing(core.db()) as ledger:
        for known_opening in (False, True, True):
            assessments = []
            if known_opening:
                rows, _ = _confirmed_statement_rows("account-a", statement[::-1], assessments=assessments)
            else:
                rows, _ = transaction_rows("account-a", statement, assessments=assessments)
            core.import_bank_rows(ledger, rows, require_fx=True, assessments=assessments)
            assert tuple(ledger.execute("SELECT count(*),sum(amount) FROM transactions").fetchone()) == (5, 86 * sign)
            assert [(row["state"], row["amount"]) for row in core.pending_bank_statement_amounts(ledger)] == (
                [("pending", 119 * sign)] if not known_opening or same_day else []
            )


@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("variant", ["missing-secondary", "missing-primary", "unanchored", "parallel", "one-witness"])
@pytest.mark.parametrize("seed", [True, False])
def test_reported_balance_order_resolves_missing_dates_and_coupled_versions(sandbox, sign, variant, seed):
    import core

    def movement(day, change, balance, ref, *, booking_day=None, value_day=None, lookup=None):
        change *= sign
        return bank_row(booking_date=booking_day or f"2026-11-{day:02}",
                        transaction_date=f"2026-11-{day:02}", value_date=value_day or f"2026-11-{day:02}",
                        transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
                        credit_debit_indicator="CRDT" if change > 0 else "DBIT",
                        balance_after_transaction={"currency": "EUR", "amount": str(sign * balance)},
                        debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"},
                        entry_reference=ref, reference_number=ref, transaction_id=lookup or ref,
                        remittance_information=[ref])

    first = movement(19, 119, 119, "rent", lookup="rent-a")
    second = movement(21, 119, 119, "rent", lookup="rent-b")
    reversal = movement(20, -119, 0, "reversal")
    opening = movement(18, 10, 0, "opening")
    fee = movement(23, -23, 96, "fee")
    if variant == "missing-secondary":
        first["booking_date"] = second["booking_date"] = reversal["booking_date"] = "2026-11-22"
        reversal["value_date"] = reversal["transaction_date"] = None
    elif variant in {"missing-primary", "unanchored"}:
        first["transaction_date"] = second["transaction_date"] = "2026-11-18"
        first["value_date"] = second["value_date"] = "2026-11-18"
        reversal["booking_date"] = reversal["transaction_date"] = None
    adjustments = [reversal]
    expected = (5, 106, False)
    batch = [opening, first, reversal, second, fee]
    if variant in {"parallel", "one-witness"}:
        for row in (first, second, fee):
            row["booking_date"] = "2026-11-23"
        first["value_date"] = second["value_date"] = "2026-11-17"
        adjustments = [
            movement(20, 20, 139, "witness", booking_day="2026-11-23", value_day="2026-11-19", lookup="witness-a"),
            movement(20, 20, 139, "witness", booking_day="2026-11-23", value_day="2026-11-20", lookup="witness-b"),
            movement(20, -139, 0, "clear", booking_day="2026-11-23"),
        ]
        if variant == "parallel":
            adjustments.append(movement(20, -20, 119, "return", booking_day="2026-11-23"))
        batch = [first, *adjustments, second, fee]
        expected = (7 if variant == "parallel" else 5, 96, False)
    elif variant == "unanchored":
        batch.remove(opening)
        expected = (3 if seed else 2, -23 if seed else -142, True)

    with closing(core.db()) as ledger:
        def sync(rows):
            mapped, skipped = transaction_rows("account-a", rows)
            result = core.import_bank_rows(ledger, mapped, auto_match=False, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        saved = None
        if seed:
            assert sync([first])[0] == 1
            saved = tuple(ledger.execute("SELECT id, ref, date FROM transactions WHERE description = 'rent'").fetchone())
            core.set_tx_category(ledger, saved[0], "einnahme_sonstige")
        for page in (batch[::-1] if seed else batch, batch if seed else batch[::-1]):
            _, warnings = sync(page)
            assert bool(warnings) == expected[2]
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
                expected[0], expected[1] * sign,
            )
            if saved:
                assert tuple(ledger.execute(
                    "SELECT id, ref, date, category FROM transactions WHERE id = ?", (saved[0],),
                ).fetchone()) == (*saved, "einnahme_sonstige")


@pytest.mark.parametrize("scenario,stored", [
    ("shifted", "new"), ("shifted", "early"), ("shifted", "alternate"),
    ("shifted-late", "new"), ("shifted-late", "early"), ("shifted-late", "alternate"),
    ("same-day", "new"), ("same-day", "early"), ("same-day", "late"),
    ("different-days", "new"), ("different-days", "early"),
    ("repeated", "new"), ("repeated", "early"), ("repeated-separate-days", "new"),
    ("four", "new"), ("corrections", "new"),
])
@pytest.mark.parametrize("direction", [-1, 1])
@pytest.mark.parametrize("lookup", [False, True])
def test_statement_subject_cohort_respects_cardinality_and_posting_date(sandbox, scenario, stored, direction, lookup):
    import core

    def movement(day, amount, balance, ref, lookup_id=None):
        amount *= direction
        booked_day = 26 if ref == "rent" and scenario in {"same-day", "repeated", "corrections", "four"} else day
        return bank_row(booking_date=f"2026-11-{booked_day:02}", value_date=f"2026-11-{day:02}",
                        transaction_date=f"2026-11-{day:02}", entry_reference=ref, reference_number=ref,
                        transaction_id=(lookup_id or ref) if lookup else None, remittance_information=[ref],
                        debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"},
                        transaction_amount={"amount": str(abs(amount)), "currency": "EUR"},
                        credit_debit_indicator="CRDT" if amount > 0 else "DBIT",
                        balance_after_transaction={"amount": str(direction * balance), "currency": "EUR"})

    first = movement(19, 119, 119, "rent", "rent-a")
    second = movement(21, 119, 119, "rent", "rent-a" if scenario.startswith("shifted") else "rent-b")
    third = movement(23 if scenario.startswith("repeated") else 22, 119, 119, "rent", "rent-c")
    reversal = movement(20, -119, 0, "reversal")
    fee = movement(24, -23, 96, "fee")
    opening = movement(18, 10, 0, "opening")
    if scenario in {"shifted", "corrections"}:
        fee = movement(20, -23, 96, "fee")
        batch = [opening, first, fee, second] + ([third] if scenario == "corrections" else [])
        count, net, warn = 3, 106, False
    elif scenario == "shifted-late":
        opening = movement(18, 10, 119, "opening")
        fee = movement(20, -119, 0, "fee")
        batch = [opening, first, fee, second]
        count, net, warn = 3, 10, False
    elif scenario.startswith("repeated"):
        next_reversal = movement(22, -119, 0, "next reversal")
        batch = [first, reversal, second, next_reversal, third, fee]
        count, net, warn = 6, 96, False
    else:
        batch = [first, reversal, second, third, fee]
        if scenario == "four":
            batch.insert(-1, movement(23, 119, 119, "rent", "rent-d"))
        count, net, warn = (3, -23, True) if scenario == "different-days" else (4, 96, True)

    with closing(core.db()) as ledger:
        def sync(page):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        if stored == "early":
            assert sync([first]) == (1, 0)
        elif stored == "late":
            assert sync([first, reversal, third, fee]) == (4, 0)
        elif stored == "alternate":
            assert sync([second]) == (1, 0)
        if (scenario, stored) in {("shifted", "alternate"), ("shifted-late", "early")}:
            warn = True
        rent_rows = "SELECT id, ref, date FROM transactions WHERE description = 'rent' ORDER BY id"
        saved = [tuple(row) for row in ledger.execute(rent_rows)]
        for booking_id, _, _ in saved:
            core.set_tx_category(ledger, booking_id, "einnahme_sonstige")
        duplicates = [first | {"balance_after_transaction": None}, *batch, batch[-1],
                      second | {"reference_number": None}]
        pages = (batch, batch[::-1], duplicates) if not lookup else (duplicates, batch[::-1], batch)
        for page in pages:
            _, warnings = sync(page)
            assert bool(warnings) == warn
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (count, net * direction)
            for booking_id, booking_ref, booked_day in saved:
                assert tuple(ledger.execute(
                    "SELECT id, ref, date, category FROM transactions WHERE id = ?", (booking_id,),
                ).fetchone()) == (booking_id, booking_ref, booked_day, "einnahme_sonstige")
        if scenario == "same-day":
            assert sync([first, second, fee])[0] == 0
            assert sync([first, third, fee])[0] == 0
            assert len(list(ledger.execute(rent_rows))) == 2


@pytest.mark.parametrize("omission", ["early-invoice", "late-invoice", "all-invoice", "late-bank-ref", "late-balance", "bridge"])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("seed", ["new", "early", "late"])
def test_statement_cohort_accepts_redundant_partial_facts_and_reuses_existing_bookings(sandbox, omission, sign, seed):
    import core

    def movement(day, change, balance, ref, booked_day=None):
        return bank_row(booking_date=booked_day or f"2026-11-{day:02}", transaction_date=f"2026-11-{day:02}",
                        value_date=f"2026-11-{day:02}", entry_reference=ref, reference_number=ref,
                        credit_debit_indicator="CRDT" if change * sign > 0 else "DBIT",
                        transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
                        balance_after_transaction={"amount": str(balance * sign), "currency": "EUR"},
                        debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"},
                        remittance_information=[ref])

    first = movement(19, 119, 119, "rent")
    second = movement(21, 119, 119, "rent")
    third = movement(22, 119, 119, "rent", booked_day="2026-11-21")
    reversal = movement(20, -119, 0, "reversal")
    fee = movement(24, -23, 96, "fee")
    opening = movement(18, 10, 0, "opening")
    early, middle, late = (row.copy() for row in (first, second, third))
    if omission in {"early-invoice", "all-invoice", "bridge"}:
        early["reference_number"] = None
    if omission == "all-invoice":
        middle["reference_number"] = None
    field = {"late-invoice": "reference_number", "all-invoice": "reference_number",
             "late-bank-ref": "entry_reference", "bridge": "entry_reference",
             "late-balance": "balance_after_transaction"}.get(omission)
    if field:
        late[field] = None
    whole = [opening, early, reversal, middle, late, fee]
    with closing(core.db()) as ledger:
        def sync(page):
            mapped, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, mapped, auto_match=False, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        if seed == "early":
            assert sync([first])[0] == 1
        elif seed == "late":
            assert sync([opening, first, reversal, third, fee])[0] == 5
        original = [tuple(row) for row in ledger.execute("SELECT id, ref, date FROM transactions WHERE description = 'rent'")]
        for booking_id, _, _ in original:
            core.set_tx_category(ledger, booking_id, "einnahme_sonstige")
        for page in (whole, whole[::-1], [*whole, late.copy()], [*whole, third] if omission != "all-invoice" else whole):
            sync(page)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (5, 106 * sign)
            for booking_id, booking_ref, booked_day in original:
                assert tuple(ledger.execute(
                    "SELECT ref, date, category FROM transactions WHERE id = ?", (booking_id,),
                ).fetchone()) == (booking_ref, booked_day, "einnahme_sonstige")
        assert sync([early, middle, fee])[0] == 0
        assert sync([early, late, fee])[0] == 0


@pytest.mark.parametrize("physical_repeats", [False, True])
@pytest.mark.parametrize("seed", [False, True])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("partial_page", [False, True])
@pytest.mark.parametrize("axis,lookup", [
    ("booked", "distinct"), ("booked", "one"), ("value", "none"), ("intraday", "same"), ("intraday", "distinct"),
    ("intraday", "same-partial"),
    ("missing-booking_date", "distinct"), ("missing-value_date", "distinct"),
    ("missing-transaction_date", "distinct"), ("mixed-dates", "distinct"), ("disjoint-dates", "distinct"),
    ("complementary", "distinct"),
])
def test_anchored_statement_distinguishes_identical_bookings_from_page_copies(
    sandbox, physical_repeats, seed, sign, partial_page, axis, lookup,
):
    import core

    def movement(day, change, balance, ref):
        return bank_row(booking_date=day, transaction_date=day, value_date=day, entry_reference=ref, reference_number=ref,
                        transaction_id=ref, remittance_information=[ref],
                        transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
                        credit_debit_indicator="CRDT" if sign * change > 0 else "DBIT",
                        balance_after_transaction={"amount": str(sign * balance), "currency": "EUR"},
                        debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"})

    first = movement("2026-11-21", 119, 119, "rent")
    second = first | {"transaction_id": "next"}
    if lookup == "none":
        first["transaction_id"] = None
    if lookup in {"none", "one", "same", "same-partial"}:
        second["transaction_id"] = first["transaction_id"] if lookup.startswith("same") else None
    if lookup == "same-partial":
        second["reference_number"] = None
    opening = movement("2026-11-20", 10, 0, "opening")
    reverse = movement("2026-11-21", -119, 0, "reversal")
    fee = movement("2026-11-22", -23, 96, "fee")
    others = [reverse] if physical_repeats else []
    whole = [opening, first, *others, second, fee]
    if axis == "value":
        for row in whole:
            row["booking_date"] = "2026-11-25"
    elif axis != "booked":
        for row in whole:
            row.update(dict.fromkeys(("booking_date", "value_date", "transaction_date"), "2026-11-21"))
    if axis.startswith("missing-"):
        second[axis.removeprefix("missing-")] = None
    if axis == "mixed-dates":
        first["booking_date"] = None
        second["value_date"] = None
        opening["transaction_date"] = None
        fee["booking_date"] = None
        reverse["value_date"] = None
    if axis == "disjoint-dates":
        first["value_date"] = first["transaction_date"] = None
        second["booking_date"] = None
    if axis == "complementary":
        first["entry_reference"] = None
        second["reference_number"] = None
    if physical_repeats and (axis.startswith("missing-") or axis.endswith("-dates")):
        mapped, skipped = transaction_rows("account-a", whole)
        assert skipped == 0
        actual = [(row["booked_day"], row["value_day"], row["transaction_day"])
                  for row in mapped if row["description"] == "rent"]
        expected = [(row["booking_date"], row["value_date"], row["transaction_date"]) for row in (first, second)]
        assert sorted(actual, key=repr) == sorted(expected, key=repr)
    initial = [first | {"transaction_id": None}, *whole] if partial_page else whole
    with closing(core.db()) as ledger:
        def sync(page):
            mapped, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, mapped, auto_match=False, require_fx=True)
            return result["imported"], skipped + result["ambiguous"]

        if seed:
            assert sync([first, *others])[0] == 1 + len(others)
            saved = tuple(ledger.execute("SELECT id, ref FROM transactions WHERE description = 'rent'").fetchone())
            core.set_tx_category(ledger, saved[0], "einnahme_sonstige")
        pages = [initial, whole[::-1], [*whole, first], [*whole, second], [*whole, *[first] * 10], [second, fee],
                 [opening, first | {"transaction_id": "rotated-a"}, *others,
                  second | {"transaction_id": "rotated-b"}, fee]]
        if lookup == "same-partial":
            pages.append([opening, first, *others, second | {"reference_number": "rent"}, fee])
        for page in pages:
            _, warnings = sync(page)
            assert warnings == 0
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == (
                5 if physical_repeats else 3, 106 * sign,
            )
            if seed:
                assert tuple(ledger.execute(
                    "SELECT ref, category FROM transactions WHERE id = ?", (saved[0],),
                ).fetchone()) == (saved[1], "einnahme_sonstige")


@pytest.mark.parametrize("first_repeats,second_repeats", [(True, True), (True, False), (False, True), (False, False)])
@pytest.mark.parametrize("sign", [-1, 1])
@pytest.mark.parametrize("lookup", [None, "shared"])
def test_statement_proves_repeat_counts_of_two_groups_together(sandbox, first_repeats, second_repeats, sign, lookup):
    import core

    def movement(day, change, balance, ref):
        return bank_row(booking_date=day, transaction_date=day, value_date=day, entry_reference=ref, reference_number=ref,
                        transaction_id=lookup, remittance_information=[ref],
                        transaction_amount={"amount": str(abs(change)), "currency": "EUR"},
                        credit_debit_indicator="CRDT" if sign * change > 0 else "DBIT",
                        balance_after_transaction={"amount": str(sign * balance), "currency": "EUR"},
                        debtor_account={"iban": "DE00PAYER"}, creditor_account={"iban": "DE00PAYEE"})

    opening = movement("2026-11-19", 10, 0, "opening")
    first = movement("2026-11-20", 119, 119, "Rent")
    second = movement("2026-11-21", 20, 139, "Supplies")
    rent_reversal = movement("2026-11-20", -119, 0, "Rent reversal")
    supplies_reversal = movement("2026-11-21", -20, 119, "Supplies reversal")
    fee = movement("2026-11-22", -23, 116, "fee")
    reversals = ([rent_reversal] if first_repeats else []) + ([supplies_reversal] if second_repeats else [])
    whole = [opening, first, first.copy(), second, second.copy(), *reversals, fee]
    expected = (4 + 2 * first_repeats + 2 * second_repeats, 126 * sign)
    with closing(core.db()) as ledger:
        def sync(page):
            rows, skipped = transaction_rows("account-a", page)
            result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
            assert skipped + result["ambiguous"] == 0

        if lookup:
            sync([first, second])
        saved = [tuple(row) for row in ledger.execute("SELECT id, ref, date FROM transactions")]
        for booking_id, _, _ in saved:
            core.set_tx_category(ledger, booking_id, "einnahme_sonstige")
        for page in (whole, whole[::-1], [*whole, *[first, second] * 3], [first, second, fee], whole):
            sync(page)
            assert tuple(ledger.execute("SELECT count(*), sum(amount) FROM transactions").fetchone()) == expected
            for booking_id, ref, day in saved:
                assert tuple(ledger.execute(
                    "SELECT ref, date, category FROM transactions WHERE id = ?", (booking_id,),
                ).fetchone()) == (ref, day, "einnahme_sonstige")


def test_partial_statement_identity_cannot_bridge_conflicting_bank_references():
    first = bank_row(entry_reference="first", transaction_id="first",
                     debtor_account={"iban": "DE00PAYER"}, reference_number="shared",
                     balance_after_transaction={"amount": "119", "currency": "EUR"},
                     remittance_information=["First"])
    second = first | {"entry_reference": "second", "transaction_id": "second", "remittance_information": ["Second"]}
    sparse = first | {"entry_reference": None, "transaction_id": None, "remittance_information": []}
    for page in ([first, sparse, second], [second, sparse, first]):
        rows, skipped = transaction_rows("account-a", page)
        assert skipped == 1
        assert sorted(row["description"] for row in rows) == ["First", "Second"]


@pytest.mark.parametrize("count", [1, 2])
@pytest.mark.parametrize("sign", [-1, 1])
def test_isolated_statement_gap_proves_count_without_reported_payment_balances(count, sign):
    def movement(day, amount, balance, ref):
        return bank_row(booking_date=day, transaction_date=day, value_date=day, entry_reference=ref, reference_number=ref,
                        remittance_information=[ref], transaction_amount={"amount": str(abs(amount)), "currency": "EUR"},
                        credit_debit_indicator="CRDT" if sign * amount > 0 else "DBIT",
                        balance_after_transaction=None if balance is None else
                        {"amount": str(sign * balance), "currency": "EUR"})

    opening = movement("2026-11-20", 10, 0, "opening")
    supplies = movement("2026-11-21", 119, None, "Supplies")
    fee = movement("2026-11-22", -23, 119 * count - 23, "fee")
    for page in ([opening, supplies, supplies.copy(), fee], [fee, supplies, supplies.copy(), opening]):
        rows, warnings = transaction_rows("account-a", page)
        assert warnings == 0
        assert len([row for row in rows if row["description"] == "Supplies"]) == count
        assert sum(float(row["amount"]) for row in rows) == (119 * count - 13) * sign


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
