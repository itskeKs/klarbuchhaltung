"""Run the recurring-payment journey through the hosted gateway when available."""
from contextlib import ExitStack
from datetime import date
import io
import sqlite3
from urllib.parse import urlsplit

import pytest

pytest.importorskip("hosted", reason="The standalone app has no hosted gateway")
from test_hosted import SITE, create_app, csrf, fetch, post, provision, start_tenant


def test_hosted_payments_render_after_assigning_recurring_payment(tmp_path, monkeypatch):
    monkeypatch.setenv("KLAR_PUBLIC_ORIGIN", SITE)
    private = tmp_path / "secrets"
    passwords = provision(private, ["Chris", "Kiki"])
    with ExitStack() as stack:
        upstreams = {tenant: start_tenant(stack, tmp_path / tenant, private / tenant, tenant)
                     for tenant in ("tenant-a", "tenant-b")}
        gateway = create_app(private / "gateway.json", tmp_path, upstreams)
        a, b = gateway.test_client(), gateway.test_client()
        for client, name in ((a, "Chris"), (b, "Kiki")):
            assert post(client, "/login", {"username": name, "password": passwords[name]}).location == "/"
            assert post(client, "/setup", {"name": name, "owner": name, "street": "1 Test Street",
                        "city": "10115 Berlin"}, token=csrf(fetch(client, "/setup"))).location == "/"

        token = csrf(fetch(a, "/zahlungen"))
        today = date.today().isoformat()
        statement = ("Date,Description,Amount,Currency\n"
                     f"{today},Office supplies,-23,EUR\n"
                     f"{today},Office supplies,-17,EUR\n")
        assert post(a, "/zahlungen/import", {"file": (io.BytesIO(statement.encode()), "debits.csv")},
                    token=token).location == "/zahlungen"
        with sqlite3.connect(tmp_path / "tenant-a" / "data" / "bookkeeping.db") as ledger:
            tid, = ledger.execute("SELECT id FROM transactions WHERE amount = -23").fetchone()
        saved = post(a, f"/zahlungen/tx/{tid}/set", {"action": "expense", "category": "4930 - Bürobedarf",
                     "vat_rate": "19"}, token=token)
        assert saved.status_code == 302
        assert urlsplit(saved.location).path == "/zahlungen"
        assert fetch(a, saved.location).status_code == 200
        fresh = fetch(a, "/zahlungen")
        assert fresh.status_code == 200
        html = fresh.get_data(as_text=True)
        assert all(text in html for text in ("Office supplies", "-23,00 €", "-17,00 €", "-40,00 €"))
        assert html.count('title="Offen"') == 1
        other = fetch(b, "/zahlungen")
        assert other.status_code == 200
        assert "Office supplies" not in other.get_data(as_text=True)
