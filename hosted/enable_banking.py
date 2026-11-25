"""Enable Banking's account-information API and transaction mapping."""
import base64
from collections import Counter
from datetime import date
from decimal import Decimal, InvalidOperation
from http.client import HTTPException, HTTPSConnection
import json
import re
import time
from urllib.parse import quote, urlencode
from uuid import UUID

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

import core
from hosted.common import digest

API_HOST = "api.enablebanking.com"


class BankingError(Exception):
    def __init__(self, message, status=None, code=None):
        super().__init__(message)
        self.status = status
        self.code = code


def fingerprint(*values):
    return digest(json.dumps(values, ensure_ascii=False, sort_keys=True, separators=(",", ":")))


class EnableBanking:
    def __init__(self, application_id, pem):
        try:
            self.application_id = str(UUID(application_id.strip()))
            self.key = serialization.load_pem_private_key(pem, password=None)
            if not isinstance(self.key, rsa.RSAPrivateKey) or self.key.key_size < 2048:
                raise ValueError("RSA key must be 2048 bits or more")
        except (ValueError, TypeError) as exc:
            raise BankingError("Ungültige Anwendungs-ID oder ungültiger RSA-Schlüssel.") from exc

    def jwt(self):
        def encoded(data):
            return base64.urlsafe_b64encode(data).rstrip(b"=")
        now = int(time.time())
        claims = {"iss": "enablebanking.com", "aud": API_HOST, "iat": now, "exp": now + 300}
        header = {"typ": "JWT", "alg": "RS256", "kid": self.application_id}
        payload = b".".join(encoded(json.dumps(v, separators=(",", ":")).encode()) for v in (header, claims))
        signature = self.key.sign(payload, padding.PKCS1v15(), hashes.SHA256())
        return (payload + b"." + encoded(signature)).decode("ascii")

    def request(self, method, path, *, query=None, data=None):
        headers = {"Authorization": "Bearer " + self.jwt(), "Accept": "application/json"}
        body = None
        if data is not None:
            headers["Content-Type"] = "application/json"
            body = json.dumps(data).encode()
        if query:
            path += "?" + urlencode(query)
        connection = HTTPSConnection(API_HOST, timeout=20)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            if not 200 <= response.status < 300:
                try:
                    code = json.loads(response.read(65536)).get("error")
                except (AttributeError, ValueError):
                    code = None
                raise BankingError(f"Enable Banking meldet einen Fehler (HTTP {response.status}).", response.status, code)
            if response.status == 204:
                return {}
            raw = response.read(16 * 1024 * 1024 + 1)
            if len(raw) > 16 * 1024 * 1024:
                raise BankingError("Die Antwort von Enable Banking ist zu groß.")
            result = json.loads(raw)
            if not isinstance(result, dict):
                raise ValueError("expected an object")
            return result
        except (HTTPException, OSError, ValueError) as exc:
            raise BankingError("Enable Banking war nicht erreichbar oder lieferte eine ungültige Antwort.") from exc
        finally:
            connection.close()

    def transactions(self, account_uid, date_from, date_to):
        path = "/accounts/" + quote(account_uid, safe="") + "/transactions"
        query = {"transaction_status": "BOOK"}
        if date_from is None:
            query["strategy"] = "longest"
        else:
            query.update(date_from=date_from, date_to=date_to)
        try:
            return list(self._transaction_pages(path, query))
        except BankingError as exc:
            if date_from is None or exc.code != "WRONG_TRANSACTIONS_PERIOD":
                raise
            fallback = {"transaction_status": "BOOK", "strategy": "longest", "date_from": date_from}
            return list(self._transaction_pages(path, fallback))

    def _transaction_pages(self, path, query):
        seen = set()
        while True:
            page = self.request("GET", path, query=dict(query))
            items = page.get("transactions")
            if not isinstance(items, list):
                raise BankingError("Enable Banking lieferte keine gültige Umsatzliste.")
            yield from items
            cursor = page.get("continuation_key")
            if not cursor:
                return
            if not isinstance(cursor, str) or cursor in seen:
                raise BankingError("Enable Banking hat eine Umsatzseite wiederholt.")
            seen.add(cursor)
            query["continuation_key"] = cursor


def transaction_rows(account_key, transactions):
    """Keep the multiplicity of identical reference-less booked transactions."""
    occurrences = Counter()
    references = {}
    rows = []
    skipped = 0
    for tx in transactions:
        if not isinstance(tx, dict):
            skipped += 1
            continue
        if tx.get("status", "BOOK") != "BOOK":
            continue
        try:
            dates = [tx.get(key) for key in ("booking_date", "value_date", "transaction_date")]
            booking = date.fromisoformat(next(d for d in dates if d)).isoformat()
            amount_struct = tx["transaction_amount"]
            currency = amount_struct["currency"].upper()
            amount = abs(Decimal(amount_struct["amount"]))
            direction = tx["credit_debit_indicator"]
            if direction not in {"CRDT", "DBIT"} or not amount.is_finite() or amount > 10**14:
                raise ValueError("invalid amount or direction")
            if not re.fullmatch("[A-Z]{3}", currency):
                raise ValueError("invalid currency")
            if direction == "DBIT":
                amount = -amount
        except (AttributeError, InvalidOperation, KeyError, StopIteration, TypeError, ValueError):
            skipped += 1
            continue
        party_key = "debtor" if direction == "CRDT" else "creditor"
        party = tx.get(party_key)
        name = party.get("name") if isinstance(party, dict) else None
        remittance = tx.get("remittance_information")
        details = [s.strip() for s in remittance if isinstance(s, str) and s.strip()] if isinstance(remittance, list) else []
        description = " · ".join(dict.fromkeys([*([name] if isinstance(name, str) and name else []), *details]))
        entry_ref = tx.get("entry_reference")
        if isinstance(entry_ref, str) and entry_ref.strip():
            identity = fingerprint(account_key, "entry", entry_ref.strip(), booking,
                                   str(amount.normalize()), currency)
            description_version = (name, details)
            if identity in references:
                if references[identity] != description_version:
                    # Same provider reference and booking facts with conflicting metadata.
                    skipped += 1
                continue
            references[identity] = description_version
        else:
            # transaction_id is a temporary lookup ID according to the provider.
            key = fingerprint(account_key, dates, str(amount.normalize()), currency, name, details,
                              tx.get(party_key + "_account"), tx.get("reference_number"),
                              tx.get("bank_transaction_code"), tx.get("balance_after_transaction"))
            occurrences[key] += 1
            identity = fingerprint(key, occurrences[key])
        rows.append({"ref": core.ENABLE_BANKING_REF_PREFIX + identity, "date": booking,
                     "amount": str(amount), "currency": currency,
                     "description": description or "Bankumsatz", "tx_type": "Enable Banking"})
    return rows, skipped
