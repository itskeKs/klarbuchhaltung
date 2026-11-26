"""Enable Banking's account-information API and transaction mapping."""
import base64
from collections import Counter, defaultdict
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


def _balance_key(balance):
    if not isinstance(balance, dict):
        return None
    try:
        amount = Decimal(balance["amount"])
        currency = balance["currency"].upper()
        if amount.is_finite() and re.fullmatch("[A-Z]{3}", currency):
            return fingerprint(currency, str(amount.normalize()) if amount else "0")
    except (AttributeError, InvalidOperation, KeyError, TypeError, ValueError):
        pass
    return None


_OPTIONAL_BOOKING_FACTS = ("balance_key", "creditor_ref", "reference_schema")
_SECONDARY_BANK_DATES = ("_value_day", "_transaction_day")


def _conflicting_facts(first, second, fields):
    return any(first.get(field) and second.get(field) and first[field] != second[field] for field in fields)


def _dated_booking_ref(dated_ref, facts):
    values = [facts.get(field) for field in _OPTIONAL_BOOKING_FACTS]
    identity = fingerprint(dated_ref, *values) if any(values) else dated_ref
    return core.ENABLE_BANKING_REF_PREFIX + identity


def _align_partial_booking_dates(bookings):
    posted = defaultdict(list)
    for dated_ref, rows in bookings.items():
        for row in rows:
            if row["provider_ref"] and row["booked_day"]:
                for field in _SECONDARY_BANK_DATES:
                    if row[field]:
                        posted[row["provider_ref"], field, row[field]].append((dated_ref, row))

    aligned = {}
    unresolved = set()
    fields = (*_SECONDARY_BANK_DATES, *_OPTIONAL_BOOKING_FACTS)
    for dated_ref, rows in bookings.items():
        for row in rows:
            key = dated_ref
            if row["provider_ref"] and not row["booked_day"]:
                matches = {ref: candidate for field in _SECONDARY_BANK_DATES
                           for ref, candidate in posted.get((row["provider_ref"], field, row[field]), ())
                           if not _conflicting_facts(row, candidate, fields)}
                if len(matches) > 1:
                    unresolved.add(row["ref"])
                    continue
                if matches:
                    key, candidate = next(iter(matches.items()))
                    row["date"] = candidate["date"]
                    row["ref"] = _dated_booking_ref(key, row)
            aligned.setdefault(key, []).append(row)
    return aligned, len(unresolved)


def _merge_dated_bookings(dated_ref, copies):
    """Combine compatible copies and keep payments with conflicting known facts separate."""
    facts = {row["ref"]: {field: row[field] for field in _OPTIONAL_BOOKING_FACTS if row[field]}
             for row in copies}
    conflicts = {ref: frozenset(other_ref for other_ref, other in facts.items()
                                if _conflicting_facts(known, other, _OPTIONAL_BOOKING_FACTS))
                 for ref, known in facts.items()}
    # Copies with the same conflicts can be merged. A sparse copy may rule out fewer
    # alternatives and can only be attached if exactly one group accounts for it.
    signatures = set(conflicts.values())
    groups = {s: [] for s in signatures if not any(s < other for other in signatures)}
    unresolved = set()
    for row in copies:
        matches = [s for s in groups if conflicts[row["ref"]] <= s]
        if len(matches) == 1:
            groups[matches[0]].append(row)
        else:
            unresolved.add(row["ref"])

    merged = []
    skipped = len(unresolved)
    for versions in groups.values():
        known = {field: value for row in versions for field, value in facts[row["ref"]].items()}
        ref = _dated_booking_ref(dated_ref, known)
        row = min(versions, key=lambda version: (version["ref"] != ref, version["description"])) | known
        row["ref"] = ref
        row["booked_day"] = next((copy["booked_day"] for copy in versions if copy["booked_day"]), None)
        row["bank_groups"] = {day: group for copy in versions for day, group in copy["bank_groups"].items()}
        # Keep the original lookup day if a later copy supplied the posting date.
        row["bank_group"] = min((copy["bank_group"] for copy in versions if not copy["booked_day"]),
                                default=row["bank_group"])
        row["prior_refs"] = list(dict.fromkeys(ref for copy in versions for ref in copy["prior_refs"]))
        skipped += len({copy["description"] for copy in versions}) - 1
        merged.append(row)
    return sorted(merged, key=lambda row: row["ref"]), skipped


def transaction_rows(account_key, transactions):
    """Keep the multiplicity of identical reference-less booked transactions."""
    occurrences = Counter()
    bookings = {}
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
        amount_key = str(amount.normalize())
        entry_ref = tx.get("entry_reference")
        provider_ref = None
        prior_refs = []
        balance_key = _balance_key(tx.get("balance_after_transaction"))
        reference = tx.get("reference_number")
        creditor_ref = fingerprint(reference.strip()) if isinstance(reference, str) and reference.strip() else None
        schema = tx.get("reference_number_schema") if creditor_ref else None
        facts = {"balance_key": balance_key, "creditor_ref": creditor_ref,
                 "reference_schema": schema if isinstance(schema, str) and schema else None}
        if isinstance(entry_ref, str) and entry_ref.strip():
            entry_ref = entry_ref.strip()
            provider_ref = fingerprint(account_key, "entry", entry_ref, amount_key, currency)
            dated_ref = fingerprint(account_key, "entry", entry_ref, booking, amount_key, currency)
            ref = _dated_booking_ref(dated_ref, facts)
            booking_key = dated_ref
            # Match earlier ledgers whose IDs used only the effective date and amount.
            prior_refs = [core.ENABLE_BANKING_REF_PREFIX + fingerprint(
                account_key, "entry", entry_ref, day, amount_key, currency
            ) for day in dict.fromkeys(day for day in dates if day)]
        else:
            # transaction_id is a temporary lookup ID according to the provider.
            fields = (account_key, dates, amount_key, currency, name, details,
                      tx.get(party_key + "_account"), reference, tx.get("bank_transaction_code"))
            key = fingerprint(*fields, balance_key)
            if balance_key:
                legacy_key = fingerprint(*fields, tx.get("balance_after_transaction"))
                occurrences[legacy_key] += 1
                prior_refs.append(core.ENABLE_BANKING_REF_PREFIX + fingerprint(legacy_key, occurrences[legacy_key]))
            occurrences[key] += 1
            booking_key = fingerprint(key, occurrences[key])
            ref = core.ENABLE_BANKING_REF_PREFIX + booking_key
        row = {"ref": ref, "date": booking, **facts,
               "amount": str(amount), "currency": currency,
               "description": description or "Bankumsatz", "tx_type": "Enable Banking"}
        row["bank_groups"] = {day: fingerprint(account_key, day, amount_key, currency)
                              for day in dict.fromkeys([booking, *(day for day in dates if day)])}
        row["bank_group"] = row["bank_groups"][booking]
        row["provider_ref"] = provider_ref
        row["booked_day"] = dates[0] or None
        row["_value_day"], row["_transaction_day"] = dates[1:]
        row["prior_refs"] = prior_refs
        bookings.setdefault(booking_key, []).append(row)
    rows = []
    aligned, warnings = _align_partial_booking_dates(bookings)
    skipped += warnings
    for booking_key, copies in aligned.items():
        if len(copies) == 1:
            rows.extend(copies)
        else:
            merged, warnings = _merge_dated_bookings(booking_key, copies)
            rows.extend(merged)
            skipped += warnings
    return rows, skipped
