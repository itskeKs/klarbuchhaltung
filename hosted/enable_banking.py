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


_FINANCIAL_BOOKING_FACTS = ("balance_key", "creditor_ref", "reference_schema")
_SECONDARY_BANK_DATES = core._BANK_SECONDARY_DATES
_OPTIONAL_BOOKING_FACTS = (*_FINANCIAL_BOOKING_FACTS, "counterparty_iban", *_SECONDARY_BANK_DATES)
_REFERENCE_COPY_FACTS = ("balance_key", "creditor_ref")
_FETCH_COPY_FACTS = ("provider_ref", "booked_day", *_OPTIONAL_BOOKING_FACTS)
_FETCH_FIXED_FACTS = tuple(field for field in _FETCH_COPY_FACTS if field not in _SECONDARY_BANK_DATES)


def _optional_bank_day(value):
    try:
        return date.fromisoformat(value).isoformat()
    except (TypeError, ValueError):
        return None


def _iban_key(value):
    normalized = "".join(value.split()).upper() if isinstance(value, str) else ""
    return fingerprint(normalized) if normalized else None


def _counterparty_ids(account, additional):
    account = account if isinstance(account, dict) else {}
    additional = additional if isinstance(additional, list) else [additional]
    iban = _iban_key(account.get("iban"))
    identifiers = {("IBAN", iban)} if iban else set()
    for alternative in (account.get("other"), *additional):
        if not isinstance(alternative, dict):
            continue
        scheme = alternative.get("scheme_name")
        identifier = alternative.get("identification")
        if not isinstance(scheme, str) or not isinstance(identifier, str) or not scheme.strip() or not identifier.strip():
            continue
        scheme = scheme.strip().upper()
        issuer = alternative.get("issuer")
        if scheme == "IBAN":
            identifiers.add((scheme, _iban_key(identifier)))
        else:
            namespace = fingerprint(scheme, issuer.strip().casefold() if isinstance(issuer, str) else "")
            identifiers.add((namespace, fingerprint(identifier.strip())))
    return iban, tuple(sorted(identifiers))


def _conflicting_facts(first, second, fields):
    return (any(first.get(field) and second.get(field) and first[field] != second[field] for field in fields)
            or core._bank_account_match(first.get("counterparty_ids", ()), second.get("counterparty_ids", ())) is False)


def _dated_booking_ref(dated_ref, facts):
    values = [facts.get(field) for field in _FINANCIAL_BOOKING_FACTS]
    if facts.get("counterparty_iban"):
        values.append(facts["counterparty_iban"])
    alternate = tuple(pair for pair in facts.get("counterparty_ids", ()) if pair != ("IBAN", facts.get("counterparty_iban")))
    if alternate:
        values.append(alternate)
    secondary = tuple((field, facts[field]) for field in _SECONDARY_BANK_DATES if facts.get(field))
    if secondary:
        values.append(secondary)
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
    fields = _OPTIONAL_BOOKING_FACTS
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
                    row["_dated_ref"] = key
                    row["ref"] = _dated_booking_ref(key, row)
            aligned.setdefault(key, []).append(row)
    return aligned, len(unresolved)


def _compatible_copy_groups(copies, conflicts_with):
    conflicts = [frozenset(index for index, other in enumerate(copies) if conflicts_with(row, other))
                 for row in copies]
    # Copies with the same conflicts can be merged. A sparse copy may rule out fewer
    # alternatives and can only be attached if exactly one group accounts for it.
    signatures = set(conflicts)
    groups = {s: [] for s in signatures if not any(s < other for other in signatures)}
    unresolved = []
    for row, known_conflicts in zip(copies, conflicts):
        matches = [s for s in groups if known_conflicts <= s]
        if len(matches) == 1:
            groups[matches[0]].append(row)
        else:
            unresolved.append(row)
    return groups.values(), unresolved


def _merge_copy_metadata(row, versions):
    row["counterparty_ids"] = tuple(sorted({pair for copy in versions for pair in copy["counterparty_ids"]}))
    row["bank_groups"] = {day: group for copy in versions for day, group in copy["bank_groups"].items()}
    # Keep the original lookup day if a later copy supplied the posting date.
    row["bank_group"] = min((copy["bank_group"] for copy in versions if not copy["booked_day"]),
                            default=row["bank_group"])
    row["prior_refs"] = list(dict.fromkeys(ref for copy in versions for ref in copy["prior_refs"]))
    row["_unreferenced_keys"] = tuple(dict.fromkeys(key for copy in versions for key in copy["_unreferenced_keys"]))
    row["_counterparty_names"] = frozenset().union(*(copy["_counterparty_names"] for copy in versions))


def _merge_dated_bookings(dated_ref, copies):
    """Combine compatible copies and keep payments with conflicting known facts separate."""
    groups, unresolved = _compatible_copy_groups(copies, lambda a, b: _conflicting_facts(a, b, _OPTIONAL_BOOKING_FACTS))

    merged = []
    skipped = len({row["ref"] for row in unresolved})
    for versions in groups:
        known = {field: row[field] for row in versions for field in _OPTIONAL_BOOKING_FACTS if row[field]}
        known["counterparty_ids"] = tuple(sorted({pair for copy in versions for pair in copy["counterparty_ids"]}))
        ref = _dated_booking_ref(dated_ref, known)
        row = min(versions, key=lambda version: (version["ref"] != ref, version["description"])) | known
        row["ref"] = ref
        row["booked_day"] = next((copy["booked_day"] for copy in versions if copy["booked_day"]), None)
        _merge_copy_metadata(row, versions)
        skipped += len({copy["description"] for copy in versions}) - 1
        merged.append(row)
    return sorted(merged, key=lambda row: row["ref"]), skipped


def _booking_evidence(row):
    return ((group, field, row[field]) for group in row["bank_groups"].values()
            for field in _REFERENCE_COPY_FACTS if row[field])


def _conflicting_counterparties(first, second):
    comparable = core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"])
    if comparable is not None:
        return not comparable
    first_names, second_names = first["_counterparty_names"], second["_counterparty_names"]
    return bool(first_names and second_names) and first_names.isdisjoint(second_names)


def _fetch_copy_corroborates(first, second):
    if not first["bank_groups"].keys().isdisjoint(second["bank_groups"]):
        return True
    if any(first[field] and first[field] == second[field] for field in ("provider_ref", *_REFERENCE_COPY_FACTS)):
        return True
    same_payer = core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True
    return same_payer and bool(first["_remittance"]) and first["_remittance"] == second["_remittance"]


def _corroborated_fetch_groups(copies):
    groups = []
    for row in copies:
        connected = [row]
        unrelated = []
        for group in groups:
            if any(_fetch_copy_corroborates(row, previous) for previous in group):
                connected.extend(group)
            else:
                unrelated.append(group)
        groups = [*unrelated, connected]
    return groups


def _fetch_copies_conflict(first, second):
    same_balance = first["balance_key"] and first["balance_key"] == second["balance_key"]
    same_reference = first["creditor_ref"] and first["creditor_ref"] == second["creditor_ref"]
    same_booking = (all(first[field] and first[field] == second[field] for field in ("booked_day", "provider_ref"))
                    and core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True)
    # A shared balance and corroborating bank facts can establish a date correction.
    fields = _FETCH_FIXED_FACTS if same_balance and (same_reference or same_booking) else _FETCH_COPY_FACTS
    return _conflicting_facts(first, second, fields) or _conflicting_counterparties(first, second)


def _merge_fetch_copies(account_key, rows):
    """Use the current lookup ID within one account fetch, before numbering source occurrences."""
    batches = defaultdict(list)
    for index, row in enumerate(rows):
        lookup_id = row.pop("_transaction_id")
        group = (lookup_id, row["_amount_key"], row["currency"]) if lookup_id else (index,)
        batches[group].append(row)

    merged = []
    skipped = 0
    for copies in (group for batch in batches.values() for group in _corroborated_fetch_groups(batch)):
        if len(copies) == 1:
            merged.extend(copies)
            continue
        groups, unresolved = _compatible_copy_groups(copies, _fetch_copies_conflict)
        skipped += len(unresolved)
        payments = []
        for versions in groups:
            preferred = min(versions, key=lambda row: (not row["provider_ref"], not row["booked_day"],
                                                        -sum(bool(row[field]) for field in _OPTIONAL_BOOKING_FACTS),
                                                        row["description"], row["ref"] or row["_source_key"]))
            known = {field: row[field] for row in versions for field in _FETCH_FIXED_FACTS if row[field]}
            for field in _SECONDARY_BANK_DATES:
                known[field] = preferred[field] or min((copy[field] for copy in versions if copy[field]), default=None)
            row = preferred | known
            _merge_copy_metadata(row, versions)
            effective_day = row["booked_day"] or row["value_day"] or row["transaction_day"]
            row["date"] = date.fromisoformat(effective_day).isoformat()
            row["_source_keys"] = tuple(dict.fromkeys(key for copy in versions for key in copy["_source_keys"]))
            row["prior_refs"].extend(copy["ref"] for copy in versions if copy["ref"])
            if row["provider_ref"]:
                row["_dated_ref"] = fingerprint(account_key, "entry", row["_entry_reference"], row["date"],
                                                row["_amount_key"], row["currency"])
                row["ref"] = _dated_booking_ref(row["_dated_ref"], row)
            skipped += len({copy["_remittance"] for copy in versions}) - 1
            payments.append(row)
        merged.extend(sorted(payments, key=lambda row: (row["ref"] or row["_source_key"], row["counterparty_ids"],
                                                        row["reference_schema"] or "")))
    return merged, skipped


def _merge_reference_copies(rows):
    """Consolidate a reference-less copy only when its booked evidence identifies one payment."""
    identified = {row["ref"]: row for row in rows if row["provider_ref"]}
    by_evidence = defaultdict(set)
    for ref, row in identified.items():
        for evidence in _booking_evidence(row):
            by_evidence[evidence].add(ref)

    candidates = defaultdict(list)
    omitted = set()
    skipped = 0
    fields = ("booked_day", *_OPTIONAL_BOOKING_FACTS)
    for row in rows:
        if row["provider_ref"]:
            continue
        matches = {ref for evidence in _booking_evidence(row) for ref in by_evidence.get(evidence, ())
                   if not _conflicting_facts(row, identified[ref], fields)
                   and not _conflicting_counterparties(row, identified[ref])}
        if len(matches) > 1:
            omitted.add(row["ref"])
            skipped += 1
        elif matches:
            candidates[next(iter(matches))].append(row)

    for ref, copies in candidates.items():
        if len(copies) > 1:
            # Several reference-less movements may have equal details. Keep their multiplicity.
            omitted.add(ref)
            skipped += 1
            continue
        copy, = copies
        booking = identified[ref]
        for field in fields:
            booking[field] = booking[field] or copy[field]
        booking["counterparty_ids"] = tuple(sorted(set(booking["counterparty_ids"]) | set(copy["counterparty_ids"])))
        booking["date"] = booking["booked_day"] or booking["date"]
        booking["bank_groups"].update(copy["bank_groups"])
        booking["prior_refs"].extend((booking["ref"], copy["ref"], *copy["prior_refs"]))
        booking["ref"] = _dated_booking_ref(booking["_dated_ref"], booking)
        omitted.add(copy["ref"])
        skipped += booking["_remittance"] != copy["_remittance"]
    return [row for row in rows if row["ref"] not in omitted], skipped


def transaction_rows(account_key, transactions):
    """Keep the multiplicity of identical reference-less booked transactions."""
    drafts = []
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
        counterparty_name = " ".join(name.split()).casefold() if isinstance(name, str) else ""
        party_account = tx.get(party_key + "_account")
        iban, counterparty_ids = _counterparty_ids(party_account, tx.get(party_key + "_account_additional_identification"))
        transaction_id = tx.get("transaction_id")
        transaction_id = transaction_id if isinstance(transaction_id, str) and transaction_id.strip() else None
        remittance = tx.get("remittance_information")
        details = [s.strip() for s in remittance if isinstance(s, str) and s.strip()] if isinstance(remittance, list) else []
        description = " · ".join(dict.fromkeys([*([name] if isinstance(name, str) and name else []), *details]))
        amount_key = str(amount.normalize())
        entry_ref = tx.get("entry_reference")
        entry_ref = entry_ref.strip() if isinstance(entry_ref, str) else ""
        provider_ref = None
        dated_ref = None
        ref = None
        source_key = None
        source_keys = ()
        prior_refs = []
        balance_key = _balance_key(tx.get("balance_after_transaction"))
        reference = tx.get("reference_number")
        creditor_ref = fingerprint(reference.strip()) if isinstance(reference, str) and reference.strip() else None
        schema = tx.get("reference_number_schema") if creditor_ref else None
        facts = {"balance_key": balance_key, "creditor_ref": creditor_ref,
                 "reference_schema": schema if isinstance(schema, str) and schema else None,
                 "counterparty_iban": iban, "counterparty_ids": counterparty_ids,
                 **{field: _optional_bank_day(day) for field, day in zip(_SECONDARY_BANK_DATES, dates[1:])}}
        alias_days = tuple(dict.fromkeys([booking, *(day for day in dates if day),
                                        *(facts[field] for field in _SECONDARY_BANK_DATES if facts[field])]))
        unreferenced_keys = ()
        if not entry_ref or counterparty_ids:
            source = (account_key, dates, amount_key, currency, name, details)
            statement = (reference, tx.get("bank_transaction_code"))
            fields = (*source, party_account, *statement)
            key = fingerprint(*fields, balance_key)
            raw_balance = tx.get("balance_after_transaction")
            legacy_key = fingerprint(*fields, raw_balance) if balance_key else None
            unreferenced_keys = (key, legacy_key) if legacy_key else (key,)
            if counterparty_ids:
                unreferenced_keys += (fingerprint(*source, None, *statement, balance_key),)
                if balance_key:
                    unreferenced_keys += (fingerprint(*source, None, *statement, raw_balance),)
        if entry_ref:
            provider_ref = fingerprint(account_key, "entry", entry_ref, amount_key, currency)
            dated_ref = fingerprint(account_key, "entry", entry_ref, booking, amount_key, currency)
            ref = _dated_booking_ref(dated_ref, facts)
            # Earlier ledgers predate secondary-date facts, and older ones also omit payer evidence.
            legacy_facts = facts | dict.fromkeys(_SECONDARY_BANK_DATES)
            legacy_financial = legacy_facts | {"counterparty_iban": None, "counterparty_ids": ()}
            for day in alias_days:
                dated = fingerprint(account_key, "entry", entry_ref, day, amount_key, currency)
                prior_refs.extend((core.ENABLE_BANKING_REF_PREFIX + dated, _dated_booking_ref(dated, legacy_financial),
                                   _dated_booking_ref(dated, legacy_facts)))
        else:
            source_key = key
            source_keys = (legacy_key, key) if legacy_key else (key,)
        row = {"ref": ref, "date": booking, **facts,
               "amount": str(amount), "currency": currency,
               "description": description or "Bankumsatz", "tx_type": "Enable Banking"}
        row["bank_groups"] = {day: fingerprint(account_key, day, amount_key, currency) for day in alias_days}
        row["bank_group"] = row["bank_groups"][booking]
        row["provider_ref"] = provider_ref
        row["booked_day"] = booking if dates[0] else None
        row["_dated_ref"] = dated_ref
        row["_counterparty_names"] = frozenset((counterparty_name,)) if counterparty_name else frozenset()
        row["_remittance"] = tuple(dict.fromkeys(details))
        row["_transaction_id"] = transaction_id
        row["_amount_key"] = amount_key
        row["_entry_reference"] = entry_ref
        row["_source_key"], row["_source_keys"] = source_key, source_keys
        row["_unreferenced_keys"] = unreferenced_keys
        row["prior_refs"] = list(dict.fromkeys(prior_refs))
        drafts.append(row)
    versions, warnings = _merge_fetch_copies(account_key, drafts)
    skipped += warnings
    occurrences = Counter()
    bookings = {}
    for row in versions:
        aliases = {}
        for key in row.pop("_source_keys"):
            occurrences[key] += 1
            aliases[key] = core.bank_source_reference(key, occurrences[key])
        source_key = row.pop("_source_key")
        if not row["provider_ref"]:
            row["ref"] = aliases.pop(source_key)
        row["prior_refs"].extend(aliases.values())
        bookings.setdefault(row["_dated_ref"] or row["ref"], []).append(row)
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
    rows, warnings = _merge_reference_copies(rows)
    return rows, skipped + warnings
