"""Enable Banking's account-information API and transaction mapping."""
import base64
from collections import Counter, defaultdict
from datetime import date
from decimal import Decimal, InvalidOperation
from http.client import HTTPException, HTTPSConnection
from itertools import combinations
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


def _statement_balance(balance):
    if not isinstance(balance, dict):
        return None
    try:
        amount = Decimal(balance["amount"])
        currency = balance["currency"].upper()
        if amount.is_finite() and re.fullmatch("[A-Z]{3}", currency):
            return currency, amount
    except (AttributeError, InvalidOperation, KeyError, TypeError, ValueError):
        pass
    return None


_FINANCIAL_BOOKING_FACTS = ("balance_key", "creditor_ref", "reference_schema")
_SECONDARY_BANK_DATES = core._BANK_SECONDARY_DATES
_FIXED_BOOKING_FACTS = (*_FINANCIAL_BOOKING_FACTS, "counterparty_iban")
_OPTIONAL_BOOKING_FACTS = (*_FIXED_BOOKING_FACTS, *_SECONDARY_BANK_DATES)
_REFERENCE_COPY_FACTS = ("balance_key", "creditor_ref")
_FETCH_COPY_FACTS = ("provider_ref", "booked_day", *_OPTIONAL_BOOKING_FACTS)
_FETCH_FIXED_FACTS = ("provider_ref", "booked_day", *_FIXED_BOOKING_FACTS)
_STATEMENT_IDENTITY_FACTS = ("provider_ref", "creditor_ref", "reference_schema")
_STATEMENT_OBSERVATION_FACTS = (*_FETCH_COPY_FACTS, "counterparty_ids", "_counterparty_names",
                                "_transaction_id", "_statement_balance")


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
    row["_statement_sources"] = frozenset().union(*(copy["_statement_sources"] for copy in versions))
    rejections = set().union(*(copy.get("_statement_rejections", ()) for copy in versions))
    if rejections:
        row["_statement_rejections"] = rejections
    if row["balance_key"]:
        row["_statement_balance"] = next(copy["_statement_balance"] for copy in versions
                                         if copy["balance_key"] == row["balance_key"])


def _statement_copies_conflict(first, second):
    if first is second:
        return False
    current_lookup_matches = first["_transaction_id"] and first["_transaction_id"] == second["_transaction_id"]
    if not (first["provider_ref"] or second["provider_ref"] or current_lookup_matches):
        return True
    if first["_statement_balance"] is not None and second["_statement_balance"] is not None:
        return (first["_statement_balance"] != second["_statement_balance"]
                or _conflicting_facts(first, second, _STATEMENT_IDENTITY_FACTS))
    if _conflicting_facts(first, second, _FETCH_COPY_FACTS):
        return True
    if first["provider_ref"] and first["provider_ref"] == second["provider_ref"]:
        return False
    if _conflicting_counterparties(first, second):
        return True
    remittance_matches = (first["creditor_ref"] and first["creditor_ref"] == second["creditor_ref"]
                          and (first["provider_ref"] or second["provider_ref"]))
    return not (current_lookup_matches or remittance_matches)


def _statement_day_balances(movements):
    for amount, observations in movements.items():
        groups, unresolved = _compatible_copy_groups(list(observations.values()), _statement_copies_conflict)
        for versions in groups:
            ending = next((row["_statement_balance"] for row in versions if row["_statement_balance"] is not None), None)
            yield amount, ending
        if unresolved:
            yield None, None


def _statement_day_span(edges):
    """Return valid opening balances and the closing balance, if fixed."""
    net = Counter()
    neighbors = defaultdict(set)
    for before, after in edges:
        net[before] += 1
        net[after] -= 1
        neighbors[before].add(after)
        neighbors[after].add(before)
    if not neighbors:
        return set(), None

    # A directed trail exists when the underlying graph is connected and
    # exactly its start/end are unbalanced (or every vertex is balanced).
    remaining = set(neighbors)
    stack = [remaining.pop()]
    while stack:
        reached = neighbors[stack.pop()] & remaining
        remaining.difference_update(reached)
        stack.extend(reached)
    if remaining:
        return set(), None
    imbalance = {balance: change for balance, change in net.items() if change}
    if not imbalance:
        return set(neighbors), None
    if sorted(imbalance.values()) == [-1, 1]:
        return {balance for balance, change in imbalance.items() if change == 1}, min(imbalance, key=imbalance.get)
    return set(), None


def _statement_gap_closings(edges, missing, openings, closings):
    """Try separately placed gaps under a fixed search budget."""
    budget = 256
    if openings is None:
        shifts = {0}
        for change in missing:
            shifts |= {shift + change for shift in shifts}
            if len(shifts) > budget:
                return False
        openings = set()
        for start, _ in edges:
            for shift in shifts:
                openings.add(start - shift)
                if len(openings) > budget:
                    return False

    def next_states(balance, remaining, gaps):
        for index, edge in enumerate(remaining):
            start, end = edge
            if start == balance and (index == 0 or edge != remaining[index - 1]):
                yield end, remaining[:index] + remaining[index + 1:], gaps
        anchors = {start for start, _ in remaining}
        choices = (index for index, change in enumerate(gaps) if index == 0 or change != gaps[index - 1])
        for index in sorted(choices, key=lambda i: balance + gaps[i] not in anchors):
            yield balance + gaps[index], remaining, gaps[:index] + gaps[index + 1:]

    edges, missing = tuple(sorted(edges)), tuple(sorted(missing))
    day_change = sum(end - start for start, end in edges) + sum(missing)
    scheduled = set()
    truncated = False
    for opening in sorted(openings):
        closing = opening + day_change
        if closing in closings:
            continue
        if len(scheduled) == budget:
            return False
        initial = (opening, edges, missing)
        scheduled.add(initial)
        pending = [initial]
        while pending:
            balance, remaining, gaps = pending.pop()
            if not remaining or (not gaps and balance in _statement_day_span(remaining)[0]):
                closings.add(closing)
                break
            next_steps = []
            for state in next_states(balance, remaining, gaps):
                if state in scheduled:
                    continue
                if len(scheduled) == budget:
                    truncated = True
                    break
                scheduled.add(state)
                next_steps.append(state)
            pending.extend(reversed(next_steps))
    return not truncated


def _statement_day_closings(currency, movements, openings, *, anchored, backwards):
    edges = []
    missing = []
    for amount, ending in _statement_day_balances(movements):
        if amount is None or (ending is not None and ending[0] != currency):
            return set(), False
        if ending is None:
            missing.append(-amount if backwards else amount)
        else:
            before, after = ending[1] - amount, ending[1]
            edges.append((after, before) if backwards else (before, after))

    if missing and not anchored and (edges or openings is not None):
        return set(), False
    change = sum(missing)
    if not edges:
        return (None if openings is None else {start + change for start in openings}), True
    closings = set()

    def follow(trail):
        starts, finish = _statement_day_span(trail)
        feasible = starts if openings is None else starts & openings
        if feasible:
            closings.update((finish,) if finish is not None else feasible)

    if not change:
        follow(edges)
    if not missing:
        return closings, True

    # A contiguous gap has exactly the sum of its observed movements. Test
    # every way it can meet a declared balance, never an arbitrary partition.
    vertices = {point for edge in edges for point in edge}
    if change:
        for start in vertices | {point - change for point in vertices}:
            follow([*edges, (start, start + change)])
    complete = len(missing) <= 1 or _statement_gap_closings(edges, missing, openings, closings)
    return closings, complete


def _statement_observe(movements, row, day):
    identity = tuple(row[fact] for fact in _STATEMENT_OBSERVATION_FACTS)
    if not row["provider_ref"] and not row["_transaction_id"]:
        identity += (row["_statement_sources"],)
    movements[day][Decimal(row["amount"])][identity] = row


def _statement_trail(currency, observations, candidates, interval, *, entering=None, leaving=None, backwards=False):
    first_day, last_day = interval
    movements = defaultdict(lambda: defaultdict(dict))
    for day, rows in observations.items():
        if first_day <= day <= last_day:
            for row in rows:
                _statement_observe(movements, row, day)
    anchored = any(row["_statement_balance"] and row["_statement_balance"][0] == currency
                   for day, rows in observations.items() if first_day <= day <= last_day for row in rows)
    for day, row in candidates:
        _statement_observe(movements, row, day)
    for checkpoint in (entering, leaving):
        if checkpoint is not None:
            movements.setdefault(checkpoint[0], {})
    openings = None
    complete = True
    for day in sorted(movements, reverse=backwards):
        if entering is not None and day == entering[0]:
            openings = entering[1] if openings is None else openings & entering[1]
        openings, checked = _statement_day_closings(
            currency, movements[day], openings, anchored=anchored, backwards=backwards,
        )
        complete &= checked
        if leaving is not None and day == leaving[0]:
            openings = leaving[1] if openings is None else openings & leaving[1]
        if openings is not None and not openings:
            break
    return openings, complete


def _statement_fit(trail):
    balances, complete = trail
    if balances is None or balances:
        return True
    return False if complete else None


def _statement_evidence(row):
    facts = row.get("_statement_evidence", {})
    return row | {field: value for field, value in facts.items() if row[field] is None} if facts else row


def _statement_variants(first, second, account_rows, date_fields=_SECONDARY_BANK_DATES):
    """Return supported version indexes, an ambiguous empty tuple, or no evidence."""
    first, second = _statement_evidence(first), _statement_evidence(second)
    if not first["balance_key"] or first["balance_key"] != second["balance_key"]:
        return None
    currency, _ = first["_statement_balance"]
    amount = Decimal(first["amount"])
    if currency != first["currency"] or not amount:
        return None
    sources = first["_statement_sources"] | second["_statement_sources"]
    supported = set()
    for field in date_fields:
        days = (first[field], second[field])
        if not all(days) or days[0] == days[1]:
            continue
        start, end = sorted(days)
        observations = defaultdict(list)
        for index, row in enumerate(account_rows):
            day = row[field]
            if day and row["currency"] == currency and index not in sources and Decimal(row["amount"]):
                observations[day].append(row)
        versions = ((days[0], first), (days[1], second))
        inside = start, end
        local_closings, closed_completely = _statement_trail(currency, observations, versions, inside)
        if not local_closings:
            continue
        anchored_days = [day for day, rows in observations.items()
                         if any(row["_statement_balance"] and row["_statement_balance"][0] == currency for row in rows)]
        has_prior = any(day < start for day in anchored_days)
        has_following = any(day > end for day in anchored_days)
        if not (has_prior or has_following):
            supported.add((0, 1))
            continue

        # Compare alternatives under the same boundaries. In the absence of
        # a surrounding balance on one side, keep the dated trail's boundary
        # there so deleting an endpoint cannot invent a new opening/closing.
        entering = leaving = None
        if not has_prior:
            local_openings, opened_completely = _statement_trail(currency, observations, versions, inside, backwards=True)
            if not opened_completely or not local_openings:
                supported.add(())
                continue
            entering = start, local_openings
        if not has_following:
            if not closed_completely:
                supported.add(())
                continue
            leaving = end, local_closings

        interval = min(start, min(observations)), max(end, max(observations))
        alternatives = tuple(
            _statement_fit(_statement_trail(currency, observations, candidate, interval, entering=entering, leaving=leaving))
            for candidate in (versions, (versions[0],), (versions[1],))
        )
        if alternatives == (True, False, False):
            supported.add((0, 1))
        elif alternatives == (False, True, False):
            supported.add((0,))
        elif alternatives == (False, False, True):
            supported.add((1,))
        else:
            supported.add(())
    if len(supported) == 1:
        return next(iter(supported))
    return () if supported else None


def _balance_repeats(first, second, account_rows):
    return _statement_variants(first, second, account_rows) == (0, 1)


def _statement_preferred_copy(versions, account_rows):
    versions = list({row["_statement_sources"]: row for row in versions}.values())
    preferred = set()
    rejected = set()
    ambiguous = False
    for left, right in combinations(range(len(versions)), 2):
        result = _statement_variants(versions[left], versions[right], account_rows)
        if result == (0,):
            preferred.add(left)
            rejected.add(right)
        elif result == (1,):
            preferred.add(right)
            rejected.add(left)
        elif result == ():
            ambiguous = True
    if len(preferred) == 1 and not (preferred & rejected or ambiguous):
        return versions[next(iter(preferred))], False, [versions[index] for index in rejected]
    return None, ambiguous or bool(preferred), ()


def _note_statement_rejections(row, preferred, rejected):
    for version in rejected:
        dates = tuple((field, version[field]) for field in ("booked_day", *_SECONDARY_BANK_DATES)
                      if version[field] and preferred[field] and version[field] != preferred[field])
        if dates:
            row.setdefault("_statement_rejections", set()).add((version["ref"], dates))


def _dated_copies_conflict(first, second, account_rows):
    one, two = _statement_evidence(first), _statement_evidence(second)
    same_financial_facts = all(one[field] and one[field] == two[field] for field in _REFERENCE_COPY_FACTS)
    date_correction = same_financial_facts and not _balance_repeats(first, second, account_rows)
    fields = _FIXED_BOOKING_FACTS if date_correction else _OPTIONAL_BOOKING_FACTS
    return _conflicting_facts(first, second, fields)


def _merge_dated_bookings(dated_ref, copies, account_rows):
    """Combine compatible copies and keep payments with conflicting known facts separate."""
    groups, unresolved = _compatible_copy_groups(
        copies, lambda first, second: _dated_copies_conflict(first, second, account_rows),
    )

    merged = []
    skipped = len({row["ref"] for row in unresolved})
    for versions in groups:
        known = {field: row[field] for row in versions for field in _FIXED_BOOKING_FACTS if row[field]}
        preferred, ambiguous, rejected = _statement_preferred_copy(versions, account_rows)
        for field in _SECONDARY_BANK_DATES:
            known[field] = (preferred and preferred[field]) or min((copy[field] for copy in versions if copy[field]), default=None)
        known["counterparty_ids"] = tuple(sorted({pair for copy in versions for pair in copy["counterparty_ids"]}))
        ref = _dated_booking_ref(dated_ref, known)
        row = min(versions, key=lambda version: (version["ref"] != ref, version["description"])) | known
        row["ref"] = ref
        row["booked_day"] = next((copy["booked_day"] for copy in versions if copy["booked_day"]), None)
        _merge_copy_metadata(row, versions)
        _note_statement_rejections(row, preferred, rejected)
        row["prior_refs"].extend(copy["ref"] for copy in versions if copy["ref"] != ref)
        skipped += max(int(ambiguous), len({copy["description"] for copy in versions}) - 1)
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


def _fetch_copies_conflict(first, second, account_rows):
    one, two = _statement_evidence(first), _statement_evidence(second)
    same_balance = one["balance_key"] and one["balance_key"] == two["balance_key"]
    same_reference = one["creditor_ref"] and one["creditor_ref"] == two["creditor_ref"]
    same_booking = (all(first[field] and first[field] == second[field] for field in ("booked_day", "provider_ref"))
                    and core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True)
    date_correction = same_balance and (same_reference or same_booking) and not _balance_repeats(first, second, account_rows)
    fields = _FETCH_FIXED_FACTS if date_correction else _FETCH_COPY_FACTS
    return _conflicting_facts(first, second, fields) or _conflicting_counterparties(first, second)


def _merge_fetch_copies(account_key, rows):
    """Use the current lookup ID within one account fetch, before numbering source occurrences."""
    batches = defaultdict(list)
    for index, row in enumerate(rows):
        lookup_id = row["_transaction_id"]
        group = (lookup_id, row["_amount_key"], row["currency"]) if lookup_id else (index,)
        batches[group].append(row)

    merged = []
    skipped = 0
    for copies in (group for batch in batches.values() for group in _corroborated_fetch_groups(batch)):
        if len(copies) == 1:
            merged.extend(copies)
            continue
        groups, unresolved = _compatible_copy_groups(
            copies, lambda first, second: _fetch_copies_conflict(first, second, rows),
        )
        skipped += len(unresolved)
        payments = []
        for versions in groups:
            preferred, ambiguous, rejected = _statement_preferred_copy(versions, rows)
            preferred = preferred or min(
                versions, key=lambda row: (not row["provider_ref"], not row["booked_day"],
                                           -sum(bool(row[field]) for field in _OPTIONAL_BOOKING_FACTS),
                                           row["description"], row["ref"] or row["_source_key"]),
            )
            known = {field: row[field] for row in versions for field in _FETCH_FIXED_FACTS if row[field]}
            for field in _SECONDARY_BANK_DATES:
                known[field] = preferred[field] or min((copy[field] for copy in versions if copy[field]), default=None)
            row = preferred | known
            _merge_copy_metadata(row, versions)
            _note_statement_rejections(row, preferred, rejected)
            effective_day = row["booked_day"] or row["value_day"] or row["transaction_day"]
            row["date"] = date.fromisoformat(effective_day).isoformat()
            row["_source_keys"] = tuple(dict.fromkeys(key for copy in versions for key in copy["_source_keys"]))
            row["prior_refs"].extend(copy["ref"] for copy in versions if copy["ref"])
            if row["provider_ref"]:
                row["_dated_ref"] = fingerprint(account_key, "entry", row["_entry_reference"], row["date"],
                                                row["_amount_key"], row["currency"])
                row["ref"] = _dated_booking_ref(row["_dated_ref"], row)
            skipped += max(int(ambiguous), len({copy["_remittance"] for copy in versions}) - 1)
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
        booking["_statement_sources"] |= copy["_statement_sources"]
        if copy.get("_statement_rejections"):
            booking.setdefault("_statement_rejections", set()).update(copy["_statement_rejections"])
        if not booking["balance_key"]:
            booking["_statement_balance"] = copy["_statement_balance"]
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


def _compare_posting_dates(rows, account_rows):
    by_reference = defaultdict(list)
    preferred = set()
    rejected = set()
    comparisons = []
    for row in rows:
        if row["provider_ref"] and row["booked_day"]:
            by_reference[row["provider_ref"]].append(row)
    for versions in by_reference.values():
        for first, second in combinations(versions, 2):
            if first["booked_day"] == second["booked_day"] or not core._bank_corroborates(first, second):
                continue
            result = _statement_variants(first, second, account_rows, ("booked_day",))
            if result in {(0,), (1,)}:
                pair = (first, second)
                winner, = result
                preferred.add(pair[winner]["ref"])
                rejected.add(pair[1 - winner]["ref"])
                comparisons.append((pair[winner], pair[1 - winner]))
                continue
            separate = result == (0, 1)
            if separate:
                preferred.update((first["ref"], second["ref"]))
            for row, other in ((first, second), (second, first)):
                peers = row.setdefault("_booked_date_peers", {})
                day = other["booked_day"]
                peers[day] = peers.get(day, False) or separate
    omitted = rejected - preferred
    for winner, loser in comparisons:
        if loser["ref"] in omitted:
            _note_statement_rejections(winner, winner, (loser,))
    return omitted


def _statement_source_conflict(first, second):
    matching_id = any(first[field] and first[field] == second[field] for field in ("provider_ref", "_transaction_id"))
    return not matching_id or _conflicting_facts(first, second, _FETCH_COPY_FACTS) or _conflicting_counterparties(first, second)


def _link_repeated_statement_sources(rows):
    """Link unambiguous same-day observations before testing alternative dates."""
    observations = defaultdict(list)
    for row in rows:
        if row["provider_ref"] or row["_transaction_id"]:
            observations[row["currency"], row["_amount_key"], row["date"]].append(row)
    for copies in observations.values():
        identifiers = Counter((field, row[field]) for row in copies
                              for field in ("provider_ref", "_transaction_id") if row[field])
        candidates = [row for row in copies if any(identifiers[field, row[field]] > 1
                                                 for field in ("provider_ref", "_transaction_id"))]
        if len(candidates) < 2:
            continue
        groups, _ = _compatible_copy_groups(candidates, _statement_source_conflict)
        for versions in groups:
            if len(versions) < 2:
                continue
            sources = frozenset().union(*(version["_statement_sources"] for version in versions))
            evidence = {field: version[field] for version in versions
                        for field in (*_REFERENCE_COPY_FACTS, "_statement_balance") if version[field] is not None}
            for row in versions:
                row["_statement_sources"] = sources
                row["_statement_evidence"] = evidence


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
        statement_balance = _statement_balance(tx.get("balance_after_transaction"))
        balance_key = None
        if statement_balance is not None:
            balance_currency, balance = statement_balance
            balance_key = fingerprint(balance_currency, str(balance.normalize()) if balance else "0")
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
        row["_statement_balance"] = statement_balance
        row["_statement_sources"] = frozenset((len(drafts),))
        row["_entry_reference"] = entry_ref
        row["_source_key"], row["_source_keys"] = source_key, source_keys
        row["_unreferenced_keys"] = unreferenced_keys
        row["prior_refs"] = list(dict.fromkeys(prior_refs))
        drafts.append(row)
    _link_repeated_statement_sources(drafts)
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
            merged, warnings = _merge_dated_bookings(booking_key, copies, drafts)
            rows.extend(merged)
            skipped += warnings
    rows, warnings = _merge_reference_copies(rows)
    rejected = _compare_posting_dates(rows, drafts)
    for row in rows:
        del row["_statement_balance"]
        del row["_statement_sources"]
        del row["_transaction_id"]
        row.pop("_statement_evidence", None)
    return [row for row in rows if row["ref"] not in rejected], skipped + warnings
