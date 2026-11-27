"""Enable Banking's account-information API and transaction mapping."""
import base64
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal, InvalidOperation
from http.client import HTTPException, HTTPSConnection
from itertools import combinations, groupby, islice, product
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


class _TransactionReport(dict):
    """Keep the provider page available during normalization."""

    def __init__(self, row, page):
        super().__init__(row)
        self.page = page


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
        page_index = 0
        while True:
            page = self.request("GET", path, query=dict(query))
            items = page.get("transactions")
            if not isinstance(items, list):
                raise BankingError("Enable Banking lieferte keine gültige Umsatzliste.")
            yield from (_TransactionReport(item, page_index) if isinstance(item, dict) else item for item in items)
            cursor = page.get("continuation_key")
            if not cursor:
                return
            if not isinstance(cursor, str) or cursor in seen:
                raise BankingError("Enable Banking hat eine Umsatzseite wiederholt.")
            seen.add(cursor)
            query["continuation_key"] = cursor
            page_index += 1


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
_STATEMENT_DATE_FIELDS = ("booked_day", *_SECONDARY_BANK_DATES)
_FIXED_BOOKING_FACTS = (*_FINANCIAL_BOOKING_FACTS, "counterparty_iban")
_OPTIONAL_BOOKING_FACTS = (*_FIXED_BOOKING_FACTS, *_SECONDARY_BANK_DATES)
_REFERENCE_COPY_FACTS = ("balance_key", "creditor_ref")
_FETCH_COPY_FACTS = ("provider_ref", "booked_day", *_OPTIONAL_BOOKING_FACTS)
_FETCH_FIXED_FACTS = ("provider_ref", "booked_day", *_FIXED_BOOKING_FACTS)
_STATEMENT_IDENTITY_FACTS = ("provider_ref", "creditor_ref", "reference_schema")
_STATEMENT_OBSERVATION_FACTS = (*_FETCH_COPY_FACTS, "counterparty_ids", "_counterparty_names",
                                "_transaction_id", "_statement_balance")
_STATEMENT_PLACEMENT_BUDGET = core._BANK_BALANCE_TRAIL_LIMIT


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
    if first.get("_statement_independent") and second.get("_statement_independent"):
        return True
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


def _statement_observe(movements, row, day, *, independent=False):
    identity = tuple(row[fact] for fact in _STATEMENT_OBSERVATION_FACTS)
    if independent or not (row["provider_ref"] or row["_transaction_id"]):
        identity += (row["_statement_sources"],)
    if independent:
        row = row | {"_statement_independent": True}
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
        _statement_observe(movements, row, day, independent=True)
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


def _statement_observations(account_rows, sources, currency):
    observations = {}
    dates = ("booked_day", *_SECONDARY_BANK_DATES)
    for index, row in enumerate(account_rows):
        if index in sources or row["currency"] != currency or not Decimal(row["amount"]):
            continue
        if row.get("_statement_capacity"):
            # A linked copy group still has up to its observed number of
            # occurrences when independent balances can settle the count.
            row = row | {"_statement_sources": frozenset((index,)), "_statement_occurrence": True}
        else:
            row = _statement_evidence(row)
        provenance = row["_statement_sources"]
        previous = observations.get(provenance)
        if previous is None:
            observations[provenance] = row
        else:
            if row["provider_ref"] and not previous["provider_ref"]:
                row, previous = previous, row
            observations[provenance] = previous | {field: row[field] for field in dates if row[field] and not previous[field]}
    return list(observations.values())


def _same_statement_fact(first, second, field):
    return bool(first[field] and first[field] == second[field])


def _statement_identity_conflict(first, second):
    return (_conflicting_facts(first, second, ("provider_ref", *_FIXED_BOOKING_FACTS))
            or _conflicting_counterparties(first, second))


def _statement_dates_compatible(versions):
    return all(len({row[field] for row in versions if row[field]}) <= 1 for field in _STATEMENT_DATE_FIELDS)


def _statement_corroborates(first, second):
    if _statement_identity_conflict(first, second):
        return False
    balance = _same_statement_fact(first, second, "balance_key")
    invoice = _same_statement_fact(first, second, "creditor_ref")
    payer = core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True
    # Use the same local evidence that could merge an unidentified copy.
    # The balance proof can instead keep it as a separate observation.
    compatible_copy = ((balance or invoice) and _statement_dates_compatible((first, second))
                       and not first["bank_groups"].keys().isdisjoint(second["bank_groups"]))
    return ((_same_statement_fact(first, second, "provider_ref") and (balance or invoice))
            or (_same_statement_fact(first, second, "_transaction_id") and (balance or (invoice and payer)))
            or (bool(first["provider_ref"] or second["provider_ref"]) and (compatible_copy or (balance and invoice and payer))))


def _statement_identity_keys(row):
    for field in ("provider_ref", "_transaction_id"):
        if row[field]:
            yield field, row[field]
    if row["balance_key"] and row["creditor_ref"]:
        yield "financial", (row["balance_key"], row["creditor_ref"])
    for evidence in _booking_evidence(row):
        yield "dated_financial", evidence


def _statement_distinct_versions(first, second, date_fields):
    lookup_distinguishes = bool(first["_transaction_id"] and second["_transaction_id"]
                                and first["_transaction_id"] != second["_transaction_id"])
    unlinked_observation = (first["_statement_sources"].isdisjoint(second["_statement_sources"])
                            and any(not row["_transaction_id"] or row.get("_statement_occurrence")
                                    for row in (first, second)))
    return lookup_distinguishes or unlinked_observation or any(
        first[field] and second[field] and first[field] != second[field] for field in date_fields
    )


def _statement_other_versions(observations):
    """Group positively linked versions while leaving conflicting bridges unresolved."""
    buckets = defaultdict(list)
    for index, row in enumerate(observations):
        for key in _statement_identity_keys(row):
            buckets[row["currency"], row["_amount_key"], key].append(index)
    links = defaultdict(set)
    for (_, _, key), bucket in buckets.items():
        if key[0] in {"financial", "dated_financial"}:
            identified = [index for index in bucket if observations[index]["provider_ref"]]
            sparse = [index for index in bucket if not observations[index]["provider_ref"]]
            pairs = product(identified, sparse)
        else:
            pairs = combinations(bucket, 2)
        for left, right in pairs:
            if _statement_corroborates(observations[left], observations[right]):
                links[left].add(right)
                links[right].add(left)
    date_fields = ("booked_day", *_SECONDARY_BANK_DATES)
    cohorts = []
    unresolved = False
    remaining = set(links)
    while remaining:
        connected = {remaining.pop()}
        pending = list(connected)
        while pending:
            adjacent = links[pending.pop()] & remaining
            remaining.difference_update(adjacent)
            pending.extend(adjacent)
            connected.update(adjacent)
        groups, uncertain = _compatible_copy_groups(
            [observations[index] for index in sorted(connected)], _statement_identity_conflict,
        )
        unresolved |= bool(uncertain)
        for variants in groups:
            if (len(variants) > 1 and any(row["provider_ref"] for row in variants)
                    and all(_statement_distinct_versions(first, second, date_fields)
                            for first, second in combinations(variants, 2))):
                cohorts.append(tuple(variants))
    return cohorts, unresolved


def _statement_shape(row):
    return tuple(row[field] for field in _STATEMENT_OBSERVATION_FACTS if field != "_transaction_id") + (row["_remittance"],)


def _reported_balance(row):
    balance = row["_statement_balance"]
    if balance and balance[0] == row["currency"] and Decimal(row["amount"]):
        return balance
    return None


def _same_reported_edge(first, second):
    balance = _reported_balance(first)
    return bool(balance and first["_amount_key"] == second["_amount_key"] and balance == _reported_balance(second)
                and any(_same_statement_fact(first, second, field) for field in _STATEMENT_DATE_FIELDS))


def _statement_choices(versions, shapes):
    repeated = defaultdict(list)
    for version, shape in zip(versions, shapes):
        repeated[shape].append(version)
    groups = tuple(repeated.values())
    counts = (range(len(group), -1, -1) for group in groups)
    choices = (tuple(item for group, count in zip(groups, selected) for item in group[:count])
               for selected in product(*counts) if any(selected))
    return tuple(sorted(islice(choices, _STATEMENT_PLACEMENT_BUDGET + 1), key=len, reverse=True))


def _statement_search(currency, observed, candidates, other_versions, floating, interval, *,
                      entering=None, leaving=None, backwards=False, find_any=False, slots_by_booking=None):
    """Return proven boundary balances and whether every placement was checked."""
    budget = _STATEMENT_PLACEMENT_BUDGET
    days = sorted(set(observed) | {day for day, _ in candidates if day}
                  | {day for options in other_versions for version in options for day, _ in version if day})
    balances = set()
    complete = True
    for other in product(*other_versions):
        included = (*candidates, *(item for version in other for item in version))
        fixed = tuple((day, row) for day, row in included if day)
        undated = [*floating, *(row for day, row in included if not day)]
        positions = [slots_by_booking.get(row["booked_day"], days) if slots_by_booking else days for row in undated]
        for slots in product(*positions):
            if not budget:
                return balances, False
            budget -= 1
            # Slots are possible positions in the proof, never inferred dates
            # written to the booking or copied from another date field.
            world = (*fixed, *zip(slots, undated))
            result, checked = _statement_trail(currency, observed, world, interval,
                                               entering=entering, leaving=leaving, backwards=backwards)
            if result is None or (find_any and result):
                return result, checked
            balances.update(result)
            complete &= checked
    return balances, complete


def _statement_boundary(currency, observed, choices, other_versions, interval, *, backwards):
    """Use the largest feasible local trail to constrain an unanchored end."""
    for _, subsets in groupby(choices, key=len):
        boundaries = set()
        complete = True
        for subset in subsets:
            balances, checked = _statement_search(
                currency, observed, subset, other_versions, (), interval, backwards=backwards,
            )
            if balances:
                boundaries.update(balances)
            complete &= checked
        if boundaries or not complete:
            return boundaries, complete
    return set(), True


def _statement_outcomes(versions, account_rows, date_fields):
    """Return all supported subsets, an indeterminate empty tuple, or no evidence."""
    versions = tuple(_statement_evidence(row) for row in versions)
    balances = {row["balance_key"] for row in versions if row["balance_key"]}
    if len(balances) > 1 or (not balances and not all(row.get("_statement_occurrence") for row in versions)):
        return None
    first = versions[0]
    currency = first["currency"]
    if not Decimal(first["amount"]) or any(row["_statement_balance"] and row["_statement_balance"][0] != currency
                                            for row in versions):
        return None
    if not any(_statement_distinct_versions(one, two, date_fields) for one, two in combinations(versions, 2)):
        return None
    indices = tuple(range(len(versions)))
    choices = tuple(tuple(sorted(choice)) for choice in _statement_choices(indices, map(_statement_shape, versions)))
    if len(choices) > _STATEMENT_PLACEMENT_BUDGET:
        return ()
    sources = frozenset().union(*(row["_statement_sources"] for row in versions))
    observed = _statement_observations(account_rows, (), currency)
    all_cohorts, unresolved = _statement_other_versions(observed)
    if unresolved:
        return None
    # Removing subject versions from the hypothesis must not turn an
    # unidentified bridge into evidence that uniquely supports another group.
    observations = [row for row in observed if row["_statement_sources"].isdisjoint(sources)]
    cohorts = [tuple(row for row in cohort if row["_statement_sources"].isdisjoint(sources)) for cohort in all_cohorts]
    cohorts = [cohort for cohort in cohorts if len(cohort) > 1]
    competing_sources = {row["_statement_sources"] for version in cohorts for row in version}
    fixed = [row for row in observations if row["_statement_sources"] not in competing_sources]
    supported = set()
    direct = False
    inconsistent = False
    uncertain = False
    axes = (*date_fields, "booked_day") if "booked_day" not in date_fields else date_fields
    compatible_dates = _statement_dates_compatible(versions)
    for field in axes:
        days = tuple(row[field] for row in versions)
        reported_days = [day for day in days if day]
        if not reported_days:
            continue
        dated = defaultdict(list)
        floating = []
        for row in fixed:
            if row[field]:
                dated[row[field]].append(row)
            else:
                floating.append(row)
        others = [_statement_choices(tuple((row[field], row) for row in cohort), map(_statement_shape, cohort))
                  for cohort in cohorts]
        other_days = [tuple(row[field] for row in cohort) for cohort in cohorts]
        alternate_days = [day for dates in other_days if len(set(dates)) > 1 for day in dates if day]
        dates = reported_days + alternate_days
        start, end = min(dates), max(dates)
        candidates = tuple(zip(days, versions))
        candidate_sets = tuple(tuple(candidates[index] for index in subset) for subset in choices)
        inside = start, end
        anchored_days = {day for day, rows in dated.items()
                         if any(row["_statement_balance"] and row["_statement_balance"][0] == currency for row in rows)}
        # Another cohort can vary in count while its date still provides a
        # reported balance in every possible placement.
        anchored_days.update(dates[0] for cohort, dates in zip(cohorts, other_days)
                             if dates[0] and len(set(dates)) == 1 and all(
                                 row["_statement_balance"] and row["_statement_balance"][0] == currency for row in cohort
                             ))
        prior = any(day < start for day in anchored_days)
        following = any(day > end for day in anchored_days)
        if not balances and not (prior and following):
            continue
        intraday = compatible_dates and start == end and start in anchored_days and sum(
            bool(row["_statement_balance"] and row["_statement_balance"][0] == currency)
            for row in (*dated[start], *floating)
        ) >= 2
        undated = (len(reported_days) != len(days) or bool(floating)
                   or any(row[field] is None for cohort in cohorts for row in cohort))
        if undated and not (intraday or (prior and following)):
            continue
        if start == end and not (intraday or (prior and following)):
            continue
        has_prior = prior or intraday or (start in anchored_days and any(row["_statement_balance"] is None for row in dated[start]))
        has_following = following or intraday or (end in anchored_days and any(row["_statement_balance"] is None for row in dated[end]))
        if not (has_prior or has_following):
            local, _ = _statement_search(currency, dated, candidates, others, floating, inside, find_any=True)
            direct |= bool(local)
            continue

        # Preserve the observed local opening unless an earlier reported
        # balance provides it independently. A local closing is needed only
        # when the trailing statement gives no separate balance evidence.
        entering = leaving = None
        if not (prior or intraday):
            local_openings, opened_completely = _statement_boundary(
                currency, dated, candidate_sets, others, inside, backwards=True,
            )
            if not opened_completely or not local_openings:
                uncertain |= not opened_completely
                inconsistent |= opened_completely
                continue
            entering = start, local_openings
        if not has_following:
            local_closings, closed_completely = _statement_boundary(
                currency, dated, candidate_sets, others, inside, backwards=False,
            )
            if not closed_completely or not local_closings:
                uncertain |= not closed_completely
                inconsistent |= closed_completely
                continue
            leaving = end, local_closings

        considered_days = [start, end, *dated, *(day for dates in other_days for day in dates if day)]
        interval = min(considered_days), max(considered_days)
        results = tuple(
            _statement_fit(_statement_search(currency, dated, candidate, others, floating, interval,
                                             entering=entering, leaving=leaving, find_any=True))
            for candidate in candidate_sets
        )
        supported.update(subset for subset, fits in zip(choices, results) if fits is True)
        uncertain |= None in results
        inconsistent |= all(fits is False for fits in results)
    if uncertain:
        return ()
    if supported:
        return tuple(sorted(supported))
    if inconsistent:
        return ()
    return (indices,) if direct else None


def _statement_variants(first, second, account_rows, date_fields=_SECONDARY_BANK_DATES):
    outcomes = _statement_outcomes((first, second), account_rows, date_fields)
    if outcomes == ((0,), (1,)) and (first["booked_day"] or first["date"]) == (second["booked_day"] or second["date"]):
        # Either alias represents one payment on the same reported day.
        return None
    if outcomes is None:
        return None
    return outcomes[0] if len(outcomes) == 1 else ()


def _balance_repeats(first, second, account_rows):
    return _statement_variants(first, second, account_rows) == (0, 1)


def _statement_preferred_copy(versions, account_rows):
    selected = next((row for row in versions if row.get("_statement_choice")), None)
    if selected is not None:
        return selected, False, ()
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


def _statement_slot_conflict(first, second):
    if first.get("_statement_extra_sparse") or second.get("_statement_extra_sparse"):
        return first["_report_index"] != second["_report_index"]
    left = first.get("_statement_slot")
    right = second.get("_statement_slot")
    if left and right and left[0] == right[0]:
        return left[1] != right[1]
    return None


def _statement_slots(versions, outcomes):
    """Keep the count proved for each reported booking day."""
    booked = defaultdict(set)
    for index, row in enumerate(versions):
        booked[row["booked_day"] or row["date"]].add(index)
    if not outcomes:
        return [(0, tuple(range(len(versions))))] if len(booked) == 1 else []
    chosen = outcomes[0]
    slots = []
    for indices in booked.values():
        on_day = {tuple(index for index in subset if index in indices) for subset in outcomes}
        selected = tuple(index for index in chosen if index in indices)
        if len({len(subset) for subset in on_day}) == 1:
            slots.extend(zip(selected, zip(*on_day)))
        else:
            mandatory = set.intersection(*(set(subset) for subset in on_day))
            slots.extend((index, (index,)) for index in sorted(mandatory))
    return slots


def _resolve_statement_cohorts(drafts):
    """Apply the supported count and placements of larger cohorts once."""
    omitted = set()
    selected = {}
    warnings = 0
    for currency in {row["currency"] for row in drafts}:
        observations = _statement_observations(drafts, (), currency)
        cohorts, _ = _statement_other_versions(observations)
        dates = ("booked_day", *_SECONDARY_BANK_DATES)
        for cohort in cohorts:
            if len(cohort) == 2 and all(row[field] for row in cohort for field in ("provider_ref", *_REFERENCE_COPY_FACTS)) and any(
                cohort[0][field] and cohort[1][field] and cohort[0][field] != cohort[1][field] for field in dates
            ):
                continue
            versions = sorted(cohort, key=lambda row: (row["booked_day"] or row["date"],
                                                       *(row[field] or "" for field in _SECONDARY_BANK_DATES),
                                                       row["ref"] or ""))
            outcomes = _statement_outcomes(versions, drafts, dates)
            if outcomes is None:
                continue
            if (any(row.get("_statement_occurrence") for row in versions) and _statement_dates_compatible(versions)
                    and len({len(outcome) for outcome in outcomes}) != 1):
                warnings += int(bool(outcomes))
                continue
            slots = _statement_slots(versions, outcomes)
            all_sources = frozenset().union(*(row["_statement_sources"] for row in versions))
            supported = [versions[index] for index in {index for subset in outcomes for index in subset}]
            rejected = [version for version in versions if outcomes and not any(
                version["date"] == accepted["date"] and _statement_dates_compatible((version, accepted))
                for accepted in supported
            )]
            occurrences = Counter(index for _, alternatives in slots for index in set(alternatives))
            chosen = {index for index, _ in slots}
            kept = set()
            for position, (preferred, alternatives) in enumerate(slots):
                compatible = {preferred, *(index for index in alternatives if occurrences[index] == 1 and index not in chosen)}
                identified = next((versions[index] for index in sorted(compatible) if versions[index]["provider_ref"]), None)
                for index in compatible:
                    sources = versions[index]["_statement_sources"]
                    kept.update(sources)
                    for source in sources:
                        row = drafts[source] | {"_statement_slot": (all_sources, position), "_statement_sources": sources}
                        if identified is not None and not row["provider_ref"]:
                            for field in ("provider_ref", "_dated_ref", "_entry_reference"):
                                row[field] = identified[field]
                            row["ref"] = _dated_booking_ref(row["_dated_ref"], row)
                        if index == preferred:
                            row["_statement_choice"] = True
                            _note_statement_rejections(row, versions[preferred], rejected)
                        selected[source] = row
            omitted.update(all_sources - kept)
            ambiguous_dates = any(
                not _statement_dates_compatible([versions[index] for index in alternatives])
                for _, alternatives in slots
            )
            warnings += int({len(outcome) for outcome in outcomes} != {len(slots)} or ambiguous_dates)
    return [selected.get(index, row) for index, row in enumerate(drafts) if index not in omitted], warnings


def _dated_copies_conflict(first, second, account_rows):
    slot_conflict = _statement_slot_conflict(first, second)
    if slot_conflict is not None:
        return slot_conflict
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
    slot_conflict = _statement_slot_conflict(first, second)
    if slot_conflict is not None:
        return slot_conflict
    one, two = _statement_evidence(first), _statement_evidence(second)
    same_balance = one["balance_key"] and one["balance_key"] == two["balance_key"]
    same_reference = one["creditor_ref"] and one["creditor_ref"] == two["creditor_ref"]
    same_booking = (all(first[field] and first[field] == second[field] for field in ("booked_day", "provider_ref"))
                    and core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True)
    date_correction = same_balance and (same_reference or same_booking) and not _balance_repeats(first, second, account_rows)
    fields = _FETCH_FIXED_FACTS if date_correction else _FETCH_COPY_FACTS
    return _conflicting_facts(first, second, fields) or _conflicting_counterparties(first, second)


def _merge_fetch_copies(account_key, rows, account_rows):
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
            copies, lambda first, second: _fetch_copies_conflict(first, second, account_rows),
        )
        skipped += len(unresolved)
        payments = []
        for versions in groups:
            preferred, ambiguous, rejected = _statement_preferred_copy(versions, account_rows)
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
            if row["provider_ref"] and row["_entry_reference"]:
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
                   and not _conflicting_counterparties(row, identified[ref])
                   and _statement_slot_conflict(row, identified[ref]) is not True}
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
            if first["booked_day"] == second["booked_day"]:
                continue
            corroborates = core._bank_corroborates(first, second)
            same_finances = (all(first[field] and first[field] == second[field] for field in _REFERENCE_COPY_FACTS)
                             and not _conflicting_facts(first, second, _FIXED_BOOKING_FACTS))
            if not (corroborates or same_finances):
                continue
            slot_conflict = _statement_slot_conflict(first, second)
            result = (0, 1) if slot_conflict else _statement_variants(first, second, account_rows, ("booked_day",))
            if result in {(0,), (1,)}:
                pair = (first, second)
                winner, = result
                preferred.add(pair[winner]["ref"])
                rejected.add(pair[1 - winner]["ref"])
                comparisons.append((pair[winner], pair[1 - winner]))
                continue
            if not (corroborates or slot_conflict):
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
    if first is second:
        return False
    same_ref = _same_statement_fact(first, second, "provider_ref")
    corroborated = (same_ref and _statement_shape(first) == _statement_shape(second)) or _statement_corroborates(first, second)
    lookup_changed = first["_transaction_id"] and second["_transaction_id"] and first["_transaction_id"] != second["_transaction_id"]
    if lookup_changed and not corroborated:
        return True
    return (not (same_ref or _same_statement_fact(first, second, "_transaction_id") or corroborated)
            or _conflicting_facts(first, second, _FETCH_COPY_FACTS) or _conflicting_counterparties(first, second))


def _link_repeated_statement_sources(rows):
    """Link unambiguous same-day observations before testing alternative dates."""
    observations = defaultdict(list)
    for row in rows:
        if any(_statement_identity_keys(row)):
            observations[row["currency"], row["_amount_key"], row["date"]].append(row)
    for copies in observations.values():
        identifiers = Counter(key for row in copies for key in _statement_identity_keys(row))
        candidates = [row for row in copies if any(identifiers[key] > 1 for key in _statement_identity_keys(row))]
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


def _isolated_statement_gap(other_rows, field, day, currency):
    """Check for an observation alone between two reported balances."""
    if any(not row[field] or row[field] == day for row in other_rows):
        return False
    previous = max((row[field] for row in other_rows if row[field] < day), default=None)
    following = min((row[field] for row in other_rows if row[field] > day), default=None)
    if previous is None or following is None:
        return False
    for boundary in (previous, following):
        movements = [row for row in other_rows if row[field] == boundary]
        if (len({row["_statement_sources"] for row in movements}) != 1
                or not any(row["_statement_balance"] and row["_statement_balance"][0] == currency for row in movements)):
            return False
    return True


def _possible_statement_reset(amount, other_rows):
    """Screen for the net change needed between two equal balance edges."""
    target = -amount
    changes = [Decimal(row["amount"]) for row in other_rows]
    if not any(change * target > 0 for change in changes):
        return False
    totals = {Decimal(0)}
    for change in changes:
        totals.update({total + change for total in totals})
        if target in totals or len(totals) > _STATEMENT_PLACEMENT_BUDGET:
            return True
    return False


def _mark_statement_capacity(rows):
    """Expose plausible repeat counts together before checking the cash flow."""
    by_currency = defaultdict(list)
    for row in rows:
        if Decimal(row["amount"]):
            by_currency[row["currency"]].append(row)
    considered = set()
    eligible = set()
    for row in rows:
        sources = row["_statement_sources"]
        if len(sources) < 2 or sources in considered or not row["provider_ref"]:
            continue
        considered.add(sources)
        currency = row["currency"]
        versions = [rows[index] for index in sources]
        received = any(version["_statement_balance"] and version["_statement_balance"][0] == currency for version in versions)
        other_rows = [other for other in by_currency[currency] if other["_statement_sources"].isdisjoint(sources)]
        independent = [other for other in other_rows if other["_statement_balance"] and other["_statement_balance"][0] == currency
                       and (other["_amount_key"] != row["_amount_key"]
                            or (other["provider_ref"] and other["provider_ref"] != row["provider_ref"]))]
        reset = received and _possible_statement_reset(
            Decimal(row["amount"]), (other for other in other_rows if _statement_dates_compatible((*versions, other))),
        )
        for field in _STATEMENT_DATE_FIELDS:
            day = next((rows[index][field] for index in sources if rows[index][field]), None)
            if day is None:
                continue
            if not received and _isolated_statement_gap(other_rows, field, day, currency):
                eligible.update(sources)
                break
            if not reset:
                continue
            dated = [(other[field], other["_statement_sources"]) for other in independent if other[field]]
            surrounding = any(other_day < day for other_day, _ in dated) and any(other_day > day for other_day, _ in dated)
            intraday = len({origins for other_day, origins in dated if other_day == day}) >= 2
            if surrounding or intraday:
                eligible.update(sources)
                break
    for index in eligible:
        rows[index]["_statement_capacity"] = True


def _statement_review_copy_conflict(first, second):
    if first is second:
        return False
    current_lookup = _same_statement_fact(first, second, "_transaction_id") and any(
        _same_statement_fact(first, second, field) for field in _STATEMENT_DATE_FIELDS
    )
    corrected_ref = current_lookup or core._bank_economic_replay(first, second)
    fields = ("booked_day", *_OPTIONAL_BOOKING_FACTS) if corrected_ref else _FETCH_COPY_FACTS
    if _conflicting_facts(first, second, fields) or _conflicting_counterparties(first, second):
        return True
    matching_payment = ((not first["provider_ref"] or not second["provider_ref"])
                        and all(_same_statement_fact(first, second, field) for field in _SECONDARY_BANK_DATES)
                        and core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True
                        and _same_statement_fact(first, second, "_remittance"))
    return not (corrected_ref or _same_statement_fact(first, second, "provider_ref")
                or _statement_corroborates(first, second) or matching_payment
                or _same_reported_edge(first, second) or _statement_shape(first) == _statement_shape(second))


def _statement_review_observations(drafts, currency):
    """Retain compatible reports as the capacity of each possible booking."""
    buckets = defaultdict(lambda: defaultdict(list))
    for index, row in enumerate(drafts):
        if row["currency"] == currency and Decimal(row["amount"]):
            signature = _statement_shape(row)
            buckets[row["_amount_key"]][signature].append(row | {"_statement_sources": frozenset((index,))})
    for reports in buckets.values():
        if len(reports) > _STATEMENT_PLACEMENT_BUDGET:
            continue
        copies = [rows[0] for rows in reports.values()]
        by_origin = {row["_statement_sources"]: rows for row, rows in zip(copies, reports.values())}
        groups, unresolved = _compatible_copy_groups(copies, _statement_review_copy_conflict)
        if unresolved:
            continue
        for versions in groups:
            versions = [copy for row in versions for copy in by_origin[row["_statement_sources"]]]
            representative = min(versions, key=lambda row: (
                not row["provider_ref"], not row["booked_day"], row["description"],
                -sum(bool(row[field]) for field in (*_OPTIONAL_BOOKING_FACTS, "counterparty_ids")), row["ref"] or "",
            ))
            dates = {field: next((row[field] for row in versions if row[field]), None) for field in _STATEMENT_DATE_FIELDS}
            balance = next((row for row in versions if row["_statement_balance"]), representative)
            representative = representative | dates | {"_statement_balance": balance["_statement_balance"],
                                                          "balance_key": balance["balance_key"]}
            origins = frozenset().union(*(row["_statement_sources"] for row in versions))
            yield representative, versions, origins


def _review_statement_placements(versions, position, limit=None, joint=False):
    """Enumerate distinct assignments of reported facts to actual occurrences."""
    states = {()}
    for row in versions:
        observation = position(row), row["_statement_balance"]
        expanded = set()
        for placements in states:
            # The observation can report another movement or add facts to one
            # already in the hypothesis. No input row is discarded.
            possibilities = [(*placements, observation)] if limit is None or len(placements) < limit else []
            for index, (day, balance) in enumerate(placements):
                if joint:
                    if any(left and right and left != right for left, right in zip(day, observation[0])):
                        continue
                    merged_day = tuple(left or right for left, right in zip(day, observation[0]))
                else:
                    merged_day = day or observation[0]
                possibilities.append((*placements[:index], (merged_day, balance or observation[1]),
                                      *placements[index + 1:]))
            for possibility in possibilities:
                expanded.add(tuple(sorted(possibility, key=repr)))
                if len(expanded) > _STATEMENT_PLACEMENT_BUDGET:
                    return None
        states = expanded
    return states


def _review_sparse_placements(copies, row, position, limit, joint=False):
    """Place the known observation and a possible alternate dated movement."""
    reports = {(position(copy), copy["_statement_balance"]): copy for copy in copies}
    choices = _review_statement_placements(reports.values(), position, limit, joint)
    if choices is None or limit < 2:
        return choices
    # The disputed dated observation could instead be a second payment in
    # this group. Repeating the same report does not provide another slot.
    alternative = (position(row), None)
    return choices | {tuple(sorted((*choice, *((alternative,) * count)), key=repr))
                      for choice in choices for count in range(1, limit - len(choice) + 1)}


def _review_version_conflict(first, second):
    if first is second:
        return False
    if _conflicting_facts(first, second, _FIXED_BOOKING_FACTS) or _conflicting_counterparties(first, second):
        return True
    known_alias = (_same_statement_fact(first, second, "creditor_ref")
                   and _same_statement_fact(first, second, "balance_key")
                   and core._bank_account_match(first["counterparty_ids"], second["counterparty_ids"]) is True)
    unreferenced_edge = (not first["provider_ref"] or not second["provider_ref"]) and _same_reported_edge(first, second)
    return not (_same_statement_fact(first, second, "provider_ref") or known_alias or unreferenced_edge)


def _review_dated_versions(groups):
    for row, copies, origins in groups:
        if not row["_statement_balance"]:
            continue
        placed = [copy for copy in copies if any(copy[field] for field in _SECONDARY_BANK_DATES)]
        floating = [copy for copy in copies if not any(copy[field] for field in _SECONDARY_BANK_DATES)]
        if not placed or not floating:
            yield row, copies, origins
            continue
        # The undated report might corroborate a dated occurrence or represent
        # another occurrence. Keep it available in the balance proof.
        for reports, representative in ((placed, row), (floating, floating[0])):
            origins = frozenset().union(*(copy["_statement_sources"] for copy in reports))
            dates = {field: next((copy[field] for copy in reports if copy[field]), None) for field in _STATEMENT_DATE_FIELDS}
            yield representative | dates | {"_statement_sources": reports[0]["_statement_sources"]}, reports, origins


def _single_balance_edge(row, copies, peers, field):
    day = row[field]
    if not day or not all(copy[field] == day for copy in copies):
        return False
    compatible = (other for other in peers if other["currency"] == row["currency"] and other[field] in {day, None})
    return not _possible_statement_reset(Decimal(row["amount"]), compatible)


def _review_fixed_observations(drafts, groups, currency):
    observations = _statement_observations(drafts, (), currency)
    single_edges = set()
    for row, copies, origins in groups:
        if len(copies) < 2 or not all(copy["_statement_balance"] for copy in copies):
            continue
        # Repeating an equal balance edge requires a return to its starting
        # balance. A fully dated same-day group cannot recur without that reset.
        for field in _SECONDARY_BANK_DATES:
            peers = (other for index, other in enumerate(drafts) if index not in origins)
            if _single_balance_edge(row, copies, peers, field):
                observations = [other for other in observations if other["_statement_sources"].isdisjoint(origins)]
                observations.append(row | {"_statement_sources": origins})
                single_edges.add(origins)
                break
    return observations, single_edges


def _review_bracket_count(prior, following, fixed, position, amount):
    """Bound identical signed occurrences with two independently dated single movements."""
    start = max(map(position, prior))
    end = min((position(row) for row in following if position(row)), default=None)
    if end is None or len(fixed[start]) != 1 or len(fixed[end]) != 1:
        return None
    opening, closing = fixed[start][0], fixed[end][0]
    observations = defaultdict(lambda: defaultdict(dict))
    for day, rows in fixed.items():
        if start < day < end:
            for row in rows:
                _statement_observe(observations, row, day)
    fixed_amounts = [amount for day in observations.values() for amount, _ in _statement_day_balances(day)]
    if None in fixed_amounts:
        return None
    fixed_change = sum(fixed_amounts)
    change = closing["_statement_balance"][1] - Decimal(closing["amount"]) - opening["_statement_balance"][1] - fixed_change
    count = change / Decimal(amount)
    return int(count) if count >= 0 and count == count.to_integral_value() else None


def _review_axis(records, field, bracketed):
    """Constrain placements by reported posting order without supplying absent dates."""
    booked_days = {row["booked_day"] for row in records}
    if None in booked_days or len(booked_days) < 2:
        return lambda row: row[field], None
    positions = {day: set() for day in booked_days}
    for row in records:
        if row[field]:
            positions[row["booked_day"]].add((row["booked_day"], row[field]))
    if not bracketed:
        recorded = [[value for _, value in positions[day]] for day in sorted(booked_days) if positions[day]]
        if any(max(earlier) > min(later) for earlier, later in zip(recorded, recorded[1:])):
            return lambda row: row[field], None
    slots = {day: tuple(sorted(available)) or ((day, ""),) for day, available in positions.items()}

    def position(row):
        day = row["booked_day"]
        if row[field]:
            return day, row[field]
        return None if positions[day] else (day, "")

    return position, slots


def _review_predecessors(dates, axes):
    booked = [days[0] for days in dates]
    primary = core._bank_date_predecessors(booked)
    before = primary.copy()
    same_day = defaultdict(int)
    for index, day in enumerate(booked):
        same_day[day] |= 1 << index
    booked_mask = ((1 << len(booked)) - 1) ^ same_day[None]
    for axis in axes:
        secondary = core._bank_date_predecessors([days[axis] for days in dates])
        reversed_bookings = 0
        for index, day in enumerate(booked):
            if day and (reversed_order := secondary[index] & booked_mask & ~(primary[index] | same_day[day])):
                reversed_bookings |= (1 << index) | reversed_order
        for index, day in enumerate(booked):
            if day:
                # Only BOOK orders distinct posting days. A secondary date
                # that inverts that order cannot place a missing BOOK date.
                comparable = same_day[day]
                if not (reversed_bookings & (1 << index)):
                    comparable |= same_day[None]
            else:
                comparable = ~reversed_bookings
            before[index] |= secondary[index] & comparable
    return before


def _review_joint_trail(currency, movements, axes, *, sparse_occurrences=()):
    """Check balances against posting order and compatible secondary dates."""
    dates = [days for days, _ in movements]
    amounts = [Decimal(row["amount"]) for _, row in movements]
    balances = [balance[1] if (balance := row["_statement_balance"]) and balance[0] == currency else None
                for _, row in movements]
    return core._bank_balance_trail(dates, amounts, balances, _review_predecessors(dates, axes), sparse_occurrences)



def _review_joint_support(currency, hypotheses, subject_end, posting_order, retain_equal, capacity):
    def size(counts):
        return sum(counts[:subject_end])

    evidence_sets = (((),),) if posting_order else (((1, 2),), ((1,), (2,)), ((),))
    for evidence in evidence_sets:
        supported = set()
        for axes in evidence:
            for counts, movements in hypotheses:
                fits = _review_joint_trail(currency, movements, axes)
                if fits is None:
                    return None
                if fits:
                    supported.add(counts)
        if supported:
            if retain_equal and evidence != ((),):
                floor = min(map(size, supported))
                for counts, movements in hypotheses:
                    count = size(counts)
                    if count <= floor and counts not in supported:
                        fits = _review_joint_trail(currency, movements, ())
                        if fits is None:
                            return None
                        if fits:
                            supported.add(counts)
            if capacity is None:
                return supported
            # An enriched copy adds facts. Keep a repeated dated movement
            # when the statement cannot fit without that multiplicity.
            bounded = {counts for counts in supported if all(count <= limit for index, (count, limit)
                       in enumerate(zip(counts, capacity)) if index != 1)}
            supported = bounded or supported
            observed = {size(counts) for counts in supported if counts[1] <= capacity[1]}
            # Reassigning the disputed report may explain a proven amount,
            # but it does not by itself establish a new possible amount.
            return {counts for counts in supported if not observed or size(counts) in observed}
    return set()


def _review_occurrence_options(cases, position, single_edges, peer_start, limit, joint):
    options = []
    variants = 1
    for index, (row, copies, sources) in enumerate(cases):
        if index == 1:
            capacity = peer_start - 1 if limit is None else min(limit, peer_start - 1)
            placements = _review_sparse_placements(copies, row, position, capacity, joint)
        elif sources in single_edges:
            placements = {((position(row), row["_statement_balance"]),)}
        else:
            placements = _review_statement_placements(copies, position, None if index == 0 else limit, joint)
        if placements is None:
            return None
        if index == 0 or 2 <= index < peer_start:
            placements.add(())
        options.append(placements)
        variants *= len(placements)
        if variants > _STATEMENT_PLACEMENT_BUDGET:
            return None
    return options


@dataclass
class _ReferenceDispute:
    required: frozenset
    proof: dict
    witnesses: list
    proven_peers: set
    uncertain_peers: set
    state: str | None
    omitted: tuple
    purpose: str | None
    booking_day_proven: bool
    remainder: bool
    surplus_day: str | None
    fiscal_bounds: tuple[str, str] | None


def _secondary_order_conflicts(records):
    by_day = defaultdict(list)
    for row in records:
        if row["value_day"] and row["transaction_day"]:
            by_day[row["booked_day"]].append((row["value_day"], row["transaction_day"]))
    for dates in by_day.values():
        earlier = ""
        for _, group in groupby(sorted(dates), key=lambda pair: pair[0]):
            transactions = [day for _, day in group]
            if min(transactions) < earlier:
                return True
            earlier = max(earlier, max(transactions))
    return False


def _statement_reference_dispute(versions, sparse, observations, groups, single_edges, currency, booked_day, *, force_joint=False):
    """Keep only the payment count supported by the complete signed statement."""
    def with_booking_order():
        return _statement_reference_dispute(versions, sparse, observations, groups, single_edges, currency, booked_day,
                                            force_joint=True)

    origins = frozenset().union(*(sources for _, _, sources in (*versions, sparse)))
    movements = {source: index for index, row in enumerate(observations) for source in row["_statement_sources"]}
    peers = [group for group in groups if group[2].isdisjoint(origins) and group[2] not in single_edges
             and len(group[1]) > 1 and (len({movements[source] for source in group[2] if source in movements}) > 1
                                       or len({row["provider_ref"] for row in group[1]}) > 1)]
    variable_origins = frozenset().union(origins, *(sources for _, _, sources in peers))
    other = [row for row in observations if row["_statement_sources"].isdisjoint(variable_origins)]
    if _statement_other_versions(other) != ([], False):
        return None
    required = None
    proof = {}
    witnesses = {}
    supported = None
    opening_observed = False
    sparse_row, _, _ = sparse
    unknown_primary = any(not row["booked_day"] for row, _, _ in (*versions, sparse))
    booking_bounds = []
    booking_day_proven = not unknown_primary
    peer_rows = [row for row, _, _ in peers]
    anchors = [row for row in (*other, *peer_rows) if row["_statement_balance"]
               and row["_statement_balance"][0] == currency]
    before_booked = [row for row in anchors if row["booked_day"] and row["booked_day"] < booked_day]
    after_booked = [row for row in anchors if row["booked_day"] and row["booked_day"] > booked_day]
    bracketed = bool(before_booked and after_booked)
    previous = sparse_row.get("_statement_overlap_floor")
    subject_rows = [row for row, _, _ in (*versions, sparse)]
    retain_equal = bool(before_booked) and all(row["booked_day"] == booked_day for row in subject_rows)
    scoped_rows = [row for row in other if row["booked_day"] == booked_day]
    unplaced_report = any(not any(row[field] for field in _SECONDARY_BANK_DATES) for row in (*subject_rows, *scoped_rows))
    records = [*other, *peer_rows, *(copy for _, copies, _ in (*versions, sparse, *peers) for copy in copies)]
    # Use typed dates to help place absent BOOK dates when backed by an
    # established opening. They cannot order movements on a known BOOK day.
    fully_booked = all(row["booked_day"] for row in records)
    posting_order = (fully_booked and (not previous or before_booked)) or (not before_booked and not previous)
    joint = (force_joint or unknown_primary or sparse_row["booked_day"] != booked_day
             or _secondary_order_conflicts(records) or posting_order or retain_equal or previous is not None)
    fields = _SECONDARY_BANK_DATES
    if joint:
        fields = sorted(fields, key=lambda field: sum(bool(row[field]) for row in subject_rows), reverse=True)
    for field in fields:
        position, slots = _review_axis(records, field, bracketed)
        dated_positions = [row[field] for row, _, _ in versions if row[field]]
        if not dated_positions:
            continue
        if not joint and not unplaced_report and (not sparse_row[field] or len(dated_positions) < len(versions)):
            continue
        earliest = min(dated_positions)
        first = [group for group in versions if group[0][field] == earliest]
        if len(first) != 1:
            continue
        if required is not None and required != first[0][2]:
            if joint:
                continue
            return None
        later = [group for group in versions if group not in first]
        early_position = position(first[0][0])
        competing_days = [day for row in (sparse_row, *(row for row, _, _ in later)) if (day := position(row))]
        if not competing_days:
            competing_days = [early_position]
        start, end = min(competing_days), max(competing_days)
        unplaced = [row for row in anchors if not position(row)]
        prior = [row for row in anchors if position(row) and early_position < position(row) < start]
        following = [row for row in anchors if position(row) and position(row) > end]
        subjects_dated = all(position(row) for row in subject_rows)
        if subjects_dated:
            booking_day_proven |= (any(row["booked_day"] == booked_day for row in prior)
                                   and any(row["booked_day"] == booked_day for row in following))
        if joint:
            local = [row for row in anchors if row["booked_day"] == booked_day]
            prior = prior or local or before_booked or unplaced
            following = following or after_booked or local or unplaced
        elif unplaced_report:
            # An independent BOOK-day checkpoint bounds a missing typed date
            # without asserting where it belongs within its own day.
            local = [row for row in anchors if row["booked_day"] == booked_day]
            prior = prior or unplaced or before_booked or local
            following = after_booked or following or unplaced or local
        else:
            prior = prior or unplaced
            following = following or unplaced
        if not any(left is not right for left, right in product(prior, following)):
            continue
        prior_dates = [row["booked_day"] for row in prior if row["booked_day"]]
        following_dates = [row["booked_day"] for row in following if row["booked_day"]]
        if subjects_dated and prior_dates and following_dates:
            booking_bounds.append((max(prior_dates), min(following_dates)))
        required = first[0][2]
        fixed = defaultdict(list)
        floating = []
        for row in other:
            day = position(row)
            if day:
                fixed[day].append(row)
            else:
                floating.append(row)
        opening_observed |= bool(before_booked) if unplaced_report or joint else any(
            position(row) and position(row) < early_position and row["_statement_balance"] for row in other
        )
        cases = (*first, sparse, *later, *peers)
        peer_start = len(first) + 1 + len(later)
        days = [*fixed, early_position, start, end, *(position(row) for row in peer_rows if position(row))]
        limit = None
        if not joint and not peers and not floating and all(position(copy) for _, copies, _ in cases for copy in copies):
            limit = _review_bracket_count(prior, following, fixed, position, sparse_row["amount"])
        if not joint or supported is None:
            def reported_dates(row):
                return tuple(row[field] for field in _STATEMENT_DATE_FIELDS)

            capacity = tuple(len({reported_dates(copy) for copy in copies}) for _, copies, _ in cases[:peer_start])
            fixed_dates = [(reported_dates(row), row) for row in other] if joint else None

            def support(reports):
                options = _review_occurrence_options(reports, reported_dates if joint else position,
                                                     single_edges, peer_start, limit, joint)
                if options is None:
                    return None
                outcomes = set()
                hypotheses = []
                for selected in product(*options):
                    # At least one dated occurrence belongs to the statement.
                    if not selected[0] and not any(selected[2:peer_start]):
                        continue
                    counts = tuple(map(len, selected))
                    # A sparse alternate reuses a reported occurrence from the
                    # disputed reference; it cannot also count that report twice.
                    if fully_booked and counts[1] > capacity[1] and sum(counts[:peer_start]) > sum(capacity):
                        continue
                    if previous and not before_booked and sum(counts[:peer_start]) not in previous:
                        continue
                    candidates = []
                    for (row, _, _), placements in zip(reports, selected):
                        for day, balance in placements:
                            candidates.append((day, row | {"_statement_balance": balance,
                                                           "_statement_sources": (len(candidates),)}))
                    if joint:
                        hypotheses.append((counts, [*candidates, *fixed_dates]))
                        continue
                    fits = _statement_fit(_statement_search(currency, fixed, candidates, (), floating, (min(days), max(days)),
                                                            find_any=True, slots_by_booking=slots))
                    if fits is None:
                        return None
                    if fits:
                        outcomes.add(counts)
                return (_review_joint_support(currency, hypotheses, peer_start, posting_order, retain_equal,
                                              capacity if fully_booked else None) if joint else outcomes)

            # Copies from repeated pages must not widen a statement that
            # already fits. Restore their occurrence capacity if it cannot fit.
            distinct = tuple((row, list({_statement_shape(copy): copy
                                         for copy in copies}.values()), origins)
                             for row, copies, origins in cases)
            axis = support(distinct)
            if axis is not None and not axis and any(len(copies) < len(original[1])
                                                     for (_, copies, _), original in zip(distinct, cases)):
                axis = support(cases)
            if not axis:
                if joint:
                    return _ReferenceDispute(required, {}, [], set(), set(), None, (), None, False, False, None, None)
                if axis is None:
                    return None
                return with_booking_order() if bracketed else None
            supported = axis if supported is None else supported & axis
        if not unplaced_report and sparse_row[field] and all(row[field] for row, _, _ in later):
            proof[field] = fingerprint(earliest, sparse_row[field], sorted({row[field] for row, _, _ in later}))
        last = min((position(row) for row in following if position(row)), default=end)
        for row in (*other, *peer_rows):
            day = position(row)
            if (day and early_position <= day <= last) or (not day and (row in prior or row in following)):
                witnesses[row["_statement_sources"]] = row
    if not supported:
        return with_booking_order() if bracketed and not joint else None
    counts = {(outcome[0], sum(outcome[2:peer_start]), outcome[1]) for outcome in supported}
    if unplaced_report or joint:
        # An undated report can change which placement is feasible without
        # changing the number of payments that the statement supports.
        counts = {(0, first + later, spare) for first, later, spare in counts}
        disputed = {(0, 2, 1), (0, 1, 2)}
    else:
        disputed = {(1, 1, 1), (1, 0, 2)}
    secure = (0, 1, 1)
    peer_counts = {sources: {outcome[index] for outcome in supported} for index, (_, _, sources) in enumerate(peers, peer_start)}
    proven_peers = {sources for sources, possible in peer_counts.items() if possible == {1}}
    if all(outcome[0] < 2 for outcome in supported):
        proven_peers.add(required)
    uncertain_peers = {sources for sources, possible in peer_counts.items() if 1 in possible and len(possible) > 1}
    peers_settled = all(len(possible) == 1 for possible in peer_counts.values())
    # This dispute can establish one surplus while an additional occurrence
    # remains possible. Keep those conclusions separate.
    totals = {sum(count) for count in counts}
    partial_counts = joint and counts <= disputed | {secure, (0, 2, 2)}
    floor_proven = partial_counts and min(totals) == 3
    remainder = floor_proven and len(totals) > 1
    state = None
    omitted = ()
    purpose = None
    surplus_days = {booked_day}
    if peers_settled and (counts <= disputed or floor_proven):
        state = "confirmed"
        labels = set()
        if all(first + later > 1 for first, later, _ in counts):
            labels = {row["description"] for index, (row, _, _) in enumerate(cases[2:peer_start], 2)
                      if any(outcome[index] for outcome in supported)}
        elif all(spare > 1 for _, _, spare in counts):
            labels = {row["description"] for row in sparse[1]}
            surplus_days = {sparse_row["booked_day"] or booked_day}
        elif sparse_row["booked_day"]:
            surplus_days.add(sparse_row["booked_day"])
        if len(labels) == 1:
            purpose = next(iter(labels))
    elif (peers_settled and secure in counts and counts & disputed
          and (counts <= disputed | {secure} or partial_counts)):
        state = "pending"
    elif (opening_observed and peers_settled and (unplaced_report or joint or len(supported) == 1)
          and all(first + later == spare == 1 for first, later, spare in counts)):
        state = "ruled_out"
        settled = max(supported)  # Prefer the earliest independently placed version when both fit.
        omitted = tuple(sources for (_, _, sources), count in zip(cases[:peer_start], settled) if not count)
    elif not disputed <= counts:
        return None
    witnesses = [row for origins, row in witnesses.items() if origins not in peer_counts or origins in proven_peers]
    fiscal_bounds = None
    if state == "confirmed":
        start, end = min(surplus_days), max(surplus_days)
        if not booking_day_proven:
            bracket = [(lo, hi) for lo, hi in booking_bounds if lo <= booked_day <= hi]
            if not bracket and after_booked and any(row["booked_day"] == booked_day for row in anchors):
                # The next reported booking day bounds the balance window,
                # even when a typed axis cannot place every candidate.
                bracket = [(booked_day, min(row["booked_day"] for row in after_booked))]
            start = max((lo for lo, _ in bracket), default="0000-01-01")
            end = min((hi for _, hi in bracket), default="9999-12-31")
        if start[:7] != end[:7]:
            state = "unplaced"
            fiscal_bounds = start, end
    return _ReferenceDispute(required, proof, witnesses, proven_peers, uncertain_peers, state, omitted, purpose,
                             booking_day_proven, remainder and state in {"confirmed", "unplaced"}, min(surplus_days), fiscal_bounds)


def _separate_unresolved_references(account_key, drafts, trace=False):
    """Keep proven bookings and reserve one neutral payment for the disputed surplus."""
    excluded = set()
    aliases = {}
    neutral = []
    assessments = []
    warnings = 0
    for currency in {row["currency"] for row in drafts}:
        by_day = defaultdict(list)
        observations = list(_statement_review_observations(drafts, currency))
        fixed, single_edges = _review_fixed_observations(drafts, observations, currency)
        exact_edges = {sources for _, copies, sources in observations if sources in single_edges
                       and len({_statement_shape(copy) for copy in copies}) == 1}
        for group in observations:
            row, copies, origins = group
            day, amount = row["booked_day"], row["_amount_key"]
            by_day[day, amount].append(group)
            if (origins in single_edges and len({copy["provider_ref"] for copy in copies}) > 1
                    and any(other["_statement_balance"] and other["_statement_balance"][0] == currency
                            and other["_statement_sources"].isdisjoint(origins) for other in fixed)):
                aliases[origins] = next(iter(row["_statement_sources"])), {copy["ref"] for copy in copies if copy["ref"]}
        for (day, amount), groups in by_day.items():
            if not day:
                continue
            # An observation without BOOK can belong to this local window.
            # The statement must still prove it between this day's checkpoints.
            groups = [*groups, *by_day.get((None, amount), ())]
            sparse_groups = [group for group in groups if any(not row["_statement_balance"] or row.get("_statement_overlap_floor")
                                                            for row in group[1])]
            if not sparse_groups:
                following = min((row["booked_day"] for row in fixed if row["booked_day"] and row["booked_day"] > day
                                 and row["_statement_balance"] and row["_statement_balance"][0] == currency), default=None)
                if following:
                    sparse_groups = [group for group in by_day.get((following, amount), ())
                                     if not group[0]["_statement_balance"] or group[0].get("_statement_overlap_floor")]
            if not sparse_groups:
                continue
            dated_versions = list(_review_dated_versions(groups))
            balanced = [row for row, _, _ in dated_versions]
            correction_groups, _ = _compatible_copy_groups(balanced, _review_version_conflict)
            indexed = {id(group[0]): group for group in dated_versions}
            disputes = []
            for candidates, sparse in product(correction_groups, sparse_groups):
                sparse_row, sparse_copies, sparse_sources = sparse
                if len(candidates) < 2 or any(row["_statement_sources"] == sparse_row["_statement_sources"]
                                              or _same_statement_fact(row, sparse_row, "provider_ref") for row in candidates):
                    continue
                versions = [indexed[id(row)] for row in candidates]
                result = _statement_reference_dispute(versions, sparse, fixed, observations, single_edges, currency, day)
                if result is not None:
                    disputes.append((versions, sparse, result))
            def dispute_order(dispute):
                _, (row, _, _), result = dispute
                priority = (result.state not in {"pending", None}, result.state not in {"confirmed", "unplaced"},
                            result.purpose is not None)
                return priority, tuple(row[field] or "" for field in _SECONDARY_BANK_DATES), row["ref"] or ""

            for versions, sparse, result in sorted(disputes, key=dispute_order):
                sparse_row, sparse_copies, sparse_sources = sparse
                required, proof, witnesses = result.required, result.proof, result.witnesses
                state, omitted, purpose = result.state, result.omitted, result.purpose
                if purpose and any(other_result.state == "confirmed" and other_result.purpose != purpose
                                   and {group[2] for group in others} & {group[2] for group in versions}
                                   for others, _, other_result in disputes):
                    purpose = None
                later = [group for group in versions if group[2] != required]
                rejected = omitted if state == "ruled_out" else [sources for _, _, sources in later]
                origins = frozenset().union(sparse_sources, *rejected)
                if not excluded.isdisjoint(origins):
                    continue
                # Keep the identifiable baseline observation. Physical copies
                # establish possible counts without adding a second named entry.
                index = next(iter(sparse_row["_statement_sources"]))
                excluded.update(origins - {index})
                warnings += int(state is None or len({row["_remittance"] for row in sparse_copies}) > 1)
                proven_single = result.proven_peers | single_edges & {required, *(row["_statement_sources"] for row in witnesses)}
                if state is not None:
                    proven_single |= exact_edges
                for row, copies, sources in observations:
                    if sources in proven_single or sources in result.uncertain_peers:
                        refs = {copy["ref"] for copy in copies if copy["ref"]} if sources in proven_single else set()
                        aliases[sources] = next(iter(row["_statement_sources"])), refs
                if state is None:
                    continue
                original = next(row for row, _, sources in versions if sources == required)
                established = original
                if state == "ruled_out":
                    chosen, copies, sources = next(group for group in versions if group[2] not in omitted)
                    established = chosen
                    refs = {copy["ref"] for copy in copies if copy["ref"]}
                    refs.update(drafts[index]["ref"] for rejected_group in omitted for index in rejected_group
                                if drafts[index]["ref"])
                    chosen_index = next(iter(chosen["_statement_sources"]))
                    aliases[sources] = chosen_index, refs
                    # A later, weaker fetch can report only the excluded date
                    # version of this now uniquely established payment.
                    drafts[chosen_index]["_statement_booking_aliases"] = {
                        day: group for dropped in omitted for index in dropped for day, group in drafts[index]["bank_groups"].items()
                        if day != drafts[index]["booked_day"] or day == chosen["booked_day"]
                    }
                for member in (established, sparse_row):
                    sources = member["_statement_sources"]
                    if result.booking_day_proven and member["booked_day"] in {None, day}:
                        for index in sources - excluded:
                            if drafts[index]["booked_day"] in {None, day}:
                                drafts[index]["_statement_booking_day"] = day
                references = sorted(ref for ref in (original["provider_ref"], sparse_row["provider_ref"]) if ref)
                scope = fingerprint(account_key, "statement-review", amount, currency)
                facts = [(row["balance_key"], row["creditor_ref"], row["counterparty_ids"]) for row in (original, sparse_row)]
                surplus_day = result.surplus_day if state == "confirmed" else day
                group = fingerprint(account_key, surplus_day, amount, currency)
                alternatives = [core._bank_statement_option(row) for row, _, _ in later]
                unestablished = [core._bank_statement_option(row) for row, _, sources in versions if sources in rejected]
                checkpoints = sorted({(row["booked_day"] or "", *(row[field] or "" for field in _SECONDARY_BANK_DATES),
                                       row["_amount_key"], row["balance_key"]) for row in witnesses if row["balance_key"]})
                review = dict.fromkeys(core._BANK_IDENTITY_FIELDS) | {
                    "ref": core.ENABLE_BANKING_REF_PREFIX + fingerprint(scope, day, proof, facts),
                    "date": surplus_day, "booked_day": surplus_day if result.booking_day_proven else None, "amount": amount,
                    "currency": currency, "description": purpose or "Kontoauszug prüfen", "tx_type": "Enable Banking",
                    "counterparty_ids": (), "bank_group": group, "bank_groups": {surplus_day: group}, "prior_refs": [],
                    "_statement_review_options": alternatives, "_statement_review_proof": (scope, proof, facts, (day, checkpoints)),
                    "_statement_review_legacy_scope": (account_key, references),
                    "_statement_review_members": [core._bank_statement_option(row) for row in (*witnesses, established, sparse_row)],
                    "_statement_review_versions": [core._bank_statement_option(row) for row, _, _ in versions],
                    "_statement_purpose": purpose,
                }
                if trace:
                    subjects = (established["_statement_sources"], sparse_sources)
                    review["_statement_subject_reports"] = tuple(frozenset(drafts[i]["_report_index"] for i in sources)
                                                                 for sources in subjects)
                observed_balances = ()
                overlap = sparse_row.get("_statement_replay_overlap")
                preceding = []
                if state in {"pending", "unplaced"} or result.remainder:
                    prior_day = max((row["booked_day"] for row in fixed if row["booked_day"] and row["booked_day"] < day), default=None)
                    preceding = [row for row in fixed if prior_day and row["booked_day"] == prior_day]
                    balance_witnesses = [*witnesses, *(row for row, _, _ in versions), *preceding]
                    observed_balances = sorted({(row["balance_key"], str(balance[1])) for row in balance_witnesses
                                                if row["balance_key"] and (balance := row["_statement_balance"])
                                                and balance[0] == currency})
                if state == "unplaced":
                    overlap = {
                        "bounds": result.fiscal_bounds,
                        "sparse": _overlap_observation(sparse_row),
                        "reports": [_overlap_observation(row) for row in (*preceding, *witnesses, *(row for row, _, _ in versions))],
                    }
                assessments.append(review | {"state": state, "account_key": account_key,
                                             "_statement_remainder": result.remainder,
                                             "_statement_fiscal_bounds": result.fiscal_bounds,
                                             "_statement_observed_balances": observed_balances,
                                             "_statement_overlap": overlap,
                                             "_statement_unestablished_options": unestablished})
                if state == "confirmed":
                    neutral.append(review)
    for origins, (index, refs) in aliases.items():
        if excluded.isdisjoint(origins):
            excluded.update(origins - {index})
            drafts[index]["_confirmed_reference_aliases"] = refs
    if not excluded:
        return drafts, neutral, warnings, assessments
    retained = []
    for index, row in enumerate(drafts):
        if index in excluded:
            continue
        retained.append(row)
    _prepare_statement_sources(retained)
    return retained, neutral, warnings, assessments


def _separate_statement_references(rows):
    """Number proven equal bookings without saving the response's lookup IDs."""
    by_ref = defaultdict(list)
    for row in rows:
        if row.get("_statement_slot"):
            by_ref[row["ref"]].append(row)
    reserved = {row["ref"] for row in rows}
    for copies in by_ref.values():
        if len(copies) < 2 or len({row["_statement_slot"] for row in copies}) != len(copies):
            continue
        for row in sorted(copies, key=lambda item: item["_statement_slot"][1])[1:]:
            ref = row["ref"]
            while ref in reserved:
                ref = core._occupied_bank_reference(ref, row)
            row["ref"] = ref
            reserved.add(ref)


def _balance_fingerprint(currency, balance):
    return fingerprint(currency, str(balance.normalize()) if balance else "0")


def _overlap_observation(row):
    return (row["_amount_key"], tuple(core._bank_statement_option(row)[1]))


def _overlap_booking(facts):
    return core._BankBooking(*facts[:-1], tuple(map(tuple, facts[-1])))


def _overlap_same_report(current, previous):
    old = _overlap_booking(previous[1])
    if current["_amount_key"] != previous[0] or core._bank_facts_conflict(current, old):
        return False
    return core._stored_secondary_match(current, old) is not False and bool(
        current["ref"] == old.ref or core._bank_economic_replay(current, old._asdict())
        or (current["provider_ref"] and current["provider_ref"] == old.provider_ref
            and core._stored_secondary_match(current, old) is True)
    )


@dataclass
class _StatementOverlap:
    matched: frozenset
    linked: frozenset
    context: list
    counts: tuple
    proof: dict


def _overlap_proof_rows(conn, account_key, amount, currency, details, drafts):
    """Reconnect a saved statement to its own current bank observations."""
    proof = details["proof"]
    if len(proof) < 4:
        return None
    day, checkpoints = proof[3]
    if proof[0] != fingerprint(account_key, "statement-review", amount, currency):
        return None
    overlap = details.get("overlap")
    bounds = overlap["bounds"] if overlap else details.get("fiscal_bounds")
    if not bounds:
        return None
    lower, upper = bounds
    current = [row for row in drafts if row["currency"] == currency]
    if overlap:
        sparse = overlap["sparse"]
        reports = overlap["reports"]
    else:
        # Older assessments retain the alternatives and dated balance hashes.
        # Recover named witnesses only through their unique account/date group.
        def candidates(signed, days):
            groups = {fingerprint(account_key, value, signed, currency) for value in days if value}
            return core._bank_statement_group_bookings(conn, groups)

        def matching_subjects(bookings, facts):
            balance, creditor, payer = facts
            return {old for old in bookings if old.balance_key == balance and old.creditor_ref == creditor
                    and core._bank_account_match(old.counterparty_ids, payer) is not False}

        sparse_matches = set()
        for row in current:
            if row["_amount_key"] != amount or not row["booked_day"] or not lower <= row["booked_day"] <= upper:
                continue
            matches = matching_subjects(candidates(amount, (row[field] for field in _STATEMENT_DATE_FIELDS)), proof[2][1])
            sparse_matches.update(old for old in matches if _overlap_same_report(row, (amount, old)))
        first = matching_subjects(candidates(amount, (day,)), proof[2][0])
        if len(sparse_matches) != 1 or len(first) != 1:
            return None
        sparse = amount, next(iter(sparse_matches))
        reports = [(amount, next(iter(first))), *((amount, facts) for _, facts in details["observations"])]
        for booked, value, transaction, signed, balance in checkpoints:
            witnesses = {old for old in candidates(signed, (booked, value, transaction)) if old.balance_key == balance
                         and tuple(getattr(old, field) or "" for field in _STATEMENT_DATE_FIELDS) == (booked, value, transaction)}
            if len(witnesses) != 1:
                return None
            reports.append((signed, next(iter(witnesses))))

    matching = [row for row in current if _overlap_same_report(row, sparse)
                and (not row["booked_day"] or lower <= row["booked_day"] <= upper)]
    booked = {row["booked_day"] for row in matching if row["booked_day"]}
    if len(booked) != 1:
        return None
    matched = frozenset(row["_report_index"] for row in matching)
    known_reports = [(report, _overlap_booking(report[1])) for report in reports]

    def linked_report(row):
        # Include a conflicting current report with the same known identity
        # so its explicit facts can veto reusing the saved observation.
        return any(_overlap_same_report(row, report) or (
            row["_amount_key"] == report[0] and row["provider_ref"] and row["provider_ref"] == old.provider_ref
            and core._stored_secondary_match(row, old) is True
        ) for report, old in known_reports)

    linked = frozenset(row["_report_index"] for row in current if linked_report(row))
    current = [row for row in current if row["_report_index"] in matched or row["_report_index"] in linked]
    known = {key: Decimal(value) for key, value in details.get("balances", ())}
    missing = {key for _, facts in reports if (key := _overlap_booking(facts).balance_key)} - known.keys()
    if missing:
        known.update(_recover_legacy_statement_balances(currency, current, missing,
                     witnessed_amounts={Decimal(signed) for signed, _ in reports}))
    anchored = []
    for report, old in known_reports:
        if any(_overlap_same_report(row, report) for row in current):
            continue
        if old.balance_key and old.balance_key not in known:
            return None
        dated = {getattr(old, field): fingerprint(account_key, getattr(old, field), report[0], currency)
                 for field in _STATEMENT_DATE_FIELDS if getattr(old, field)}
        if not dated:
            return None
        # Leftover versions sharing a reference can only be reused when the
        # current copies are identified as different reports of this statement.
        for row in current:
            same_reference = old.provider_ref and row["provider_ref"] == old.provider_ref
            if same_reference and not any(_overlap_same_report(row, other) for other in reports):
                return None
        day = old.booked_day or old.value_day or old.transaction_day
        anchored.append(old._asdict() | {
            "date": day, "amount": report[0], "currency": currency, "bank_groups": dated,
            "bank_group": dated[day], "description": old.description or "Kontoauszug prüfen",
            "_amount_key": report[0], "_transaction_id": None, "_counterparty_names": frozenset(),
            "_remittance": (), "_statement_balance": (currency, known[old.balance_key]) if old.balance_key else None,
            "_statement_context": True,
        })
    return _StatementOverlap(matched, linked, anchored,
                             (3, 4) if details.get("remainder") else (3,),
                             {"bounds": bounds, "sparse": sparse, "reports": reports})


def _verified_statement_balance(row, candidates):
    matches = set()
    for old in candidates:
        if not old.balance_key or core._bank_facts_conflict(row, old):
            continue
        shared_dates = core._stored_secondary_match(row, old)
        if shared_dates is False:
            continue
        if shared_dates is True and row["provider_ref"] and row["provider_ref"] == old.provider_ref:
            matches.add((old.balance_key, old.value_day, old.transaction_day))
        elif core._bank_economic_replay(row, old._asdict()):
            matches.add((old.balance_key, old.value_day, old.transaction_day))
    if len(matches) == 1:
        return next(iter(matches))[0]
    return None


def _recover_legacy_statement_balances(currency, reports, fingerprints, *, witnessed_amounts=()):
    """Verify old balance hashes against the current signed movements."""
    values = {balance[1] for row in reports if (balance := row["_statement_balance"]) and balance[0] == currency}
    amounts = {Decimal(row["amount"]) for row in reports if row["currency"] == currency} | set(witnessed_amounts)
    if witnessed_amounts:
        # Older reviews retained the fingerprints only. Search a bounded set of
        # possible balances, accepting a value only if it matches a saved hash.
        values.add(Decimal(0))
    found = {}
    checked = set()
    for _ in range(5 if witnessed_amounts else 3):
        for value in values - checked:
            key = _balance_fingerprint(currency, value)
            if key in fingerprints:
                found[key] = value
        if fingerprints <= found.keys() or len(values) >= _STATEMENT_PLACEMENT_BUDGET:
            break
        checked = values.copy()
        for value, amount in product(sorted(checked), sorted(amounts)):
            values.update((value + amount, value - amount))
            if len(values) >= _STATEMENT_PLACEMENT_BUDGET:
                break
    return found


def _matches_page_occurrence(row, options):
    references = {old.provider_ref for old in options if old.provider_ref}
    if references and row["provider_ref"] and row["provider_ref"] not in references:
        return False
    return any(core._bank_has_shared_date(row, old) and not core._bank_facts_conflict(row, old) for old in options)


def _joint_replay_rank(row, groups, old, booked, *, subject):
    if core._joint_statement_source(row, groups, old):
        if (old.ref and row["ref"] == old.ref) or (old.provider_ref and row["provider_ref"] == old.provider_ref):
            return 0
        return 1 if row["provider_ref"] else 2
    if core._joint_proof_member_matches((groups, old), core._bank_statement_option(row), subject=subject):
        return 1 if row["provider_ref"] else 2
    # A checkpoint can lose both its balance and reference. Its posted
    # description and typed dates still identify it in a complete replay.
    if (not subject and not row["balance_key"] and (not row["provider_ref"] or row["provider_ref"] == old.provider_ref)
            and row["booked_day"] and row["booked_day"] == old.booked_day
            and core._stored_secondary_match(row, old) is not False
            and core._bank_description_matches(row, booked) and not core._bank_facts_conflict(row, old)):
        return 2
    return None


def _joint_replay_assignment(choices, omitted=None, *, required=None):
    required = len(choices) if required is None else required
    matched = {}

    def place(member, seen):
        for index in sorted(choices[member]):
            if index in seen or omitted == (member, index):
                continue
            seen.add(index)
            if index not in matched or place(matched[index], seen):
                matched[index] = member
                return True
        return False

    for member in range(len(choices)):
        if not place(member, set()) and member < required:
            return {}
    return matched


def _joint_replay_matches(choices, *, required=None):
    """Return assignments shared by every largest matching of the required rows."""
    required = len(choices) if required is None else required
    assigned = _joint_replay_assignment(choices, required=required)
    return {index: member for index, member in assigned.items()
            if (member < required and len(choices[member]) == 1)
            or len(_joint_replay_assignment(choices, (member, index), required=required)) < len(assigned)}


def _joint_replay_subset(drafts, currency, candidates, members, bookings, observations):
    """Identify the established part of a reply, leaving new reports in the trail."""
    required = len(members)
    subject_groups = {group for groups, _ in observations for group in groups}
    provider_refs = {row["provider_ref"] for row in drafts if row["currency"] == currency}

    def matching(groups, old):
        description = set((old.description or "").split(" · "))
        def covered(row):
            return (all(not row[field] or row[field] == getattr(old, field) for field in core._BANK_IDENTITY_FIELDS)
                    and set(row["counterparty_ids"]) <= set(old.counterparty_ids)
                    and (row["description"] == "Bankumsatz" or set(row["description"].split(" · ")) <= description))

        return [index for index in {i for group in groups for i in candidates[currency, group]} if covered(drafts[index])]

    choices, unchanged = [], []
    for member, ((groups, _), old) in enumerate(zip(members, bookings)):
        weaker = matching(groups, old)
        unchanged.append(set(weaker))
        current = {index for group in groups for index in candidates[currency, group]}
        # A positively identified report may supply new evidence. Prefer
        # it as the booked member over sparse copies of that movement.
        identified = []
        for index in current:
            row = drafts[index]
            same_source = (old.provider_ref and old.provider_ref == row["provider_ref"]) or (old.ref and old.ref == row["ref"])
            if same_source and core._joint_statement_source(row, groups, old):
                identified.append(index)
        options = identified or weaker
        # A previously established checkpoint can fall outside a shorter
        # response. Keep it as context only if no live report could replace
        # or contradict it, and still require the named subjects themselves.
        if (not options and old.booked_day and old.balance_key and (not old.provider_ref or old.provider_ref not in provider_refs)
                and subject_groups.isdisjoint(groups) and not any(candidates[currency, group] for group in groups)):
            options = [-member - 1]
            unchanged[-1].update(options)
        choices.append(options)
    previous = list(bookings)
    for groups, facts in observations:
        option = _overlap_booking(facts)
        names = {old.description for (other_groups, _), old in zip(members, bookings)
                 if core._joint_proof_member_matches((groups, option), (other_groups, old), subject=True)}
        if len(names) == 1:
            option = option._replace(description=next(iter(names)))
        compatible = matching(groups, option)
        choices.append(compatible)
        unchanged.append(set(compatible))
        previous.append(option)

    assigned = _joint_replay_assignment(choices, required=required)
    live = {index: member for index, member in assigned.items() if index >= 0}
    same_evidence = len(live) == len(drafts) and all(index in unchanged[member] for index, member in live.items())
    omissions = len(live) < len(choices) or any(
        any(getattr(previous[member], field) and not drafts[index][field] for field in core._BANK_IDENTITY_FIELDS)
        or (previous[member].description and previous[member].description != drafts[index]["description"])
        or set(previous[member].counterparty_ids) != set(drafts[index]["counterparty_ids"])
        for index, member in live.items()
    )
    if same_evidence and omissions:
        return True, {}, {}
    # A report is an established movement only when every maximal matching
    # that covers the named movements assigns it to the same one.
    matched = _joint_replay_matches(choices, required=required)
    owners = Counter(index for options in choices[:required] for index in options)
    exclusive = [[index for index in options if owners[index] == 1] for options in choices[:required]] + choices[required:]
    distinct = _joint_replay_assignment(exclusive, required=required)
    # Reserve one report for each known movement when equally complete
    # assignments can identify their owners. Other reports stay available
    # to the balance solver, with their observed facts intact.
    representatives = distinct if len(distinct) == len(assigned) else live
    for index, member in representatives.items():
        if member < required and owners[index] == 1:
            matched[index] = member
    named = {index: member for index, member in matched.items() if member < required}
    alternatives = {}
    eligible = {index for options in choices for index in options if index >= 0}
    if len(named) == required and len(live) == len(eligible):
        # Once the booked occurrences are reserved, a weaker copy can be
        # identified as a previously observed alternative by elimination.
        remaining = [[index for index in options if index not in named] for options in choices[required:]]
        alternatives = {index: previous[required + member]
                        for index, member in _joint_replay_matches(remaining, required=0).items()}
    return False, named, alternatives


def _joint_checkpoint_context(conn, account, currency, groups, old, balances):
    """Represent an established payment as a witness, without importing it."""
    stored = conn.execute("SELECT amount FROM transactions WHERE ref=? AND currency=?", (old.ref, currency)).fetchone()
    if not stored or old.balance_key not in balances:
        return None
    amount = str(Decimal(str(stored[0])).normalize())
    dates = {getattr(old, field) for field in _STATEMENT_DATE_FIELDS if getattr(old, field)}
    bank_groups = {day: fingerprint(account, day, amount, currency) for day in dates}
    if bank_groups[old.booked_day] not in groups:
        return None
    balance = (currency, balances[old.balance_key])
    return old._asdict() | {
        "date": old.booked_day, "amount": amount, "currency": currency, "bank_groups": bank_groups,
        "bank_group": bank_groups[old.booked_day], "_amount_key": amount, "_statement_balance": balance,
        "_bank_observed_balance": balance, "_bank_account_key": account, "_statement_context": True,
        "_counterparty_names": frozenset(), "_remittance": (), "_transaction_id": None,
    }


def _joint_common_fields(versions, fields):
    # An omitted field does not contradict an earlier supplied value.
    return {field: next(iter(values)) for field in fields
            if len(values := {getattr(old, field) for old in versions if getattr(old, field)}) == 1}


def _joint_replay_evidence(conn, account, first, last, drafts):
    """Use a complete matching witness before filling omissions on a replay."""
    saved = conn.execute(
        "SELECT currency, details FROM bank_statement_assessments WHERE account_key = :account "
        "AND json_type(details, '$.joint') = 'object' AND state IN ('confirmed', 'unplaced') "
        "AND json_extract(details, '$.joint.bounds[0]') <= :last AND json_extract(details, '$.joint.bounds[1]') >= :first "
        "UNION SELECT currency, alternatives FROM bank_statement_reviews JOIN transactions USING (ref) "
        "WHERE json_extract(alternatives, '$.joint.account_key') = :account "
        "AND json_extract(alternatives, '$.joint.bounds[0]') <= :last "
        "AND json_extract(alternatives, '$.joint.bounds[1]') >= :first",
        {"account": account, "first": first, "last": last},
    )
    candidates, recorded = defaultdict(list), {}
    for index, row in enumerate(drafts):
        for group in row["bank_groups"].values():
            candidates[row["currency"], group].append(index)
    evidence, balances = defaultdict(list), defaultdict(dict)
    context = defaultdict(list)
    alternatives = defaultdict(list)
    checked = set()
    for currency, encoded in saved:
        for proof in core._joint_evidence_versions(json.loads(encoded)):
            joint = proof["joint"]
            members = joint["members"]
            identity = currency, json.dumps(members)
            if identity in checked:
                continue
            checked.add(identity)
            subjects = {group for groups, _ in proof["observations"] for group in groups}
            bookings = []
            for groups, facts in members:
                scope = tuple(groups)
                if scope not in recorded:
                    recorded[scope] = core._bank_statement_group_bookings(conn, scope)
                subject = not subjects.isdisjoint(groups)
                prior = {booking for booking in recorded[scope] if core._joint_proof_member_matches(
                    (groups, facts), (groups, booking), subject=subject,
                )}
                if len(prior) != 1:
                    break
                booking = next(iter(prior))
                bookings.append(_overlap_booking(facts)._replace(ref=booking.ref, description=booking.description))
            if len(bookings) != len(members):
                continue
            replay, covered, options = _joint_replay_subset(drafts, currency, candidates, members, bookings, proof["observations"])
            if replay:
                return {}, balances, (), True

            if not covered:
                choices = []
                for (groups, facts), booked in zip(members, bookings):
                    old = _overlap_booking(facts)
                    subject = not subjects.isdisjoint(groups)
                    current = {index for group in groups for index in candidates[currency, group]}
                    ranked = [(priority, index) for index in current if (priority := _joint_replay_rank(
                        drafts[index], groups, old, booked, subject=subject,
                    )) is not None]
                    if not ranked:
                        break
                    best = min(priority for priority, _ in ranked)
                    choices.append([index for priority, index in ranked if priority == best])
                if len(choices) != len(bookings):
                    continue
                covered = _joint_replay_matches(choices)
            if sum(bool(bookings[member].balance_key) for member in covered.values()) < 2:
                continue
            confirmed_balances = {key: Decimal(value) for key, value in joint.get("balances", ())}
            missing = [member for index, member in covered.items() if index < 0]
            if missing:
                unknown = {bookings[member].balance_key for member in missing} - confirmed_balances.keys()
                if unknown:
                    confirmed_balances.update(_recover_legacy_statement_balances(currency, drafts, unknown))
                restored = [_joint_checkpoint_context(conn, account, currency, members[member][0], bookings[member], confirmed_balances)
                            for member in missing]
                if not all(restored):
                    continue
                for row in restored:
                    context[row["ref"]].append(row)
            balances[currency].update(confirmed_balances)
            for index, option in options.items():
                alternatives[index].append(option)
            for index, member in covered.items():
                if index < 0:
                    continue
                previous = bookings[member]
                row = drafts[index]
                if core._stored_secondary_match(row, previous) is not False:
                    evidence[index].append(previous)

    witnessed = {}
    for index, versions in evidence.items():
        if len({old.ref for old in versions}) != 1:
            continue
        # Different saved versions can be complementary. A conflict on a
        # typed field supplies no replacement for an omitted observation.
        available = _joint_common_fields(versions, (*core._BANK_IDENTITY_FIELDS, "counterparty_ids", "description"))
        witnessed[index] = versions[0].ref, available
    for index, versions in alternatives.items():
        if index not in witnessed:
            # Alternative reports carry no posting identity, date or balance
            # inferred from a different occurrence.
            available = _joint_common_fields(versions, ("creditor_ref", "reference_schema", "counterparty_iban",
                                                        "counterparty_ids", "description"))
            if available:
                witnessed[index] = None, available
    agreed = [rows[0] for rows in context.values()
              if len({(row["booked_day"], row["amount"], row["balance_key"]) for row in rows}) == 1]
    checkpoints = tuple(row | {"_report_index": -index} for index, row in enumerate(agreed, 1))
    return witnessed, balances, checkpoints, False


@dataclass(eq=False)
class _StatementFetch:
    account_key: str
    drafts: list
    skipped: int
    original: dict = field(default_factory=dict)

    def revision_drafts(self, conn):
        """Retain identifiable movements before reducing optional page copies."""
        reports = [row | {"ref": row["ref"] or core.bank_source_reference(row["_source_key"], index),
                          "_bank_account_key": self.account_key, "_bank_observed_balance": _reported_balance(row)}
                   for index, row in enumerate(self.drafts, start=1)]
        revised, _ = core._reconcile_bank_balance_revisions(conn, reports, ())
        result = []
        for row, observed in zip(self.drafts, revised):
            if observed.get("_bank_new_occurrence"):
                row = row | {"_statement_new_observation": True}
            if ref := observed.get("_bank_balance_revision"):
                row = row.copy()
                if not row["date"]:
                    known = conn.execute("SELECT t.date,f.booked_day FROM transactions t JOIN bank_import_facts f USING(ref) "
                                         "WHERE ref=?", (ref,)).fetchone()
                    row |= {"date": known[0], "booked_day": known[1]}
                    row["bank_groups"] = {known[0]: fingerprint(self.account_key, known[0], row["_amount_key"], row["currency"])}
                    row["bank_group"] = row["bank_groups"][known[0]]
                if not row["balance_key"] and (ending := observed.get("_bank_revision_ending")) is not None:
                    row |= {"balance_key": observed["_bank_revision_balance"], "_statement_balance": (row["currency"], ending)}
            result.append(row)
        return result

    def corrected_drafts(self, conn):
        """Return all effective evidence; only a confirmed replay returns no drafts."""
        self.drafts = self.revision_drafts(conn)
        last = max(row["date"] for row in self.drafts)
        first = min(row["date"] for row in self.drafts)
        # A placed receipt can be re-reported on its resolved day after the
        # original review date falls outside the fetched statement.
        saved = [(state, str(Decimal(str(amount)).normalize()), currency, json.loads(details))
                 for state, amount, currency, details in conn.execute(
            "SELECT state, amount, currency, details FROM bank_statement_assessments WHERE account_key = :account AND "
            "(state IN ('pending', 'unplaced', 'protected') OR (state = 'confirmed' AND json_extract(details, '$.remainder')) "
            "OR (date BETWEEN :first AND :last AND json_extract(details, '$.balances') IS NOT NULL) "
            "OR (state = 'confirmed' AND json_extract(details, '$.overlap.bounds[0]') <= :last "
            "AND json_extract(details, '$.overlap.bounds[1]') >= :first))",
            {"account": self.account_key, "first": first, "last": last},
        )]
        witnessed, known, checkpoints, replay = _joint_replay_evidence(conn, self.account_key, first, last, self.drafts)
        if replay:
            return [], (), ()
        if not saved and not witnessed:
            return self.drafts, (), checkpoints
        alternatives = defaultdict(list)
        pending_pages = defaultdict(list)
        for index, (state, _, currency, details) in enumerate(saved):
            known[currency].update((key, Decimal(value)) for key, value in details.get("balances", ()))
            peers = [witness for witness in details.get("witnesses", ()) if not isinstance(witness, str)]
            for groups, facts in (*details["observations"], *peers):
                booking = core._BankBooking(*facts[:-1], tuple(map(tuple, facts[-1])))
                for group in groups:
                    alternatives[group].append(booking)
            if state == "pending" and details.get("page_family"):
                options = [core._BankBooking(*facts[:-1], tuple(map(tuple, facts[-1]))) for _, facts in details["observations"]]
                sparse_days = frozenset(booking.booked_day for booking in options if not booking.balance_key)
                signed_edges = {(booking.booked_day, booking.balance_key) for booking in options}
                signed_edge = next(iter(signed_edges)) if len(signed_edges) == 1 and not sparse_days else None
                groups = {group for group_ids, _ in details["observations"] for group in group_ids}
                for group in groups:
                    pending_pages[group].append((index, details["occurrences"][1], sparse_days, signed_edge, options))
        current_balances = defaultdict(list)
        for index, row in enumerate(self.drafts):
            key = row["balance_key"] if _reported_balance(row) else witnessed.get(index, (None, {}))[1].get("balance_key")
            if key and (index in witnessed or row.get("_fetch_page") is not None):
                current_balances[row["currency"], row["_amount_key"], key].append(row)
        sources = {}
        pending_counts = {}
        missing = defaultdict(set)
        for index, row in enumerate(self.drafts):
            groups = row["bank_groups"].values()
            if row.get("_fetch_page") is not None:
                matches = {(key, upper, sparse_days, signed_edge) for group in groups
                           for key, upper, sparse_days, signed_edge, options in pending_pages[group]
                           if _matches_page_occurrence(row, options)}
                if len(matches) == 1:
                    pending_counts[index] = next(iter(matches))[1:]
            # A possible additional occurrence must not inherit the cached
            # checkpoint of an already represented member of its family.
            if row["_statement_balance"] or row.get("_statement_new_observation"):
                continue
            candidates = core._bank_statement_group_bookings(conn, groups)
            candidates.update(option for group in groups for option in alternatives[group])
            if key := witnessed.get(index, (None, {}))[1].get("balance_key") or _verified_statement_balance(row, candidates):
                currency = row["currency"]
                # A balance belongs to the corroborated observation. Do not
                # also infer it for another copy whose balance is unknown.
                page = row.get("_fetch_page")
                if any(other is not row and (witnessed.get(other["_report_index"], (None, {}))[0]
                       or (page is not None and other["_fetch_page"] != page)) and _sparse_reports_match(row, other)
                       for other in current_balances[currency, row["_amount_key"], key]):
                    continue
                sources[index] = currency, key
                if key not in known[currency]:
                    missing[currency].add(key)
        for currency, fingerprints in missing.items():
            amounts = {Decimal(self.drafts[index]["amount"]) for index in witnessed if self.drafts[index]["currency"] == currency}
            known[currency].update(_recover_legacy_statement_balances(currency, self.drafts, fingerprints, witnessed_amounts=amounts))
        has_balances = any(key in known[currency] for currency, key in sources.values())
        if not has_balances and not witnessed and not pending_counts and not any(state in {"unplaced", "confirmed"} for state, _, _, _ in saved):
            return self.drafts, (), checkpoints
        drafts = []
        for index, row in enumerate(self.drafts):
            currency, key = sources.get(index, (row["currency"], None))
            if key in known[currency]:
                row = row | {"_statement_balance": (currency, known[currency][key]), "balance_key": key}
            if index in witnessed:
                ref, fields = witnessed[index]
                dated = {field: fields[field] for field in _STATEMENT_DATE_FIELDS if field in fields and not row[field]}
                groups = {day: fingerprint(self.account_key, day, row["_amount_key"], row["currency"]) for day in dated.values()}
                facts = {field: fields[field] for field in ("creditor_ref", "reference_schema", "counterparty_iban", "counterparty_ids")
                         if field in fields and not row[field]}
                row = row | dated | facts | {"bank_groups": row["bank_groups"] | groups}
                if ref:
                    row["_confirmed_reference_aliases"] = {ref}
                if not row["provider_ref"] and "provider_ref" in fields:
                    # The stored reference groups copies even when the
                    # bank no longer sends the underlying entry identifier.
                    row |= {"provider_ref": fields["provider_ref"], "ref": ref, "_dated_ref": ref}
                if row["description"] == "Bankumsatz" and "description" in fields:
                    row["description"] = fields["description"]
                if day := dated.get("booked_day"):
                    row |= {"date": day, "bank_group": groups[day]}
            if index in pending_counts:
                count, sparse_days, signed_edge = pending_counts[index]
                row = row | {"_pending_page_count": count, "_pending_sparse_days": sparse_days, "_pending_signed_edge": signed_edge}
            drafts.append(row | {"bank_groups": row["bank_groups"].copy(), "prior_refs": row["prior_refs"].copy()})
        overlaps = [overlap for state, amount, currency, details in saved if state in {"unplaced", "confirmed"}
                    and (overlap := _overlap_proof_rows(conn, self.account_key, amount, currency, details, drafts))]
        claims = Counter(index for overlap in overlaps for index in overlap.matched)
        independent = [overlap for overlap in overlaps if all(claims[index] == 1 for index in overlap.matched)]
        return drafts, independent, checkpoints

    def restore(self, conn, selected):
        drafts, overlaps, checkpoints = self.corrected_drafts(conn)
        if not drafts:
            return [], []
        assessments = []
        rows, _ = _map_statement_drafts(self.account_key, drafts, self.skipped, assessments, trace=True,
                                        overlaps=overlaps, checkpoints=checkpoints)
        if self.original.keys() <= selected:
            return rows, assessments

        # A caller can select rows from the normalized response. The other
        # reports can corroborate a balance, but remain outside that selection.
        allowed = set()
        denied = set()
        withheld = []
        for ref, (reports, subjects) in self.original.items():
            if subjects:
                if ref not in selected:
                    withheld.append(subjects)
            else:
                (allowed if ref in selected else denied).update(reports)

        def selected_statement(row):
            subjects = row["_statement_subject_reports"]
            selected = [bool(reports & allowed) for reports in subjects]
            return any(selected) and all(included or (reports and max(reports) < 0)
                                         for included, reports in zip(selected, subjects)) and not any(
                all(left & right for left, right in zip(subjects, prior)) for prior in withheld
            )

        accepted = [row for row in assessments if selected_statement(row)]
        if not accepted:
            return None
        refs = {row["ref"] for row in accepted}

        def selected_payment(row):
            if "_statement_subject_reports" in row:
                return row["ref"] in refs
            origins = row["_statement_report_origins"]
            return bool(origins & allowed) and not origins & denied

        return [row for row in rows if selected_payment(row)], accepted


def transaction_rows(account_key, transactions, *, assessments=None, ledger=None):
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
            supplied_day = next((d for d in dates if d), None)
            booking = date.fromisoformat(supplied_day).isoformat() if supplied_day else ""
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
            balance_key = _balance_fingerprint(balance_currency, balance)
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
        row["_fetch_page"] = tx.page if isinstance(tx, _TransactionReport) else None
        row["_amount_key"] = amount_key
        row["_statement_balance"] = statement_balance
        row["_statement_sources"] = frozenset((len(drafts),))
        row["_report_index"] = len(drafts)
        row["_entry_reference"] = entry_ref
        row["_source_key"], row["_source_keys"] = source_key, source_keys
        row["_unreferenced_keys"] = unreferenced_keys
        row["prior_refs"] = list(dict.fromkeys(prior_refs))
        drafts.append(row)
    source = None
    overlaps, checkpoints = (), ()
    if drafts:
        if ledger is not None:
            drafts, overlaps, checkpoints = _StatementFetch(account_key, drafts, skipped).corrected_drafts(ledger)
        elif assessments is not None:
            snapshot = [row | {"bank_groups": row["bank_groups"].copy(), "prior_refs": row["prior_refs"].copy()} for row in drafts]
            source = _StatementFetch(account_key, snapshot, skipped)
    assessment_start = len(assessments) if source is not None else 0
    rows, skipped = _map_statement_drafts(account_key, drafts, skipped, assessments,
                                         trace=source is not None, overlaps=overlaps, checkpoints=checkpoints)
    skipped += sum(not row["date"] for row in rows)
    rows = [row for row in rows if row["date"]]
    if source is not None:
        for assessment in assessments[assessment_start:]:
            assessment["_statement_fetch"] = source
        for row in rows:
            source.original[row["ref"]] = (row.pop("_statement_report_origins", ()), row.pop("_statement_subject_reports", ()))
            row["_statement_fetch"] = source
    return rows, skipped


def _prepare_statement_sources(drafts):
    for index, row in enumerate(drafts):
        row["_statement_sources"] = frozenset((index,))
        row.pop("_statement_evidence", None)
        row.pop("_statement_capacity", None)
    _link_repeated_statement_sources(drafts)
    _mark_statement_capacity(drafts)


def _signed_edge_variants(edge, sparse, count, complete):
    if not sparse:
        yield count, [edge] * count
        return
    dated = [row for row in sparse if row["booked_day"]]
    undated = [row for row in sparse if not row["booked_day"]]
    for known in range(max(1, count - len(sparse)), min(complete, count) + 1):
        missing = count - known
        for with_date in range(max(0, missing - len(undated)), min(missing, len(dated)) + 1):
            gaps = [*dated[:with_date], *undated[:missing - with_date]]
            yield known, [*([edge] * known), *(((row["booked_day"], None, None), row) for row in gaps)]


def _balance_witness_groups(rows, currency):
    """Use corroborated versions of a bank witness as one minimum occurrence."""
    consumed = set()
    provider_reports = sum(row.get("_fetch_page") is not None for row in rows)
    observations = _statement_review_observations(rows, currency) if provider_reports > 1 else ()
    for representative, versions, origins in observations:
        if sum(row.get("_fetch_page") is not None for row in versions) < 2:
            continue
        consumed.update(origins)
        representative["bank_groups"] = {day: group for row in versions for day, group in row["bank_groups"].items()}
        copies = [row for row in versions if row["_statement_sources"] != representative["_statement_sources"]]
        yield [representative, *sorted(copies, key=_balance_report_preference)]
    exact = defaultdict(list)
    for index, row in enumerate(rows):
        if index not in consumed:
            exact[row["_amount_key"], _statement_shape(row)].append(row)
    yield from exact.values()


def _supported_edge_count(versions, observed):
    """Find the occurrence counts compatible with the signed statement window."""
    first = versions[0]
    day = first["booked_day"] if all(row["booked_day"] for row in versions) else None
    if day:
        observed = _booked_balance_window(observed, day)
    if len(observed) > _STATEMENT_PLACEMENT_BUDGET or not any(_reported_balance(row) for row in observed):
        return None

    # Each complete trail differs by at most one arrival/departure per
    # balance. Repeating this edge changes that degree at its start.
    amount = Decimal(first["amount"])
    opening = first["_statement_balance"][1] - amount
    sparse = [row for row in versions if not _reported_balance(row)]
    complete = len(versions) - len(sparse)
    previous = max(row.get("_pending_page_count", 0) for row in versions)
    if previous > _STATEMENT_PLACEMENT_BUDGET:
        return None
    saved_days = set().union(*(row.get("_pending_sparse_days", ()) for row in versions))
    if previous > len(versions) and len(saved_days) == 1:
        # The prior unsigned report need not occur in a weaker response.
        # Recheck its placement, but only actual reports can be imported.
        sparse.extend([{"booked_day": next(iter(saved_days)), "_statement_balance": None, "amount": first["amount"]}]
                      * (previous - len(versions)))
    dated = first["booked_day"] if sparse else day
    edge = ((dated, None, None), first)
    witnesses = tuple(_balance_witness_groups(observed, first["currency"]))
    paginated = bool(previous or all(row.get("_fetch_page") is not None for row in versions))
    counts = (1,) * len(witnesses)
    pending = [counts]
    checked = {counts}
    trials = 0
    while pending:
        supported = {}
        for selection in pending:
            peers = [row for copies, count in zip(witnesses, selection) for row in copies[:count]]
            signed = [(Decimal(row["amount"]), balance[1]) for row in peers if (balance := _reported_balance(row))]
            departure = sum(ending - amount == opening for amount, ending in signed)
            departure -= sum(ending == opening for _, ending in signed)
            # A movement without an ending balance can add or remove one
            # edge at this balance. Its actual position is tested below.
            gaps = len(peers) - len(signed)
            minimum = max(1, -1 - departure - gaps - len(sparse))
            maximum = min(max(2, complete + len(sparse)), 1 - departure + gaps + 2 * len(sparse))
            peer_edges = [((row["booked_day"], None, None), row) for row in peers]
            for count in range(minimum, maximum + 1):
                for known, subjects in _signed_edge_variants(edge, sparse, count, complete):
                    if sparse and trials >= _STATEMENT_PLACEMENT_BUDGET:
                        return None
                    trials += 1
                    candidates = [len(peer_edges) + index for index in range(known, len(subjects))
                                  if not paginated or not subjects[index][0][0]]
                    fits = _review_joint_trail(first["currency"], [*peer_edges, *subjects], (), sparse_occurrences=candidates)
                    if fits is None:
                        return None
                    if fits:
                        supported[count] = min(supported.get(count, known), known)
        if supported:
            return (supported, [copies[0] for copies in witnesses]) if min(supported) <= len(versions) else None
        # A repeated witness is needed only when fewer observations cannot
        # form a trail. Compare every hypothesis at that level before using it.
        expanded = []
        for selection in pending:
            for index, (copies, count) in enumerate(zip(witnesses, selection)):
                if count == len(copies):
                    continue
                candidate = (*selection[:index], count + 1, *selection[index + 1:])
                if candidate in checked:
                    continue
                if len(checked) >= _STATEMENT_PLACEMENT_BUDGET:
                    return None
                checked.add(candidate)
                expanded.append(candidate)
        pending = expanded
    return None


def _balance_edge_witnesses(row, peers):
    ending = row["_statement_balance"][1]
    opening = ending - Decimal(row["amount"])
    day = row["booked_day"]
    before = [core._bank_statement_option(peer) for peer in peers if (balance := _reported_balance(peer)) and balance[1] == opening
              and (not peer["booked_day"] or peer["booked_day"] <= day)]
    after = [core._bank_statement_option(peer) for peer in peers if (balance := _reported_balance(peer))
             and balance[1] - Decimal(peer["amount"]) == ending
             and (not peer["booked_day"] or peer["booked_day"] >= day)]
    return before, after


def _balance_report_conflict(first, second):
    if _conflicting_facts(first, second, _FETCH_FIXED_FACTS) or _conflicting_counterparties(first, second):
        return True
    if ("_confirmed_reference_aliases" in first or "_confirmed_reference_aliases" in second):
        if all(row["_remittance"] for row in (first, second)) and first["_remittance"] != second["_remittance"]:
            return True
    # With both BOOK dates absent, leave disjoint possible posting days
    # separate. Calendar overlap alone is used only to admit a hypothesis.
    return not (first["booked_day"] or second["booked_day"]) and first["bank_groups"].keys().isdisjoint(second["bank_groups"])


def _sparse_reports_match(first, second):
    return not _balance_report_conflict(first, second) and (
        any(_same_statement_fact(first, second, field) for field in _STATEMENT_DATE_FIELDS)
        or (not _conflicting_facts(first, second, _SECONDARY_BANK_DATES)
            and not first["bank_groups"].keys().isdisjoint(second["bank_groups"]))
    )


def _link_copy_family(contested, candidates, row):
    linked = [(sources, peers) for sources, peers in contested if not candidates.isdisjoint(sources)]
    remaining = [(sources, peers) for sources, peers in contested if candidates.isdisjoint(sources)]
    return [*remaining, (candidates.union(*(sources for sources, _ in linked)),
                         [row, *(peer for _, peers in linked for peer in peers)])]


def _unbalanced_observation_families(reports):
    groups, unresolved = _compatible_copy_groups(reports, lambda first, second: not _sparse_reports_match(first, second))
    groups = list(groups)
    contested = []
    for row in unresolved:
        candidates = {index for index, group in enumerate(groups) if all(_sparse_reports_match(row, other) for other in group)}
        if candidates:
            contested = _link_copy_family(contested, candidates, row)
    linked = set().union(*(sources for sources, _ in contested))
    yield from (([groups[index] for index in sorted(sources)], peers) for sources, peers in contested)
    yield from (([group], []) for index, group in enumerate(groups) if index not in linked)


def _signed_observation_groups(drafts, shared, unbalanced):
    complete = defaultdict(list)
    sparse = defaultdict(list)
    for row in drafts:
        key = row["currency"], row["_amount_key"]
        if balance := _reported_balance(row):
            complete[key, balance].append(row)
        else:
            sparse[key].append(row)
    by_amount = defaultdict(list)
    for (key, _), reports in complete.items():
        groups, _ = _compatible_copy_groups(reports, _balance_report_conflict)
        by_amount[key].extend(list(group) for group in groups)
    for key in dict.fromkeys((*by_amount, *sparse)):
        groups = by_amount[key]
        unmatched = []
        contested = []
        for row in sparse[key]:
            matches = set()
            for index, group in enumerate(groups):
                anchored = [other for other in group if _reported_balance(other)]
                if all(_sparse_reports_match(row, other) for other in anchored) and not (len(anchored) > 1 and any(
                    _conflicting_facts(row, other, _SECONDARY_BANK_DATES) for other in anchored
                )):
                    matches.add(index)
            if len(matches) == 1:
                groups[next(iter(matches))].append(row)
            elif matches:
                contested = _link_copy_family(contested, matches, row)
            elif row.get("_fetch_page") is not None and Decimal(row["amount"]):
                unmatched.append(row)
        unbalanced.extend(_unbalanced_observation_families(unmatched))
        shared.extend(([groups[index] for index in sorted(candidates)], reports) for candidates, reports in contested)
        yield from groups


def _booked_balance_window(rows, day):
    openings, closings, edges = defaultdict(set), defaultdict(set), defaultdict(list)
    for row in rows:
        if not (booked := row["booked_day"]) or not (amount := Decimal(row["amount"])):
            continue
        balance = _reported_balance(row)
        openings[booked].add(balance[1] - amount if balance else None)
        closings[booked].add(balance[1] if balance else None)
        if balance:
            edges[booked].append((row, core._BankMovement(booked, booked, amount, balance[1])))

    def checkpoint(booked, boundaries):
        if None in boundaries:
            return False
        if len(boundaries) == 1:
            return True
        # A day can have several reported balances and still end at one
        # checkpoint if its signed transitions form a single dated trail.
        group = edges[booked]
        starts = core._bank_day_openings([movement for _, movement in group])
        return bool(starts and len(starts) == 1 and
                    core._bank_revision_order({booked: group}, next(iter(starts)), group[0][0]["currency"]))

    # The nearest signed day might end at different balances. Keep its
    # enclosing checkpoint rather than letting that day's opening float.
    start = next((date for date in sorted(closings, reverse=True) if date < day and checkpoint(date, closings[date])), None)
    end = next((date for date in sorted(openings) if date > day and checkpoint(date, openings[date])), None)
    return [row for row in rows if not (booked := row["booked_day"])
            or ((start is None or start <= booked) and (end is None or booked <= end))]


def _shared_sparse_occurrences(account_key, groups, sparse, account_rows, trace, assess):
    """Count unbalanced reports in a family without claiming which edge each repeats."""
    contested = {row["_report_index"] for row in sparse}
    complete = [[row for row in group if _reported_balance(row)] for group in groups]
    sparse = [*sparse, *(row for group in groups for row in group if not _reported_balance(row))]
    anchored = [row for group in complete for row in group]
    first = anchored[0]
    days = {row["booked_day"] for row in anchored if row["booked_day"]} or {row["date"] for row in anchored}
    if len(days) != 1:
        return set(), [], 0, None
    origins = {row["_report_index"] for row in (*anchored, *sparse)}
    observed = [row for row in account_rows if row["currency"] == first["currency"] and row["_report_index"] not in origins]
    window = _booked_balance_window(observed, next(iter(days)))
    independent = [copies[0] for copies in _balance_witness_groups(window, first["currency"])]
    peers = [((row["booked_day"], None, None), row) for row in independent]
    by_day = defaultdict(list)
    for row in sparse:
        by_day[row["booked_day"]].append(row)
    buckets = [*complete, *by_day.values()]
    counts = product(*(range(1 if index < len(complete) else 0, len(rows) + 1) for index, rows in enumerate(buckets)))
    preferred = None
    supported = set()
    if len(window) + len(origins) <= _STATEMENT_PLACEMENT_BUDGET and (not window or any(_reported_balance(row) for row in window)):
        for trial, selected in enumerate(counts):
            if trial >= _STATEMENT_PLACEMENT_BUDGET:
                supported.clear()
                break
            reports = [row for rows, count in zip(buckets, selected) for row in rows[:count]]
            subject = [((row["booked_day"], None, None), row) for row in reports]
            candidates = {len(peers) + index for index, row in enumerate(reports) if not _reported_balance(row)}
            fits = _review_joint_trail(first["currency"], [*peers, *subject], (), sparse_occurrences=candidates)
            if fits is None:
                supported.clear()
                break
            if fits:
                supported.add(len(reports))
                live = [row for row in reports if not _reported_balance(row)]
                if preferred is None or (len(reports), len(live)) < preferred[0]:
                    preferred = (len(reports), len(live)), live
    page_bounds = _paginated_occurrence_bounds(complete, sparse) if assess else None
    if not supported and not page_bounds:
        return set(), [], 0, None
    assessment = None
    if page_bounds:
        assessment = _balance_occurrence_assessment(account_key, [*anchored, *sparse], supported or page_bounds,
                                                    independent, trace, paginated=True)
    live = preferred[1] if supported else []
    dropped = {row["_report_index"] for row in sparse} - {row["_report_index"] for row in live}
    # The signed payments alone can settle the count while leaving the
    # sparse observation's identity unresolved.
    return dropped, live, int(not window and bool(contested & dropped)), assessment


def _balance_occurrence_reports(versions, count, anchored=None):
    """Keep distinguishable source facts before selecting repeated reports."""
    support = Counter(_statement_shape(row) for row in versions)
    by_details = defaultdict(list)
    for row in versions:
        by_details[row["provider_ref"], row["creditor_ref"], row["description"]].append(row)

    def priority(row):
        return (-support[_statement_shape(row)], not row["booked_day"], row["description"], row["ref"] or row["_source_key"])

    ordered = [(index, row) for reports in by_details.values()
               for index, row in enumerate(sorted(reports, key=priority))]
    ordered.sort(key=lambda item: (item[1]["description"] == "Bankumsatz", item[0], *priority(item[1])))
    ordered = [row for _, row in ordered]
    if anchored is None:
        kept = ordered[:count]
    else:
        complete = [row for row in ordered if _reported_balance(row)]
        sparse = [row for row in ordered if not _reported_balance(row)]
        kept = [*complete[:anchored], *sparse[:count - anchored]]
    kept_indices = {row["_report_index"] for row in kept}
    dropped = [row for row in ordered if row["_report_index"] not in kept_indices]
    represented = {row["_remittance"] for row in kept}
    warning = any(row["_remittance"] and row["_remittance"] not in represented for row in dropped)
    return {row["_report_index"] for row in dropped}, warning


def _balance_occurrence_assessment(account_key, versions, supported, peers, trace, *, paginated=False):
    first = versions[0]
    days = {row["booked_day"] for row in versions if row["booked_day"]} or {row["date"] for row in versions}
    if len(days) != 1 or (len(versions) == 1 and len(supported) > 1):
        return None
    day = next(iter(days))
    # A pending amount needs an observable statement window. An intraday
    # offset with a floating opening is not evidence of an extra payment.
    if len(supported) > 1 and not paginated and not (
        any(row["booked_day"] and row["booked_day"] < day for row in peers)
        and any(row["booked_day"] and row["booked_day"] > day for row in peers)
        and sum(bool(_reported_balance(row) or row["booked_day"]) for row in versions) > min(supported)
    ):
        return None
    balances = sorted({row["balance_key"] for row in versions if _reported_balance(row)})
    if len(balances) <= 1:
        creditor = next((row["creditor_ref"] for row in versions if row["creditor_ref"]), None)
        party = tuple(sorted(set().union(*(row["counterparty_ids"] for row in versions))))
        identity = balances[0] if balances else None
        facts = (identity, creditor, party)
        proof = [facts]
    else:
        identity = balances
        proof = [(balance, None, ()) for balance in balances]
        facts = proof
    scope = fingerprint(account_key, "balance-occurrence", first["_amount_key"], first["currency"], identity)
    reference_facts = facts if balances else (facts, sorted({row["provider_ref"] for row in versions if row["provider_ref"]}))
    observation = {
        "ref": core.ENABLE_BANKING_REF_PREFIX + fingerprint(scope, day, reference_facts),
        "account_key": account_key, "date": day, "amount": first["amount"], "currency": first["currency"],
        "_statement_review_proof": (scope, {"day": day}, proof),
        "_statement_review_options": [core._bank_statement_option(row) for row in versions],
        "_statement_observed_balances": sorted({(row["balance_key"], str(balance[1])) for row in (*versions, *peers)
                                               if (balance := _reported_balance(row))}),
        "_statement_occurrence_bounds": (min(supported), min(max(supported), len(versions))),
        "_statement_occurrence_observed": len(versions) > 1,
        "_statement_occurrence_witnesses": [
            (row["bank_group"], core._bank_statement_option(row), row["description"]) for row in peers
        ],
    }
    if all(row.get("_fetch_page") is not None for row in versions):
        observation["_statement_page_family"] = fingerprint(account_key, first["_amount_key"], first["currency"])
    if trace:
        observation["_statement_subject_reports"] = (frozenset(row["_report_index"] for row in versions),)
    return observation


def _paginated_occurrence_bounds(groups, sparse):
    """Allow continuation reports to overlap independently known movements."""
    if not sparse:
        return None
    pages = set()
    for versions in groups:
        complete = Counter(row.get("_fetch_page") for row in versions if _reported_balance(row))
        if None in complete or max(complete.values()) != 1:
            return None
        pages.update(complete)
    overlaps = defaultdict(set)
    for row in sparse:
        overlaps[row.get("_fetch_page")].add(_statement_shape(row))
    if None in overlaps or len(pages | overlaps.keys()) < 2:
        return None
    lower = len(groups)
    return {lower: lower, lower + max(map(len, overlaps.values())): lower}


def _balance_report_preference(row):
    return (not row["provider_ref"], not _reported_balance(row), not row["booked_day"], row["description"] == "Bankumsatz",
            -sum(bool(row[field]) for field in (*_OPTIONAL_BOOKING_FACTS, "counterparty_ids")),
            row["description"], row["ref"] or row["_source_key"])


def _merge_balance_reports(account_key, versions, count, disputed, supported, proof_peers):
    preferred = min(versions, key=_balance_report_preference)
    known = {field: row[field] for row in versions for field in ("booked_day", *_OPTIONAL_BOOKING_FACTS) if row[field]}
    known.update((field, preferred[field]) for field in _SECONDARY_BANK_DATES if preferred[field])
    merged = preferred | known | {"_statement_balance": versions[0]["_statement_balance"]}
    if merged["booked_day"]:
        merged["date"] = merged["booked_day"]
    _merge_copy_metadata(merged, versions)
    if merged["provider_ref"] and merged["_entry_reference"]:
        merged["_dated_ref"] = fingerprint(account_key, "entry", merged["_entry_reference"], merged["date"],
                                            merged["_amount_key"], merged["currency"])
        merged["ref"] = _dated_booking_ref(merged["_dated_ref"], merged)
    merged["_source_keys"] = tuple(dict.fromkeys(key for row in versions for key in row["_source_keys"]))
    merged["prior_refs"].extend(row["ref"] for row in versions if row["ref"] and row["ref"] != merged["ref"])
    if aliases := set().union(*(row.get("_confirmed_reference_aliases", ()) for row in versions)):
        merged["_confirmed_reference_aliases"] = aliases
    if count == 1:
        merged["_statement_observed_refs"] = {
            row["ref"] or core.bank_source_reference(row["_source_key"], 1) for row in versions
            if not disputed or row["description"] == preferred["description"]
        }
        if merged["booked_day"] and _reported_balance(merged) and len(supported) == 1:
            merged["_statement_edge_witnesses"] = _balance_edge_witnesses(merged, proof_peers)
    return preferred["_report_index"], merged


def _unbalanced_placements(versions, minimum):
    previous = max(row.get("_pending_page_count", 0) for row in versions)
    if previous > _STATEMENT_PLACEMENT_BUDGET:
        return
    # An absent echo is not proof that it was a copy. Recheck the previous
    # range against the current balance interval, without importing probes.
    if previous > len(versions):
        versions = [*versions, *([min(versions, key=_balance_report_preference)] * (previous - len(versions)))]
    dated = [row for row in versions if row["booked_day"]]
    undated = [row for row in versions if not row["booked_day"]]
    for known, unknown in product(range(len(dated) + 1), range(len(undated) + 1)):
        if known + unknown >= minimum:
            yield [((row["booked_day"], None, None), row) for row in (*dated[:known], *undated[:unknown])]


def _review_page_balance_trail(currency, movements, unplaced):
    """Check occurrence counts against fixed BOOK days and known balances."""
    if not unplaced and all(days[0] for days, _ in movements):
        groups = defaultdict(list)
        for days, row in movements:
            day = days[0]
            balance = _reported_balance(row)
            groups[day].append((None, core._BankMovement(day, day, Decimal(row["amount"]), balance[1] if balance else None)))
        if openings := core._bank_revision_openings(groups):
            uncertain = False
            for opening in openings:
                if trail := core._bank_revision_order(groups, opening, currency):
                    return True
                uncertain |= trail is None
            return None if uncertain else False
    return _review_joint_trail(currency, movements, (), sparse_occurrences=unplaced)


def _unbalanced_page_support(versions, peers, minimum, related):
    days = {row["booked_day"] for row in versions if row["booked_day"]} or {row["date"] for row in versions}
    if len(days) != 1:
        return set(), ()
    day = next(iter(days))
    window = _booked_balance_window(peers, day)
    # An undated movement can sit outside the local window. Its signed
    # trail then also needs the intervening booked movements.
    if all(row["booked_day"] for row in window):
        peers = window
    selected = {row["_report_index"] for row in peers}
    coupled = []
    representatives = []
    for alternatives, families in related:
        origins = {row["_report_index"] for row in alternatives}
        if not selected.isdisjoint(origins):
            if not origins <= selected or len({row["booked_day"] for row in alternatives if row["booked_day"]}) > 1:
                return set(), peers
            coupled.append((alternatives, len(families)))
            representatives.extend(min(group, key=_balance_report_preference) for group in families)
            selected.difference_update(origins)
    unrelated = [row for row in peers if row["_report_index"] in selected]
    independent = [copies[0] for copies in _balance_witness_groups(unrelated, versions[0]["currency"])]
    evidence = [*independent, *representatives]
    checkpoint_days = [row["booked_day"] for row in independent if row["booked_day"] and _reported_balance(row)]
    unplaced = sum(not row["booked_day"] or not _reported_balance(row) for row in evidence)
    if (unplaced + len(versions) > _STATEMENT_PLACEMENT_BUDGET or len(checkpoint_days) < 2
            or (day not in checkpoint_days and not min(checkpoint_days) < day < max(checkpoint_days))):
        return set(), evidence
    witnesses = [((row["booked_day"], None, None), row) for row in independent]
    choices = [list(islice(_unbalanced_placements(group, lower), _STATEMENT_PLACEMENT_BUDGET + 1))
               for group, lower in [(versions, minimum), *coupled]]
    supported = set()
    for trial, (subject, *companions) in enumerate(product(*choices)):
        if trial >= _STATEMENT_PLACEMENT_BUDGET:
            return set(), evidence
        motions = [*witnesses, *subject, *(motion for group in companions for motion in group)]
        # A recorded BOOK day can put an unsigned movement before or after
        # the last numeric checkpoint on that day. Keep both placements.
        constrained = [index for index in range(len(witnesses), len(motions)) if not motions[index][0][0]]
        fits = _review_page_balance_trail(versions[0]["currency"], motions, constrained)
        if fits is None:
            return set(), evidence
        if fits:
            supported.add(len(subject))
    return supported, evidence


@dataclass
class _BalanceFamily:
    groups: list
    contested: list

    @property
    def reports(self):
        return [*(row for group in self.groups for row in group), *self.contested]

    def representatives(self):
        return [min(group, key=lambda row: (not _reported_balance(row), _balance_report_preference(row)))
                for group in self.groups]

    def has_optional_reports(self):
        reports = self.reports
        if any(row.get("_pending_page_count", 0) > len(self.groups) for row in reports):
            return True
        return len(reports) > len(self.groups) and any(
            not _reported_balance(row) or not row["provider_ref"] for row in reports
        )

    def choices(self):
        """Keep one observation of each distinct payment in every hypothesis."""
        fixed = self.representatives()
        fixed_indices = {row["_report_index"] for row in fixed}
        reports = self.reports
        extras = defaultdict(list)
        for row in reports:
            if row["_report_index"] not in fixed_indices:
                extras[row["booked_day"], _reported_balance(row)].append(row)
        previous = max(row.get("_pending_page_count", 0) for row in reports)
        saved_days = set().union(*(row.get("_pending_sparse_days", ()) for row in reports))
        if previous > len(reports):
            # Retain a previously observed option on a shorter replay. A
            # probe can constrain the proof, but can never become a booking.
            anchor = fixed[0]
            signed_edge = anchor["booked_day"], anchor["balance_key"]
            saved_edges = {row["_pending_signed_edge"] for row in reports if row.get("_pending_signed_edge")}
            if len(saved_days) == 1:
                placement = next(iter(saved_days)), None
            elif not saved_days and len(fixed) == 1 and saved_edges == {signed_edge} and (balance := _reported_balance(anchor)):
                placement = anchor["booked_day"], balance
            else:
                placement = None
            if placement is not None:
                day, balance = placement
                extras[placement].extend([{"booked_day": day, "_statement_balance": balance, "amount": anchor["amount"]}]
                                         * min(previous - len(reports), _STATEMENT_PLACEMENT_BUDGET + 1))
        buckets = tuple(extras.values())
        for counts in product(*(range(len(rows) + 1) for rows in buckets)):
            yield (*fixed, *(row for rows, count in zip(buckets, counts) for row in rows[:count]))


def _joint_balance_window(families, witnesses, currency):
    """Project one set of feasible account histories onto every subject."""
    choices = [list(islice(family.choices(), _STATEMENT_PLACEMENT_BUDGET + 1)) for family in families]
    peers = [((row["booked_day"], None, None), row) for row in witnesses]
    histories = {}
    baseline = tuple(len(family.groups) for family in families)
    alternatives = {}
    for trial, selection in enumerate(product(*choices)):
        if trial >= _STATEMENT_PLACEMENT_BUDGET:
            return None
        subjects = [((row["booked_day"], None, None), row) for rows in selection for row in rows]
        if len(peers) + len(subjects) > _STATEMENT_PLACEMENT_BUDGET:
            return None
        constrained = [len(peers) + i for i, (days, row) in enumerate(subjects) if not days[0] and not row["_statement_balance"]]
        fits = _review_joint_trail(currency, [*peers, *subjects], (), sparse_occurrences=constrained)
        if fits is None:
            return None
        if fits:
            counts = tuple(map(len, selection))
            if all("_report_index" in row for rows in selection for row in rows):
                histories[counts] = selection
                for rows, count in zip(selection, baseline):
                    alternatives.update((row["_report_index"], row) for row in rows[count:])
            else:
                histories.setdefault(counts, None)
    if not histories:
        return None
    supported = [set(counts) for counts in zip(*histories)]
    # Book only a combination supported by the same statement. An optional
    # receipt and its possible reversal cannot prove one another separately.
    minimum = tuple(map(min, supported))
    if selection := histories.get(minimum):
        return list(zip(families, supported, selection)), ()
    # Different named allocations can establish the same signed count
    # even when no single allocation contains all per-source minima.
    surplus_counts = {sum(counts) - sum(baseline) for counts in histories}
    if (min(surplus_counts) > 0 and all(rows is not None for rows in histories.values())
            and len({row["_amount_key"] for row in alternatives.values()}) == 1):
        return [], (list(alternatives.values()), min(surplus_counts), max(surplus_counts))
    return [], ()


def _joint_balance_proofs(families, account_by_currency):
    """Group occurrence decisions whose dated windows share bank observations."""
    by_currency = defaultdict(list)
    for family in families:
        reports = family.reports
        currency = reports[0]["currency"]
        days = {row["booked_day"] for row in reports if row["booked_day"]}
        if len(days) != 1 or not all(row.get("_fetch_page") is not None for row in reports):
            continue
        window = _booked_balance_window(account_by_currency[currency], next(iter(days)))
        by_currency[currency].append((family, {row["_report_index"] for row in reports},
                                      {row["_report_index"] for row in window}))
    for currency, pending in by_currency.items():
        if len(pending) < 2:
            continue
        dated = {row["_report_index"]: row["booked_day"] for row in account_by_currency[currency] if row["booked_day"]}
        while pending:
            family, subjects, window = pending.pop()
            connected = [family]
            while related := [(other, origins, bounds) for other, origins, bounds in pending
                              if not origins.isdisjoint(window) or not subjects.isdisjoint(bounds)]:
                for other, origins, bounds in related:
                    pending.remove((other, origins, bounds))
                    connected.append(other)
                    subjects = subjects | origins
                    window = window | bounds
                # A report without BOOK can connect noncontiguous local
                # windows. The combined trail still covers every booked
                # movement between its enclosing checkpoints.
                days = [day for index, day in dated.items() if index in window]
                first, last = min(days), max(days)
                window.update(index for index, day in dated.items() if first <= day <= last)
            if len(connected) < 2:
                continue
            peers = [row for row in account_by_currency[currency] if row["_report_index"] in window - subjects]
            if not any(_reported_balance(row) for row in peers):
                continue
            bounded = len(window) <= _STATEMENT_PLACEMENT_BUDGET
            witnesses = [copies[0] for copies in _balance_witness_groups(peers, currency)] if bounded else peers
            subject_rows = [row for family in connected for row in family.reports]
            if not any(_reported_balance(row) for row in subject_rows):
                # The subjects can all lack their own balances. Independent
                # dated checkpoints must still bracket the possible postings.
                days = [row["booked_day"] for row in subject_rows]
                checkpoints = [row["booked_day"] for row in witnesses if row["booked_day"] and _reported_balance(row)]
                if not all(days) or len(checkpoints) < 2 or not min(checkpoints) <= min(days) <= max(days) <= max(checkpoints):
                    continue
            decisions = None
            if bounded:
                decisions = _joint_balance_window(connected, witnesses, currency)
            if decisions and decisions[0]:
                for subject, supported, selection in decisions[0]:
                    peers = [row for other in connected if other is not subject for row in other.representatives()]
                    yield subject, supported, selection, [*witnesses, *peers], None
            else:
                # Keep independently identified movements and earlier
                # monetary decisions. Review the unresolved reports without
                # letting separate proofs turn either echo into a booking.
                surplus = None
                if decisions and decisions[1]:
                    members = [*witnesses, *(row for subject in connected for row in subject.representatives())]
                    alternatives, minimum, maximum = decisions[1]
                    surplus = alternatives, members, minimum, maximum
                for subject in connected:
                    yield subject, None, subject.representatives(), (), surplus
                    surplus = None


def _joint_statement_reviews(account_key, alternatives, members, minimum, maximum, trace):
    first = alternatives[0]
    amount, currency = first["_amount_key"], first["currency"]
    checkpoints = sorted({(row["booked_day"] or "", *(row[field] or "" for field in _SECONDARY_BANK_DATES),
                           row["_amount_key"], row["balance_key"])
                          for row in members if _reported_balance(row)})
    dates = {row["booked_day"] for row in alternatives}
    known = None not in dates and len(dates) == 1
    enclosing = sorted({row["booked_day"] for row in members if _reported_balance(row) and row["booked_day"]})
    if not enclosing or (None in dates and len(enclosing) < 2):
        return
    bounds = (min(dates), max(dates)) if None not in dates else (enclosing[0], enclosing[-1])
    context = tuple(row for row in members if row.get("_statement_context"))
    balances = sorted({(row["balance_key"], str(balance[1])) for row in members if (balance := _reported_balance(row))})
    members = [core._bank_statement_option(row) for row in members]
    scope = core._joint_statement_scope(account_key, amount, currency, checkpoints, bounds, members)
    joint = {
        "scope": scope,
        "account_key": account_key,
        "bounds": (enclosing[0], enclosing[-1]),
        "dates": bounds, "members": members, "balances": balances, "minimum": minimum, "maximum": maximum,
    }
    details = {
        "joint": joint, "proof": (scope, {}, (), (bounds[0], checkpoints)),
        "observations": [core._bank_statement_option(row) for row in alternatives],
    }
    for slot in range(minimum):
        review = core._joint_statement_template(scope, slot, details, bounds, currency, amount, known=known)
        review["_statement_remainder"] = maximum - minimum if slot == 0 else 0
        if context:
            review["_statement_closing_context"] = context
        if trace:
            review["_statement_subject_reports"] = (frozenset(row["_report_index"] for row in alternatives),)
        yield review


def _reconcile_balance_reports(account_key, drafts, account_rows, assessments, neutral, trace, overlap_witnesses=()):
    """Reconcile compatible reports to the number supported by the balance trail."""
    reviewed = defaultdict(set)
    for assessment in assessments:
        for days, facts in assessment["_statement_review_members"]:
            booking = core._BankBooking(*facts)
            for day in days:
                reviewed[day].add(booking)
    def independently_reviewed(versions):
        return any(not core._bank_facts_conflict(row, booking)
                   for row in versions for group in row["bank_groups"].values() for booking in reviewed.get(group, ()))

    account_by_currency = defaultdict(list)
    for row in account_rows:
        account_by_currency[row["currency"]].append(row)
    retained = defaultdict(list)
    for row in overlap_witnesses:
        retained[row["currency"], row["booked_day"]].append(row)
    replacements = {}
    omitted = set()
    warnings = 0
    shared = []
    unbalanced = []
    groups = list(_signed_observation_groups(drafts, shared, unbalanced))
    shared_members = {id(group) for family, _ in shared for group in family}
    joint_families = [_BalanceFamily(family, sparse) for family, sparse in shared]
    joint_families.extend(_BalanceFamily([group], []) for group in groups if id(group) not in shared_members)
    page_families = []
    for families, contested in unbalanced:
        family = _BalanceFamily(families, contested)
        versions = family.reports
        if (len(versions) > 1 or any(row.get("_pending_page_count") for row in versions)) and not independently_reviewed(versions):
            page_families.append((versions, families))
            joint_families.append(family)
    joint_families = [family for family in joint_families if (
        family.has_optional_reports()
        and not independently_reviewed(family.reports)
    )]
    joint = set()
    for family, supported, selection, peers, surplus in _joint_balance_proofs(joint_families, account_by_currency):
        if surplus:
            for review in _joint_statement_reviews(account_key, *surplus, trace):
                if review["state"] == "confirmed":
                    neutral.append(review)
                if review["state"] == "unplaced" or review["_statement_remainder"]:
                    assessments.append(review)
        versions = family.reports
        origins = {row["_report_index"] for row in versions}
        joint.update(origins)
        if supported is not None:
            if assessment := _balance_occurrence_assessment(account_key, versions, supported, peers, trace, paginated=True):
                assessments.append(assessment)
        if len(selection) == 1 and supported is not None:
            index, merged = _merge_balance_reports(account_key, versions, 1, len(supported) > 1, supported, peers)
            replacements[index] = merged
            omitted.update(origins - {index})
        else:
            kept = {row["_report_index"] for row in selection}
            omitted.update(origins - kept)
            if len(selection) > 1:
                for slot, row in enumerate(selection):
                    replacements[row["_report_index"]] = row | {"_statement_slot": (("balance", frozenset(kept)), slot),
                                                                 "_statement_edge_occurrence": True}
        memos = {row["_remittance"] for row in selection}
        warnings += int(supported is None or any(row["_remittance"] and row["_remittance"] not in memos for row in versions))
    page_families = [(versions, families) for versions, families in page_families
                     if versions[0]["_report_index"] not in joint]
    for versions, families in page_families:
        origins = {row["_report_index"] for row in versions}
        observed = [row for row in account_by_currency[versions[0]["currency"]] if row["_report_index"] not in origins]
        related = ((other, groups) for other, groups in page_families if other is not versions)
        supported, peers = _unbalanced_page_support(versions, observed, len(families), related)
        separate_pages = len({row["_fetch_page"] for row in versions}) > 1
        if not separate_pages and (not supported or min(supported) > len(versions)):
            continue
        if not supported:
            references = {row["provider_ref"] for row in versions}
            if len(references) == 1 and None not in references:
                continue
            lower = sum(max(Counter(row["_fetch_page"] for row in group).values()) for group in families)
            supported = {lower, min(len(versions), lower * 2)}
        witnesses = {(row["_amount_key"], _statement_shape(row)): row for row in peers}
        assessment = _balance_occurrence_assessment(account_key, versions, supported, witnesses.values(), trace, paginated=True)
        if not assessment:
            continue
        assessments.append(assessment)
        count = min(supported)
        if count == 1:
            index, merged = _merge_balance_reports(account_key, versions, count, len(supported) > 1, supported, ())
            replacements[index] = merged
            omitted.update(origins - {index})
            warnings += int(len({row["_remittance"] for row in versions if row["_remittance"]}) > 1)
        else:
            required = {min(group, key=_balance_report_preference)["_report_index"] for group in families}
            dropped, _ = _balance_occurrence_reports([row for row in versions if row["_report_index"] not in required], count - len(required))
            omitted.update(dropped)
            members = ("balance", frozenset(origins - dropped))
            kept = [row for row in versions if row["_report_index"] not in dropped]
            for slot, row in enumerate(kept):
                replacements[row["_report_index"]] = row | {"_statement_slot": (members, slot), "_statement_edge_occurrence": True}
            memos = {row["_remittance"] for row in kept}
            warnings += int(any(row["_remittance"] and row["_remittance"] not in memos for row in versions))
    retained_sparse = set()
    for family, sparse in shared:
        if sparse[0]["_report_index"] in joint:
            continue
        assess = not independently_reviewed([*sparse, *(row for group in family for row in group)])
        dropped, live, unidentified, assessment = _shared_sparse_occurrences(account_key, family, sparse, account_rows, trace, assess)
        if assessment:
            assessments.append(assessment)
        omitted.update(dropped)
        warnings += unidentified
        retained_sparse.update(row["_report_index"] for row in live)
        for row in live:
            replacements[row["_report_index"]] = row | {"_statement_edge_occurrence": True, "_statement_extra_sparse": True}
    if omitted:
        account_by_currency = {currency: [row for row in rows if row["_report_index"] not in omitted]
                               for currency, rows in account_by_currency.items()}
    for group in groups:
        if group[0]["_report_index"] in joint:
            continue
        versions = [row for row in group if row["_report_index"] not in omitted | retained_sparse]
        sparse = [row for row in versions if not _reported_balance(row)]
        if not sparse and all(row["provider_ref"] and not row.get("_pending_page_count") for row in versions):
            continue
        # A separate statement assessment can already have established
        # independent canonical movements on the same signed edge.
        if sum("_confirmed_reference_aliases" in row for row in versions) > 1:
            continue
        first = versions[0]
        origins = {row["_report_index"] for row in versions}
        observed = [row for row in account_by_currency[first["currency"]] if row["_report_index"] not in origins]
        paginated = all(row.get("_fetch_page") is not None for row in versions)
        if paginated and first["booked_day"]:
            # A settled statement may contain previously witnessed movements
            # on this day that a short fetch no longer returns.
            observed.extend(retained[first["currency"], first["booked_day"]])
        # The copies alone are not a statement. In an isolated reply
        # preserve source occurrences until independent movements can
        # constrain whether the balance was reached again.
        has_context = any(
            (row["_amount_key"] != first["_amount_key"] or balance not in (None, first["_statement_balance"]))
            for row in observed if Decimal(row["amount"]) and ((balance := _reported_balance(row)) or not sparse)
        )
        supported, proof_peers = (_supported_edge_count(versions, observed) if has_context else None) or ({}, ())
        assessment = None
        if not independently_reviewed(versions):
            if supported:
                assessment = _balance_occurrence_assessment(account_key, versions, supported, proof_peers, trace,
                                                            paginated=paginated)
            if not assessment and len(supported) != 1 and (page_bounds := _paginated_occurrence_bounds((versions,), sparse)):
                peers = {(row["_amount_key"], _statement_shape(row)): row for row in observed}
                assessment = _balance_occurrence_assessment(account_key, versions, page_bounds, peers.values(), trace, paginated=True)
                if assessment:
                    supported = page_bounds
        disputed = bool(assessment and len(supported) > 1)
        if assessment:
            assessments.append(assessment)
        elif len(supported) > 1 and len(versions) > max(supported):
            dropped, _ = _balance_occurrence_reports(versions, min(supported))
            omitted.update(dropped)
            warnings += 1
            continue
        count = min(supported) if disputed or len(supported) == 1 else None
        if sparse and count is None:
            continue
        if count is None:
            if not has_context or len(versions) < 2 or any(not _same_reported_edge(left, right) or _conflicting_facts(left, right, _FETCH_COPY_FACTS)
                                        for left, right in combinations(versions, 2)):
                continue
            day = first["booked_day"] if all(row["booked_day"] for row in versions) else None
            peers = (row for row in observed if not day or row["booked_day"] in {day, None})
            if _possible_statement_reset(Decimal(first["amount"]), peers):
                continue
        if count and count > 1:
            dropped, label_warning = _balance_occurrence_reports(versions, count, supported[count] if sparse else None)
            omitted.update(dropped)
            members = ("balance", frozenset(origins - dropped))
            kept = (row for row in versions if row["_report_index"] not in dropped)
            for slot, row in enumerate(kept):
                replacements[row["_report_index"]] = row | {"_statement_slot": (members, slot), "_statement_edge_occurrence": True}
            warnings += label_warning
            continue
        index, merged = _merge_balance_reports(account_key, versions, count, disputed, supported, proof_peers)
        replacements[index] = merged
        omitted.update(row["_report_index"] for row in versions if row["_report_index"] != index)
        warnings += int(len({row["_remittance"] for row in versions if row["_remittance"]}) > 1)
    if not omitted and not replacements:
        return drafts, 0
    return [replacements.get(row["_report_index"], row) for row in drafts if row["_report_index"] not in omitted], warnings


def _separate_overlapping_statements(account_key, drafts, overlaps, trace):
    """Evaluate retained proofs independently, then return one set of live reports."""
    by_index = {row["_report_index"]: row for row in drafts}
    corrections = set().union(*(overlap.matched for overlap in overlaps))
    witness_claims = Counter(index for overlap in overlaps for index in overlap.linked)
    batches = []
    claimed = set()
    for overlap in overlaps:
        # A correction belongs to its proven subject. A report linked to
        # another proof can support it read-only; unlinked rows import normally.
        members = overlap.matched | {index for index in overlap.linked - corrections if witness_claims[index] == 1}
        witnesses = [by_index[index] | {"_statement_context": True} for index in sorted(overlap.linked - members)]
        for index, row in enumerate((*witnesses, *overlap.context), 1):
            row["_report_index"] = -index
        marker = {"_statement_overlap_floor": overlap.counts, "_statement_replay_overlap": overlap.proof}
        live = [by_index[index] | marker if index in overlap.matched else by_index[index] for index in sorted(members)]
        batches.append(([*live, *witnesses, *overlap.context], overlap.context))
        claimed.update(members)
    batches.append(([row for row in drafts if row["_report_index"] not in claimed], ()))
    retained, neutral, assessments = [], [], []
    proven = {}
    warnings = 0
    for batch, context in batches:
        _prepare_statement_sources(batch)
        rows, reviews, skipped, decisions = _separate_unresolved_references(account_key, batch, trace)
        confirmed = {facts for decision in decisions if decision["state"] == "confirmed"
                     for _, facts in decision["_statement_review_members"]}
        for row in context:
            option = core._bank_statement_option(row)
            if row["booked_day"] and _reported_balance(row) and option[1] in confirmed:
                proven[option] = row
        retained.extend(row for row in rows if not row.get("_statement_context"))
        neutral.extend(reviews)
        assessments.extend(decisions)
        warnings += skipped
    retained.sort(key=lambda row: row["_report_index"])
    _prepare_statement_sources(retained)
    return retained, neutral, warnings, assessments, proven.values()


def _map_statement_drafts(account_key, drafts, skipped, assessments, trace=False, overlaps=(), checkpoints=()):
    account_rows = [*drafts, *checkpoints] if checkpoints else drafts
    overlap_witnesses = ()
    if overlaps:
        drafts, neutral, review_warnings, statement_assessments, overlap_witnesses = _separate_overlapping_statements(
            account_key, drafts, overlaps, trace,
        )
    else:
        _prepare_statement_sources(drafts)
        drafts, neutral, review_warnings, statement_assessments = _separate_unresolved_references(account_key, drafts, trace)
    retained, balance_warnings = _reconcile_balance_reports(account_key, drafts, account_rows, statement_assessments, neutral, trace,
                                                           overlap_witnesses)
    if retained is not drafts:
        drafts = retained
        _prepare_statement_sources(drafts)
    if assessments is not None:
        assessments.extend(statement_assessments)
    else:
        review_warnings += sum(row.get("state") in {"pending", "unplaced"} or (
            (bounds := row.get("_statement_occurrence_bounds")) is not None and bounds[0] < bounds[1]
        ) for row in statement_assessments)
    skipped += review_warnings + balance_warnings
    selected, warnings = _resolve_statement_cohorts(drafts)
    skipped += warnings
    versions, warnings = _merge_fetch_copies(account_key, selected, drafts)
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
    _separate_statement_references(rows)
    rejected = _compare_posting_dates(rows, drafts)
    report_indices = [row["_report_index"] for row in drafts] if trace else ()
    for row in rows:
        row["_bank_account_key"] = account_key
        row["bank_groups"].update(row.pop("_statement_booking_aliases", {}))
        if statement_day := row.get("_statement_booking_day"):
            row["date"] = statement_day
            row["bank_groups"][statement_day] = fingerprint(account_key, statement_day, row["_amount_key"], row["currency"])
        row["_bank_observed_balance"] = _reported_balance(row)
        del row["_statement_balance"]
        if trace:
            row["_statement_report_origins"] = frozenset(report_indices[i] for i in row["_statement_sources"])
        del row["_statement_sources"]
        del row["_transaction_id"]
        row.pop("_report_index", None)
        row.pop("_statement_evidence", None)
        row.pop("_statement_capacity", None)
        row.pop("_statement_choice", None)
        row.pop("_statement_slot", None)
        row.pop("_statement_new_observation", None)
    return [*(row for row in rows if row["ref"] not in rejected), *neutral], skipped + warnings
