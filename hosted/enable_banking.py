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
_STATEMENT_DATE_FIELDS = ("booked_day", *_SECONDARY_BANK_DATES)
_FIXED_BOOKING_FACTS = (*_FINANCIAL_BOOKING_FACTS, "counterparty_iban")
_OPTIONAL_BOOKING_FACTS = (*_FIXED_BOOKING_FACTS, *_SECONDARY_BANK_DATES)
_REFERENCE_COPY_FACTS = ("balance_key", "creditor_ref")
_FETCH_COPY_FACTS = ("provider_ref", "booked_day", *_OPTIONAL_BOOKING_FACTS)
_FETCH_FIXED_FACTS = ("provider_ref", "booked_day", *_FIXED_BOOKING_FACTS)
_STATEMENT_IDENTITY_FACTS = ("provider_ref", "creditor_ref", "reference_schema")
_STATEMENT_OBSERVATION_FACTS = (*_FETCH_COPY_FACTS, "counterparty_ids", "_counterparty_names",
                                "_transaction_id", "_statement_balance")
_STATEMENT_PLACEMENT_BUDGET = 128


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
    if first["_transaction_id"] and second["_transaction_id"] and first["_transaction_id"] != second["_transaction_id"]:
        return True
    matching_id = any(first[field] and first[field] == second[field] for field in ("provider_ref", "_transaction_id"))
    return (not (matching_id or _statement_corroborates(first, second))
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
                or _statement_corroborates(first, second) or matching_payment)


def _statement_review_observations(drafts, currency):
    """Retain compatible reports as the capacity of each possible booking."""
    buckets = defaultdict(lambda: defaultdict(list))
    for index, row in enumerate(drafts):
        if row["currency"] == currency and Decimal(row["amount"]):
            signature = _statement_shape(row), row["_transaction_id"]
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
            if not any((row["provider_ref"] or (row["creditor_ref"] and row["counterparty_ids"]))
                       for row in versions):
                continue
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
    return not (_same_statement_fact(first, second, "provider_ref") or known_alias)


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


def _review_fixed_observations(drafts, groups, currency):
    observations = _statement_observations(drafts, (), currency)
    single_edges = set()
    for row, copies, origins in groups:
        if len(copies) < 2 or not all(copy["_statement_balance"] for copy in copies):
            continue
        # Repeating an equal balance edge requires a return to its starting
        # balance. A fully dated same-day group cannot recur without that reset.
        for field in _SECONDARY_BANK_DATES:
            day = row[field]
            if not day or not all(copy[field] == day for copy in copies):
                continue
            peers = (other for index, other in enumerate(drafts) if index not in origins
                     and other["currency"] == currency and other[field] in {day, None})
            if not _possible_statement_reset(Decimal(row["amount"]), peers):
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


def _date_predecessors(dates):
    before = [0] * len(dates)
    earlier = 0
    for _, same_day in groupby(sorted((day, i) for i, day in enumerate(dates) if day), key=lambda pair: pair[0]):
        today = 0
        for _, index in same_day:
            before[index] = earlier
            today |= 1 << index
        earlier |= today
    return before


def _review_predecessors(dates, axes):
    booked = [days[0] for days in dates]
    primary = _date_predecessors(booked)
    before = primary.copy()
    same_day = defaultdict(int)
    for index, day in enumerate(booked):
        same_day[day] |= 1 << index
    booked_mask = ((1 << len(booked)) - 1) ^ same_day[None]
    for axis in axes:
        secondary = _date_predecessors([days[axis] for days in dates])
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


def _review_joint_trail(currency, movements, axes):
    """Check balances against posting order and compatible secondary dates."""
    before = _review_predecessors([days for days, _ in movements], axes)

    amounts = [Decimal(row["amount"]) for _, row in movements]
    balances = [balance[1] if (balance := row["_statement_balance"]) and balance[0] == currency else None
                for _, row in movements]
    order = sorted(range(len(movements)), key=lambda index: balances[index] is None)

    def successors(remaining, running):
        for index in order:
            bit = 1 << index
            if not remaining & bit or before[index] & remaining:
                continue
            balance = balances[index]
            ending = None if running is None else running + amounts[index]
            if balance is not None and ending is not None and balance != ending:
                continue
            yield remaining ^ bit, balance if balance is not None else ending

    # Traverse lazily so the bound also limits retained states. Extra states
    # proportional to the number of movements allow a long ordered trail.
    budget = _STATEMENT_PLACEMENT_BUDGET + len(movements)
    stack = [iter((((1 << len(movements)) - 1, None),))]
    seen = set()
    while stack:
        state = next(stack[-1], None)
        if state is None:
            stack.pop()
            continue
        if state in seen:
            continue
        remaining, running = state
        if not remaining:
            return True
        if len(seen) >= budget:
            return None
        seen.add(state)
        stack.append(successors(remaining, running))
    return False


def _review_joint_support(currency, hypotheses):
    for evidence in (((1, 2),), ((1,), (2,)), ((),)):
        supported = set()
        for axes in evidence:
            for counts, movements in hypotheses:
                fits = _review_joint_trail(currency, movements, axes)
                if fits is None:
                    return None
                if fits:
                    supported.add(counts)
        if supported:
            return supported
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
    peers = [group for group in groups if group[2].isdisjoint(origins) and group[2] not in single_edges
             and len(group[1]) > 1 and len({row["provider_ref"] for row in group[1]}) > 1]
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
    subject_rows = [row for row, _, _ in (*versions, sparse)]
    scoped_rows = [row for row in other if row["booked_day"] == booked_day]
    unplaced_report = any(not any(row[field] for field in _SECONDARY_BANK_DATES) for row in (*subject_rows, *scoped_rows))
    records = [*other, *peer_rows, *(copy for _, copies, _ in (*versions, sparse, *peers) for copy in copies)]
    joint = force_joint or unknown_primary or sparse_row["booked_day"] != booked_day or _secondary_order_conflicts(records)
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

            options = _review_occurrence_options(cases, reported_dates if joint else position,
                                                 single_edges, peer_start, limit, joint)
            if options is None:
                if not joint:
                    return None
                return _ReferenceDispute(required, {}, [], set(), set(), None, (), None, False, False, None, None)
            axis = set()
            hypotheses = []
            fixed_dates = [(reported_dates(row), row) for row in other] if joint else None
            for selected in product(*options):
                # Date variants can represent another occurrence or another
                # report of the same movement. At least one occurrence remains.
                if not selected[0] and not any(selected[2:peer_start]):
                    continue
                candidates = []
                for (row, _, _), placements in zip(cases, selected):
                    for day, balance in placements:
                        candidates.append((day, row | {"_statement_balance": balance,
                                                       "_statement_sources": (len(candidates),)}))
                if joint:
                    hypotheses.append((tuple(map(len, selected)), [*candidates, *fixed_dates]))
                    continue
                else:
                    fits = _statement_fit(_statement_search(currency, fixed, candidates, (), floating, (min(days), max(days)),
                                                            find_any=True, slots_by_booking=slots))
                if fits is None:
                    return None
                if fits:
                    axis.add(tuple(map(len, selected)))
            if joint:
                axis = _review_joint_support(currency, hypotheses)
                if not axis:
                    return _ReferenceDispute(required, {}, [], set(), set(), None, (), None, False, False, None, None)
            if not axis:
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
            sparse_groups = [group for group in groups if any(not row["_statement_balance"] for row in group[1])]
            if not sparse_groups:
                following = min((row["booked_day"] for row in fixed if row["booked_day"] and row["booked_day"] > day
                                 and row["_statement_balance"] and row["_statement_balance"][0] == currency), default=None)
                if following:
                    sparse_groups = [group for group in by_day.get((following, amount), ())
                                     if not group[0]["_statement_balance"]]
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
                if state in {"pending", "unplaced"} or result.remainder:
                    prior_day = max((row["booked_day"] for row in fixed if row["booked_day"] and row["booked_day"] < day), default=None)
                    balance_witnesses = [*witnesses, *(row for row, _, _ in versions),
                                         *(row for row in fixed if prior_day and row["booked_day"] == prior_day)]
                    observed_balances = sorted({(row["balance_key"], str(balance[1])) for row in balance_witnesses
                                                if row["balance_key"] and (balance := row["_statement_balance"])
                                                and balance[0] == currency})
                assessments.append(review | {"state": state, "account_key": account_key,
                                             "_statement_remainder": result.remainder,
                                             "_statement_fiscal_bounds": result.fiscal_bounds,
                                             "_statement_observed_balances": observed_balances,
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
        row["_statement_sources"] = frozenset((len(retained),))
        row.pop("_statement_evidence", None)
        row.pop("_statement_capacity", None)
        retained.append(row)
    _link_repeated_statement_sources(retained)
    _mark_statement_capacity(retained)
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


def _recover_legacy_statement_balances(currency, reports, fingerprints):
    """Verify old balance hashes against the current signed movements."""
    values = {balance[1] for row in reports if (balance := row["_statement_balance"]) and balance[0] == currency}
    amounts = {Decimal(row["amount"]) for row in reports if row["currency"] == currency}
    found = {}
    checked = set()
    for _ in range(3):
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


@dataclass(eq=False)
class _StatementFetch:
    account_key: str
    drafts: list
    skipped: int
    original: dict = field(default_factory=dict)

    def corrected_drafts(self, conn):
        last = max(row["date"] for row in self.drafts)
        first = min(row["date"] for row in self.drafts)
        saved = [(currency, json.loads(details)) for currency, details in conn.execute(
            "SELECT currency, details FROM bank_statement_assessments WHERE account_key = ? AND "
            "(state IN ('pending', 'unplaced', 'protected') OR (state = 'confirmed' AND json_extract(details, '$.remainder')) "
            "OR (date BETWEEN ? AND ? AND json_extract(details, '$.balances') IS NOT NULL))",
            (self.account_key, first, last),
        )]
        if not saved:
            return None
        alternatives, known = defaultdict(list), defaultdict(dict)
        for currency, details in saved:
            known[currency].update((key, Decimal(value)) for key, value in details.get("balances", ()))
            for groups, facts in details["observations"]:
                booking = core._BankBooking(*facts[:-1], tuple(map(tuple, facts[-1])))
                for group in groups:
                    alternatives[group].append(booking)
        sources = {}
        missing = defaultdict(set)
        for index, row in enumerate(self.drafts):
            if row["_statement_balance"]:
                continue
            groups = row["bank_groups"].values()
            candidates = core._bank_statement_group_bookings(conn, groups)
            candidates.update(option for group in groups for option in alternatives[group])
            if key := _verified_statement_balance(row, candidates):
                currency = row["currency"]
                sources[index] = currency, key
                if key not in known[currency]:
                    missing[currency].add(key)
        for currency, fingerprints in missing.items():
            known[currency].update(_recover_legacy_statement_balances(currency, self.drafts, fingerprints))
        if not any(key in known[currency] for currency, key in sources.values()):
            return None
        drafts = []
        for index, row in enumerate(self.drafts):
            currency, key = sources.get(index, (row["currency"], None))
            if key in known[currency]:
                row = row | {"_statement_balance": (currency, known[currency][key]), "balance_key": key}
            drafts.append(row | {"bank_groups": row["bank_groups"].copy(), "prior_refs": row["prior_refs"].copy()})
        return drafts

    def restore(self, conn, selected):
        drafts = self.corrected_drafts(conn)
        if drafts is None:
            return None
        assessments = []
        rows, _ = _map_statement_drafts(self.account_key, drafts, self.skipped, assessments, trace=True)
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
            return all(reports & allowed for reports in subjects) and not any(
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
    if drafts and any(not row["_statement_balance"] for row in drafts):
        if ledger is not None:
            drafts = _StatementFetch(account_key, drafts, skipped).corrected_drafts(ledger) or drafts
        elif assessments is not None:
            snapshot = [row | {"bank_groups": row["bank_groups"].copy(), "prior_refs": row["prior_refs"].copy()} for row in drafts]
            source = _StatementFetch(account_key, snapshot, skipped)
    assessment_start = len(assessments) if source is not None else 0
    rows, skipped = _map_statement_drafts(account_key, drafts, skipped, assessments, trace=source is not None)
    if source is not None:
        for assessment in assessments[assessment_start:]:
            assessment["_statement_fetch"] = source
        for row in rows:
            source.original[row["ref"]] = (row.pop("_statement_report_origins", ()), row.pop("_statement_subject_reports", ()))
            row["_statement_fetch"] = source
    return rows, skipped


def _map_statement_drafts(account_key, drafts, skipped, assessments, trace=False):
    _link_repeated_statement_sources(drafts)
    _mark_statement_capacity(drafts)
    drafts, neutral, review_warnings, statement_assessments = _separate_unresolved_references(account_key, drafts, trace)
    if assessments is not None:
        assessments.extend(statement_assessments)
    skipped += review_warnings
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
        row["bank_groups"].update(row.pop("_statement_booking_aliases", {}))
        if statement_day := row.get("_statement_booking_day"):
            row["date"] = statement_day
            row["bank_groups"][statement_day] = fingerprint(account_key, statement_day, row["_amount_key"], row["currency"])
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
    return [*(row for row in rows if row["ref"] not in rejected), *neutral], skipped + warnings
