"""Tenant-local credentials, consent and scheduled bank imports."""
from contextlib import closing
from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
import secrets
import sqlite3
from threading import Event, Lock, Thread
from time import monotonic
from urllib.parse import quote, urlsplit
from uuid import UUID

import core
from hosted.common import digest
from hosted.enable_banking import BankingError, EnableBanking, fingerprint, transaction_rows


def utc_now():
    return datetime.now(timezone.utc)


class BankingService:
    def __init__(self, storage, secrets_dir, callback, *, client_factory=EnableBanking):
        self.path = Path(storage) / "enable-banking.db"
        self.secrets = secrets_dir
        self.callback = callback
        self.client_factory = client_factory
        self.sync_lock = Lock()
        self.queue_lock = Lock()
        self.wake = Event()
        self.force = False
        self.validated_application = None
        with closing(self.connect()) as db, db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS credentials (
                    id INTEGER PRIMARY KEY CHECK(id = 1), application_id TEXT NOT NULL, pem BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS pending (
                    state TEXT PRIMARY KEY, login TEXT NOT NULL, expires INTEGER NOT NULL,
                    country TEXT NOT NULL, bank TEXT NOT NULL, psu_type TEXT NOT NULL, valid_until TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS consents (
                    id TEXT PRIMARY KEY, bank TEXT NOT NULL, country TEXT NOT NULL, psu_type TEXT NOT NULL,
                    valid_until TEXT NOT NULL, accounts TEXT NOT NULL, last_synced TEXT,
                    last_attempt INTEGER, message TEXT, skipped INTEGER NOT NULL DEFAULT 0,
                    UNIQUE (bank, country, psu_type)
                );
            """)
        self.path.chmod(0o600)

    def connect(self):
        db = sqlite3.connect(self.path)
        db.row_factory = sqlite3.Row
        return db

    def mounted_credentials(self):
        application_id = self.secrets / "application-id"
        private_key = self.secrets / "private-key.pem"
        if application_id.exists() or private_key.exists():
            try:
                return application_id.read_text().strip(), private_key.read_bytes()
            except OSError as exc:
                raise BankingError("Die bereitgestellten Enable-Banking-Dateien sind unvollständig.") from exc
        return None

    def credentials_configured(self):
        if self.mounted_credentials():
            return True
        with closing(self.connect()) as db:
            return db.execute("SELECT 1 FROM credentials WHERE id = 1").fetchone() is not None

    def client(self):
        args = self.mounted_credentials()
        if args is None:
            with closing(self.connect()) as db:
                args = db.execute("SELECT application_id, pem FROM credentials WHERE id = 1").fetchone()
        if args is None:
            raise BankingError("Hinterlege zuerst deine Enable-Banking-Anwendungsdaten.")
        client = self.client_factory(*args)
        self.verify_application(client, args[1])
        return client

    def verify_application(self, client, pem):
        key = (client.application_id, sha256(pem).digest())
        cached = self.validated_application
        if cached and cached[0] == key and cached[1] > monotonic():
            return
        details = client.request("GET", "/application")
        if details.get("kid") != client.application_id or details.get("environment") != "PRODUCTION":
            raise BankingError("Hinterlege eine Enable-Banking-Produktionsanwendung mit der passenden Anwendungs-ID.")
        if details.get("active") is not True:
            raise BankingError("Die Produktionsanwendung ist bei Enable Banking noch nicht aktiv.")
        services = details.get("services")
        if not isinstance(services, list) or "AIS" not in services:
            raise BankingError("Die Anwendung benötigt den Kontoinformationsdienst (AIS).")
        redirects = details.get("redirect_urls")
        if not isinstance(redirects, list) or self.callback not in redirects:
            raise BankingError("Hinterlege die angezeigte Rücksprungadresse in deiner Enable-Banking-Anwendung.")
        self.validated_application = (key, monotonic() + 600)

    def save_credentials(self, application_id, pem):
        if self.mounted_credentials():
            raise BankingError("Diese Anwendungsdaten werden vom Betreiber bereitgestellt.")
        if not pem or len(pem) > 24_000:
            raise BankingError("Wähle eine gültige PEM-Datei aus.")
        if self.consents():
            raise BankingError("Trenne zuerst die aktiven Bankverbindungen.")
        client = self.client_factory(application_id, pem)
        self.verify_application(client, pem)
        with closing(self.connect()) as db, db:
            db.execute("DELETE FROM pending")
            if db.execute("SELECT 1 FROM consents LIMIT 1").fetchone():
                raise BankingError("Trenne zuerst die aktiven Bankverbindungen.")
            db.execute("INSERT OR REPLACE INTO credentials VALUES (1, ?, ?)",
                       (client.application_id, pem))

    def banks(self, country):
        if not re.fullmatch("[A-Z]{2}", country):
            raise BankingError("Gib einen zweistelligen Ländercode ein.")
        response = self.client().request("GET", "/aspsps", query={"country": country, "service": "AIS"})
        banks = response.get("aspsps")
        if not isinstance(banks, list):
            raise BankingError("Enable Banking lieferte keine gültige Bankliste.")
        return sorted(
            (bank for bank in banks if isinstance(bank, dict) and isinstance(bank.get("name"), str)),
            key=lambda bank: bank["name"].casefold(),
        )

    def begin(self, login, country, name, psu_type):
        banks = self.banks(country)
        bank = next((bank for bank in banks if bank["name"] == name), None)
        if not bank or psu_type not in {"personal", "business"} or psu_type not in (bank.get("psu_types") or []):
            raise BankingError("Wähle eine Bank und die passende Kontoart.")
        try:
            seconds = min(int(bank["maximum_consent_validity"]), 180 * 86400)
            if seconds <= 0:
                raise ValueError
        except (TypeError, ValueError, KeyError) as exc:
            raise BankingError("Diese Bank bietet derzeit keine gültige Zugriffsfrist.") from exc
        now = utc_now()
        valid_until = (now + timedelta(seconds=seconds)).isoformat()
        state = secrets.token_urlsafe(32)
        response = self.client().request("POST", "/auth", data={
            "access": {"valid_until": valid_until}, "aspsp": {"name": name, "country": country},
            "state": state, "redirect_url": self.callback, "psu_type": psu_type, "language": "de",
        })
        url = response.get("url")
        parsed = urlsplit(url or "")
        if parsed.scheme != "https" or parsed.netloc != "auth.enablebanking.com":
            raise BankingError("Enable Banking lieferte keine gültige Freigabeadresse.")
        with closing(self.connect()) as db, db:
            db.execute("DELETE FROM pending WHERE expires < ? OR login = ?", (int(now.timestamp()), login))
            db.execute("INSERT INTO pending VALUES (?, ?, ?, ?, ?, ?, ?)",
                       (digest(state), login, int(now.timestamp()) + 900, country, name, psu_type, valid_until))
        return url

    def finish(self, login, state, code, error):
        if not state or len(state) != 43 or len(code) > 2048:
            raise BankingError("Die Bankfreigabe konnte nicht zugeordnet werden. Starte sie erneut.")
        with closing(self.connect()) as db, db:
            pending = db.execute(
                "DELETE FROM pending WHERE state = ? AND login = ? AND expires >= ? RETURNING *",
                (digest(state), login, int(utc_now().timestamp())),
            ).fetchone()
        if not pending:
            raise BankingError("Die Bankfreigabe konnte nicht zugeordnet werden. Starte sie erneut.")
        if error or not code:
            raise BankingError("Die Bankfreigabe wurde abgebrochen oder ist fehlgeschlagen.")
        client = self.client()
        authorized = client.request("POST", "/sessions", data={"code": code})
        try:
            session_id = str(UUID(authorized["session_id"]))
            accounts = []
            for account in authorized["accounts"]:
                try:
                    uid = str(UUID(account["uid"]))
                except (KeyError, TypeError, ValueError, AttributeError):
                    continue
                iban = (account.get("account_id") or {}).get("iban")
                stable = iban or account.get("identification_hash") or uid
                accounts.append({"uid": uid, "key": fingerprint(stable),
                                 "label": (account.get("name") or account.get("product") or "Konto"),
                                 "suffix": iban[-4:] if iban else None})
            valid_until = (authorized.get("access") or {}).get("valid_until") or pending["valid_until"]
            datetime.fromisoformat(valid_until)
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise BankingError("Enable Banking lieferte keine gültige Bankverbindung.") from exc
        if not accounts:
            raise BankingError("Die Bank hat keine Konten freigegeben.")
        with closing(self.connect()) as db, db:
            previous = db.execute(
                "SELECT id FROM consents WHERE bank = ? AND country = ? AND psu_type = ?",
                (pending["bank"], pending["country"], pending["psu_type"]),
            ).fetchone()
            db.execute(
                "INSERT OR REPLACE INTO consents "
                "(id, bank, country, psu_type, valid_until, accounts) VALUES (?, ?, ?, ?, ?, ?)",
                (session_id, pending["bank"], pending["country"], pending["psu_type"],
                 valid_until, json.dumps(accounts)),
            )
        if previous and previous["id"] != session_id:
            try:
                client.request("DELETE", "/sessions/" + quote(previous["id"], safe=""))
            except BankingError:
                # The newly authorized session remains usable when the bank has already closed the old one.
                pass
        self.wake.set()

    def consents(self):
        with closing(self.connect()) as db:
            rows = db.execute("SELECT * FROM consents ORDER BY country, bank, psu_type").fetchall()
        return [dict(row) | {"accounts": json.loads(row["accounts"])} for row in rows]

    def disconnect(self, session_id):
        with closing(self.connect()) as db:
            present = db.execute("SELECT 1 FROM consents WHERE id = ?", (session_id,)).fetchone()
        if not present:
            raise BankingError("Diese Bankverbindung wurde nicht gefunden.")
        try:
            self.client().request("DELETE", "/sessions/" + quote(session_id, safe=""))
        except BankingError as exc:
            if exc.status not in {404, 410}:
                raise
        with closing(self.connect()) as db, db:
            db.execute("DELETE FROM consents WHERE id = ?", (session_id,))

    def sync(self, *, force=False, now=None):
        now = now or utc_now()
        with self.sync_lock:
            return self._sync_due(force, now)

    def _sync_due(self, force, now):
        if not core.config_exists():
            return 0
        count = 0
        for consent in self.consents():
            expires = datetime.fromisoformat(consent["valid_until"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
            today = now.date().isoformat()
            if expires <= now:
                self._record(consent["id"], now, "Die Bankfreigabe ist abgelaufen. Verbinde das Konto erneut.")
                continue
            last_sync = consent["last_synced"]
            if not force and (last_sync == today or int(now.timestamp()) - (consent["last_attempt"] or 0) < 3600):
                continue
            # Carry forward a gap after downtime, with overlap for late bookings.
            start = (datetime.fromisoformat(last_sync).date() - timedelta(days=14)).isoformat() if last_sync else None
            try:
                client = self.client()
                rows = []
                skipped = 0
                for account in consent["accounts"]:
                    items, dropped = transaction_rows(account["key"], client.transactions(
                        account["uid"], start, today,
                    ))
                    rows.extend(items)
                    skipped += dropped
                with closing(self.connect()) as state:
                    if not state.execute("SELECT 1 FROM consents WHERE id = ?", (consent["id"],)).fetchone():
                        continue
                with closing(core.db()) as ledger:
                    result = core.import_bank_rows(ledger, rows, auto_match=False, require_fx=True)
                imported, deferred = result["imported"], result["deferred"]
                message = f"{imported} neue Umsätze importiert."
                if deferred:
                    message += f" Für {deferred} weitere Umsätze fehlen Wechselkurse. Der Abruf wird wiederholt."
                self._record(consent["id"], now, message, done=not (skipped or deferred), skipped=skipped)
                count += imported
            except BankingError as exc:
                self._record(consent["id"], now, str(exc))
        return count

    def _record(self, session_id, now, message, *, done=False, skipped=0):
        with closing(self.connect()) as db, db:
            db.execute(
                """UPDATE consents SET last_attempt = ?, message = ?, skipped = ?,
                   last_synced = COALESCE(?, last_synced) WHERE id = ?""",
                (int(now.timestamp()), message, skipped, now.date().isoformat() if done else None, session_id),
            )

    def request_sync(self):
        with self.queue_lock:
            self.force = True
            self.wake.set()

    def start_worker(self, logger):
        def run():
            while True:
                with self.queue_lock:
                    self.wake.clear()
                    force = self.force
                    self.force = False
                try:
                    self.sync(force=force)
                except Exception:
                    logger.exception("Hosted bank synchronization failed")
                self.wake.wait(900)
        Thread(target=run, name="enable-banking", daemon=True).start()
