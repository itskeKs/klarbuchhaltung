"""Shared hosted request settings and credential format."""
import hashlib
import os
from pathlib import Path
from urllib.parse import urlsplit

TENANTS = ("tenant-a", "tenant-b")
LOGIN_COOKIE = "__Host-klar-auth"
INTERNAL_GATEWAY_HEADER = "X-Klar-Gateway"
INTERNAL_LOGIN_HEADER = "X-Klar-Login"
CSRF_HEADER = "X-Klar-CSRF"
MAX_UPLOAD = 25 * 1024 * 1024
SECRET_DIR = Path("/run/klar")


def origin():
    value = os.environ["KLAR_PUBLIC_ORIGIN"]
    url = urlsplit(value)
    if url.scheme != "https" or not url.hostname or value != f"https://{url.netloc}":
        raise ValueError("KLAR_PUBLIC_ORIGIN must be an HTTPS origin without a path")
    if url.username is not None or url.password is not None:
        raise ValueError("KLAR_PUBLIC_ORIGIN cannot contain credentials")
    return value


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def csrf_for(login_id):
    return digest("klar-csrf:" + login_id)


def tenant_cookie(tenant):
    return "__Host-klar-" + tenant


def password_hash(password, salt):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=32768, r=8,
                          p=1, maxmem=64 * 1024 * 1024).hex()
