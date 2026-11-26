"""Provision the two hosted logins in a new secrets directory."""
import argparse
import json
from pathlib import Path
import secrets

from hosted.common import TENANTS, password_hash


def provision(directory, names):
    if len(names) != 2 or any(not (name.isascii() and name.isalnum() and len(name) <= 64) for name in names) or names[0].casefold() == names[1].casefold():
        raise ValueError("Provide two distinct alphanumeric usernames")
    directory.mkdir(mode=0o700)
    users = {}
    credentials = {}
    for tenant, name in zip(TENANTS, names):
        tenant_dir = directory / tenant
        tenant_dir.mkdir(mode=0o700)
        password = secrets.token_urlsafe(24)
        token = secrets.token_urlsafe(32)
        salt = secrets.token_bytes(16)
        with open(tenant_dir / "gateway-token", "x", opener=private_file) as file:
            file.write(token + "\n")
        users[name.casefold()] = {
            "display": name, "tenant": tenant, "token": token,
            "salt": salt.hex(), "hash": password_hash(password, salt),
        }
        credentials[name] = password
    with open(directory / "gateway.json", "x", opener=private_file) as file:
        json.dump(users, file)
    return credentials


def private_file(path, flags):
    import os
    return os.open(path, flags, 0o600)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("usernames", nargs=2)
    args = parser.parse_args()
    for username, password in provision(args.directory, args.usernames).items():
        print(f"{username}: {password}")
