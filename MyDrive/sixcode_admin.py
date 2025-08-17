#!/usr/bin/env python3
import json
import argparse
import os
import random
import string
import hashlib
from pathlib import Path

CODES_FILE = Path("codes.json")
PEPPER = os.environ.get("SIXCODE_PEPPER", "")

def sha256_hex(s: str) -> str:
    return hashlib.sha256((PEPPER + s).encode("utf-8")).hexdigest()

def load_codes():
    if not CODES_FILE.exists():
        return {}
    return json.loads(CODES_FILE.read_text(encoding="utf-8"))

def save_codes(codes):
    CODES_FILE.write_text(json.dumps(codes, indent=2, ensure_ascii=False), encoding="utf-8")

def generate_code():
    # строго 6 цифр
    return "".join(random.choices(string.digits, k=6))

def cmd_new(n: int):
    codes = load_codes()
    result = []
    for _ in range(n):
        code = generate_code()
        h = sha256_hex(code)
        # если вдруг коллизия — генерим снова
        while h in codes:
            code = generate_code()
            h = sha256_hex(code)
        codes[h] = True  # активен
        result.append(code)
    save_codes(codes)
    print("Generated codes:")
    for c in result:
        print(c)

def cmd_revoke(code: str):
    codes = load_codes()
    h = sha256_hex(code)
    if h in codes and codes[h] is True:
        codes[h] = False
        save_codes(codes)
        print("Revoked.")
    else:
        print("Not found or already revoked.")

def cmd_list():
    codes = load_codes()
    alive = sum(1 for v in codes.values() if v is True)
    total = len(codes)
    print(f"Total: {total}, active: {alive}, revoked: {total - alive}")
    # Показать только первые 6 символов хэша — не секреты
    for h, v in list(codes.items())[:50]:
        print(h[:6], "ACTIVE" if v else "REVOKED")

if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="SixCodeSistem admin")
    sub = ap.add_subparsers(dest="cmd", required=True)
    g1 = sub.add_parser("new", help="generate N new codes")
    g1.add_argument("n", type=int)
    g2 = sub.add_parser("revoke", help="revoke a code")
    g2.add_argument("code")
    g3 = sub.add_parser("list", help="list stats")
    args = ap.parse_args()

    if args.cmd == "new":
        cmd_new(args.n)
    elif args.cmd == "revoke":
        cmd_revoke(args.code)
    elif args.cmd == "list":
        cmd_list()
