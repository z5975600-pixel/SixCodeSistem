#!/usr/bin/env python3
import os
import sys
import json
import socket
import struct
import hashlib
import argparse
from pathlib import Path

# ---------- Фрейминг ----------
def send_frame(conn: socket.socket, payload: bytes):
    conn.sendall(struct.pack(">I", len(payload)) + payload)

def recv_exact(conn: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = conn.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("Connection closed")
        buf.extend(chunk)
    return bytes(buf)

def recv_frame(conn: socket.socket) -> bytes:
    hdr = recv_exact(conn, 4)
    (length,) = struct.unpack(">I", hdr)
    if length > 1_000_000_000:
        raise ValueError("Frame too large")
    return recv_exact(conn, length)

def send_json(conn: socket.socket, obj: dict):
    send_frame(conn, json.dumps(obj, ensure_ascii=False).encode("utf-8"))

def recv_json(conn: socket.socket) -> dict:
    data = recv_frame(conn)
    return json.loads(data.decode("utf-8"))

def human_size(n: int) -> str:
    units = ["B","KB","MB","GB","TB"]
    i = 0
    f = float(n)
    while f >= 1024 and i < len(units)-1:
        f /= 1024
        i += 1
    return f"{f:.2f} {units[i]}"

# ---------- Клиент ----------
def main():
    ap = argparse.ArgumentParser(description="SixCodeSistem client (text)")
    ap.add_argument("host", help="server IP/host")
    ap.add_argument("code", help="6-digit access code")
    ap.add_argument("--port", type=int, default=5000)
    args = ap.parse_args()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((args.host, args.port))
        # AUTH
        send_json(s, {"op": "AUTH", "code": args.code})
        resp = recv_json(s)
        if not resp.get("ok"):
            print("Auth failed:", resp.get("err"))
            return
        print("Auth OK. Type HELP for commands.")

        while True:
            try:
                line = input("> ").strip()
            except (EOFError, KeyboardInterrupt):
                line = "QUIT"
                print()
            if not line:
                continue
            parts = line.split()
            cmd = parts[0].upper()

            # Простые команды
            if cmd in {"HELP", "PWD"} and len(parts) == 1:
                send_json(s, {"op": cmd})
                print_response(recv_json(s))
                continue

            if cmd == "LS":
                path = parts[1] if len(parts) > 1 else None
                send_json(s, {"op": "LS", "path": path})
                resp = recv_json(s)
                if not resp.get("ok"):
                    print("Error:", resp.get("err"))
                else:
                    for it in resp["items"]:
                        typ = "<DIR>" if it["type"] == "dir" else "     "
                        size = "" if it["type"] == "dir" else human_size(it["size"])
                        print(f"{typ:5} {it['name']} {size}")
                continue

            if cmd == "CD" and len(parts) >= 2:
                send_json(s, {"op": "CD", "path": " ".join(parts[1:])})
                print_response(recv_json(s))
                continue

            if cmd == "MKDIR" and len(parts) >= 2:
                send_json(s, {"op": "MKDIR", "path": " ".join(parts[1:])})
                print_response(recv_json(s))
                continue

            if cmd == "RM" and len(parts) >= 2:
                send_json(s, {"op": "RM", "path": " ".join(parts[1:])})
                print_response(recv_json(s))
                continue

            if cmd == "RMDIR" and len(parts) >= 2:
                send_json(s, {"op": "RMDIR", "path": " ".join(parts[1:])})
                print_response(recv_json(s))
                continue

            if cmd == "TREE":
                depth = int(parts[1]) if len(parts) > 1 else 2
                send_json(s, {"op": "TREE", "depth": depth})
                resp = recv_json(s)
                if not resp.get("ok"):
                    print("Error:", resp.get("err"))
                else:
                    print_tree(resp["tree"])
                continue

            if cmd == "GET" and len(parts) >= 2:
                remote = " ".join(parts[1:])
                send_json(s, {"op": "GET", "path": remote})
                meta = recv_json(s)
                if not meta.get("ok"):
                    print("Error:", meta.get("err"))
                    continue
                size = meta["size"]
                digest = meta["sha256"]
                print(f"Downloading {remote} ({human_size(size)}) ...")
                send_json(s, {"ok": True})  # готов принимать
                received = 0
                h = hashlib.sha256()
                local = Path(remote).name  # сохраняем под именем файла
                with open(local, "wb") as f:
                    while received < size:
                        chunk = recv_frame(s)
                        f.write(chunk)
                        h.update(chunk)
                        received += len(chunk)
                if h.hexdigest() != digest:
                    print("ERROR: hash mismatch (file corrupted)")
                    try: os.remove(local)
                    except Exception: pass
                else:
                    print(f"Saved to {local}")
                continue

            if cmd == "PUT" and len(parts) >= 2:
                local_path = Path(parts[1]).expanduser()
                if not local_path.exists() or not local_path.is_file():
                    print("No such local file")
                    continue
                remote_path = parts[2] if len(parts) >= 3 else local_path.name
                size = local_path.stat().st_size
                h = hashlib.sha256()
                with local_path.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                send_json(s, {"op": "PUT", "path": remote_path, "size": size, "sha256": h.hexdigest()})
                resp = recv_json(s)
                if not resp.get("ok"):
                    print("Error:", resp.get("err"))
                    continue
                print(f"Uploading {local_path} ({human_size(size)}) ...")
                with local_path.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        send_frame(s, chunk)
                done = recv_json(s)
                if done.get("ok"):
                    print("Upload OK")
                else:
                    print("Upload failed:", done.get("err"))
                continue

            if cmd == "QUIT":
                send_json(s, {"op": "QUIT"})
                try:
                    print_response(recv_json(s))
                except Exception:
                    pass
                break

            print("Unknown/invalid command. Type HELP.")

def print_response(resp: dict):
    if resp.get("ok"):
        if "data" in resp:
            print(resp["data"])
        elif "cwd" in resp:
            print("CWD:", resp["cwd"])
        elif "msg" in resp:
            print(resp["msg"])
        else:
            print("OK")
    else:
        print("Error:", resp.get("err"))

def print_tree(tree, prefix=""):
    for i, node in enumerate(tree):
        last = i == len(tree) - 1
        branch = "└── " if last else "├── "
        print(prefix + branch + node["name"] + ("/" if node["type"] == "dir" else ""))
        if node.get("children"):
            print_tree(node["children"], prefix + ("    " if last else "│   "))

if __name__ == "__main__":
    main()
