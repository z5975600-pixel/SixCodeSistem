#!/usr/bin/env python3
import os
import json
import socket
import threading
import hashlib
import struct
import argparse
from pathlib import Path
from datetime import datetime

# ----------------- НАСТРОЙКИ -----------------
HOST = "0.0.0.0"
PORT = 5000
STORAGE_ROOT = Path("storage").resolve()  # корень песочницы
CODES_FILE = Path("codes.json")           # хэши кодов и их статусы
LOG_FILE = Path("server.log")             # простой лог
PEPPER = os.environ.get("SIXCODE_PEPPER", "")  # опционально: общий секрет

# ----------------- УТИЛИТЫ -------------------
def log(msg: str):
    LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a", encoding="utf-8") as f:
        f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")
    print(msg)

def sha256_hex(s: str) -> str:
    return hashlib.sha256((PEPPER + s).encode("utf-8")).hexdigest()

def load_codes() -> dict:
    if not CODES_FILE.exists():
        return {}
    with CODES_FILE.open("r", encoding="utf-8") as f:
        return json.load(f)

def save_codes(codes: dict):
    with CODES_FILE.open("w", encoding="utf-8") as f:
        json.dump(codes, f, indent=2, ensure_ascii=False)

def ensure_storage_root():
    STORAGE_ROOT.mkdir(parents=True, exist_ok=True)

def safe_join(base: Path, *parts: str) -> Path:
    """Разрешить путь и убедиться, что он остаётся внутри base."""
    p = (base.joinpath(*parts)).resolve()
    if base not in p.parents and p != base:
        raise PermissionError("Path escapes storage root")
    return p

# Простейший фрейминг: 4 байта big-endian длина, затем payload (bytes)
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

# ----------------- КОМАНДЫ -------------------
def cmd_help():
    return {
        "ok": True,
        "data": (
            "Команды:\n"
            "  HELP\n"
            "  PWD\n"
            "  LS [path]\n"
            "  CD <path>\n"
            "  MKDIR <path>\n"
            "  RM <path>\n"
            "  RMDIR <path>\n"
            "  TREE [depth]\n"
            "  GET <path>\n"
            "  PUT <remote_path>\n"
            "  QUIT\n"
        )
    }

def list_dir(path: Path):
    items = []
    for entry in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        stat = entry.stat()
        items.append({
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
            "size": stat.st_size,
            "mtime": int(stat.st_mtime),
        })
    return items

def tree_dir(path: Path, depth: int, cur=0):
    if cur > depth:
        return []
    out = []
    for entry in sorted(path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower())):
        node = {
            "name": entry.name,
            "type": "dir" if entry.is_dir() else "file",
        }
        if entry.is_dir() and cur < depth:
            node["children"] = tree_dir(entry, depth, cur+1)
        out.append(node)
    return out

# ----------------- ОБРАБОТЧИК КЛИЕНТА --------
def handle_client(conn: socket.socket, addr):
    log(f"Connected {addr}")
    try:
        # 1) АВТОРИЗАЦИЯ
        req = recv_json(conn)
        if req.get("op") != "AUTH":
            send_json(conn, {"ok": False, "err": "AUTH required first"})
            return
        code = req.get("code", "")
        h = sha256_hex(code)
        codes = load_codes()
        if codes.get(h) is not True:
            send_json(conn, {"ok": False, "err": "Auth failed"})
            log(f"Auth failed from {addr}")
            return
        send_json(conn, {"ok": True, "msg": "Auth OK"})
        log(f"Auth OK {addr}")

        # Контекст сессии
        cwd = STORAGE_ROOT

        # 2) Основной цикл команд
        while True:
            try:
                msg = recv_json(conn)
            except ConnectionError:
                break

            op = msg.get("op")
            if op == "HELP":
                send_json(conn, cmd_help())

            elif op == "PWD":
                rel = str(cwd.relative_to(STORAGE_ROOT))
                send_json(conn, {"ok": True, "cwd": "/" + (rel if rel != "." else "")})

            elif op == "LS":
                path_arg = msg.get("path")
                target = safe_join(cwd if not path_arg else STORAGE_ROOT, *(path_arg.strip("/").split("/")) if path_arg else [])
                if not target.exists() or not target.is_dir():
                    send_json(conn, {"ok": False, "err": "No such directory"})
                else:
                    send_json(conn, {"ok": True, "items": list_dir(target)})

            elif op == "CD":
                path_arg = msg.get("path")
                if not path_arg:
                    send_json(conn, {"ok": False, "err": "Path required"})
                    continue
                target = safe_join(cwd, *path_arg.split("/"))
                if target.exists() and target.is_dir():
                    cwd = target
                    rel = str(cwd.relative_to(STORAGE_ROOT))
                    send_json(conn, {"ok": True, "cwd": "/" + (rel if rel != "." else "")})
                else:
                    send_json(conn, {"ok": False, "err": "No such directory"})

            elif op == "MKDIR":
                path_arg = msg.get("path")
                if not path_arg:
                    send_json(conn, {"ok": False, "err": "Path required"})
                    continue
                target = safe_join(cwd, *path_arg.split("/"))
                target.mkdir(parents=True, exist_ok=True)
                send_json(conn, {"ok": True})

            elif op == "RM":
                path_arg = msg.get("path")
                target = safe_join(cwd, *path_arg.split("/"))
                if target.exists() and target.is_file():
                    target.unlink()
                    send_json(conn, {"ok": True})
                else:
                    send_json(conn, {"ok": False, "err": "No such file"})

            elif op == "RMDIR":
                path_arg = msg.get("path")
                target = safe_join(cwd, *path_arg.split("/"))
                try:
                    target.rmdir()  # удалит только пустую папку
                    send_json(conn, {"ok": True})
                except Exception as e:
                    send_json(conn, {"ok": False, "err": f"Cannot remove dir: {e}"})

            elif op == "TREE":
                depth = int(msg.get("depth", 2))
                send_json(conn, {"ok": True, "tree": tree_dir(cwd, depth)})

            elif op == "GET":
                path_arg = msg.get("path")
                target = safe_join(cwd, *path_arg.split("/"))
                if not target.exists() or not target.is_file():
                    send_json(conn, {"ok": False, "err": "No such file"})
                    continue
                size = target.stat().st_size
                # сообщаем размер и хэш
                h = hashlib.sha256()
                with target.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        h.update(chunk)
                send_json(conn, {"ok": True, "size": size, "sha256": h.hexdigest()})
                # ждём подтверждение
                ack = recv_json(conn)
                if not ack.get("ok"):
                    continue
                # шлём файл
                with target.open("rb") as f:
                    for chunk in iter(lambda: f.read(1024 * 1024), b""):
                        send_frame(conn, chunk)

            elif op == "PUT":
                # ожидаем: path (куда сохранить), size, sha256
                path_arg = msg.get("path")
                size = int(msg.get("size", -1))
                digest = msg.get("sha256")
                if not path_arg or size < 0 or not digest:
                    send_json(conn, {"ok": False, "err": "path/size/sha256 required"})
                    continue
                target = safe_join(cwd, *path_arg.split("/"))
                target.parent.mkdir(parents=True, exist_ok=True)
                send_json(conn, {"ok": True, "msg": "ready"})
                received = 0
                h = hashlib.sha256()
                with target.open("wb") as f:
                    while received < size:
                        chunk = recv_frame(conn)
                        f.write(chunk)
                        h.update(chunk)
                        received += len(chunk)
                if h.hexdigest() != digest:
                    # испортилось — удаляем
                    try:
                        target.unlink()
                    except Exception:
                        pass
                    send_json(conn, {"ok": False, "err": "hash mismatch"})
                else:
                    send_json(conn, {"ok": True})

            elif op == "QUIT":
                send_json(conn, {"ok": True, "msg": "bye"})
                break

            else:
                send_json(conn, {"ok": False, "err": "Unknown command"})

    except Exception as e:
        log(f"Error {addr}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        log(f"Closed {addr}")

def serve():
    ensure_storage_root()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(100)
        log(f"Server listening on {HOST}:{PORT}, root={STORAGE_ROOT}")
        while True:
            conn, addr = s.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SixCodeSistem file server")
    parser.add_argument("--port", type=int, default=PORT)
    parser.add_argument("--root", type=str, default=str(STORAGE_ROOT))
    args = parser.parse_args()

    PORT = args.port
    STORAGE_ROOT = Path(args.root).resolve()
    serve()

