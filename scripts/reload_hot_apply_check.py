import json
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional, Tuple
from urllib import request


def encode_varint(value: int) -> bytes:
    out = bytearray()
    value &= 0xFFFFFFFF
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def decode_varint(data: bytes, start: int = 0) -> Tuple[int, int]:
    num_read = 0
    result = 0
    while True:
        if start + num_read >= len(data):
            raise ValueError("incomplete varint")
        byte = data[start + num_read]
        result |= (byte & 0x7F) << (7 * num_read)
        num_read += 1
        if num_read > 5:
            raise ValueError("varint too big")
        if (byte & 0x80) == 0:
            break
    return result, num_read


def recv_exact(sock: socket.socket, n: int) -> bytes:
    chunks = []
    rem = n
    while rem > 0:
        chunk = sock.recv(rem)
        if not chunk:
            raise ConnectionError("socket closed")
        chunks.append(chunk)
        rem -= len(chunk)
    return b"".join(chunks)


def recv_packet(sock: socket.socket) -> bytes:
    head = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("socket closed before header")
        head.extend(b)
        if not (b[0] & 0x80):
            break
    plen, _ = decode_varint(bytes(head))
    return recv_exact(sock, plen)


def build_login_handshake(protocol_id: int, host: str, port: int) -> bytes:
    host_bytes = host.encode("utf-8")
    payload = (
        encode_varint(0)
        + encode_varint(protocol_id)
        + encode_varint(len(host_bytes))
        + host_bytes
        + struct.pack(">H", port)
        + encode_varint(2)
    )
    return encode_varint(len(payload)) + payload


def build_status_handshake(protocol_id: int, host: str, port: int) -> bytes:
    host_bytes = host.encode("utf-8")
    payload = (
        encode_varint(0)
        + encode_varint(protocol_id)
        + encode_varint(len(host_bytes))
        + host_bytes
        + struct.pack(">H", port)
        + encode_varint(1)
    )
    return encode_varint(len(payload)) + payload


def build_login_start(username: str) -> bytes:
    username_bytes = username.encode("utf-8")
    payload = encode_varint(0) + encode_varint(len(username_bytes)) + username_bytes
    return encode_varint(len(payload)) + payload


def parse_disconnect_text(packet: bytes) -> str:
    packet_id, read = decode_varint(packet, 0)
    if packet_id != 0:
        return f"<unexpected packet id={packet_id}>"
    strlen, sread = decode_varint(packet, read)
    start = read + sread
    body = packet[start : start + strlen].decode("utf-8")
    parsed = json.loads(body)
    return parsed.get("text", body)


def test_login_disconnect(host: str, port: int, protocol_id: int = 762) -> str:
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(8)
        sock.sendall(build_login_handshake(protocol_id, "localhost", port))
        sock.sendall(build_login_start("reload-check"))
        packet = recv_packet(sock)
        return parse_disconnect_text(packet)


def load_key_values(path: Path) -> dict:
    values = {}
    section = None
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            continue
        if section in ("listener", "admin") and "=" in stripped:
            k, v = stripped.split("=", 1)
            values[f"{section}.{k.strip()}"] = v.strip().strip('"')
    return values


def start_proxy(repo: Path, host: str, port: int) -> subprocess.Popen:
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet"],
        cwd=repo,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("proxy exited during startup")
        try:
            with socket.create_connection((host, port), timeout=0.2):
                return proc
        except OSError:
            time.sleep(0.2)
    proc.terminate()
    raise TimeoutError("proxy failed to start")


def post_reload(admin_bind: str, token: str) -> str:
    req = request.Request(
        f"http://{admin_bind}/reload",
        method="POST",
        headers={"x-admin-token": token},
        data=b"",
    )
    with request.urlopen(req, timeout=3) as resp:
        return resp.read().decode("utf-8")


def post_shutdown(admin_bind: str, token: str) -> None:
    req = request.Request(
        f"http://{admin_bind}/shutdown",
        method="POST",
        headers={"x-admin-token": token},
        data=b"",
    )
    try:
        request.urlopen(req, timeout=2).read()
    except Exception:
        pass


def main() -> int:
    repo = Path(__file__).resolve().parent.parent
    cfg = load_key_values(repo / "vex.toml")
    listener = cfg["listener.bind"]
    admin_bind = cfg["admin.bind"]
    token = cfg["admin.auth_token"]

    host, port_s = listener.rsplit(":", 1)
    host = "127.0.0.1" if host == "0.0.0.0" else host
    port = int(port_s)

    protocol_path = repo / "config" / "protocol_ids.toml"
    vex_path = repo / "vex.toml"
    original_protocol = protocol_path.read_text(encoding="utf-8")
    original_vex = vex_path.read_text(encoding="utf-8")

    proc = start_proxy(repo, host, port)
    try:
        before = test_login_disconnect(host, port, 762)
        print(f"[before-reload] {before}")
        if "Unsupported protocol 762" not in before:
            print("[error] expected unsupported protocol before reload")
            return 1

        modified = original_protocol.replace(
            "supported_ids = [763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774]",
            "supported_ids = [762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774]",
        )
        if '"1.19.4" = 762' not in modified:
            modified += '\n"1.19.4" = 762\n'
        protocol_path.write_text(modified, encoding="utf-8")

        vex_modified = original_vex.replace(
            'address = "127.0.0.1:25565"',
            'address = "127.0.0.1:1"',
            1,
        )
        vex_path.write_text(vex_modified, encoding="utf-8")

        reload_resp = post_reload(admin_bind, token)
        print(f"[reload] {reload_resp}")

        after = test_login_disconnect(host, port, 762)
        print(f"[after-reload] {after}")
        if "Unsupported protocol 762" in after:
            print("[error] reload did not apply protocol map")
            return 1
        if "backend" not in after.lower():
            print("[error] unexpected post-reload disconnect message")
            return 1

        print("[summary] hot reload apply verified")
        return 0
    finally:
        protocol_path.write_text(original_protocol, encoding="utf-8")
        vex_path.write_text(original_vex, encoding="utf-8")
        try:
            post_reload(admin_bind, token)
        except Exception:
            pass
        post_shutdown(admin_bind, token)
        try:
            proc.wait(timeout=25)
        except subprocess.TimeoutExpired:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()


if __name__ == "__main__":
    sys.exit(main())
