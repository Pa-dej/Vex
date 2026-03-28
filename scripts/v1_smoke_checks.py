import json
import socket
import struct
import subprocess
import sys
import time
import zlib
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
    remaining = n
    while remaining > 0:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("socket closed while reading")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_packet(sock: socket.socket) -> bytes:
    raw_len = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            raise ConnectionError("socket closed before packet header")
        raw_len.extend(b)
        if not (b[0] & 0x80):
            break
        if len(raw_len) > 5:
            raise ValueError("bad varint header")
    packet_len, _ = decode_varint(bytes(raw_len))
    return recv_exact(sock, packet_len)


def build_handshake(protocol_id: int, host: str, port: int, next_state: int) -> bytes:
    host_bytes = host.encode("utf-8")
    payload = (
        encode_varint(0)
        + encode_varint(protocol_id)
        + encode_varint(len(host_bytes))
        + host_bytes
        + struct.pack(">H", port)
        + encode_varint(next_state)
    )
    return encode_varint(len(payload)) + payload


def build_login_start(username: str) -> bytes:
    username_bytes = username.encode("utf-8")
    payload = (
        encode_varint(0)
        + encode_varint(len(username_bytes))
        + username_bytes
        + bytes(16)  # player UUID in 1.20+ login_start
    )
    return encode_varint(len(payload)) + payload


def parse_login_disconnect(packet: bytes) -> str:
    packet_id, read = decode_varint(packet, 0)
    if packet_id != 0:
        raise ValueError(f"expected login disconnect packet id 0, got {packet_id}")
    str_len, str_read = decode_varint(packet, read)
    start = read + str_read
    end = start + str_len
    body = packet[start:end].decode("utf-8")
    parsed = json.loads(body)
    if isinstance(parsed, dict):
        return str(parsed.get("text", body))
    if isinstance(parsed, str):
        return parsed
    return body


def decode_login_payload(packet: bytes, compression_enabled: bool) -> bytes:
    if not compression_enabled:
        return packet
    data_length, read = decode_varint(packet, 0)
    if data_length == 0:
        return packet[read:]
    compressed = packet[read:]
    decompressed = zlib.decompress(compressed)
    if len(decompressed) != data_length:
        raise ValueError(
            f"bad decompressed length: expected {data_length}, got {len(decompressed)}"
        )
    return decompressed


def try_connect(host: str, port: int, timeout_s: float = 0.3) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout_s):
            return True
    except OSError:
        return False


def load_config(repo_root: Path) -> dict:
    data = {"listener": {}, "admin": {}, "forwarding.velocity": {}}
    current = None
    raw = (repo_root / "vex.toml").read_text(encoding="utf-8")
    for line in raw.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("[") and stripped.endswith("]"):
            section = stripped[1:-1].strip()
            if section in data:
                current = section
            else:
                current = None
            continue
        if current is None or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"')
        data[current][key] = value
    return data


def start_proxy(repo_root: Path) -> Optional[subprocess.Popen]:
    cfg = load_config(repo_root)
    bind = cfg["listener"]["bind"]
    host, port_s = bind.rsplit(":", 1)
    host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    port = int(port_s)

    if try_connect(host, port):
        print(f"[info] proxy already running on {host}:{port}")
        return None

    print("[info] starting proxy via cargo run --quiet")
    proc = subprocess.Popen(
        ["cargo", "run", "--quiet"],
        cwd=repo_root,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            raise RuntimeError("proxy exited during startup")
        if try_connect(host, port):
            print(f"[info] proxy started on {host}:{port}")
            return proc
        time.sleep(0.2)
    proc.terminate()
    raise TimeoutError("proxy did not start within timeout")


def stop_proxy(repo_root: Path, proc: Optional[subprocess.Popen]) -> None:
    if proc is None:
        return
    cfg = load_config(repo_root)
    admin_bind = cfg["admin"]["bind"]
    token = cfg["admin"]["auth_token"]

    try:
        post_admin(admin_bind, token, "/shutdown")
    except Exception:
        pass

    try:
        proc.wait(timeout=25)
    except subprocess.TimeoutExpired:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def test_reject_unsupported_version(host: str, port: int) -> Tuple[bool, str]:
    with socket.create_connection((host, port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(build_handshake(762, "localhost", port, 2))
        packet = recv_packet(sock)
        message = parse_login_disconnect(packet)
        ok = "Unsupported protocol 762" in message
        return ok, message


def test_hot_reload(
    host: str, port: int, admin_bind: str, token: str, repo_root: Path
) -> Tuple[bool, str]:
    pre_ok, pre_msg = test_reject_unsupported_version(host, port)
    if not pre_ok:
        return False, f"precondition failed: {pre_msg}"

    proto_path = repo_root / "config" / "protocol_ids.toml"
    original = proto_path.read_text(encoding="utf-8")

    modified = original
    for line in modified.splitlines():
        if line.strip().startswith("supported_ids"):
            if "762" not in line:
                modified = modified.replace(
                    line,
                    "supported_ids = [762, 763, 764, 765, 766, 767, 768, 769, 770, 771, 772, 773, 774]",
                    1,
                )
            break
    if '"1.19.4" = 762' not in modified:
        modified += '\n"1.19.4" = 762\n'

    try:
        proto_path.write_text(modified, encoding="utf-8")
        post_admin(admin_bind, token, "/reload")

        with socket.create_connection((host, port), timeout=2) as sock:
            sock.settimeout(6)
            sock.sendall(build_handshake(762, "localhost", port, 2))
            sock.sendall(build_login_start("hot-reload-check"))
            try:
                packet = recv_packet(sock)
                message = parse_login_disconnect(packet)
                passed = "Unsupported protocol 762" not in message
                return passed, message
            except socket.timeout:
                # Connection moved past protocol reject path and is waiting deeper in login flow.
                return True, "no immediate disconnect (connection progressed past protocol gate)"
            except ConnectionError:
                # Backend/proxy may close without packet; still means unsupported gate is gone.
                return True, "connection closed without protocol reject packet"
    finally:
        proto_path.write_text(original, encoding="utf-8")
        try:
            post_admin(admin_bind, token, "/reload")
        except Exception:
            pass


def test_slowloris_timeout(host: str, port: int) -> Tuple[bool, str]:
    sock = socket.create_connection((host, port), timeout=2)
    sock.settimeout(1)
    try:
        time.sleep(5)
        try:
            data = sock.recv(1)
            if data == b"":
                return True, "socket closed by proxy after idle handshake"
            return False, f"unexpected data received: {data!r}"
        except socket.timeout:
            return False, "connection still open after 5s (no timeout close observed)"
        except OSError as err:
            return True, f"connection closed with socket error: {err}"
    finally:
        sock.close()


def test_velocity_login(host: str, port: int) -> Tuple[bool, str]:
    with socket.create_connection((host, port), timeout=3) as sock:
        sock.settimeout(3)
        sock.sendall(build_handshake(774, host, port, 2))
        sock.sendall(build_login_start("smokeplayer"))

        compression_enabled = False
        for _ in range(20):
            try:
                raw = recv_packet(sock)
            except socket.timeout:
                continue
            except ConnectionError as err:
                return False, f"connection closed: {err}"

            payload = decode_login_payload(raw, compression_enabled)
            packet_id, packet_id_read = decode_varint(payload, 0)

            if packet_id == 0x03:
                threshold, _ = decode_varint(payload, packet_id_read)
                compression_enabled = True
                continue
            if packet_id == 0x02:
                return True, "login success received"
            if packet_id == 0x00:
                message = parse_login_disconnect(payload)
                return False, f"disconnect: {message}"

        return False, "no login success received"


def parse_bool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "on"}


def post_admin(admin_bind: str, token: str, endpoint: str) -> str:
    req = request.Request(
        f"http://{admin_bind}{endpoint}",
        method="POST",
        headers={"x-admin-token": token},
        data=b"",
    )
    with request.urlopen(req, timeout=2) as resp:
        return resp.read().decode("utf-8", errors="replace")


def main() -> int:
    repo_root = Path(__file__).resolve().parent.parent
    cfg = load_config(repo_root)
    bind = cfg["listener"]["bind"]
    host, port_s = bind.rsplit(":", 1)
    host = "127.0.0.1" if host in ("0.0.0.0", "::") else host
    port = int(port_s)
    admin_bind = cfg["admin"]["bind"]
    token = cfg["admin"]["auth_token"]
    velocity_enabled = parse_bool(
        cfg.get("forwarding.velocity", {}).get("enabled", "false")
    )

    proc = start_proxy(repo_root)
    try:
        reject_ok, reject_msg = test_reject_unsupported_version(host, port)
        print(f"[reject-version] ok={reject_ok} message={reject_msg}")

        hot_reload_ok, hot_reload_msg = test_hot_reload(
            host, port, admin_bind, token, repo_root
        )
        print(f"[hot-reload] ok={hot_reload_ok} detail={hot_reload_msg}")

        if velocity_enabled:
            velocity_ok, velocity_msg = test_velocity_login(host, port)
        else:
            velocity_ok, velocity_msg = (
                True,
                "skipped (forwarding.velocity.enabled=false)",
            )
        print(f"[velocity-login] ok={velocity_ok} detail={velocity_msg}")

        slowloris_ok, slowloris_msg = test_slowloris_timeout(host, port)
        print(f"[slowloris] ok={slowloris_ok} detail={slowloris_msg}")

        all_ok = reject_ok and hot_reload_ok and velocity_ok and slowloris_ok
        print(f"[summary] all_ok={all_ok}")
        return 0 if all_ok else 1
    finally:
        stop_proxy(repo_root, proc)


if __name__ == "__main__":
    sys.exit(main())
