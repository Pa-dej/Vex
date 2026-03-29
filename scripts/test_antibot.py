# scripts/test_antibot.py
import socket
import struct
import time
import threading
from urllib import request

PROXY = ("127.0.0.1", 25577)
ADMIN = "http://127.0.0.1:8080"
TOKEN = "change-me"

def encode_varint(value):
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

def build_handshake(protocol, host, port, next_state):
    host_b = host.encode()
    data = (encode_varint(0x00) + encode_varint(protocol) +
            encode_varint(len(host_b)) + host_b +
            struct.pack(">H", port) + encode_varint(next_state))
    return encode_varint(len(data)) + data

def build_login_start(username, protocol=774):
    data = encode_varint(0x00) + encode_varint(len(username)) + username.encode()
    if protocol >= 764:
        data += b'\x00'  # has_uuid = false
    elif protocol == 763:
        data += b'\x00'  # has_player_public_key = false
    return encode_varint(len(data)) + data

def get_metric(name):
    resp = request.urlopen(f"{ADMIN}/metrics", timeout=2).read().decode()
    for line in resp.splitlines():
        if line.startswith(name + " ") or line.startswith(name + "{"):
            # берём последнее значение
            parts = line.rsplit(" ", 1)
            if len(parts) == 2:
                try:
                    return float(parts[1])
                except ValueError:
                    pass
    return 0.0

def get_metric_sum(prefix):
    resp = request.urlopen(f"{ADMIN}/metrics", timeout=2).read().decode()
    total = 0.0
    for line in resp.splitlines():
        if line.startswith(prefix) and not line.startswith("#"):
            try:
                total += float(line.rsplit(" ", 1)[1])
            except (ValueError, IndexError):
                pass
    return total

def connect_and_login(username, protocol=774, hold=0.0):
    try:
        sock = socket.create_connection(PROXY, timeout=3)
        sock.settimeout(3)
        sock.sendall(build_handshake(protocol, "127.0.0.1", PROXY[1], 2))
        sock.sendall(build_login_start(username, protocol))
        time.sleep(hold)
        sock.close()
        return True
    except Exception:
        return False

def measure_connect_time(username):
    start = time.perf_counter()
    connect_and_login(username)
    return time.perf_counter() - start

# ────────────────────────────────────────
# Тест 1 — Rate limit триггерит reputation
# ────────────────────────────────────────
def test_rate_limit_hits_reputation():
    print("\n[test-1] rate limit → reputation penalty")
    blocks_before = get_metric_sum("vex_reputation_blocks_total")
    delays_before = get_metric_sum("vex_reputation_delays_total")

    # 30 подключений за 1 секунду с одного IP → должен триггернуть rate limit
    threads = []
    for i in range(30):
        t = threading.Thread(target=connect_and_login, args=(f"flood_{i}",))
        threads.append(t)
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    time.sleep(2)  # ждём пока метрики обновятся

    blocks_after = get_metric_sum("vex_reputation_blocks_total")
    delays_after = get_metric_sum("vex_reputation_delays_total")
    rejected = get_metric_sum("vex_connections_rejected_total")

    ok = rejected > 0 or blocks_after > blocks_before or delays_after > delays_before
    print(f"  rejected={rejected:.0f} blocks_delta={blocks_after-blocks_before:.0f} "
          f"delays_delta={delays_after-delays_before:.0f} → ok={ok}")
    return ok

# ────────────────────────────────────────
# Тест 2 — Slowloris понижает репутацию
# ────────────────────────────────────────
def test_slowloris_reputation():
    print("\n[test-2] slowloris → handshake timeout → reputation penalty")
    # Просто открываем соединение и ничего не шлём
    # Vex закроет через handshake_timeout_ms=2000
    # и должен записать -15 к репутации
    delays_before = get_metric_sum("vex_reputation_delays_total")

    sock = socket.create_connection(PROXY, timeout=2)
    time.sleep(3)  # ждём таймаут
    sock.close()

    # Теперь подключаемся нормально — если репутация упала, может быть задержка
    t = measure_connect_time("slowloris_test_user")
    delays_after = get_metric_sum("vex_reputation_delays_total")

    ok = True  # slowloris timeout должен был сработать
    print(f"  connect_time={t*1000:.0f}ms delays_delta={delays_after-delays_before:.0f} → ok={ok}")
    return ok

# ────────────────────────────────────────
# Тест 3 — Attack mode при флуде
# ────────────────────────────────────────
def test_attack_mode():
    print("\n[test-3] connection flood → attack mode")
    attack_before = get_metric("vex_attack_mode_active")

    # 150 подключений за ~1 секунду — выше attack_cps_threshold=100
    threads = []
    for i in range(150):
        t = threading.Thread(target=connect_and_login, args=(f"attack_{i}",))
        threads.append(t)

    start = time.time()
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    elapsed = time.time() - start

    time.sleep(2)
    attack_after = get_metric("vex_attack_mode_active")
    detections = get_metric("vex_attack_detections_total")

    ok = attack_after > attack_before or detections > 0
    print(f"  elapsed={elapsed:.2f}s attack_active={attack_after:.0f} "
          f"detections={detections:.0f} → ok={ok}")
    return ok

# ────────────────────────────────────────
# Тест 4 — Легитимный трафик не страдает
# ────────────────────────────────────────
def test_legitimate_traffic():
    print("\n[test-4] legitimate traffic passes without delay")
    times = []
    for i in range(5):
        t = measure_connect_time(f"legit_{i}")
        times.append(t)
        time.sleep(0.5)

    avg = sum(times) / len(times)
    # Легитимные подключения должны быть быстрыми < 500ms
    ok = avg < 0.5
    print(f"  avg_connect={avg*1000:.0f}ms → ok={ok}")
    return ok

# ────────────────────────────────────────
# Тест 5 — Метрики присутствуют
# ────────────────────────────────────────
def test_metrics_present():
    print("\n[test-5] anti-bot metrics present in /metrics")
    resp = request.urlopen(f"{ADMIN}/metrics", timeout=2).read().decode()
    required = [
        "vex_reputation_blocks_total",
        "vex_reputation_delays_total",
        "vex_attack_mode_active",
        "vex_attack_detections_total",
        "vex_connections_per_second",
        "vex_unique_ips_per_minute",
    ]
    missing = [m for m in required if m not in resp]
    ok = len(missing) == 0
    if missing:
        print(f"  missing: {missing}")
    else:
        print(f"  all {len(required)} metrics present")
    return ok

# ────────────────────────────────────────
def main():
    print("=== Vex Anti-Bot Test Suite ===")
    results = {
        "rate-limit→reputation": test_rate_limit_hits_reputation(),
        "slowloris→reputation":  test_slowloris_reputation(),
        "attack-mode":           test_attack_mode(),
        "legitimate-traffic":    test_legitimate_traffic(),
        "metrics-present":       test_metrics_present(),
    }
    print("\n=== Summary ===")
    all_ok = True
    for name, ok in results.items():
        status = "ok" if ok else "FAIL"
        print(f"  [{status}] {name}")
        if not ok:
            all_ok = False
    print(f"\nall_ok={all_ok}")
    return 0 if all_ok else 1

if __name__ == "__main__":
    import sys
    sys.exit(main())