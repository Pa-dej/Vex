import argparse
import re
import subprocess
import threading
import time


def mem_kb_for_process(image_name: str) -> int:
    try:
        out = subprocess.check_output(
            ["tasklist", "/fo", "csv", "/nh"], text=True, encoding="utf-8", errors="ignore"
        )
    except Exception:
        return 0
    for line in out.splitlines():
        if not line:
            continue
        parts = [p.strip().strip('"') for p in line.split('","')]
        if not parts or parts[0].lower() != image_name.lower():
            continue
        if len(parts) < 5:
            continue
        mem = parts[4]
        digits = re.sub(r"[^0-9]", "", mem)
        return int(digits) if digits else 0
    return 0


def stream_output(proc: subprocess.Popen) -> None:
    if proc.stdout is None:
        return
    for line in proc.stdout:
        print(line, end="")


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Vex bench with memory sampling")
    parser.add_argument("--bench", default=r"C:\Users\User\Desktop\probe\Vex\target\release\bench.exe")
    parser.add_argument("--target", default="127.0.0.1:25577")
    parser.add_argument("--handshake-host", default="127.0.0.1")
    parser.add_argument("--players", type=int, default=10000)
    parser.add_argument("--ramp-up-secs", type=int, default=30)
    parser.add_argument("--hold-secs", type=int, default=60)
    parser.add_argument("--protocol", type=int, default=774)
    parser.add_argument("--sample-interval", type=float, default=1.0)
    args = parser.parse_args()

    cmd = [
        args.bench,
        "--target",
        args.target,
        "--handshake-host",
        args.handshake_host,
        "--players",
        str(args.players),
        "--ramp-up-secs",
        str(args.ramp_up_secs),
        "--hold-secs",
        str(args.hold_secs),
        "--protocol",
        str(args.protocol),
    ]

    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    t = threading.Thread(target=stream_output, args=(proc,), daemon=True)
    t.start()

    peak_vex_kb = 0
    peak_backend_kb = 0
    sample_count = 0
    start = time.time()

    try:
        while proc.poll() is None:
            vex_kb = mem_kb_for_process("Vex.exe")
            back_kb = mem_kb_for_process("mock_backend.exe")
            peak_vex_kb = max(peak_vex_kb, vex_kb)
            peak_backend_kb = max(peak_backend_kb, back_kb)
            sample_count += 1
            time.sleep(args.sample_interval)
    finally:
        proc.wait()

    elapsed = time.time() - start
    print("")
    print("=== Memory Summary ===")
    print(f"samples: {sample_count} interval_s: {args.sample_interval} elapsed_s: {elapsed:.1f}")
    print(f"vex_peak_mb: {peak_vex_kb / 1024:.1f}")
    print(f"mock_backend_peak_mb: {peak_backend_kb / 1024:.1f}")
    if peak_vex_kb == 0:
        print("warning: Vex.exe not detected (is it running under a different name?)")
    if peak_backend_kb == 0:
        print("warning: mock_backend.exe not detected (is it running?)")
    return proc.returncode


if __name__ == "__main__":
    raise SystemExit(main())
