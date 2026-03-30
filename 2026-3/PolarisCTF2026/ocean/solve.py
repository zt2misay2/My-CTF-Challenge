import hashlib
import re
import socket
import subprocess
import sys
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


ROOT = Path(__file__).resolve().parent
SRC = ROOT / "solver.cpp"
BIN = ROOT / ("solver_cpp.exe" if sys.platform.startswith("win") else "solver_cpp")


def build_solver():
    if BIN.exists():
        return
    subprocess.run(
        ["g++", "-O3", "-std=c++20", str(SRC), "-lcrypto", "-o", str(BIN)],
        check=True,
        cwd=ROOT,
    )


def recv_until(sock, marker=b"> "):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def parse_instance(text):
    def grab(pattern):
        match = re.search(pattern, text)
        if not match:
            raise ValueError(f"missing pattern: {pattern}")
        return match.group(1)

    return {
        "n": 64,
        "mask1": int(grab(r"mask1 = (\d+)")),
        "mask2": int(grab(r"mask2 = (\d+)")),
        "output": int(grab(r"output = (\d+)")),
        "enc": grab(r"enc = ([0-9a-fA-F]+)"),
    }


def run_solver(instance):
    build_solver()
    payload = "\n".join(
        [
            str(instance["n"]),
            str(instance["mask1"]),
            str(instance["mask2"]),
            format(instance["output"], "064b"),
            instance["enc"],
            "6",
            "5",
            "7",
            "8192",
            "128",
        ]
    ) + "\n"
    result = subprocess.run(
        [str(BIN)],
        input=payload,
        text=True,
        capture_output=True,
        check=True,
        cwd=ROOT,
    )
    values = {}
    for line in result.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip()
    if values.get("status") != "ok":
        raise RuntimeError(result.stdout)
    return int(values["seed"])


def decrypt_secret(seed, enc_hex):
    key = hashlib.md5(str(seed).encode()).digest()
    plaintext = AES.new(key, AES.MODE_ECB).decrypt(bytes.fromhex(enc_hex))
    return unpad(plaintext, 16).decode()


def solve_remote(host, port):
    with socket.create_connection((host, port), timeout=20) as sock:
        banner = recv_until(sock).decode("utf-8", "ignore")
        print(banner, end="")
        instance = parse_instance(banner)
        seed = run_solver(instance)
        secret = decrypt_secret(seed, instance["enc"])
        print(f"[+] seed: {seed}")
        print(f"[+] secret: {secret}")
        sock.sendall(secret.encode() + b"\n")
        print(sock.recv(4096).decode("utf-8", "ignore"), end="")


def solve_from_text(text):
    instance = parse_instance(text)
    seed = run_solver(instance)
    secret = decrypt_secret(seed, instance["enc"])
    print(f"[+] seed: {seed}")
    print(f"[+] secret: {secret}")


def main():
    if len(sys.argv) == 3:
        solve_remote(sys.argv[1], int(sys.argv[2]))
        return
    if len(sys.argv) == 2:
        solve_from_text(Path(sys.argv[1]).read_text(encoding="utf-8"))
        return
    solve_from_text(sys.stdin.read())


if __name__ == "__main__":
    main()
