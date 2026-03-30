import hashlib
import socket
import shutil
import subprocess
import sys
import tempfile
import urllib.request
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parent
CHAL = ROOT / "chal (4).py"
FASTCOLL_DIR = ROOT / "fastcoll"
FASTCOLL_BIN = FASTCOLL_DIR / "fastcoll"
FASTCOLL_ZIP = "https://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip"
ROUNDS = 10


def md5(data: bytes) -> bytes:
    return hashlib.md5(data).digest()


def ensure_fastcoll() -> None:
    if FASTCOLL_BIN.exists():
        return

    if not FASTCOLL_DIR.exists():
        with urllib.request.urlopen(FASTCOLL_ZIP) as resp:
            archive = resp.read()
        with tempfile.NamedTemporaryFile(suffix=".zip") as tmp_zip:
            tmp_zip.write(archive)
            tmp_zip.flush()
            with zipfile.ZipFile(tmp_zip.name) as zf:
                FASTCOLL_DIR.mkdir()
                zf.extractall(FASTCOLL_DIR)

    makefile = FASTCOLL_DIR / "Makefile"
    makefile.write_text(
        "fastcoll:\n\tg++ -O3 -DBOOST_TIMER_ENABLE_DEPRECATED *.cpp "
        "-lboost_filesystem -lboost_program_options -o fastcoll\n",
        encoding="ascii",
    )
    subprocess.run(["make"], cwd=FASTCOLL_DIR, check=True)


def fastcoll_suffixes(prefix: bytes) -> tuple[bytes, bytes]:
    with tempfile.TemporaryDirectory() as td:
        td_path = Path(td)
        prefix_path = td_path / "prefix.bin"
        out0 = td_path / "msg0.bin"
        out1 = td_path / "msg1.bin"
        prefix_path.write_bytes(prefix)
        subprocess.run(
            [
                str(FASTCOLL_BIN),
                "-q",
                "-p",
                str(prefix_path),
                "-o",
                str(out0),
                str(out1),
            ],
            check=True,
            cwd=ROOT,
        )
        msg0 = out0.read_bytes()
        msg1 = out1.read_bytes()
    if not msg0.startswith(prefix) or not msg1.startswith(prefix):
        raise RuntimeError("fastcoll output does not preserve prefix")
    return msg0[len(prefix) :], msg1[len(prefix) :]


def unique_three_way(prefix: bytes, used: set[bytes]) -> tuple[bytes, bytes, bytes]:
    while True:
        s0, s1 = fastcoll_suffixes(prefix)
        t0, t1 = fastcoll_suffixes(prefix + s0)
        candidates = [s0 + t0, s0 + t1, s1 + t0, s1 + t1]
        full = [prefix + suffix for suffix in candidates]
        if len({md5(x) for x in full}) != 1:
            raise RuntimeError("constructed messages are not a multicollision")
        if len(set(candidates)) != 4:
            continue
        chosen = candidates[:3]
        if any(x in used for x in chosen):
            continue
        used.update(chosen)
        return tuple(chosen)


def generate_rounds() -> list[list[bytes]]:
    used: set[bytes] = set()
    rounds: list[list[bytes]] = []
    for idx in range(ROUNDS):
        print(f"[+] round {idx + 1}/{ROUNDS}: A/B/C", flush=True)
        a, b, c = unique_three_way(b"", used)
        h0 = md5(a)

        print(f"[+] round {idx + 1}/{ROUNDS}: D/E/F", flush=True)
        d, e, f = unique_three_way(h0, used)

        h1 = md5(h0 + d)
        print(f"[+] round {idx + 1}/{ROUNDS}: G/H/I", flush=True)
        g, h, i = unique_three_way(h1, used)

        rounds.append([a, b, c, d, e, f, g, h, i])
    return rounds


def run_local(rounds: list[list[bytes]]) -> str:
    temp_dir = None
    chal_path = CHAL
    if not (ROOT / "secret.py").exists():
        temp_dir = Path(tempfile.mkdtemp(prefix="truck-local-"))
        shutil.copy2(CHAL, temp_dir / CHAL.name)
        (temp_dir / "secret.py").write_text("flag = 'TEST_FLAG'\n", encoding="ascii")
        chal_path = temp_dir / CHAL.name

    try:
        proc = subprocess.Popen(
            [sys.executable, str(chal_path)],
            cwd=chal_path.parent,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        payload = "\n".join(item.hex() for round_items in rounds for item in round_items) + "\n"
        out, _ = proc.communicate(payload, timeout=180)
        if proc.returncode != 0:
            raise RuntimeError(out)
        return out
    finally:
        if temp_dir is not None:
            shutil.rmtree(temp_dir)


def recv_until(sock: socket.socket, marker: bytes) -> bytes:
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def run_remote(rounds: list[list[bytes]], host: str, port: int) -> str:
    with socket.create_connection((host, port), timeout=30) as sock:
        sock.settimeout(30)
        recv_until(sock, b"A > ")
        for idx, item in enumerate(x for round_items in rounds for x in round_items):
            sock.sendall(item.hex().encode() + b"\n")
            if idx != ROUNDS * 9 - 1:
                recv_until(sock, b"> ")
        output = b""
        while True:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            output += chunk
    return output.decode("latin1", "replace")


def main() -> None:
    ensure_fastcoll()
    rounds = generate_rounds()
    if len(sys.argv) == 3:
        output = run_remote(rounds, sys.argv[1], int(sys.argv[2]))
    else:
        output = run_local(rounds)
    print(output)


if __name__ == "__main__":
    main()
