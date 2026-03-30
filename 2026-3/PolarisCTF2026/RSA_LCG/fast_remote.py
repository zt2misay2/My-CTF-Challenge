import ast
import os
import socket
import subprocess
import sys
import time


def parse_instance(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("N = "):
            values["N"] = int(line.split("=", 1)[1].strip())
        elif line.startswith("e = "):
            values["e"] = int(line.split("=", 1)[1].strip())
        elif line.startswith("[+] leak: "):
            leak = ast.literal_eval(line.split(": ", 1)[1])
            values["a"] = int(leak[0])
            values["L"] = int(leak[1])
        elif line.startswith("[+] Output 1: "):
            values["C1"] = int(line.split(": ", 1)[1].strip())
        elif line.startswith("[+] Output 2: "):
            values["C2"] = int(line.split(": ", 1)[1].strip())
    return values


def to_core_input(inst):
    order = ["N", "e", "a", "L", "C1", "C2"]
    return "".join(f"{k}=0x{inst[k]:x}\n" for k in order)


def run_core(inst):
    env = os.environ.copy()
    payload = to_core_input(inst)
    start = time.time()
    res = subprocess.run(
        ["./fast_core"],
        input=payload,
        text=True,
        capture_output=True,
        cwd=".",
        env=env,
        check=True,
    )
    elapsed = time.time() - start
    vals = {}
    for line in res.stdout.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            vals[k.strip()] = v.strip()
    vals["elapsed_s"] = elapsed
    return vals


def recv_until(sock, marker=b"secret (hex): "):
    data = b""
    while marker not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def run_remote(host, port):
    with socket.create_connection((host, port)) as sock:
        text = recv_until(sock).decode()
        print(text, end="")
        inst = parse_instance(text)
        vals = run_core(inst)
        print(
            {
                "core_elapsed_s": round(vals["elapsed_s"], 3),
                "gcd_x_degree": vals.get("gcd_x_degree"),
                "gcd_y_degree": vals.get("gcd_y_degree"),
            }
        )
        secret_hex = int(vals["s0"]).to_bytes(64, "big").hex()
        sock.sendall(secret_hex.encode() + b"\n")
        print(sock.recv(4096).decode(errors="replace"), end="")


def run_local():
    env = os.environ.copy()
    env["FLAG"] = "LOCAL_TEST_FLAG"
    cmd = [
        "python",
        "-c",
        (
            "import runpy, signal; "
            "signal.alarm = lambda *_args, **_kwargs: 0; "
            "runpy.run_path('task (27).py', run_name='__main__')"
        ),
    ]
    proc = subprocess.Popen(
        cmd,
        cwd=".",
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    text = ""
    while "secret (hex): " not in text:
        ch = proc.stdout.read(1)
        if ch == "":
            break
        text += ch
    print(text, end="")
    inst = parse_instance(text)
    vals = run_core(inst)
    print(
        {
            "core_elapsed_s": round(vals["elapsed_s"], 3),
            "gcd_x_degree": vals.get("gcd_x_degree"),
            "gcd_y_degree": vals.get("gcd_y_degree"),
        }
    )
    secret_hex = int(vals["s0"]).to_bytes(64, "big").hex()
    proc.stdin.write(secret_hex + "\n")
    proc.stdin.flush()
    print(proc.stdout.read(), end="")
    proc.wait()


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "local":
        run_local()
    else:
        host = "nc1.ctfplus.cn"
        port = 29902
        if len(sys.argv) == 3:
            host = sys.argv[1]
            port = int(sys.argv[2])
        run_remote(host, port)
