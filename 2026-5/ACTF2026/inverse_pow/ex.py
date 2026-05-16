from pwn import *
from advance_solver import attack_pow
import time

TEAM_NAME = ''
TEAM_TOKEN = ''
HOST = "1.95.44.158"
PORT = 11314

context.log_level = "debug"
io = remote(HOST, PORT)
io.sendlineafter(b"Team:", TEAM_NAME.encode())
io.sendlineafter(b"Token:", TEAM_TOKEN.encode())

for index in range(8):
    print(f"\n=== Round {index+1} / 8 ===")

    # Important: consume the actual ROUND line for this round.
    # The old script did not consume it, so timing/output labels were shifted.
    try:
        round_line = io.recvline_startswith(b"ROUND", timeout=5)
        print(round_line.decode(errors="ignore").strip())
    except EOFError:
        print("[-] EOF before ROUND")
        break

    try:
        m_line = io.recvline_startswith(b"m = ", timeout=5)
    except EOFError:
        print("[-] EOF before m")
        break
    m = int(m_line.split(b"m = ", 1)[1].strip())
    print(f"m={m}")

    t_solve0 = time.perf_counter()
    n = attack_pow(m)
    solve_dt = time.perf_counter() - t_solve0
    print(f"n={n} solve={solve_dt:.4f}s")

    io.recvuntil(b"n = ")
    t_verify0 = time.perf_counter()
    io.sendline(str(n).encode())

    # Measure from send(n) until server result for this same round.
    try:
        res = io.recvline(timeout=70)
    except EOFError:
        print("[-] EOF waiting result")
        break
    verify_dt = time.perf_counter() - t_verify0
    print(f"result={res.decode(errors='ignore').strip()} verify_wait={verify_dt:.2f}s")

    if b"Verified" not in res:
        print("[-] stop on non-Verified result")
        break

io.interactive()
