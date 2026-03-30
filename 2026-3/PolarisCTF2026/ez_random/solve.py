import ast
import random
import re
import select
import socket
import sys
import time
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


HOST = "nc1.ctfplus.cn"
PORT = 24416
N = 2**31 - 1
ORDERED_INDICES = [18, 27, 31, 21, 15, 33, 23, 25, 28, 7, 34, 2, 35, 12, 1, 0, 6, 20, 3, 11, 8, 24, 4, 13, 17, 5, 30, 26, 22, 32, 14, 9, 29, 19, 10, 16]


def unshift_right(x, shift):
    result = x
    for _ in range(32):
        result = x ^ (result >> shift)
    return result & 0xFFFFFFFF


def unshift_left(x, shift, mask):
    result = x
    for _ in range(32):
        result = x ^ ((result << shift) & mask)
    return result & 0xFFFFFFFF


def untemper(value):
    value = unshift_right(value, 18)
    value = unshift_left(value, 15, 0xEFC60000)
    value = unshift_left(value, 7, 0x9D2C5680)
    value = unshift_right(value, 11)
    return value & 0xFFFFFFFF


def invert_step(si, si227):
    x = si ^ si227
    mti1 = (x & 0x80000000) >> 31
    if mti1:
        x ^= 0x9908B0DF
    x = (x << 1) & 0xFFFFFFFF
    mti = x & 0x80000000
    mti1 = (mti1 + (x & 0x7FFFFFFF)) & 0xFFFFFFFF
    return mti, mti1


def init_genrand(seed):
    mt = [0] * 624
    mt[0] = seed & 0xFFFFFFFF
    for i in range(1, 624):
        mt[i] = (0x6C078965 * (mt[i - 1] ^ (mt[i - 1] >> 30)) + i) & 0xFFFFFFFF
    return mt


def recover_kj_from_ji(ji, ji1, index):
    const = init_genrand(19650218)
    key = ji - (const[index] ^ ((ji1 ^ (ji1 >> 30)) * 1664525))
    return key & 0xFFFFFFFF


def recover_ji_from_ii(ii, ii1, index):
    ji = (ii + index) ^ ((ii1 ^ (ii1 >> 30)) * 1566083941)
    return ji & 0xFFFFFFFF


def get_limit(index):
    return 2 * N // 3 if index == 10 else N


def recv_until_markers(sock, markers, timeout=3.0):
    chunks = []
    deadline = time.time() + timeout
    while time.time() < deadline:
        remain = max(0.0, deadline - time.time())
        ready, _, _ = select.select([sock], [], [], remain)
        if not ready:
            break
        data = sock.recv(4096)
        if not data:
            break
        chunks.append(data)
        blob = b"".join(chunks)
        if any(marker in blob for marker in markers):
            return blob
    return b"".join(chunks)


def open_conn(host, port):
    sock = socket.create_connection((host, port), timeout=15)
    banner = recv_until_markers(sock, [b"option > "], timeout=8.0)
    if b"option > " not in banner:
        raise RuntimeError(f"bad banner: {banner!r}")
    return sock


def fetch_option1(host, port):
    sock = open_conn(host, port)
    try:
        sock.sendall(b"1\n")
        blob = recv_until_markers(sock, [b"option > "], timeout=6.0)
    finally:
        sock.close()
    text = blob.decode("utf-8", "ignore")
    a = ast.literal_eval(re.search(r"Key Part A: (\[.*\])", text).group(1))
    b0 = ast.literal_eval(re.search(r"Key Part B0: (\[.*\])", text).group(1))
    b1 = ast.literal_eval(re.search(r"Key Part B1: (\[.*\])", text).group(1))
    return a, b0, b1


def run_option2(host, port, ordered_values):
    sock = open_conn(host, port)
    try:
        sock.sendall(b"2\n")
        blob = recv_until_markers(sock, [b"1th number"], timeout=3.0)
        if b"1th number" not in blob:
            raise RuntimeError(blob.decode("utf-8", "ignore"))

        for index, value in enumerate(ordered_values, start=1):
            sock.sendall(str(value).encode() + b"\n")
            markers = [b"Traceback", b"Flag:"]
            if index < len(ordered_values):
                markers.append(f"{index + 1}th number".encode())
            blob = recv_until_markers(sock, markers, timeout=3.0)
            if index == len(ordered_values) and b"Flag:" not in blob and b"Traceback" not in blob:
                blob += recv_until_markers(sock, [b"Flag:", b"Traceback"], timeout=6.0)

        text = blob.decode("utf-8", "ignore")
        for line in text.splitlines():
            if line.startswith("Flag:"):
                ciphertext = ast.literal_eval(line.split("Flag:", 1)[1].strip())
                return ciphertext
        raise RuntimeError(text)
    finally:
        sock.close()


def recover_python_seed(ordered_a, b1):
    words = {}
    position = 0
    for round_index, value in enumerate(ordered_a, start=1):
        limbs = [(value >> (32 * limb)) & 0xFFFFFFFF for limb in range(30)]
        for offset, limb in enumerate(limbs):
            if position + offset < 624:
                words[position + offset] = limb
        position += 31 + b1[round_index - 1]

    recoverable_i = {}
    for index in range(228, 624):
        required = [index, index - 227, index - 1, index - 228]
        if not all(pos in words for pos in required):
            continue
        si = untemper(words[index])
        si227 = untemper(words[index - 227])
        sim1 = untemper(words[index - 1])
        sim228 = untemper(words[index - 228])
        msb_i, _ = invert_step(si, si227)
        _, low31_i = invert_step(sim1, sim228)
        recoverable_i[index] = (msb_i | low31_i) & 0xFFFFFFFF

    votes = {0: {}, 1: {}, 2: {}, 3: {}}
    for index in range(230, 624):
        if not all(pos in recoverable_i for pos in (index, index - 1, index - 2)):
            continue
        ii = recoverable_i[index]
        ii1 = recoverable_i[index - 1]
        ii2 = recoverable_i[index - 2]
        ji = recover_ji_from_ii(ii, ii1, index)
        ji1 = recover_ji_from_ii(ii1, ii2, index - 1)
        kj_raw = recover_kj_from_ji(ji, ji1, index)
        limb_index = (index - 1) % 4
        votes[limb_index][kj_raw] = votes[limb_index].get(kj_raw, 0) + 1

    raw_limbs = [max(votes[i], key=votes[i].get) for i in range(4)]
    limbs = [((raw_limbs[i] - i) & 0xFFFFFFFF) for i in range(4)]
    seed = sum(value << (32 * index) for index, value in enumerate(limbs))

    rng = random.Random(seed)
    replay = [rng.getrandbits(32) for _ in range(624)]
    if not all(replay[index] == value for index, value in words.items()):
        raise RuntimeError("recovered seed does not replay observed words")
    return seed


def is_prime(value):
    if value < 2:
        return False
    if value % 2 == 0:
        return value == 2
    divisor = 3
    while divisor * divisor <= value:
        if value % divisor == 0:
            return False
        divisor += 2
    return True


def derive_key_from_seed(python_seed, ordered_a, b0, b1):
    rng = random.Random(python_seed)
    replay_b0 = []
    replay_b1 = []
    for round_index, expected_a in enumerate(ordered_a, start=1):
        if rng.getrandbits(988) != expected_a:
            raise RuntimeError(f"A mismatch at round {round_index}")
        limit = get_limit(round_index)
        attempts = 0
        while True:
            candidate = rng.randint(0, limit - 1)
            attempts += 1
            if candidate >= 2 and is_prime(candidate):
                replay_b0.append(candidate)
                replay_b1.append(attempts)
                break
    if replay_b0 != b0 or replay_b1 != b1:
        raise RuntimeError("replayed B0/B1 do not match observation")

    r_value = rng.getrandbits(256)
    key = sha256(str(r_value).encode()).digest()
    return r_value, key


def main():
    host = sys.argv[1] if len(sys.argv) > 1 else HOST
    port = int(sys.argv[2]) if len(sys.argv) > 2 else PORT

    observed_a, b0, b1 = fetch_option1(host, port)
    ordered_a = [observed_a[index] for index in ORDERED_INDICES]
    ciphertext = run_option2(host, port, ordered_a)
    python_seed = recover_python_seed(ordered_a, b1)
    r_value, key = derive_key_from_seed(python_seed, ordered_a, b0, b1)
    plaintext = unpad(AES.new(key, AES.MODE_ECB).decrypt(ciphertext), AES.block_size)

    print(f"[+] python seed: {python_seed}")
    print(f"[+] rand256: {r_value}")
    print(f"[+] key: {key.hex()}")
    print(f"[+] flag: {plaintext.decode()}")


if __name__ == "__main__":
    main()
