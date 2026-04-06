from sage.all import *
from pwn import *
from hashlib import sha512
from hashlib import sha256
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

from util import N


P = 2**255 - 19
A = 486662
B = 35039673
GXY = (
    9,
    14781619447589544791020593568409986887264606134616475288964881837755586237401,
)
MAX_MSG = 100
SMALL_FACTOR_LIMIT = 40
TARGET_BITS = 242


def pack_point(point):
    x, y = point
    return (int(x) << 256) | int(y)


def unpack_point(value):
    x = value >> 256
    y = value & ((1 << 256) - 1)
    return x, y


def forge_input_coord(priv, target_coord):
    low_mask = (1 << 256) - 1
    priv_low = priv & low_mask
    priv_high = priv >> 256
    offset = int((Integer(priv_high) * (1 << 256)) % P)
    wanted_low = int((target_coord - offset) % P)
    return wanted_low ^ priv_low


def int_to_vec(x, q, n=N):
    out = []
    for _ in range(n):
        out.append(x % q)
        x //= q
    return out


def vec_to_int(v, q):
    out = 0
    for i, coeff in enumerate(v):
        out += int(coeff) * (q**i)
    return out


def primal_attack2(A_mat, b_vec, m, n, p, esz):
    L = block_matrix(
        [
            [matrix(Zmod(p), A_mat).T.echelon_form().change_ring(ZZ), 0],
            [matrix.zero(m - n, n).augment(matrix.identity(m - n) * p), 0],
            [matrix(ZZ, b_vec), 1],
        ]
    )
    Q = diagonal_matrix([1] * m + [esz])
    L *= Q
    L = L.LLL()
    L /= Q
    res = L[0]
    if res[-1] == 1:
        e = vector(GF(p), res[:m])
    elif res[-1] == -1:
        e = -vector(GF(p), res[:m])
    else:
        return None
    s = matrix(Zmod(p), A_mat).solve_right(vector(Zmod(p), b_vec) - e)
    return vector(GF(p), list(s))


def parse_after_colon(line):
    return line.decode().strip().split(": ", 1)[1]


class LocalChall:
    def __init__(self):
        # self.io = process(["python3", "-u", "task.py"])
        self.io = remote("114.66.24.221", 41793)
        self.pub = None
        self.enc = None
        self.round_idx = 0
        self.q = None
        self.started = False

    def read_banner_and_round(self):
        if not self.started:
            self.pub = int(parse_after_colon(self.io.recvline()))
            self.enc = parse_after_colon(self.io.recvline())
            self.started = True
        self.q = int(parse_after_colon(self.io.recvline()))
        self.round_idx += 1
        self.io.recvuntil(b"Channel your intent (m=message, e=exchange):")
        return self.pub, self.enc, self.q

    def send_m(self, msg):
        self.io.sendline(b"m")
        self.io.recvuntil(b"Offer your spiritual essence (int):")
        self.io.sendline(str(msg).encode())
        line = self.io.recvline()
        ct = eval(parse_after_colon(line))
        self.io.recvuntil(b"Channel your intent (m=message, e=exchange):")
        return ct

    def send_e(self, packed):
        self.io.sendline(b"e")
        self.io.recvuntil(b"Forge your spirit formation (int):")
        self.io.sendline(str(packed).encode())
        line = self.io.recvline()
        value = int(parse_after_colon(line))
        return value

    def close(self):
        self.io.close()


def pub_to_point(pub_int):
    E = EllipticCurve(GF(P), [A, B])
    x, y = unpack_point(pub_int)
    return E(x, y)


def recover_round_secret(io, q):
    rows = []
    rhs = []
    for msg in range(MAX_MSG):
        m8 = int(sha512(str(msg).encode()).hexdigest(), 16) & 0xFF
        a_int, b_val = io.send_m(msg)
        rows.append(int_to_vec(a_int, q))
        rhs.append((b_val - (m8 << 2)) % q)
    A_mat = matrix(GF(q), rows)
    b_vec = vector(GF(q), rhs)
    s = primal_attack2(A_mat, b_vec, MAX_MSG, N, q, 4)
    if s is None:
        raise ValueError("failed to recover LWE secret")
    priv = vec_to_int(s, q)
    return s, priv


def curve_b_from_point(x, y):
    return int((y * y - x * x * x - A * x) % P)


def exact_order_point(E, order_target, trials=64):
    order_E = E.order()
    if order_E % order_target != 0:
        return None
    cofactor = order_E // order_target
    for _ in range(trials):
        Q = cofactor * E.random_point()
        if Q.is_zero():
            continue
        if Q.order() == order_target:
            return Q
    return None


def find_invalid_curve_point(limit_bits=SMALL_FACTOR_LIMIT):
    gf = GF(P)
    used_b = set([B])
    while True:
        b = ZZ.random_element(1, P - 1)
        if b in used_b:
            continue
        used_b.add(int(b))
        if (4 * A**3 + 27 * b**2) % P == 0:
            continue
        E = EllipticCurve(gf, [A, int(b)])
        order_E = E.order()
        factors = factor(order_E)
        small = []
        for pr, exp in factors:
            pe = int(pr**exp)
            if Integer(pe).nbits() <= limit_bits:
                small.append(pe)
        small.sort(reverse=True)
        for order_target in small:
            Q = exact_order_point(E, order_target)
            if Q is not None:
                return {
                    "curve_b": int(b),
                    "curve_order": int(order_E),
                    "point": (int(Q[0]), int(Q[1])),
                    "order": int(order_target),
                }


def build_candidate_pool(target_bits=TARGET_BITS, limit_bits=SMALL_FACTOR_LIMIT):
    modulus = 1
    pool = []
    while Integer(modulus).nbits() < target_bits:
        candidate = find_invalid_curve_point(limit_bits=limit_bits)
        self_check_candidate(candidate)
        r = candidate["order"]
        if gcd(modulus, r) != 1:
            continue
        pool.append(candidate)
        modulus *= r
        print(
            f"[*] candidate {len(pool)}: order={r} "
            f"(bits={Integer(r).nbits()}), crt_bits={Integer(modulus).nbits()}"
        )
    return pool


def residue_from_response(candidate, response_int):
    x, y = unpack_point(response_int)
    E = EllipticCurve(GF(P), [A, candidate["curve_b"]])
    P0 = E(*candidate["point"])
    Q0 = E(x, y)
    return int(discrete_log(Q0, P0, ord=candidate["order"], operation="+"))


def one_round_invalid_curve_residue(io, candidate):
    _, _, q = io.read_banner_and_round()
    _, priv = recover_round_secret(io, q)
    px, py = candidate["point"]
    in_x = forge_input_coord(priv, px)
    in_y = forge_input_coord(priv, py)
    masked = pack_point((in_x, in_y))
    response = io.send_e(masked)
    if response == 0:
        raise ValueError("oracle returned point at infinity")
    residue = residue_from_response(candidate, response)
    return {"q": q, "priv": priv, "response": response, "residue": residue}


def self_check_candidate(candidate):
    bx = curve_b_from_point(*candidate["point"])
    if bx != candidate["curve_b"]:
        raise ValueError("candidate point is not on the intended curve")


def recover_master_secret_locally(candidates):
    io = LocalChall()
    logs = []
    moduli = []
    try:
        for idx, candidate in enumerate(candidates, 1):
            result = one_round_invalid_curve_residue(io, candidate)
            pub_int = io.pub
            enc_hex = io.enc
            logs.append(result["residue"])
            moduli.append(candidate["order"])
            d = int(crt(logs, moduli))
            crt_mod = prod(moduli)
            print(
                f"[*] round {idx}: residue={result['residue']} mod {candidate['order']}, "
                f"crt_bits={Integer(crt_mod).nbits()}"
            )
            E = EllipticCurve(GF(P), [A, B])
            G = E(*GXY)
            pub = pub_to_point(pub_int)
            if d * G == pub:
                return d, pub_int, enc_hex
        return int(crt(logs, moduli)), pub_int, enc_hex
    finally:
        io.close()


def decrypt_flag(d, enc_hex):
    key = sha256(str(d).encode()).digest()
    ct = bytes.fromhex(enc_hex)
    pt = AES.new(key, AES.MODE_ECB).decrypt(ct)
    try:
        pt = unpad(pt, 32)
    except ValueError:
        pass
    return pt


def main():
    context.log_level = "error"
    print("[*] building invalid-curve candidate pool")
    candidates = build_candidate_pool()
    print(f"[*] total candidates = {len(candidates)}")
    d, pub_int, enc_hex = recover_master_secret_locally(candidates)
    print(f"[*] recovered d = {d}")
    print(f"[*] pub = {pub_int}")
    print(f"[*] enc = {enc_hex}")
    pt = decrypt_flag(d, enc_hex)
    print(f"[*] plaintext = {pt!r}")


if __name__ == "__main__":
    main()
