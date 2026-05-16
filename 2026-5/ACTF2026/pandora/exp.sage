from sage.all import *
sage_log = log
import ast
import logging
import os
import time
from pwn import *
import re
import urllib.request
import tempfile
import subprocess


def solve_pow_token(token, timeout=120):
    """Solve kCTF PoW token.

    Prefer the exact official command via bash process substitution.  This
    avoids Python urllib SSL issues observed on some WSL/Python builds.
    Optional env:
      KCTF_POW=/path/to/kctf-pow.py  use local cached solver
    """
    token = str(token).strip()
    local_solver = os.environ.get("KCTF_POW")
    if local_solver:
        cmd = ["python3", local_solver, "solve", token]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
    else:
        # Same command printed by the challenge.  Use bash, not /bin/sh, because
        # process substitution <(...) is a bash feature.
        qtoken = token.replace("'", "'\\''")
        cmd = f"python3 <(curl -sSL https://goo.gle/kctf-pow) solve '{qtoken}'"
        out = subprocess.check_output(["bash", "-lc", cmd], stderr=subprocess.STDOUT, timeout=timeout)

    text = out.decode(errors="ignore").strip()
    lines = [L.strip() for L in text.splitlines() if L.strip()]
    if not lines:
        raise ValueError("pow solver produced no output")
    # Official solver usually prints only the solution.  If there are extra
    # words, take the final whitespace token.
    return lines[-1].split()[-1]


def solve_pow_from_remote(tube, timeout=40):
    """Read PoW banner, solve it, and submit the solution.

    recvuntil(b"Solution?") was flaky against this service: sometimes pwntools
    returned b"" on timeout before the banner was fully buffered.  Use an
    explicit accumulation loop and parse the full banner.
    """
    data = b""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            chunk = tube.recv(timeout=1)
        except EOFError:
            break
        if chunk:
            data += chunk
            # Stop once the PoW prompt is visible.  Also allow direct challenge
            # mode if PoW is disabled.
            if b"Solution?" in data or b"[token]:" in data:
                break
        else:
            continue

    text = data.decode(errors="ignore")
    if os.environ.get("DEBUG_POW", "0") == "1":
        dbg(f"[.] PoW/banner raw: {text!r}")

    if b"[token]:" in data and b"Solution?" not in data:
        # No PoW.  Return already-read challenge bytes so caller can prepend it.
        return None, data

    # Parse only the actual command/token, not "please solve a pow first".
    m = re.search(r"solve\s+(s\.[A-Za-z0-9+/_=.-]+)", text)
    if not m:
        toks = re.findall(r"\b(s\.[A-Za-z0-9+/_=.-]{8,})\b", text)
        if not toks:
            raise ValueError(f"could not find kCTF pow token in banner: {text!r}")
        token = toks[-1]
    else:
        token = m.group(1)

    dbg(f"[.] Found PoW token: {token}")
    sol = solve_pow_token(token)
    dbg(f"[.] PoW solution: {sol}")
    tube.sendline(sol.encode())
    return sol, b""


# Pandora EXP rewritten from CM_method.md
# version: CM-HG-HOM-2026-05-10-r10-parse-correct
# =========================

context.log_level = os.environ.get("PWN_LOG", "info")
logging.basicConfig(level=logging.INFO)

# CHAL = os.environ.get("CHAL", "./chal.sage")
LOW_A_BITS = 360
TOKEN_X_BITS = 240
TOKEN_Y_BITS = 120
LAMBDA_DIGITS = 470


def dbg(msg):
    print(msg, flush=True)


# ----------------------------------------------------------------------
# Stage 1: lambda = frac(q*sqrt(p)) -> D = p*q^2
# ----------------------------------------------------------------------
def recover_D(lambda_digits):
    Q = ZZ(10) ** len(lambda_digits)
    L = ZZ(lambda_digits)

    M = Q * Q
    A = 2 * L * Q
    C = L * L

    max_T_bits = int(os.environ.get("T_BITS", "800"))
    X = ZZ(2) ** max_T_bits
    E = Q * X

    # Need integer T such that 2*T*(L/Q)+(L/Q)^2 is almost integer.
    # Lattice vector:
    #   n*(Q^2,0,0) + T*(2LQ,Q,0) + 1*(L^2,0,QX)
    Bmat = Matrix(ZZ, [
        [M, 0, 0],
        [A, Q, 0],
        [C, 0, E],
    ])

    candidates = []
    for reduced in (Bmat.LLL(), Bmat.BKZ(block_size=3)):
        for row in reduced.rows():
            if row[2] % E != 0:
                continue
            z = row[2] // E
            if abs(z) != 1:
                continue
            if row[1] % Q != 0:
                continue
            T = row[1] // Q
            if z == -1:
                T = -T
            if 0 <= T < X:
                candidates.append(ZZ(T))

    Rcheck = RealField(2333)
    Rcalc = RealField(2400)
    seen = set()
    for T in candidates:
        if T in seen:
            continue
        seen.add(T)
        D = ZZ(round((Rcalc(T) + Rcalc(L) / Q) ** 2))
        if D <= 0:
            continue
        check = f"{Rcheck(D).sqrt():.{LAMBDA_DIGITS}f}".split(".")[1]
        if check == lambda_digits:
            return D

    raise ValueError("Stage1 failed: cannot recover D")


# ----------------------------------------------------------------------
# Stage 2: K=(B^2+D)/4=a*C, a=A0+u, 0<=u<2^360
# Custom tiny univariate HG lattice, no Sage small_roots by default.
# ----------------------------------------------------------------------
def row_to_poly(row, Xbound, R):
    u = R.gen()
    P = R(0)
    for j, val in enumerate(row):
        scale = Xbound ** j
        if val % scale != 0:
            return None
        coeff = ZZ(val // scale)
        if coeff:
            P += coeff * (u ** j)
    return P


def integer_roots_poly(P):
    """Return integer roots of a ZZ polynomial; robust wrapper."""
    if P is None or P == 0:
        return []
    # Primitive part reduces root-finding cost.
    try:
        coeffs = [ZZ(c) for c in P.list() if c]
        if coeffs:
            cont = abs(gcd(coeffs))
            if cont > 1:
                P = P // cont
    except Exception:
        pass

    roots = []
    try:
        for r, mult in P.roots(ring=ZZ):
            roots.append(ZZ(r))
        return roots
    except TypeError:
        pass
    except Exception:
        pass

    try:
        for r, mult in P.roots():
            if r in ZZ:
                roots.append(ZZ(r))
    except Exception:
        pass
    return roots


def recover_a_hg_shifted_once(K, Abase, Rbound, m, t):
    """Centered shifted univariate unknown-divisor HG/Coppersmith lattice.

    Instead of a=A0+u with 0<=u<2^360, use interval centering:
        a = Abase + v,  |v| <= Rbound.
    This cuts the Coppersmith absolute bound by about one bit.  On this
    challenge Stage2 is very close to the boundary, so this is materially more
    reliable than the one-sided variable u.

    Basis:
      K^(m-i) * f(v)^i                 for i=0..m
      v^j * f(v)^m                     for j=1..t
    where f(v)=Abase+v.
    """
    R = PolynomialRing(ZZ, "v")
    v = R.gen()
    f = ZZ(Abase) + v

    polys = []
    for i in range(m + 1):
        polys.append((f ** i) * (K ** (m - i)))
    for j in range(1, t + 1):
        polys.append((v ** j) * (f ** m))

    deg = m + t
    rows = len(polys)
    cols = deg + 1
    M = Matrix(ZZ, rows, cols)
    for r, poly in enumerate(polys):
        coeffs = poly.list()
        for j in range(min(len(coeffs), cols)):
            M[r, j] = ZZ(coeffs[j]) * (Rbound ** j)

    maxbits = max(abs(x).nbits() for x in M.list())
    dbg(f"[.] Stage2 centered-HG m={m} t={t} dim={rows}x{cols} Rbits={Rbound.nbits()} max_entry_bits={maxbits}")
    L = M.LLL()

    candidates = []
    trivial = -ZZ(Abase)
    for ridx, row in enumerate(L.rows()):
        P = row_to_poly(row, Rbound, R)
        if P is None or P == 0:
            continue
        roots = integer_roots_poly(P)
        good = []
        for rr in roots:
            rr = ZZ(rr)
            if rr == trivial:
                continue
            if -Rbound <= rr <= Rbound:
                candidates.append(rr)
                good.append(rr)
        if good:
            dbg(f"[.] Stage2 row={ridx} centered_roots={good[:5]}")
        elif roots and os.environ.get("VERBOSE_TRIVIAL", "0") == "1":
            dbg(f"[.] Stage2 row={ridx} only_unbounded_or_trivial_roots={roots[:3]}")

    out = []
    seen = set()
    for vv in candidates:
        if vv not in seen:
            seen.add(vv)
            out.append(vv)
    if not out:
        dbg(f"[.] Stage2 centered-HG m={m} t={t} produced no bounded roots")
    return out


def parse_stage2_configs():
    """Parse STAGE2_CONFIGS as m:t pairs, or derive from STAGE2_M_LIST."""
    if os.environ.get("STAGE2_CONFIGS"):
        cfgs = []
        for item in os.environ["STAGE2_CONFIGS"].split(','):
            item = item.strip()
            if not item:
                continue
            m, t = item.split(':')
            cfgs.append((int(m), int(t)))
        return cfgs

    # Default strategy: this boundary is instance-dependent.  Empirically
    # m=t=24 is the first setting that often produces the correct bounded root.
    # Re-running the same lattice on the same instance is deterministic, so the
    # useful "retry" is to abandon a bad instance quickly and get fresh p,q,token.
    # Override with STAGE2_CONFIGS=20:20,24:24,28:28,... if desired.
    return [(24,24)]


def recover_a(D, a_high, Bcoef):
    D = ZZ(D)
    Bcoef = ZZ(Bcoef)
    K = (Bcoef * Bcoef + D) // 4
    if 4 * K != Bcoef * Bcoef + D:
        raise ValueError("Stage2: (B^2+D) not divisible by 4")

    A0 = ZZ(a_high) << LOW_A_BITS
    full_lo = ZZ(0)
    full_hi = (ZZ(1) << LOW_A_BITS) - 1
    if A0 <= 0:
        raise ValueError("Stage2: bad a_high/A0")

    # Use reduced-form information to tighten the low-bit interval.
    # |B| <= a gives a lower bound; a <= C and a*C=K gives a^2 <= K.
    lo = full_lo
    hi = full_hi
    lo = max(lo, abs(Bcoef) - A0)
    hi = min(hi, floor(sqrt(K)) - A0)
    # Also use construction bound a=x^2+p*y^2, p<2^512, x<2^240, y<2^120.
    a_construct_max = (ZZ(1) << 480) + ((ZZ(1) << 512) * (ZZ(1) << 240))
    hi = min(hi, a_construct_max - A0)
    lo = max(lo, ZZ(0))
    hi = min(hi, full_hi)
    if lo > hi:
        raise ValueError(f"Stage2 interval empty: lo={lo} hi={hi}")

    center = (lo + hi) // 2
    Rbound = max(center - lo, hi - center) + 1
    Abase = A0 + center

    beta_est = float(sage_log(RealField(100)(max(Abase, 2))) / sage_log(RealField(100)(K)))
    dbg(f"[.] Stage2 Kbits={K.nbits()} A0bits={A0.nbits()} beta_est={beta_est:.6f}")
    dbg(f"[.] Stage2 interval lo_bits={ZZ(lo).nbits()} hi_bits={ZZ(hi).nbits()} width_bits={(hi-lo+1).nbits()} center_bits={ZZ(center).nbits()} Rbits={Rbound.nbits()}")

    configs = parse_stage2_configs()
    dbg(f"[.] Stage2 configs={configs}")
    for m, t in configs:
        roots = recover_a_hg_shifted_once(K, Abase, Rbound, m, t)
        dbg(f"[.] Stage2 m={m} t={t} candidate_count={len(roots)}")
        for vv in roots:
            uu = center + ZZ(vv)
            if not (lo <= uu <= hi):
                continue
            a = A0 + uu
            if a > 0 and K % a == 0:
                dbg(f"[.] Stage2 exact divisor candidate u_bits={ZZ(uu).nbits()} v_bits={ZZ(vv).nbits()}")
                C = K // a
                if Bcoef * Bcoef - 4 * a * C == -D:
                    dbg(f"[+] Stage2 success m={m} t={t} u_bits={ZZ(uu).nbits()} a_bits={a.nbits()} C_bits={C.nbits()}")
                    return a, C

    # Optional dangerous fallback; default OFF because it caused OOM.
    if os.environ.get("STAGE2_SAGE_FALLBACK", "0") == "1":
        dbg("[!] Stage2 entering Sage small_roots fallback; may OOM")
        PR = PolynomialRing(Zmod(K), "u")
        u = PR.gen()
        f = u + PR(A0)
        for delta in [0.001, 0.002, 0.004, 0.006, 0.008, 0.010, 0.015]:
            beta = beta_est - delta
            eps_max = beta * beta - (LOW_A_BITS + 2) / float(K.nbits())
            if eps_max <= 0:
                continue
            epsilon = min(0.002, eps_max / 2)
            dbg(f"[.] Stage2 Sage beta={beta:.6f} eps={epsilon:.6f}")
            roots = f.small_roots(X=Xbound, beta=beta, epsilon=epsilon)
            for rr in roots:
                uu = ZZ(rr)
                a = A0 + uu
                if 0 <= uu < Xbound and K % a == 0:
                    C = K // a
                    if Bcoef * Bcoef - 4 * a * C == -D:
                        return a, C

    raise ValueError("Stage2 failed: no a recovered")


# ----------------------------------------------------------------------
# Stage 3: homogeneous Coppersmith for h(k,Y)=q^2
# ----------------------------------------------------------------------
def center_mod(x, n):
    x = ZZ(x) % ZZ(n)
    if x > n // 2:
        x -= n
    return ZZ(x)


def primitive_candidates_from_ratio(r):
    r = QQ(r)
    num = ZZ(r.numerator())
    den = ZZ(r.denominator())
    return [(num, den), (-num, -den)]


def validate_primitive_candidate(D, a, Bcoef, C, k, Y0):
    D = ZZ(D)
    a = ZZ(a)
    Bcoef = ZZ(Bcoef)
    C = ZZ(C)
    k = ZZ(k)
    Y0 = ZZ(Y0)

    if abs(k) >= ZZ(2) ** 125 or abs(Y0) >= ZZ(2) ** 125:
        return None
    if Y0 % 2:
        return None

    y0 = -Y0 // 2
    if not (0 <= y0 < ZZ(2) ** TOKEN_Y_BITS):
        return None

    value = ZZ(a * k * k + Bcoef * k * Y0 + C * Y0 * Y0)
    if value <= 0:
        return None

    # In the ideal case value == q^2.  Keep gcd fallback.
    q2_candidates = []
    if D % value == 0:
        q2_candidates.append(value)
    g = gcd(value, D)
    if g not in q2_candidates:
        q2_candidates.append(g)

    for q2 in q2_candidates:
        q = ZZ(floor(sqrt(q2)))
        if q * q != q2:
            continue
        if not (ZZ(2) ** 500 <= q <= ZZ(2) ** 512):
            continue
        if D % (q * q) != 0:
            continue

        num = k * a - Bcoef * y0
        if num % q != 0:
            continue
        x0 = ZZ(num // q)
        if 0 <= x0 < ZZ(2) ** TOKEN_X_BITS:
            return q, x0, y0
    return None


def recover_primitive_homogeneous(D, a, Bcoef, C, m=4, t=6, bound_bits=122):
    D = ZZ(D)
    a = ZZ(a)
    Bcoef = ZZ(Bcoef)
    C = ZZ(C)

    if gcd(a, D) != 1:
        dbg(f"[!] Stage3 gcd(a,D)={gcd(a,D)}")

    ainv = inverse_mod(a % D, D)
    b1 = center_mod(Bcoef * ainv, D)
    c1 = center_mod(C * ainv, D)

    PR = PolynomialRing(ZZ, names=("X", "Y"))
    X, Y = PR.gens()
    f = X ** 2 + b1 * X * Y + c1 * Y ** 2

    N = D
    deg = 2 * t
    MX = ZZ(2) ** bound_bits
    MY = ZZ(2) ** bound_bits

    polys = []
    # g_{i,j}=X^j Y^{2(t-i)-j} f^i N^{m-i}, i=0..m-1, j=0,1
    for i in range(m):
        for j in range(2):
            eY = 2 * (t - i) - j
            if eY >= 0:
                polys.append((X ** j) * (Y ** eY) * (f ** i) * (N ** (m - i)))
    # h_i=X^i Y^{2(t-m)-i} f^m, i=0..2(t-m)
    for i in range(2 * (t - m) + 1):
        eY = 2 * (t - m) - i
        if eY >= 0:
            polys.append((X ** i) * (Y ** eY) * (f ** m))

    monoms = [(e, deg - e) for e in range(deg + 1)]
    if len(polys) != len(monoms):
        raise ValueError(f"Stage3 bad dimensions: polys={len(polys)} monoms={len(monoms)}")

    M = Matrix(ZZ, len(polys), len(monoms))
    for r, poly in enumerate(polys):
        # Do not use poly.dict().  In Sage multivariate polynomial dict keys
        # may be ETuple objects and tuple lookup can silently miss everything,
        # producing an all-zero matrix.  monomial_coefficient is stable.
        for col, (ex, ey) in enumerate(monoms):
            mon = (X ** ex) * (Y ** ey)
            coeff = ZZ(poly.monomial_coefficient(mon))
            M[r, col] = coeff * (MX ** ex) * (MY ** ey)

    vals = M.list()
    nz = sum(1 for v in vals if v != 0)
    maxbits = max(abs(v).nbits() for v in vals) if vals else 0
    dbg(f"[.] Stage3 HOM m={m} t={t} dim={M.nrows()}x{M.ncols()} bound=2^{bound_bits} nonzero={nz} max_entry_bits={maxbits}")
    if nz == 0:
        raise ValueError("Stage3 internal error: all-zero lattice matrix")
    L = M.LLL()

    Rz = PolynomialRing(QQ, "z")
    z = Rz.gen()
    tried = set()

    for ridx, row in enumerate(L.rows()):
        coeffs = []
        ok = True
        for col, (ex, ey) in enumerate(monoms):
            scale = (MX ** ex) * (MY ** ey)
            if row[col] % scale != 0:
                ok = False
                break
            coeffs.append(ZZ(row[col] // scale))
        if not ok or all(c == 0 for c in coeffs):
            continue

        P = Rz(0)
        for (ex, ey), coeff in zip(monoms, coeffs):
            P += QQ(coeff) * (z ** ex)
        if P == 0:
            continue

        roots = []
        try:
            roots = [rr for rr, mult in P.roots()]
        except Exception as exc:
            dbg(f"[.] Stage3 row={ridx} roots failed: {type(exc).__name__}: {exc}")
            continue

        if roots:
            dbg(f"[.] Stage3 row={ridx} rational_roots={roots[:5]}")
        for rr in roots:
            for k, Y0 in primitive_candidates_from_ratio(rr):
                key = (k, Y0)
                if key in tried:
                    continue
                tried.add(key)
                ans = validate_primitive_candidate(D, a, Bcoef, C, k, Y0)
                if ans is not None:
                    return ans

    raise ValueError("Stage3 homogeneous failed")


def recover_primitive(D, a, Bcoef, C):
    # Try default and then small parameter variations.
    configs = []
    env = os.environ.get("STAGE3_CONFIGS", "4:6:122,4:6:123,5:7:122,5:8:122")
    for item in env.split(","):
        item = item.strip()
        if not item:
            continue
        mm, tt, bb = item.split(":")
        configs.append((int(mm), int(tt), int(bb)))

    last = None
    for m, t, bbits in configs:
        try:
            return recover_primitive_homogeneous(D, a, Bcoef, C, m=m, t=t, bound_bits=bbits)
        except Exception as exc:
            last = exc
            dbg(f"[-] Stage3 config m={m} t={t} b={bbits} failed: {type(exc).__name__}: {exc}")
    raise last if last is not None else ValueError("Stage3 no configs")


# ----------------------------------------------------------------------
# IO / main
# ----------------------------------------------------------------------
def parse_chal_output(buf):
    text = buf.decode(errors="ignore")
    # Remote prepends "Correct" after PoW.  Find the actual Python-literal
    # challenge line: ([a_high, B], 'lambda_digits').
    target = None
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("([") and "]," in line and line.endswith(")"):
            target = line
            break
    if target is None:
        m = re.search(r"(\(\[[-0-9,\s]+\],\s*'\d+'\))", text)
        if not m:
            raise ValueError(f"could not locate challenge tuple in buffer: {text!r}")
        target = m.group(1)
    zeta, lambda_digits = ast.literal_eval(target)
    return ZZ(zeta[0]), ZZ(zeta[1]), lambda_digits


def submit_token(io, x0, y0):
    # One chal instance accepts one token only.  The primitive recovery normally
    # returns the exact token when gcd(x,y)=1.  If gcd>1, retrying requires a new
    # challenge instance, so we submit g=1 here.
    token = int(x0).to_bytes(30, "big") + int(y0).to_bytes(15, "big")
    io.sendline(token.hex().encode())
    out = io.recvall(timeout=10).decode(errors="ignore")
    print(out.strip(), flush=True)
    return "^_^" in out or "actf{" in out


def try_instance(idx=None):
    
    t0 = time.time()

    io = remote("1.95.80.34", 9999)

    # handle proof-of-work before the challenge
    _, prebuf = solve_pow_from_remote(io)

    data = prebuf
    if b"[token]:" not in data:
        data += io.recvuntil(b"[token]:", timeout=80)
    a_high, Bcoef, lambda_digits = parse_chal_output(data)
    dbg("[+] parsed output")

    D = recover_D(lambda_digits)
    dbg(f"[+] Stage1 recovered D bits={D.nbits()} time={time.time()-t0:.2f}s")

    t1 = time.time()
    a, C = recover_a(D, a_high, Bcoef)
    dbg(f"[+] Stage2 recovered a,C bits={a.nbits()},{C.nbits()} time={time.time()-t1:.2f}s")

    if os.environ.get("SKIP_PRIMITIVE", "0") == "1":
        io.close()
        return False

    t2 = time.time()
    q, x0, y0 = recover_primitive(D, a, Bcoef, C)
    dbg(f"[+] Stage3 recovered q,x,y bits={q.nbits()},{x0.nbits()},{y0.nbits()} time={time.time()-t2:.2f}s")

    return submit_token(io, x0, y0)


def main():
    dbg("[*] exp.sage version CM-HG-HOM-2026-05-10-r10-parse-correct")
    attempts = int(os.environ.get("ATTEMPTS", "32"))
    for i in range(1, attempts + 1):
        dbg(f"[*] attempt {i}/{attempts}")
        try:
            if try_instance(i):
                return
        except Exception as exc:
            dbg(f"[-] attempt {i} failed: {type(exc).__name__}: {exc}")
    raise SystemExit("failed; adjust STAGE2_M_LIST / STAGE3_CONFIGS / ATTEMPTS")


main()
