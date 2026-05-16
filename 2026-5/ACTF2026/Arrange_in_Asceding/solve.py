import base64
import os
import socket
import struct
import sys
import tempfile
from concurrent.futures import ProcessPoolExecutor, as_completed
from typing import Iterable, List

import tenseal as ts
import tenseal.sealapi as sealapi
import numpy as np
from numpy.polynomial import chebyshev as ncheb
try:
    from scipy.optimize import linprog
except Exception:  # scipy is only needed when coeff_mode="minimax"
    linprog = None


N = 128
SLOTS = 32768 // 2
SCALE = 2**40


def varint(n: int) -> bytes:
    out = bytearray()
    while True:
        c = n & 0x7F
        n >>= 7
        if n:
            out.append(c | 0x80)
        else:
            out.append(c)
            return bytes(out)


def ct_save_bytes(ct) -> bytes:
    fd, path = tempfile.mkstemp(suffix=".ct")
    os.close(fd)
    try:
        ct.save(path)
        with open(path, "rb") as f:
            return f.read()
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def ct_load_bytes(ctxdata, raw: bytes):
    fd, path = tempfile.mkstemp(suffix=".ct")
    os.close(fd)
    try:
        with open(path, "wb") as f:
            f.write(raw)
        ct = sealapi.Ciphertext()
        ct.load(ctxdata, path)
        return ct
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def wrap_ckks_serialized(raw_ct: bytes, logical_size: int = SLOTS, scale: float = SCALE) -> bytes:
    # TenSEAL CKKSVector protobuf, single ciphertext:
    # field 1: packed logical vector size(s); field 2: raw SEAL ciphertext;
    # field 3: fixed64 scale.
    size_enc = varint(logical_size)
    return (
        b"\x0a" + varint(len(size_enc)) + size_enc
        + b"\x12" + varint(len(raw_ct)) + raw_ct
        + b"\x19" + struct.pack("<d", scale)
    )


class HE:
    def __init__(self, ctx: ts.Context, galois_key_path: str):
        self.ctx = ctx
        self.ctxdata = ctx.seal_context().data
        self.encoder = sealapi.CKKSEncoder(self.ctxdata)
        self.evaluator = sealapi.Evaluator(self.ctxdata)
        self.gk = sealapi.GaloisKeys()
        self.gk.load(self.ctxdata, os.path.abspath(galois_key_path))
        self.zero_cache = {}
        self.mask_cache = {}
        self.mask_plain_cache = {}
        self.coeff_cache = {}
        self.decomp_cache = {}

    def as_vec(self, ct, size=SLOTS):
        raw = ct_save_bytes(ct)
        return ts.ckks_vector_from(self.ctx, wrap_ckks_serialized(raw, size, getattr(ct, "scale", SCALE)))

    def from_vec(self, v):
        return v.data.ciphertext()[0]

    def copy(self, ct):
        # add plaintext zero at the current parms_id; this is much faster than
        # serializing through protobuf and preserves level/scale.
        key = (tuple(ct.parms_id()), float(ct.scale))
        pt = self.zero_cache.get(key)
        if pt is None:
            pt = sealapi.Plaintext()
            self.encoder.encode(0.0, ct.parms_id(), ct.scale, pt)
            self.zero_cache[key] = pt
        out = sealapi.Ciphertext()
        self.evaluator.add_plain(ct, pt, out)
        return out

    def add(self, a, b):
        a, b = self.align(a, b)
        out = sealapi.Ciphertext()
        self.evaluator.add(a, b, out)
        return out

    def sub(self, a, b):
        a, b = self.align(a, b)
        out = sealapi.Ciphertext()
        self.evaluator.sub(a, b, out)
        return out

    def add_plain_const(self, a, c: float):
        pt = sealapi.Plaintext()
        self.encoder.encode(float(c), a.parms_id(), a.scale, pt)
        out = sealapi.Ciphertext()
        self.evaluator.add_plain(a, pt, out)
        out.scale = a.scale
        return out

    def align(self, a, b):
        """Mod-switch the higher-level operand down and equalize CKKS scales."""
        ca, cb = a.coeff_modulus_size(), b.coeff_modulus_size()
        if ca > cb:
            aa = sealapi.Ciphertext()
            self.evaluator.mod_switch_to(a, b.parms_id(), aa)
            bb = self.copy(b)
        elif cb > ca:
            bb = sealapi.Ciphertext()
            self.evaluator.mod_switch_to(b, a.parms_id(), bb)
            aa = self.copy(a)
        else:
            aa, bb = self.copy(a), self.copy(b)
        # SEAL requires near-identical scales for ciphertext addition.
        target = min(float(aa.scale), float(bb.scale))
        aa.scale = target
        bb.scale = target
        return aa, bb

    def rotate_pow2_left(self, ct, step: int):
        out = sealapi.Ciphertext()
        self.evaluator.rotate_vector(ct, step, self.gk, out)
        return out

    def rotate_left(self, ct, step: int):
        step %= SLOTS
        if step == 0:
            return self.copy(ct)
        cur = ct
        first = True
        bit = 1
        while step:
            if step & 1:
                cur = self.rotate_pow2_left(cur, bit)
                first = False
            step >>= 1
            bit <<= 1
        return cur if not first else self.copy(ct)

    def rotate_right(self, ct, step: int):
        return self.rotate_left(ct, -step)

    def mul_ct(self, a, b):
        # For multiplication, only parms_id/level must match; scales should NOT
        # be forced equal. Product scale is a.scale*b.scale. Forcing a 2^40
        # Chebyshev term down to a 2^20 S_j metadata corrupts the plaintext by
        # a factor 2^20.
        ca, cb = a.coeff_modulus_size(), b.coeff_modulus_size()
        if ca > cb:
            aa = sealapi.Ciphertext()
            self.evaluator.mod_switch_to(a, b.parms_id(), aa)
            bb = self.copy(b)
        elif cb > ca:
            bb = sealapi.Ciphertext()
            self.evaluator.mod_switch_to(b, a.parms_id(), bb)
            aa = self.copy(a)
        else:
            aa, bb = self.copy(a), self.copy(b)
        a, b = aa, bb
        in_scale = min(float(a.scale), float(b.scale))
        out = sealapi.Ciphertext()
        self.evaluator.multiply(a, b, out)
        # ctx.public contains relin keys in this challenge.
        if self.ctx.has_relin_keys():
            rel = sealapi.Ciphertext()
            self.evaluator.relinearize(out, self.ctx.relin_keys().data, rel)
            out = rel
        res = sealapi.Ciphertext()
        self.evaluator.rescale_to_next(out, res)
        # For normal ct-ct products scale is ~2^40; force away tiny drift.
        # For deliberately low-scale products (late giant steps), preserve
        # SEAL's natural scale or the decoded value would be multiplied.
        if 2**30 < float(res.scale) < 2**50:
            res.scale = SCALE
        elif float(res.scale) < 2**10 and in_scale > 2**10:
            # When multiplying a deliberately low-scale linear combination
            # (e.g. scale 2^20) by a normal Chebyshev giant (2^40), SEAL's
            # metadata can collapse to ~1 at lower chain levels although the
            # decoded value is off by exactly the low scale. Restore it.
            res.scale = in_scale
        return res

    def mul_plain_rescale(self, a, c: float):
        if abs(c) < 1e-300:
            # return encrypted zero at next level by multiplying by 0 is forbidden
            # in SEAL (transparent); instead multiply by tiny is worse. Caller skips.
            raise ValueError("zero coefficient should be skipped")
        pt = sealapi.Plaintext()
        self.encoder.encode(float(c), a.parms_id(), SCALE, pt)
        out = sealapi.Ciphertext()
        self.evaluator.multiply_plain(a, pt, out)
        res = sealapi.Ciphertext()
        self.evaluator.rescale_to_next(out, res)
        res.scale = SCALE
        return res

    def mul_plain_rescale_to(self, a, c: float, pscale: float, out_scale: float):
        if abs(c) < 1e-300:
            raise ValueError("zero coefficient should be skipped")
        pt = sealapi.Plaintext()
        self.encoder.encode(float(c), a.parms_id(), float(pscale), pt)
        out = sealapi.Ciphertext()
        self.evaluator.multiply_plain(a, pt, out)
        res = sealapi.Ciphertext()
        self.evaluator.rescale_to_next(out, res)
        res.scale = float(out_scale)
        return res

    def mul_plain_norescale(self, a, c: float, pscale: float = 2**20):
        if abs(c) < 1e-300:
            raise ValueError("zero coefficient should be skipped")
        pt = sealapi.Plaintext()
        self.encoder.encode(float(c), a.parms_id(), float(pscale), pt)
        out = sealapi.Ciphertext()
        self.evaluator.multiply_plain(a, pt, out)
        return out

    def const_like(self, a, c: float):
        # Enc(c) as ciphertext by adding plaintext c to an encrypted zero copy.
        z = self.add_plain_const(self.copy(a), -0.0)  # copy at same parms
        return self.add_plain_const(z, c)

    def mask(self, ct, kind: str):
        # Use TenSEAL plaintext-vector multiply. It consumes one plaintext-mul
        # level, but avoids writing fragile CKKS scale management by hand.
        if kind not in self.mask_cache:
            m = [0.0] * SLOTS
            if kind == "row0":
                for j in range(N):
                    m[j] = 1.0
            elif kind == "col0":
                for i in range(N):
                    m[i * N] = 1.0
            else:
                raise ValueError(kind)
            self.mask_cache[kind] = m
        return self.from_vec(self.as_vec(ct) * self.mask_cache[kind])

    def mask_norescale(self, ct, kind: str, pscale: float = 256.0):
        """Apply a 0/1 slot mask without rescale/level consumption.

        The old mask() path goes through TenSEAL CKKSVector multiplication and
        consumes one modulus level.  For matrix mode those two mask levels are
        exactly what prevent using a high enough comparator degree.

        A CKKS plaintext mask encoded at scale=1.0 keeps ciphertext scale
        unchanged after multiply_plain and does not require rescale.  Since the
        coefficients are only 0/1, scale=1 is precise enough for a mask.
        """
        key = (kind, tuple(ct.parms_id()), float(pscale))
        pt = self.mask_plain_cache.get(key)
        if pt is None:
            m = [0.0] * SLOTS
            if kind == "row0":
                for j in range(N):
                    m[j] = 1.0
            elif kind == "col0":
                for i in range(N):
                    m[i * N] = 1.0
            else:
                raise ValueError(kind)
            pt = sealapi.Plaintext()
            self.encoder.encode(m, ct.parms_id(), float(pscale), pt)
            self.mask_plain_cache[key] = pt
        out = sealapi.Ciphertext()
        self.evaluator.multiply_plain(ct, pt, out)
        return out

    def repl_r(self, ct):
        x = self.copy(ct)
        for i in range(7):
            x = self.add(x, self.rotate_right(x, N * (1 << i)))
        return x

    def trans_r(self, ct):
        x = self.copy(ct)
        for i in range(1, 8):
            x = self.add(x, self.rotate_right(x, (N * (N - 1)) // (1 << i)))
        return self.mask(x, "col0")

    def trans_r_norescale(self, ct, mask_pscale: float = 256.0):
        x = self.copy(ct)
        for i in range(1, 8):
            x = self.add(x, self.rotate_right(x, (N * (N - 1)) // (1 << i)))
        return self.mask_norescale(x, "col0", pscale=mask_pscale)

    def repl_c(self, ct):
        x = self.copy(ct)
        for i in range(7):
            x = self.add(x, self.rotate_right(x, 1 << i))
        return x

    def sum_r(self, ct):
        x = self.copy(ct)
        for i in range(7):
            x = self.add(x, self.rotate_left(x, N * (1 << i)))
        # The challenge only decodes/checks the first 128 slots.  Avoid the
        # final row mask because it costs another plaintext multiplication level.
        return x

    def cmp_poly(self, diff_ct, dg=2, df=1, denom_g=766.0):
        # Composite sign approximation from Cheon et al. / paper Sec. 2.2:
        # Cmp(x,y)=(f^df(g^dg((x-y)/512))+1)/2.
        f = [0.0] * 8
        f[1], f[3], f[5], f[7] = 35 / 16, -35 / 16, 21 / 16, -5 / 16
        g = [0.0] * 8
        g[1], g[3], g[5], g[7] = 4589 / denom_g, -16577 / denom_g, 25614 / denom_g, -12860 / denom_g
        # First g absorbs the 1/512 normalization into its coefficients.
        gs = [0.0] * 8
        for k in (1, 3, 5, 7):
            gs[k] = g[k] / (512.0 ** k)
        v = self.as_vec(diff_ct)
        v = v.polyval(gs)
        for _ in range(dg - 1):
            v = v.polyval(g)
        for _ in range(df):
            v = v.polyval(f)
        # map sign [-1,1] to [0,1]
        v = v * 0.5 + 0.5
        return self.from_vec(v)

    def cheb_T(self, n: int, x_ct, memo: dict):
        """Compute ciphertext T_n(x) with balanced Chebyshev product identities."""
        if n in memo:
            return memo[n]
        if n == 0:
            memo[0] = self.const_like(x_ct, 1.0)
            return memo[0]
        if n == 1:
            memo[1] = self.copy(x_ct)
            return memo[1]
        a = n // 2
        b = n - a
        ta = self.cheb_T(a, x_ct, memo)
        tb = self.cheb_T(b, x_ct, memo)
        prod = self.mul_ct(ta, tb)
        doubled = self.add(prod, prod)  # 2*T_a*T_b, no extra level
        if a == b:
            res = self.add_plain_const(doubled, -1.0)
        else:
            td = self.cheb_T(b - a, x_ct, memo)
            res = self.sub(doubled, td)
        memo[n] = res
        return res

    def lincomb_plain(self, terms):
        """Sum coeff*ciphertext terms. terms=[(coeff, ct), ...]."""
        acc = None
        for coeff, ct in terms:
            if abs(coeff) < 1e-14:
                continue
            t = self.mul_plain_rescale(ct, float(coeff))
            if acc is None:
                acc = t
            else:
                acc = self.add(acc, t)
        if acc is None:
            # Should not happen for our fitted comparator.
            raise ValueError("empty linear combination")
        return acc

    def lincomb_plain_low(self, terms, pscale=2**20, out_scale=2**20):
        acc = None
        for coeff, ct in terms:
            if abs(coeff) < 1e-14:
                continue
            t = self.mul_plain_rescale_to(ct, float(coeff), pscale, out_scale)
            if acc is None:
                acc = t
            else:
                acc = self.add(acc, t)
        if acc is None:
            raise ValueError("empty linear combination")
        return acc

    @staticmethod
    def cheb_sign_coeffs(deg=511, amplitude=1.0):
        gap = 1 / 512
        # Fit on Chebyshev nodes (with the forbidden comparison gap removed)
        # instead of an equally-spaced linspace.  This keeps the approximation
        # better conditioned near the ±1/512 decision boundary.
        k = np.arange(1, 100000 + 1)
        nodes = np.cos((2 * k - 1) * np.pi / (2 * 100000))
        xs = nodes[np.abs(nodes) >= gap]
        ys = np.where(xs > 0, float(amplitude), -float(amplitude))
        co = ncheb.chebfit(xs, ys, deg)
        co[::2] = 0.0
        return co

    @staticmethod
    def minimax_sign_coeffs(deg=511, amplitude=1.0):
        """Discrete odd minimax sign approximation on the challenge grid.

        The paper/reference code uses Remez minimax approximations.  For this
        challenge the comparison inputs are exactly k/512 (k != 0), so we can
        solve the finite minimax problem directly:

            min max_k |sum_i c_i T_i(k/512) - amplitude|

        using only odd Chebyshev terms; the negative side follows by symmetry.
        This function is intentionally available as an experiment knob.  The
        default solver path below still uses the oscillatory Chebyshev fit for
        the final degree-511 direct-indicator comparator, because its signed
        rank errors cancel better after summation.
        """
        if linprog is None:
            raise RuntimeError("scipy.optimize.linprog is required for minimax coefficients")

        xs = np.arange(1, 512, dtype=float) / 512.0
        odd = list(range(1, deg + 1, 2))
        vander = ncheb.chebvander(xs, deg)[:, odd]

        # Variables are [coefficients..., E].
        #  V c - amplitude <= E
        # -V c + amplitude <= E
        a_ub = []
        b_ub = []
        for row in vander:
            a_ub.append(list(row) + [-1.0])
            b_ub.append(float(amplitude))
            a_ub.append(list(-row) + [-1.0])
            b_ub.append(float(-amplitude))

        obj = [0.0] * len(odd) + [1.0]
        bounds = [(None, None)] * len(odd) + [(0.0, None)]
        res = linprog(
            obj,
            A_ub=np.asarray(a_ub, dtype=float),
            b_ub=np.asarray(b_ub, dtype=float),
            bounds=bounds,
            method="highs",
        )
        if not res.success:
            raise RuntimeError("minimax LP failed: " + res.message)

        co = np.zeros(deg + 1, dtype=float)
        co[odd] = res.x[:-1]
        return co

    def get_sign_coeffs(self, deg=511, amplitude=1.0, coeff_mode="cheb"):
        key = (coeff_mode, int(deg), float(amplitude))
        if key not in self.coeff_cache:
            if coeff_mode == "cheb":
                co = self.cheb_sign_coeffs(deg, amplitude=amplitude)
            elif coeff_mode in ("minimax", "minimaz"):
                co = self.minimax_sign_coeffs(deg, amplitude=amplitude)
            else:
                raise ValueError(f"unknown coeff_mode={coeff_mode!r}")
            self.coeff_cache[key] = co
        return self.coeff_cache[key]

    @staticmethod
    def decompose_cheb_coeffs(co, k=32, blocks=16):
        # Implements framework.md downward substitution:
        # M[j,i]=2*c[32j+i], c[32j-i]-=c[32j+i]
        c = np.array(co, dtype=float).copy()
        M = {}
        for j in range(blocks - 1, 0, -1):
            for i in range(1, k, 2):
                hi = k * j + i
                if hi >= len(c):
                    continue
                val = c[hi]
                if abs(val) < 1e-18:
                    continue
                M[(j, i)] = 2.0 * val
                lo = k * j - i
                c[lo] -= val
        for i in range(1, k, 2):
            if i < len(c) and abs(c[i]) >= 1e-18:
                M[(0, i)] = c[i]
        return M

    def cmp_cheb_bsgs(self, diff_ct, deg=511, pscale=2**30, amplitude=1.0,
                      coeff_mode="cheb", norm_pscale=None):
        """Degree-511 Chebyshev sign comparator. Returns sign approx in [-1,1]."""
        # x = diff/512; one plaintext multiplication/rescale.
        if norm_pscale is None:
            x_ct = self.mul_plain_rescale(diff_ct, 1.0 / 512.0)
        else:
            x_ct = self.mul_plain_rescale_to(diff_ct, 1.0 / 512.0, norm_pscale, SCALE)
        co = self.get_sign_coeffs(deg, amplitude=amplitude, coeff_mode=coeff_mode)
        dkey = (coeff_mode, int(deg), float(amplitude), 32, deg // 32 + 1)
        if dkey not in self.decomp_cache:
            self.decomp_cache[dkey] = self.decompose_cheb_coeffs(co, 32, deg // 32 + 1)
        M = self.decomp_cache[dkey]
        memo = {1: self.copy(x_ct)}
        # Precompute needed baby and giant Chebyshev terms.
        babies = {i: self.cheb_T(i, x_ct, memo) for i in range(1, 32, 2)}
        giants = {j: self.cheb_T(32 * j, x_ct, memo) for j in range(1, deg // 32 + 1)}
        pieces = []
        for j in range(0, deg // 32 + 1):
            terms = [(M.get((j, i), 0.0), babies[i]) for i in range(1, 32, 2)]
            sj = self.lincomb_plain_low(terms, pscale, pscale)
            if j == 0:
                pieces.append(sj)
            else:
                pieces.append(self.mul_ct(sj, giants[j]))
        acc = pieces[0]
        for p in pieces[1:]:
            acc = self.add(acc, p)
        return acc

    def sharpen_sign(self, y_ct):
        """Apply g(y)=(3y-y^3)/2 for composite sign approximation.

        Division by 2 is done by doubling CKKS scale metadata; this avoids a
        plaintext multiply/rescale and preserves depth.
        """
        y2 = self.mul_ct(y_ct, y_ct)
        y3 = self.mul_ct(y2, y_ct)
        three_y = self.add(self.add(y_ct, y_ct), y_ct)
        out = self.sub(three_y, y3)
        out.scale = float(out.scale) * 2.0
        return out

    def scale_value_metadata(self, ct, c: float):
        """Return a copy whose decoded value is multiplied by c via scale metadata."""
        out = self.copy(ct)
        out.scale = float(out.scale) / float(c)
        return out

    def mul_int(self, ct, n: int):
        if n == 0:
            return self.const_like(ct, 0.0)
        neg = n < 0
        n = abs(n)
        acc = None
        cur = self.copy(ct)
        while n:
            if n & 1:
                acc = cur if acc is None else self.add(acc, cur)
            n >>= 1
            if n:
                cur = self.add(cur, cur)
        if neg:
            out = sealapi.Ciphertext()
            self.evaluator.negate(acc, out)
            return out
        return acc

    def sharpen_f7(self, y_ct):
        """Degree-7 Cheon f: (35y -35y^3 +21y^5 -5y^7)/16.

        Uses only integer linear combinations plus scale metadata division.
        """
        y2 = self.mul_ct(y_ct, y_ct)
        y3 = self.mul_ct(y2, y_ct)
        y4 = self.mul_ct(y2, y2)
        y5 = self.mul_ct(y4, y_ct)
        y7 = self.mul_ct(y4, y3)
        acc = self.mul_int(y_ct, 35)
        acc = self.add(acc, self.mul_int(y3, -35))
        acc = self.add(acc, self.mul_int(y5, 21))
        acc = self.add(acc, self.mul_int(y7, -5))
        acc.scale = float(acc.scale) * 16.0
        return acc

    def sharpen_f7_num(self, y_ct):
        """Return the numerator 35y -35y^3 +21y^5 -5y^7.

        This avoids the final metadata division by 16, keeping scale at 2^40.
        The caller can sum numerators and apply the combined affine
        (sum_num + 16*(N-1)) / 32 at the end. This is much friendlier for
        adding the affine constant at the last modulus level.
        """
        y2 = self.mul_ct(y_ct, y_ct)
        y3 = self.mul_ct(y2, y_ct)
        y4 = self.mul_ct(y2, y2)
        y5 = self.mul_ct(y4, y_ct)
        y7 = self.mul_ct(y4, y3)
        acc = self.mul_int(y_ct, 35)
        acc = self.add(acc, self.mul_int(y3, -35))
        acc = self.add(acc, self.mul_int(y5, 21))
        acc = self.add(acc, self.mul_int(y7, -5))
        return acc

    def cmp_cheb_direct_low(self, diff_ct, deg=511, pscale=2**20, amplitude=1.0):
        """Direct Chebyshev-basis evaluation with low-scale plaintext coeffs.

        This is slower/more memory-heavy than BSGS, but it avoids the extra
        final S_j*T_giant multiplication at the end of the modulus chain, making
        it a useful local feasibility test.
        """
        x_ct = self.mul_plain_rescale(diff_ct, 1.0 / 512.0)
        co = self.cheb_sign_coeffs(deg, amplitude=amplitude)
        memo = {1: self.copy(x_ct)}
        acc = None
        for i in range(1, deg + 1, 2):
            if abs(co[i]) < max(1e-14, 0.5 / float(pscale)):
                continue
            ti = self.cheb_T(i, x_ct, memo)
            term = self.mul_plain_norescale(ti, float(co[i]), pscale)
            if acc is None:
                acc = term
            else:
                acc = self.add(acc, term)
        return acc

    def rank0_cheb(self, chaos_ct):
        vr = self.copy(chaos_ct)
        row0 = self.mask(chaos_ct, "row0")
        vc = self.repl_c(self.trans_r(row0))
        d = self.sub(vr, vc)
        s = self.cmp_cheb_bsgs(d, 511)   # sign matrix: -1,0,+1
        summed = self.sum_r(s)           # sum signs column-wise in first row slots
        # rank = (sum_signs + (N-1)) / 2 ; diagonal sign(0)=0.
        v = self.as_vec(summed)
        return self.from_vec((v + float(N - 1)) * 0.5)

    def rank0_cheb_direct(self, chaos_ct):
        vr = self.copy(chaos_ct)
        row0 = self.mask(chaos_ct, "row0")
        vc = self.repl_c(self.trans_r(row0))
        d = self.sub(vr, vc)
        s = self.cmp_cheb_direct_low(d, 511, 4)
        summed = self.sum_r(s)
        # For direct-low, scale is ~2^60. Add plaintext (N-1) at same scale,
        # then multiply by 0.5 with plaintext scale 1 (no level consumption).
        shifted = self.add_plain_const(summed, float(N - 1))
        half = sealapi.Plaintext()
        self.encoder.encode(0.5, shifted.parms_id(), 1.0, half)
        out = sealapi.Ciphertext()
        self.evaluator.multiply_plain(shifted, half, out)
        return out

    def affine_rank_from_sign_sum(self, sign_sum_ct):
        # rank = (sum_j sign(x_i-x_j) + (N-1)) / 2, j excludes self.
        # At the very last CKKS level f7 leaves scale=2^44. Encoding +127 in
        # one plaintext overflows the remaining 50-bit prime, but small chunks
        # (<=8) fit. Add 127 as 15*8+7, then divide by 2 via scale metadata.
        shifted = self.copy(sign_sum_ct)
        remain = N - 1
        while remain:
            c = min(8, remain)
            shifted = self.add_plain_const(shifted, float(c))
            remain -= c
        shifted.scale = float(shifted.scale) * 2.0
        return shifted

    def affine_rank_from_f7_num_sum(self, num_sum_ct):
        # f7_num = 16*sign_approx, so
        # rank = (sum(f7_num)/16 + (N-1)) / 2
        #      = (sum(f7_num) + 16*(N-1)) / 32.
        shifted = self.copy(num_sum_ct)
        remain = 16 * (N - 1)
        while remain:
            # At the final chain level even scale=2^40 cannot encode large
            # plaintext constants reliably. Use tiny chunks; additions do not
            # consume levels, so this only costs a little time and avoids
            # "encoded value is too large".
            c = min(8, remain)
            shifted = self.add_plain_const(shifted, float(c))
            remain -= c
        shifted.scale = float(shifted.scale) * 32.0
        return shifted

    def indicator_from_f7_num(self, num_ct):
        """Map one f7 numerator comparison to an indicator in [0, 1].

        num_ct is approximately 16*sign(x-y), at scale 2^40.  Instead of
        summing 127 signed numerators and trying to add a huge final offset,
        do the affine transform per comparison:

            indicator = (num + 16) / 32

        Then the final rank is just sum_j indicator_j, whose magnitude is at
        most 127 and fits the last 50-bit modulus at scale 2^40.
        """
        shifted = self.add_plain_const(num_ct, 16.0)
        return self.mul_plain_rescale(shifted, 1.0 / 32.0)

    def indicator_from_sign_norescale(self, sign_ct):
        """Map a sign approximation to an indicator without consuming a level.

        indicator = (sign + 1) / 2.  The +1 plaintext is safe before summation
        (scale 2^40 at level >=1), and division by two is represented by
        doubling CKKS scale metadata instead of multiplying by plaintext 0.5.
        This is the key depth-saving change: degree-511 comparison can end at
        coeff_modulus_size=2 and still be converted to [0,1] before summing.
        """
        shifted = self.add_plain_const(sign_ct, 1.0)
        shifted.scale = float(shifted.scale) * 2.0
        return shifted

    def rank0_shift_cheb(self, chaos_ct, deg=511, verbose=False):
        """1D shift-and-compare ranking from advance.md.

        Chaos is TenSEAL's repeated [Base]*128 packing. For each shift j,
        D_j[i] = x_i - x_{i+j}; summing sign(D_j) across j gives the rank.
        This avoids MaskR/TransR/ReplC and feeds the comparator at top level.
        """
        rank_sign_sum = None
        cur = self.copy(chaos_ct)
        for j in range(1, N):
            cur = self.rotate_left(cur, 1)
            d = self.sub(chaos_ct, cur)
            s = self.cmp_cheb_bsgs(d, deg)
            rank_sign_sum = s if rank_sign_sum is None else self.add(rank_sign_sum, s)
            if verbose and (j <= 3 or j % 16 == 0 or j == N - 1):
                print(f"[shift] {j}/{N-1} level={rank_sign_sum.coeff_modulus_size()} scale={rank_sign_sum.scale}", flush=True)
        return self.affine_rank_from_sign_sum(rank_sign_sum)

    def rank0_shift_direct_indicator(self, chaos_ct, deg=511, pscale=SCALE,
                                     amplitude=1.0, coeff_mode="cheb",
                                     verbose=False):
        """1D shift-and-compare ranking with direct per-comparison indicators.

        This path completes the comparison under the available CKKS depth:
        - evaluate a high-degree Chebyshev/minimax sign approximation;
        - immediately convert each comparison to an indicator via metadata
          division, avoiding the final huge signed-sum affine offset;
        - sum 127 small [0,1]-like ciphertexts to obtain the rank.

        In plaintext simulation, deg=511 with coeff_mode="cheb" keeps the
        accumulated rank error below round()'s 0.5 threshold on random Base
        samples, while avoiding the unavailable f7-indicator rescale.
        """
        rank_sum = None
        cur = self.copy(chaos_ct)
        for j in range(1, N):
            cur = self.rotate_left(cur, 1)
            d = self.sub(chaos_ct, cur)
            s = self.cmp_cheb_bsgs(
                d, deg=deg, pscale=pscale, amplitude=amplitude,
                coeff_mode=coeff_mode,
            )
            ind = self.indicator_from_sign_norescale(s)
            rank_sum = ind if rank_sum is None else self.add(rank_sum, ind)
            if verbose and (j <= 3 or j % 16 == 0 or j == N - 1):
                print(
                    f"[direct-ind] {j}/{N-1} "
                    f"level={rank_sum.coeff_modulus_size()} scale={rank_sum.scale}",
                    flush=True,
                )
        return rank_sum

    def rank0_matrix_direct_indicator(self, chaos_ct, deg=399, pscale=SCALE,
                                      amplitude=1.0, coeff_mode="cheb",
                                      verbose=False):
        """Matrix ranking path: do all 128x128 comparisons in one ciphertext.

        TenSEAL stores the 128-value challenge repeated across all CKKS slots.
        Interpreting the first 16384 slots as a 128x128 matrix:

          vr[row, col] = Base[col]
          vc[row, col] = Base[row]
          d             = vr - vc

        Then indicator(sign(d)) is 1 iff Base[col] > Base[row]. Summing down
        rows gives rank(Base[col]) in the first row.  The diagonal contributes
        0.5 because sign(0) ~= 0, so subtract 0.5 at the end.

        This costs two setup plaintext-mul levels (row masks) but only ONE
        high-degree comparator instead of 127. It therefore needs a Galois key
        containing power-of-two rotations up to 8192, not just 1..64.
        """
        if verbose:
            print(
                f"[matrix] start level={chaos_ct.coeff_modulus_size()} "
                f"scale={chaos_ct.scale}",
                flush=True,
            )
        # Hybrid matrix setup: the first row0 mask uses the normal rescaled
        # TenSEAL path for accuracy. The final col0 mask is a sparse 0/1 mask;
        # doing it with a full rescale costs the one level that prevents a
        # high-degree comparator.  Use a no-rescale plaintext mask at scale
        # 2^20 (large enough to avoid sparse-mask quantization noise), lift vr
        # by the same plaintext scale, and compensate in the comparator's
        # initial diff/512 normalization with norm_pscale = 2^20.
        mask_pscale = 2.0 ** 20
        vr = self.mul_plain_norescale(self.copy(chaos_ct), 1.0, pscale=mask_pscale)
        row0 = self.mask(chaos_ct, "row0")
        if verbose:
            print(f"[matrix] row0 level={row0.coeff_modulus_size()} scale={row0.scale}", flush=True)
        vc = self.repl_c(self.trans_r_norescale(row0, mask_pscale=mask_pscale))
        d = self.sub(vr, vc)
        if verbose:
            print(f"[matrix] diff level={d.coeff_modulus_size()} scale={d.scale}", flush=True)
        s = self.cmp_cheb_bsgs(
            d, deg=deg, pscale=pscale, amplitude=amplitude,
            coeff_mode=coeff_mode, norm_pscale=SCALE / mask_pscale,
        )
        if verbose:
            print(f"[matrix] sign level={s.coeff_modulus_size()} scale={s.scale}", flush=True)
        ind = self.indicator_from_sign_norescale(s)
        summed = self.sum_r(ind)
        # Remove the diagonal's 0.5 contribution.  This is small enough to
        # encode safely even when the indicator metadata scale is 2*SCALE.
        out = self.add_plain_const(summed, -0.5)
        if verbose:
            print(f"[matrix] rank level={out.coeff_modulus_size()} scale={out.scale}", flush=True)
        return out

    def rank0_shift_direct_indicator_range(self, chaos_ct, j_start: int, j_end: int,
                                           deg=511, pscale=SCALE,
                                           amplitude=1.0, coeff_mode="cheb",
                                           verbose=False, tag="worker"):
        """Partial rank sum for shifts j_start..j_end inclusive.

        This is the parallelization unit.  The full rank is the sum of all
        disjoint partial sums over j=1..127.
        """
        if not (1 <= j_start <= j_end <= N - 1):
            raise ValueError((j_start, j_end))
        rank_sum = None

        # Prepare cur = rotate(chaos, j_start-1), then each loop advances by 1.
        cur = self.copy(chaos_ct)
        if j_start > 1:
            cur = self.rotate_left(cur, j_start - 1)

        for j in range(j_start, j_end + 1):
            cur = self.rotate_left(cur, 1)
            d = self.sub(chaos_ct, cur)
            s = self.cmp_cheb_bsgs(
                d, deg=deg, pscale=pscale, amplitude=amplitude,
                coeff_mode=coeff_mode,
            )
            ind = self.indicator_from_sign_norescale(s)
            rank_sum = ind if rank_sum is None else self.add(rank_sum, ind)
            if verbose and (j == j_start or j == j_end or j % 16 == 0):
                print(
                    f"[{tag}] shift {j}/{N-1} "
                    f"level={rank_sum.coeff_modulus_size()} scale={rank_sum.scale}",
                    flush=True,
                )
        return rank_sum

    def rank0_shift_composite(self, chaos_ct, deg=159, rounds=1, pscale=SCALE, prescale=1.0, mode="f7", amplitude=1.0, verbose=False):
        """1D shift-and-compare with Chebyshev coarse comparator + sharpening."""
        rank_sign_sum = None
        cur = self.copy(chaos_ct)
        for j in range(1, N):
            cur = self.rotate_left(cur, 1)
            d = self.sub(chaos_ct, cur)
            s = self.cmp_cheb_bsgs(d, deg, pscale=pscale, amplitude=amplitude)
            if prescale != 1.0:
                s = self.scale_value_metadata(s, prescale)
            for _ in range(rounds):
                if mode == "f7":
                    s = self.sharpen_f7(s)
                elif mode in ("f7num", "f7ind"):
                    s = self.sharpen_f7_num(s)
                else:
                    s = self.sharpen_sign(s)
            if mode == "f7ind" and rounds == 1:
                s = self.indicator_from_f7_num(s)
            rank_sign_sum = s if rank_sign_sum is None else self.add(rank_sign_sum, s)
            if verbose and (j <= 3 or j % 16 == 0 or j == N - 1):
                print(f"[comp] {j}/{N-1} level={rank_sign_sum.coeff_modulus_size()} scale={rank_sign_sum.scale}", flush=True)
        if mode == "f7ind" and rounds == 1:
            return rank_sign_sum
        if mode == "f7num" and rounds == 1:
            return self.affine_rank_from_f7_num_sum(rank_sign_sum)
        return self.affine_rank_from_sign_sum(rank_sign_sum)

    def rank0(self, chaos_ct):
        # TenSEAL encodes a short CKKSVector by repeating it across all slots.
        # Thus the challenge ciphertext is already VR (the row replicated
        # matrix).  For VC we first isolate one row, then transpose+replicate.
        vr = self.copy(chaos_ct)
        row0 = self.mask(chaos_ct, "row0")
        vc = self.repl_c(self.trans_r(row0))
        d = self.sub(vr, vc)
        c = self.cmp_poly(d)
        r = self.sum_r(c)
        # diagonal contributes 0.5; challenge wants zero-indexed #strictly-less
        return self.from_vec(self.as_vec(r) - [0.5] * SLOTS)


def load_public_context(path="pubkey/ctx.public"):
    return ts.context_from(open(path, "rb").read())


def extract_ct_from_challenge_b64(ctx, line_b64: str):
    data = base64.b64decode(line_b64.strip())
    v = ts.ckks_vector_from(ctx, data)
    return v.data.ciphertext()[0]


def _solve_range_worker(args):
    (challenge_b64, ctx_path, gk_path, j_start, j_end, deg,
     amplitude, coeff_mode, verbose, tag) = args
    ctx = load_public_context(ctx_path)
    he = HE(ctx, gk_path)
    chaos = extract_ct_from_challenge_b64(ctx, challenge_b64)
    part = he.rank0_shift_direct_indicator_range(
        chaos,
        j_start,
        j_end,
        deg=deg,
        pscale=SCALE,
        amplitude=amplitude,
        coeff_mode=coeff_mode,
        verbose=verbose,
        tag=tag,
    )
    return j_start, j_end, ct_save_bytes(part)


def split_ranges(start: int, end: int, jobs: int):
    total = end - start + 1
    jobs = max(1, min(int(jobs), total))
    base, rem = divmod(total, jobs)
    out = []
    cur = start
    for i in range(jobs):
        n = base + (1 if i < rem else 0)
        out.append((cur, cur + n - 1))
        cur += n
    return out


def solve_once(
    challenge_b64: str,
    ctx_path="pubkey/ctx.public",
    gk_path="galois_pos.key",
    deg: int = 511,
    amplitude: float = 1.0,
    coeff_mode: str = "cheb",
    verbose: bool = True,
    jobs: int = 1,
    method: str = "shift",
) -> bytes:
    ctx = load_public_context(ctx_path)
    if method == "matrix":
        he = HE(ctx, gk_path)
        chaos = extract_ct_from_challenge_b64(ctx, challenge_b64)
        ans = he.rank0_matrix_direct_indicator(
            chaos, deg=deg, pscale=SCALE, amplitude=amplitude,
            coeff_mode=coeff_mode, verbose=verbose,
        )
    elif jobs and jobs > 1:
        ranges = split_ranges(1, N - 1, jobs)
        if verbose:
            print(f"[*] parallel jobs={jobs} ranges={ranges}", flush=True)
        tasks = [
            (challenge_b64, ctx_path, gk_path, a, b, deg, amplitude,
             coeff_mode, verbose, f"job{i}:{a}-{b}")
            for i, (a, b) in enumerate(ranges)
        ]
        partials = []
        with ProcessPoolExecutor(max_workers=len(tasks)) as ex:
            futs = [ex.submit(_solve_range_worker, t) for t in tasks]
            for fut in as_completed(futs):
                a, b, raw = fut.result()
                if verbose:
                    print(f"[*] partial done {a}-{b} bytes={len(raw)}", flush=True)
                partials.append((a, b, raw))
        partials.sort()

        he = HE(ctx, gk_path)
        ctxdata = ctx.seal_context().data
        acc = None
        for a, b, raw in partials:
            ct = ct_load_bytes(ctxdata, raw)
            acc = ct if acc is None else he.add(acc, ct)
        ans = acc
    else:
        he = HE(ctx, gk_path)
        chaos = extract_ct_from_challenge_b64(ctx, challenge_b64)
        # Final path: use a high-degree direct sign comparator and convert each
        # comparison to an indicator before summation. This avoids the terminal
        # f7-indicator rescale and the huge final signed-sum offset.
        ans = he.rank0_shift_direct_indicator(
            chaos, deg=deg, pscale=SCALE, amplitude=amplitude,
            coeff_mode=coeff_mode, verbose=verbose,
        )
    return ct_save_bytes(ans)


def remote(host: str, port: int):
    ctx = load_public_context()
    he = HE(ctx, "galois_pos.key")
    with socket.create_connection((host, port), timeout=30) as s:
        f = s.makefile("rwb", buffering=0)
        first = f.readline().strip()
        # Service prints one base64 line before the prompt.
        chaos = extract_ct_from_challenge_b64(ctx, first.decode())
        ans = he.rank0_shift_direct_indicator(
            chaos, deg=511, pscale=SCALE, amplitude=1.0,
            coeff_mode="cheb", verbose=True,
        )
        payload = base64.b64encode(ct_save_bytes(ans)) + b"\n"
        f.write(payload)
        out = f.read().decode(errors="replace")
        print(out)


if __name__ == "__main__":
    if len(sys.argv) == 3:
        remote(sys.argv[1], int(sys.argv[2]))
    else:
        b64 = sys.stdin.readline().strip()
        sys.stdout.write(base64.b64encode(solve_once(b64)).decode() + "\n")
