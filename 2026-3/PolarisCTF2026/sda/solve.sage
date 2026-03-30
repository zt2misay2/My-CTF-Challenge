from sage.all import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util.number import long_to_bytes
import hashlib

A1 = 234110215243875326749544596075512335544257
B1 = 68765596672109672407420253033782942222910
A2 = 636185906634748653451789798738597280632127
B2 = 131860738134887128678021271054606611917493
A3 = 905712574946398586494048707872100065355613
B3 = 197958111431918701470218006359610095848736

As = [A1, A2, A3]
Bs = [B1, B2, B3]

ct_hex = "93192f46a00b2dade984ca758706b00681263a8536d8051aff0206d257ce4c2aad6bc017138d4c7aeaed5c8fc2c1ea2f3cec3fbd9201bb5844fa8143d6630944"
raw = bytes.fromhex(ct_hex)
iv, ciphertext = raw[:16], raw[16:]


def factor_phi(A):
    fac = factor(A)
    p = ZZ(fac[0][0])
    q = ZZ(fac[1][0])
    return p, q, (p - 1) * (q - 1)


def bound_constant(A, p, q):
    if p > q:
        p, q = q, p
    R = RealField(200)
    return (R(q - p) / (3 * R(p + q))) * (R(A) ** (R(1) / 4))


params = [factor_phi(A) for A in As]
phis = [phi for _, _, phi in params]
Cs = [bound_constant(A, p, q) for A, (p, q, _) in zip(As, params)]

print("[*] phis =", phis)
print("[*] error constants =", Cs)

# The lattice encodes:
#   phi_i * v + z_i = k_i * B_i
# with |z_i| < C_i * v.
# A vector (W_i * z_i, ..., v) becomes short after scaling W_i ~= 1 / C_i.
F = ZZ(2) ** 64
Ws = [ZZ(floor(F / c)) for c in Cs]

L = Matrix(ZZ, 4, 4)
for i in range(3):
    L[i, i] = Bs[i] * Ws[i]
    L[3, i] = phis[i] * Ws[i]
L[3, 3] = 1

print("[*] weights =", Ws)
print("[*] running LLL on 4D lattice")
red = L.LLL()


def try_candidate(v):
    if v <= 0:
        return None

    us = []
    zs = []
    for i in range(3):
        ui = ZZ(round(RealField(200)(phis[i]) * RealField(200)(v) / RealField(200)(Bs[i])))
        zi = Bs[i] * ui - phis[i] * v
        if abs(zi) >= Cs[i] * v:
            return None
        us.append(ui)
        zs.append(zi)

    key_material = ZZ(v + us[0] * us[1] * us[2])
    key = hashlib.sha256(long_to_bytes(key_material)).digest()[:16]
    plain = AES.new(key, AES.MODE_CBC, iv).decrypt(ciphertext)
    try:
        plain = unpad(plain, 16)
    except ValueError:
        return None

    return us, zs, plain


seen = set()
for row in red.rows():
    for v in [ZZ(abs(row[3]))]:
        if v == 0 or v in seen:
            continue
        seen.add(v)
        result = try_candidate(v)
        if result is None:
            continue

        us, zs, plain = result
        print("[+] recovered v =", v)
        print("[+] recovered u_i =", us)
        print("[+] recovered z_i =", zs)
        print("[+] plaintext =", plain.decode())
        break
    else:
        continue
    break
else:
    print("[-] no valid candidate found in reduced basis")
