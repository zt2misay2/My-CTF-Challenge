from Crypto.Util.number import isPrime
from sage.all import *
from hashlib import sha256
from tqdm import tqdm

E1 = 17599828213549223253832044274649684283770977196846184512551517947600728059
E2 = 13524024408490227176018717697716068955892095093578246398907145843636542721
N = 39857078746406469131129281921490520306196739933449401384580614683236877901453146754149222509812535866333862501431453065249306959004319408436548574942416212329735258587670686655658056553446879680643872518009328886406310298097685861873954727153720761248262606469217940464611561028443119183464419610396387619860313813067179519809796028310723320608528262638653826016645983671026819244220510314301178181698134390850683834304169240632402535087021483298892547974104858755498823118164815682452718215716370727477136888839954993949013970026988378086175471190518276414200966496353144747778470590767485019943178534397845127421058830430797806265311195099187747227867325234593386438995618936934586514932401108874934000734850169069717060963988677462779177959990601405850727404268354600078746523164279

print(f"isPrime(E1)={isPrime(E1)}")
print(f"isPrime(E2)={isPrime(E2)}")
print(f"N bits={N.bit_length()}")

M = E1 * E2
print(f"M bits={M.bit_length()}")

pl = ZZ(crt([1, N % E2], [E1, E2]))
print(f"p mod M: {pl}")

q2 = N % E1
q1_candidates = Mod(q2, E1).sqrt(all=True)
rq_candidates = sorted(
    set(ZZ(crt(ZZ(1), ZZ(int(q1)), ZZ(E2), ZZ(E1))) for q1 in q1_candidates)
)
print(f"rq candidates: {len(rq_candidates)}")

for rq in rq_candidates:
    assert (rq - 1) % E2 == 0
    assert pow(rq, 2, E1) == q2 % E1

R.<x> = PolynomialRing(Zmod(N))

def try_single(rq, qbit=870, beta=2/3 - 0.1, eps=0.05):
    K = 2 ** (qbit - M.nbits())
    f = (x * M + rq) ** 2
    roots = f.monic().small_roots(X=K, beta=beta, epsilon=eps)
    return K, [ZZ(r) for r in roots]

found = False
for rq in tqdm(rq_candidates):
    K, roots = try_single(rq)
    if roots:
        print(f"[+] rq={rq}")
        print(f"[+] K={K}")
        print(f"[+] roots={roots}")
    for k in roots:
        if k < 0:
            continue
        q = k * M + rq
        if q <= 0:
            continue
        q2v = q * q
        if N % q2v != 0:
            continue
        p = N // q2v
        if p * q2v != N:
            continue
        print(f"[+] hit! k={k}")
        print(f"[+] p bits={p.nbits()}, q bits={q.nbits()}")
        print(f"[+] isPrime(p)={isPrime(p)}, isPrime(q)={isPrime(q)}")
        digest = sha256(str(q).encode()).hexdigest()
        print(f"[+] flag: r3ctf{{{digest}}}")
        found = True
        break
    if found:
        break

if not found:
    print("[-] not found with default params, start quick param sweep.")
    qbits = range(864, 881)
    betas = [0.52, 0.54, 0.56, 0.58, 0.60]
    for qbit in qbits:
        for beta in betas:
            print(f"[*] trying qbit={qbit}, beta={beta}")
            for rq in rq_candidates:
                K = 2 ** (qbit - M.nbits())
                f = (x * M + rq) ** 2
                roots = f.monic().small_roots(X=K, beta=beta, epsilon=0.05)
                for r in roots:
                    k = ZZ(r)
                    if k < 0:
                        continue
                    q = k * M + rq
                    if q <= 0:
                        continue
                    q2v = q * q
                    if N % q2v != 0:
                        continue
                    p = N // q2v
                    print(f"[+] hit! qbit={qbit}, beta={beta}, k={k}")
                    print(f"[+] p bits={p.nbits()}, q bits={q.nbits()}")
                    print(f"[+] isPrime(p)={isPrime(p)}, isPrime(q)={isPrime(q)}")
                    digest = sha256(str(q).encode()).hexdigest()
                    print(f"[+] flag: r3ctf{{{digest}}}")
                    raise SystemExit(0)
    print("[-] sweep finished, still no hit.")
