FLAG = b"actf{redacted}"
while (p:=random_prime(2**512))%4 != 3:
    continue
q = random_prime(2**512)
K = QuadraticField(-p, 'w')
R = RealField(2333)
ΔΚ, Δq = -p, -p*q**2
OK = K.maximal_order()
Oq = K.order([1, (Δq+q*K.gen())/2])

token = os.urandom(45)
α = OK.ideal(int(token[:30].hex(),16)+\
             int(token[30:].hex(),16)*K.gen())

a, b, c = list(α.quadratic_form())
A, B = a, b*q%(2*a)
if B >= a: B -= 2*a
h = Oq.ideal([A, (-B + q*K.gen())/2]).quadratic_form()
ζ = list(h.reduced_form())[:2]; ζ[0] >>= 360
λ = f"{R(-Δq).sqrt():.470f}".split('.')[1]

if bytes.fromhex(input(f"{ζ, λ}\n[token]: ")) == token:
    print("^_^ >🚩", FLAG)