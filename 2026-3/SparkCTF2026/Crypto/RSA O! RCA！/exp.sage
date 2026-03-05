from Crypto.Util.number import *
import random
from sympy import prime
from sage.all import *

n=17853573899076341181096267567874616214556285809566419320975211748455658403574952424384450961122059841394637349769390646220566170958316752370568080811
enc=14134528243637339528516880595615017358007046031917320457849840313575913728415212293709028402353118219198627787035921516021202481286846551245272653155

def primorial(num):
    result = 1
    for i in range(1, num + 1):
        result *= prime(i)
    return result

M = primorial(39)
# print M in hex 
print(M)
print(f"M: {hex(M)}")
# M 220 bits

# p % M = pow(e, a, M)
# q % M = pow(e, b, M)
# n % M = pow(e, a+b, M)

# solve discrete log

e = 65537
sumA = discrete_log(Mod(n, M), Mod(e, M))
print(f'sumA: {sumA}')
print(f'sumA bit length: {sumA.nbits()}')

# calc ord _M 65537 
ordM = Mod(e, M).multiplicative_order()
print(f'ordM: {ordM}')
print(f'ordM bit length: {ordM.nbits()}') # 62
# assert pow(e,ordM,M) == 1

p=20492938434817723399296468206351320687527786407284800160725225515262948467
q=871206145271140159738069222201100389633539041626914343201479204781757664233
assert p*q == n
print(long_to_bytes(pow(enc, inverse_mod(e, (p-1)*(q-1)), n)))