from Crypto.Util.number import *
import random
from sympy import prime

FLAG=b'flag{????????????}'
e=0x10001

def primorial(num):
    result = 1
    for i in range(1, num + 1):
        result *= prime(i)
    return result
M=primorial(random.choice([39,71,126]))

def gen_key():
    while True:
        k = random.getrandbits(30)
        a = random.getrandbits(50)
        p = k * M + pow(e, a, M)
        if isPrime(p):
            return p

p,q=gen_key(),gen_key()
n=p*q
m=bytes_to_long(FLAG)
enc=pow(m,e,n)

print(f'{n=}')
print(f'{enc=}')

"""
n=17853573899076341181096267567874616214556285809566419320975211748455658403574952424384450961122059841394637349769390646220566170958316752370568080811
enc=14134528243637339528516880595615017358007046031917320457849840313575913728415212293709028402353118219198627787035921516021202481286846551245272653155
"""
