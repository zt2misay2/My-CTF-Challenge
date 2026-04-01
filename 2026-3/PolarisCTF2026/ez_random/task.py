import patcher
from sage.all import *
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad
from secret import SEED , flag

ROUNDS = 40
N_BITS = 988
N_PAIRS = 37
N = 2**31 - 1
get_limit =  lambda i:  N - (1 * N // 3) * (1 - 0**(i == 10))



for i in range(ROUNDS):
    t = input('🤔 Please give me an option > ')

    if t == '1':
        set_random_seed(int.from_bytes(SEED, 'big'))

        pairs = [(getrandbits(N_BITS), random_prime(get_limit(_))) for _ in range(1, N_PAIRS)]

        key0, key1 = map(list, zip(*pairs))


        shuffle(key0)
        print(f"Key Part A: {key0}")

        key1_list0 = [x[0] for x in key1]
        key1_list1 = [x[1] for x in key1]

        print(f"Key Part B{0}: {key1_list0}")
        print(f"Key Part B{1}: {key1_list1}")


    elif t == '2':
        set_random_seed(int.from_bytes(SEED, 'big'))

        for k in range(1, N_PAIRS):
            random_prime(int(input(f'😋 Give me the {k}th number: ')) ^ (getrandbits(N_BITS) ^ get_limit(k)))

        print("👏 Let's get the flag")
        SHA = SHA256.new()
        SHA.update(str(getrandbits(256)).encode())
        KEY = SHA.digest()
        cipher = AES.new(KEY, AES.MODE_ECB)
        flag = pad(flag.encode(), AES.block_size)
        print("Flag:", cipher.encrypt(flag))

    else:
        print("❌ Invalid input!")
        break
