from pwn import *

io = remote("114.66.24.221", 40637)
seed = io.recvline_startswith(b"Here is my seed: ").strip().split(b": ")[1]
seed = int(seed)
print("Original seed:", seed)

K = []
temp = seed
for _ in range(4):
    K.append(temp & 0xffffffff)
    temp >>= 32
K_prime = []
for i in range(8):
    if i < 4:
        K_prime.append(K[i])
    else:
        K_prime.append((K[i - 4] - 4) & 0xffffffff)
new_seed = 0
for i in range(8):
    new_seed |= (K_prime[i] << (32 * i))

io.sendlineafter(b"Give me your seed: ", str(new_seed).encode())
io.interactive()
'''
[+] Opening connection to 114.66.24.221 on port 40637: Done
Original seed: 200703692074314762824726492312521959737
revenge seed is:
[*] Switching to interactive mode
68295927280979238419361521959980240335781165199549622724694722589059674040633
Congratulations!! Here is your flag:
flag{57f5a69f-d448-4583-a0d9-5391355fd429}
'''