from pwn import *

io = remote("114.66.24.221", 49296)
print(io.recvall(timeout=1).decode())