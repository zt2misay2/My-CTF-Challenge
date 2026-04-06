# RNG-GAME

## 题目信息

- 题目名: RNG-GAME
- 交互端口: `114.66.24.221:33162`
- 题面核心:
  - 服务端给出 Alice 使用过的随机数种子 `seed`
  - 需要提交一个不同的种子
  - 但这个不同种子要能生成相同的随机数

## 先从黑盒现象反推

服务端交互大致如下:

```text
Welcome RNG GAME!!

In this game, I'll give you a seed that I used to generate a random number, and you need to give me a different seed that can generate the same random number. If you can do it, you will get the flag!!

Here is my seed: 11699632797685506822033299566007753128
Give me your seed:
```

### 1. 先排除字符串比较

如果直接发送这些形式:

- `0<seed>`
- `+<seed>`
- ` <seed>`

服务端会返回:

```text
Don't use the same seed!!
```

这说明服务端不是按字符串判断是否相同，而是先把输入解析成整数，再比较数值是否相同。也就是类似:

```python
your_seed = int(input())
if your_seed == alice_seed:
    print("Don't use the same seed!!")
```

### 2. 排除低位截断

尝试发送:

- `seed mod 2^32`
- `seed mod 2^64`

都只会得到:

```text
Game over!!
```

所以它不像 C 语言里 `srand((unsigned)seed)` 那种只看低 32 位或低 64 位的实现。

### 3. 发送负数种子可以成功

如果服务端给出的种子是:

```text
11699632797685506822033299566007753128
```

发送:

```text
-11699632797685506822033299566007753128
```

会直接得到 flag。

这说明题目的真正漏洞是:

> 两个不同的整数种子 `s` 和 `-s`，在服务端使用的 PRNG 初始化逻辑下，会导向同一个随机状态。

## 远端大概的比较思路

综合上面的现象，服务端大概率是下面这种流程:

```python
import random

alice_seed = ...
print(f"Here is my seed: {alice_seed}")

your_seed = int(input("Give me your seed: "))

if your_seed == alice_seed:
    print("Don't use the same seed!!")
    exit()

r1 = random.Random()
r1.seed(alice_seed)
x = r1.getrandbits(64)

r2 = random.Random()
r2.seed(your_seed)
y = r2.getrandbits(64)

if x == y:
    print(flag)
else:
    print("Game over!!")
```

它也可能比较的是 `random()`、`randint()`，甚至不止一个输出，但这不影响攻击，因为只要初始化状态相同，后续整条随机序列都相同。

## 漏洞原理

这题大概率使用的是 Python 的 `random` 模块。

本地可以直接验证:

```python
import random

r1 = random.Random()
r1.seed(123)

r2 = random.Random()
r2.seed(-123)

print(r1.getrandbits(64))
print(r2.getrandbits(64))
```

输出相同。

也就是说:

```python
random.seed(s)
random.seed(-s)
```

会把 PRNG 初始化到同一个状态。因此:

- `s != -s`
- 但 `PRNG(s)` 和 `PRNG(-s)` 后续输出完全一致

题目要求的是:

- 你的种子必须和 Alice 的种子不同
- 但生成的随机数要相同

于是直接提交 `-seed` 就满足要求。

## 利用方法

当服务端给出:

```text
Here is my seed: S
```

直接发送:

```text
-S
```

即可。

## 最小利用脚本

```python
from pwn import *
import re

HOST = "114.66.24.221"
PORT = 33162

io = remote(HOST, PORT)
banner = io.recvuntil(b"Give me your seed: ").decode()

seed = re.search(r"Here is my seed: (\d+)", banner).group(1)
io.sendline(("-" + seed).encode())

print(io.recvall(timeout=2).decode())
```

## 结论

这题不是把种子拆段后拼接碰撞，也不是低位截断。

核心是 Python `random.seed(int)` 对整数种子的处理方式导致:

- 正整数 `s`
- 负整数 `-s`

虽然数值不同，但会生成相同的随机状态，因此整条随机数序列都一致。

所以最终攻击就是:

```text
answer = -alice_seed
```
