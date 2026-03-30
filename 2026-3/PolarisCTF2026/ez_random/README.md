# ez_random

## 核心识别

这题最有价值的点不是直接从 `B0/B1` 硬恢复完整 MT19937 状态，而是先把 `option 2` 变成顺序恢复 oracle。

原因是提交的第 `k` 个输入会进入 `random_prime(x_k xor (a_k xor limit_k))`。如果让提交值恰好等于真实的 `a_k`，内部参数就会变成 `0`，被改过的 `random_prime(0)` 会直接异常。于是远程就泄露了一个严格的等值 oracle，可以逐位恢复被 `shuffle` 打乱后的 `Key Part A` 顺序。

顺序恢复完之后，真正要逆的是 Python `Random` 的 128-bit seeding 流程，而不是任意 19968-bit MT 内部状态。用 `MTAgain` 那套 `S -> I -> J -> K` 逆链恢复 4 个 32-bit limb，就能把整条随机流完整重放，最终拿到最后那次 `getrandbits(256)` 生成的 AES key。

## 最短解链

1. 用 `option 1` 抓一份 `A/B0/B1`。
2. 用 `option 2` 的崩溃行为逐个恢复 `A` 的真实顺序。
3. 从有序 `A` 和 `B1` 中提取足够多的 MT 观测词，逆出 Python 的 128-bit seed。
4. 本地完整重放随机流，恢复最后的 `r`。
5. 用 `SHA256(str(r))` 作为 AES key，解出 flag。

## 归档文件

- `solve.py`：自包含 exploit，内联了需要的 MTAgain 辅助函数，不再依赖外部目录。

## Flag

`XMCTF{a649c39e-fd53-4f68-8791-3ea4c1bec9f9}`
