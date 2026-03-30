# ocean

## 核心识别

两条寄存器链共享同一个 `seed`，这是整题能被拆开的原因。

`lfsr1` 产生控制位，`lfsr2` 只有在控制位为 `1` 时才更新，因此公开输出不是简单的线性序列，而是“隐藏路径 + 线性观测”。真正的隐藏变量不是每一位控制位本身，而是累计更新次数 `m_t`。

一旦换成“按 value-run / chunk 枚举总更新次数”，很多结构化约束都能重新压回 `GF(2)`：

- 输出翻转必然意味着当前控制位是 `1`
- 每个 chunk 的更新次数有 exact-count 约束
- parity、边界强制位、`rows2` 前缀上界都能做前剪枝
- 小 pattern family 的交集还能提炼出额外线性不变量

最终做法不是 SMT 或 Gr\"obner，而是定制的 `GF(2)` 增量消元 + beam + DFS 搜索。

## 最短解链

1. 预计算 `mask1`、`mask2` 对应的线性观测行。
2. 把输出切成 value-run，再切成更小的 chunk。
3. 对每个 chunk 枚举总更新次数，而不是逐时刻枚举控制位。
4. 把翻转、parity、exact-count、prefix cap 等约束持续压进 `GF(2)` 系统。
5. 在自由维数足够小后枚举剩余变量，恢复真实 `seed`。
6. 用 `md5(str(seed))` 解开 AES-ECB，得到提交串。

## 归档文件

- `solver.cpp`：最终高性能求解器。
- `solve.py`：编译并调用 `solver.cpp`，同时负责解密和远程交互。

## Flag

`xmctf{a0a3b3ad-c603-4a30-b7aa-b6acfebb3397}`
