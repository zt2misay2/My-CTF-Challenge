# RSA_LCG

## 核心识别

题目给了三个彼此相关的 RSA 幂值：`t^e`、`s1^e`、`(a*s1 + a + t)^e`。直接想到的是 Franklin-Reiter 风格的代数消元，但真正的困难不是 `gcd`，而是 resultant 的次数会炸到 `e^2 = 69169`。

真正可落地的突破点有两个：

1. 我们只需要 `R(X) mod (X^e - C1)`，不需要完整展开 `R(X)`。
2. resultant 对 `K = a(X+1)` 的依赖只通过 `K^e` 出现，所以可以先恢复一个低次数多项式 `G(T)`，再把 `T = K^e` 代回去。

这样原本无法直接处理的巨大二元消元，变成了 264 个标量 resultant 求值 + 一次模 `N` 插值 + 低次数多项式代换。

## 最短解链

1. 记 `X = s1`，`Y = t = b-a`，列出三条模 `N` 方程。
2. 在若干常数点 `k` 上计算 `Res_Y((Y+k)^e - C2, Y^e - L)`。
3. 对这些点做模 `N` 插值，恢复关于 `T = K^e` 的 `G(T)`。
4. 在商环 `Z_N[X] / (X^e - C1)` 中代回 `T = (a(X+1))^e`。
5. 对 `X^e - C1` 做 `gcd` 拿到 `s1`，再做一次 `gcd` 拿到 `t`。
6. 反推 `b` 和 `s0`，把 `secret` 作为 64 字节十六进制提交。

## 归档文件

- `fast_core.cpp`：最终高性能核心，实现了标量 resultant、模插值和多项式运算。
- `fast_remote.py`：包装远程交互，调用本地核心后回填答案。

编译示例：

```bash
g++ -O3 -fopenmp fast_core.cpp -lgmpxx -lgmp -o fast_core
python fast_remote.py nc1.ctfplus.cn 29902
```

## Flag

`XMCTF{bdca1813-40e1-446d-9289-4e8ee930f210}`
