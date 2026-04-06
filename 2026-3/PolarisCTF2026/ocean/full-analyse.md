# ocean Full Analyse

## 1. 题目概述

题目源码见 `chal (5).py`。核心逻辑非常短，但结构很有意思：

```python
n = 64
seed = getRandomNBitInteger(n)
mask1, mask2 = getRandomNBitInteger(n), getRandomNBitInteger(n)
lfsr1 = LFSR(n, seed, mask1)
lfsr2 = MLFSR(n, seed, mask2, lfsr1)
print(f"mask1 = {mask1}")
print(f"mask2 = {mask2}")
print(f"output = {sum(lfsr2() << (n - 1 - i) for i in range(n))}")
print(f"enc = {AES.new(key=md5(str(seed).encode()).digest(), mode=AES.MODE_ECB).encrypt(pad(secret.encode(), 16)).hex()}")
```

其中：

- `lfsr1` 是普通 `LFSR`
- `lfsr2` 是被 `lfsr1` 控制是否更新的门控寄存器
- 两个寄存器 **共享同一个 64 位 `seed`**
- 输出给我们的是：
  - `mask1`
  - `mask2`
  - 64 位 `output`
  - `enc = AES-ECB(md5(str(seed)))`

真正的攻击面不在 AES，而在于 **共享初态的门控 LFSR**。

## 2. 题目结构拆解

源码中的两个类如下：

```python
class MLFSR:
    def update(self):
        s = sum([self.state[i] * self.mask_bits[i] for i in range(self.n)]) & 1
        self.state = self.state[1:] + [s]

    def __call__(self):
        if self.lfsr:
            if self.lfsr():
                self.update()
            return self.state[-1]
        else:
            self.update()
            return self.state[-1]

class LFSR(MLFSR):
    def __init__(self, n, seed, mask):
        super().__init__(n, seed, mask, lfsr=None)
```

这意味着：

- `lfsr1()` 每次都会更新自己，并返回自己的最低位
- `lfsr2()` 先调用 `lfsr1()` 取得控制位
- 若控制位为 `1`，`lfsr2` 才更新
- 无论是否更新，`lfsr2()` 都返回当前最低位

记：

- `x` 表示未知的 `seed`
- `y_t` 表示第 `t` 次调用时 `lfsr1` 的输出位
- `m_t = y_0 + y_1 + ... + y_t`
- `z_t` 表示公开输出序列 `output` 的第 `t` 位

那么 `lfsr2` 在第 `t` 时刻真正被推进了 `m_t` 步，因此：

$$
z_t = \text{LSB}\left(LFSR_2^{(m_t)}(x)\right)
$$

这个 `m_t` 就是整题的隐藏路径变量。

## 3. 为什么这题会有明显弱点

如果两个寄存器的初态独立，那么这是一个标准门控发生器，分析难度会高很多。

但这题里它们共享同一个 `seed`，于是：

$$
\text{state}_1(0) = \text{state}_2(0) = x
$$

这会带来两个关键后果：

1. `lfsr1` 的控制序列是 `x` 的线性函数
2. `lfsr2` 的任意步输出也是 `x` 的线性函数
3. 控制路径和被控制序列不再独立，而是都纠缠在同一个未知量 `x` 上

这就是整题可以被大量线性约束压缩的根本原因。

## 4. 从源码到代数模型

### 4.1 预计算线性观测行

对一个普通 `n` 位 LFSR，如果初态是 `x`，那么任意一步的输出位都可以写成 `x` 上的线性型。

我们预计算两组行向量：

- `rows1[t]`：`mask1` 对应 LFSR 在第 `t` 步的输出线性行
- `rows2[k]`：`mask2` 对应 LFSR 在第 `k` 步的输出线性行

于是有：

$$
y_t = \langle a_t, x \rangle = \langle rows1[t+1], x \rangle
$$

$$
v_k = \langle b_k, x \rangle = \langle rows2[k], x \rangle
$$

其中内积在 `GF(2)` 上计算。

最终公开输出满足：

$$
z_t = v_{m_t} = \langle b_{m_t}, x \rangle
$$

### 4.2 真正的非线性在哪里

`idea.md` 的出发点是正确的：门控逻辑可以代数化。

但真正的问题不是“能不能把它写成多项式”，而是：

$$
z_t = \langle b_{m_t}, x \rangle
$$

这里的索引 `m_t` 本身依赖于未知控制位前缀和。

也就是说，这题的困难不在高阶乘法本身，而在于：

$$
\text{隐藏路径} + \text{线性观测}
$$

所以直接走 Gröbner 基硬算不是最优主线，更适合的方向是：

- 把路径变量单独拿出来
- 尽量从 `output` 中榨取关于 `m_t` 的约束
- 让所有剩余信息重新回到 `GF(2)` 线性系统

## 5. 第一条最强约束：翻转位置必然更新

这是最早就确认有效、并且一直保留到最终求解器里的约束。

如果：

$$
z_t \neq z_{t-1}
$$

那么第 `t` 步控制位一定为 `1`。

原因很简单。若 `y_t = 0`，则 `lfsr2` 不更新，输出仍然是上一步同一个最低位，不可能翻转。

因此：

$$
z_t \neq z_{t-1} \Longrightarrow y_t = 1
$$

再写成线性方程就是：

$$
\langle rows1[t+1], x \rangle = 1
$$

这类约束在题目一开始就能批量加入，几乎没有代价，但价值极高。

## 6. 为什么从逐时刻搜索转向 run/chunk 搜索

### 6.1 逐时间点搜索

最初的 `linear_path_experiment.py` 走的是逐时刻搜索：

- 每个时刻枚举当前 `y_t`
- 一边维护 `m_t`
- 一边往 `GF(2)` 系统里塞方程

这个模型是正确的，但在 `n = 64` 下分支太细，搜索树太深。

### 6.2 改成常值段搜索

注意到 `output` 是一个 64 位 0/1 串，其中天然可以分成若干段常值区间：

$$
z_{l} = z_{l+1} = ... = z_r
$$

在这样一段里，`lfsr2` 被推进若干次，但每次推进后的输出都必须保持同一个比特值。

因此，与其逐个猜 `y_t`，不如对一个常值段只猜：

$$
\Delta = \text{这一段中总共更新了多少次}
$$

这样一个长度为 `L` 的 run，本来要枚举 `2^L` 个控制模式，现在只需要考虑 `0..L` 之间的更新次数。

这就是 `run_count_experiment.py` 和最终 `solver.cpp` 的主线。

### 6.3 再切成 chunk

只按 whole-run 搜索还不够，因为长 run 的 `\Delta` 取值仍然很多。

于是进一步把每个 value-run 切成更小的 chunk：

- 每个 chunk 长度取 `3` 到 `6` 左右
- 每个 chunk 独立建立 exact-count 约束
- 在 chunk 内尽量榨干模式信息

这一步非常关键，因为它把“长 run 中模糊的大自由度”拆成了多个可传播的小计数问题。

## 7. run/chunk 上的代数约束

设某个 chunk 的时间范围为 `t = s, s+1, ..., e`，长度为 `L`，观测值恒为比特 `b`。

记该段控制位为：

$$
c_i = y_{s+i} = \langle rows1[s+i+1], x \rangle, \quad 0 \le i < L
$$

记进入该 chunk 前 `lfsr2` 已经推进了 `m` 步，离开时推进了 `m'` 步。

那么该段的总更新次数为：

$$
\Delta = m' - m = \sum_{i=0}^{L-1} c_i
$$

### 7.1 `rows2` 常值约束

因为这段观测全是 `b`，所以所有真正访问到的 `lfsr2` 输出都必须等于 `b`：

$$
\langle rows2[m+1], x \rangle = b
$$

$$
\langle rows2[m+2], x \rangle = b
$$

$$
\cdots
$$

$$
\langle rows2[m'], x \rangle = b
$$

如果该 chunk 是某个 value-run 的最后一段，下一次发生翻转，那么边界还要满足：

$$
\langle rows2[m'+1], x \rangle = b_{\text{next}}
$$

### 7.2 parity 约束

因为：

$$
\Delta = \sum_{i=0}^{L-1} c_i
$$

在 `GF(2)` 里只看奇偶性就得到一条线性方程：

$$
\bigoplus_{i=0}^{L-1} c_i = \Delta \bmod 2
$$

写回 `rows1` 后就是：

$$
\left\langle \bigoplus_{i=0}^{L-1} rows1[s+i+1], x \right\rangle = \Delta \bmod 2
$$

这就是代码里的 `parity_row`。

### 7.3 极值情形的逐位强制

如果一个长度为 `L` 的 chunk 中：

$$
\Delta = 0
$$

那就说明这一段里所有控制位都必须是 `0`。

如果：

$$
\Delta = L
$$

那就说明这一段里所有控制位都必须是 `1`。

如果它是 value-run 的第一段，还可能出现：

- 第一位被前一段翻转强制为 `1`
- 剩余位由 `\Delta` 决定

这些都能直接落成多条线性方程。

### 7.4 exact-count 传播

更一般地，假设当前系统已经能推出这段里某些 `c_i` 已知，剩下若干未知。

设已知 `1` 的数量为 `u`，未知位数量为 `v`。

如果要求总数是 `\Delta`，那么：

$$
u \le \Delta \le u+v
$$

若不满足，立即剪枝。

若：

$$
\Delta = u
$$

则所有未知位都必须为 `0`。

若：

$$
\Delta = u + v
$$

则所有未知位都必须为 `1`。

这就是 `propagate_run_count()` 的基础逻辑。

## 8. 最关键的增强：小模式族交集与线性不变量

这一步是整条攻击链从“可行”走向“高效”的核心。

假设某个 chunk 长度很小，比如 `L = 4`，并且我们知道：

$$
\sum c_i = 2
$$

理论上共有：

$$
\binom{4}{2} = 6
$$

种具体模式。

但结合当前 `GF(2)` 系统中的其它信息，很多模式其实已经不可能了。

### 8.1 过滤幸存模式

设幸存模式集合为：

$$
P = \{p_1, p_2, ..., p_r\}
$$

每个 `p_j` 都是一个 `L` 位 0/1 模式，表示该 chunk 内各时刻的 `c_i` 取值。

在代码里，我们会：

1. 枚举所有权重为 `\Delta` 的模式
2. 把每个模式逐位压进当前线性系统
3. 保留所有不矛盾的模式

如果：

$$
P = \varnothing
$$

则当前分支直接剪掉。

### 8.2 公共常量位

若所有幸存模式在某个位置都相同，例如都满足：

$$
c_2 = 0
$$

那么就可以直接向系统加入：

$$
\langle rows1[s+2+1], x \rangle = 0
$$

### 8.3 更强：线性不变量

更进一步，即使没有任何单个位是常量，也可能存在稳定的异或关系。

例如幸存模式是：

$$
1001,\ 0110
$$

那么单个位看不出常量，但它们始终满足：

$$
c_1 \oplus c_2 = 1
$$

以及：

$$
c_1 \oplus c_4 = 0
$$

因此我们会枚举所有非空子集掩码 `mask`，检查对所有幸存模式是否有：

$$
\bigoplus_{i \in mask} c_i = \text{const}
$$

一旦成立，就把对应的 `rows1` 异或行压回 `GF(2)` 系统。

这一招的本质是：

$$
\text{把 exact-count 的组合信息重新提炼成仿射约束}
$$

这一步是纯代数剪枝，不依赖 SMT，不依赖 Gröbner，效果却非常好。

## 9. 再加一层：`rows2` 前缀上界探针

对于一个 bit 恒为 `b` 的 run，若从某个当前推进次数 `m` 往后看：

$$
\langle rows2[m+1], x \rangle = b
$$

$$
\langle rows2[m+2], x \rangle = b
$$

$$
\cdots
$$

但在某一步开始就与当前子空间矛盾，那么该 run 能容纳的总推进次数就被截断了。

代码中的 `max_prefix_count()` 就是在做这个事情：

- 从 `rows2[start_count]` 开始不断尝试加上 “输出为当前 run 比特值” 的约束
- 一旦矛盾，说明最多只能推进到上一步

它给出了一个便宜但很有效的上界：

$$
m' \le m_{\max}
$$

这可以明显缩小每个 run 的候选 `\Delta` 范围。

## 10. `GF(2)` 线性系统模块

最终求解器最核心的数据结构是 `GF2System`。

其职责是维护关于 `seed` 的仿射子空间：

$$
A x = b \pmod 2
$$

支持三类操作：

1. `add_equation(row, value)`  
   向系统加入一条线性方程

2. `implied_value(row)`  
   判断某条线性型在当前子空间下是否已经被决定

3. `solution_from_free_mask(mask)`  
   在自由变量赋值给定时恢复一个完整解

核心代码如下：

```cpp
struct GF2System {
    int n = 0;
    std::array<U64, 64> pivots{};
    U64 pivot_mask = 0;
    U64 rhs_mask = 0;
    int rank = 0;

    std::pair<U64, int> reduce_row(U64 row) const {
        row &= full_mask;
        int value = 0;
        while (row) {
            int pivot = 63 - __builtin_clzll(row);
            if (((pivot_mask >> pivot) & 1ULL) == 0ULL) {
                break;
            }
            row ^= pivots[pivot];
            value ^= static_cast<int>((rhs_mask >> pivot) & 1ULL);
        }
        return {row, value};
    }

    std::optional<int> implied_value(U64 row) const {
        auto [reduced, value] = reduce_row(row);
        if (reduced == 0) {
            return value;
        }
        return std::nullopt;
    }

    bool add_equation(U64 row, int value) {
        auto [reduced, bias] = reduce_row(row);
        value ^= bias;
        if (reduced == 0) {
            return value == 0;
        }
        ...
    }
};
```

由于变量只有 64 位，整个系统可以完全压在 `uint64_t` 上做位运算，C++ 下常数非常小。

## 11. `rows1 / rows2` 预计算模块

为了把整个问题变成线性代数，我们先对每个基向量初态单独模拟 LFSR，得到所有输出线性行。

代码如下：

```cpp
std::vector<U64> output_rows(int n, U64 mask, int steps) {
    std::vector<U64> rows(steps + 1, 0);
    for (int basis_index = 0; basis_index < n; ++basis_index) {
        U64 basis_seed = 1ULL << (n - 1 - basis_index);
        LFSR lfsr{n, basis_seed, mask, mask_for_bits(n)};
        rows[0] |= static_cast<U64>(lfsr.output()) << (n - 1 - basis_index);
        for (int step = 1; step <= steps; ++step) {
            int bit = lfsr.step();
            rows[step] |= static_cast<U64>(bit) << (n - 1 - basis_index);
        }
    }
    return rows;
}
```

它的意义是：

$$
rows[t] = \text{第 } t \text{ 步输出位对应的线性行}
$$

这样后面所有判断都不再需要真的维护两个 LFSR 状态对象，直接做：

$$
\langle rows[t], x \rangle
$$

即可。

## 12. run 构造模块

求解器不会直接对 64 个时间点逐点搜索，而是先把 `output` 切成 value-run，再进一步切成 chunk。

对应代码：

```cpp
std::vector<Run> build_runs() const {
    std::vector<std::tuple<int, int, int>> original_runs;
    int start = 0;
    for (int idx = 1; idx <= cfg_.n; ++idx) {
        if (idx == cfg_.n || cfg_.outputs[idx] != cfg_.outputs[start]) {
            original_runs.emplace_back(cfg_.outputs[start] - '0', start, idx - 1);
            start = idx;
        }
    }

    std::vector<Run> runs;
    for (std::size_t run_index = 0; run_index < original_runs.size(); ++run_index) {
        ...
    }
    return runs;
}
```

每个 `Run` 中会存：

- `bit`：这段输出的常值
- `start/end/length`
- `time_rows`
- `parity_row`
- `forced_first`
- `last_of_value_run`

其中 `forced_first` 表示该段是某个 value-run 的第一段，但不是全局第一段，因此第一时刻必然对应一次翻转，也就有一位控制位被强制为 `1`。

## 13. exact-count 传播模块

这是整个求解器中最重要的传播器之一。

核心代码如下：

```cpp
bool propagate_run_count(GF2System& system, const std::vector<U64>& time_rows, int required_ones) {
    while (true) {
        int ones = 0;
        std::vector<U64> unknown_rows;
        for (U64 row : time_rows) {
            auto implied = system.implied_value(row);
            if (implied.has_value()) {
                ones += implied.value();
            } else {
                unknown_rows.push_back(row);
            }
        }

        if (required_ones < ones || required_ones > ones + static_cast<int>(unknown_rows.size())) {
            return false;
        }

        if (required_ones == ones) {
            ...
        }

        if (required_ones == ones + static_cast<int>(unknown_rows.size())) {
            ...
        }

        ...
    }
}
```

对应的数学逻辑就是：

$$
u \le \Delta \le u + v
$$

若到达边界，则整段未知位可以被一次性强制。

而当 `L \le 6` 时，还会进一步调用幸存模式分析，自动提炼线性不变量。

## 14. 小模式族分裂模块

在某些情况下，幸存模式数量非常少，比如只剩 2 到 6 个。

此时除了提取公共线性关系，还可以直接把每个幸存模式单独分裂成一个子状态：

```cpp
std::vector<GF2System> split_small_pattern_family(
    const GF2System& system,
    const std::vector<U64>& time_rows,
    int required_ones
) {
    ...
}
```

这一步看上去像增加了分支，但实际上常常会降低整体复杂度，因为：

- 分裂出来的子状态 rank 更高
- 后续 run 的候选数更少
- 更容易在浅层就进入可枚举自由度

## 15. 选项生成模块

对某个 run，求解器要做的事情可以概括为：

1. 根据 `forced_first` 和 run 长度给出 `moved_after` 的基础范围
2. 用 exact-count 上下界过滤
3. 用 parity 过滤
4. 用 `rows2` 前缀上界过滤
5. 用未来最少推进次数过滤
6. 真正尝试扩展系统
7. 再做小模式族细化

对应代码是 `generate_options()`，这里是整个搜索器的中心。

它实际上在枚举：

$$
m' \in [m_{\min}, m_{\max}]
$$

并把每个候选对应的代数后果尽可能前置到当前层完成。

## 16. 搜索顺序：为什么不是纯 DFS

仅仅有代数约束还不够。`n = 64` 时，`output` 本身存在碰撞：

$$
\exists x \neq x', \quad Output(x) = Output(x')
$$

所以会出现大量：

- `output` 合法
- 但 `enc` 不合法

的伪解叶子。

如果直接纯 DFS，很容易在这些伪解盆地里陷太久。

因此最终求解器采用：

$$
\text{beam frontier} + \text{DFS tail}
$$

的混合结构。

### 16.1 前段 beam

先在前若干层 run 上做 beam 扩展：

- 保留有限宽度的前沿
- 对 `(moved, system_signature)` 去重
- 对每个 `moved` 设桶上限，避免前沿塌缩到同一类状态

### 16.2 后段 DFS

从 beam 保留下来的前沿状态继续往下 DFS。

这时因为：

- rank 已经比较高
- 自由度已经下降
- 未来 run 的分支数更小

DFS 的效率就会明显提升。

## 17. beam 的评分逻辑

在最终 C++ 求解器中，beam 不是简单按“rank 越高越好”排序。

实际使用的是一种更保守、更稳定的优先级：

```cpp
auto lhs_key = std::make_tuple(
    rough_option_count(run_index, lhs.moved_before, lhs.system),
    std::abs(2 * lhs.moved_before - depth_times_[run_index]),
    lhs.system.rank,
    cfg_.n - lhs.system.rank,
    lhs.moved_before
);
```

这背后的经验是：

- 未来候选数更少的状态优先
- `moved_before` 不要过早偏离统计中心太多
- rank 不是越大越好，而是作为后置参考

这一步是从大量实验里摸出来的。单纯“贪心追最高 rank”反而更容易提前杀死真路径。

## 18. 最后一步：枚举自由变量并用 `enc` 去伪

当系统自由维数下降到阈值以下时，直接枚举剩余自由变量：

$$
2^{n-rank}
$$

个候选解。

对应代码：

```cpp
std::optional<U64> enumerate_and_verify(const GF2System& system, int enum_threshold) {
    int free_dim = cfg_.n - system.rank;
    if (free_dim > enum_threshold) {
        return std::nullopt;
    }
    for (U64 mask = 0; mask < total; ++mask) {
        U64 candidate = system.solution_from_free_mask(mask);
        if (accept_seed(candidate)) {
            return candidate;
        }
    }
    return std::nullopt;
}
```

`accept_seed()` 会做两件事：

1. 验证该 `seed` 是否真的生成公开 `output`
2. 若给了 `enc`，则尝试：

$$
key = MD5(str(seed))
$$

并检查 AES-ECB 解密结果是否满足：

$$
\text{plaintext} = \texttt{fakeflag\{32 hex\}}
$$

这一步非常关键，因为 `output` 确实存在碰撞，只有 `enc` 能把真实 `seed` 从伪解中筛出来。

## 19. 为什么没有走 Z3 / Gröbner 主线

### 19.1 Gröbner 基路线的问题

`idea.md` 的统一代数化方向并没有错，但如果直接把门控逻辑展开成高阶布尔多项式，然后交给 Gröbner 基：

- 多项式次数会迅速升高
- 单项式数量会膨胀
- 真正困难的还是隐藏路径 `m_t`

所以它更适合作为“存在代数攻击面”的理论说明，而不是实战主解。

### 19.2 Z3 路线的问题

早期 `solve_local.py` 用 bit-vector + `If` 把整条轨迹塞给 Z3，能作为基线验证。

但在 `n = 64` 下：

- Z3 会承担全部路径搜索
- 我们无法把题目特有的 run/chunk 剪枝细节充分注入
- 大量结构信息被浪费在通用求解器开销里

最终效果不如“自己维护 `GF(2)` 系统 + 手工搜索”。

## 20. Python 阶段的实验演进

整个求解过程并不是一步到位，而是这样演化出来的：

### 20.1 第一阶段：逐时刻路径搜索

文件：`linear_path_experiment.py`

目标：

- 验证“隐藏路径 + 线性观测”模型是否成立
- 验证 `flip => y_t = 1` 是否足够强

结论：

- 思路是对的
- 但 `n = 64` 下逐时间点搜索不够高效

### 20.2 第二阶段：run-count 搜索

文件：`run_count_experiment.py`

目标：

- 改为每段只搜“总更新数”
- 把局部 exact-count 的信息尽量压成线性传播

结论：

- 32 位规模已经可以稳定 exact recover
- 64 位规模仍有较多碰撞叶子，但攻击方向正确

### 20.3 第三阶段：C++ 重写热路径

文件：`solver.cpp`

目标：

- 保留已经验证过的代数建模和搜索框架
- 只把真正吃算力的部分搬到 C++

结论：

- 64 位上已经能在本地稳定打出真实 `seed`
- 远程服务也已成功拿到 flag

## 21. 本地实验数据

### 21.1 32 位基准

使用 `bench_cpp_solver.py` 跑到的一组代表性结果：

- 参数：`chunk_len = 3`
- `enum_threshold = 14`
- `beam_depth = 4`
- `beam_width = 512`
- `per_moved = 64`

结果：

```text
trial_seed=20260328 n=32 elapsed=0.0087s status=ok exact=True recovered=187836224 real_seed=187836224
status=ok
seed=187836224
nodes=4
contradictions=3
branch_choices=56
forced_runs=32
enum_candidates=24576
pattern_relations=0
prefix_caps=0
pattern_splits=4
lookahead_prunes=0
beam_kept=88
beam_prunes=0
max_run=4
```

这说明在小规模下，整个系统已经非常稳定。

### 21.2 64 位基准

同样使用 `bench_cpp_solver.py` 跑到的一组代表性结果：

- 参数：`chunk_len = 6`
- `enum_threshold = 5`
- `beam_depth = 7`
- `beam_width = 8192`
- `per_moved = 128`

结果：

```text
trial_seed=20260328 n=64 elapsed=5.4711s status=ok exact=True recovered=5286508213556094784 real_seed=5286508213556094784
status=ok
seed=5286508213556094784
nodes=690848
contradictions=808672
branch_choices=1049565
forced_runs=8789
enum_candidates=5061464
pattern_relations=171683
prefix_caps=18754
pattern_splits=855904
lookahead_prunes=366453
beam_kept=972
beam_prunes=64
max_run=17
```

从这个统计可以清楚看到：

- `pattern_relations` 很高，说明小模式族提炼出的线性不变量非常有用
- `prefix_caps` 和 `lookahead_prunes` 也贡献了大量剪枝
- 最终确实能 exact recover 真实 64 位 `seed`

### 21.3 一个重要现象：不同参数对不同实例鲁棒性不同

实验中也观察到：

- 某些 64 位随机实例适合 `chunk_len = 6, beam_depth = 7`
- 某些更难的实例需要退回到更稳的配置，例如：
  - `chunk_len = 5`
  - `beam_depth = 0`
  - 更接近纯 DFS 但剪枝更扎实

这说明当前求解器已经能打通题目，但参数仍然存在实例相关性。

## 22. 远程求解过程

拿 flag 的时候，远程服务会先输出：

- `mask1`
- `mask2`
- `output`
- `enc`

我们本地做的事情是：

1. 连上远程
2. 解析上述四个参数
3. 把 `output` 转成 64 位比特串
4. 把参数喂给 `solver_cpp`
5. 得到 `seed`
6. 本地解出：

$$
secret = AES^{-1}_{MD5(str(seed))}(enc)
$$

7. 把 `secret` 发回服务端

一次成功的远程记录如下：

- 求解状态：`status=ok`
- 耗时：约 `26.1754s`
- 恢复 `seed`：

```text
14354937176956861088
```

- 解出的提交串：

```text
fakeflag{fca9b25b91605f4f2c37c8a60c4d707b}
```

- 服务端返回真实 flag：

```text
xmctf{a0a3b3ad-c603-4a30-b7aa-b6acfebb3397}
```

## 23. 最终攻击链总结

整条攻击链可以压缩成下面这几步：

1. 预计算两个普通 LFSR 的输出线性行 `rows1 / rows2`
2. 把门控问题改写成：

$$
y_t = \langle rows1[t+1], x \rangle
$$

$$
m_t = \sum_{i=0}^{t} y_i
$$

$$
z_t = \langle rows2[m_t], x \rangle
$$

3. 利用 `output` 的 run 结构，不再逐时刻搜 `y_t`，而是按 chunk 搜总更新数
4. 对每个 chunk 同时使用：
   - 翻转强制位
   - `rows2` 常值约束
   - parity 约束
   - exact-count 上下界传播
   - 小模式族交集
   - 小模式族线性不变量
   - `rows2` 前缀上界探针
5. 用 `GF(2)` 增量消元维护 `seed` 仿射子空间
6. 用 `beam frontier + DFS tail` 组织搜索顺序
7. 当自由维度足够小时，直接枚举剩余自由变量
8. 用 `enc` 做最终去伪，恢复真实 `seed`
9. 解出 `secret` 并提交得到 flag

## 24. 这题最值得记住的点

### 24.1 建模上的核心启发

不要被“门控 LFSR”这个外观吓到。  
真正重要的是看它是否能被改写成：

$$
\text{隐藏路径} + \text{线性观测}
$$

一旦能改写成这个形式，就应该优先思考：

- 路径变量怎么压缩
- 哪些观测会强制路径转移
- 怎样把非线性重新规约回 `GF(2)` 线性系统

### 24.2 代数攻击不等于 Gröbner 基

这题是一个非常典型的例子：

- “存在代数攻击面”是对的
- “直接用 Gröbner 基求”不一定是最优路线

更高效的方法往往是：

$$
\text{找出题目特有的代数关系，再把它们编进定制搜索器}
$$

### 24.3 exact-count 信息很值钱

`sum c_i = k` 不是只有一个 parity。  
它还隐含了：

- 上下界
- 极值强制
- 存活模式交集
- 更高阶的仿射关系

这些都是能直接变成线性方程的。

## 25. 文件说明

- `chal (5).py`
  - 原题源码
- `idea.md`
  - 最初的统一代数化思路
- `linear_path_experiment.py`
  - 逐时间点路径搜索实验
- `run_count_experiment.py`
  - Python 版主力原型
- `solver.cpp`
  - 最终 C++ 求解器
- `bench_cpp_solver.py`
  - 本地 benchmark 脚本
- `progress.md`
  - 中途阶段性总结

## 26. 最终结果

最终远程拿到的 flag 为：

```text
xmctf{a0a3b3ad-c603-4a30-b7aa-b6acfebb3397}
```

这道题的完整解法并不是“把所有东西扔给通用求解器”，而是：

$$
\text{共享 seed 的结构识别}
\rightarrow
\text{线性观测建模}
\rightarrow
\text{run/chunk exact-count 代数剪枝}
\rightarrow
\text{C++ 高性能搜索}
\rightarrow
\text{enc 去伪}
$$

这条路线最终是完全可落地、可复现、可远程利用的。
