# truck

## 核心识别

题目看起来像三路多层哈希校验，但第一层已经强制 `md5(A)=md5(B)=md5(C)`，于是第二层三条分支的前缀完全相同；第三层同理。这样整题根本不需要 chosen-prefix collision，只要 identical-prefix collision 就够了。

单次 `fastcoll` 只能造两条碰撞消息，但把它串两层就能得到 4 路 multicollision，从里面任选 3 条不同消息即可满足题面要求。

## 最短解链

1. 对空前缀做两次 `fastcoll`，堆出 4 路同哈希消息，取 3 条作为 `A/B/C`。
2. 令公共前缀变成 `md5(A)`，再做两次 `fastcoll`，得到 `D/E/F`。
3. 令公共前缀变成 `md5(md5(A) || D)`，重复同样动作得到 `G/H/I`。
4. 一轮要做 6 次 `fastcoll`，总共 10 轮。

## 归档文件

- `solve.py`：自动下载/编译 `fastcoll`，生成三路 multicollision 并支持本地或远程交互。

归档中不保存 `fastcoll` 二进制，只保留利用脚本。

## Flag

`xmctf{8a3cb520-30d4-4c65-8d2e-01cde45ad26b}`
