# Whisper-Line

## 核心识别

逆向 APK 后可以确认聊天正文走的是 textbook RSA，没有 padding，密文只是做了“定长补齐 + 反转字节序 + hex”。

真正的密码学突破点不在常规 RSA 因子分解，而在模数 `N` 的 base-12 结构。把 `N` 写成 12 进制系数后，可以构造整数系数多项式 `F(x)`，并且这个 `F(x)` 在 `Z[x]` 里能直接分解成两个低复杂度因子。把它们在 `x = 12` 处回代，就直接得到真实的 `p` 和 `q`。

所以这题本质上不是“硬拆 2048-bit RSA”，而是“先发现小底数稀疏结构，再做多项式回代”。

## 最短解链

1. 从 APK 里确认通信协议和 raw RSA 加密方式。
2. 从 PCAP 提炼唯一密文列表，这一步归档里已经压成了 `data/pcap_messages.json`。
3. 把 `N` 展开成 base-12 系数，写成多项式 `F(x)`。
4. 用已知的两个多项式因子在 `x = 12` 处回代，得到 `p` 和 `q`。
5. 计算私钥 `d`，逐条解出聊天内容，拼出 flag。

## 归档文件

- `solve.py`：自包含解密脚本，直接恢复 `p/q/d` 并解出对话。
- `data/pcap_messages.json`：从抓包提取出的最小消息集，避免把 `pcapng` 放进仓库。

## Flag

`xmctf{Th3_L0ud3st_Wh1sp3r_1s_1n_th3_PC4P_ju5t_RSA_4nd_4_L1ttl3_R3v3rs3}`
