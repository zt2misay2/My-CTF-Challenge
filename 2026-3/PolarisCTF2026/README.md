# PolarisCTF2026

比赛链接：

- https://polarisctf.play.ctfplus.cn
- https://www.ctfplus.cn/competition/hall?competitionId=2031260122948308992

这个目录是从 `E:\Crypto\Polaris` 提炼出的精简归档，只保留每题的关键分析与最终可用代码，不收录 `zip`、`apk`、`pcapng`、`pdf`、`pyc`、编译产物和解包目录。

| challenge | archived | notes |
| --- | --- | --- |
| [ECC](./ECC/README.md) | `README.md` `solve.py` | 奇异曲线退化为可参数化加法群 |
| [ez_Login](./ez_Login/README.md) | `README.md` `solve.py` | 实际利用点是默认管理员密码 |
| [ez_random](./ez_random/README.md) | `README.md` `solve.py` | `option 2` 顺序 oracle + Python 128-bit seed 恢复 |
| [ocean](./ocean/README.md) | `README.md` `solve.py` `solver.cpp` | 共享 seed 的门控 LFSR，按 run/chunk 搜索 |
| [RSA_LCG](./RSA_LCG/README.md) | `README.md` `fast_remote.py` `fast_core.cpp` | 低次数插值替代巨大 resultant 展开 |
| [sda](./sda/README.md) | `README.md` `solve.sage` | 代换平方量后做低维格攻击 |
| [smx](./smx/README.md) | `README.md` `solve.py` | 导数信息唯一恢复参数，再枚举小素数 `k` |
| [truck](./truck/README.md) | `README.md` `solve.py` | identical-prefix MD5 multicollision |
| [Whisper-Line](./Whisper-Line/README.md) | `README.md` `solve.py` `data/pcap_messages.json` | base-12 多项式分解 RSA 模数 |

补充说明：

- `truck` 依赖 `fastcoll`，归档里不保存其编译产物。
- `ocean` 和 `RSA_LCG` 的核心都在 C++ 源码里，归档保留源码，不保存二进制。
- `Whisper-Line` 只保留从 `pcap` 提炼出的消息 JSON，避免把抓包文件本体放进仓库。
