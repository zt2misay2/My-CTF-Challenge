RSA的ROCA攻击 参考

[FlorianPicca/ROCA: A Sage implementation of the ROCA attack (github.com)](https://github.com/FlorianPicca/ROCA?tab=readme-ov-file)

赛题给出构造
$$
p=kM+(e^a\mod M)\\q=k_0M+(e^b\mod M)
$$
从而有
$$
e^{a+b}\equiv n\mod M
$$


$M$是光滑弱素数 可由DLP方法 快速解出
$$
s\equiv a+b \mod \text{ord(M)}
$$


ROCA的核心思路在于合理选取
$$
M' | M
$$
使得$ord(M^{'})$很小 但是仍然满足覆盖$a\;b$ 此时可以遍历搜索$a\;b$ 把烦人的指数部分去掉 然后对于线性的$k$做CopperSmith来分解

分解脚本用的是提到的repo的