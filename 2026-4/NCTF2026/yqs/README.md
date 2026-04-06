先走message 解一个标准LWE 使用基本的primal-attack可以完成

然后用LWE的私钥打exchange接口 要解ECDLP 这个Oracle实际上没有做点有效性的检测 直接打 invalid-curve-attack