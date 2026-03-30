# ez_Login

## 核心识别

源码里确实有 CBC padding oracle，但这题根本不需要走到那一步。真正的直接利用点是管理员密码没有被环境变量覆盖，默认值就是 `admin123`。

也就是说最短路线不是伪造 cookie，而是直接用默认口令登录管理员账号。

## 最短解链

1. 审源码发现 `ADMIN_PASS = os.getenv("ADMIN_PASS", "admin123")`。
2. 直接请求 `/login`，提交 `admin / admin123`。
3. 带着会话 cookie 访问首页即可拿到 flag。

## 归档文件

- `solve.py`：最小登录脚本，直接打默认管理员口令。

## Flag

`xmctf{9f7fedd8-1bc5-49c0-ac9e-b61b0a09facc}`
