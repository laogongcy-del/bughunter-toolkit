# JS接口挖掘四步法

> **合规声明：** 本文档所述技术仅适用于**已获明确授权**的安全测试。JavaScript文件可能包含Access Key、内网地址、数据库密码等高度敏感信息。一旦发现此类信息，**必须立即停止测试并按照漏洞披露流程报告**，不得利用、扩散或存储所发现的敏感凭证。违反者可能承担相应法律责任。

---

## 1. 概述

现代Web应用大量依赖JavaScript进行客户端渲染、API调用和路由管理。JS文件往往暴露了开发人员未曾料及的敏感信息，包括：

- 内部API端点路径
- 认证Token和Access Key
- 云服务凭据（AWS Key、阿里云AK/SK）
- 数据库连接字符串
- 内网IP地址
- 隐藏功能开关
- 调试接口

据统计，在成熟的Bug Bounty项目中，**约30%的高危漏洞**来源于JS文件分析。掌握系统的JS分析方法对于扩大攻击面至关重要。

---

## 2. 四步法总览

```
第一步：收集JS文件
  ├── 从页面标签提取
  ├── 从第三方CDN获取
  ├── 从Sourcemap重建源码
  └── 从历史版本恢复
        │
第二步：提取API路径和敏感信息
  ├── 正则匹配API端点
  ├── 搜索敏感关键词
  ├── 识别模糊/编码后的路径
  └── 提取硬编码凭据
        │
第三步：测试提取到的端点
  ├── 替换Host/Referer测试
  ├── 参数fuzzing
  ├── 方法混淆
  └── 权限绕过尝试
        │
第四步：从报错信息反推参数
  ├── 收集错误信息
  ├── 从返回值推断参数格式
  └── 跨接口参数关联
```

---

## 3. 第一步：收集JS文件

### 3.1 从页面标签提取

```bash
# 从HTML中提取script标签的src属性
curl -s https://example.com | grep -oP 'src="[^"]*\.js[^"]*"' | cut -d'"' -f2 | sort -u

# 更全面的提取（包含内联脚本中的JS路径）
curl -s https://example.com | grep -oP '(src|href)="[^"]*"' | grep '\.js' | sort -u

# 使用gospider爬取所有页面中的JS引用
gospider -a -s https://example.com -c 10 -d 2 | grep -E '\.js' | sort -u
```

### 3.2 从第三方CDN/子域名收集

```bash
# 使用gau/wayback收集历史的JS文件URL
gau --subs example.com | grep '\.js$' | sort -u > historical_js.txt

# 子域名JS文件收集
katana -u https://example.com -d 3 -jc -o katana_js.txt

# nuclei JS端点发现
nuclei -u https://example.com -t ~/nuclei-templates/exposures/configs/ -o js_endpoints.txt
```

### 3.3 从Sourcemap重建源码

Sourcemap文件（`.map`）通常随生产环境一起部署，可还原出接近开发版本的源码。

```bash
# 检测Sourcemap是否存在
curl -s https://example.com/static/js/main.js.map -o /dev/null -w "%{http_code}"

# 遍历常见Sourcemap路径
for js in $(cat js_files.txt); do
  map_url="${js}.map"
  status=$(curl -s -o /dev/null -w "%{http_code}" "$map_url")
  if [ "$status" = "200" ]; then
    echo "[FOUND] $map_url"
  fi
done

# 使用sourcemap工具还原
npm install -g source-map-visualization
# 或使用在线解析工具：https://evileg.com/ru/tools/sourcemap/
```

**常见Sourcemap位置：**

```
/assets/js/app.bundle.js.map
/static/js/main.abc123.js.map
/dist/app.min.js.map
/build/static/js/*.js.map
```

### 3.4 使用工具批量收集

```bash
# LinkFinder - JS端点提取工具
python3 linkfinder.py -i https://example.com -o cli | tee linkfinder_output.txt
# 更激进模式（-d 递归深度）
python3 linkfinder.py -i https://example.com -d 3 -o cli

# JSParser - JS分析工具集
python2 jsparser.py -u https://example.com

# JSMin - 去除JS混淆，便于阅读
# 浏览器中可使用 Prettier 或 de4js 插件

# 批量下载JS文件
cat js_urls.txt | while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s -L --max-time 30 "$url" -o "js_files/$filename"
  echo "$url -> js_files/$filename" >> js_mapping.txt
done
```

---

## 4. 第二步：正则提取API路径和敏感信息

### 4.1 API端点提取正则

```bash
# 核心API端点匹配
grep -oP '(https?://[^"'\''<>]+)' file.js | sort -u

# 匹配相对路径API端点
grep -oP '["'\'']/(api|v[0-9]|rest|graphql|auth|user|admin|config|upload|download|proxy|callback|webhook|sso|oauth|token)/[^"'\'' ]*["'\'']' file.js | sort -u

# 匹配路由定义模式
grep -oP '["'\'']/[a-zA-Z0-9_/-]+["'\'']\s*[=:]\s*(function|async|\(|router\.|Route\.)' file.js | sort -u
```

### 4.2 敏感信息搜索关键词

```bash
#!/bin/bash
# js_secrets_scan.sh - JS中敏感信息搜索

JS_FILE="$1"

echo "=== 搜索 API Keys ==="
grep -oP '["'\''](api[_-]?key|apikey|api[_-]?secret|api_secret)["'\'']\s*[:=]\s*["'\''][^"'\'']+["'\'']' "$JS_FILE"

echo "=== 搜索 Access Token ==="
grep -oP '["'\''](access_token|accessToken|auth_token|jwt|bearer|token|sid|session)["'\'']\s*[:=]\s*["'\''][^"'\'']+["'\'']' "$JS_FILE"

echo "=== 搜索云服务凭据 ==="
grep -oP '(AKIA[0-9A-Z]{16}|eyJ[A-Za-z0-9_/=+-]{10,}|sk-[A-Za-z0-9]{32,})' "$JS_FILE"

echo "=== 搜索 AWS Keys ==="
grep -oP '(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])' "$JS_FILE"

echo "=== 搜索内网地址 ==="
grep -oP '(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3})' "$JS_FILE"

echo "=== 搜索数据库连接 ==="
grep -oP '(mysql|postgres|mongodb|redis)://[^"'\''\s]+' "$JS_FILE"

echo "=== 搜索调试/测试信息 ==="
grep -oP '(debug|test|staging|dev|localhost|127\.0\.0\.1|FIXME|TODO|HACK|TEMP|REMOVE)' "$JS_FILE"

echo "=== 搜索SSO/OAuth配置 ==="
grep -oP '(client_id|client_secret|redirect_uri|authorization_url|token_url)' "$JS_FILE"
```

### 4.3 常用关键词速查表

| 类别 | 关键词 |
|------|--------|
| API路径 | `/api`, `/v1/`, `/rest/`, `/graphql`, `/rpc/` |
| 认证相关 | `token`, `jwt`, `bearer`, `auth`, `session`, `cookie` |
| 敏感操作 | `admin`, `delete`, `update`, `config`, `upload`, `exec` |
| 调试信息 | `debug`, `test`, `dev`, `localhost`, `FIXME`, `TODO` |
| 云服务 | `aws`, `amazon`, `s3`, `bucket`, `cloudfront`, `aliyun` |
| 数据库 | `sql`, `query`, `db`, `connection`, `server` |
| 通讯 | `ws://`, `wss://`, `socket`, `webhook`, `callback` |
| 内部地址 | `10.`, `192.168.`, `172.`, `internal`, `private` |
| 文件操作 | `upload`, `download`, `file`, `export`, `import` |
| 配置 | `config`, `setting`, `env`, `.json`, `secret` |

### 4.4 识别模糊/编码后的路径

```bash
# 搜索Base64编码的端点
grep -oP '["'\''][A-Za-z0-9+/]{20,}={0,2}["'\'']' file.js | while read line; do
  decoded=$(echo "$line" | tr -d '"' | base64 -d 2>/dev/null)
  if [ $? -eq 0 ] && [ -n "$decoded" ]; then
    echo "[B64] $decoded"
  fi
done

# 搜索Hex编码
grep -oP '["'\''][0-9a-fA-F]{20,}["'\'']' file.js

# 搜索URI编码
grep -oP '%[0-9A-F]{2}%[0-9A-F]{2}%[0-9A-F]{2}' file.js | sort -u
```

---

## 5. 第三步：测试提取到的端点

> **注意：** 在测试JS中发现的端点前，请再次确认该端点是否在授权范围内。

### 5.1 基础测试

```bash
# 直接访问（检查是否有未授权访问）
curl -sv https://example.com/api/internal/users 2>&1

# 修改Host头测试
curl -sv -H "Host: internal.example.com" https://example.com/api/users

# 添加X-Forwarded-For尝试绕过IP限制
curl -sv -H "X-Forwarded-For: 127.0.0.1" https://example.com/api/admin

# 添加Referer模拟合法调用
curl -sv -H "Referer: https://example.com/admin/" https://example.com/api/data
```

### 5.2 请求方法混淆测试

```bash
# 切换到不同的HTTP方法
for method in GET POST PUT DELETE PATCH OPTIONS HEAD; do
  echo "=== Method: $method ==="
  curl -sv -X "$method" https://example.com/api/endpoint 2>&1
done
```

### 5.3 Content-Type切换

```bash
# JSON格式
curl -X POST https://example.com/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"test"}'

# URL编码格式
curl -X POST https://example.com/api/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=test"

# XML格式
curl -X POST https://example.com/api/login \
  -H "Content-Type: application/xml" \
  -d '<user><username>admin</username><password>test</password></user>'
```

### 5.4 参数Fuzzing

利用从JS中找到的参数名进行定向测试：

```bash
# ffuf 参数枚举
ffuf -u https://example.com/api/data?FUZZ=1 \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -fc 400,404

# 批量测试JS中找到的接口端点
cat api_endpoints.txt | while read endpoint; do
  echo ">>> Testing: $endpoint"
  curl -sk -o /dev/null -w "%{http_code} %{size_download}" "$endpoint"
  echo ""
done
```

---

## 6. 第四步：从报错信息反推参数名

### 6.1 收集错误信息

当访问一个缺少参数或参数错误的API时，服务器可能会返回详细的错误提示，泄露了正确的参数名。

```bash
# 示例：访问API不传参
curl -sv https://example.com/api/user/detail
# 返回: {"error": "missing required parameter: user_id"}

# 添加推测的参数再测
curl -sv "https://example.com/api/user/detail?user_id=1"
# 返回: {"error": "missing required parameter: token"}
# 说明需要额外参数

# 继续补充参数直至成功
curl -sv "https://example.com/api/user/detail?user_id=1&token=test"
```

### 6.2 从其他接口返回值推断

```bash
# 有时接口A的返回值就是接口B所需的参数
# 接口A返回：{"data":[{"id":123,"name":"test"}]}
# 接口B需要：/api/detail?id=123

# 从多个接口中关联参数名
# 常见参数名互推：
# 接口A的 user_id → 接口B的 uid
# 接口A的 token → 接口B的 auth_token
# 接口A的 session → 接口B的 sid
```

### 6.3 实战场景：从JS到接口调通

**场景还原：**

1. 在 JS 中找到隐藏接口：
   ```javascript
   // 在 app.bundle.js 中发现
   const apiEndpoint = '/api/v2/internal/user/profile';
   ```

2. 访问该接口收到错误：
   ```http
   GET /api/v2/internal/user/profile HTTP/1.1
   Host: example.com
   ---
   HTTP/1.1 400 Bad Request
   {"code":400,"message":"Required String parameter 'uid' is missing"}
   ```

3. 添加 uid 参数后继续收到提示：
   ```http
   GET /api/v2/internal/user/profile?uid=123 HTTP/1.1
   ---
   HTTP/1.1 400 Bad Request
   {"code":400,"message":"Required String parameter 'sign' is missing"}
   ```

4. 在其他 JS 文件中搜索 sign 的生成逻辑：
   ```javascript
   // 在 utils.js 中发现签名算法
   function generateSign(uid, timestamp) {
     return md5(uid + ":" + timestamp + ":" + SECRET_KEY);
   }
   // 发现 SECRET_KEY 硬编码在文件中
   const SECRET_KEY = "xj7@3kF!9";
   ```

5. 按签名算法构造请求：
   ```bash
   # 计算sign
   sign=$(echo -n "123:1680000000:xj7@3kF!9" | md5sum | cut -d' ' -f1)
   
   # 调通接口
   curl "https://example.com/api/v2/internal/user/profile?uid=123&timestamp=1680000000&sign=$sign"
   ```

6. 接口返回敏感数据（如用户手机号、邮箱等），构成严重信息泄露漏洞。

---

## 7. 工具推荐

### 7.1 核心工具

| 工具 | 用途 | 安装 |
|------|------|------|
| **LinkFinder** | 从JS中提取端点 | `git clone https://github.com/GerbenJavado/LinkFinder` |
| **JSParser** | JS端点解析 | `git clone https://github.com/nahamsec/JSParser` |
| **JS-Scanner** | JS敏感信息扫描 | `git clone https://github.com/zseano/JS-Scanner` |
| **SecretFinder** | 密钥/Token提取 | `git clone https://github.com/m4ll0k/SecretFinder` |
| **JSFuck** | JSFuck解码 | `npm install -g jsfuck` |
| **de4js** | JS反混淆 | 在线: https://lelinhtinh.github.io/de4js/ |

### 7.2 Burp插件

| 插件 | 用途 |
|------|------|
| **JS Link Finder** | 自动解析JS中的端点 |
| **Autorize** | 检测越权漏洞（配合JS发现的接口） |
| **JSON Web Tokens** | JWT调试与攻击 |
| **JS Miner** | 挖掘JS中的敏感信息 |

### 7.3 自动化组合

```bash
# 一键JS分析流程
TARGET="https://example.com"

# 1. 收集JS URL
katana -u "$TARGET" -jc -o katana_js.txt
gau --subs "$TARGET" | grep '\.js$' >> all_js_urls.txt
sort -u all_js_urls.txt -o all_js_urls.txt

# 2. 批量扫描端点
python3 ~/tools/LinkFinder/linkfinder.py -i "$TARGET" -o cli > linkfinder_results.txt

# 3. 扫描敏感信息
while read js_url; do
  python3 ~/tools/SecretFinder/SecretFinder.py -i "$js_url" -o cli >> secrets.txt
done < all_js_urls.txt

# 4. 测试发现的端点
cat linkfinder_results.txt | grep -oP 'https?://[^"'\''<> ]+' | sort -u | httpx -silent > live_api_endpoints.txt
```

---

## 8. 高级技巧

### 8.1 WebSocket端点审计

```javascript
// 查找WebSocket连接建立代码
// 搜索关键词: new WebSocket, ws://, wss://
const ws = new WebSocket('wss://example.com/socket');
ws.onmessage = function(event) {
  console.log(event.data);
};
```

```bash
# 测试WebSocket端点的未授权访问
wscat -c wss://example.com/socket
> {"action":"getAllUsers","token":""}
< {"error":"Auth required"}

> {"action":"getAllUsers","token":"test"}
< {"users":["admin","user1","user2"]}
```

### 8.2 Service Worker分析

```javascript
// Service Worker可能包含网络请求拦截逻辑
// 搜索关键词: self.addEventListener('fetch', ...
// 可能暴露内部路由规则和白名单
```

### 8.3 混淆代码还原

```bash
# 对混淆的JS代码使用AST分析工具找到真正的逻辑
npm install -g esprima estraverse escodegen

# 格式化压缩代码
npx prettier --write obfuscated.js
npx js-beautify obfuscated.js
```

---

## 9. 常见搜索关键词完整列表

```
# 端点类
/api /v1 /v2 /rest /graphql /rpc /soap /odata

# 认证类
token jwt bearer auth session cookie apikey secret credential

# 云平台
aws_access_key aws_secret_key s3_bucket azure_storage 
aliyun_ak aliyun_sk oss_endpoint

# 数据库
mysql:// postgres:// mongodb:// redis:// connectionString

# 内部地址
internal intranet private backend service proxy gateway

# 配置
.env .config config.json settings.json application.properties

# 敏感路径
admin debug test dev stage backup upload download

# 测试占位
TODO FIXME HACK XXX test password passwd pwd dummy

# HTTP Client
axios.get fetch.get $.ajax XMLHttpRequest httpClient
```

---

## 10. 实战案例演示

### 案例1：从Sourcemap中找到内部API

```
场景：目标网站使用了Vue.js框架
步骤：
1. 打开Chrome DevTools → Source → 发现 .map 文件存在
2. 下载 main.a1b2c3.js.map
3. 使用 reverse-sourcemap 还原
   npm install -g reverse-sourcemap
   reverse-sourcemap -o restored/ main.a1b2c3.js.map
4. 在还原的源码中找到：
   axios.get('/api/internal/dashboard/stats', {
     headers: { 'X-Internal-Token': 'dev_token_2024' }
   })
5. 使用该Token访问内部接口获得越权访问
```

### 案例2：从JS注释中找到隐藏测试账号

```
场景：JS文件中有开发者遗留的注释
步骤：
1. grep 搜索 TODO / FIXME 关键词
2. 发现注释：
   // TODO: remove test admin account before release
   // username: testadmin, password: Test@123456
3. 尝试登录，发现该账号在正式环境仍可用
4. 该账号拥有管理员权限，可操作其他用户数据
```

---

## 11. 常见陷阱与注意事项

| 陷阱 | 说明 | 应对 |
|------|------|------|
| 误判端点 | 提取的路径可能是拼接变量 | 确认变量可预测性后再验证 |
| 蜜罐Token | 故意放置的假凭据用于追踪 | 使用前验证Token有效性而非直接使用 |
| 动态加载JS | SPA应用动态加载大量JS | 使用Headless浏览器完整渲染 |
| CORS限制 | 跨域限制导致无法直接提取 | 使用官方域或修改Origin头 |
| 版本覆盖 | 新版本部署后旧版本可能下线 | 通过wayback获取历史版本 |

---

> **最终提醒：** JS中发现的敏感信息往往是企业最关键的资产。发现Access Key、数据库密码等请立即停止并向厂商报告，**切勿用于任何未经授权的访问。** 安全测试的底线是不越界，不滥用。

---

## 12. 参考文献

- LinkFinder: https://github.com/GerbenJavado/LinkFinder
- SecretFinder: https://github.com/m4ll0k/SecretFinder
- JS技术文章: https://medium.com/bugbountywriteup/javascript-deobfuscation-techniques
- OWASP JS安全检查清单: https://owasp.org/www-community/attacks/DOM_Based_XSS
- Intigriti JS安全: https://blog.intigriti.com/category/javascript/
