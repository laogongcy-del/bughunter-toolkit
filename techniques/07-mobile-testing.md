# 移动端安全测试方法论

> **免责声明**：本文档仅供授权的安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得书面授权后进行任何安全测试活动。

---

## 一、移动端攻击面总览

移动应用已经成为企业数字化服务的重要入口，然而其安全性往往落后于Web端。移动端的安全测试有其独特的攻击面，需要专门的方法论和工具链。

### 1.1 API接口（移动端API通常比Web端弱）

移动端API是攻击面中最重要的部分。在实际测试中我们发现，大量企业的移动端API存在以下问题：

- **认证机制薄弱**：移动端API往往仅依赖设备ID（Device ID）或客户端生成的Token进行认证，缺少服务端二次校验。
- **缺少CSRF防护**：移动端API很少实现CSRF Token机制，因为移动端通过原生HTTP请求而非浏览器Cookie进行通信，但这并不意味着安全。
- **API版本差异**：移动端旧版本API可能缺少Web端已修复的安全补丁，通过降级攻击可以绕过安全措施。
- **敏感接口暴露**：移动端经常暴露Web端没有的接口，如注册、重置密码、上传头像等。

### 1.2 本地存储（SharedPreferences、SQLite、Keychain）

移动端本地存储是信息泄露的重灾区：

**Android端**：
- `SharedPreferences`：明文存储的XML文件，通常位于`/data/data/<包名>/shared_prefs/`
- `SQLite数据库`：未加密的数据库文件，位于`/data/data/<包名>/databases/`
- `内部存储`：`/data/data/<包名>/files/` 目录下的文件
- `外部存储`：SD卡上的文件，其他应用可读取

**iOS端**：
- `NSUserDefaults`：类似于Android的SharedPreferences
- `CoreData/SQLite`：未加密的数据库
- `Keychain`：相对安全，但仍需检查使用的安全级别
- `Plist文件`：属性列表文件，常存储明文配置

**常见发现**：
```
# Android SharedPreferences 中发现硬编码密码
<map>
    <string name="auth_token">eyJhbGciOiJIUzI1NiJ9...</string>
    <string name="api_key">sk_live_xxxxxxxxxxxxx</string>
    <string name="user_password">P@ssw0rd123!</string>
</map>

# SQLite数据库中明文存储信用卡信息
sqlite> SELECT * FROM credit_cards;
1|4111111111111111|123|12/25|John Doe
```

### 1.3 硬编码凭证

硬编码凭证是移动端测试中最常见的高危发现之一：

**常见硬编码类型**：
- API Key（支付网关、短信服务、地图服务）
- AWS Access Key / Secret Key
- 第三方服务Token（推送服务、统计分析）
- 加密密钥和IV（初始化向量）
- 内部服务的认证凭证
- 调试模式下遗留的后门账号

**检测方法**：
```bash
# 使用grep搜索硬编码字符串
# 反编译后搜索常见模式
grep -r "api_key" ./smali/
grep -r "sk_live_" ./smali/
grep -r "aws_secret" ./smali/

# 使用strings命令
strings app.apk | grep -i "password"
strings app.apk | grep -i "secret"
strings app.apk | grep -iE "^(AKIA|SK)"

# 使用jadx反编译后搜索
# 在jadx GUI中按Ctrl+Shift+F全局搜索
```

### 1.4 第三方SDK

第三方SDK引入的供应链风险不容忽视：

**常见SDK漏洞**：
- **推送SDK**：极光推送、个推等SDK可能存在数据泄露
- **统计SDK**：友盟、Firebase Analytics等可能收集超过必要的数据
- **支付SDK**：微信支付、支付宝SDK可能存在支付逻辑绕过
- **社交登录SDK**：微博、微信登录SDK的OAuth实现问题
- **广告SDK**：广告SDK往往权限要求过高

**测试要点**：
1. 检查SDK版本是否过旧（是否存在已知CVE）
2. 检查SDK是否申请了不必要的权限
3. 检查SDK与服务器的通信是否加密
4. 检查SDK是否在后台发送敏感数据

### 1.5 WebView

WebView是移动应用中最容易出问题的组件之一：

**常见漏洞**：
- **XSS**：通过WebView加载的网页存在XSS漏洞
- **JavaScript Bridge**：`addJavascriptInterface` 暴露了不安全的接口
- **文件域访问**：`setAllowFileAccess(true)` 允许访问本地文件
- **域限制绕过**：`setAllowUniversalAccessFromFileURLs(true)`
- **HTTPS校验绕过**：`setWebViewClient` 覆盖 `onReceivedSslError` 接受所有证书

**测试代码**：
```java
// 危险配置示例
WebView webView = (WebView) findViewById(R.id.webview);
webView.getSettings().setJavaScriptEnabled(true);
webView.getSettings().setAllowFileAccess(true);
webView.getSettings().setAllowUniversalAccessFromFileURLs(true);
webView.addJavascriptInterface(new JSInterface(), "bridge");

// 危险的SSL配置
webView.setWebViewClient(new WebViewClient() {
    @Override
    public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
        handler.proceed(); // 接受所有证书，中间人攻击风险
    }
});
```

### 1.6 Deep Link（URL Scheme劫持）

Deep Link是移动端特有的攻击面，攻击者可以通过注册相同的URL Scheme来劫持合法应用的链接。

**测试方法**：
```xml
<!-- 检查AndroidManifest.xml中的intent-filter配置 -->
<intent-filter>
    <action android:name="android.intent.action.VIEW" />
    <category android:name="android.intent.category.DEFAULT" />
    <category android:name="android.intent.category.BROWSABLE" />
    <!-- 易被劫持的URL Scheme -->
    <data android:scheme="myapp" android:host="auth" />
    <data android:scheme="myapp" android:host="payment" />
</intent-filter>

<!-- iOS中的URL Scheme -->
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>myapp</string>
        </array>
    </dict>
</array>
```

**验证Deep Link劫持**：
```bash
# 在Android上测试Deep Link
adb shell am start -W -a android.intent.action.VIEW -d "myapp://reset-password?token=12345"

# 在iOS上测试Universal Link
curl -v https://example.com/apple-app-site-association
```

---

## 二、没有APK怎么办

在实际渗透测试中，经常遇到没有APK安装包的情况。但这并不妨碍我们进行移动端安全测试。

### 2.1 通过抓包工具抓取移动端API

即使没有APK，也可以通过以下方式获取移动端通信数据：

**方式一：代理抓包**

```bash
# 使用mitmproxy启动透明代理
mitmproxy --mode transparent --listen-port 8080

# 使用mitmweb（Web界面）
mitmweb --listen-port 8081

# 使用Burp Suite
# Proxy -> Options -> Add new proxy listener
# 设置为 0.0.0.0:8080
```

**方式二：搭建WiFi热点**

```bash
# 创建WiFi热点，将流量转发到代理
# 1. 启动AP热点
# 2. 配置iptables转发
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -i wlan0 -p tcp --dport 443 -j REDIRECT --to-port 8080
```

**方式三：DNS劫持**

```bash
# 修改DNS，将目标域名指向攻击机
# 配合mitmproxy使用
mitmdump --mode transparent --listen-port 8080 --set block_global=false
```

### 2.2 设置代理

**HTTP/Socks代理**：
```bash
# 使用ADB设置代理（无需ROOT）
adb shell settings put global http_proxy 192.168.1.100:8080

# 取消代理
adb shell settings put global http_proxy :0

# 使用iptables透明代理（需ROOT）
adb shell
su
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to-destination 192.168.1.100:8080
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to-destination 192.168.1.100:8080
```

**VPN代理**：
使用Postern（Android）或Shadowrocket（iOS）配置全局代理，将流量转发到攻击机的mitmproxy。

### 2.3 安装CA证书

**Android 7+** 默认不再信任用户安装的CA证书，需要以下方法：

**方法一：Magisk模块（推荐）**
```bash
# 使用Magisk模块 MoveCertificates
# 将证书安装到系统证书存储区
adb push burp-cacert.der /data/local/tmp/
adb shell
su
cp /data/local/tmp/burp-cacert.der /system/etc/security/cacerts/
chmod 644 /system/etc/security/cacerts/burp-cacert.der
reboot
```

**方法二：使用adb安装**
```bash
# 通过adb安装用户CA证书
openssl x509 -inform DER -in burp-cacert.cer -out burp-cacert.pem
# 计算证书hash
hash=$(openssl x509 -inform PEM -subject_hash_old -in burp-cacert.pem | head -1)
cp burp-cacert.pem $hash.0
# 推送并安装
adb root
adb remount
adb push $hash.0 /system/etc/security/cacerts/
adb shell chmod 644 /system/etc/security/cacerts/$hash.0
adb reboot
```

**方法三：Xposed + JustTrustMe**
```bash
# 安装Xposed框架后，安装JustTrustMe模块
# 该模块会Hook SSL证书校验函数，绕过证书固定
xposed install com.justtrustme
```

### 2.4 使用Android模拟器抓包

Android模拟器是抓包的最佳环境之一：

```bash
# 使用Android Studio自带的AVD
# 创建模拟器时选择包含Google API的系统镜像

# 设置模拟器代理
emulator -avd Pixel_3a_API_30 -http-proxy http://192.168.1.100:8080

# 在模拟器中安装CA证书
# 将Burp证书发送到模拟器
adb push burp.cer /sdcard/
# 在模拟器中：设置 -> 安全 -> 从SD卡安装证书

# 使用Genymotion个人版（免费）
# 自带root权限，方便操作
```

**抓包工具配置示例**：

```bash
# mitmproxy自动安装证书到Android模拟器
# 启动mitmproxy时指定Android模拟器
mitmproxy --mode regular --listen-host 0.0.0.0 --listen-port 8080 --set ssl_insecure=true
```

---

## 三、移动API vs Web API 差异

理解移动端API与Web端API的差异，能够发现Web端不容易找到的漏洞。

### 3.1 移动端往往缺少CSRF Token

Web端API通常会校验CSRF Token，但移动端API很少实现。

```
# Web端API请求示例
POST /api/transfer HTTP/1.1
Host: example.com
Cookie: session=xxxx
X-CSRF-Token: xxxxxxxx
Content-Type: application/json

{"amount": 1000, "to": "user123"}

# 移动端API请求示例
POST /api/mobile/transfer HTTP/1.1
Host: api.example.com
Authorization: Bearer xxxxxxxx
Content-Type: application/json

{"amount": 1000, "to": "user123"}
# 没有CSRF Token！
```

**利用方式**：找到移动端敏感接口后，可以尝试构造CSRF攻击，或者直接在Web端重放移动端请求。

### 3.2 移动端API版本更新不及时

移动端APP的更新依赖用户手动升级，导致大量旧版本API仍然在线：

- **旧版本API可能缺少安全控制**：新版本修复的漏洞，旧版本API可能仍然存在
- **降级攻击**：通过修改APP版本号或User-Agent，触发旧版本API逻辑
- **兼容性接口**：为了兼容旧版本APP，服务端保留了不安全的接口

**测试方法**：
```bash
# 修改请求头中的版本信息
# 原始请求
POST /api/v3/payment HTTP/1.1
User-Agent: MyApp/3.2.1 (Android 12)

# 尝试降级到旧版本
POST /api/v1/payment HTTP/1.1
User-Agent: MyApp/1.0.0 (Android 5.0)

# 或者使用旧版本API路径
POST /api/v2/payment HTTP/1.1
```

### 3.3 移动端认证机制更弱

移动端为了实现"便捷登录"，往往引入了更弱的认证机制：

- **Token长期有效**：移动端Token有效期可能长达数月
- **设备绑定**：仅通过设备ID（IMEI/IDFA）绑定身份
- **免密登录**：首次登录后使用Refresh Token，无需再次输入密码
- **生物特征绕过**：指纹/面容登录可能存在绕过
- **OAuth简化流程**：移动端的OAuth流程可能缺少state参数校验

**测试案例**：
```
# 设备ID认证示例
POST /api/mobile/login HTTP/1.1
Content-Type: application/json

{
    "device_id": "356938035643809",
    "phone": "13800138000"
}

# 服务器返回Token，完全依赖device_id
{
    "token": "eyJhbGciOiJIUzI1NiJ9...",
    "expires_in": 2592000
}

# 尝试修改device_id劫持他人账户
POST /api/mobile/login HTTP/1.1
Content-Type: application/json

{
    "device_id": "攻击者获取的目标设备ID",
    "phone": "目标手机号"
}
```

### 3.4 移动端请求头更简单

移动端请求头通常比Web端简单，缺少一些安全相关的Headers：

```
# Web端请求头（完整）
GET /api/user/info HTTP/1.1
Host: example.com
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) ...
Accept: text/html,application/xhtml+xml,...
Accept-Language: zh-CN,zh;q=0.9
Accept-Encoding: gzip, deflate
Connection: keep-alive
Cookie: session=xxxx; csrf_token=yyyy
X-Requested-With: XMLHttpRequest
Referer: https://example.com/dashboard

# 移动端请求头（简单）
GET /api/mobile/user/info HTTP/1.1
Host: api.example.com
Authorization: Bearer xxxxxxxx
User-Agent: okhttp/3.14.9
Content-Type: application/json
```

移动端请求头简单意味着：
- 安全检测规则宽松（WAF可能不对移动端流量做严格限制）
- 更容易进行参数篡改
- 缺少Referer等来源验证

---

## 四、APP测试流程

### 4.1 标准测试流程

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│   安装APP    │ → │   抓包分析   │ → │   提取API   │
└─────────────┘    └─────────────┘    └─────────────┘
                                              ↓
┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  测试特有端点 │ ← │ 对比鉴权差异 │ ← │ 测试Web端API │
└─────────────┘    └─────────────┘    └─────────────┘
```

### 4.2 详细步骤

**第一步：安装APP**

在模拟器或测试机上安装目标APP，确保网络代理配置正确。

**第二步：抓包分析**

```bash
# 启动mitmproxy
mitmweb --listen-host 0.0.0.0 --listen-port 8080

# 操作APP各个功能，记录流量
# 重点关注：
# - 登录/注册接口
# - 支付/交易接口
# - 个人信息接口
# - 文件上传接口
```

**第三步：提取API**

从抓包数据中提取所有API端点，分类整理：

```bash
# 使用mitmproxy导出所有URL
mitmdump -r traffic.flow --set flow_detail=0 2>&1 | grep -oP '"GET|POST|PUT|DELETE[^"]+' | sort -u

# 提取请求到文件
mitmproxy --listen-port 8080 --save-stream-file traffic.flows
```

**第四步：测试Web端同样的API**

将提取的移动端API在Web端进行测试，观察鉴权差异：

```bash
# 使用curl复现移动端API请求
curl -X POST https://api.example.com/mobile/transfer \
  -H "Authorization: Bearer MOBILE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "to": "attacker"}'

# 尝试去掉Bearer Token
curl -X POST https://api.example.com/mobile/transfer \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "to": "attacker"}'

# 尝试使用Web端Token访问移动端API
curl -X GET https://api.example.com/mobile/admin/users \
  -H "Cookie: session=WEB_SESSION"
```

**第五步：对比Web和Mobile API的鉴权差异**

```bash
# 对比测试：同一个操作，Web端和移动端的鉴权要求
# Web端需要CSRF Token
curl -X POST https://example.com/api/transfer \
  -H "Cookie: session=WEB_SESSION" \
  -H "X-CSRF-Token: CSRF_TOKEN" \
  -d 'amount=1000&to=user123'

# 移动端不需要CSRF Token
curl -X POST https://api.example.com/mobile/transfer \
  -H "Authorization: Bearer MOBILE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 1000, "to": "user123"}'

# 尝试把移动端请求复制到Web端
curl -X POST https://example.com/api/transfer \
  -H "Authorization: Bearer MOBILE_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"amount": 10000, "to": "attacker"}'
```

**第六步：测试移动端特有的端点**

移动端可能暴露Web端没有的敏感接口：
```bash
# 常见的移动端特有端点
/api/mobile/register
/api/mobile/reset-password
/api/mobile/upload-avatar
/api/mobile/feedback
/api/mobile/device/bind
/api/mobile/user/profile
/api/mobile/phone/change
/api/mobile/logout
```

---

## 五、工具推荐

### 5.1 mitmproxy（免费，推荐）

```bash
# 安装（支持Linux/macOS/Windows）
pip install mitmproxy

# 启动Web界面
mitmweb --listen-host 0.0.0.0 --listen-port 8080

# 命令行模式
mitmdump --listen-port 8080

# 保存流量
mitmproxy --save-stream-file traffic.flows

# 重放流量
mitmdump -c traffic.flows

# 使用Python脚本处理流量
mitmdump -s modify_response.py --listen-port 8080
```

**mitmproxy脚本示例**：
```python
# modify_response.py
from mitmproxy import http

def response(flow: http.HTTPFlow) -> None:
    # 在返回中修改支付金额
    if "/api/payment" in flow.request.pretty_url:
        response_text = flow.response.text
        response_text = response_text.replace('"amount":100', '"amount":1')
        flow.response.text = response_text
        print(f"[+] Modified response: {flow.request.pretty_url}")

def request(flow: http.HTTPFlow) -> None:
    # 记录所有API请求
    if "api" in flow.request.pretty_url:
        print(f"[+] API Request: {flow.request.method} {flow.request.pretty_url}")
        print(f"[+] Request Body: {flow.request.text}")
```

### 5.2 Burp Suite（专业版）

Burp Suite是Web安全测试的行业标准，对移动端测试同样强大：

```bash
# 配置Burp作为移动端代理
# Proxy -> Options -> Proxy Listeners
# 添加监听 0.0.0.0:8080，勾选 "Support invisible proxying"

# 安装Burp CA证书
# 浏览器访问 http://burpsuite
# 下载 cacert.der 并安装到设备

# 常用模块
# - Proxy: 拦截和修改请求
# - Repeater: 重放和修改请求
# - Intruder: 自动化参数测试
# - Decoder: 编解码
```

### 5.3 Objection（Frida）

Objection基于Frida，是移动端Runtime测试的利器：

```bash
# 安装
pip install objection

# 启动Objection，注入APP
objection -g com.target.app explore

# 常用命令
# 在Objection控制台中：
android sslpinning disable    # 禁用SSL Pinning
android hooking list classes  # 列出所有类
android hooking list activities # 列出Activity

# 搜索类和方法
android hooking search classes ApiService
android hooking search methods login

# Hook特定方法
android hooking watch class_method com.target.app.ApiService.login --dump-args --dump-return

# 导出数据
env
android sqlite export
```

**Frida脚本示例**：
```javascript
// ssl_bypass.js
Java.perform(function() {
    var array_list = Java.use("java.util.ArrayList");
    var TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var SSLContext = Java.use("javax.net.ssl.SSLContext");

    // 创建信任所有证书的TrustManager
    var TrustManagerClass = Java.registerClass({
        name: "com.example.TrustAllManager",
        implements: [TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });

    // Hook SSLContext.init() 方法
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom').implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[*] SSLContext.init called, replacing TrustManager...");
        var trustAll = [TrustManagerClass.$new()];
        this.init.call(this, keyManager, trustAll, secureRandom);
    };
});
```

### 5.4 jadx（反编译）

jadx是Android反编译的王者工具：

```bash
# 安装（需要Java环境）
# 下载jadx-gui

# 命令行反编译
jadx -d output_dir app.apk

# 使用GUI
jadx-gui app.apk

# 搜索功能
# Ctrl+Shift+F 全局搜索字符串
# Ctrl+N 搜索类
# Ctrl+Shift+N 搜索文件

# 常用搜索词
# - api_key, secret, password, token
# - http://, https://
# - SharedPreferences, getString
# - decrypt, encrypt, AES, RSA
# - WebView, addJavascriptInterface
# - Intent, Scheme, DeepLink
```

**反编译后检查清单**：
```
1. 检查AndroidManifest.xml
   - android:allowBackup="true"（数据备份风险）
   - android:debuggable="true"（调试模式）
   - android:exported="true"（组件暴露）
   - 自定义权限定义

2. 检查Network Activity
   - 检查网络请求代码
   - 检查API端点和参数
   - 检查认证机制

3. 检查本地存储
   - 搜索SharedPreferences使用
   - 搜索SQLite使用
   - 搜索文件操作

4. 检查加密相关
   - 搜索AES/DES/RSA密钥
   - 搜索Base64编码（不是加密！）
   - 检查自定义加密算法

5. 检查WebView配置
   - JavaScriptEnabled
   - AllowFileAccess
   - addJavascriptInterface
```

---

## 六、实战案例

### 案例 1：移动端越权访问

**背景**：某社交APP的移动端API缺少权限校验
**发现过程**：
1. 抓包发现用户信息接口：`GET /api/mobile/user/{userId}/profile`
2. 尝试修改userId为其他用户的ID
3. 服务端没有校验当前用户是否有权限访问
4. 成功获取所有用户的个人信息

**修复**：在服务端添加权限校验，确保当前用户只能访问自己的数据。

### 案例 2：移动端API认证绕过

**背景**：某金融APP的移动端API不校验签名
**发现过程**：
1. 分析发现API请求都不需要签名
2. 直接将移动端API复制到Burp中测试
3. 发现支付接口不需要二次验证
4. 成功绕过支付确认流程

**修复**：对敏感操作添加签名机制和二次验证。

---

## 结语

移动端安全测试是漏洞挖掘中产出丰厚的领域。由于移动端API往往比Web端更弱、版本更新不及时、认证机制简化，攻击者可以找到Web端已经修复但移动端仍然存在的漏洞。掌握抓包、反编译、Runtime注入等技术，配合系统化的测试流程，能够在移动端发现高价值的漏洞。

> **再次提醒**：所有测试行为必须在获得授权的前提下进行。本文档仅用于教育和授权的安全测试目的。
