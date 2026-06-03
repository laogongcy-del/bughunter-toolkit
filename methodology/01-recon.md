# 信息收集标准流程

> **合规声明：** 本文档所述所有技术和方法仅适用于**已获得明确书面授权**的渗透测试、漏洞众测（Bug Bounty）或红队评估。在未获授权的情况下对任何目标进行测试均属违法行为。开始任何测试前，请务必确认：
> 1. 目标在授权范围内（域名/IP列表）
> 2. 测试方式在授权范围内（如禁止扫描某些端口）
> 3. 已了解并遵守目标平台的漏洞披露规则

---

## 1. 概述

信息收集（Reconnaissance）是渗透测试的基石，直接决定了后续攻击面的广度和漏洞发现的概率。一个系统化的信息收集流程能够帮助测试者全面了解目标资产、暴露面和技术架构，从而精准定位潜在风险点。

本流程遵循"由外到内、由粗到细"的渐进式收集策略，共分为八个阶段。

---

## 2. 信息收集总流程图

```
目标域名/IP
    │
    ├── 1. 备案与基础信息查询 ─── ICP备、Whois、企业信息
    │
    ├── 2. 子域名收集 ─────────── 被动模式 → 主动模式
    │
    ├── 3. 历史URL收集 ────────── 搜索引擎、历史快照、gau/wayback
    │
    ├── 4. 存活检测 ───────────── httpx 批量存活验证
    │
    ├── 5. 技术栈识别 ─────────── whatweb、wappalyzer
    │
    ├── 6. Web指纹与目录枚举 ──── 指纹识别 → 目录爆破
    │
    ├── 7. JS文件提取 ─────────── JS逆向、sourcemap解析
    │
    └── 8. 端口扫描（可选） ───── 仅限授权范围且谨慎执行
```

---

## 3. 各阶段详细操作

### 3.1 备案与基础信息查询

用于了解目标企业的网络资产归属，识别未备案或已过期的域名。

#### ICP备案查询

```bash
# 通过ICP备案查询目标企业名下所有域名
# 工具：icp（https://github.com/m4ll0k/icp）
icp -d example.com

# 或使用在线查询
curl "https://api.xxx.com/icp?keyword=目标公司名"
```

**查询要点：**
- 主办单位名称、备案号
- 备案域名列表（可能发现未录入目标的资产）
- 备案审核时间（过期备案可能说明无人维护）

#### Whois查询

```bash
# Whois信息查询
whois example.com

# 批量Whois
cat domains.txt | while read d; do whois "$d" >> whois_output.txt; done
```

**关注信息：**
- 注册邮箱（用于后续社工或关联资产发现）
- 注册人/组织名称
- DNS服务器
- 注册日期与过期日期
- Nameserver关联查询（可能发现同一NS下的其他域名）

#### 企业信息关联

```bash
# 通过企业名称查找关联域名
# 方式一：天眼查/企查查等商业查询
# 方式二：搜索引擎 site:icp.gov.cn "企业名称"
# 方式三：证书透明度（CRT.SH）
curl -s "https://crt.sh/?q=%25.example.com%25&output=json" | jq .
```

---

### 3.2 子域名收集

子域名是攻击面扩展的关键途径，优先使用被动模式以减少对目标的影响。

#### 被动子域名收集（推荐优先）

```bash
# Subfinder 被动模式
subfinder -d example.com -all -o subdomains_passive.txt

# 使用多个数据源（内置）
subfinder -d example.com -sources crtsh,wayback,alienvault,securitytrails -o subfinder_result.txt

# Amass 被动模式（更全面但较慢）
amass enum -passive -d example.com -o amass_passive.txt
```

**常用被动数据源：**
- CRT.SH（证书透明度日志）
- SecurityTrails
- AlienVault OTX
- Wayback Machine
- Shodan/Censys
- VirusTotal
- DNSDumpster
- Riddler（Farsight Security）

#### DNS解析验证

```bash
# 解析所有收集到的子域名
cat subdomains_*.txt | sort -u | dnsx -a -resp -o resolved_subdomains.txt
```

#### 子域名接管检测

```bash
# 检测可能存在接管风险的子域名
cat resolved_subdomains.txt | nuclei -t ~/nuclei-templates/subdomain-takeover/ -o takeover_results.txt

# 或使用 subjack
subjack -w resolved_subdomains.txt -t 100 -timeout 30 -ssl -o takeover.txt
```

---

### 3.3 历史URL收集

历史URL中可能包含隐藏的API端点、参数名、测试页面和管理后台地址。

```bash
# GAU（Get All URLs）
gau --subs example.com | tee gau_output.txt

# Wayback机器
waybackurls example.com | tee wayback_output.txt

# meg + wayback（批量）
echo example.com | waybackurls | meg -d 1000 paths/

# katana（新一代URL收集）
katana -u example.com -d 5 -o katana_output.txt

# 合并去重
cat gau_output.txt wayback_output.txt | sort -u > all_urls.txt
```

**关注的关键URL模式：**

```
/api/
/admin/
/.git/
/.env/
/backup/
/debug/
/swagger/
/graphql
/actuator/
/assets/
/uploads/
/download/
/proxy/
/callback/
/webhook/
```

---

### 3.4 存活检测

收集到的URL和子域名中很多可能已失效，需要过滤出存活的资产。

```bash
# httpx 批量存活检测
cat all_urls.txt | httpx -silent -status-code -title -tech-detect -o httpx_results.txt

# 子域名存活检测
cat resolved_subdomains.txt | httpx -silent -status-code -title -o live_subdomains.txt

# 带截图模式
cat live_subdomains.txt | httpx -silent -screenshot -screenshot-dir screenshots/
```

**httpx常用参数说明：**

| 参数 | 用途 |
|------|------|
| `-status-code` | 显示HTTP状态码 |
| `-title` | 提取页面标题 |
| `-tech-detect` | 技术栈识别 |
| `-content-length` | 响应体长度 |
| `-web-server` | Web服务器类型 |
| `-follow-host-redirects` | 跟踪跨域跳转 |

---

### 3.5 技术栈识别

了解目标使用的技术栈有助于针对性地选择测试方法。

```bash
# WhatWeb
whatweb -a 3 example.com -v | tee whatweb_result.txt

# webanalyze（更快速）
webanalyze -host example.com -crawl 50

# nuclei 技术标签扫描
nuclei -u https://example.com -tags tech -o tech_stack.txt

# Wappalyzer CLI（需要Node环境）
wappalyzer https://example.com
```

**需要关注的关键技术指标：**

| 技术类型 | 关注点 |
|---------|--------|
| Web服务器 | Apache/Nginx/IIS → 版本已知漏洞 |
| 编程语言 | PHP/Java/Go/Node/Python → 框架漏洞 |
| 前端框架 | React/Vue/Angular → SPA的API接口 |
| CMS | WordPress/Drupal/Joomla → 插件漏洞 |
| 中间件 | Tomcat/JBoss/WebLogic → 反序列化 |
| 云服务 | AWS/Azure/阿里云 → 配置错误 |
| CDN/WAF | Cloudflare/CloudFront → 源站IP绕过 |

---

### 3.6 Web指纹识别与目录枚举

#### Web指纹识别

```bash
# nuclei 模板扫描
nuclei -u https://example.com -t ~/nuclei-templates/ -severity low,medium,high,critical -o nuclei_result.txt

# httpx 内置指纹
httpx -l live_subdomains.txt -tech-detect -o tech_detected.txt

# WAD（Web Application Detector）
wad -u https://example.com
```

#### 目录枚举

```bash
# dirsearch（推荐，多线程）
dirsearch -u https://example.com -e php,asp,aspx,jsp,html,txt,xml,json,js -t 50 -r -o dirsearch_result.txt

# ffuf（更灵活快速）
ffuf -u https://example.com/FUZZ -w /usr/share/wordlists/dirb/common.txt -t 100 -o ffuf_result.json

# gobuster（经典）
gobuster dir -u https://example.com -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -t 50
```

**推荐目录字典（按优先级）：**

```bash
# 1. 快速扫描（常用路径）
/usr/share/wordlists/dirb/common.txt

# 2. 中等扫描（推荐）
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

# 3. 完整扫描（耗时较长）
/usr/share/seclists/Discovery/Web-Content/big.txt

# 4. API路径字典
/usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt

# 5. 参数枚举
/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

**返回码分析：**

| 状态码 | 含义 | 处理方式 |
|--------|------|---------|
| 200 OK | 正常访问 | 重点关注 |
| 301/302 | 重定向 | 检查跳转目标，可能存在开放重定向 |
| 401/403 | 未授权/禁止 | 可能存在未授权访问或权限绕过 |
| 404 | 未找到 | 一般忽略，注意自定义404页面 |
| 405 | 方法不允许 | 可能存在其他HTTP方法可用 |
| 500/502/503 | 服务器错误 | 可能存在参数处理漏洞 |

#### 403/401绕过技巧

```bash
# 常见403绕过方式
# 1. 添加请求头
curl -H "X-Forwarded-For: 127.0.0.1" https://example.com/admin
curl -H "X-Real-IP: 127.0.0.1" https://example.com/admin

# 2. 路径篡改
/admin/..
/./admin
/ADMIN （大小写混淆）
/admin;.css
/%2e/admin

# 3. HTTP方法切换
curl -X POST https://example.com/admin
curl -X PUT https://example.com/admin

# 4. 协议切换
http://example.com/admin  →  https://example.com/admin
```

---

### 3.7 JS文件提取

JavaScript文件中通常隐藏着API端点、AccessKey、内网地址等敏感信息。

```bash
# 提取页面中的JS文件
cat live_subdomains.txt | xargs -I{} curl -s {} | grep -oP 'src="[^"]*\.js"' | sort -u

# nuclei JS扫描
nuclei -u https://example.com -t ~/nuclei-templates/exposures/ -o js_exposures.txt

# 批量下载JS文件
cat js_urls.txt | while read url; do
  filename=$(echo "$url" | md5sum | cut -d' ' -f1).js
  curl -s "$url" -o "/tmp/js/$filename"
done
```

> 详细JS分析方法请参见 **02-js-analysis.md**

---

### 3.8 端口扫描（谨慎使用）

> **警告：** 端口扫描可能触发目标WAF/IDS警报，部分众测平台明确禁止端口扫描。**必须在授权范围内进行，且优先使用低速率扫描。**

```bash
# naabu（推荐，内嵌nmap式指纹）
# 扫描常见Web端口
naabu -host example.com -top-ports 1000 -rate 100 -o naabu_result.txt

# 全端口扫描（耗时较长，慎用）
naabu -host example.com -p - -rate 50 -o naabu_full.txt

# masscan（极速，但容易触发告警）
sudo masscan -p1-65535 --rate=1000 example.com

# nmap 服务识别（对识别出的端口进行精细化扫描）
nmap -sV -sC -p 80,443,8080,8443 example.com
```

**推荐的端口扫描策略：**

```
优先扫描 → Top 100端口（低风险）
需要授权 → Top 1000端口
谨慎执行 → 全端口扫描
禁止执行 → SYN扫描（-sS）在众测中通常不允许
```

**常见高危端口：**

| 端口 | 服务 | 潜在风险 |
|------|------|---------|
| 21 | FTP | 匿名访问、弱口令 |
| 22 | SSH | 弱口令、密钥泄露 |
| 27017 | MongoDB | 未授权访问 |
| 6379 | Redis | 未授权访问+写文件提权 |
| 9200 | ElasticSearch | 未授权访问数据泄露 |
| 3306/5432 | MySQL/PostgreSQL | 弱口令、数据库泄露 |
| 8080/8443 | Tomcat/WebLogic | 管理后台弱口令 |

---

## 4. 信息汇总输出

### 4.1 目录结构建议

```
recon/
├── target_domains.txt           # 目标域名列表
├── target_ips.txt               # 目标IP列表
├── icp_whois.txt                # 备案与Whois信息
├── subdomains/
│   ├── subfinder_result.txt
│   └── resolved_subdomains.txt
├── urls/
│   ├── gau_output.txt
│   ├── wayback_output.txt
│   └── all_urls.txt
├── live/
│   ├── httpx_results.txt
│   └── screenshots/
├── tech/
│   └── whatweb_result.txt
├── directories/
│   └── dirsearch_result.txt
├── js/
│   └── extracted_js.txt
├── ports/
│   └── naabu_result.txt
└── summary/
    └── recon_summary.json        # 汇总报告
```

### 4.2 自动生成汇总报告

```bash
#!/bin/bash
# recon_summary.sh - 信息收集汇总脚本

TARGET=$1
OUTPUT_DIR="recon_summary_$TARGET"
mkdir -p "$OUTPUT_DIR"

echo "===== $TARGET 信息收集汇总 =====" > "$OUTPUT_DIR/summary.txt"
echo "扫描时间: $(date)" >> "$OUTPUT_DIR/summary.txt"
echo "存活子域名: $(wc -l < live_subdomains.txt)" >> "$OUTPUT_DIR/summary.txt"
echo "收集URL数: $(wc -l < all_urls.txt)" >> "$OUTPUT_DIR/summary.txt"
echo "存活Web服务: $(wc -l < httpx_results.txt)" >> "$OUTPUT_DIR/summary.txt"
echo "" >> "$OUTPUT_DIR/summary.txt"
echo "技术栈汇总:" >> "$OUTPUT_DIR/summary.txt"
grep -oP '"name": "\K[^"]+' tech_detected.txt | sort | uniq -c | sort -rn >> "$OUTPUT_DIR/summary.txt"
```

---

## 5. 关键注意事项

### ⚠️ 法律与合规
- **未授权测试是犯罪行为**，违反《刑法》第285条
- 众测平台测试前务必阅读并理解其规则
- 发现严重漏洞（如数据库泄露）应立即停止测试并报告
- 不得下载、备份或扩散目标敏感数据

### ⚠️ 技术注意
- 控制扫描速率，避免对目标造成拒绝服务
- 优先使用被动枚举，减少请求量
- 部分CDN/WAF会屏蔽高频请求，合理配置延时
- 定期检查IP是否被封禁
- 使用代理或跳板机时注意保护自身隐私

### ⚠️ 效率优化
- 字典质量决定扫描效果，定期更新字典库
- 善用并行处理但不要过度
- 记录所有命令和输出，便于复现和报告编写
- 对大型目标优先使用被动收集，减少请求

---

## 6. 常用工具速查表

| 工具 | 用途 | 安装方式 |
|------|------|---------|
| subfinder | 子域名被动收集 | `go install github.com/projectdiscovery/subfinder/v2/...` |
| amass | 子域名收集 | `go install github.com/OWASP/Amass/v3/...` |
| httpx | 存活检测 | `go install github.com/projectdiscovery/httpx/...` |
| gau | 历史URL收集 | `go install github.com/lc/gau/v2/...` |
| waybackurls | 历史URL收集 | `go install github.com/tomnomnom/waybackurls/...` |
| katana | 爬虫+URL收集 | `go install github.com/projectdiscovery/katana/...` |
| whatweb | 技术栈识别 | `gem install whatweb` |
| dirsearch | 目录枚举 | `git clone https://github.com/maurosoria/dirsearch` |
| ffuf | Web Fuzzing | `go install github.com/ffuf/ffuf/v2/...` |
| naabu | 端口扫描 | `go install github.com/projectdiscovery/naabu/v2/...` |
| nuclei | 漏洞扫描 | `go install github.com/projectdiscovery/nuclei/v3/...` |
| dnsx | DNS解析 | `go install github.com/projectdiscovery/dnsx/...` |
| jq | JSON处理 | `apt install jq` |
| curl | HTTP请求 | `apt install curl` |

---

## 7. 参考文献

- ProjectDiscovery 官方文档: https://docs.projectdiscovery.io
- HackerOne Recon Methodology: https://www.hackerone.com/vulnerability-management/reconnaissance
- NahamSec Recon Playbook: https://github.com/nahamsec/recon-playbook
- SecLists 字典库: https://github.com/danielmiessler/SecLists

---

> **最终提醒：** 信息收集的目的是为了提升目标的安全性，而不是破坏。任何发现的漏洞都应按漏洞披露流程负贵责任地报告。
