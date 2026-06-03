# GitHub信息泄露监控

> **免责声明**：本文档仅供授权的安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得书面授权后进行任何安全测试活动。本指南中涉及的所有搜索行为仅限于公开数据，不得使用任何非法手段获取非公开信息。

---

## 一、GitHub信息泄露概述

GitHub作为全球最大的代码托管平台，已经成为企业敏感信息泄露的重灾区。开发者在日常工作中不自觉地将各种敏感信息提交到仓库中，包括API密钥、数据库密码、云服务凭证、内部配置等。对于安全测试人员和红队而言，GitHub信息泄露监控是信息收集阶段非常重要的一环。

### 为什么GitHub泄露如此普遍？

```
1. 开发者安全意识不足
   - 将API Key直接写在代码中用于测试
   - 提交.env文件到仓库
   - 忘记删除配置中的真实密码

2. 版本控制特性
   - 即使删除了敏感信息，commit历史中仍然存在
   - Fork的仓库不会自动同步删除

3. 协作流程漏洞
   - 代码审查不严格
   - 自动化CI/CD配置中硬编码凭证

4. 第三方服务接入
   - 在代码中配置支付网关密钥
   - 嵌入第三方API Token
   - Slack/钉钉Webhook URL
```

---

## 二、搜索语法详解

GitHub提供了强大的代码搜索功能，掌握搜索语法是发现敏感信息的基础。

### 2.1 基础搜索语法

```
# 基本搜索格式
<关键词> <限定条件>

# 搜索目标公司的相关信息
"target.com"                    # 搜索包含target.com的代码
org:target                      # 搜索target组织的仓库
user:target                     # 搜索target用户的仓库
repo:target/repo-name           # 搜索特定仓库
```

### 2.2 关键词组合搜索

#### 搜索API密钥和凭证

```github
# 通用API Key搜索
"target.com" api_key
"target.com" api_secret
"target.com" apikey
"target.com" api-key
"target.com" "apiKey"

# 密码搜索
"target.com" password
"target.com" passwd
"target.com" "password="
"target.com" "pass="

# Secret搜索
"target.com" secret
"target.com" "secret="
"target.com" "secret_key"
"target.com" "secretKey"

# Token搜索
"target.com" token
"target.com" "token="
"target.com" "access_token"
"target.com" "auth_token"
"target.com" "refresh_token"
```

#### 搜索云服务凭证

```github
# AWS
"target.com" aws_key
"target.com" aws_secret
"target.com" "AWS_ACCESS_KEY_ID"
"target.com" "AWS_SECRET_ACCESS_KEY"
"target.com" "AKIA"                  # AWS Access Key前缀

# 阿里云
"target.com" "aliyun_ak"
"target.com" "aliyun_sk"
"target.com" "LTAI"                   # 阿里云AccessKey前缀

# 腾讯云
"target.com" "secretId"
"target.com" "secretKey"
"target.com" "AKID"                   # 腾讯云SecretId前缀

# Google Cloud
"target.com" "GOOGLE_APPLICATION_CREDENTIALS"
"target.com" "type: service_account"
"target.com" "gcp_service_account"

# Azure
"target.com" "AZURE_CLIENT_SECRET"
"target.com" "AZURE_TENANT_ID"
"target.com" "AZURE_SUBSCRIPTION_KEY"
```

#### 搜索数据库连接串

```github
# 通用
"target.com" "jdbc:" 
"target.com" "mongodb://"
"target.com" "postgresql://"
"target.com" "mysql://"
"target.com" "redis://"
"target.com" "connectionString"

# 具体数据库
"target.com" "jdbc:mysql://" password
"target.com" "mongodb+srv://"
"target.com" "postgres://" password
"target.com" "jdbc:oracle:" password
```

### 2.3 文件类型搜索

```github
# 配置文件
"target.com" filename:.env
"target.com" filename:.env.prod
"target.com" filename:.env.development
"target.com" filename:.env.local
"target.com" filename:config.json
"target.com" filename:config.php
"target.com" filename:config.py
"target.com" filename:config.rb
"target.com" filename:database.yml
"target.com" filename:application.properties
"target.com" filename:application.yml
"target.com" filename:docker-compose.yml

# 密钥文件
"target.com" filename:*.pem
"target.com" filename:*.key
"target.com" filename:id_rsa
"target.com" filename:id_dsa
"target.com" filename:*.p12
"target.com" filename:*.jks
"target.com" filename:keystore

# 历史/备份文件
"target.com" filename:*.bak
"target.com" filename:*.old
"target.com" filename:*.swp
"target.com" filename:*.save
"target.com" filename:*.orig
"target.com" filename:*.backup
```

### 2.4 限定搜索范围

```github
# 限定文件路径
"target.com" path:config/
"target.com" path:.env
"target.com" path:deploy/
"target.com" path:ci/
"target.com" path:credentials/

# 限定语言
"target.com" language:python
"target.com" language:java
"target.com" language:javascript
"target.com" language:go
"target.com" language:shell

# 排除特定仓库（减少噪音）
"target.com" -repo:target/official-repo

# 组合搜索
"target.com" filename:.env language:shell
org:target password language:python path:config/
```

### 2.5 高级组合搜索示例

```github
# 查找可能包含真实密码的代码
"target.com" "password" "root" not language:markdown

# 查找可能包含AWS Key的代码
"target.com" "AKIA" not filename:.gitignore

# 查找可能泄露的Slack Token
"target.com" "xoxb-" OR "xoxp-"

# 查找Firebase配置泄露
"target.com" "firebase" "apiKey" "authDomain"

# 查找微信支付密钥
"target.com" "wechat" "appsecret"
"target.com" "wxpay" "key"

# 查找支付宝密钥
"target.com" "alipay" "private_key"
"target.com" "alipay" "app_private_key"

# 查找JWT Secret
"target.com" "jwt_secret"
"target.com" "JWT_SECRET"
"target.com" "jwt secret"
"target.com" "HS256" "secret"
```

### 2.6 搜索Gist和Wiki

Gist和Wiki常常被忽视，但充满了敏感信息：

```github
# 搜索Gist
"target.com" site:gist.github.com
"target.com" site:gist.github.com password
"target.com" site:gist.github.com filename:.env

# 搜索Wiki
"target.com" site:github.com/wiki
"target.com" site:github.com/wiki password
"target.com" site:github.com/wiki "api key"

# 搜索Issue和PR
"target.com" site:github.com/issues password
"target.com" site:github.com/pull api_key
"target.com" site:github.com/issues "secret key"
```

---

## 三、常用GitHub监控工具

### 3.1 GitGuardian（在线，SaaS）

GitGuardian是业界领先的GitHub秘密扫描服务，支持实时监控和自动告警。

**主要功能**：
- 自动检测超过350种秘密类型（API Key、Token、证书等）
- 实时告警，支持Slack、邮件、Webhook通知
- 历史扫描，检查整个Git历史
- Incident管理，追踪修复状态
- 免费版支持个人开发者

**使用方式**：
```
1. 注册GitGuardian账号（https://www.gitguardian.com/）
2. 安装GitHub App授权
3. 配置告警通知
4. 查看扫描结果和Incidents
```

### 3.2 truffleHog（本地部署）

truffleHog是一款强大的开源Git秘密扫描工具，支持深度扫描Git历史。

```bash
# 安装truffleHog v3（推荐）
pip install truffleHog

# 扫描单个仓库（深度扫描所有commit历史）
trufflehog git https://github.com/target/repo.git

# 扫描组织下所有仓库
trufflehog git https://github.com/target --org

# 扫描本地仓库
trufflehog git file:///path/to/local/repo

# 扫描Github组织，并输出JSON
trufflehog git https://github.com/target \
  --json \
  --only-verified \
  --concurrency 10

# 使用GitHub Token提高API限制
trufflehog git https://github.com/target \
  --token=ghp_xxxxxxxxxxxx \
  --json

# 扫描特定分支
trufflehog git https://github.com/target/repo.git \
  --branch=main

# 指定扫描深度（最近N次commit）
trufflehog git https://github.com/target/repo.git \
  --since-commit HEAD~50
```

**truffleHog v2（旧版，仍有用）**：
```bash
# 安装旧版
pip install trufflehog==2.2.1

# 基本扫描
trufflehog --regex --entropy=True https://github.com/target/repo.git

# 扫描组织
trufflehog --regex --entropy=True https://github.com/target

# 使用高熵检测模式
trufflehog --regex --entropy=True --max_depth=1000 https://github.com/target/repo.git
```

### 3.3 git-secrets（本地部署）

git-secrets由AWS Labs开发，专注于防止敏感信息提交到Git仓库。它也可以用于扫描已有历史。

```bash
# 安装 git-secrets
# macOS
brew install git-secrets

# Linux
git clone https://github.com/awslabs/git-secrets.git
cd git-secrets
sudo make install

# 安装到Git仓库
cd /path/to/repo
git secrets --install

# 配置规则
# 添加AWS Access Key模式
git secrets --register-aws

# 添加自定义模式
git secrets --add 'target\.com.*password'
git secrets --add 'api_key\s*=\s*["\x27][A-Za-z0-9]{32,}["\x27]'
git secrets --add 'private_key\s*=\s*["\x27]-----BEGIN'

# 扫描已有历史
git secrets --scan-history

# 递归扫描目录
git secrets --scan -r /path/to/directory

# 扫描时忽略特定模式
git secrets --scan --exclude='test_.*\.py'
```

### 3.4 GitHub Secret Scanning（GitHub原生）

GitHub自带的Secret Scanning功能，支持自动检测已知类型的秘密：

```github
# 支持的秘密类型（部分）：
# - AWS Access Key
# - Azure Storage Account Key
# - GitHub Personal Access Token
# - Google Cloud Service Account
# - Slack Token
# - Stripe API Key
# - Twilio API Key
# - 等等100+种模式

# 启用方式：
# 仓库 Settings -> Security & analysis -> GitHub Advanced Security
# 启用 Secret scanning
```

### 3.5 其他工具推荐

```bash
# detect-secrets（Yelp开源）
pip install detect-secrets
detect-secrets scan .
detect-secrets scan --all-files

# Gitleaks（Go编写，速度快）
brew install gitleaks
gitleaks detect -s /path/to/repo -v

# gopass（密码管理器，可审计密码泄露）
# shhgit（实时监控GitHub）
go get -u github.com/eth0izzle/shhgit

# gittyleaks（结合typos的扫描工具）
pip install gittyleaks
gittyleaks --repo-url https://github.com/target/repo.git
```

---

## 四、搜索技巧详解

### 4.1 不要只看源代码，要看commit历史

敏感信息最常出现在历史commit中。即使后来删除了，Git历史仍然保留。

```bash
# 使用git命令查看commit历史中的敏感信息
git log --all --full-history --diff-filter=D -p -- '*.env'
git log --all -p --diff-filter=D -S "password"
git log --all -p --diff-filter=D -S "api_key"

# 使用grep搜索所有commit
git grep -i "password" $(git rev-list --all)

# 搜索特定文件在历史中的所有版本
git log --all --full-history -- "config/database.yml"

# 使用truffleHog自动完成
trufflehog git file:///path/to/local/repo
```

**实战技巧**：
```bash
# 查找被删除文件中包含的秘密
git log --diff-filter=D --summary | grep delete

# 查找提交信息中包含密码的commit
git log --all --grep="password" --grep="password" --all-match

# 搜索特定模式在历史中的所有出现
git rev-list --all | xargs git grep "AKIA" 2>/dev/null
```

### 4.2 搜索Fork的仓库

开发者经常在Fork的仓库中提交敏感信息，然后忘记清理。Fork的仓库不会同步原仓库的删除操作，这使得它们成为信息泄露的重灾区。

```github
# 搜索目标公司Fork的仓库
# GitHub搜索目前不支持直接限定Fork，但有变通方法
fork:true "target.com" password

# 搜索Fork仓库中的敏感文件
fork:true "target.com" filename:.env

# 使用Google搜索Fork的仓库
site:github.com "forked from target/repo" "password"
site:github.com "forked from target/repo" "api_key"

# 通过GitHub API获取Fork列表
curl -H "Accept: application/vnd.github+json" \
  https://api.github.com/repos/target/repo/forks

# 使用git clone所有Fork的仓库并扫描
#!/bin/bash
for fork_url in $(curl -s "https://api.github.com/repos/target/repo/forks" | jq -r '.[].clone_url'); do
    git clone --depth=50 $fork_url tmp_repo
    trufflehog git file://./tmp_repo
    rm -rf tmp_repo
done
```

### 4.3 搜索Gist

Gist是代码片段分享服务，开发者经常将敏感信息放到Secret Gist中（以为别人看不到）。

```github
# 搜索Gist中的敏感信息
"target.com" site:gist.github.com
"target.com" site:gist.github.com password
"target.com" site:gist.github.com "api_key"

# 使用GitHub API搜索Gist
curl -H "Accept: application/vnd.github+json" \
  "https://api.github.com/search/code?q=%22target.com%22+gist:true"

# 使用专用工具搜索Gist
# gitleaks支持Gist扫描
gitleaks detect --source=https://gist.github.com/username/123456 --gist
```

### 4.4 搜索Wiki

项目Wiki中常常包含部署文档、配置说明等敏感信息。

```github
# 搜索Wiki中的敏感信息
"target.com" site:github.com/wiki
"target.com" site:github.com/wiki password
"target.com" site:github.com/wiki "connection string"

# 克隆Wiki仓库进行深度扫描
git clone https://github.com/target/repo.wiki.git
cd repo.wiki
git log --all -p | grep -i "password\|secret\|api_key"
trufflehog git file://./repo.wiki
```

### 4.5 搜索Issue和PR

Issue和PR的讨论中经常暴露API Key、密码等信息。

```github
# 搜索Issue
"target.com" site:github.com/issues password
"target.com" site:github.com/issues "api key"
"target.com" site:github.com/issues "my password is"
"target.com" site:github.com/issues "please try with"

# 搜索PR
"target.com" site:github.com/pull password
"target.com" site:github.com/pull "api_key"
"target.com" site:github.com/pull "secret"
"target.com" site:github.com/pull "credentials"

# 搜索PR中的diff（包含敏感信息的修改）
"target.com" site:github.com/pull "diff" "password"
```

### 4.6 搜索特定云服务凭证

```github
# 阿里云
"LTAI" "target.com"
"target.com" "aliyun" "accesskey"
"target.com" "aliyun" "AccessKeySecret"

# 腾讯云
"AKID" "target.com"
"target.com" "secretId"
"target.com" "secretKey"

# 华为云
"target.com" "HW_ACCESS_KEY"
"target.com" "HW_SECRET_KEY"

# 微信/支付宝
"target.com" "wx" "appsecret"
"target.com" "wechat" "appid" "secret"
"target.com" "alipay" "private_key"
"target.com" "alipay" "public_key"

# Slack
"target.com" "xoxb-" "slack"
"target.com" "xoxp-" "slack"
"target.com" "hooks.slack.com"

# Stripe
"target.com" "sk_live_"
"target.com" "pk_live_"
"target.com" "stripe" "secret_key"

# Twilio
"target.com" "ACCOUNT_SID"
"target.com" "AUTH_TOKEN"
"target.com" "twilio"
```

### 4.7 搜索硬编码证书和SSH密钥

```github
# SSH私钥
"target.com" "-----BEGIN RSA PRIVATE KEY-----"
"target.com" "-----BEGIN OPENSSH PRIVATE KEY-----"
"target.com" "-----BEGIN DSA PRIVATE KEY-----"
"target.com" "-----BEGIN EC PRIVATE KEY-----"

# 证书
"target.com" "-----BEGIN CERTIFICATE-----"
"target.com" filename:*.p12
"target.com" filename:*.jks
"target.com" filename:*.keystore
"target.com" "PKCS12"

# 已知主机密钥
"target.com" "SSH-2.0-"
"target.com" "ssh-rsa AAAAB3"
```

---

## 五、自动化监控体系

### 5.1 使用GitHub API定期搜索

```python
#!/usr/bin/env python3
"""
GitHub敏感信息监控脚本
定期搜索GitHub上的敏感信息并发送告警
"""

import requests
import json
import hashlib
import time
import os
from datetime import datetime

class GitHubMonitor:
    def __init__(self, token, target):
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github+json"
        }
        self.target = target
        self.base_url = "https://api.github.com/search/code"
        self.seen_hashes = set()

    def search(self, query):
        """执行GitHub代码搜索"""
        results = []
        page = 1
        while True:
            params = {
                "q": f'"{self.target}" {query}',
                "per_page": 100,
                "page": page
            }
            response = requests.get(
                self.base_url,
                headers=self.headers,
                params=params
            )
            if response.status_code != 200:
                print(f"[!] API Error: {response.status_code} - {response.text}")
                break

            data = response.json()
            results.extend(data.get("items", []))

            if len(results) >= data.get("total_count", 0):
                break
            page += 1
        return results

    def check_new_results(self, results):
        """检查是否有新的结果"""
        new_items = []
        for item in results:
            content_hash = hashlib.md5(
                json.dumps(item, sort_keys=True).encode()
            ).hexdigest()
            if content_hash not in self.seen_hashes:
                self.seen_hashes.add(content_hash)
                new_items.append(item)
        return new_items

    def run(self):
        """执行一轮监控扫描"""
        queries = [
            "password",
            "api_key",
            "secret",
            "token",
            "filename:.env",
            "filename:config.json",
            "filename:database.yml",
            "AKIA",
            "aws_secret",
            "jdbc:mysql://",
            "mongodb://",
            "-----BEGIN RSA PRIVATE KEY-----"
        ]

        for query in queries:
            print(f"[*] Searching: {self.target} - {query}")
            try:
                results = self.search(query)
                new_results = self.check_new_results(results)
                for item in new_results:
                    self.send_alert(query, item)
            except Exception as e:
                print(f"[!] Search failed: {e}")
            time.sleep(2)  # API限制控制

    def send_alert(self, query, item):
        """发送告警通知"""
        alert = f"""
[GitHub Leak Alert]
Target: {self.target}
Query: {query}
Repository: {item['repository']['full_name']}
URL: {item['html_url']}
File: {item['name']}
Path: {item['path']}
Time: {datetime.now().isoformat()}
        """
        print(alert)

if __name__ == "__main__":
    # 配置
    TOKEN = os.environ.get("GITHUB_TOKEN", "your_token_here")
    TARGET = os.environ.get("TARGET", "example.com")

    monitor = GitHubMonitor(TOKEN, TARGET)
    monitor.run()
```

### 5.2 配置Webhook通知

```python
#!/usr/bin/env python3
"""
Webhook通知模块
支持Slack、钉钉、企业微信等
"""

import requests
import json

class WebhookNotifier:
    def __init__(self, webhook_url, platform="slack"):
        self.webhook_url = webhook_url
        self.platform = platform

    def send_slack(self, message):
        """发送Slack通知"""
        payload = {
            "text": message,
            "username": "GitHub Leak Monitor",
            "icon_emoji": ":warning:"
        }
        requests.post(self.webhook_url, json=payload)

    def send_dingtalk(self, message):
        """发送钉钉通知"""
        payload = {
            "msgtype": "text",
            "text": {
                "content": message
            }
        }
        requests.post(
            self.webhook_url,
            json=payload,
            headers={"Content-Type": "application/json"}
        )

    def send_wechat_work(self, message):
        """发送企业微信通知"""
        payload = {
            "msgtype": "markdown",
            "markdown": {
                "content": message
            }
        }
        requests.post(self.webhook_url, json=payload)

    def notify(self, message):
        """通用通知方法"""
        if self.platform == "slack":
            self.send_slack(message)
        elif self.platform == "dingtalk":
            self.send_dingtalk(message)
        elif self.platform == "wechat_work":
            self.send_wechat_work(message)
        else:
            print(f"[!] Unknown platform: {self.platform}")
```

### 5.3 使用GitHub Actions自动化监控

```yaml
# .github/workflows/github-leak-monitor.yml
name: GitHub Leak Monitor

on:
  schedule:
    # 每天UTC时间2:00运行
    - cron: '0 2 * * *'
  workflow_dispatch:  # 手动触发

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'

      - name: Install dependencies
        run: |
          pip install requests

      - name: Run Leak Scanner
        env:
          GITHUB_TOKEN: ${{ secrets.GH_SCAN_TOKEN }}
          TARGET: ${{ secrets.SCAN_TARGET }}
          WEBHOOK_URL: ${{ secrets.WEBHOOK_URL }}
        run: |
          python leak_scanner.py

      - name: Save Results
        uses: actions/upload-artifact@v3
        with:
          name: scan-results
          path: results/
          retention-days: 30
```

### 5.4 保存历史记录对比变化

```python
#!/usr/bin/env python3
"""
结果对比和历史记录管理
"""

import sqlite3
import json
from datetime import datetime

class ResultManager:
    def __init__(self, db_path="leak_monitor.db"):
        self.conn = sqlite3.connect(db_path)
        self.init_db()

    def init_db(self):
        """初始化数据库"""
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP,
                target TEXT,
                query TEXT,
                repo_full_name TEXT,
                file_path TEXT,
                file_url TEXT,
                content_hash TEXT,
                status TEXT DEFAULT 'new',
                UNIQUE(content_hash)
            )
        """)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_time TIMESTAMP,
                query TEXT,
                result_count INTEGER
            )
        """)
        self.conn.commit()

    def save_result(self, target, query, item):
        """保存扫描结果"""
        cursor = self.conn.cursor()
        content_hash = hashlib.md5(
            json.dumps(item, sort_keys=True).encode()
        ).hexdigest()
        try:
            cursor.execute("""
                INSERT OR IGNORE INTO scan_results
                (scan_time, target, query, repo_full_name, file_path, file_url, content_hash)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                datetime.now(),
                target,
                query,
                item['repository']['full_name'],
                item['path'],
                item['html_url'],
                content_hash
            ))
            self.conn.commit()
            return cursor.rowcount > 0
        except Exception as e:
            print(f"[!] DB Error: {e}")
            return False

    def get_new_results(self, since_hours=24):
        """获取指定时间内的新结果"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT * FROM scan_results
            WHERE scan_time >= datetime('now', '-? hours')
            AND status = 'new'
            ORDER BY scan_time DESC
        """, (since_hours,))
        return cursor.fetchall()

    def mark_reviewed(self, result_id):
        """标记结果已审查"""
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE scan_results SET status = 'reviewed' WHERE id = ?",
            (result_id,)
        )
        self.conn.commit()

    def get_stats(self):
        """获取统计数据"""
        cursor = self.conn.cursor()
        cursor.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(CASE WHEN status = 'new' THEN 1 ELSE 0 END) as new_count,
                SUM(CASE WHEN status = 'reviewed' THEN 1 ELSE 0 END) as reviewed_count,
                target
            FROM scan_results
            GROUP BY target
        """)
        return cursor.fetchall()
```

### 5.5 完整自动化方案架构

```
┌─────────────────────────────────────────────────┐
│                 定时调度器                       │
│           (Cron / GitHub Actions)                │
└─────────────────────┬───────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────┐
│                GitHub API搜索                     │
│          (Python脚本 / truffleHog)               │
└──────────┬──────────────────────┬───────────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐   ┌──────────────────────────┐
│   结果去重/存储   │   │      结果分析/排序        │
│   (SQLite/文件)   │   │  (按严重程度/类型分类)     │
└──────────┬───────┘   └──────────┬───────────────┘
           │                      │
           ▼                      ▼
┌──────────────────┐   ┌──────────────────────────┐
│   告警通知       │   │      报告生成             │
│   (Slack/钉钉)   │   │  (HTML/Markdown报告)      │
└──────────────────┘   └──────────────────────────┘
```

---

## 六、验证和利用

### 6.1 验证泄露的凭证是否有效

找到疑似泄露的凭证后，需要进行验证：

```bash
# 验证AWS Access Key
aws sts get-caller-identity --profile leaked

# 验证GitHub Token
curl -H "Authorization: token ghp_xxxxxxxxx" \
  https://api.github.com/user

# 验证MySQL连接
mysql -h host -u username -p'password' -e "SELECT 1"

# 验证SSH密钥
ssh -i leaked_key -o StrictHostKeyChecking=no user@host

# 验证API Key
curl -H "Authorization: Bearer leaked_token" \
  https://api.target.com/v1/user

# 验证Slack Token
curl -H "Authorization: Bearer xoxb-xxxx" \
  https://slack.com/api/auth.test
```

### 6.2 利用场景

```bash
# AWS凭证泄露 - 枚举S3存储桶
aws s3 ls --profile leaked
aws s3 cp s3://bucket-name/file.txt . --profile leaked

# GitHub Token泄露 - 查看私有仓库
curl -H "Authorization: token ghp_xxxxx" \
  https://api.github.com/user/repos?type=private

# 数据库泄露 - 导出用户数据
pg_dump -h host -U username -d dbname > data.sql

# JWT Secret泄露 - 伪造JWT Token
# 使用泄露的secret伪造管理员Token
```

---

## 七、实战案例

### 案例 1：某知名电商平台的AWS Key泄露

**发现过程**：
1. 搜索 `"target.com" "AKIA"` 发现一个Fork的仓库
2. 在仓库的历史commit中发现 `credentials.json`
3. 使用 `trufflehog` 深度扫描确认
4. 验证该AWS Key具有S3完全访问权限
5. 下载了包含用户数据的多个S3存储桶

**影响**：超200万用户数据泄露，包含姓名、电话、地址

### 案例 2：GitHub Token泄露导致内部代码泄露

**发现过程**：
1. 搜索 `"target.com" "ghp_"` 发现一个Gist
2. Token具有 `repo` 全部权限
3. 使用该Token访问了目标公司的私有仓库
4. 发现包含支付系统完整源码

**影响**：支付系统源码泄露，暴露了支付流程中的安全漏洞

---

## 结语

GitHub信息泄露监控是红队测试和渗透测试中非常重要的信息收集环节。通过系统化的搜索策略、自动化监控工具和持续的分析，可以发现大量高价值的敏感信息。掌握这些技术不仅有助于安全测试，也能帮助企业及时发现并修复信息泄露风险。

> **再次提醒**：所有测试行为必须在获得授权的前提下进行。发现敏感信息后，应通过负责任的渠道报告给相关方，不得滥用获取的信息。

---

## 附录：快速搜索参考表

| 搜索目标 | GitHub搜索语法 |
|---------|---------------|
| API Key | `"target" api_key OR apikey OR "api-key"` |
| AWS Key | `"target" "AKIA"` |
| 密码 | `"target" password filename:.env` |
| 数据库 | `"target" "jdbc:mysql://" OR "mongodb://"` |
| SSH密钥 | `"target" "-----BEGIN RSA PRIVATE KEY-----"` |
| Token | `"target" token OR "access_token"` |
| 配置文件 | `"target" filename:.env OR filename:config.json` |
| Slack Token | `"target" xoxb- OR xoxp-` |
| Firebase | `"target" firebaseio.com` |
| Docker | `"target" filename:docker-compose.yml` |
| CI配置 | `"target" filename:.travis.yml OR filename:.github/workflows` |
| 历史记录 | `"target" filename:*.bak OR filename:*.old` |
