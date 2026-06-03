#!/usr/bin/env python3
"""
BugBounty Toolkit — CORS配置检测脚本
======================================
用途: 检测目标是否存在CORS配置缺陷（仅检测，不利用）
使用方法:
    python cors_tester.py -u https://target.com/api

注意: 仅用于已获得明确授权的安全测试！
"""

import argparse
import urllib3
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CORS测试Origin
TEST_ORIGINS = [
    'https://evil.com',
    'null',
    'https://target.com.evil.com',
    'https://evil.target.com',
    'https://target.com:9999',
    'http://target.com',
    'https://target.com@evil.com',
    'https://evil.com/?target.com',
    'https://evil.com#target.com',
    'data://target.com',
    'file://evil.com',
]


class CORSTester:
    """CORS配置检测器"""

    def __init__(self, url: str, timeout: int = 10, delay_ms: int = 500):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.delay = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = False
        self.findings = []

    def test_origin(self, origin: str) -> Optional[dict]:
        """测试单个Origin的CORS配置"""
        try:
            resp = self.session.options(
                self.url,
                headers={
                    'Origin': origin,
                    'Access-Control-Request-Method': 'GET',
                },
                timeout=self.timeout
            )

            acao = resp.headers.get('Access-Control-Allow-Origin', '')
            acac = resp.headers.get('Access-Control-Allow-Credentials', '')
            acam = resp.headers.get('Access-Control-Allow-Methods', '')

            # 检查CORS配置缺陷
            issues = []

            # 1. Origin反射（最严重）
            if acao == origin:
                issues.append(f'ORIGIN_REFLECTED: ACAO回显了任意Origin {origin}')

            if acao == '*':
                issues.append('WILDCARD_ORIGIN: ACAO设置为通配符*')

            # 2. Credentials + 危险Origin组合
            if acac.lower() == 'true' and acao and acao != '*':
                issues.append(f'CREDENTIALS_ENABLED: ACAO="{acao}", 凭据模式开启')

            if acac.lower() == 'true' and acao == '*':
                issues.append('CRITICAL: 通配符Origin + Credentials=true (浏览器会拦截，但配置错误)')

            if issues:
                return {
                    'url': self.url,
                    'origin': origin,
                    'acao': acao,
                    'acac': acac,
                    'acam': acam,
                    'issues': issues,
                }

            return None

        except Exception:
            return None

    def run(self) -> list:
        """执行CORS检测"""
        print(f"\n[*] 开始检测: {self.url}")

        # 先检测OPTIONS方法是否支持
        try:
            preflight = self.session.options(self.url, timeout=self.timeout)
            if preflight.status_code not in (200, 204):
                print(f"[*] OPTIONS方法返回 {preflight.status_code}")
        except Exception:
            print("[*] OPTIONS方法不可用，尝试GET方法")

        for origin in TEST_ORIGINS:
            result = self.test_origin(origin)
            if result:
                self.findings.append(result)
                print(f"  [!!] CORS配置异常: {origin[:50]}")
                for issue in result['issues']:
                    print(f"       - {issue}")

            import time
            time.sleep(self.delay / 1000.0)

        return self.findings

    def report(self):
        """输出报告"""
        if not self.findings:
            print("\n[+] 未发现CORS配置缺陷")
            return

        print(f"\n{'='*60}")
        print("CORS检测报告")
        print(f"{'='*60}")
        for f in self.findings:
            print(f"\n[发现] Origin: {f['origin']}")
            print(f"  ACAO: {f['acao']}")
            print(f"  ACAC: {f['acac']}")
            print(f"  ACAM: {f['acam']}")
            for issue in f['issues']:
                print(f"  ⚠️  {issue}")


def main():
    print("\n⚠️  本工具仅用于已获得明确授权的安全测试")
    resp = input("输入 yes 确认并继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        return

    parser = argparse.ArgumentParser(description='CORS配置检测 (仅限授权测试)')
    parser.add_argument('-u', '--url', required=True, help='目标URL')
    args = parser.parse_args()

    tester = CORSTester(args.url)
    tester.run()
    tester.report()


if __name__ == '__main__':
    main()
