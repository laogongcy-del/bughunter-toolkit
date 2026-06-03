#!/usr/bin/env python3
"""
BugBounty Toolkit — XSS反射检测器
==================================
用途: 检测反射型XSS漏洞（仅检测反射，不触发执行）
使用方法:
    python xss_scanner.py -u https://target.com/search?q=test

注意: 仅用于已获得明确授权的安全测试！
      本脚本仅检测payload是否被反射到响应中，不执行XSS。
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
║        ⚠️  XSS检测 — 仅限授权测试                            ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅检测payload在响应中的反射情况                          ║
║ 仅用于已获得明确授权的安全测试                                 ║
╚══════════════════════════════════════════════════════════════╝
"""

# 检测用payload（无实际攻击性，仅用于检测反射）
XSS_PAYLOADS = [
    # 简单字符串（检测HTML上下文反射）
    'XSS_TEST_ALERT_1',
    'XSS_TEST_PROMPT_1',
    # HTML标签反射检测
    '<xss-test-123>',
    '<test-xss-id>',
    # HTML属性反射检测
    '"xss-test-attr"',
    "'xss-test-attr'",
    # JS上下文检测
    'xss-js-test-123',
]


class XSSTester:
    """XSS反射检测器"""

    def __init__(self, base_url: str, param: str = None, timeout: int = 10, delay_ms: int = 500):
        self.base_url = base_url
        self.param = param
        self.timeout = timeout
        self.delay = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.findings = []

    def _inject_payload(self, url: str, payload: str) -> Optional[dict]:
        """向URL注入payload并检测反射"""
        try:
            if self.param:
                # 替换指定参数的值
                parsed = urllib.parse.urlparse(url)
                params = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
                params[self.param] = [payload]
                new_query = urllib.parse.urlencode(params, doseq=True)
                test_url = urllib.parse.urlunparse(parsed._replace(query=new_query))
            else:
                # 在URL末尾拼接payload
                sep = '?' if '?' not in url else '&'
                test_url = f"{url}{sep}q={urllib.parse.quote(payload)}"

            resp = self.session.get(test_url, timeout=self.timeout)
            time.sleep(self.delay)

            # 检测payload是否被反射到响应中
            reflected = False
            context = ''
            response_text = resp.text

            # 1. 检查纯文本反射
            if payload in response_text:
                reflected = True
                context = 'BODY_TEXT'

            # 2. 检查HTML编码后的反射
            html_encoded = urllib.parse.quote(payload)
            if not reflected and html_encoded in response_text:
                reflected = True
                context = 'HTML_ENCODED'

            # 3. 检查在script标签中的反射
            if not reflected and payload.replace('"', '\\"') in response_text:
                reflected = True
                context = 'JS_STRING'

            if reflected:
                return {
                    'payload': payload,
                    'status': resp.status_code,
                    'context': context,
                    'url': test_url,
                }

            return None

        except Exception:
            return None

    def run(self) -> list:
        """执行XSS检测"""
        print("\n[*] 开始XSS反射检测")
        print(f"[*] 目标: {self.base_url}")
        print(f"[*] 参数: {self.param or '自动'}")
        print(f"[*] 测试: {len(XSS_PAYLOADS)} 个payload\n")

        for payload in XSS_PAYLOADS:
            result = self._inject_payload(self.base_url, payload)
            if result:
                self.findings.append(result)
                print(f"  [!!] 检测到反射! payload=[{payload[:40]}] 上下文={result['context']}")

        return self.findings

    def report(self):
        """输出报告"""
        if not self.findings:
            print("\n[+] 未检测到XSS反射")
            print("[*] 注意: 无反射不代表一定安全，请结合上下文手动验证")
            return

        print(f"\n{'='*60}")
        print("✅ XSS反射检测报告")
        print(f"{'='*60}")
        print(f"\n发现 {len(self.findings)} 个反射点:")
        for f in self.findings:
            print(f"\n  Payload: {f['payload']}")
            print(f"  上下文: {f['context']}")
            print(f"  HTTP:   {f['status']}")
            print(f"  URL:    {f['url'][:100]}")
        print(f"\n{'='*60}")
        print("⚠️  检测到反射不代表一定能利用，需手动确认上下文转义情况")
        print("⚠️  本检测仅用于漏洞报告，请勿用于未授权测试")


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='XSS反射检测 (仅限授权测试)')
    parser.add_argument('-u', '--url', required=True, help='目标URL')
    parser.add_argument('-p', '--param', help='指定测试参数名')
    parser.add_argument('-d', '--delay', type=int, default=500, help='请求延迟(毫秒)')
    args = parser.parse_args()

    tester = XSSTester(args.url, param=args.param, delay_ms=args.delay)
    tester.run()
    tester.report()


if __name__ == '__main__':
    main()
