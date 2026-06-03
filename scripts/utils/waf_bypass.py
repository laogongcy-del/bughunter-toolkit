#!/usr/bin/env python3
"""
BugBounty Toolkit — WAF绕过检测器
==================================
用途: 自动测试多种WAF绕过方法，找到可用的绕过路径
使用方法:
    python waf_bypass.py -u https://target.com/admin

注意: 仅用于已获得明确授权的安全测试！
"""

import argparse
import sys
import time
import urllib3
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        ⚠️  WAF绕过检测 — 仅限授权测试                        ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确授权的安全测试                           ║
║ 仅测试WAF规则是否可绕过，不用于攻击                            ║
╚══════════════════════════════════════════════════════════════╝
"""

# ============================================
# 绕过方法配置
# ============================================
BYPASS_TECHNIQUES = [
    # (名称, headers, 方法, 说明)
    {
        'name': 'Python Requests (TLS指纹)',
        'get_requests': True,  # 使用requests session
        'headers': {},
        'method': 'GET',
        'description': 'Python TLS握手与curl不同，可绕过基于TLS指纹的WAF',
    },
    {
        'name': 'POST方法',
        'headers': {},
        'method': 'POST',
        'description': '改为POST请求，部分WAF只拦截GET',
    },
    {
        'name': 'PUT方法',
        'headers': {},
        'method': 'PUT',
        'description': '改为PUT请求',
    },
    {
        'name': 'DELETE方法',
        'headers': {},
        'method': 'DELETE',
        'description': '改为DELETE请求',
    },
    {
        'name': 'PATCH方法',
        'headers': {},
        'method': 'PATCH',
        'description': '改为PATCH请求',
    },
    {
        'name': 'OPTIONS方法',
        'headers': {},
        'method': 'OPTIONS',
        'description': 'OPTIONS请求通常不会触发WAF',
    },
    {
        'name': 'X-Forwarded-For',
        'headers': {'X-Forwarded-For': '127.0.0.1'},
        'method': 'GET',
        'description': '伪造来源IP为本地回环地址',
    },
    {
        'name': 'X-Real-IP',
        'headers': {'X-Real-IP': '127.0.0.1'},
        'method': 'GET',
        'description': '真实IP伪造',
    },
    {
        'name': 'X-Original-URL',
        'headers': {'X-Original-URL': '/'},
        'method': 'GET',
        'description': '覆盖原始URL',
    },
    {
        'name': 'X-Rewrite-URL',
        'headers': {'X-Rewrite-URL': '/'},
        'method': 'GET',
        'description': '重写URL',
    },
    {
        'name': 'X-Custom-IP-Authorization',
        'headers': {'X-Custom-IP-Authorization': '127.0.0.1'},
        'method': 'GET',
        'description': '自定义IP授权头',
    },
    {
        'name': 'Client-IP',
        'headers': {'Client-IP': '127.0.0.1'},
        'method': 'GET',
        'description': '客户端IP伪造',
    },
    {
        'name': 'X-Forwarded-Host',
        'headers': {'X-Forwarded-Host': 'localhost'},
        'method': 'GET',
        'description': '伪造Host头',
    },
    {
        'name': 'X-Host',
        'headers': {'X-Host': 'localhost'},
        'method': 'GET',
        'description': '伪造Host头(变种)',
    },
]


class WAFBypassTester:
    """WAF绕过检测器"""

    def __init__(self, url: str, timeout: int = 10, delay_ms: int = 500):
        self.url = url.rstrip('/')
        self.timeout = timeout
        self.delay = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.baseline = None  # 基线响应
        self.results = []

    def get_baseline(self) -> bool:
        """获取基线响应（正常的403/401）"""
        try:
            # 先用curl验证（如果可用）
            resp = requests.get(self.url, timeout=self.timeout,
                                headers={'User-Agent': 'curl/8.0'},
                                verify=False)
            self.baseline = {
                'status': resp.status_code,
                'length': len(resp.text),
                'body_preview': resp.text[:200],
            }
            print(f"\n[*] 基线响应: HTTP {resp.status_code} ({len(resp.text)} bytes)")
            return True
        except Exception as e:
            print(f"\n[-] 获取基线响应失败: {e}")
            return False

    def _send_request(self, technique: dict) -> requests.Response:
        """根据technique配置发送HTTP请求"""
        headers = dict(self.session.headers)
        headers.update(technique.get('headers', {}))
        method = technique.get('method', 'GET')

        if technique.get('get_requests'):
            http_methods = {
                'GET': requests.get, 'POST': requests.post,
                'PUT': requests.put, 'DELETE': requests.delete,
                'PATCH': requests.patch, 'OPTIONS': requests.options,
            }
            requester = http_methods.get(method, requests.get)
            return requester(self.url, headers=headers, timeout=self.timeout, verify=False)
        return self.session.request(method, self.url, headers=headers, timeout=self.timeout)

    def _check_bypassed(self, resp) -> bool:
        """判断是否绕过WAF成功"""
        status_changed = resp.status_code != self.baseline['status']
        content_changed = len(resp.text) != self.baseline['length'] and len(resp.text) > 100

        if status_changed and resp.status_code in (200, 201, 202, 204):
            return True
        if content_changed and not self._is_still_blocked(resp.text):
            return True
        return False

    def test_bypass(self, technique: dict) -> Optional[dict]:
        """测试单个绕过方法"""
        try:
            start = time.time()
            resp = self._send_request(technique)
            elapsed = time.time() - start
            time.sleep(self.delay)

            bypassed = self._check_bypassed(resp)
            result = {
                'technique': technique['name'],
                'method': technique.get('method', 'GET'),
                'headers': technique.get('headers', {}),
                'status': resp.status_code,
                'length': len(resp.text),
                'elapsed': f'{elapsed:.2f}s',
                'bypassed': bypassed,
                'body_preview': resp.text[:150] if bypassed else '',
            }
            return result

        except requests.exceptions.Timeout:
            return {'technique': technique['name'], 'error': 'Timeout'}
        except requests.exceptions.ConnectionError:
            return {'technique': technique['name'], 'error': 'ConnectionError'}
        except Exception as e:
            return {'technique': technique['name'], 'error': str(e)}

    def _is_still_blocked(self, body: str) -> bool:
        """判断是否仍然被WAF拦截"""
        blocked_keywords = [
            '403 forbidden', '403 Forbidden',
            'waf', 'blocked', 'denied', 'rejected',
            '安全防护', '拦截', '拒绝访问',
            'access denied', 'request blocked',
            '<title>403', '<title>404',
        ]
        body_lower = body.lower()[:500]
        return any(kw in body_lower for kw in blocked_keywords)

    def run(self):
        """执行所有绕过测试"""
        if not self.get_baseline():
            return

        print(f"\n[*] 测试绕过方法 ({len(BYPASS_TECHNIQUES)} 种)...")
        print(f"{'='*60}")

        for technique in BYPASS_TECHNIQUES:
            result = self.test_bypass(technique)

            if 'error' in result:
                print(f"  [-] {result['technique']}: {result['error']}")
            elif result['bypassed']:
                print(f"  [✅] {result['technique']}: HTTP {result['status']} ✅ 绕过成功!")
                self.results.append(result)
            else:
                status = result.get('status', '?')
                print(f"  [ ] {result['technique']}: HTTP {status} (未绕过)")
                self.results.append(result)

    def report(self):
        """生成报告"""
        bypassed = [r for r in self.results if r.get('bypassed')]

        if not bypassed:
            print(f"\n{'='*60}")
            print("[-] 未找到可用的绕过方法")
            print("[*] 建议:")
            print("    1. 尝试路径编码绕过后再次测试")
            print("    2. 检查是否有其他接口可绕过")
            print("    3. 换Content-Type (JSON/XML/form)")
            return

        print(f"\n{'='*60}")
        print(f"✅ WAF绕过报告 — 发现 {len(bypassed)} 种绕过方法！")
        print(f"{'='*60}")
        for r in bypassed:
            print(f"\n  方法: {r['technique']}")
            print(f"  HTTP: {r['status']} ({r['length']} bytes)")
            print(f"  耗时: {r['elapsed']}")


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='WAF绕过检测 (仅限授权测试)')
    parser.add_argument('-u', '--url', required=True, help='目标URL')
    parser.add_argument('-d', '--delay', type=int, default=500, help='请求延迟(毫秒)')
    args = parser.parse_args()

    tester = WAFBypassTester(args.url, delay_ms=args.delay)
    tester.run()
    tester.report()


if __name__ == '__main__':
    main()
