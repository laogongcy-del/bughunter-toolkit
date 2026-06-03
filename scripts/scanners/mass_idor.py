#!/usr/bin/env python3
"""
BugBounty Toolkit — 批量IDOR/越权检测脚本
===========================================
用途: 批量测试URL列表中的未授权/越权访问
使用方法:
    python mass_idor.py -l urls.txt -c cookies.txt

注意: 仅用于已获得明确授权的安全测试！
      本脚本仅做检测，不下载/利用任何数据。
"""

import argparse
import re
import sys
import time
import urllib3
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Optional

import requests

# 禁用SSL警告
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================
# 合规声明
# ============================================
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║            ⚠️  授权确认 / AUTHORIZATION CHECK                ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确书面授权的安全测试                      ║
║ This tool is for AUTHORIZED testing ONLY                     ║
║                                                              ║
║ 本脚本仅发送检测请求，不下载/篡改任何数据                      ║
║ 使用者需自行确保拥有目标系统的测试授权                        ║
╚══════════════════════════════════════════════════════════════╝
"""


class IDORDetector:
    """IDOR/越权漏洞检测器"""

    def __init__(self, urls: List[str], cookies: dict = None, headers: dict = None,
                 delay_ms: int = 500, timeout: int = 10, threads: int = 3):
        self.urls = urls
        self.cookies = cookies or {}
        self.headers = headers or {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        self.delay = delay_ms / 1000.0
        self.timeout = timeout
        self.threads = min(threads, 5)  # 限制并发数，避免对目标造成压力
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update(self.headers)
        self.results = []

    def check_unauthenticated_access(self, url: str) -> Optional[dict]:
        """
        检测未授权访问
        策略: 不加认证Cookie发送请求，看是否返回正常内容
        """
        try:
            # 不加Cookie请求
            resp = self.session.get(url, timeout=self.timeout)
            time.sleep(self.delay)  # 速率限制

            # 判断是否返回了正常页面（而非登录页重定向）
            if resp.status_code in (200, 201, 202):
                # 进一步判断：不是登录页
                content_lower = resp.text[:500].lower()
                login_keywords = ['login', 'sign in', '登录', '认证', 'unauthorized',
                                  '403 forbidden', 'access denied']
                if not any(kw in content_lower for kw in login_keywords):
                    return {
                        'url': url,
                        'method': 'GET (no auth)',
                        'status': resp.status_code,
                        'length': len(resp.text),
                        'finding': 'POSSIBLE_UNAUTHORIZED_ACCESS',
                        'detail': f'返回 {resp.status_code}，内容长度 {len(resp.text)}，'
                                  f'无认证即可访问'
                    }

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

        return None

    def check_id_param_manipulation(self, url: str) -> List[dict]:
        """
        检测ID参数篡改越权
        策略: 提取URL中的数字ID，替换为相邻值
        """
        findings = []

        # 匹配URL中的数字ID
        id_patterns = [
            (r'/users?/(\d+)', '/users/'),
            (r'/user/(\d+)', '/user/'),
            (r'/profile/(\d+)', '/profile/'),
            (r'/order/(\d+)', '/order/'),
            (r'/document/(\d+)', '/document/'),
            (r'[?&]id=(\d+)', 'id='),
            (r'[?&]user_id=(\d+)', 'user_id='),
            (r'[?&]userId=(\d+)', 'userId='),
        ]

        for pattern, prefix in id_patterns:
            match = re.search(pattern, url, re.IGNORECASE)
            if match:
                original_id = match.group(1)
                for new_id in [str(int(original_id) + 1), str(int(original_id) - 1)]:
                    new_url = url.replace(f'{prefix}{original_id}', f'{prefix}{new_id}')

                    try:
                        resp = self.session.get(
                            new_url, timeout=self.timeout,
                            cookies=self.cookies  # 携带认证Cookie测试越权
                        )
                        time.sleep(self.delay)

                        if resp.status_code == 200 and len(resp.text) > 100:
                            findings.append({
                                'url': new_url,
                                'method': 'ID_MANIPULATION',
                                'status': resp.status_code,
                                'length': len(resp.text),
                                'finding': 'POSSIBLE_IDOR',
                                'detail': f'原ID: {original_id}, 篡改为: {new_id}, '
                                          f'返回 {resp.status_code}'
                            })
                    except Exception:
                        continue

        return findings

    def run(self) -> List[dict]:
        """执行所有检测"""
        start_time = time.time()
        total = len(self.urls)
        print(f"\n[+] 开始检测 {total} 个URL...")

        # 阶段1: 未授权检测
        print("\n[*] 阶段1: 未授权访问检测")
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {executor.submit(self.check_unauthenticated_access, url): url
                       for url in self.urls}
            for i, future in enumerate(as_completed(futures), 1):
                result = future.result()
                if result:
                    self.results.append(result)
                    print(f"  [!!] 发现: {result['url'][:80]}")
                if i % 10 == 0:
                    print(f"  [*] 进度: {i}/{total}")

        # 阶段2: ID参数篡改检测
        print("\n[*] 阶段2: ID参数篡改检测")
        for i, url in enumerate(self.urls, 1):
            findings = self.check_id_param_manipulation(url)
            for f in findings:
                self.results.append(f)
                print(f"  [!!] 发现: {f['finding']} @ {url[:60]}")
            if i % 10 == 0:
                print(f"  [*] 进度: {i}/{total}")

        elapsed = time.time() - start_time
        print(f"\n[+] 检测完成，耗时 {elapsed:.1f}s")
        return self.results

    def report(self, output_file: Optional[str] = None):
        """生成检测报告"""
        if not self.results:
            print("\n[+] 未发现越权漏洞")
            return

        report_lines = [
            "=" * 60,
            "IDOR 越权检测报告",
            f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"检测URL数: {len(self.urls)}",
            f"发现数: {len(self.results)}",
            "=" * 60,
            "",
        ]

        for i, r in enumerate(self.results, 1):
            report_lines.extend([
                f"[发现 {i}]",
                f"  URL:     {r['url']}",
                f"  类型:    {r.get('finding', 'UNKNOWN')}",
                f"  状态码:  {r['status']}",
                f"  详情:    {r.get('detail', '')}",
                "",
            ])

        report_text = "\n".join(report_lines)
        print(report_text)

        if output_file:
            Path(output_file).parent.mkdir(parents=True, exist_ok=True)
            Path(output_file).write_text(report_text, encoding='utf-8')
            print(f"\n[+] 报告已保存: {output_file}")


def load_cookies(cookie_file: str) -> dict:
    """从文件加载Cookie"""
    cookies = {}
    try:
        text = Path(cookie_file).read_text().strip()
        for item in text.split(';'):
            if '=' in item:
                k, v = item.strip().split('=', 1)
                cookies[k] = v
    except Exception:
        pass
    return cookies


def main():
    # ============================================
    # 合规声明
    # ============================================
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续，no 退出: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(
        description='批量IDOR/越权漏洞检测 (仅限授权测试)',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('-l', '--list', required=True, help='URL列表文件')
    parser.add_argument('-c', '--cookies', help='Cookie文件 (格式: key=value; key2=value2)')
    parser.add_argument('-d', '--delay', type=int, default=500, help='请求延迟(毫秒)，默认500')
    parser.add_argument('-o', '--output', help='输出报告文件')
    parser.add_argument('-t', '--threads', type=int, default=3, help='并发数(最大5)，默认3')
    args = parser.parse_args()

    # 加载URL
    if not Path(args.list).exists():
        print(f"[!] 文件不存在: {args.list}")
        sys.exit(1)

    urls = [line.strip() for line in Path(args.list).read_text().splitlines()
            if line.strip() and not line.startswith('#')]

    if not urls:
        print("[!] URL列表为空")
        sys.exit(1)

    print(f"\n[+] 共加载 {len(urls)} 个URL")

    # 加载Cookie
    cookies = {}
    if args.cookies:
        cookies = load_cookies(args.cookies)
        print(f"[+] 已加载 {len(cookies)} 个Cookie")

    # 执行检测
    detector = IDORDetector(
        urls=urls,
        cookies=cookies,
        delay_ms=args.delay,
        threads=args.threads
    )
    detector.run()
    detector.report(args.output)


if __name__ == '__main__':
    main()
