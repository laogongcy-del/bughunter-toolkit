#!/usr/bin/env python3
"""
BugBounty Toolkit — JS API接口提取器
======================================
用途: 从JavaScript文件中提取API端点、路径和敏感信息
使用方法:
    python js_api_extractor.py -u https://target.com/app.js
    python js_api_extractor.py -f js_files.txt

注意: 仅用于已获得明确授权的安全测试！
      提取到的接口仅用于授权范围内的漏洞检测。
"""

import argparse
import json
import re
import sys
import time
import urllib3
from pathlib import Path
from typing import List, Set, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║            ⚠️  JS接口提取 — 仅限授权测试                      ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确授权的安全测试                           ║
║ 提取的接口仅用于漏洞检测，不得用于未授权访问                    ║
╚══════════════════════════════════════════════════════════════╝
"""


class JSApiExtractor:
    """JS API接口提取器"""

    def __init__(self, timeout: int = 15, delay_ms: int = 300):
        self.timeout = timeout
        self.delay = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
            'Accept': '*/*',
        })

        # 提取结果
        self.api_endpoints: Set[str] = set()
        self.secrets: List[dict] = []
        self.all_findings: dict = {}

        # API路径正则
        self.api_pattern = re.compile(
            r'["\']((?:/[a-zA-Z][a-zA-Z0-9._-]*)+'
            r'(?:/v[12]/|[Aa]pi/|[Rr]est/|[Gg]raphql|/oauth|/auth|/sdk|/gateway)'
            r'(?:/[a-zA-Z][a-zA-Z0-9._/-]*)?)["\']'
        )

        # 通用路径正则（含参数）
        self.path_pattern = re.compile(
            r'["\']((?:/[a-zA-Z][a-zA-Z0-9._-]*)+'
            r'(?:\?[a-zA-Z][a-zA-Z0-9._-]*(?:=[^"\'\s&]*)?'
            r'(?:&[a-zA-Z][a-zA-Z0-9._-]*(?:=[^"\'\s&]*)?)*)?)["\']'
        )

        # 敏感信息正则
        self.secret_patterns = [
            (r'["\'](?:api[_\s]?key|apikey|api[_\s]?secret)["\'][\s:=]+["\']([^"\'\s]+)["\']', 'API_KEY'),
            (r'["\'](?:access[_\s]?token|access_token)["\'][\s:=]+["\']([^"\'\s]+)["\']', 'ACCESS_TOKEN'),
            (r'["\'](?:secret|secretkey|secret_key)["\'][\s:=]+["\']([^"\'\s]+)["\']', 'SECRET'),
            (r'["\'](?:authorization|auth)["\'][\s:=]+["\']([^"\'\s]+)["\']', 'AUTH_HEADER'),
            (r'AKIA[0-9A-Z]{16}', 'AWS_ACCESS_KEY'),
            (r'sk-[a-zA-Z0-9]{20,}', 'OPENAI_KEY'),
            (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'JWT_TOKEN'),
            (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}', 'GITHUB_TOKEN'),
        ]

    def fetch_js(self, url: str) -> Optional[str]:
        """获取JS文件内容"""
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 200 and resp.text:
                return resp.text
            return None
        except Exception as e:
            return None

    def extract_apis(self, content: str, source_url: str = '') -> dict:
        """从JS内容中提取API接口"""
        result = {
            'source': source_url,
            'api_endpoints': [],
            'paths': [],
            'secrets': [],
        }

        # 提取API端点
        apis = self.api_pattern.findall(content)
        for api in apis:
            clean_path = api.strip('"\' ')
            if clean_path:
                result['api_endpoints'].append(clean_path)
                self.api_endpoints.add(clean_path)

        # 提取所有路径
        paths = self.path_pattern.findall(content)
        for path in paths:
            clean_path = path.strip('"\' ')
            if clean_path and len(clean_path) > 5 and clean_path not in result['api_endpoints']:
                result['paths'].append(clean_path)

        # 提取敏感信息
        for pattern, secret_type in self.secret_patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(1) if match.lastindex >= 1 else match.group(0)
                result['secrets'].append({
                    'type': secret_type,
                    'value': secret_value[:60],  # 只显示前60字符
                    'position': match.start(),
                })
                self.secrets.append({
                    'type': secret_type,
                    'value': secret_value[:60],
                    'source': source_url,
                })

        return result

    def process_js_url(self, js_url: str) -> dict:
        """处理单个JS URL"""
        import time
        print(f"  [*] 分析: {js_url}")

        content = self.fetch_js(js_url)
        if not content:
            print(f"  [-] 获取失败: {js_url}")
            return {'source': js_url, 'api_endpoints': [], 'paths': [], 'secrets': []}

        result = self.extract_apis(content, js_url)
        time.sleep(self.delay)

        if result['api_endpoints']:
            print(f"  [+] 发现 {len(result['api_endpoints'])} 个API端点")
        if result['secrets']:
            print(f"  [!!] 发现 {len(result['secrets'])} 个敏感信息!")
            for s in result['secrets']:
                print(f"       [{s['type']}] {s['value'][:50]}")

        return result

    def process_js_file(self, file_path: str) -> dict:
        """处理本地JS文件"""
        try:
            content = Path(file_path).read_text(encoding='utf-8', errors='ignore')
        except Exception:
            try:
                content = Path(file_path).read_text(encoding='latin-1')
            except Exception:
                print(f"  [-] 读取失败: {file_path}")
                return {'source': file_path, 'api_endpoints': [], 'paths': [], 'secrets': []}

        return self.extract_apis(content, file_path)

    def run_urls(self, urls: List[str], threads: int = 3) -> dict:
        """批量处理URL"""
        results = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.process_js_url, url): url for url in urls}
            for future in as_completed(futures):
                results.append(future.result())

        return self._aggregate(results)

    def run_files(self, files: List[str]) -> dict:
        """批量处理本地文件"""
        results = [self.process_js_file(f) for f in files]
        return self._aggregate(results)

    def _aggregate(self, results: List[dict]) -> dict:
        """聚合结果"""
        all_apis = set()
        all_secrets = []
        for r in results:
            all_apis.update(r.get('api_endpoints', []))
            all_secrets.extend(r.get('secrets', []))

        return {
            'total_sources': len(results),
            'api_endpoints': sorted(all_apis),
            'total_apis': len(all_apis),
            'secrets': all_secrets,
            'total_secrets': len(all_secrets),
        }

    def report(self, result: dict, output: str = None):
        """输出报告"""
        lines = [
            "=" * 60,
            "JS API 接口提取报告",
            f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"分析源文件数: {result['total_sources']}",
            f"发现API端点: {result['total_apis']}",
            f"发现敏感信息: {result['total_secrets']}",
            "=" * 60,
            "",
        ]

        if result['secrets']:
            lines.append("⚠️  敏感信息告警:")
            for s in result['secrets']:
                lines.append(f"  [{s['type']}] {s['value']}")
                if 'source' in s:
                    lines.append(f"    来源: {s['source']}")
            lines.append("")

        if result['api_endpoints']:
            lines.append(f"📋 API接口列表 ({result['total_apis']}个):")
            for api in result['api_endpoints']:
                lines.append(f"  {api}")
            lines.append("")

        report_text = "\n".join(lines)
        print(report_text)

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(report_text, encoding='utf-8')
            print(f"[+] 报告已保存: {output}")

            # 同时导出JSON格式
            json_output = output.replace('.txt', '.json') if output.endswith('.txt') else output + '.json'
            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(result, f, ensure_ascii=False, indent=2)
            print(f"[+] JSON导出: {json_output}")


def main():
    import time
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='JS API接口提取 (仅限授权测试)')
    parser.add_argument('-u', '--url', help='JS文件的URL')
    parser.add_argument('-f', '--file', help='本地JS文件路径或包含URL列表的文件')
    parser.add_argument('-t', '--threads', type=int, default=3, help='并发数')
    parser.add_argument('-o', '--output', default='output/js_extract_report.txt', help='输出报告')
    args = parser.parse_args()

    extractor = JSApiExtractor()

    if args.url:
        result = extractor.process_js_url(args.url)
        result = {
            'total_sources': 1,
            'api_endpoints': list(set(result.get('api_endpoints', []))),
            'total_apis': len(set(result.get('api_endpoints', []))),
            'secrets': result.get('secrets', []),
            'total_secrets': len(result.get('secrets', [])),
        }
        extractor.report(result, args.output)

    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"[!] 文件不存在: {args.file}")
            sys.exit(1)

        content = path.read_text().strip()
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.startswith('#')]

        # 判断是URL还是本地文件路径
        urls = [l for l in lines if l.startswith('http://') or l.startswith('https://')]
        files = [l for l in lines if not l.startswith('http://') and not l.startswith('https://')]

        result = {'total_sources': 0, 'api_endpoints': [], 'total_apis': 0, 'secrets': [], 'total_secrets': 0}

        if urls:
            print(f"\n[*] 处理 {len(urls)} 个JS URL...")
            result = extractor.run_urls(urls, args.threads)

        if files:
            print(f"\n[*] 处理 {len(files)} 个本地文件...")
            file_result = extractor.run_files(files)
            # 合并结果
            result['total_sources'] += file_result['total_sources']
            all_apis = set(result.get('api_endpoints', [])) | set(file_result['api_endpoints'])
            result['api_endpoints'] = sorted(all_apis)
            result['total_apis'] = len(all_apis)
            result['secrets'] = list(result.get('secrets', [])) + list(file_result.get('secrets', []))
            result['total_secrets'] = len(result['secrets'])

        extractor.report(result, args.output)

    else:
        parser.print_help()
        sys.exit(1)


if __name__ == '__main__':
    main()
