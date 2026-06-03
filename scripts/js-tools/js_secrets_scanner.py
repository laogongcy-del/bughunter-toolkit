#!/usr/bin/env python3
"""
BugBounty Toolkit — JS密钥/敏感信息扫描器
==========================================
用途: 扫描JS文件中泄露的API密钥、Token、密码等敏感信息
使用方法:
    python js_secrets_scanner.py -u https://target.com/app.js
    python js_secrets_scanner.py -d https://target.com/assets/

注意: 仅用于已获得明确授权的安全测试！
      发现敏感信息后仅记录，不利用。
"""

import argparse
import json
import re
import sys
import time
import urllib3
from pathlib import Path
from typing import List, Set, Optional
from urllib.parse import urljoin, urlparse

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║      ⚠️  JS敏感信息扫描 — 仅限授权测试                        ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确授权的安全测试                           ║
║ 发现的敏感信息仅用于漏洞报告，不得用于未授权访问                 ║
╚══════════════════════════════════════════════════════════════╝
"""

# 敏感信息检测规则 (正则, 类型, 严重级别)
SECRET_RULES = [
    # 云服务密钥
    (r'AKIA[0-9A-Z]{16}', 'AWS_Access_Key', 'HIGH'),
    (r'("|'')?(?:aws_access_key_id|aws_secret_access_key)("|'')?\s*[:=]\s*("|'')([A-Za-z0-9/+=]{20,})("|'')', 'AWS_Credential', 'HIGH'),
    (r'["\'](?:sk|pk)_[a-zA-Z0-9]{20,}["\']', 'Stripe_Key', 'HIGH'),
    (r'(?:sk|pk)_(?:live|test)_[a-zA-Z0-9]{10,}', 'Stripe_Key_v2', 'HIGH'),

    # 通用API密钥
    (r'["\'](?:api[_-]?key|api[_-]?secret|app[_-]?secret)["\'][\s:=]+["\']([^"\'\s]{8,})["\']', 'API_Key', 'HIGH'),
    (r'["\'](?:secret|secretkey|secret_key|client_secret)["\'][\s:=]+["\']([^"\'\s]{8,})["\']', 'Secret_Key', 'HIGH'),

    # Token
    (r'eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}', 'JWT_Token', 'MEDIUM'),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[a-zA-Z0-9]{36}', 'GitHub_Token', 'HIGH'),
    (r'(?:xox[bpsa]|xapp|xoxr)-[a-zA-Z0-9-]{10,}', 'Slack_Token', 'HIGH'),
    (r'(?:sk|pk)_[a-f0-9]{32,}', 'Private_Key_Hash', 'HIGH'),

    # 认证相关
    (r'["\'](?:authorization|auth|bearer)["\'][\s:=]+["\']([A-Za-z0-9+/=.=_\-]{20,})["\']', 'Auth_Token', 'HIGH'),
    (r'(?:-----BEGIN (?:RSA |EC )?PRIVATE KEY-----)', 'Private_Key', 'CRITICAL'),
    (r'(?:-----BEGIN CERTIFICATE-----)', 'Certificate', 'MEDIUM'),

    # 连接字符串
    (r'(?:mongodb(?:\+srv)?://)[^\s\'"]+', 'MongoDB_URI', 'HIGH'),
    (r'(?:mysql://)[^\s\'"]+', 'MySQL_URI', 'HIGH'),
    (r'(?:postgres(?:ql)?://)[^\s\'"]+', 'PostgreSQL_URI', 'HIGH'),
    (r'(?:redis://)[^\s\'"]+', 'Redis_URI', 'HIGH'),
    (r'jdbc:[a-z]+://[^\s\'"]+', 'JDBC_URI', 'MEDIUM'),

    # OpenAI/其他AI服务
    (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI_API_Key', 'HIGH'),
    (r'["\'](?:openai|claude|anthropic)["\'][\s:=]+["\'](sk-[a-zA-Z0-9]+)["\']', 'AI_API_Key', 'HIGH'),

    # Google服务
    (r'AIza[0-9A-Za-z_-]{35}', 'Google_API_Key', 'HIGH'),
    (r'["\'](?:google_client_id|google_oauth)["\'][\s:=]+["\'](\d+[-_][a-zA-Z0-9_-]+\.apps\.googleusercontent\.com)["\']', 'Google_OAuth_ID', 'MEDIUM'),

    # Firebase
    (r'["\'](?:firebase|firebase_url|databaseURL)["\'][\s:=]+["\']([^"\'\s]+)["\']', 'Firebase_URL', 'MEDIUM'),

    # 内网地址泄露
    (r'(?:https?://)?(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3})(?::\d+)?(?:/[\w./-]*)?', 'Internal_IP', 'LOW'),
    (r'(?:https?://)?(?:172\.1[6-9]|172\.2\d|172\.3[01])\.\d{1,3}\.\d{1,3}(?::\d+)?', 'Internal_IP', 'LOW'),
    (r'(?:https?://)?192\.168\.\d{1,3}\.\d{1,3}(?::\d+)?', 'Internal_IP', 'LOW'),
]


class SecretsScanner:
    """JS敏感信息扫描器"""

    def __init__(self, timeout: int = 15, delay_ms: int = 500):
        self.timeout = timeout
        self.delay = delay_ms / 1000.0
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })
        self.findings: List[dict] = []

    def scan_content(self, content: str, source: str = '') -> List[dict]:
        """扫描文本内容中的敏感信息"""
        findings = []

        for pattern, secret_type, severity in SECRET_RULES:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                # 提取实际匹配的值
                value = match.group(0)
                # 如果有捕获组，优先使用第一个捕获组
                if match.lastindex and match.lastindex >= 1:
                    for i in range(1, match.lastindex + 1):
                        if match.group(i):
                            value = match.group(i)
                            break

                findings.append({
                    'type': secret_type,
                    'severity': severity,
                    'value': value[:60],  # 截断显示
                    'position': match.start(),
                    'source': source,
                })

        return findings

    def scan_url(self, url: str) -> List[dict]:
        """扫描远程JS文件"""
        try:
            resp = self.session.get(url, timeout=self.timeout)
            time.sleep(self.delay)

            if resp.status_code != 200:
                return []

            findings = self.scan_content(resp.text, url)
            if findings:
                print(f"  [!!] {url}: 发现 {len(findings)} 个敏感信息")
                for f in findings:
                    print(f"       [{f['severity']}][{f['type']}] {f['value'][:50]}")
            else:
                print(f"  [*] {url}: 安全")

            return findings

        except Exception as e:
            print(f"  [-] {url}: 扫描失败 ({type(e).__name__})")
            return []

    def scan_directory(self, base_url: str, depth: int = 1) -> List[dict]:
        """扫描目录下所有JS文件"""
        all_findings = []
        # 先获取页面，提取所有JS引用
        try:
            resp = self.session.get(base_url, timeout=self.timeout)
            if resp.status_code == 200:
                # 提取script标签
                js_urls = re.findall(r'<script[^>]*src=["\']([^"\']+\.js[^"\']*)["\']', resp.text, re.IGNORECASE)
                # 提取所有.js链接
                js_urls += re.findall(r'["\']([^"\']*\.js(?:[?][^"\']*)?)["\']', resp.text)

                seen = set()
                for js in js_urls:
                    full_url = urljoin(base_url, js)
                    if full_url not in seen:
                        seen.add(full_url)
                        all_findings.extend(self.scan_url(full_url))
                        self.findings.extend(all_findings)
        except Exception:
            pass

        return all_findings

    def report(self, output: str = None):
        """生成报告"""
        if not self.findings:
            print("\n[+] 未发现敏感信息泄露")
            return

        # 按严重程度分组
        by_severity = {'CRITICAL': [], 'HIGH': [], 'MEDIUM': [], 'LOW': []}
        for f in self.findings:
            by_severity.setdefault(f['severity'], []).append(f)

        lines = [
            "=" * 60,
            "JS 敏感信息扫描报告",
            f"生成时间: {time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"发现总数: {len(self.findings)}",
            "=" * 60,
            "",
        ]

        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            items = by_severity.get(severity, [])
            if items:
                severity_label = {'CRITICAL': '🔴 严重', 'HIGH': '🟠 高危',
                                  'MEDIUM': '🟡 中危', 'LOW': '🔵 低危'}.get(severity, severity)
                lines.append(f"\n{severity_label} ({len(items)}个):")
                for i, f in enumerate(items, 1):
                    lines.append(f"  {i}. [{f['type']}] {f['value'][:50]}")
                    if f.get('source'):
                        lines.append(f"     来源: {f['source']}")
                lines.append("")

        report_text = "\n".join(lines)
        print(report_text)

        if output:
            Path(output).parent.mkdir(parents=True, exist_ok=True)
            Path(output).write_text(report_text, encoding='utf-8')
            print(f"[+] 报告已保存: {output}")

            # JSON格式
            json_output = output.replace('.txt', '.json')
            with open(json_output, 'w', encoding='utf-8') as f:
                json.dump(self.findings, f, ensure_ascii=False, indent=2)
            print(f"[+] JSON导出: {json_output}")


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='JS敏感信息扫描 (仅限授权测试)')
    parser.add_argument('-u', '--url', help='JS文件的URL')
    parser.add_argument('-d', '--dir', help='目标页面URL (自动提取所有JS)')
    parser.add_argument('-f', '--file', help='包含JS URL列表的文件')
    parser.add_argument('-o', '--output', default='output/secrets_scan_report.txt', help='输出报告')
    args = parser.parse_args()

    scanner = SecretsScanner()

    if args.url:
        findings = scanner.scan_url(args.url)
        scanner.findings = findings
        scanner.report(args.output)

    elif args.dir:
        print(f"\n[*] 扫描目录: {args.dir}")
        scanner.scan_directory(args.dir)
        scanner.report(args.output)

    elif args.file:
        path = Path(args.file)
        if not path.exists():
            print(f"[!] 文件不存在: {args.file}")
            sys.exit(1)

        urls = [l.strip() for l in path.read_text().splitlines()
                if l.strip() and not l.startswith('#') and
                (l.startswith('http://') or l.startswith('https://'))]

        print(f"\n[*] 扫描 {len(urls)} 个JS文件...")
        for url in urls:
            scanner.findings.extend(scanner.scan_url(url))

        scanner.report(args.output)

    else:
        parser.print_help()


if __name__ == '__main__':
    main()
