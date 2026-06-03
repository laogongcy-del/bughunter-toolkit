#!/usr/bin/env python3
"""
BugBounty Toolkit — OOB/带外检测工具
======================================
用途: 用于检测盲注、无回显类漏洞的带外检测
使用方法:
    python oob_collab.py              # 启动HTTP监听
    python oob_collab.py --dns        # 启动DNS监听（需root）
    python oob_collab.py --gen        # 生成测试URL

注意: 仅用于已获得明确授权的安全测试！
      本工具仅用于漏洞存在性检测，不用于数据窃取。
"""

import argparse
import json
import random
import string
import sys
import time
import urllib3
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║      ⚠️  OOB检测工具 — 仅限授权测试                          ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于盲注/无回显漏洞的存在性检测                         ║
║ 不用于数据窃取，检测结果仅用于漏洞报告                          ║
╚══════════════════════════════════════════════════════════════╝
"""


class OOBRequestHandler(BaseHTTPRequestHandler):
    """OOB HTTP请求处理器"""

    def do_GET(self):
        log_entry = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'method': 'GET',
            'path': self.path,
            'client': self.client_address[0],
            'headers': dict(self.headers),
        }
        self.server.oob_log.append(log_entry)  # type: ignore
        print(f"  [OOB] GET {self.path} from {self.client_address[0]}")

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OOB OK')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length) if content_length > 0 else b''

        log_entry = {
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'method': 'POST',
            'path': self.path,
            'client': self.client_address[0],
            'headers': dict(self.headers),
            'body': body[:200].decode('utf-8', errors='replace'),
        }
        self.server.oob_log.append(log_entry)  # type: ignore
        print(f"  [OOB] POST {self.path} from {self.client_address[0]} ({len(body)}B)")

        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.end_headers()
        self.wfile.write(b'OOB OK')

    def log_message(self, format, *args):
        pass  # 关闭默认日志，使用自定义输出


class OOBServer:
    """OOB检测服务器"""

    def __init__(self, host: str = '0.0.0.0', port: int = 8888):
        self.host = host
        self.port = port
        self.log: list = []
        self.server: Optional[HTTPServer] = None

    def generate_test_url(self, prefix: str = 'oob') -> str:
        """生成随机测试URL"""
        random_str = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
        return f"http://{self.host}:{self.port}/{prefix}-{random_str}"

    def start(self, timeout: int = 300):
        """启动OOB监听服务器"""
        server = HTTPServer((self.host, self.port), OOBRequestHandler)
        server.oob_log = self.log
        self.server = server

        print(f"\n[+] OOB监听已启动: http://{self.host}:{self.port}")
        print(f"[+] 监听超时: {timeout}秒")
        print(f"[+] 测试URL示例: {self.generate_test_url()}")
        print(f"\n[*] 在目标请求中使用以上URL进行OOB检测")
        print(f"[*] 按 Ctrl+C 停止监听\n")

        server.timeout = timeout
        try:
            while True:
                server.handle_request()
        except KeyboardInterrupt:
            print("\n[-] 用户中断")
        finally:
            self.stop()

    def stop(self):
        """停止监听"""
        if self.server:
            self.server.server_close()
            self.server = None

    def show_log(self):
        """显示检测结果"""
        if not self.log:
            print("[*] 未收到OOB请求")
            return

        print(f"\n{'='*60}")
        print(f"✅ OOB检测报告 — 收到 {len(self.log)} 个请求")
        print(f"{'='*60}")
        for i, entry in enumerate(self.log, 1):
            print(f"\n  [{i}] {entry['time']}")
            print(f"      来源: {entry['method']} {entry['path']}")
            print(f"      客户端: {entry['client']}")
            if entry.get('body'):
                print(f"      内容: {entry['body'][:100]}")

        print(f"\n{'='*60}")
        print("⚠️  收到OOB请求说明存在盲注/无回显类漏洞可能性")
        print("⚠️  请结合业务逻辑判断实际危害")


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='OOB带外检测工具 (仅限授权测试)')
    parser.add_argument('--host', default='0.0.0.0', help='监听IP (默认 0.0.0.0)')
    parser.add_argument('--port', type=int, default=8888, help='监听端口 (默认 8888)')
    parser.add_argument('--timeout', type=int, default=300, help='监听超时秒数 (默认 300)')
    parser.add_argument('--gen', action='store_true', help='仅生成测试URL，不启动监听')
    args = parser.parse_args()

    server = OOBServer(args.host, args.port)

    if args.gen:
        test_url = server.generate_test_url()
        print(f"\n[+] OOB测试URL: {test_url}")
        print(f"[*] 请在其他终端运行: python oob_collab.py --port {args.port}")
        return

    server.start(timeout=args.timeout)
    server.show_log()


if __name__ == '__main__':
    main()
