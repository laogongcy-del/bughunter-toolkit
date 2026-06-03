#!/usr/bin/env python3
"""
BugBounty Toolkit — JS文件变化监控器
======================================
用途: 监控JS文件内容变化，发现新增API、密钥、功能（常用于监控目标更新）
使用方法:
    python js_diff.py init https://target.com/app.js
    python js_diff.py check https://target.com/app.js

注意: 仅用于已获得明确授权的安全测试！
"""

import argparse
import hashlib
import json
import sys
import time
import urllib3
from pathlib import Path
from typing import Optional

import requests

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║      ⚠️  JS变化监控 — 仅限授权测试                           ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确授权的安全测试                           ║
║ 用于监控目标JS变化（新增API、移除调试功能等）                   ║
╚══════════════════════════════════════════════════════════════╝
"""


class JSDiffer:
    """JS文件变化监控器"""

    def __init__(self, base_dir: str = 'output/js_snapshots'):
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        })

    def _safe_filename(self, url: str) -> str:
        """将URL转为安全的文件名"""
        return hashlib.md5(url.encode()).hexdigest()

    def _fetch_js(self, url: str) -> Optional[str]:
        """获取JS内容"""
        try:
            resp = self.session.get(url, timeout=15)
            return resp.text if resp.status_code == 200 else None
        except Exception:
            return None

    def _hash_content(self, content: str) -> str:
        """计算内容hash"""
        return hashlib.sha256(content.encode()).hexdigest()

    def init_snapshot(self, url: str) -> bool:
        """初始化快照"""
        print(f"[*] 初始化快照: {url}")
        content = self._fetch_js(url)

        if not content:
            print(f"[-] 获取JS失败: {url}")
            return False

        file_id = self._safe_filename(url)
        snapshot_file = self.base_dir / f"{file_id}.snapshot"

        # 保存内容
        (self.base_dir / f"{file_id}.content").write_text(content, encoding='utf-8')

        snapshot = {
            'url': url,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'hash': self._hash_content(content),
            'size': len(content),
        }
        snapshot_file.write_text(json.dumps(snapshot, indent=2))

        print(f"  [+] 快照已保存")
        print(f"  [+] 大小: {len(content)} bytes")
        print(f"  [+] Hash: {snapshot['hash'][:16]}")
        return True

    def check_diff(self, url: str) -> dict:
        """检查与快照的差异"""
        file_id = self._safe_filename(url)
        snapshot_file = self.base_dir / f"{file_id}.snapshot"
        content_file = self.base_dir / f"{file_id}.content"

        if not snapshot_file.exists():
            return {'error': '快照不存在，请先运行 init'}

        old_snapshot = json.loads(snapshot_file.read_text())
        old_content = content_file.read_text(encoding='utf-8') if content_file.exists() else ''
        new_content = self._fetch_js(url)

        if not new_content:
            return {'error': '获取JS失败'}

        new_hash = self._hash_content(new_content)
        old_hash = old_snapshot['hash']

        result = {
            'url': url,
            'old_time': old_snapshot['time'],
            'new_time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'old_size': old_snapshot['size'],
            'new_size': len(new_content),
            'changed': new_hash != old_hash,
        }

        if result['changed']:
            print(f"  [!!] JS文件已变化!")
            print(f"      旧: {old_snapshot['size']} bytes ({old_snapshot['time']})")
            print(f"      新: {len(new_content)} bytes (当前)")

            # 简单diff（按行）
            old_lines = old_content.split('\n')
            new_lines = new_content.split('\n')

            # 查找新增/删除的行
            old_set = set(old_lines)
            new_set = set(new_lines)

            added = [l for l in new_lines if l.strip() and l not in old_set]
            removed = [l for l in old_lines if l.strip() and l not in new_set]

            # 查找新增API端点
            import re
            added_apis = []
            for line in added:
                apis = re.findall(r'["\']((?:/[a-zA-Z][a-zA-Z0-9._-]*)+)["\']', line)
                added_apis.extend(apis)

            if added_apis:
                print(f"\n  [+] 新增API端点:")
                for api in added_apis[:20]:
                    print(f"      {api}")

            if added:
                print(f"\n  [+] 新增 {len(added)} 行 (可能包含新功能)")
            if removed:
                print(f"  [-] 删除 {len(removed)} 行 (可能移除调试代码)")

            # 保存新快照
            self.base_dir / f"{file_id}.content"
            Path(str(content_file) + ".new").write_text(new_content, encoding='utf-8')

            result['added_lines'] = len(added)
            result['removed_lines'] = len(removed)
            result['added_apis'] = added_apis[:20]

            # 询问是否更新快照
            print(f"\n  [?] 是否更新快照？(y/n): ", end='')
            # 非交互模式自动更新
            import sys as _sys
            if '--auto-update' in _sys.argv:
                self._update_snapshot(file_id, url, new_content, new_hash)
        else:
            print(f"  [*] JS文件无变化")

        return result

    def _update_snapshot(self, file_id: str, url: str, content: str, hash_val: str):
        """更新快照"""
        snapshot = {
            'url': url,
            'time': time.strftime('%Y-%m-%d %H:%M:%S'),
            'hash': hash_val,
            'size': len(content),
        }
        (self.base_dir / f"{file_id}.snapshot").write_text(json.dumps(snapshot, indent=2))
        (self.base_dir / f"{file_id}.content").write_text(content, encoding='utf-8')
        if Path(f"{self.base_dir / file_id}.content.new").exists():
            Path(f"{self.base_dir / file_id}.content.new").unlink()
        print(f"  [+] 快照已更新")


def main():
    print(BANNER)
    print("[!] 你是否已获得目标系统的书面测试授权？")
    resp = input("输入 yes 继续: ").strip().lower()
    if resp not in ('yes', 'y'):
        print("[!] 未确认授权，退出。")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='JS文件变化监控 (仅限授权测试)')
    parser.add_argument('action', choices=['init', 'check'], help='init=初始化快照, check=检查变化')
    parser.add_argument('-u', '--url', required=True, help='JS文件的URL')
    parser.add_argument('--auto-update', action='store_true', help='check后自动更新快照')
    args = parser.parse_args()

    differ = JSDiffer()

    if args.action == 'init':
        differ.init_snapshot(args.url)
    elif args.action == 'check':
        result = differ.check_diff(args.url)
        if 'error' in result:
            print(f"[-] {result['error']}")
            sys.exit(1)


if __name__ == '__main__':
    main()
