#!/usr/bin/env python3
"""
PoC: 越权访问存在性证明工具
================================
用途: 在发现可能的IDOR漏洞后，证明不同用户ID返回不同数据
方案: 仅对比响应元数据 (状态码、响应长度、存在/不存在)，不展示实际数据内容

使用条件: ONLY FOR AUTHORIZED SECURITY TESTING
你必须获得目标系统的书面授权才能使用此工具。

支持的认证方式:
  - Cookie-based   : 通过Cookie头进行认证
  - Bearer Token   : 通过Authorization: Bearer头进行认证
  - Custom Header  : 通过自定义请求头进行认证

版本: 1.0.0
"""

import argparse
import sys
import time
import hashlib
import json
from datetime import datetime
from urllib.parse import urlparse
from difflib import HtmlDiff

try:
    import requests
except ImportError:
    print("[!] 缺少依赖: requests")
    print("    安装: pip install requests")
    sys.exit(1)


# ============================================================
# 授权确认
# ============================================================
def confirm_authorization():
    """显示授权声明并等待用户确认"""
    print("=" * 70)
    print("  越权访问存在性证明工具 - IDOR Proof PoC")
    print("=" * 70)
    print()
    print("  [重要声明]")
    print("  本工具仅用于**已获得明确书面授权**的安全测试。")
    print("  未经授权使用本工具攻击目标系统属于违法行为。")
    print("  使用者需自行承担所有法律责任。")
    print()
    print("  本工具的行为: ")
    print("  - 仅对比不同用户ID的响应元数据 (状态码、长度、关键词)")
    print("  - 不会展示或保存实际响应中的数据内容")
    print("  - 所有请求均带有速率限制，避免对目标造成影响")
    print("  - 响应内容经过不可逆哈希处理，无法还原原始数据")
    print()
    print("  [合规要求]")
    print("  1. 你拥有目标系统的书面渗透测试授权")
    print("  2. 你已获得测试范围书面确认")
    print("  3. 你了解并遵守当地法律法规")
    print()
    try:
        resp = input("  继续执行请输 'yes' 确认授权 > ").strip().lower()
        if resp != "yes":
            print("\n  [!] 已取消操作。请在获得授权后再使用本工具。")
            return False
    except (EOFError, KeyboardInterrupt):
        print("\n  [!] 用户取消操作。")
        return False
    print()
    return True


# ============================================================
# 速率限制
# ============================================================
class RateLimiter:
    """请求速率限制器"""

    def __init__(self, delay_ms=600):
        self.min_interval = delay_ms / 1000.0
        self._last_call = 0.0

    def wait(self):
        elapsed = time.time() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.time()


def safe_request(method, url, headers=None, **kwargs):
    """带超时和错误处理的HTTP请求"""
    defaults = {"timeout": 15, "verify": False}
    defaults.update(kwargs)
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        return requests.request(method, url, headers=headers, **defaults)
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"    [请求失败] 连接错误: {e}")
        return None
    except Exception as e:
        print(f"    [请求失败] 未知错误: {e}")
        return None


# ============================================================
# 响应分析
# ============================================================
class ResponseSummary:
    """对响应内容做最小化摘要，不保留原始数据"""

    def __init__(self, response):
        self.status_code = response.status_code if response else 0
        self.content_length = len(response.text) if response and hasattr(response, 'text') else 0
        self.content_hash = hashlib.sha256(
            response.text.encode() if response and hasattr(response, 'text') else b""
        ).hexdigest()[:16]
        self.headers = dict(response.headers) if response and hasattr(response, 'headers') else {}
        self.elapsed = response.elapsed.total_seconds() if response and hasattr(response, 'elapsed') else 0.0

        # 提取关键元数据 (不包含实际数据)
        self.metadata = {
            "content_type": self.headers.get("Content-Type", ""),
            "content_length": self.content_length,
        }

    def __eq__(self, other):
        """两个响应是否"相似" (用于判断IDOR是否存在)"""
        if not isinstance(other, ResponseSummary):
            return False
        # 状态码不同 -> 肯定存在差异
        if self.status_code != other.status_code:
            return False
        # 响应长度差异超过20% -> 可能存在差异
        if self.content_length > 0 and other.content_length > 0:
            ratio = min(self.content_length, other.content_length) / max(self.content_length, other.content_length)
            if ratio < 0.8:
                return False
        # 哈希不同 -> 内容不同
        if self.content_hash != other.content_hash:
            return False
        return True

    def difference_score(self, other):
        """计算两个响应的差异分数 (0-100)"""
        score = 0
        if self.status_code != other.status_code:
            score += 40
        len_diff = abs(self.content_length - other.content_length)
        if self.content_length > 0:
            ratio = len_diff / max(self.content_length, 1)
            score += min(ratio * 50, 50)
        return min(score, 100)

    def to_dict(self):
        """安全的摘要输出"""
        return {
            "status_code": self.status_code,
            "content_length": self.content_length,
            "content_hash": self.content_hash,
            "elapsed_seconds": round(self.elapsed, 3),
            "metadata": self.metadata,
        }


# ============================================================
# IDOR检测逻辑
# ============================================================
def detect_idor(base_url, own_id, target_ids, headers, id_placeholder, delay_ms):
    """
    核心检测逻辑:
    1. 使用own_id获取自己的数据作为基线
    2. 用target_ids获取其他用户的数据
    3. 对比响应，判断是否存在越权
    """
    rate_limiter = RateLimiter(delay_ms)

    print("\n  [步骤1] 获取自身数据作为基线")
    print("  " + "-" * 50)

    own_url = base_url.replace(id_placeholder, str(own_id))
    print(f"    [*] 请求自身ID: {own_id}")
    print(f"    [*] URL: {own_url}")

    rate_limiter.wait()
    own_resp = safe_request("GET", own_url, headers=headers)
    if own_resp is None:
        print("    [!] 无法获取自身数据，请检查认证凭据")
        return None

    own_summary = ResponseSummary(own_resp)
    print(f"    [*] 状态码: {own_summary.status_code}")
    print(f"    [*] 响应长度: {own_summary.content_length} bytes")
    print(f"    [*] 内容哈希: {own_summary.content_hash}")
    print(f"    [*] 响应时间: {own_summary.elapsed:.3f}s")

    print(f"\n  [步骤2] 尝试访问其他用户数据")
    print("  " + "-" * 50)

    idor_findings = []

    for i, tid in enumerate(target_ids):
        target_url = base_url.replace(id_placeholder, str(tid))
        print(f"\n    [{i+1}/{len(target_ids)}] 测试ID: {tid}")
        print(f"       URL: {target_url}")

        rate_limiter.wait()
        target_resp = safe_request("GET", target_url, headers=headers)
        if target_resp is None:
            print("       [跳过] 请求失败")
            continue

        target_summary = ResponseSummary(target_resp)
        diff_score = own_summary.difference_score(target_summary)

        print(f"       状态码: {target_summary.status_code}")
        print(f"       响应长度: {target_summary.content_length} bytes")
        print(f"       内容哈希: {target_summary.content_hash}")
        print(f"       差异分数: {diff_score}/100")

        # 判断是否存在越权
        # 如果状态码都是200但内容不同，或者状态码不同，都可能是IDOR
        finding = {
            "target_id": tid,
            "own_status": own_summary.status_code,
            "target_status": target_summary.status_code,
            "own_length": own_summary.content_length,
            "target_length": target_summary.content_length,
            "diff_score": diff_score,
            "potential_idor": False,
            "reason": "",
        }

        if target_summary.status_code == 200:
            # 成功返回了数据
            if diff_score > 30:
                finding["potential_idor"] = True
                finding["reason"] = f"状态码200，但与自身ID的比较差异分数为{diff_score}"
                idor_findings.append(finding)
                print("       [!] 可能存在越权: 可访问其他用户数据!")
            else:
                print("       [*] 数据与自身ID一致，可能是通用接口")
        elif target_summary.status_code == 403:
            print("       [*] 返回403: 权限控制生效")
        elif target_summary.status_code == 404:
            print("       [*] 返回404: 可能ID不存在")
        elif target_summary.status_code == 401:
            print("       [*] 返回401: 认证失败，请检查凭据")
        else:
            finding["reason"] = f"状态码{target_summary.status_code}"
            if target_summary.status_code not in (401, 403, 404, 500):
                finding["potential_idor"] = True
                idor_findings.append(finding)
                print(f"       [!] 异常状态码: {target_summary.status_code}")

        if not finding["potential_idor"]:
            print("       [安全] 未检测到越权")

    return {
        "own_id": own_id,
        "own_summary": own_summary.to_dict(),
        "findings": idor_findings,
    }


# ============================================================
# 报告生成
# ============================================================
def generate_report(target_url, results):
    """生成报告格式的输出，仅包含元数据，不含实际数据"""
    if not results:
        return None

    finding_count = len(results.get("findings", []))

    # 生成证据哈希链
    evidence_entries = []
    for f in results.get("findings", []):
        chain_input = f"{target_url}:{f['target_id']}:{f['target_status']}:{f['target_length']}:{f['diff_score']}"
        evidence_entries.append(hashlib.sha256(chain_input.encode()).hexdigest()[:16])

    report = {
        "vulnerability": "IDOR (Insecure Direct Object Reference / 越权访问)",
        "target": target_url,
        "severity": "High (如影响其他用户数据) / Medium (如仅泄露非敏感信息)",
        "own_id": results.get("own_id"),
        "affected_ids_found": finding_count,
        "potential_idor_ids": [f["target_id"] for f in results.get("findings", [])],
        "evidence_hashes": evidence_entries,
        "tested_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "disclaimer": "仅对比了响应元数据 (状态码/长度/哈希)，未获取/存储任何用户实际数据",
        "recommendations": [
            "使用基于会话的用户标识，而非从请求参数中获取",
            "实施严格的访问控制检查: 验证当前用户是否有权访问请求的资源",
            "使用属性级访问控制 (ABAC) 或关系级访问控制",
            "对API接口进行自动化测试，确保越权场景被覆盖",
            "日志记录所有越权尝试，以便追溯",
        ],
    }

    return report


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="越权访问存在性证明工具 - IDOR Proof PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # Cookie认证 - 测试多个用户ID
  python idor_proof.py -u "http://target.com/api/user/PROFILE_ID/profile" \\
      -p PROFILE_ID --own-id 1001 --target-ids 1002 1003 1004 \\
      --cookie "sessionid=abc123"

  # Bearer Token
  python idor_proof.py -u "http://target.com/api/order/ORDER_ID" \\
      -p ORDER_ID --own-id 5001 --target-ids 5002 5003 \\
      --token "eyJhbGciOi..."

  # 自定义头认证
  python idor_proof.py -u "http://target.com/api/doc/DOC_ID" \\
      -p DOC_ID --own-id 100 --target-ids 200 300 400 \\
      --header "X-API-Key: secret123"

注意事项:
  - 请使用自己的合法账号ID作为 --own-id
  - --target-ids 请使用测试账号或公开ID
  - 本工具不会获取/显示其他用户的实际数据
  - 请确保已获得目标授权
        """,
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="目标API URL，包含ID占位符 (如: http://target.com/api/user/USER_ID/profile)",
    )
    parser.add_argument(
        "-p", "--placeholder",
        default="USER_ID",
        help="ID占位符 (默认: USER_ID)",
    )
    parser.add_argument(
        "--own-id",
        required=True,
        help="自己的用户/资源ID (用于获取基线数据)",
    )
    parser.add_argument(
        "--target-ids",
        nargs="+",
        required=True,
        help="要测试的其他用户/资源ID列表 (空格分隔)",
    )

    # 认证方式 (三选一)
    auth_group = parser.add_mutually_exclusive_group()
    auth_group.add_argument(
        "--cookie",
        help="Cookie认证字符串 (如: \"sessionid=abc123; csrftoken=xyz\")",
    )
    auth_group.add_argument(
        "--token",
        help="Bearer Token (如: eyJhbGciOi...)",
    )
    auth_group.add_argument(
        "--header",
        action="append",
        dest="custom_headers",
        help="自定义请求头 (可多次使用，如: --header \"X-API-Key: secret123\")",
    )

    parser.add_argument(
        "-d", "--delay",
        type=int,
        default=600,
        help="请求间隔延迟，单位毫秒 (默认: 600)",
    )
    parser.add_argument(
        "--no-confirm",
        action="store_true",
        help="跳过授权确认 (仅脚本调用时使用)",
    )

    args = parser.parse_args()

    # 授权确认
    if not args.no_confirm and not confirm_authorization():
        sys.exit(1)

    # 构建请求头
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Accept": "application/json, text/html, */*",
    }

    if args.cookie:
        headers["Cookie"] = args.cookie
        print("    [认证方式] Cookie")
    elif args.token:
        headers["Authorization"] = f"Bearer {args.token}"
        print("    [认证方式] Bearer Token")
    elif args.custom_headers:
        for h in args.custom_headers:
            if ":" in h:
                key, value = h.split(":", 1)
                headers[key.strip()] = value.strip()
        print("    [认证方式] 自定义请求头")
    else:
        print("    [警告] 未指定认证方式，将发送无认证请求")
        print("    [提示] 请使用 --cookie, --token 或 --header 提供认证凭据")
        if not args.no_confirm:
            try:
                resp = input("    是否继续? (yes/no) > ").strip().lower()
                if resp != "yes":
                    print("    已取消操作。")
                    sys.exit(1)
            except (EOFError, KeyboardInterrupt):
                print("\n    已取消操作。")
                sys.exit(1)

    # 验证URL
    parsed = urlparse(args.url)
    if not parsed.netloc:
        print("[!] URL格式无效")
        sys.exit(1)

    if args.placeholder not in args.url:
        print(f"[!] URL中未找到占位符 '{args.placeholder}'")
        print(f"    请在URL中使用 {args.placeholder} 标记ID位置")
        sys.exit(1)

    print()
    print("=" * 70)
    print(f"  IDOR越权检测")
    print(f"  目标: {args.url}")
    print(f"  自身ID: {args.own_id}")
    print(f"  测试ID数: {len(args.target_ids)}")
    print(f"  请求间隔: {args.delay}ms")
    print("=" * 70)

    # 执行检测
    results = detect_idor(
        base_url=args.url,
        own_id=args.own_id,
        target_ids=args.target_ids,
        headers=headers,
        id_placeholder=args.placeholder,
        delay_ms=args.delay,
    )

    # 输出结果
    print()
    print("=" * 70)
    if results and results.get("findings"):
        findings = results["findings"]
        print(f"  [检测结果] 发现 {len(findings)} 个潜在IDOR漏洞!")
        print()

        for f in findings:
            print(f"  [!] ID: {f['target_id']}")
            print(f"      状态码: {f['target_status']} (自身: {f['own_status']})")
            print(f"      响应长度: {f['target_length']} bytes (自身: {f['own_length']} bytes)")
            print(f"      差异分数: {f['diff_score']}/100")
            print(f"      原因: {f['reason']}")
            print()

        report = generate_report(args.url, results)
        if report:
            print("  --- 报告编写参考 ---")
            print(f"  漏洞类型: {report['vulnerability']}")
            print(f"  影响等级: {report['severity']}")
            print(f"  漏洞描述: 在 {args.url} 发现IDOR漏洞。")
            print(f"           用户可通过修改ID参数访问其他用户的数据。")
            print(f"           本次测试发现 {len(findings)} 个可越权访问的资源。")
            print()
            print("  --- 修复建议 ---")
            for rec in report["recommendations"]:
                print(f"  - {rec}")
            print()
            print(f"  [!] 注意: {report['disclaimer']}")
            print()
            print("  --- 机器可读结果 (JSON) ---")
            print(f"  {json.dumps(report, ensure_ascii=False, indent=2)}")
    else:
        print("  [检测结果] 未检测到IDOR漏洞")
        print()
        print("  可能的原因:")
        print("  - 目标接口已有完善的访问控制")
        print("  - 选择的target_ids不存在或无效")
        print("  - 需要API接口返回不同的状态码才能判断")
        print("  - 未登录状态与已登录状态返回相同数据")

    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
