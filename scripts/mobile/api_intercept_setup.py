#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
移动API抓取配置助手 - Mobile API Interception Setup Assistant
===============================================================
用途: 自动生成移动端API抓取配置，提供代理设置指南和流量分析工具

功能:
  1. 生成 Burp Suite / mitmproxy 配置
  2. 生成 Android/iOS 代理配置命令
  3. 提供 ADB 命令设置模拟器代理
  4. 提供 Android 7+ 证书导入绕过方案
  5. 流量分析工具（从抓包文件提取API端点）
  6. 生成一键配置脚本

注意:
  本工具仅用于已获得明确授权的安全测试。
  拦截和分析移动端流量应仅在您拥有或已获授权的设备上进行。

合规要求:
  1. 必须获得目标App所有者的书面授权
  2. 拦截的流量不得泄露给第三方
  3. 测试完成后应清理代理配置
  4. 不得利用截获的凭据进行未授权访问
  5. 中国大陆用户注意遵守《网络安全法》相关规定
"""

import argparse
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
from datetime import datetime
from typing import Optional, List, Dict, Tuple
from pathlib import Path

# ---------------------------------------------------------------------------
# 授权确认
# ---------------------------------------------------------------------------
CONSENT_TEXT = """
╔══════════════════════════════════════════════════════════════════════╗
║                    ⚠  法律与合规声明  ⚠                             ║
╠══════════════════════════════════════════════════════════════════════╣
║  本工具仅限已获得目标系统所有者书面授权的安全测试使用。              ║
║  拦截和分析移动端流量应仅在您拥有或已获授权的设备上进行。            ║
║                                                                      ║
║  使用前请确认:                                                       ║
║  □ 我已获得拦截目标App流量的书面授权                                 ║
║  □ 我了解在未经授权情况下拦截通信的法律风险                         ║
║  □ 我将在测试完成后清除所有代理配置和拦截数据                        ║
║  □ 承诺不将截获的凭据用于未授权访问                                  ║
╚══════════════════════════════════════════════════════════════════════╝
"""


def confirm_consent() -> bool:
    print(CONSENT_TEXT)
    try:
        answer = input("\n[*] 是否已获得授权？(yes/no): ").strip().lower()
        if answer in ("yes", "y", "是", "确认"):
            print("[+] 授权确认通过。\n")
            return True
        print("[-] 未确认授权，程序退出。")
        return False
    except (KeyboardInterrupt, EOFError):
        print("\n[-] 用户取消。")
        return False


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
import logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("api_intercept")


# ---------------------------------------------------------------------------
# 网络信息
# ---------------------------------------------------------------------------
def get_local_ip() -> str:
    """获取本机局域网IP"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def detect_platform() -> Dict[str, str]:
    """检测运行平台"""
    system = platform.system().lower()
    info = {
        "os": system,
        "has_adb": False,
        "has_burp": False,
        "has_mitmproxy": False,
    }

    # 检测 adb
    try:
        r = subprocess.run(["adb", "version"], capture_output=True, text=True, timeout=5)
        info["has_adb"] = r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 检测 mitmproxy
    try:
        r = subprocess.run(["mitmproxy", "--version"], capture_output=True, text=True, timeout=5)
        info["has_mitmproxy"] = r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # 检测 Java (Burp)
    try:
        r = subprocess.run(["java", "-version"], capture_output=True, text=True, timeout=5)
        info["has_burp"] = r.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    return info


# ---------------------------------------------------------------------------
# 配置生成
# ---------------------------------------------------------------------------
def generate_burp_config(ip: str, port: int = 8080) -> str:
    """生成 Burp Suite 配置说明"""
    config = f"""
╔══════════════════════════════════════════════════════════════╗
║              Burp Suite 抓包配置                              ║
╚══════════════════════════════════════════════════════════════╝

【步骤1】Burp Suite 监听器设置
  1. 打开 Burp Suite -> Proxy -> Proxy Settings
  2. 添加监听器: {ip}:{port}
  3. 勾选 "All interfaces" (或指定IP)
  4. 勾选 "Support invisible proxying" (如需HTTP/2)

【步骤2】导出 Burp CA 证书
  - 访问 http://burpsuite 或 http://{ip}:{port}
  - 点击 "CA Certificate" 下载 cacert.der

【步骤3】Android 模拟器设置代理 + 安装证书
  # 设置代理
  adb shell settings put global http_proxy {ip}:{port}

  # 推送并安装证书
  adb push cacert.der /sdcard/
  adb shell su -c "cat /sdcard/cacert.der > /data/local/tmp/cert-der.crt"
  adb shell su -c "mount -o rw,remount /system"
  adb shell su -c "cp /data/local/tmp/cert-der.crt /system/etc/security/cacerts/9a5ba575.0"
  adb shell su -c "chmod 644 /system/etc/security/cacerts/9a5ba575.0"
  adb shell su -c "reboot"

  # 或使用 Magisk 模块方式（推荐）:
  # 安装 MoveCertificates Magisk 模块

【步骤4】iOS 设置代理
  - 设置 -> 无线局域网 -> 点击当前WiFi -> 配置代理 -> 手动
  - 服务器: {ip}
  - 端口: {port}

【步骤5】iOS 安装 Burp CA 证书
  1. Safari 访问 http://burpsuite -> 下载证书
  2. 设置 -> 通用 -> VPN与设备管理 -> 安装配置文件
  3. 设置 -> 通用 -> 关于本机 -> 证书信任设置 -> 开启信任

【步骤6】验证代理
  - 移动设备访问 http://{ip}:{port}
  - Burp Suite Proxy -> HTTP history 应显示流量
"""
    return config


def generate_mitmproxy_config(ip: str, port: int = 8080) -> str:
    """生成 mitmproxy 配置说明"""
    config = f"""
╔══════════════════════════════════════════════════════════════╗
║              mitmproxy 抓包配置                              ║
╚══════════════════════════════════════════════════════════════╝

【步骤1】启动 mitmproxy
  # 带Web界面
  mitmweb --listen-host {ip} --listen-port {port}

  # 或命令行模式
  mitmproxy --listen-host {ip} --listen-port {port}

  # 或后台模式（保存到文件）
  mitmdump --listen-host {ip} --listen-port {port} -w intercept.flow

【步骤2】安装 mitmproxy CA 证书
  移动设备浏览器访问 mitm.it
  选择对应平台下载并安装证书

  # 或手动推送:
  # Android
  cp ~/.mitmproxy/mitmproxy-ca-cert.pem mitmproxy-ca-cert.crt
  adb push mitmproxy-ca-cert.crt /sdcard/

  # iOS (通过邮件或Safari安装)
  # 发送证书到设备邮件，点击安装

【步骤3】Android 设置代理
  adb shell settings put global http_proxy {ip}:{port}

【步骤4】iOS 设置代理
  设置 -> 无线局域网 -> WiFi -> 配置代理 -> 手动
  服务器: {ip}  端口: {port}

【步骤5】处理 Android 7+ SSL Pinning
  # 方法1: 使用 Xposed + JustTrustMe
  # 方法2: 使用 Frida
  frida -U -l ssl_bypass.js -f com.target.app

  # 方法3: 使用 Objection
  objection -g com.target.app explore
  # 在 objection 中执行:
  > android sslpinning disable

  # 方法4: 将 App 设置为 debug 模式
  adb shell pm grant com.target.app android.permission.READ_LOGS
  # 修改 AndroidManifest.xml 添加 android:debuggable="true"
  # 使用 apktool 重打包
"""
    return config


def generate_android_config(ip: str, port: int = 8080) -> str:
    """生成 Android 专用配置命令"""
    config = f"""
╔══════════════════════════════════════════════════════════════╗
║              Android 代理配置命令                             ║
╚══════════════════════════════════════════════════════════════╝

【基本代理设置】

  # ---------- 设置 HTTP 代理 ----------
  adb shell settings put global http_proxy {ip}:{port}

  # ---------- 清除代理（测试结束后） ----------
  adb shell settings put global http_proxy :0
  adb shell settings delete global http_proxy
  adb shell settings delete global global_http_proxy_host
  adb shell settings delete global global_http_proxy_port

  # ---------- 查看当前代理 ----------
  adb shell settings get global http_proxy

  # ---------- 获取当前连接设备 ----------
  adb devices -l

【模拟器专用】

  # ---------- Android Emulator 代理 ----------
  # 启动模拟器并设置代理
  emulator -avd <AVD_NAME> -http-proxy http://{ip}:{port}

  # ---------- Genymotion 代理 ----------
  # 设置 -> Proxy -> 手动配置

【WiFi 代理设置 via ADB】

  # 通过 ADB 修改 WiFi 代理 (Android 10+)
  adb shell cmd wifi set-connection-param <SSID> proxy.host {ip}
  adb shell cmd wifi set-connection-param <SSID> proxy.port {port}

  # 或使用 Network Settings 命令
  adb shell cmd net-security set-proxy {ip} {port}

【ADB 网络调试】

  # ---------- 无线 ADB (无需USB) ----------
  adb tcpip 5555
  adb connect <DEVICE_IP>:5555

  # 断开
  adb disconnect <DEVICE_IP>:5555

【证书安装 (Android 7+)】

  # ---------- 方法1: 系统证书（需要root） ----------
  # 将证书转为 Android 系统证书格式
  openssl x509 -inform DER -in burp_cacert.der -out burp_cacert.pem
  HASH=$(openssl x509 -inform PEM -subject_hash_old -in burp_cacert.pem | head -1)
  cp burp_cacert.pem $HASH.0

  adb root
  adb remount
  adb push $HASH.0 /system/etc/security/cacerts/
  adb shell chmod 644 /system/etc/security/cacerts/$HASH.0
  adb shell reboot

  # ---------- 方法2: 用户证书（Android 14+ 限制） ----------
  # Android 14+ 用户证书不再被信任，只能使用系统证书方法

  # ---------- 方法3: 使用 Magisk 模块 ----------
  # 安装 MoveCertificates 模块
  # 模块会自动将用户证书移至系统目录

【SSL Pinning 绕过】

  # ---------- Frida SSL Pinning 绕过 ----------
  # 安装 frida
  pip install frida-tools

  # 注入 ssl pinning 绕过脚本
  frida -U --no-pause -l frida-ssl-bypass.js -f com.target.app

  # ---------- Objection ----------
  # 安装
  pip install objection

  # 使用
  objection -g com.target.app explore
  > android sslpinning disable
  > android root disable  # 如果检测root

  # ---------- 通用 frida 脚本 ----------
  # ssl_bypass.js 内容:
  '''
  // Universal SSL Pinning Bypass for Android
  Java.perform(function() {{
      var ArrayList = Java.use('java.util.ArrayList');
      var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
      TrustManagerImpl.verifyChain.implementation = function(unused, certs, authType, host) {{
          return ArrayList.$new();
      }};

      // OkHttp3
      try {{
          var CertificatePinner = Java.use('okhttp3.CertificatePinner');
          CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCertificates) {{
              console.log('[Bypass] Skipping certificate pin for: ' + hostname);
              return;
          }};
      }} catch(e) {{ console.log('No OkHttp3 pinning found'); }}

      // TrustManager
      try {{
          var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
          X509TrustManager.checkServerTrusted.implementation = function(chain, authType) {{
              console.log('[Bypass] Trusting all certificates');
              return;
          }};
      }} catch(e) {{}}
  }});
  '''

【APK 重打包（修改证书校验）】

  # 1. 解包
  apktool d target.apk -o target_extracted

  # 2. 修改 AndroidManifest.xml 添加 debuggable
  # android:debuggable="true"

  # 3. 修改网络配置 (res/xml/network_security_config.xml)
  # 添加: <base-config cleartextTrafficPermitted="true">
  #   <trust-anchors>
  #     <certificates src="system" />
  #     <certificates src="user" />
  #   </trust-anchors>
  # </base-config>

  # 4. 回包并签名
  apktool b target_extracted -o target_patched.apk
  keytool -genkey -v -keystore debug.keystore -alias debug -keyalg RSA -keysize 2048 -validity 10000
  jarsigner -keystore debug.keystore target_patched.apk debug
  adb install target_patched.apk
"""
    return config


def generate_ios_config(ip: str, port: int = 8080) -> str:
    """生成 iOS 代理配置说明"""
    config = f"""
╔══════════════════════════════════════════════════════════════╗
║              iOS 代理配置指南                                 ║
╚══════════════════════════════════════════════════════════════╝

【条件】
  建议使用越狱设备或 iOS 模拟器。
  非越狱 iOS 14.5+ 的 SSL 抓包限制较多。

【设置代理】

  # ---------- WiFi 代理（手动） ----------
  设置 -> 无线局域网 -> 点击已连接的WiFi
  配置代理 -> 手动
  服务器: {ip}
  端口: {port}

  # ---------- 使用 proxy 配置文件 ----------
  # 可以通过 Apple Configurator 或 MDM 配置

【安装 CA 证书】

  1. Safari 访问 http://{ip}:{port} 或 http://mitm.it
  2. 下载并安装描述文件
  3. 设置 -> 通用 -> VPN与设备管理 -> 安装
  4. 设置 -> 通用 -> 关于本机 -> 证书信任设置 -> 开启信任

【SSL Pinning 绕过 (越狱)】

  # ---------- 使用 Frida ----------
  frida -U -l ios_ssl_bypass.js -f com.target.app

  # ---------- 使用 Objection ----------
  objection -g com.target.app explore
  > ios sslpinning disable

  # ---------- 使用 SSL Kill Switch 2 ----------
  # Cydia 安装 SSL Kill Switch 2
  # 设置 -> 启用

【模拟器设置】

  # iOS 模拟器使用 Mac 代理
  # 设置代理:
  networksetup -setwebproxy "iPhone OS" {ip} {port}
  networksetup -setsecurewebproxy "iPhone OS" {ip} {port}

【常用命令】

  # 查看代理状态
  adb (不适用 iOS, 使用 ideviceproxy)

  # 安装 ipa
  ios-deploy -b app.ipa
"""
    return config


# ---------------------------------------------------------------------------
# 一键配置脚本生成
# ---------------------------------------------------------------------------
def generate_setup_script(ip: str, port: int, output_path: str) -> str:
    """生成一键配置Shell脚本"""
    script = f"""#!/bin/bash
# =========================================================================
# 移动端API抓包 - 一键配置脚本
# 生成时间: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
# 代理地址: {ip}:{port}
# 注意: 本脚本仅用于授权测试
# =========================================================================

echo "=========================================="
echo " 移动端API抓包 - 一键配置"
echo "=========================================="
echo ""

# 检测 adb
if ! command -v adb &>/dev/null; then
    echo "[!] adb 未找到，请安装 Android SDK platform-tools"
    echo "    sudo apt install adb  # Linux"
    echo "    brew install android-platform-tools  # macOS"
    exit 1
fi

echo "[*] 检查设备连接..."
DEVICES=$(adb devices | grep -w device | wc -l)
if [ "$DEVICES" -eq 0 ]; then
    echo "[!] 未检测到 Android 设备/模拟器"
    echo "    请确认设备已通过USB连接并开启USB调试"
    exit 1
fi
echo "[+] 已检测到 $DEVICES 台设备"

echo ""
echo "[*] 设置代理 {ip}:{port}..."
adb shell settings put global http_proxy {ip}:{port}

RESULT=$(adb shell settings get global http_proxy)
echo "[+] 代理已设置: $RESULT"

echo ""
echo "[*] 验证网络连通性..."
adb shell ping -c 1 -W 2 {ip} >/dev/null 2>&1
if [ $? -eq 0 ]; then
    echo "[+] 设备可连通测试机"
else
    echo "[!] 设备无法连通测试机，请检查:"
    echo "    - 设备与测试机是否在同一网络"
    echo "    - 防火墙是否放行端口 {port}"
fi

echo ""
echo "=========================================="
echo " 配置完成！"
echo " 代理: {ip}:{port}"
echo " 清除代理请运行: adb shell settings put global http_proxy :0"
echo "=========================================="
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(script)
    os.chmod(output_path, 0o755)
    logger.info(f"一键配置脚本已生成: {output_path}")
    return output_path


# ---------------------------------------------------------------------------
# 流量分析工具
# ---------------------------------------------------------------------------
def parse_mitmproxy_flows(flow_path: str) -> List[Dict]:
    """
    解析 mitmproxy 保存的流量文件 (.flow)
    需要 mitmproxy 库: pip install mitmproxy
    """
    try:
        from mitmproxy import flow  # type: ignore
        from mitmproxy import http  # type: ignore
    except ImportError:
        logger.warning("mitmproxy 库未安装，跳过流量解析")
        logger.warning("安装: pip install mitmproxy")
        return []

    if not os.path.isfile(flow_path):
        logger.error(f"流量文件不存在: {flow_path}")
        return []

    requests_data = []
    try:
        flows = flow.read_flows_from_path(flow_path)
        for f in flows:
            if isinstance(f.request, http.Request):
                req_info = {
                    "method": f.request.method,
                    "url": f.request.pretty_url,
                    "host": f.request.host,
                    "path": f.request.path,
                    "status_code": f.response.status_code if f.response else None,
                    "content_type": f.response.headers.get("Content-Type", "") if f.response else "",
                    "response_length": len(f.response.content) if f.response else 0,
                    "timestamp": f.request.timestamp_start,
                }
                requests_data.append(req_info)
    except Exception as e:
        logger.error(f"解析流量文件失败: {e}")

    logger.info(f"从流量文件中解析出 {len(requests_data)} 个请求")
    return requests_data


def parse_har_file(har_path: str) -> List[Dict]:
    """
    解析 HAR 格式的抓包文件（Burp Suite / Chrome DevTools 导出）
    """
    if not os.path.isfile(har_path):
        logger.error(f"HAR文件不存在: {har_path}")
        return []

    try:
        with open(har_path, "r", encoding="utf-8") as f:
            har_data = json.load(f)
    except (json.JSONDecodeError, Exception) as e:
        logger.error(f"HAR 解析失败: {e}")
        return []

    requests_data = []
    try:
        entries = har_data.get("log", {}).get("entries", [])
        for entry in entries:
            req = entry.get("request", {})
            resp = entry.get("response", {})
            req_info = {
                "method": req.get("method", ""),
                "url": req.get("url", ""),
                "host": req.get("url", "").split("/")[2] if "//" in req.get("url", "") else "",
                "path": "/" + "/".join(req.get("url", "").split("/")[3:]) if req.get("url", "").count("/") >= 3 else "",
                "status_code": resp.get("status"),
                "content_type": next(
                    (h.get("value") for h in resp.get("headers", [])
                     if h.get("name", "").lower() == "content-type"),
                    "",
                ),
                "response_length": resp.get("content", {}).get("size", 0),
                "timestamp": entry.get("startedDateTime", ""),
            }
            requests_data.append(req_info)
    except Exception as e:
        logger.error(f"HAR解析异常: {e}")

    logger.info(f"从 HAR 中解析出 {len(requests_data)} 个请求")
    return requests_data


def extract_api_endpoints(reqs: List[Dict]) -> Dict:
    """
    从请求列表中提取并分析API端点

    Returns:
        包含域名统计、端点路径、参数信息的字典
    """
    endpoints = {}

    for r in reqs:
        host = r.get("host", "")
        path = r.get("path", "")
        method = r.get("method", "")
        url = r.get("url", "")
        status = r.get("status_code", 0)

        if not host:
            continue

        if host not in endpoints:
            endpoints[host] = {
                "host": host,
                "total_requests": 0,
                "methods": set(),
                "paths": {},
                "status_codes": {},
                "urls": [],
            }

        ep = endpoints[host]
        ep["total_requests"] += 1
        if method:
            ep["methods"].add(method)

        # 规范化路径（去掉参数）
        clean_path = path.split("?")[0] if path else path

        if clean_path not in ep["paths"]:
            ep["paths"][clean_path] = {"count": 0, "methods": set()}
        ep["paths"][clean_path]["count"] += 1
        if method:
            ep["paths"][clean_path]["methods"].add(method)

        if status:
            s = str(status)
            ep["status_codes"][s] = ep["status_codes"].get(s, 0) + 1

        if len(ep["urls"]) < 100:
            ep["urls"].append(url)

    # 转换为可序列化的格式
    result = {}
    for host, data in endpoints.items():
        result[host] = {
            "host": host,
            "total_requests": data["total_requests"],
            "methods": sorted(list(data["methods"])),
            "paths": [
                {
                    "path": p,
                    "count": info["count"],
                    "methods": sorted(list(info["methods"])),
                }
                for p, info in sorted(data["paths"].items(), key=lambda x: -x[1]["count"])
            ],
            "status_codes": data["status_codes"],
            "sample_urls": data["urls"][:20],
        }

    return result


def analyze_traffic_file(file_path: str, output_path: Optional[str] = None) -> Optional[str]:
    """
    分析抓包文件并生成API端点报告

    Args:
        file_path: 流量文件路径 (.har 或 .flow)
        output_path: 报告输出路径

    Returns:
        报告文件路径
    """
    ext = os.path.splitext(file_path)[1].lower()
    logger.info(f"正在分析流量文件: {file_path}")

    reqs = []
    if ext == ".har":
        reqs = parse_har_file(file_path)
    elif ext == ".flow":
        reqs = parse_mitmproxy_flows(file_path)
    else:
        logger.error(f"不支持的文件格式: {ext} (支持: .har, .flow)")
        return None

    if not reqs:
        logger.warning("未解析到任何请求")
        return None

    endpoints = extract_api_endpoints(reqs)

    # 统计
    total = len(reqs)
    unique_hosts = len(endpoints)
    unique_paths = sum(len(ep["paths"]) for ep in endpoints.values())

    if output_path is None:
        base = os.path.splitext(file_path)[0]
        output_path = f"{base}_api_endpoints.json"

    report = {
        "分析时间": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "源文件": file_path,
        "统计": {
            "总请求数": total,
            "唯一域名": unique_hosts,
            "唯一路径": unique_paths,
        },
        "端点按域名": endpoints,
    }

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    logger.info(f"API端点报告已生成: {output_path}")

    # 控制台摘要
    print(f"\n{'='*50}")
    print(f"流量分析摘要 - {os.path.basename(file_path)}")
    print(f"{'='*50}")
    print(f"  总请求数: {total}")
    print(f"  唯一域名: {unique_hosts}")
    print(f"  唯一路径: {unique_paths}")
    print(f"  报告文件: {output_path}")

    print(f"\n  域名列表:")
    for host, data in sorted(endpoints.items(), key=lambda x: -x[1]["total_requests"])[:10]:
        print(f"    {host:40s} {data['total_requests']:4d} 请求  {data['methods']}")

    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="移动API抓取配置助手 - API Interception Setup (仅限授权测试)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 生成所有配置
  %(prog)s gen-config

  # 生成配置并指定IP和端口
  %(prog)s gen-config --ip 192.168.1.100 --port 8888

  # 只生成特定配置
  %(prog)s gen-config --only android

  # 生成一键配置脚本
  %(prog)s gen-script

  # 分析 HAR 流量文件
  %(prog)s analyze traffic.har

  # 分析 mitmproxy 流量文件
  %(prog)s analyze traffic.flow

  # 检测当前环境
  %(prog)s detect
        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # gen-config
    gen_parser = subparsers.add_parser("gen-config", help="生成代理配置指南")
    gen_parser.add_argument("--ip", default=get_local_ip(), help=f"本机IP (默认: {get_local_ip()})")
    gen_parser.add_argument("--port", type=int, default=8080, help="代理端口 (默认: 8080)")
    gen_parser.add_argument("--output", "-o", default="./", help="输出目录")
    gen_parser.add_argument(
        "--only", choices=["all", "burp", "mitm", "android", "ios"],
        default="all", help="仅生成特定配置"
    )

    # gen-script
    script_parser = subparsers.add_parser("gen-script", help="生成一键配置脚本")
    script_parser.add_argument("--ip", default=get_local_ip(), help="本机IP")
    script_parser.add_argument("--port", type=int, default=8080, help="代理端口")
    script_parser.add_argument("--output", "-o", default="./setup_proxy.sh", help="输出路径")

    # analyze
    analyze_parser = subparsers.add_parser("analyze", help="分析抓包文件")
    analyze_parser.add_argument("file", help="流量文件路径 (.har 或 .flow)")
    analyze_parser.add_argument("--output", "-o", help="输出报告路径")

    # detect
    subparsers.add_parser("detect", help="检测当前环境工具链")

    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    # 授权确认
    if not confirm_consent():
        sys.exit(1)

    # gen-config
    if args.command == "gen-config":
        ip = args.ip
        port = args.port
        out_dir = args.output
        os.makedirs(out_dir, exist_ok=True)

        configs = []
        if args.only in ("all", "burp"):
            configs.append(("burp_config.txt", generate_burp_config(ip, port)))
        if args.only in ("all", "mitm"):
            configs.append(("mitmproxy_config.txt", generate_mitmproxy_config(ip, port)))
        if args.only in ("all", "android"):
            configs.append(("android_config.txt", generate_android_config(ip, port)))
        if args.only in ("all", "ios"):
            configs.append(("ios_config.txt", generate_ios_config(ip, port)))

        for fname, content in configs:
            fpath = os.path.join(out_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(content)
            print(f"[+] 配置已生成: {fpath}")

        print(f"\n[+] 所有配置已写入: {os.path.abspath(out_dir)}")

    # gen-script
    elif args.command == "gen-script":
        generate_setup_script(args.ip, args.port, args.output)

    # analyze
    elif args.command == "analyze":
        if not os.path.isfile(args.file):
            print(f"[-] 文件不存在: {args.file}")
            sys.exit(1)
        analyze_traffic_file(args.file, args.output)

    # detect
    elif args.command == "detect":
        info = detect_platform()
        print(f"\n当前环境检测:")
        print(f"  操作系统:     {info['os']}")
        print(f"  ADB:         {'[OK]' if info['has_adb'] else '[--]'}  (adb)")
        print(f"  mitmproxy:   {'[OK]' if info['has_mitmproxy'] else '[--]'}  (mitmproxy)")
        print(f"  Java:        {'[OK]' if info['has_burp'] else '[--]'}  (用于 Burp Suite)")
        print(f"\n本机IP: {get_local_ip()}")


if __name__ == "__main__":
    main()
