#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
验证码工具集 - Captcha Utilities
=====================================
用途: 下载、识别、绕过验证码的辅助工具集（仅限已授权测试）
目标: 基于 blacklake.cn 注册流程的实际测试经验编写

注意:
  本工具仅用于已获得明确书面授权的安全测试。
  未经授权使用本工具进行验证码绕过可能违反《中华人民共和国网络安全法》。
  使用者需自行承担所有法律责任。

合规要求:
  1. 必须获得目标系统所有者的书面授权
  2. 测试过程中不得影响正常用户服务
  3. 发现漏洞后需立即停止并负责任地报告
  4. 不得将获取的数据用于任何非授权目的
"""

import argparse
import json
import os
import sys
import time
import logging
from typing import Optional, List

# ---------------------------------------------------------------------------
# 第三方导入（带优雅降级）
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[!] 建议安装 requests 库: pip install requests", file=sys.stderr)

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("[!] 建议安装 Pillow 库: pip install Pillow", file=sys.stderr)

try:
    import pytesseract
    TESSERACT_AVAILABLE = True
except ImportError:
    TESSERACT_AVAILABLE = False

# 尝试导入 tkinter 用于手动输入弹窗
try:
    import tkinter as tk
    from tkinter import simpledialog
    TKINTER_AVAILABLE = True
except ImportError:
    TKINTER_AVAILABLE = False

# ---------------------------------------------------------------------------
# 日志配置
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("captcha_utils")

# ---------------------------------------------------------------------------
# 授权确认
# ---------------------------------------------------------------------------
AUTHORIZATION_MESSAGE = """
╔═══════════════════════════════════════════════════════════════╗
║               ⚠  法律与合规声明  ⚠                           ║
╠═══════════════════════════════════════════════════════════════╣
║  本工具仅供已获得目标系统所有者明确书面授权的情况使用。        ║
║  未经授权使用可能违反《中华人民共和国网络安全法》及相关法律。   ║
║  使用者须自行承担所有法律责任。                               ║
║                                                               ║
║  使用前请确认:                                                 ║
║  □ 我已获得目标系统的书面授权                                  ║
║  □ 我了解未经授权测试的法律后果                                ║
║  □ 我将在发现漏洞后负责任地报告                                ║
╚═══════════════════════════════════════════════════════════════╝
"""


def confirm_authorization() -> bool:
    """显示授权声明并等待用户确认"""
    print(AUTHORIZATION_MESSAGE)
    try:
        resp = input("\n是否已获得授权？(yes/no): ").strip().lower()
        if resp in ("yes", "y", "是", "确认"):
            print("[+] 授权确认通过，继续执行...\n")
            return True
        else:
            print("[-] 未获得授权确认，程序退出。")
            return False
    except (KeyboardInterrupt, EOFError):
        print("\n[-] 用户取消操作，程序退出。")
        return False


# ---------------------------------------------------------------------------
# 速率限制器
# ---------------------------------------------------------------------------
class RateLimiter:
    """简单的请求速率限制器"""

    def __init__(self, min_interval: float = 1.0):
        """
        Args:
            min_interval: 最小请求间隔（秒）
        """
        self.min_interval = min_interval
        self._last_call: float = 0.0

    def wait(self):
        """等待直到允许发送下一个请求"""
        now = time.time()
        elapsed = now - self._last_call
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            logger.debug(f"速率限制: 等待 {sleep_time:.2f}s")
            time.sleep(sleep_time)
        self._last_call = time.time()

    def __enter__(self):
        self.wait()
        return self

    def __exit__(self, *args):
        pass


# ---------------------------------------------------------------------------
# 会话管理（带重试）
# ---------------------------------------------------------------------------
def create_session(retries: int = 3, backoff_factor: float = 0.5) -> "requests.Session":
    """创建带重试机制的 requests Session"""
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("需要安装 requests 库: pip install requests")

    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    })
    retry_strategy = Retry(
        total=retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"],
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


# ---------------------------------------------------------------------------
# 验证码下载
# ---------------------------------------------------------------------------
def download_captcha(
    url: str,
    output_path: str,
    session: Optional["requests.Session"] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> str:
    """
    从指定URL下载验证码图片

    Args:
        url: 验证码图片URL
        output_path: 保存路径
        session: 可选的 requests Session
        rate_limiter: 可选的速率限制器

    Returns:
        保存文件的绝对路径
    """
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("需要安装 requests 库: pip install requests")

    if rate_limiter:
        rate_limiter.wait()

    s = session or create_session()

    logger.info(f"正在下载验证码: {url}")
    try:
        resp = s.get(url, timeout=15, stream=True)
        resp.raise_for_status()

        os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

        with open(output_path, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if chunk:
                    f.write(chunk)

        abs_path = os.path.abspath(output_path)
        file_size = os.path.getsize(abs_path)
        logger.info(f"验证码已保存: {abs_path} ({file_size} bytes)")
        return abs_path

    except requests.exceptions.Timeout:
        logger.error("下载超时")
        raise
    except requests.exceptions.RequestException as e:
        logger.error(f"下载失败: {e}")
        raise


# ---------------------------------------------------------------------------
# OCR 识别
# ---------------------------------------------------------------------------
def ocr_captcha(image_path: str, config: Optional[str] = None) -> Optional[str]:
    """
    使用 pytesseract 识别验证码

    Args:
        image_path: 图片文件路径
        config: tesseract 额外配置参数

    Returns:
        识别出的文本，失败返回 None
    """
    if not TESSERACT_AVAILABLE:
        logger.warning("pytesseract 未安装，无法使用OCR模式")
        logger.warning("安装方法: pip install pytesseract && sudo apt install tesseract-ocr")
        return None

    if not PIL_AVAILABLE:
        logger.warning("Pillow 未安装，无法处理图片")
        return None

    try:
        if not os.path.exists(image_path):
            logger.error(f"图片文件不存在: {image_path}")
            return None

        img = Image.open(image_path)

        # 转为灰度图，提高识别率
        img = img.convert("L")

        # 简单的二值化处理
        threshold = 128
        img = img.point(lambda p: 255 if p > threshold else 0)

        # tesseract 配置: 仅识别数字和字母，PSM 8 = 单字符模式
        custom_config = config or (
            "--psm 8 --oem 3 "
            "-c tessedit_char_whitelist="
            "0123456789"
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            "abcdefghijklmnopqrstuvwxyz"
        )

        result = pytesseract.image_to_string(img, config=custom_config).strip()

        if result:
            logger.info(f"OCR 识别结果: '{result}'")
            return result
        else:
            logger.warning("OCR 未能识别出有效字符")
            return None

    except Exception as e:
        logger.error(f"OCR 识别失败: {e}")
        return None


# ---------------------------------------------------------------------------
# 手动输入模式
# ---------------------------------------------------------------------------
def _gui_captcha_input(image_path: str) -> Optional[str]:
    """弹出图形化输入框获取验证码"""
    try:
        root = tk.Tk()
        root.withdraw()
        result = simpledialog.askstring(
            "验证码输入",
            f"请查看验证码图片:\n{os.path.abspath(image_path)}\n\n输入验证码:"
        )
        root.destroy()
        if result:
            logger.info(f"用户输入验证码: '{result}'")
            return result.strip()
        return None
    except Exception:
        return None


def _cli_captcha_input() -> Optional[str]:
    """命令行输入验证码"""
    try:
        result = input("请输入验证码 (直接回车取消): ").strip()
        if result:
            logger.info(f"用户输入验证码: '{result}'")
            return result
        return None
    except (KeyboardInterrupt, EOFError):
        print()
        return None


def _preview_image(image_path: str) -> None:
    """如果可用，用 PIL 显示图片信息"""
    if PIL_AVAILABLE:
        try:
            img = Image.open(image_path)
            logger.info(f"图片尺寸: {img.size}, 模式: {img.mode}")
        except Exception as e:
            logger.warning(f"无法打开图片预览: {e}")


def manual_captcha_input(image_path: str) -> Optional[str]:
    """
    手动模式: 下载验证码并提示用户输入

    Args:
        image_path: 验证码图片路径

    Returns:
        用户输入的验证码，取消返回 None
    """
    if not os.path.exists(image_path):
        logger.error(f"图片不存在: {image_path}")
        return None

    logger.info(f"验证码图片位置: {os.path.abspath(image_path)}")
    _preview_image(image_path)

    # 尝试弹出 GUI 输入框
    if TKINTER_AVAILABLE:
        result = _gui_captcha_input(image_path)
        if result is not None:
            return result

    # 退化为命令行输入
    print(f"\n[!] 请查看验证码文件: {os.path.abspath(image_path)}")
    return _cli_captcha_input()


# ---------------------------------------------------------------------------
# 验证码绕过测试
# ---------------------------------------------------------------------------
def get_bypass_payloads() -> List[dict]:
    """
    获取常见的验证码绕过测试 payloads

    基于真实测试经验整理，包括:
    - whitelake.cn 注册流程中发现的验证码校验缺失
    - OWASP 推荐的验证码绕过测试用例

    Returns:
        包含测试payload的字典列表
    """
    return [
        # --- 空值测试 ---
        {"name": "空字符串", "field_value": "", "description": "提交空验证码"},
        {"name": "null字符串", "field_value": "null", "description": "提交字面量 'null'"},
        {"name": "None字符串", "field_value": "None", "description": "提交字面量 'None'"},
        {"name": "空格", "field_value": " ", "description": "提交单个空格"},
        {"name": "多个空格", "field_value": "   ", "description": "提交多个空格"},

        # --- 常见验证码 ---
        {"name": "全零", "field_value": "0000", "description": "常见默认值"},
        {"name": "全一", "field_value": "1111", "description": "常见默认值"},
        {"name": "顺序数字", "field_value": "1234", "description": "常见默认值"},
        {"name": "重复数字", "field_value": "8888", "description": "常见默认值"},
        {"name": "电话号码尾号", "field_value": "000000", "description": "6位零"},
        {"name": "通用码", "field_value": "111111", "description": "6位一"},
        {"name": "测试码", "field_value": "test", "description": "常见测试值"},
        {"name": "通配符码", "field_value": "admin", "description": "常见管理值"},

        # --- 逻辑绕过 ---
        {"name": "移除captcha参数", "field_value": "__REMOVED__", "description": "完全删除验证码参数"},
        {"name": "替换captcha字段名", "field_value": "__RENAME__", "description": "修改参数名称"},
        {"name": "重复使用旧token", "field_value": "__REUSE__", "description": "使用之前请求中的验证码值"},
    ]


def _get_baseline(
    s: "requests.Session",
    url: str,
    form_data_template: dict,
    captcha_field: str,
    rate_limiter: RateLimiter,
) -> tuple:
    """获取正常请求的基线响应状态码和长度"""
    logger.info("正在获取基线响应（正常请求）...")
    rate_limiter.wait()
    baseline_data = form_data_template.copy()
    baseline_data[captcha_field] = "DUMMY_BASELINE"
    try:
        baseline_resp = s.post(url, data=baseline_data, timeout=15)
        baseline_length = len(baseline_resp.text)
        baseline_status = baseline_resp.status_code
        logger.info(f"基线响应: 状态码={baseline_status}, 响应体长度={baseline_length}")
        return baseline_status, baseline_length
    except requests.exceptions.RequestException as e:
        logger.error(f"无法获取基线响应: {e}")
        return 0, -1


def _build_payload_data(
    form_data_template: dict,
    captcha_field: str,
    payload: dict,
    reuse_captcha_value: Optional[str] = None,
) -> Optional[dict]:
    """根据 payload 构建测试用表单数据，返回 None 表示跳过"""
    test_data = form_data_template.copy()
    field_value = payload["field_value"]

    if field_value == "__REMOVED__":
        return test_data  # 不加 captcha_field
    elif field_value == "__RENAME__":
        test_data[captcha_field + "_bypass"] = "ignored"
        test_data[captcha_field] = ""
    elif field_value == "__REUSE__":
        if reuse_captcha_value:
            test_data[captcha_field] = reuse_captcha_value
        else:
            logger.warning("未提供旧的验证码值，跳过重放测试")
            return None
    else:
        test_data[captcha_field] = field_value
    return test_data


def _check_bypass_response(
    resp: "requests.Response",
    baseline_status: int,
    baseline_length: int,
    payload: dict,
) -> dict:
    """检查单个响应是否可能被绕过，返回结果字典"""
    resp_len = len(resp.text)
    status_diff = resp.status_code != baseline_status
    length_diff_ratio = abs(resp_len - baseline_length) / max(baseline_length, 1)

    maybe_bypass = False
    if status_diff and resp.status_code in (200, 201, 302, 301):
        maybe_bypass = True
    if length_diff_ratio > 0.3:
        maybe_bypass = True
    success_keywords = ["成功", "success", "验证通过", "注册成功", "redirect"]
    if any(kw in resp.text.lower() for kw in success_keywords):
        maybe_bypass = True

    return {
        "name": payload["name"],
        "field_value": payload["field_value"],
        "status_code": resp.status_code,
        "response_length": resp_len,
        "description": payload["description"],
        "maybe_vulnerable": maybe_bypass,
    }


def _log_bypass_summary(results: List[dict]):
    """打印绕过测试汇总日志"""
    vulnerable_found = [r for r in results if r.get("maybe_vulnerable")]
    if vulnerable_found:
        logger.warning(
            f"\n[!] 发现 {len(vulnerable_found)} 个可能的绕过方式:"
        )
        for v in vulnerable_found:
            logger.warning(f"    - {v['name']} (状态码: {v['status_code']})")
    else:
        logger.info("\n[-] 未发现明显的验证码绕过（仅供参考，不保证安全性）")


def _test_single_payload(
    s: "requests.Session",
    url: str,
    payload: dict,
    test_data: dict,
    baseline_status: int,
    baseline_length: int,
) -> dict:
    """测试单个payload，返回结果字典"""
    try:
        resp = s.post(url, data=test_data, timeout=15)
        result = _check_bypass_response(resp, baseline_status, baseline_length, payload)

        status_icon = "[!]" if result["maybe_vulnerable"] else "[.]"
        logger.info(
            f"{status_icon} payload='{payload['name']}' "
            f"-> status={resp.status_code}, len={result['response_length']}"
            f"{' ** 可能绕过! **' if result['maybe_vulnerable'] else ''}"
        )
        return result
    except requests.exceptions.RequestException as e:
        logger.error(f"payload='{payload['name']}' 请求失败: {e}")
        return {
            "name": payload["name"],
            "field_value": payload["field_value"],
            "status_code": 0,
            "response_length": 0,
            "description": payload["description"],
            "maybe_vulnerable": False,
            "error": str(e),
        }


def test_captcha_bypass(
    url: str,
    form_data_template: dict,
    captcha_field: str,
    session: Optional["requests.Session"] = None,
    rate_limiter: Optional[RateLimiter] = None,
    reuse_captcha_value: Optional[str] = None,
) -> List[dict]:
    """
    测试验证码绕过

    发送一系列绕过payload，观察服务端响应以判断是否存在验证码校验缺失。

    Args:
        url: 提交URL
        form_data_template: 表单数据模板（不含验证码字段）
        captcha_field: 验证码表单字段名
        session: 可选的 requests Session
        rate_limiter: 可选的速率限制器
        reuse_captcha_value: 可选的旧验证码值（用于重放测试）

    Returns:
        测试结果列表，每项包含 name/status_code/response_length/maybe_vulnerable
    """
    if not REQUESTS_AVAILABLE:
        raise RuntimeError("需要安装 requests 库: pip install requests")

    if rate_limiter is None:
        rate_limiter = RateLimiter(min_interval=2.0)

    s = session or create_session()
    payloads = get_bypass_payloads()
    results = []

    baseline_status, baseline_length = _get_baseline(
        s, url, form_data_template, captcha_field, rate_limiter
    )

    logger.info(f"开始验证码绕过测试（共 {len(payloads)} 个payload）...")

    for payload in payloads:
        rate_limiter.wait()

        test_data = _build_payload_data(
            form_data_template, captcha_field, payload, reuse_captcha_value
        )
        if test_data is None:
            continue

        result = _test_single_payload(
            s, url, payload, test_data, baseline_status, baseline_length
        )
        results.append(result)

    _log_bypass_summary(results)
    return results


# ---------------------------------------------------------------------------
# 一站式验证码处理
# ---------------------------------------------------------------------------
def handle_captcha(
    url: str,
    output_path: str,
    mode: str = "manual",
    ocr_config: Optional[str] = None,
    session: Optional["requests.Session"] = None,
    rate_limiter: Optional[RateLimiter] = None,
) -> Optional[str]:
    """
    一站式验证码处理: 下载 + 识别/输入

    Args:
        url: 验证码图片URL
        output_path: 保存路径
        mode: 处理模式 - 'manual'(手动), 'ocr'(自动识别), 'both'(先自动再手动)
        ocr_config: OCR 额外配置
        session: 可选的 requests Session
        rate_limiter: 可选的速率限制器

    Returns:
        验证码文本，失败返回 None
    """
    # 下载
    abs_path = download_captcha(url, output_path, session, rate_limiter)

    captcha_code = None

    if mode in ("ocr", "both"):
        captcha_code = ocr_captcha(abs_path, ocr_config)

    if mode == "both" and not captcha_code:
        logger.info("OCR识别失败，切换手动模式...")

    if mode == "manual" or (mode == "both" and not captcha_code):
        captcha_code = manual_captcha_input(abs_path)

    return captcha_code


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _show_payloads():
    """打印所有可用的绕过payload"""
    print("\n可用的验证码绕过payloads:")
    for i, p in enumerate(get_bypass_payloads(), 1):
        print(f"  {i:2d}. {p['name']:16s} -> {p['field_value']!r:20s} ({p['description']})")


def _handle_download(args):
    """处理 download 子命令"""
    download_captcha(args.url, args.output, rate_limiter=RateLimiter(args.rate_limit))
    print(f"[+] 验证码已下载到: {os.path.abspath(args.output)}")


def _handle_ocr(args):
    """处理 ocr 子命令"""
    result = ocr_captcha(args.image, args.config)
    if result:
        print(f"[+] OCR 识别结果: {result}")
    else:
        print("[-] OCR 识别失败")


def _handle_manual(args):
    """处理 manual 子命令"""
    result = manual_captcha_input(args.image)
    if result:
        print(f"[+] 用户输入验证码: {result}")
    else:
        print("[-] 用户取消输入")


def _handle_auto(args):
    """处理 auto 子命令"""
    result = handle_captcha(
        args.url, args.output, mode=args.mode,
        rate_limiter=RateLimiter(args.rate_limit),
    )
    if result:
        print(f"[+] 验证码: {result}")
    else:
        print("[-] 未能获取验证码")


def _handle_bypass(args):
    """处理 bypass 子命令"""
    try:
        form_data = json.loads(args.form)
    except json.JSONDecodeError as e:
        print(f"[-] 表单数据JSON解析失败: {e}")
        sys.exit(1)

    results = test_captcha_bypass(
        args.url, form_data, args.field,
        rate_limiter=RateLimiter(args.rate_limit),
        reuse_captcha_value=args.reuse,
    )

    vulnerable = [r for r in results if r.get("maybe_vulnerable")]
    if vulnerable:
        print(f"\n[!] 发现 {len(vulnerable)} 个可能的绕过方式:")
        print(f"{'名称':20s} {'状态码':8s} {'响应长度':12s}")
        print("-" * 45)
        for v in vulnerable:
            print(f"{v['name']:20s} {v['status_code']:<8d} {v['response_length']:<12d}")
    else:
        print("\n[-] 未发现明显的验证码绕过")
        print("    注意: 这不能保证验证码实现是安全的。")


def _build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description="验证码工具集 - Captcha Utilities (仅限授权测试)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 下载验证码
  %(prog)s download --url https://example.com/captcha.jpg --output /tmp/captcha.png

  # OCR识别
  %(prog)s ocr --image /tmp/captcha.png

  # 一站式处理（手动输入）
  %(prog)s auto --url https://example.com/captcha.jpg --mode manual

  # 一站式处理（先OCR，失败则手动）
  %(prog)s auto --url https://example.com/captcha.jpg --mode both

  skip
  %(prog)s bypass --url https://example.com/register --form '{"username":"test","password":"test123"}' --field captcha

        """,
    )

    subparsers = parser.add_subparsers(dest="command", help="子命令")

    # download
    dl_parser = subparsers.add_parser("download", help="下载验证码图片")
    dl_parser.add_argument("--url", required=True, help="验证码图片URL")
    dl_parser.add_argument("--output", required=True, help="保存路径")
    dl_parser.add_argument("--rate-limit", type=float, default=1.0, help="请求间隔(秒)")

    # ocr
    ocr_parser = subparsers.add_parser("ocr", help="OCR识别验证码")
    ocr_parser.add_argument("--image", required=True, help="验证码图片路径")
    ocr_parser.add_argument("--config", help="tesseract配置参数")

    # manual
    manual_parser = subparsers.add_parser("manual", help="手动输入验证码")
    manual_parser.add_argument("--image", required=True, help="验证码图片路径")

    # auto (一站式)
    auto_parser = subparsers.add_parser("auto", help="一站式验证码处理")
    auto_parser.add_argument("--url", required=True, help="验证码图片URL")
    auto_parser.add_argument("--output", default="/tmp/captcha.png", help="保存路径")
    auto_parser.add_argument(
        "--mode", choices=["manual", "ocr", "both"],
        default="manual", help="处理模式"
    )
    auto_parser.add_argument("--rate-limit", type=float, default=1.0, help="请求间隔(秒)")

    # bypass
    bypass_parser = subparsers.add_parser("bypass", help="验证码绕过测试")
    bypass_parser.add_argument("--url", required=True, help="提交URL")
    bypass_parser.add_argument(
        "--form", required=True,
        help='表单数据JSON (不含验证码字段)，如 \'{"username":"test","password":"test123"}\''
    )
    bypass_parser.add_argument("--field", default="captcha", help="验证码字段名")
    bypass_parser.add_argument("--reuse", help="重放旧的验证码值")
    bypass_parser.add_argument("--rate-limit", type=float, default=2.0, help="请求间隔(秒)")
    bypass_parser.add_argument("--list-payloads", action="store_true", help="列出所有绕过payload")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if args.command is None:
        parser.print_help()
        return

    if not confirm_authorization():
        sys.exit(1)

    if hasattr(args, "list_payloads") and args.list_payloads:
        _show_payloads()
        return

    handlers = {
        "download": _handle_download,
        "ocr": _handle_ocr,
        "manual": _handle_manual,
        "auto": _handle_auto,
        "bypass": _handle_bypass,
    }
    handler = handlers.get(args.command)
    if handler:
        handler(args)


if __name__ == "__main__":
    main()
