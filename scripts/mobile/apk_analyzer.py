#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APK分析工具 - Android APK Static Analyzer
=============================================
用途: 从APK中提取API端点、密钥、敏感信息
      对移动端APK做静态分析，发现隐藏API和凭证

功能:
  - 下载APK文件
  - 使用 apktool (如有) 或 zipfile 解包
  - 提取 URL / API 端点
  - 搜索硬编码密钥、Token
  - 搜索 Firebase / AWS / 阿里云等云服务端点
  - 生成详细分析报告

注意:
  本工具仅用于已获得明确授权的安全测试。
  未经授权逆向分析APK可能违反相关软件许可协议及法律法规。

合规要求:
  1. 必须获得目标App所有者的书面授权
  2. 分析结果仅用于评估安全性，不得泄露或滥用
  3. 发现敏感信息后应立即通知目标方
  4. 不得将提取的API端点用于未授权访问
"""

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from datetime import datetime
from typing import Optional, List, Tuple, Dict
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

# ---------------------------------------------------------------------------
# 授权确认
# ---------------------------------------------------------------------------
CONSENT_TEXT = """
╔══════════════════════════════════════════════════════════════════╗
║               ⚠  法律与合规声明  ⚠                              ║
╠══════════════════════════════════════════════════════════════════╣
║  本工具仅限已获得目标APK所有者明确书面授权的安全测试使用。        ║
║  未经授权逆向分析APK可能违反:                                    ║
║    - 《中华人民共和国网络安全法》                                 ║
║    - 《计算机软件保护条例》                                       ║
║    - 目标App的最终用户许可协议(EULA)                              ║
║                                                                  ║
║  使用前请确认:                                                   ║
║  □ 我已获得目标APK所有者的书面授权                               ║
║  □ 我了解逆向分析的法律风险                                      ║
║  □ 我将在发现敏感信息后负责任地报告                               ║
║  □ 承诺不将提取的端点用于未授权访问                               ║
╚══════════════════════════════════════════════════════════════════╝
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
logger = logging.getLogger("apk_analyzer")


# ---------------------------------------------------------------------------
# 速率限制器（用于下载）
# ---------------------------------------------------------------------------
class RateLimiter:
    def __init__(self, interval: float = 1.0):
        self.interval = interval
        self._last = 0.0

    def wait(self):
        now = time.time()
        elapsed = now - self._last
        if elapsed < self.interval:
            time.sleep(self.interval - elapsed)
        self._last = time.time()


# ---------------------------------------------------------------------------
# APK 解包
# ---------------------------------------------------------------------------
def find_apktool() -> Optional[str]:
    """查找系统 apktool"""
    for candidate in ("apktool", "apktool.sh", "java -jar apktool.jar"):
        try:
            subprocess.run(
                [candidate, "--version"],
                capture_output=True, timeout=10, check=False
            )
            return candidate
        except (FileNotFoundError, OSError):
            continue
    return None


def extract_with_apktool(apk_path: str, output_dir: str) -> bool:
    """使用 apktool 解包"""
    apktool = find_apktool()
    if not apktool:
        logger.warning("apktool 未找到，将使用基本解包")
        return False

    logger.info(f"使用 apktool 解包: {apk_path}")
    try:
        result = subprocess.run(
            [apktool, "d", "-f", "-o", output_dir, apk_path],
            capture_output=True, text=True, timeout=120,
        )
        if result.returncode == 0:
            logger.info("apktool 解包成功")
            return True
        else:
            logger.warning(f"apktool 解包失败: {result.stderr[:200]}")
            return False
    except subprocess.TimeoutExpired:
        logger.error("apktool 解包超时")
        return False
    except Exception as e:
        logger.error(f"apktool 异常: {e}")
        return False


def extract_with_zipfile(apk_path: str, output_dir: str) -> bool:
    """使用 zipfile 基本解包（APK本质是ZIP）"""
    logger.info(f"使用 zipfile 解包: {apk_path}")
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(output_dir)
        logger.info(f"zipfile 解包成功 -> {output_dir}")
        return True
    except zipfile.BadZipFile as e:
        logger.error(f"APK 文件损坏: {e}")
        return False
    except Exception as e:
        logger.error(f"解包异常: {e}")
        return False


def extract_apk(apk_path: str, output_dir: str) -> bool:
    """解包 APK，优先使用 apktool"""
    if not os.path.isfile(apk_path):
        logger.error(f"APK文件不存在: {apk_path}")
        return False

    os.makedirs(output_dir, exist_ok=True)

    # 优先 apktool
    if extract_with_apktool(apk_path, output_dir):
        return True

    # 回退到 zipfile
    return extract_with_zipfile(apk_path, output_dir)


# ---------------------------------------------------------------------------
# 分析引擎
# ---------------------------------------------------------------------------

# API 端点正则
URL_PATTERNS = [
    re.compile(r'https?://[^\s"\'<>{}|\\^`\[\]]+(?:\.[^\s"\'<>{}|\\^`\[\]]+)+'),
    re.compile(r'(?:ws|wss)://[^\s"\'<>{}|\\^`\[\]]+'),
]

# 常见 API 路径模式
API_PATH_PATTERN = re.compile(
    r'[/]?(?:api|v[12]|rest|graphql|service|sdk|gateway|endpoint)'
    r'[/][a-zA-Z0-9_\-./]+',
    re.IGNORECASE
)

# 敏感信息正则
SECRET_PATTERNS: List[Tuple[str, re.Pattern, str]] = [
    ("AWS Access Key", re.compile(r'AKIA[0-9A-Z]{16}'), "高"),
    ("AWS Secret Key", re.compile(r'(?i)aws[_-]?(?:secret|access)[_-]?key["\s:=]+["\']["\'a-zA-Z0-9+/=]{40}'), "高"),
    ("Firebase URL", re.compile(r'https://[a-zA-Z0-9-]+\.firebaseio\.com'), "中"),
    ("Firebase API Key", re.compile(r'AIzaSy[0-9A-Za-z_-]{33}'), "高"),
    ("Google OAuth", re.compile(r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com'), "中"),
    ("阿里云 AccessKey", re.compile(r'LTAI[0-9A-Za-z]{12,20}'), "高"),
    ("通用 API Key", re.compile(
        r'(?i)(?:api[_-]?key|apikey|secret[_-]?key)'
        r'["\s:=]+["\'][a-zA-Z0-9_\-]{16,64}["\']'
    ), "高"),
    ("JWT Token", re.compile(r'eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}'), "高"),
    ("Authorization Header", re.compile(r'(?i)authorization:\s*(?:bearer|basic|token)\s+[a-zA-Z0-9_\-./=+]{8,}'), "高"),
    ("Password Hardcode", re.compile(r'(?i)(?:password|pwd|passwd)["\s:=]+["\'][^"\'"]{6,}["\']'), "中"),
    ("Token Hardcode", re.compile(
        r'(?i)(?:token|access_token|refresh_token)'
        r'["\s:=]+["\'][a-zA-Z0-9_\-]{16,}["\']'
    ), "高"),
    ("OSS Endpoint", re.compile(r'(?:oss|cos|s3)[.\-][a-zA-Z0-9.\-]+(?:\.com|\.cn)'), "中"),
    ("Private IP", re.compile(
        r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}'
        r'|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
        r'|192\.168\.\d{1,3}\.\d{1,3})\b'
    ), "中"),
    ("MongoDB URI", re.compile(r'mongodb(?:\+srv)?://[^\s"\'<>]+'), "高"),
    ("MySQL URI", re.compile(r'mysql://[^\s"\'<>]+'), "高"),
    ("Redis URI", re.compile(r'redis://[^\s"\'<>]+'), "高"),
]

# 文件扩展名白名单（可分析的文件类型）
ANALYZABLE_EXTENSIONS = {
    ".xml", ".json", ".txt", ".html", ".js", ".java", ".kt", ".gradle",
    ".properties", ".yml", ".yaml", ".cfg", ".conf", ".ini", ".plist",
    ".dex", ".smali",
}

# 忽略的目录
IGNORE_DIRS = {
    "res/drawable", "res/mipmap", "res/raw", "res/color",
    "META-INF", "org/apache", "kotlin",
}

# 常见混淆关键字，跳过
SKIP_KEYWORDS = {"example", "sample", "dummy", "placeholder", "your-"}


# ---------------------------------------------------------------------------
# 文件扫描
# ---------------------------------------------------------------------------
def should_scan_file(file_path: str) -> bool:
    """判断文件是否应被扫描"""
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ANALYZABLE_EXTENSIONS:
        return False
    for ignore in IGNORE_DIRS:
        if ignore in file_path.replace("\\", "/"):
            return False
    return True


def read_file_safe(file_path: str, max_size: int = 5 * 1024 * 1024) -> Optional[str]:
    """安全读取文件内容（限制大小、处理编码问题）"""
    try:
        size = os.path.getsize(file_path)
        if size > max_size:
            logger.debug(f"跳过大文件: {file_path} ({size} bytes)")
            return None
        if size == 0:
            return None

        with open(file_path, "rb") as f:
            raw = f.read()

        # 尝试多种编码
        for enc in ("utf-8", "gbk", "gb2312", "latin-1", "utf-16"):
            try:
                return raw.decode(enc)
            except (UnicodeDecodeError, LookupError):
                continue
        return raw.decode("latin-1")  # 兜底
    except Exception as e:
        logger.debug(f"读取文件失败 {file_path}: {e}")
        return None


def scan_file_for_urls(content: str, file_path: str) -> List[Dict]:
    """扫描文件中的URL"""
    results = []
    for pattern in URL_PATTERNS:
        for match in pattern.finditer(content):
            url = match.group()
            # 过滤明显无关的内容
            if any(skip in url.lower() for skip in SKIP_KEYWORDS):
                continue
            results.append({
                "type": "URL",
                "value": url,
                "file": file_path,
                "severity": "info",
            })
    # 额外扫描 API 路径
    for match in API_PATH_PATTERN.finditer(content):
        path = match.group().strip()
        if path and len(path) > 5:
            results.append({
                "type": "API Path",
                "value": path,
                "file": file_path,
                "severity": "info",
            })
    return results


def scan_file_for_secrets(content: str, file_path: str) -> List[Dict]:
    """扫描文件中的敏感信息"""
    results = []
    for name, pattern, severity in SECRET_PATTERNS:
        for match in pattern.finditer(content):
            value = match.group()
            # 过滤无关内容
            if any(skip in value.lower() for skip in SKIP_KEYWORDS):
                continue
            results.append({
                "type": name,
                "value": value[:120] + ("..." if len(value) > 120 else ""),
                "file": file_path,
                "severity": severity,
            })
    return results


def scan_file(file_path: str, base_dir: str) -> Tuple[List[Dict], List[Dict]]:
    """扫描单个文件，返回 (urls, secrets)"""
    rel_path = os.path.relpath(file_path, base_dir)
    content = read_file_safe(file_path)
    if content is None:
        return [], []

    urls = scan_file_for_urls(content, rel_path)
    secrets = scan_file_for_secrets(content, rel_path)

    return urls, secrets


def scan_directory(extract_dir: str, max_workers: int = 4) -> Tuple[List[Dict], List[Dict]]:
    """扫描解包后的目录"""
    all_urls = []
    all_secrets = []

    files_to_scan = []
    for root, dirs, files in os.walk(extract_dir):
        # 过滤忽略目录
        dirs[:] = [d for d in dirs if d not in IGNORE_DIRS]
        for fname in files:
            fpath = os.path.join(root, fname)
            if should_scan_file(fpath):
                files_to_scan.append(fpath)

    logger.info(f"待扫描文件: {len(files_to_scan)}")

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(scan_file, fp, extract_dir): fp for fp in files_to_scan}
        done = 0
        for future in as_completed(futures):
            done += 1
            if done % 50 == 0:
                logger.info(f"扫描进度: {done}/{len(files_to_scan)}")

            urls, secrets = future.result()
            all_urls.extend(urls)
            all_secrets.extend(secrets)

    # 去重
    seen_urls = set()
    unique_urls = []
    for u in all_urls:
        key = u["value"]
        if key not in seen_urls:
            seen_urls.add(key)
            unique_urls.append(u)

    return unique_urls, all_secrets


# ---------------------------------------------------------------------------
# 报告生成
# ---------------------------------------------------------------------------
def generate_report(
    apk_path: str,
    urls: List[Dict],
    secrets: List[Dict],
    output_path: str,
    metadata: Optional[Dict] = None,
):
    """生成结构化分析报告"""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    file_size = os.path.getsize(apk_path) if os.path.exists(apk_path) else 0

    # 统计
    high_secrets = [s for s in secrets if s["severity"] == "高"]
    mid_secrets = [s for s in secrets if s["severity"] == "中"]

    report = {
        "报告生成时间": now,
        "APK文件": os.path.abspath(apk_path),
        "文件大小": f"{file_size / 1024 / 1024:.1f} MB",
        "SHA256": metadata.get("sha256", "") if metadata else "",
        "统计": {
            "发现的URL/端点": len(urls),
            "高严重性敏感信息": len(high_secrets),
            "中严重性敏感信息": len(mid_secrets),
            "总发现数": len(urls) + len(secrets),
        },
        "API端点": [],
        "敏感信息": [],
    }

    # 按来源文件分组URL
    urls_by_file: Dict[str, List[str]] = {}
    for u in urls:
        f = u.get("file", "unknown")
        urls_by_file.setdefault(f, []).append(u["value"])

    for fname, endpoints in sorted(urls_by_file.items()):
        report["API端点"].append({
            "文件": fname,
            "端点数": len(endpoints),
            "端点列表": endpoints[:50],  # 限制每文件50个
        })

    for s in secrets:
        report["敏感信息"].append({
            "类型": s["type"],
            "值": s["value"],
            "文件": s["file"],
            "严重程度": s["severity"],
        })

    # 写入
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)

    logger.info(f"报告已生成: {output_path}")

    # 控制台摘要
    print(f"\n{'='*50}")
    print(f"分析摘要 - {os.path.basename(apk_path)}")
    print(f"{'='*50}")
    print(f"  URL/端点:        {len(urls)}")
    print(f"  高严重性发现:    {len(high_secrets)}")
    print(f"  中严重性发现:    {len(mid_secrets)}")
    print(f"  报告文件:        {output_path}")

    if high_secrets:
        print("\n  [!] 高严重性发现:")
        for s in high_secrets[:10]:
            print(f"      - [{s['type']}] {s['value'][:80]}")
            print(f"        文件: {s['file']}")
        if len(high_secrets) > 10:
            print(f"      ... 还有 {len(high_secrets)-10} 个")

    return report


# ---------------------------------------------------------------------------
# 下载 APK
# ---------------------------------------------------------------------------
def download_apk(url: str, output_path: str, rate_limiter: Optional[RateLimiter] = None) -> str:
    """下载APK文件"""
    try:
        import requests
    except ImportError:
        raise RuntimeError("需要安装 requests: pip install requests")

    if rate_limiter:
        rate_limiter.wait()

    logger.info(f"正在下载APK: {url}")
    resp = requests.get(url, timeout=60, stream=True)
    resp.raise_for_status()

    os.makedirs(os.path.dirname(os.path.abspath(output_path)) or ".", exist_ok=True)

    with open(output_path, "wb") as f:
        downloaded = 0
        for chunk in resp.iter_content(chunk_size=8192):
            if chunk:
                f.write(chunk)
                downloaded += len(chunk)

    abs_path = os.path.abspath(output_path)
    logger.info(f"APK下载完成: {abs_path} ({downloaded / 1024 / 1024:.1f} MB)")
    return abs_path


def compute_sha256(file_path: str) -> str:
    """计算文件SHA256"""
    h = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
def analyze_apk(
    apk_path: str,
    output_dir: Optional[str] = None,
    keep_extracted: bool = False,
    max_workers: int = 4,
) -> str:
    """
    分析APK文件

    Args:
        apk_path: APK文件路径
        output_dir: 输出目录（默认与APK同目录）
        keep_extracted: 是否保留解包目录
        max_workers: 并行扫描线程数

    Returns:
        报告文件路径
    """
    if not os.path.isfile(apk_path):
        raise FileNotFoundError(f"APK文件不存在: {apk_path}")

    apk_name = os.path.splitext(os.path.basename(apk_path))[0]
    if output_dir is None:
        output_dir = os.path.dirname(os.path.abspath(apk_path))

    os.makedirs(output_dir, exist_ok=True)

    # 计算哈希
    logger.info("计算文件哈希...")
    sha256 = compute_sha256(apk_path)
    logger.info(f"SHA256: {sha256}")

    # 解包
    extract_dir = os.path.join(output_dir, f"{apk_name}_extracted")
    logger.info(f"解包到: {extract_dir}")

    if not extract_apk(apk_path, extract_dir):
        raise RuntimeError("APK解包失败")

    # 扫描
    logger.info("开始扫描...")
    urls, secrets = scan_directory(extract_dir, max_workers)

    # 报告
    report_path = os.path.join(output_dir, f"{apk_name}_report.json")
    generate_report(apk_path, urls, secrets, report_path, metadata={"sha256": sha256})

    # 清理
    if not keep_extracted:
        logger.info(f"清理解包目录: {extract_dir}")
        shutil.rmtree(extract_dir, ignore_errors=True)
    else:
        logger.info(f"解包目录保留: {extract_dir}")

    return report_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _handle_download(args, output_dir: str) -> list:
    """处理 --download 参数，返回下载的APK路径列表"""
    apk_paths = []
    if args.download:
        if not args.no_download_confirm:
            try:
                ok = input(f"[?] 即将下载: {args.download}\n    继续? (yes/no): ").strip().lower() in ("yes", "y")
                if not ok:
                    print("[-] 取消下载")
                    sys.exit(1)
            except (KeyboardInterrupt, EOFError):
                print()
                sys.exit(1)

        dl_path = os.path.join(output_dir, "downloaded.apk")
        downloaded = download_apk(args.download, dl_path, RateLimiter(args.rate_limit))
        apk_paths.append(downloaded)
    return apk_paths


def _handle_url_list(args, output_dir: str) -> list:
    """处理 --url-list 参数，返回下载的APK路径列表"""
    apk_paths = []
    if args.url_list:
        if not os.path.isfile(args.url_list):
            print(f"[-] URL列表文件不存在: {args.url_list}")
            sys.exit(1)

        rate_limiter = RateLimiter(args.rate_limit)
        with open(args.url_list, "r") as f:
            urls = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        for i, url in enumerate(urls):
            fname = f"apk_{i}_{int(time.time())}.apk"
            dl_path = os.path.join(output_dir, fname)
            try:
                downloaded = download_apk(url, dl_path, rate_limiter)
                apk_paths.append(downloaded)
            except Exception as e:
                logger.error(f"下载失败 {url}: {e}")
    return apk_paths


def _build_parser() -> argparse.ArgumentParser:
    """构建命令行参数解析器"""
    parser = argparse.ArgumentParser(
        description="APK分析工具 - Android APK Static Analyzer (仅限授权测试)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 分析本地APK
  %(prog)s --apk app.apk

  # 下载并分析
  %(prog)s --download https://example.com/app.apk

  # 指定输出目录
  %(prog)s --apk app.apk --output ./reports

  # 保留解包文件（便于手动审查）
  %(prog)s --apk app.apk --keep

  # 从URL列表文件批量分析
  %(prog)s --url-list urls.txt --output ./reports
        """,
    )

    parser.add_argument("--apk", help="本地APK文件路径")
    parser.add_argument("--download", help="APK下载URL")
    parser.add_argument("--url-list", help="包含多个APK URL的文件（每行一个URL）")
    parser.add_argument("--output", "-o", help="输出目录")
    parser.add_argument("--keep", action="store_true", help="保留解包目录")
    parser.add_argument("--workers", type=int, default=4, help="并行扫描线程数（默认4）")
    parser.add_argument("--rate-limit", type=float, default=2.0, help="下载请求间隔(秒)")
    parser.add_argument("--no-download-confirm", action="store_true", help="下载前不确认")

    return parser


def main():
    parser = _build_parser()
    args = parser.parse_args()

    if not any([args.apk, args.download, args.url_list]):
        parser.print_help()
        print("\n[-] 请提供 --apk, --download 或 --url-list")
        sys.exit(1)

    # 授权确认
    if not confirm_consent():
        sys.exit(1)

    output_dir = args.output or os.getcwd()
    os.makedirs(output_dir, exist_ok=True)

    apk_paths = []
    apk_paths.extend(_handle_download(args, output_dir))
    apk_paths.extend(_handle_url_list(args, output_dir))

    # 处理 --apk
    if args.apk:
        if not os.path.isfile(args.apk):
            print(f"[-] APK文件不存在: {args.apk}")
            sys.exit(1)
        apk_paths.append(args.apk)

    # 去重
    apk_paths = list(dict.fromkeys(apk_paths))
    logger.info(f"待分析APK: {len(apk_paths)}")

    # 逐个分析
    reports = []
    for apk_path in apk_paths:
        try:
            report = analyze_apk(
                apk_path,
                output_dir=output_dir,
                keep_extracted=args.keep,
                max_workers=args.workers,
            )
            reports.append(report)
        except Exception as e:
            logger.error(f"分析失败 {apk_path}: {e}")

    print(f"\n[+] 分析完成。共生成 {len(reports)} 份报告。")
    for r in reports:
        print(f"    - {r}")


if __name__ == "__main__":
    main()
