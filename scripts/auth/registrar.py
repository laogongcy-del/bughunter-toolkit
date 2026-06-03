#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动化注册助手 - Registration Automation Framework
=====================================================
用途: 自动化多平台用户注册流程（仅限已授权测试）
设计: 基于模板的可扩展注册框架，内置目标注册流程

内置目标:
  - blacklake.cn: 验证码 → 短信验证码 → 提交注册

合规要求:
  1. 必须获得目标系统所有者的书面授权
  2. 不得用于批量注册、恶意注册或破坏平台规则
  3. 测试频率必须控制在不影响正常服务的范围内
  4. 发现漏洞后立即停止并负责任地报告
  5. 不得将测试中获得的用户信息用于任何非授权目的

法律声明:
  本工具仅限安全研究人员在授权范围内使用。
  未经授权使用可能违反《中华人民共和国网络安全法》第27条及相关法规。
"""

import argparse
import json
import os
import re
import sys
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, List, Callable, Any
from enum import Enum

# ---------------------------------------------------------------------------
# 授权确认与合规提示
# ---------------------------------------------------------------------------
LEGAL_NOTICE = """
╔══════════════════════════════════════════════════════════════════╗
║                    ⚠  法律与合规声明  ⚠                         ║
╠══════════════════════════════════════════════════════════════════╣
║  本工具仅限已获得目标系统所有者明确书面授权的安全测试使用。       ║
║  未经授权使用可能违反《中华人民共和国网络安全法》及相关刑法条款。   ║
║                                                                  ║
║  使用前请确认以下事项:                                            ║
║  □ 我已获得测试目标的书面授权文件                                  ║
║  □ 我了解在未经授权情况下模拟注册的法律风险                       ║
║  □ 同意测试发现的问题仅通过负责任披露渠道报告                      ║
║  □ 同意测试过程中不存储或泄露任何真实用户信息                      ║
╚══════════════════════════════════════════════════════════════════╝
"""


def require_consent() -> bool:
    """要求用户确认授权"""
    print(LEGAL_NOTICE)
    try:
        answer = input("\n[*] 是否已获得书面授权？(yes/no): ").strip().lower()
        if answer in ("yes", "y", "是", "确认", "ok"):
            print("[+] 授权确认通过。\n")
            return True
        print("[-] 未确认授权，程序退出。\n")
        return False
    except (KeyboardInterrupt, EOFError):
        print("\n[-] 用户取消。")
        return False


# ---------------------------------------------------------------------------
# 速率限制
# ---------------------------------------------------------------------------
class RateLimiter:
    """请求速率限制器"""

    def __init__(self, min_interval: float = 2.0):
        self.min_interval = min_interval
        self._last: float = 0.0

    def wait(self):
        now = time.time()
        elapsed = now - self._last
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)
        self._last = time.time()


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------
import logging
logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s - %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("registrar")


# ---------------------------------------------------------------------------
# 数据定义
# ---------------------------------------------------------------------------
class RegistrationStatus(Enum):
    PENDING = "pending"
    CAPTCHA_REQUIRED = "captcha_required"
    SMS_REQUIRED = "sms_required"
    SUBMITTED = "submitted"
    SUCCESS = "success"
    FAILED = "failed"
    BLOCKED = "blocked"


@dataclass
class RegistrationResult:
    """注册结果"""
    success: bool
    status: RegistrationStatus
    message: str = ""
    response_data: Optional[Dict] = None
    cookies: Optional[Dict] = None
    error: Optional[str] = None

    def __str__(self):
        return (
            f"[{'OK' if self.success else 'FAIL'}] "
            f"{self.status.value}: {self.message or self.error or ''}"
        )


@dataclass
class RegistrationProfile:
    """注册用户信息"""
    username: str = ""
    password: str = ""
    email: str = ""
    phone: str = ""
    extra: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, str]:
        d = {
            "username": self.username,
            "password": self.password,
            "email": self.email,
            "phone": self.phone,
        }
        d.update(self.extra)
        return {k: v for k, v in d.items() if v}


# ---------------------------------------------------------------------------
# 会话管理
# ---------------------------------------------------------------------------
try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

    class requests:  # type: ignore
        class Session:
            def __enter__(self):
                return self

            def __exit__(self, *a):
                pass

    logger.warning("requests 未安装: pip install requests")


def new_session() -> "requests.Session":
    """创建带重试的HTTP会话"""
    if not HAS_REQUESTS:
        raise RuntimeError("需要 requests 库: pip install requests")
    session = requests.Session()
    session.headers.update({
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/125.0.0.0 Safari/537.36"
        ),
        "Accept-Language": "zh-CN,zh;q=0.9",
    })
    retry = Retry(total=3, backoff_factor=0.5, status_forcelist=[500, 502, 503])
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# ---------------------------------------------------------------------------
# 验证码处理钩子（尝试导入 captcha_utils）
# ---------------------------------------------------------------------------
try:
    from scripts.auth.captcha_utils import (
        download_captcha,
        manual_captcha_input,
        ocr_captcha,
    )
    HAS_CAPTCHA_UTILS = True
except ImportError:
    HAS_CAPTCHA_UTILS = False
    logger.info("captcha_utils 未找到，使用内置简化版")

    # 内置最小替代
    def download_captcha(url, path, session=None, rate_limiter=None):
        if not HAS_REQUESTS:
            raise RuntimeError("需要 requests")
        s = session or requests.Session()
        if rate_limiter:
            rate_limiter.wait()
        r = s.get(url, timeout=15, stream=True)
        r.raise_for_status()
        os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
        with open(path, "wb") as f:
            for chunk in r.iter_content(8192):
                if chunk:
                    f.write(chunk)
        logger.info(f"验证码已下载: {path}")
        return os.path.abspath(path)

    def manual_captcha_input(path, desktop=False):
        print(f"\n[!] 验证码图片位置: {os.path.abspath(path)}")
        return input("请输入验证码 (回车取消): ").strip() or None


# ---------------------------------------------------------------------------
# 目标模板基类
# ---------------------------------------------------------------------------
class TargetTemplate(ABC):
    """注册流程模板基类"""

    @property
    @abstractmethod
    def name(self) -> str:
        """目标名称"""
        ...

    @abstractmethod
    def get_captcha(self, session: "requests.Session", rate_limiter: RateLimiter) -> Optional[str]:
        """获取验证码，返回验证码文本"""
        ...

    @abstractmethod
    def submit_sms_code(self, code: str, session: "requests.Session", rate_limiter: RateLimiter) -> bool:
        """提交短信验证码"""
        ...

    @abstractmethod
    def submit_registration(
        self, profile: RegistrationProfile, session: "requests.Session", rate_limiter: RateLimiter
    ) -> RegistrationResult:
        """提交最终注册"""
        ...

    def extract_error(self, response_text: str) -> str:
        """从响应中提取错误信息"""
        # 尝试匹配常见中文错误提示
        patterns = [
            r'"message"\s*:\s*"([^"]+)"',
            r'"msg"\s*:\s*"([^"]+)"',
            r'"error"\s*:\s*"([^"]+)"',
            r'<div[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
            r'<p[^>]*class="[^"]*error[^"]*"[^>]*>([^<]+)',
        ]
        for pat in patterns:
            m = re.search(pat, response_text)
            if m:
                return m.group(1).strip()
        return "未知错误"


# ---------------------------------------------------------------------------
# 内置目标: blacklake.cn
# ---------------------------------------------------------------------------
class BlackLakeCNTemplate(TargetTemplate):
    """
    blacklake.cn 注册流程

    流程: 获取验证码 -> 输入短信验证码 -> 提交注册

    基于实际测试观察:
      - 验证码URL: /captcha/image (GET)
      - 发送短信: /register/sendSms (POST)
      - 提交注册: /register/submit (POST)
    """

    name = "blacklake.cn"

    def __init__(
        self,
        base_url: str = "https://www.blacklake.cn",
        captcha_url: str = "/captcha/image",
        sms_url: str = "/register/sendSms",
        register_url: str = "/register/submit",
    ):
        self.base_url = base_url.rstrip("/")
        self.captcha_url = captcha_url
        self.sms_url = sms_url
        self.register_url = register_url

    def get_captcha(self, session: "requests.Session", rate_limiter: RateLimiter) -> Optional[str]:
        """下载验证码图片并获取用户输入"""
        captcha_full_url = self.base_url + self.captcha_url

        logger.info(f"[blacklake] 正在获取验证码图片: {captcha_full_url}")

        # 第一次请求获取验证码（可能返回图片或需要先获取cookie）
        rate_limiter.wait()
        resp = session.get(captcha_full_url, timeout=15)
        resp.raise_for_status()

        # 保存验证码图片
        captcha_dir = "/tmp/blacklake_captcha"
        os.makedirs(captcha_dir, exist_ok=True)
        captcha_path = os.path.join(captcha_dir, f"captcha_{int(time.time())}.png")

        with open(captcha_path, "wb") as f:
            f.write(resp.content)

        logger.info(f"[blacklake] 验证码已保存: {captcha_path}")

        # 手动输入
        code = manual_captcha_input(captcha_path)
        if not code:
            logger.warning("[blacklake] 用户取消了验证码输入")
            return None

        logger.info(f"[blacklake] 用户输入验证码: {code}")
        return code

    def submit_sms_code(self, code: str, session: "requests.Session", rate_limiter: RateLimiter) -> bool:
        """
        提交短信验证码

        Args:
            code: 用户输入的短信验证码
            session: HTTP session
            rate_limiter: 速率限制器

        Returns:
            是否成功
        """
        sms_full_url = self.base_url + self.sms_url

        logger.info(f"[blacklake] 正在提交短信验证码...")

        # 短信验证码需要用户手动从手机获取
        # 这里提示用户输入
        print("\n[!] 请在手机上查看短信验证码（若已发送）")
        try:
            sms_code = input("[*] 请输入短信验证码 (回车跳过): ").strip()
        except (KeyboardInterrupt, EOFError):
            print()
            return False

        if not sms_code:
            logger.warning("[blacklake] 用户未输入短信验证码，跳过")
            return False

        # 提交短信验证码
        rate_limiter.wait()
        payload = {"smsCode": sms_code, "phone": code}
        try:
            resp = session.post(sms_full_url, data=payload, timeout=15)
            resp.raise_for_status()

            # 检查响应是否成功
            if resp.status_code == 200:
                logger.info("[blacklake] 短信验证码提交成功")
                return True
            else:
                logger.warning(f"[blacklake] 短信验证码提交失败: {resp.status_code}")
                return False

        except Exception as e:
            logger.error(f"[blacklake] 短信验证码请求异常: {e}")
            return False

    def submit_registration(
        self, profile: RegistrationProfile, session: "requests.Session", rate_limiter: RateLimiter
    ) -> RegistrationResult:
        """提交最终注册"""
        register_full_url = self.base_url + self.register_url
        form_data = profile.to_dict()

        logger.info(f"[blacklake] 正在提交注册表单: {register_full_url}")

        rate_limiter.wait()
        try:
            resp = session.post(register_full_url, data=form_data, timeout=15)

            result = RegistrationResult(
                success=resp.status_code == 200,
                status=RegistrationStatus.SUCCESS if resp.status_code == 200 else RegistrationStatus.FAILED,
                response_data=resp.json() if "application/json" in resp.headers.get("Content-Type", "") else None,
                cookies=dict(session.cookies),
            )

            if resp.status_code == 200:
                result.message = "注册提交成功"
                logger.info(f"[blacklake] {result}")
            else:
                error_msg = self.extract_error(resp.text)
                result.message = f"注册失败: {error_msg} (HTTP {resp.status_code})"
                logger.warning(f"[blacklake] {result}")

            return result

        except Exception as e:
            return RegistrationResult(
                success=False,
                status=RegistrationStatus.FAILED,
                error=str(e),
                cookies=dict(session.cookies),
            )


# ---------------------------------------------------------------------------
# 注册引擎
# ---------------------------------------------------------------------------
class RegistrationEngine:
    """
    注册引擎 - 驱动注册流程

    用法:
        engine = RegistrationEngine(BlackLakeCNTemplate())
        result = engine.run(RegistrationProfile(phone="13800138000"))
    """

    def __init__(
        self,
        template: TargetTemplate,
        rate_limit_seconds: float = 2.0,
        session: Optional["requests.Session"] = None,
        auto_confirm: bool = False,
    ):
        self.template = template
        self.rate_limiter = RateLimiter(rate_limit_seconds)
        self.session = session or (new_session() if HAS_REQUESTS else None)
        self.auto_confirm = auto_confirm
        self._steps: List[Dict] = []

    def run(self, profile: RegistrationProfile) -> RegistrationResult:
        """
        执行完整的注册流程

        Args:
            profile: 注册用户信息

        Returns:
            注册结果
        """
        self._steps = []
        logger.info(f"[引擎] 开始 [{self.template.name}] 注册流程")

        if not self.session:
            return RegistrationResult(False, RegistrationStatus.FAILED, error="无可用HTTP会话")

        if not self.auto_confirm:
            print(f"\n[*] 即将对 {self.template.name} 执行注册流程")
            print(f"    用户: {profile.username or profile.phone or profile.email}")
            try:
                ok = input("[*] 继续? (yes/no): ").strip().lower() in ("yes", "y", "是")
                if not ok:
                    logger.info("[引擎] 用户取消")
                    return RegistrationResult(False, RegistrationStatus.PENDING, message="用户取消")
            except (KeyboardInterrupt, EOFError):
                print()
                return RegistrationResult(False, RegistrationStatus.PENDING, message="用户取消")

        # Step 1: 获取验证码
        captcha_code = self._step("获取验证码", self.template.get_captcha, self.session, self.rate_limiter)
        if not captcha_code:
            return RegistrationResult(False, RegistrationStatus.CAPTCHA_REQUIRED, message="验证码获取失败")

        # Step 2: 验证码提交（部分平台验证码在短信步骤前提交）
        # 根据模板决定是否需要先在短信步骤中提交验证码
        sms_param = captcha_code

        # Step 3: 短信验证码
        sms_ok = self._step("提交短信验证码", self.template.submit_sms_code, sms_param, self.session, self.rate_limiter)
        if not sms_ok:
            logger.warning("[引擎] 短信验证码步骤未完成，继续尝试提交注册...")

        # Step 4: 提交注册
        result = self._step("提交注册", self.template.submit_registration, profile, self.session, self.rate_limiter)

        self._summary(result)
        return result

    def _step(self, name: str, func: Callable, *args, **kwargs) -> Any:
        """执行一个步骤并记录"""
        logger.info(f"[引擎] 步骤: {name}")
        self._steps.append({"step": name, "start": time.time()})
        try:
            result = func(*args, **kwargs)
            self._steps[-1]["result"] = str(result)[:200]
            self._steps[-1]["end"] = time.time()
            return result
        except Exception as e:
            self._steps[-1]["error"] = str(e)
            self._steps[-1]["end"] = time.time()
            logger.error(f"[引擎] 步骤 '{name}' 失败: {e}")
            return None

    def _summary(self, result: RegistrationResult):
        """打印执行摘要"""
        print("\n" + "=" * 50)
        print("注册流程执行摘要")
        print("=" * 50)
        for i, step in enumerate(self._steps, 1):
            status = "OK" if "error" not in step else "FAIL"
            duration = step.get("end", 0) - step.get("start", 0)
            print(f"  {i}. {step['step']:20s} [{status}] ({duration:.1f}s)")
        print("-" * 50)
        print(f"  结果: {result}")
        print("=" * 50)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="自动化注册助手 - Registration Framework (仅限授权测试)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
使用示例:
  # 交互式 blacklake.cn 注册
  %(prog)s --target blacklake --phone 13800138000

  # 指定自定义base URL
  %(prog)s --target blacklake --base-url https://test.blacklake.cn --phone 13800138000

  # 带额外字段
  %(prog)s --target blacklake --phone 13800138000 --extra '{"invite_code":"TEST123"}'

  # 不使用确认提示
  %(prog)s --target blacklake --phone 13800138000 --yes
        """,
    )

    parser.add_argument("--target", "-t", required=True, help="目标平台 (当前支持: blacklake)")
    parser.add_argument("--base-url", help="目标基础URL")
    parser.add_argument("--phone", help="手机号")
    parser.add_argument("--username", help="用户名")
    parser.add_argument("--password", help="密码")
    parser.add_argument("--email", help="邮箱")
    parser.add_argument("--extra", help="额外字段JSON, e.g. '{\"invite_code\":\"xxx\"}'")
    parser.add_argument("--rate-limit", type=float, default=2.0, help="请求间隔(秒)")
    parser.add_argument("--yes", "-y", action="store_true", help="自动确认，跳过提示")

    parser.add_argument("--list-targets", action="store_true", help="列出所有可用目标")

    args = parser.parse_args()

    # 授权确认
    if not require_consent():
        sys.exit(1)

    # 列出目标
    if args.list_targets:
        print("\n可用目标:")
        print("  blacklake   - www.blacklake.cn 注册流程")
        print("\n可通过 --target 指定")
        return

    # 构建 profile
    extra = {}
    if args.extra:
        try:
            extra = json.loads(args.extra)
        except json.JSONDecodeError as e:
            print(f"[-] extra JSON 解析失败: {e}")
            sys.exit(1)

    profile = RegistrationProfile(
        username=args.username or "",
        password=args.password or "",
        email=args.email or "",
        phone=args.phone or "",
        extra=extra,
    )

    if not any([profile.phone, profile.username, profile.email]):
        print("[-] 至少需要提供 phone、username 或 email 之一")
        sys.exit(1)

    # 选择模板
    target_name = args.target.lower()
    if target_name in ("blacklake", "blacklake.cn"):
        kwargs = {}
        if args.base_url:
            kwargs["base_url"] = args.base_url
        template = BlackLakeCNTemplate(**kwargs)
    else:
        print(f"[-] 不支持的目标: {args.target}")
        print("    可用目标: blacklake")
        sys.exit(1)

    # 运行
    engine = RegistrationEngine(
        template=template,
        rate_limit_seconds=args.rate_limit,
        auto_confirm=args.yes,
    )
    result = engine.run(profile)

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
