#!/usr/bin/env python3
"""
BugBounty Toolkit — 漏洞报告生成器
===================================
用途: 根据发现的信息自动生成格式化漏洞报告
使用方法:
    python report_gen.py -t 补天 -o report.md

注意: 仅用于已获得明确授权的安全测试！
"""

import argparse
import time
from pathlib import Path

BANNER = """
╔══════════════════════════════════════════════════════════════╗
║        ⚠️  报告生成器 — 仅限授权测试                         ║
╠══════════════════════════════════════════════════════════════╣
║ 本工具仅用于已获得明确授权的安全测试报告生成                     ║
║ 报告中不包含任何敏感数据                                     ║
╚══════════════════════════════════════════════════════════════╝
"""


def generate_butian_template(args) -> str:
    """生成补天平台格式的报告"""
    return f"""# [{args.severity}] {args.vuln_type} - {args.target}

## 漏洞信息
- **漏洞类型**: {args.vuln_type}
- **影响范围**: {args.target}
- **危害等级**: {args.severity}
- **测试时间**: {time.strftime('%Y-%m-%d %H:%M:%S')}

## 漏洞描述
{args.description or '[请描述漏洞是什么]'}

## 影响
{args.impact or '[请描述漏洞可能造成的影响]'}

## 复现步骤
1. {args.step1 or '[第一步]'}
2. {args.step2 or '[第二步]'}
3. {args.step3 or '[第三步]'}

## 复现截图/PoC
> 请在此处添加截图或PoC代码

## 修复建议
{args.fix or '[请给出修复建议]'}

## 声明
- ✅ 已获得授权测试
- ✅ 仅提交漏洞证明，未下载/利用任何数据
- ✅ 所有数据已销毁
"""


def generate_hackerone_template(args) -> str:
    """生成HackerOne格式的报告"""
    return f"""# Vulnerability Report

**Vulnerability Type:** {args.vuln_type}
**Affected Component:** {args.target}
**Severity:** {args.severity}

## Description
{args.description or '[Describe the vulnerability]'}

## Steps to Reproduce
1. {args.step1 or '[First step]'}
2. {args.step2 or '[Second step]'}
3. {args.step3 or '[Third step]'}

## Impact
{args.impact or '[Describe the potential impact]'}

## Proof of Concept
> Add PoC here

## Remediation Suggestion
{args.fix or '[Suggest a fix]'}

## Supporting Material
[Screenshots, logs, etc.]

## Declaration
- Authorized testing was conducted
- No data was exfiltrated
"""


def generate_self_template(args) -> str:
    """生成自用报告格式"""
    return f"""# 安全漏洞报告

## 基本信息
| 项目 | 内容 |
|------|------|
| 漏洞类型 | {args.vuln_type} |
| 目标 | {args.target} |
| 危害等级 | {args.severity} |
| 发现时间 | {time.strftime('%Y-%m-%d %H:%M:%S')} |
| 测试者 | {args.author or '[姓名/ID]'} |

## 漏洞详情
{args.description or '[详细描述]'}

## 影响范围
{args.impact or '[影响分析]'}

## 复现步骤
1. {args.step1 or '[步骤1]'}
2. {args.step2 or '[步骤2]'}
3. {args.step3 or '[步骤3]'}

## 证据
> 截图/请求/响应数据

## 修复建议
{args.fix or '[修复方案]'}

## 补充信息
- **平台**: {args.platform or '补天/HackerOne/自建'}
- **状态**: 待提交
"""


def _fill_args_interactive(parser, args):
    """交互式填写参数"""
    print("[*] 进入交互模式（也可使用命令行参数）")
    print()

    if not args.target:
        args.target = input("目标: ")
    if not args.vuln_type:
        args.vuln_type = input("漏洞类型: ")
    if not args.severity:
        args.severity = input("危害等级 (严重/高危/中危/低危): ") or '中危'
    if not args.description:
        args.description = input("漏洞描述: ")
    if not args.impact:
        args.impact = input("漏洞影响: ")
    print("复现步骤 (每行一行，空行结束):")
    steps = []
    for i in range(3):
        step = input(f"  步骤{i+1}: ")
        if step:
            steps.append(step)
    if steps:
        args.step1 = steps[0] if len(steps) > 0 else ''
        args.step2 = steps[1] if len(steps) > 1 else ''
        args.step3 = steps[2] if len(steps) > 2 else ''
    if not args.fix:
        args.fix = input("修复建议: ")
    return args


def main():
    print(BANNER)

    parser = argparse.ArgumentParser(description='漏洞报告生成器 (仅限授权测试)')
    parser.add_argument('-t', '--template', choices=['补天', 'hackerone', 'self'],
                        default='补天', help='报告模板')
    parser.add_argument('-o', '--output', default='output/report.md', help='输出文件')
    parser.add_argument('--target', help='目标域名/应用名')
    parser.add_argument('--vuln-type', help='漏洞类型')
    parser.add_argument('--severity', choices=['严重', '高危', '中危', '低危', 'info',
                                               'Critical', 'High', 'Medium', 'Low', 'Info'],
                        default='中危', help='危害等级')
    parser.add_argument('--description', help='漏洞描述')
    parser.add_argument('--impact', help='影响描述')
    parser.add_argument('--fix', help='修复建议')
    parser.add_argument('--step1', help='复现步骤1')
    parser.add_argument('--step2', help='复现步骤2')
    parser.add_argument('--step3', help='复现步骤3')
    parser.add_argument('--author', help='测试者名称（自用模板）')
    parser.add_argument('--platform', help='提交平台（自用模板）')
    args = parser.parse_args()

    # 交互模式：如果没有提供参数，逐一询问
    if not any([args.target, args.vuln_type, args.description]):
        args = _fill_args_interactive(parser, args)

    # 生成报告
    if args.template == '补天':
        report = generate_butian_template(args)
    elif args.template == 'hackerone':
        report = generate_hackerone_template(args)
    else:
        report = generate_self_template(args)

    # 输出
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(report, encoding='utf-8')

    print(f"\n[+] 报告已生成: {output_path}")
    print(f"\n{'='*60}")
    print(report)


if __name__ == '__main__':
    main()
