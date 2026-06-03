# 🛡️ BugBounty Toolkit

> 白帽挖洞工具箱 — 从信息收集到漏洞利用的全流程方法论、自动化脚本、实用技巧

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](.github/CONTRIBUTING.md)
[![Maintenance](https://img.shields.io/badge/maintained-yes-green.svg)](https://github.com/yourname/BugBounty-Toolkit)

---

## 📋 目录

- [为什么做这个项目](#为什么做这个项目)
- [快速开始](#快速开始)
- [项目结构](#项目结构)
- [使用场景](#使用场景)
- [贡献指南](#贡献指南)
- [免责声明](#免责声明)

---

## 🎯 为什么做这个项目

在真实挖洞实战中积累的经验教训、技巧方法，整理成系统化的知识库和工具集。目标是：

1. **知识系统化** — 把零散的技巧整理成方法论框架
2. **工具自动化** — 一键执行重复性工作，聚焦核心漏洞
3. **经验可传承** — 新人可以站在前人肩膀上，不必重复踩坑

---

## 🚀 快速开始

### 前置要求

- Python 3.8+
- Bash (Linux/macOS/WSL)

### 一键安装

```bash
git clone https://github.com/yourname/BugBounty-Toolkit.git
cd BugBounty-Toolkit
pip install -r requirements.txt
```

### 快速使用

```bash
# 一键信息收集
bash scripts/recon/full_recon.sh example.com

# JS接口提取
python scripts/js-tools/js_api_extractor.py -u https://example.com/app.js

# 批量IDOR检测
python scripts/scanners/mass_idor.py -l urls.txt -c cookies.txt

# WAF绕过测试
python scripts/utils/waf_bypass.py -u https://example.com/admin
```

### Docker 方式

```bash
docker-compose up -d
docker exec -it bugbounty-toolkit bash
```

---

## 📂 项目结构

```
BugBounty-Toolkit/
├── methodology/          # 📖 挖洞方法论
│   ├── 01-recon.md          — 信息收集标准流程
│   ├── 02-js-analysis.md    — JS接口挖掘四步法
│   ├── 03-api-testing.md    — API安全测试方法论
│   ├── 04-chained-attacks.md— 链式攻击思维
│   └── 05-business-logic.md — 业务逻辑漏洞挖掘
│
├── techniques/           # 🔓 漏洞利用技巧
│   ├── 01-waf-bypass.md     — WAF/403绕过手册
│   ├── 02-idor.md           — 越权漏洞检测
│   ├── 03-jwt-attacks.md    — JWT攻击技术
│   ├── 04-graphql.md        — GraphQL安全测试
│   ├── 05-oauth.md          — OAuth 2.0测试
│   └── 06-race-condition.md — 条件竞争漏洞
│
├── scripts/              # ⚡ 自动化工具
│   ├── recon/               — 信息收集
│   ├── scanners/            — 漏洞扫描
│   ├── js-tools/            — JS分析
│   └── utils/               — 工具函数
│
├── wordlists/            # 📚 自定义字典
├── templates/            # 📝 漏洞报告模板
├── case-studies/         # 🎯 实战案例分析
├── cheatsheets/          # 📋 速查手册
└── config/               # ⚙️ 工具配置
```

---

## 🎬 使用场景

| 场景 | 操作 | 预计耗时 |
|------|------|---------|
| 新目标信息收集 | `bash scripts/recon/full_recon.sh target.com` | 5-15min |
| 从JS找API接口 | `python scripts/js-tools/js_api_extractor.py -u URL` | 1-2min |
| 批量测试未授权 | `python scripts/scanners/mass_idor.py -l urls.txt` | 3-10min |
| 403/WAF绕过 | 参考 `techniques/01-waf-bypass.md` | - |
| 写漏洞报告 | 参考 `templates/补天.md` | 10min |

---

## 🤝 贡献指南

欢迎贡献！详见 [CONTRIBUTING.md](.github/CONTRIBUTING.md)

---

## ⚠️ 免责声明

本项目仅用于**授权的安全测试、CTF比赛、安全研究**等合法用途。使用者需遵守当地法律法规，任何非法使用与作者无关。

---

## 📜 致谢

- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload参考
- [ProjectDiscovery](https://github.com/projectdiscovery) — 优秀的开源工具
- 所有在挖洞路上分享知识的师傅们 🙏
