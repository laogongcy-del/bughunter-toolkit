# 贡献指南

感谢你考虑为本项目做出贡献！本工具集专为**授权的安全测试**设计，所有贡献必须以此为前提。

## 行为准则

- 所有贡献者必须承诺仅将本项目用于合法授权的安全测试
- 严禁将本项目用于任何未经授权的活动
- 尊重他人，保持专业和友善的沟通
- 保护漏洞细节，避免公开未修复的安全问题

## 合规审查

> **重要：所有贡献内容必须通过合规审查。**

提交 Pull Request 时，请确保：
1. 新增的工具/脚本/字典仅用于授权测试场景
2. 不包含任何针对特定未授权目标的攻击代码
3. 不包含窃取数据、破坏系统或造成实际损害的功能
4. 包含必要的免责声明和安全警告
5. 遵循相关法律法规和行业规范

**不合规的内容将被直接拒绝。**

## 贡献类型

我们欢迎以下类型的贡献：

### 技术字典（Wordlists）
- 新的参数字典（API参数、路径、Cookie名称等）
- 针对特定场景的特殊字典（如JWT payloads、云服务端点等）
- 改进现有字典，增加覆盖率，去除噪音

### 测试脚本
- 新的安全测试辅助脚本
- 现有脚本的Bug修复和功能增强
- 自动化工作流改进

### 漏洞报告模板
- 新增针对特定平台的报告模板
- 现有模板的优化和改进
- 多语言支持

### 文档
- 使用文档的改进和补充
- 技术知识库的更新（绕过技巧、检测方法等）
- 方法论文档的完善
- 错误修正和翻译改进

### 基础设施
- CI/CD 流程改进
- Docker 镜像优化
- 依赖管理和版本更新

## 代码规范

### 通用要求
- 编码使用 UTF-8
- 文件末尾保留一个空行
- 使用有意义的命名
- 关键逻辑必须有注释说明
- 配置项外部化，不要硬编码敏感信息

### Python
- 目标版本：Python 3.8+
- 遵循 PEP 8 编码风格
- 使用类型注解提升可读性
- 函数和类必须包含 docstring
- 使用 `argparse` 或 `click` 处理命令行参数
- 使用 `logging` 模块而非 `print`

```python
# 良好示例
def fuzz_parameter(url: str, param: str, payloads: list[str]) -> dict:
    """
    对指定参数进行fuzz测试

    Args:
        url: 目标URL
        param: 参数名
        payloads: 测试payload列表

    Returns:
        dict: {payload: response_status} 格式的结果字典
    """
    results = {}
    for payload in payloads:
        # 发送请求并记录响应状态
        try:
            response = requests.get(url, params={param: payload}, timeout=10)
            results[payload] = response.status_code
        except requests.RequestException as e:
            logging.warning(f"请求失败: {e}")
    return results
```

### Shell脚本
- 使用 `#!/bin/bash` 作为 shebang
- 使用 `set -euo pipefail` 开启严格模式
- 使用函数组织逻辑
- 所有变量引用使用 `${var}` 形式
- 使用 `[[ ]]` 而非 `[ ]` 进行条件测试

```bash
#!/bin/bash
set -euo pipefail

validate_url() {
    local url="$1"
    if [[ ! "$url" =~ ^https?:// ]]; then
        echo "错误：无效的URL格式" >&2
        return 1
    fi
}
```

### 字典文件（Wordlists）
- 每行一个条目
- 移除重复项
- 按字母顺序排序（特定场景可另议）
- 注释行以 `#` 开头
- 文件名使用小写字母和下划线

## Pull Request 流程

### 基本流程

1. **Fork 仓库** — 点击 GitHub 上的 Fork 按钮
2. **创建分支** — 从 main 分支创建功能分支
   ```bash
   git checkout -b feature/your-feature-name
   ```
3. **提交更改** — 使用清晰的提交信息
   ```bash
   git commit -m "feat: 添加XX参数字典"
   ```
4. **推送到远程**
   ```bash
   git push origin feature/your-feature-name
   ```
5. **创建 Pull Request** — 在 GitHub 上创建 PR

### PR 规范

**标题格式：**

- `feat:` — 新功能或新字典
- `fix:` — Bug 修复
- `docs:` — 文档变更
- `style:` — 代码风格调整（不影响功能）
- `refactor:` — 代码重构
- `test:` — 测试相关
- `chore:` — 构建/依赖等杂项

例如：`feat: 添加Cloudflare防护绕过参数字典`

**PR描述应包含：**

1. **变更摘要** — 简要说明改了些什么
2. **动机和背景** — 为什么需要这个变更
3. **影响范围** — 可能影响哪些部分
4. **测试情况** — 做了哪些测试
5. **合规声明** — 确认内容符合合规要求

```markdown
## 变更摘要
[简要描述变更内容]

## 动机
[说明为什么需要这个变更]

## 影响范围
[列举可能受影响的文件或功能]

## 测试
- [ ] 本地测试通过
- [ ] 现有测试不受影响

## 合规声明
- [ ] 我确认此贡献仅用于授权安全测试
- [ ] 代码/字典不包含针对特定未授权目标的攻击代码
- [ ] 不包含可能造成实际损害的功能
```

### PR 合并前检查清单

- [ ] 代码通过所有自动化测试（CI）
- [ ] 字典文件无重复项
- [ ] 脚本语法正确
- [ ] 文档已更新（如适用）
- [ ] 无敏感信息泄露（凭据、Token、IP等）
- [ ] 已添加必要的安全警告和免责声明

## 开发环境设置

### 方式一：本地环境

```bash
# 克隆仓库
git clone https://github.com/laogongcy-del/bughunter-toolkit.git
cd bughunter-toolkit

# 安装依赖
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 方式二：Docker

```bash
# 构建镜像
docker-compose build

# 启动环境
docker-compose run toolkit
```

## 问题报告

发现 Bug 或有改进建议？请通过 GitHub Issues 提交：

1. 搜索现有 Issues 避免重复
2. 使用明确的标题
3. 附上：
   - 环境信息（OS、Python版本等）
   - 复现步骤
   - 期望行为与实际行为
   - 相关日志或截图

## 安全披露

如果发现本项目本身存在安全漏洞，**请不要公开提交 Issue**。请通过以下方式私下联系维护者：

- 发送邮件至：[维护者邮箱]
- 在仓库中创建安全公告（Security Advisory）

## 许可

贡献即表示你同意你的贡献将遵循本项目的开源许可证进行分发。

---

**再次强调：本项目仅供授权的安全测试使用。任何未经授权的使用均违反了本项目的目的和宗旨。请遵守法律法规，负责任地进行安全研究。**
