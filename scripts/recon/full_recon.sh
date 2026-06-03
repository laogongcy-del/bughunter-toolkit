#!/bin/bash
# ============================================================================
# BugBounty Toolkit — 全流程信息收集脚本
# ============================================================================
# 用途: 对授权目标进行信息收集（子域名→存活检测→历史URL→端口扫描）
# 使用方法: bash full_recon.sh example.com
# 注意: 仅用于已获得明确授权的安全测试！
# ============================================================================

set -euo pipefail

# ============================================
# 颜色定义
# ============================================
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# ============================================
# 合规声明 — 每次执行必须确认
# ============================================
echo -e "${RED}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║            ⚠️  授权确认 / AUTHORIZATION CHECK                ║"
echo "╠═══════════════════════════════════════════════════════════════╣"
echo "║ 本工具仅用于已获得明确书面授权的安全测试                      ║"
echo "║ This tool is for AUTHORIZED testing ONLY                     ║"
echo "║                                                              ║"
echo "║ 使用者需自行确保拥有目标系统的测试授权                        ║"
echo "║ 任何非法使用与作者无关                                        ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

echo -e "${YELLOW}目标:${NC} $1"
echo -e "${YELLOW}[!] 你是否已获得 $1 的书面测试授权？${NC}"
echo -e "输入 ${GREEN}yes${NC} 继续，${RED}no${NC} 退出: "
read -r CONFIRM

if [[ "$CONFIRM" != "yes" && "$CONFIRM" != "y" ]]; then
    echo -e "${RED}[!] 未确认授权，脚本退出。${NC}"
    exit 1
fi

echo -e "${GREEN}[+] 授权已确认，开始信息收集...${NC}"

# ============================================
# 配置
# ============================================
DOMAIN="$1"
OUTPUT_DIR="output/${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTPUT_DIR"
RATE_LIMIT_MS=500  # 请求间隔（毫秒），避免对目标造成压力

echo -e "${BLUE}[*] 输出目录: ${OUTPUT_DIR}${NC}"
echo -e "${BLUE}[*] 速率限制: ${RATE_LIMIT_MS}ms/请求${NC}"

# ============================================
# 阶段1: 子域名收集（被动模式，不发请求到目标）
# ============================================
echo -e "${CYAN}[阶段 1/5] 子域名被动收集...${NC}"

if command -v subfinder &>/dev/null; then
    echo "[*] 运行 subfinder..."
    subfinder -d "$DOMAIN" -silent 2>/dev/null | tee "$OUTPUT_DIR/subfinder_subs.txt"
    echo "[+] subfinder 完成: $(wc -l < "$OUTPUT_DIR/subfinder_subs.txt") 个子域名"
else
    echo -e "${YELLOW}[!] subfinder 未安装，跳过${NC}"
fi

# ============================================
# 阶段2: 存活检测（httpx，只发HEAD请求）
# ============================================
echo -e "${CYAN}[阶段 2/5] 存活检测...${NC}"

if command -v httpx &>/dev/null; then
    echo "[*] 运行 httpx..."
    SUB_FILE="$OUTPUT_DIR/subfinder_subs.txt"
    if [[ -f "$SUB_FILE" && -s "$SUB_FILE" ]]; then
        httpx -l "$SUB_FILE" -silent -status-code -title -tech-detect \
            -o "$OUTPUT_DIR/alive_hosts.txt" 2>/dev/null
        echo "[+] httpx 完成: $(wc -l < "$OUTPUT_DIR/alive_hosts.txt") 个存活目标"
    else
        echo -e "${YELLOW}[!] 无子域名输入，跳过${NC}"
    fi
else
    echo -e "${YELLOW}[!] httpx 未安装，跳过${NC}"
fi

# ============================================
# 阶段3: 历史URL收集（gau，公共数据源）
# ============================================
echo -e "${CYAN}[阶段 3/5] 历史URL收集 (Wayback Machine)...${NC}"

if command -v gau &>/dev/null; then
    echo "[*] 运行 gau..."
    gau "$DOMAIN" 2>/dev/null | tee "$OUTPUT_DIR/historical_urls.txt"
    echo "[+] gau 完成: $(wc -l < "$OUTPUT_DIR/historical_urls.txt") 个历史URL"

    # 按文件类型分类
    echo "[*] 分类历史URL..."
    grep -E '\.js$' "$OUTPUT_DIR/historical_urls.txt" > "$OUTPUT_DIR/js_files.txt" 2>/dev/null || true
    grep -E '\.json$' "$OUTPUT_DIR/historical_urls.txt" > "$OUTPUT_DIR/json_endpoints.txt" 2>/dev/null || true
    grep -E 'api/' "$OUTPUT_DIR/historical_urls.txt" > "$OUTPUT_DIR/api_endpoints.txt" 2>/dev/null || true
    grep -E 'admin|dashboard|manage' "$OUTPUT_DIR/historical_urls.txt" > "$OUTPUT_DIR/admin_paths.txt" 2>/dev/null || true
else
    echo -e "${YELLOW}[!] gau 未安装，跳过${NC}"
fi

# ============================================
# 阶段4: 技术栈识别
# ============================================
echo -e "${CYAN}[阶段 4/5] 首页分析...${NC}"

if [[ -f "$OUTPUT_DIR/alive_hosts.txt" && -s "$OUTPUT_DIR/alive_hosts.txt" ]]; then
    MAIN_URL=$(head -1 "$OUTPUT_DIR/alive_hosts.txt" | awk '{print $1}')
    echo "[*] 分析首页: $MAIN_URL"

    # 获取响应头
    curl -sI -L --max-time 10 "$MAIN_URL" > "$OUTPUT_DIR/response_headers.txt" 2>/dev/null || true
    echo "[+] 响应头已保存"

    # 获取首页HTML概览
    curl -sL --max-time 10 "$MAIN_URL" 2>/dev/null | head -100 > "$OUTPUT_DIR/index_preview.html" || true
    echo "[+] 首页HTML已保存（前100行）"
else
    echo -e "${YELLOW}[!] 无存活目标，首页分析跳过${NC}"
fi

# ============================================
# 阶段5: 工具版本记录
# ============================================
echo -e "${CYAN}[阶段 5/5] 生成报告摘要...${NC}"

{
    echo "=========================================="
    echo " BugBounty Toolkit — Recon Report"
    echo " 目标: $DOMAIN"
    echo " 时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "=========================================="
    echo ""
    echo "--- 子域名 ---"
    [[ -f "$OUTPUT_DIR/subfinder_subs.txt" ]] && echo "子域名总数: $(wc -l < "$OUTPUT_DIR/subfinder_subs.txt")"
    echo ""
    echo "--- 存活目标 ---"
    [[ -f "$OUTPUT_DIR/alive_hosts.txt" ]] && wc -l < "$OUTPUT_DIR/alive_hosts.txt" || echo "0"
    echo ""
    echo "--- 历史URL ---"
    [[ -f "$OUTPUT_DIR/historical_urls.txt" ]] && echo "URL总数: $(wc -l < "$OUTPUT_DIR/historical_urls.txt")"
    [[ -f "$OUTPUT_DIR/api_endpoints.txt" ]] && echo "API端点: $(wc -l < "$OUTPUT_DIR/api_endpoints.txt")"
    [[ -f "$OUTPUT_DIR/js_files.txt" ]] && echo "JS文件: $(wc -l < "$OUTPUT_DIR/js_files.txt")"
    [[ -f "$OUTPUT_DIR/admin_paths.txt" ]] && echo "管理路径: $(wc -l < "$OUTPUT_DIR/admin_paths.txt")"
    echo ""
    echo "--- 响应头 ---"
    [[ -f "$OUTPUT_DIR/response_headers.txt" ]] && cat "$OUTPUT_DIR/response_headers.txt"
} > "$OUTPUT_DIR/recon_summary.txt"

echo -e "${GREEN}"
echo "============================================"
echo " ✅ 信息收集完成！"
echo " 输出目录: $OUTPUT_DIR"
echo " 报告摘要: $OUTPUT_DIR/recon_summary.txt"
echo "============================================"
echo -e "${NC}"

# 清理临时文件（可选）
echo -e "${YELLOW}[!] 是否删除临时文件？仅保留摘要报告 (y/n):${NC}"
read -r CLEANUP
if [[ "$CLEANUP" == "y" ]]; then
    rm -f "$OUTPUT_DIR/subfinder_subs.txt" 2>/dev/null || true
    echo "[+] 临时文件已清理"
    echo -e "${GREEN}[+] 最终报告: $OUTPUT_DIR/recon_summary.txt${NC}"
fi
