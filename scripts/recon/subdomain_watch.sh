#!/bin/bash
# ============================================================================
# BugBounty Toolkit — 子域名监控脚本
# ============================================================================
# 用途: 定期检查目标域名是否有新增子域名（用于持续监控）
# 使用方法:
#   首次运行: bash subdomain_watch.sh init example.com
#   后续检查: bash subdomain_watch.sh check example.com
# 注意: 仅用于已获得明确授权的安全测试！
# ============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# 配置
WATCH_DIR="output/subdomain_watch"

# ============================================
# 合规声明
# ============================================
echo -e "${RED}[!] 本工具仅用于已获得明确授权的安全测试${NC}"
echo -e "${RED}[!] 使用者需自行确保拥有目标系统的测试授权${NC}"

if [[ $# -lt 2 ]]; then
    echo "用法: bash subdomain_watch.sh {init|check} domain.com"
    exit 1
fi

ACTION="$1"
DOMAIN="$2"

case "$ACTION" in
    init)
        echo -e "${BLUE}[*] 初始化子域名基线: $DOMAIN${NC}"

        if ! command -v subfinder &>/dev/null; then
            echo -e "${RED}[!] 需要安装 subfinder${NC}"
            exit 1
        fi

        mkdir -p "$WATCH_DIR"

        subfinder -d "$DOMAIN" -silent 2>/dev/null | sort -u > "$WATCH_DIR/${DOMAIN}_baseline.txt"

        echo -e "${GREEN}[+] 基线已保存: $WATCH_DIR/${DOMAIN}_baseline.txt${NC}"
        echo -e "${GREEN}[+] 共收集 $(wc -l < "$WATCH_DIR/${DOMAIN}_baseline.txt") 个子域名${NC}"
        echo -e "${GREEN}[+] 下次运行: bash subdomain_watch.sh check $DOMAIN${NC}"
        ;;

    check)
        echo -e "${BLUE}[*] 检查子域名变化: $DOMAIN${NC}"

        if [[ ! -f "$WATCH_DIR/${DOMAIN}_baseline.txt" ]]; then
            echo -e "${RED}[!] 基线文件不存在，请先运行 init${NC}"
            echo -e "${YELLOW}   bash subdomain_watch.sh init $DOMAIN${NC}"
            exit 1
        fi

        if ! command -v subfinder &>/dev/null; then
            echo -e "${RED}[!] 需要安装 subfinder${NC}"
            exit 1
        fi

        # 收集当前子域名
        subfinder -d "$DOMAIN" -silent 2>/dev/null | sort -u > "$WATCH_DIR/${DOMAIN}_current.txt"

        # 对比差异
        NEW_SUBS=$(comm -13 "$WATCH_DIR/${DOMAIN}_baseline.txt" "$WATCH_DIR/${DOMAIN}_current.txt" 2>/dev/null || true)
        LOST_SUBS=$(comm -23 "$WATCH_DIR/${DOMAIN}_baseline.txt" "$WATCH_DIR/${DOMAIN}_current.txt" 2>/dev/null || true)

        if [[ -n "$NEW_SUBS" ]]; then
            echo -e "${GREEN}[+] 发现新增子域名:${NC}"
            echo "$NEW_SUBS" | tee "$WATCH_DIR/${DOMAIN}_new.txt"
        else
            echo -e "${YELLOW}[!] 无新增子域名${NC}"
        fi

        if [[ -n "$LOST_SUBS" ]]; then
            echo -e "${YELLOW}[!] 以下子域名已消失:${NC}"
            echo "$LOST_SUBS"
        fi

        echo -e "${BLUE}[*] 上次: $(wc -l < "$WATCH_DIR/${DOMAIN}_baseline.txt") 个${NC}"
        echo -e "${BLUE}[*] 当前: $(wc -l < "$WATCH_DIR/${DOMAIN}_current.txt") 个${NC}"

        # 可选：更新基线
        echo -e "${YELLOW}[?] 是否更新基线文件？(y/n):${NC}"
        read -r UPDATE
        if [[ "$UPDATE" == "y" ]]; then
            cp "$WATCH_DIR/${DOMAIN}_current.txt" "$WATCH_DIR/${DOMAIN}_baseline.txt"
            echo -e "${GREEN}[+] 基线已更新${NC}"
        fi
        ;;

    *)
        echo "用法: bash subdomain_watch.sh {init|check} domain.com"
        exit 1
        ;;
esac
