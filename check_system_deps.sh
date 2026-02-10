#!/bin/bash

# 系统依赖检查脚本
# 用于验证部署所需的系统依赖是否已正确安装

echo "=========================================="
echo "调度工具平台V1.0 - 系统依赖检查脚本"
echo "=========================================="
echo ""

# 颜色定义
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查函数
check_command() {
    if command -v $1 &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} $1 已安装"
        return 0
    else
        echo -e "${RED}[✗]${NC} $1 未安装"
        return 1
    fi
}

check_package() {
    if dpkg -l | grep -q "^ii  $1 "; then
        echo -e "${GREEN}[✓]${NC} $1 已安装"
        return 0
    else
        echo -e "${RED}[✗]${NC} $1 未安装"
        return 1
    fi
}

check_python_module() {
    if python3 -c "import $1" &> /dev/null; then
        echo -e "${GREEN}[✓]${NC} Python模块 $1 已安装"
        return 0
    else
        echo -e "${RED}[✗]${NC} Python模块 $1 未安装"
        return 1
    fi
}

# 检查系统信息
echo "1. 系统信息检查"
echo "----------------"
echo "操作系统: $(lsb_release -d -s 2>/dev/null || echo '无法确定')"
echo "内核版本: $(uname -r)"
echo "架构: $(uname -m)"
echo ""

# 检查基本命令
echo "2. 基本命令检查"
echo "----------------"
check_command "python3"
check_command "pip3"
check_command "git"
check_command "nginx"
check_command "supervisorctl"
echo ""

# 检查软件包
echo "3. 软件包检查"
echo "--------------"
check_package "python3"
check_package "python3-pip"
check_package "python3-venv"
check_package "git"
check_package "nginx"
check_package "supervisor"
echo ""

# 检查Python venv模块
echo "4. Python venv模块检查"
echo "----------------------"
check_python_module "venv"
echo ""

# 检查服务状态
echo "5. 服务状态检查"
echo "--------------"
if systemctl is-active --quiet nginx; then
    echo -e "${GREEN}[✓]${NC} Nginx 服务正在运行"
else
    echo -e "${YELLOW}[!]${NC} Nginx 服务未运行 (这是正常的，因为尚未配置)"
fi

if systemctl is-enabled --quiet nginx; then
    echo -e "${GREEN}[✓]${NC} Nginx 服务已启用"
else
    echo -e "${YELLOW}[!]${NC} Nginx 服务未启用 (这是正常的，因为尚未配置)"
fi

if systemctl is-active --quiet supervisor; then
    echo -e "${GREEN}[✓]${NC} Supervisor 服务正在运行"
else
    echo -e "${YELLOW}[!]${NC} Supervisor 服务未运行 (这是正常的，因为尚未配置)"
fi

if systemctl is-enabled --quiet supervisor; then
    echo -e "${GREEN}[✓]${NC} Supervisor 服务已启用"
else
    echo -e "${YELLOW}[!]${NC} Supervisor 服务未启用 (这是正常的，因为尚未配置)"
fi
echo ""

# 检查目录和权限
echo "6. 目录和权限检查"
echo "------------------"
if [ -d "/var/www" ]; then
    echo -e "${GREEN}[✓]${NC} /var/www 目录存在"
else
    echo -e "${RED}[✗]${NC} /var/www 目录不存在"
fi

if [ -d "/var/log" ]; then
    echo -e "${GREEN}[✓]${NC} /var/log 目录存在"
else
    echo -e "${RED}[✗]${NC} /var/log 目录不存在"
fi

if [ -w "/var/www" ]; then
    echo -e "${GREEN}[✓]${NC} /var/www 目录可写"
else
    echo -e "${YELLOW}[!]${NC} /var/www 目录不可写 (可能需要sudo权限)"
fi
echo ""

# 检查网络连接
echo "7. 网络连接检查"
echo "----------------"
if ping -c 1 archive.ubuntu.com &> /dev/null; then
    echo -e "${GREEN}[✓]${NC} 可以连接到Ubuntu软件源"
else
    echo -e "${RED}[✗]${NC} 无法连接到Ubuntu软件源"
fi

if ping -c 1 pypi.org &> /dev/null; then
    echo -e "${GREEN}[✓]${NC} 可以连接到Python包索引"
else
    echo -e "${RED}[✗]${NC} 无法连接到Python包索引"
fi
echo ""

# 检查系统资源
echo "8. 系统资源检查"
echo "----------------"
MEMORY=$(free -m | awk 'NR==2{printf "%.1fGB/%.1fGB (%.1f%%)\n", $3/1024, $2/1024, $3*100/$2 }')
echo "内存使用: $MEMORY"

DISK=$(df -h / | awk 'NR==2{printf "%s/%s (%s)\n", $3, $2, $5}')
echo "磁盘使用: $DISK"

CPU=$(top -bn1 | grep "Cpu(s)" | sed "s/.*, *\([0-9.]*\)%* id.*/\1/" | sed "s/^100//" | awk '{print 100 - $1"%"}')
echo "CPU使用: $CPU"
echo ""

# 总结
echo "9. 安装建议"
echo "------------"
echo "如果所有检查项都显示 [✓]，则系统依赖已正确安装。"
echo "如果有 [✗] 项，请运行以下命令安装缺失的依赖："
echo ""
echo "sudo apt update"
echo "sudo apt install -y python3 python3-pip python3-venv git nginx supervisor"
echo ""
echo "如果有 [!] 项，这通常是正常的，因为相关服务尚未配置。"
echo ""

echo "=========================================="
echo "检查完成"
echo "=========================================="