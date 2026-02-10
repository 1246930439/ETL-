## 项目概述

调度工具平台V1.0是一个基于Flask的Web应用，提供数据库监控、SQL脚本执行、定时任务调度和邮件通知等功能。

## 系统要求

- 操作系统：Linux (推荐Ubuntu 20.04+)
- Python版本：Python 3.8+
- 内存：至少2GB RAM
- 磁盘空间：至少5GB可用空间
- 网络：稳定的互联网连接

## 部署步骤

### 1. 服务器准备

#### 1.1 更新系统

```bash
sudo apt update && sudo apt upgrade -y
```

#### 1.2 配置软件源（可选，解决软件包下载问题）

如果遇到软件包下载失败（如404错误），可以配置官方软件源：

```bash
# 备份原有软件源
sudo cp /etc/apt/sources.list /etc/apt/sources.list.backup

# 配置官方软件源（根据您的Ubuntu版本选择）
# Ubuntu 22.04 LTS (Jammy)
cat << EOF | sudo tee /etc/apt/sources.list
deb http://archive.ubuntu.com/ubuntu/ jammy main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ jammy-updates main restricted universe multiverse
deb http://archive.ubuntu.com/ubuntu/ jammy-backports main restricted universe multiverse
deb http://security.ubuntu.com/ubuntu/ jammy-security main restricted universe multiverse
EOF

# 更新软件源
sudo apt update
```

#### 1.3 安装必要的系统依赖

```bash
sudo apt install -y python3 python3-pip python3-venv git nginx supervisor
```

如果安装过程中遇到错误，可以尝试以下解决方法：

```bash
# 方法1：修复可能的依赖问题
sudo apt --fix-missing install

# 方法2：清理软件包缓存
sudo apt clean
sudo apt autoclean
sudo apt autoremove

# 方法3：重新更新软件源
sudo apt update

# 方法4：单独安装有问题的软件包
sudo apt install -y python3-venv --fix-missing
```

#### 1.4 验证系统依赖安装

项目中提供了系统依赖检查脚本 `check_system_deps.sh`，用于验证所有必要的系统依赖是否已正确安装：

```bash
# 上传检查脚本到服务器
scp check_system_deps.sh user@server:/tmp/

# 在服务器上执行检查
chmod +x /tmp/check_system_deps.sh
sudo /tmp/check_system_deps.sh
```

检查脚本会验证以下内容：

- 基本命令是否可用（python3, pip3, git, nginx, supervisorctl）
- 相关软件包是否已安装
- Python venv模块是否可用
- 服务状态（Nginx和Supervisor）
- 目录和权限
- 网络连接状态
- 系统资源使用情况

如果检查脚本显示所有项目都是 [✓] 绿色勾号，则表示系统依赖已正确安装。如果有 [✗] 红色叉号，请根据提示安装缺失的依赖。

### 2. 项目部署

#### 2.1 创建项目目录

```bash
sudo mkdir -p /var/www/scheduler
sudo chown -R $USER:$USER /var/www/scheduler
cd /var/www/scheduler
```

#### 2.2 上传项目文件

**必须上传的核心文件列表：**

1. **Python应用文件**
   - `web_scheduler.py` - 主应用文件
   - `start_server.py` - 服务器启动脚本

2. **依赖文件**
   - `requirements.txt` - Python依赖包列表

3. **模板文件** (templates目录)
   - `templates/base.html` - 基础模板
   - `templates/login.html` - 登录页面
   - `templates/index.html` - 主页面
   - `templates/alerts.html` - 告警页面
   - `templates/notification_logs.html` - 通知日志页面
   - `templates/users.html` - 用户管理页面
   - `templates/db_config.html` - 数据库配置页面
   - `templates/email_configs.html` - 邮件配置页面
   - `templates/sql_scripts.html` - SQL脚本页面

4. **静态文件** (static目录)
   - `static/style.css` - 自定义样式文件
   - `static/bootstrap.min.css` - Bootstrap 5.3.0 CSS框架
   - `static/bootstrap-icons.css` - Bootstrap Icons图标库
   - `static/fonts/bootstrap-icons.woff` - Bootstrap Icons字体文件
   - `static/fonts/bootstrap-icons.woff2` - Bootstrap Icons字体文件(woff2格式)

5. **工具脚本** (可选)
   - `uploads/excel_to_db.py` - Excel导入数据库工具
   - `excel_to_db/excel_to_db.py` - Excel导入工具主文件
   - `excel_to_db/README.md` - Excel工具说明文档

6. **文档文件** (可选)
   - `部署指南.md` - 本部署文档
   - `project_overview.md` - 项目概述
   - `postman_api_guide.md` - API测试指南

**不需要上传的文件：**

- `.venv/` - Python虚拟环境目录
- `__pycache__/` - Python缓存目录
- `.idea/` - IDE配置目录
- `scheduler.db` - 本地SQLite数据库
- `scheduler.log` - 本地日志文件
- `flask_session/` - Flask会话文件
- `cookie.txt` - Cookie文件
- `start_server.bat` 和 `start_server.ps1` - Windows启动脚本
