# 调度工具平台云服务器部署指南

本文档详细介绍如何将调度工具平台部署到云服务器上，并配置连接远程数据库。

## 系统要求

- Python 3.7 或更高版本
- pip 包管理器
- 云服务器（推荐配置：1核CPU，1GB内存，Ubuntu 20.04或CentOS 7以上）
- 可访问的远程数据库（MySQL、PostgreSQL或SQLite）

## 部署步骤

### 1. 准备云服务器

1. 选择云服务提供商（如阿里云、腾讯云、AWS等）
2. 创建云服务器实例
3. 确保安全组规则开放以下端口：
   - SSH: 22 (用于远程连接)
   - HTTP: 80 (可选)
   - HTTPS: 443 (可选)
   - 应用端口: 5000 (默认Flask端口)

### 2. 连接云服务器

使用SSH工具连接到云服务器：

```bash
ssh root@your_server_ip
```

### 3. 安装基础环境

```bash
# Ubuntu/Debian系统
sudo apt update
sudo apt install python3 python3-pip git -y

# CentOS/RHEL系统
sudo yum update
sudo yum install python3 python3-pip git -y
```

### 4. 获取项目代码

有两种方式获取项目代码：

#### 方式一：Git克隆（推荐）

```bash
git clone <项目仓库地址>
cd your_project_directory
```

#### 方式二：上传项目文件

如果选择上传文件的方式，需要上传以下文件和目录：

1. **核心代码文件**：
   - `web_scheduler.py` - 主应用文件
   - `excel_to_db.py` - Excel导入数据库脚本

2. **模板文件夹**：
   - `templates/` - 包含所有HTML模板文件
     - `index.html` - 主界面模板
     - `login.html` - 登录界面模板

3. **静态文件夹**：
   - `static/` - 静态资源文件夹
     - `style.css` - 样式表文件

4. **上传文件夹**：
   - `uploads/` - 上传的Python脚本文件存储位置

5. **配置和依赖文件**：
   - `requirements.txt` - Python依赖包列表
   - `scheduler.db` - SQLite数据库文件（如果已有数据）

6. **文档文件**：
   - `README.md` - 项目说明文档
   - `deployment_guide.md` - 部署指南文档
   - `project_overview.md` - 项目概览文档
   - `postman_api_guide.md` - Postman API接口文档

使用FTP/SFTP工具将这些文件上传到云服务器的指定目录中。

### 5. 安装项目依赖

```bash
# 创建虚拟环境（推荐）
python3 -m venv venv
source venv/bin/activate

# 安装依赖包
pip install -r requirements.txt

# 如果需要支持PostgreSQL数据库，还需要安装额外依赖
pip install psycopg2-binary
```

### 6. 配置应用

1. 检查并修改配置文件（如果有）
2. 确保数据库连接信息正确

### 7. 启动应用

#### 方法一：直接运行（测试用途）

```bash
python3 web_scheduler.py
```

#### 方法二：使用Gunicorn（生产环境推荐）

```bash
# 安装Gunicorn
pip install gunicorn

# 启动应用
gunicorn -w 4 -b 0.0.0.0:5000 web_scheduler:app
```

#### 方法三：使用Systemd服务（生产环境推荐）

创建服务文件：
```bash
sudo nano /etc/systemd/system/scheduler.service
```

添加以下内容：
```ini
[Unit]
Description=Scheduler App
After=network.target

[Service]
User=www-data
WorkingDirectory=/path/to/your/project
ExecStart=/path/to/your/project/venv/bin/gunicorn -w 4 -b 0.0.0.0:5000 web_scheduler:app
Restart=always

[Install]
WantedBy=multi-user.target
```

启用并启动服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable scheduler
sudo systemctl start scheduler
```

### 8. 配置反向代理（可选但推荐）

#### 使用Nginx

1. 安装Nginx：
```bash
# Ubuntu/Debian
sudo apt install nginx -y

# CentOS/RHEL
sudo yum install nginx -y
```

2. 创建Nginx配置文件：
```bash
sudo nano /etc/nginx/sites-available/scheduler
```

添加配置：
```nginx
server {
    listen 80;
    server_name your_domain_or_ip;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

3. 启用配置：
```bash
sudo ln -s /etc/nginx/sites-available/scheduler /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### 9. 配置SSL证书（HTTPS，可选但推荐）

使用Let's Encrypt免费SSL证书：

```bash
# 安装Certbot
sudo apt install certbot python3-certbot-nginx -y

# 获取SSL证书
sudo certbot --nginx -d your_domain
```

### 10. 配置远程数据库连接

1. 访问应用界面：http://your_server_ip:5000
2. 使用默认账户登录：
   - 用户名：admin
   - 密码：admin123
3. 在"数据库配置"页面添加远程数据库连接：
   - 选择数据库类型（MySQL、PostgreSQL等）
   - 输入远程数据库主机地址
   - 输入端口号
   - 输入用户名和密码
   - 输入数据库名称
4. 测试连接确保配置正确

### 11. 创建调度任务

1. 在"任务管理"页面创建新的调度任务
2. 选择任务类型（Python脚本或SQL脚本）
3. 配置任务参数
4. 设置调度间隔
5. 保存并启动任务

## 监控和日志

### 查看应用日志

```bash
# 如果使用Systemd
sudo journalctl -u scheduler -f

# 如果直接运行
tail -f scheduler.log
```

### 查看系统资源使用情况

```bash
htop
df -h
free -m
```

## 安全加固建议

1. **修改默认密码**：
   - 登录后立即修改默认管理员密码
   - 定期更换密码

2. **配置防火墙**：
```bash
# Ubuntu/Debian (UFW)
sudo ufw allow ssh
sudo ufw allow 80
sudo ufw allow 443
sudo ufw enable

# CentOS/RHEL (Firewalld)
sudo firewall-cmd --permanent --add-service=ssh
sudo firewall-cmd --permanent --add-service=http
sudo firewall-cmd --permanent --add-service=https
sudo firewall-cmd --reload
```

3. **定期备份**：
   - 定期备份scheduler.db数据库文件
   - 备份重要配置文件

4. **更新系统和软件**：
   - 定期更新操作系统
   - 更新Python包

## 故障排除

### 常见问题及解决方案

1. **应用无法访问**：
   - 检查防火墙设置
   - 检查应用是否正常运行
   - 检查端口是否被占用

2. **数据库连接失败**：
   - 检查数据库服务器是否可访问
   - 检查用户名和密码是否正确
   - 检查数据库是否允许远程连接

3. **任务执行失败**：
   - 检查任务配置是否正确
   - 查看任务执行日志
   - 检查脚本文件是否存在

### 联系支持

如有问题，请联系项目维护人员或查阅相关文档。

## 附录

### 环境变量配置

可以根据需要设置以下环境变量：

```bash
export FLASK_ENV=production
export SECRET_KEY=your_secret_key_here
```

### 性能调优

1. 根据服务器配置调整Gunicorn工作进程数
2. 配置数据库连接池
3. 使用Redis等缓存系统（如需要）