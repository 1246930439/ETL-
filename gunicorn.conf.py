# Gunicorn配置文件
# 部署时请复制到 /var/www/scheduler/gunicorn.conf.py

# 绑定地址和端口
bind = "127.0.0.1:8000"

# 工作进程数 (通常为 CPU核心数 * 2 + 1)
workers = 4

# 工作进程类型 (sync, eventlet, gevent, tornado, etc.)
worker_class = "sync"

# 每个工作进程的连接数
worker_connections = 1000

# 每个工作进程处理的最大请求数 (重启工作进程以防止内存泄漏)
max_requests = 1000

# 添加随机性到max_requests
max_requests_jitter = 100

# 请求超时时间(秒)
timeout = 30

# 保持连接时间(秒)
keepalive = 2

# 预加载应用代码
preload_app = True

# 运行用户和组
user = "www-data"
group = "www-data"

# 临时上传目录
tmp_upload_dir = None

# 日志文件路径
logfile = "/var/log/scheduler/gunicorn.log"

# 日志级别
loglevel = "info"

# 访问日志格式
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# 进程名称
proc_name = "scheduler"

# 进程ID文件路径
pidfile = "/var/run/scheduler/scheduler.pid"

# 守护进程模式
daemon = False

# 临时工作目录
tmpdir = "/tmp"

# 启动钩子
def on_starting(server):
    server.log.info("Server is starting...")

def when_ready(server):
    server.log.info("Server is ready.")

def on_reload(server):
    server.log.info("Server is reloading...")

def worker_int(worker):
    worker.log.info("Worker received INT or QUIT signal")

def pre_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_fork(server, worker):
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def post_worker_init(worker):
    worker.log.info("Worker initialized (pid: %s)", worker.pid)

def worker_exit(server, worker):
    server.log.info("Worker exiting (pid: %s)", worker.pid)

def child_exit(server, worker):
    server.log.info("Child worker exited (pid: %s)", worker.pid)