#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import time
import sys
import os

def start_server():
    """启动服务器并保持运行"""
    print("正在启动服务器...")
    
    # 切换到脚本所在目录
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    
    # 启动服务器进程
    process = subprocess.Popen([sys.executable, "web_scheduler.py"], 
                              stdout=subprocess.PIPE, 
                              stderr=subprocess.STDOUT,
                              universal_newlines=True)
    
    print("服务器已启动，进程ID:", process.pid)
    print("等待服务器初始化...")
    
    # 等待服务器启动
    time.sleep(3)
    
    print("服务器应该已经启动在 http://127.0.0.1:5000")
    print("请在浏览器中打开 test_api.html 进行测试")
    print("按 Ctrl+C 停止服务器")
    
    try:
        # 实时输出服务器日志
        for line in process.stdout:
            print(line.rstrip())
    except KeyboardInterrupt:
        print("\n正在停止服务器...")
        process.terminate()
        process.wait()
        print("服务器已停止")

if __name__ == "__main__":
    start_server()