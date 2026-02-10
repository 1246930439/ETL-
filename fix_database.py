#!/usr/bin/env python3
"""
修复数据库表结构，添加缺失的字段
"""

import sqlite3
import os

# 数据库文件路径
DB_PATH = 'scheduler.db'

def fix_database():
    """修复数据库表结构，添加缺失的字段"""
    if not os.path.exists(DB_PATH):
        print(f"错误: 数据库文件 {DB_PATH} 不存在")
        return False
    
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        
        # 检查tasks表是否有cron_expression字段
        cursor.execute("PRAGMA table_info(tasks)")
        columns = [column[1] for column in cursor.fetchall()]
        
        print(f"当前tasks表包含的字段: {columns}")
        
        # 如果不存在cron_expression字段，则添加
        if 'cron_expression' not in columns:
            print("添加cron_expression字段到tasks表...")
            cursor.execute("ALTER TABLE tasks ADD COLUMN cron_expression TEXT")
            print("cron_expression字段添加成功")
        else:
            print("cron_expression字段已存在")
        
        # 提交更改
        conn.commit()
        conn.close()
        
        print("数据库结构修复完成")
        return True
        
    except sqlite3.Error as e:
        print(f"数据库错误: {e}")
        return False
    except Exception as e:
        print(f"未知错误: {e}")
        return False

if __name__ == "__main__":
    if fix_database():
        print("修复成功，请重启应用程序")
    else:
        print("修复失败，请检查错误信息")