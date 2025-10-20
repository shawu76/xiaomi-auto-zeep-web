#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
自动跑步步数提交系统
包含管理员登录、用户管理、账号管理、额度控制、自动执行功能和日志展示
"""

import os
import sys
import json
import time
import random
import logging
import requests
import sqlite3
import threading
from datetime import datetime, timedelta
from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for
from apscheduler.schedulers.background import BackgroundScheduler
from contextlib import contextmanager
from werkzeug.security import generate_password_hash, check_password_hash


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("step_system.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


app = Flask(__name__)
app.secret_key = os.urandom(24)  # 用于会话加密


DATABASE = 'step_accounts.db'


STEP_RANGES = {
    8: {"min": 6000, "max": 10000},  # 早上8点：6000-10000步
    12: {"min": 8000, "max": 14000},  # 中午12点：8000-14000步
    16: {"min": 10000, "max": 18000},  # 下午4点：10000-18000步
    20: {"min": 12000, "max": 22000},  # 晚上8点：12000-22000步
    22: {"min": 15000, "max": 24000}  # 晚上10点：15000-24000步
}
DEFAULT_STEPS = 24465


BASE_URL = 'https://wzz.wangzouzou.com/motion/api/motion/Xiaomi'


HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.7339.128 Safari/537.36',
    'Accept': 'application/json, text/javascript, */*; q=0.01',
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8',
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
    'Origin': 'https://m.cqzz.top',
    'Referer': 'https://m.cqzz.top/',
    'X-Requested-With': 'XMLHttpRequest'
}



@contextmanager
def db_connection():
    
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row  # 使查询结果可以通过列名访问
    cursor = conn.cursor()
    try:
        yield cursor
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"数据库操作错误: {str(e)}")
        raise
    finally:
        conn.close()


def init_database():
    
    with db_connection() as cursor:
        # 创建管理员表
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS admins (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )
        ''')

       
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            max_accounts INTEGER NOT NULL DEFAULT 5,
            status TEXT DEFAULT 'active',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            last_login TIMESTAMP,
            FOREIGN KEY (created_by) REFERENCES admins (id)
        )
        ''')

        
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS quota_settings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            max_accounts INTEGER NOT NULL DEFAULT 10,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_by INTEGER,
            FOREIGN KEY (updated_by) REFERENCES admins (id)
        )
        ''')

       
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            password TEXT NOT NULL,
            expiry_date DATE NOT NULL,
            custom_steps INTEGER,  -- 自定义步数字段
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,  -- 记录创建者，可以是admin或user
            created_by_type TEXT,  -- 'admin' 或 'user'
            last_run TIMESTAMP,
            status TEXT DEFAULT 'active',
            FOREIGN KEY (created_by) REFERENCES users (id)
        )
        ''')

        
        cursor.execute("PRAGMA table_info(accounts)")
        columns = [column[1] for column in cursor.fetchall()]
        if 'custom_steps' not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN custom_steps INTEGER")
            logger.info("已为accounts表添加custom_steps字段")
        if 'created_by' not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN created_by INTEGER")
            logger.info("已为accounts表添加created_by字段")
        if 'created_by_type' not in columns:
            cursor.execute("ALTER TABLE accounts ADD COLUMN created_by_type TEXT")
            logger.info("已为accounts表添加created_by_type字段")

      
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS run_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_id INTEGER NOT NULL,
            run_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            steps INTEGER,
            result TEXT,
            FOREIGN KEY (account_id) REFERENCES accounts (id)
        )
        ''')

        
        cursor.execute("SELECT COUNT(*) as count FROM admins")
        if cursor.fetchone()['count'] == 0:
            # 默认管理员: admin, 密码: admin123 (首次登录后应修改)
            default_password = generate_password_hash('admin123')
            cursor.execute(
                "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
                ('admin', default_password)
            )
            logger.warning("创建了默认管理员账号: admin, 密码: admin123，请尽快修改密码!")

        
        cursor.execute("SELECT COUNT(*) as count FROM quota_settings")
        if cursor.fetchone()['count'] == 0:
            cursor.execute(
                "INSERT INTO quota_settings (max_accounts) VALUES (?)",
                (10,)  
            )
            logger.info("创建了默认额度设置: 最大账号数10个")

    logger.info("数据库初始化完成")



def add_admin(username, password):
    """添加新管理员"""
    password_hash = generate_password_hash(password)
    with db_connection() as cursor:
        cursor.execute(
            "INSERT INTO admins (username, password_hash) VALUES (?, ?)",
            (username, password_hash)
        )
        return cursor.lastrowid


def validate_admin(username, password):
    
    with db_connection() as cursor:
        cursor.execute(
            "SELECT * FROM admins WHERE username = ?",
            (username,)
        )
        admin = cursor.fetchone()
        if admin and check_password_hash(admin['password_hash'], password):
            
            cursor.execute(
                "UPDATE admins SET last_login = ? WHERE id = ?",
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), admin['id'])
            )
            return dict(admin)
        return None


def change_admin_password(admin_id, new_password):
   
    password_hash = generate_password_hash(new_password)
    with db_connection() as cursor:
        cursor.execute(
            "UPDATE admins SET password_hash = ? WHERE id = ?",
            (password_hash, admin_id)
        )
        return cursor.rowcount > 0



def add_user(username, password, max_accounts, created_by):
    
    password_hash = generate_password_hash(password)
    with db_connection() as cursor:
        cursor.execute(
            """INSERT INTO users 
               (username, password_hash, max_accounts, created_by) 
               VALUES (?, ?, ?, ?)""",
            (username, password_hash, max_accounts, created_by)
        )
        return cursor.lastrowid


def get_all_users():
  
    with db_connection() as cursor:
        cursor.execute("SELECT * FROM users ORDER BY created_at DESC")
        return [dict(row) for row in cursor.fetchall()]


def get_user(user_id):
    
    with db_connection() as cursor:
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user = cursor.fetchone()
        return dict(user) if user else None


def update_user(user_id, data):
   
    with db_connection() as cursor:
        # 构建更新字段
        fields = []
        values = []

        if 'password' in data and data['password']:
            fields.append("password_hash = ?")
            values.append(generate_password_hash(data['password']))

        if 'max_accounts' in data:
            fields.append("max_accounts = ?")
            values.append(data['max_accounts'])

        if 'status' in data:
            fields.append("status = ?")
            values.append(data['status'])

        if not fields:
            return False

        values.append(user_id)
        query = f"UPDATE users SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(query, tuple(values))
        return cursor.rowcount > 0


def delete_user(user_id):
    
    with db_connection() as cursor:
       
        cursor.execute("SELECT id FROM accounts WHERE created_by = ? AND created_by_type = 'user'", (user_id,))
        account_ids = [row['id'] for row in cursor.fetchall()]

        if account_ids:
            placeholders = ', '.join('?' for _ in account_ids)
            cursor.execute(f"DELETE FROM run_logs WHERE account_id IN ({placeholders})", account_ids)
            cursor.execute(f"DELETE FROM accounts WHERE id IN ({placeholders})", account_ids)

       
        cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
        return cursor.rowcount > 0


def validate_user(username, password):
    
    with db_connection() as cursor:
        cursor.execute(
            "SELECT * FROM users WHERE username = ? AND status = 'active'",
            (username,)
        )
        user = cursor.fetchone()
        if user and check_password_hash(user['password_hash'], password):
            
            cursor.execute(
                "UPDATE users SET last_login = ? WHERE id = ?",
                (datetime.now().strftime('%Y-%m-%d %H:%M:%S'), user['id'])
            )
            return dict(user)
        return None



def get_quota_settings():
    
    with db_connection() as cursor:
        cursor.execute("SELECT * FROM quota_settings ORDER BY updated_at DESC LIMIT 1")
        settings = cursor.fetchone()
        return dict(settings) if settings else {"max_accounts": 10}


def update_quota_settings(max_accounts, admin_id):
    
    with db_connection() as cursor:
        cursor.execute(
            "INSERT INTO quota_settings (max_accounts, updated_by) VALUES (?, ?)",
            (max_accounts, admin_id)
        )
        return cursor.lastrowid


def get_account_count(created_by=None, created_by_type=None):
    
    with db_connection() as cursor:
        if created_by and created_by_type:
            cursor.execute(
                "SELECT COUNT(*) as count FROM accounts WHERE created_by = ? AND created_by_type = ?",
                (created_by, created_by_type)
            )
        else:
            cursor.execute("SELECT COUNT(*) as count FROM accounts")
        return cursor.fetchone()['count']


def is_within_quota(created_by=None, created_by_type=None):
    
    if created_by and created_by_type == 'user':
        
        user = get_user(created_by)
        if not user:
            return False
        max_accounts = user['max_accounts']
    else:
        
        max_accounts = get_quota_settings()['max_accounts']

    current_count = get_account_count(created_by, created_by_type)
    return current_count < max_accounts



def add_account(username, password, expiry_date, custom_steps=None, created_by=None, created_by_type=None):
    """添加新账号"""
    
    if not is_within_quota(created_by, created_by_type):
        if created_by and created_by_type == 'user':
            user = get_user(created_by)
            raise Exception(f"已达到最大账号数量限制({user['max_accounts']}个)")
        else:
            quota = get_quota_settings()
            raise Exception(f"已达到最大账号数量限制({quota['max_accounts']}个)")

    with db_connection() as cursor:
        cursor.execute(
            """INSERT INTO accounts 
               (username, password, expiry_date, custom_steps, created_by, created_by_type) 
               VALUES (?, ?, ?, ?, ?, ?)""",
            (username, password, expiry_date, custom_steps, created_by, created_by_type)
        )
        return cursor.lastrowid


def get_all_accounts(created_by=None, created_by_type=None):
    
    with db_connection() as cursor:
        if created_by and created_by_type:
            cursor.execute(
                "SELECT * FROM accounts WHERE created_by = ? AND created_by_type = ? ORDER BY expiry_date DESC",
                (created_by, created_by_type)
            )
        else:
            cursor.execute("SELECT * FROM accounts ORDER BY expiry_date DESC")
        return [dict(row) for row in cursor.fetchall()]


def get_active_accounts(created_by=None, created_by_type=None):
    
    today = datetime.now().strftime('%Y-%m-%d')
    with db_connection() as cursor:
        if created_by and created_by_type:
            cursor.execute(
                "SELECT * FROM accounts WHERE expiry_date >= ? AND status = 'active' AND created_by = ? AND created_by_type = ?",
                (today, created_by, created_by_type)
            )
        else:
            cursor.execute(
                "SELECT * FROM accounts WHERE expiry_date >= ? AND status = 'active'",
                (today,)
            )
        return [dict(row) for row in cursor.fetchall()]


def update_account_status(account_id, status):
    
    with db_connection() as cursor:
        cursor.execute(
            "UPDATE accounts SET status = ? WHERE id = ?",
            (status, account_id)
        )


def update_last_run(account_id):
    
    now = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    with db_connection() as cursor:
        cursor.execute(
            "UPDATE accounts SET last_run = ? WHERE id = ?",
            (now, account_id)
        )


def update_custom_steps(account_id, custom_steps):
    
    with db_connection() as cursor:
        cursor.execute(
            "UPDATE accounts SET custom_steps = ? WHERE id = ?",
            (custom_steps, account_id)
        )


def add_run_log(account_id, steps, result):

    with db_connection() as cursor:
        cursor.execute(
            "INSERT INTO run_logs (account_id, steps, result) VALUES (?, ?, ?)",
            (account_id, steps, result)
        )


def delete_account(account_id):
    
    with db_connection() as cursor:
        cursor.execute("DELETE FROM accounts WHERE id = ?", (account_id,))
        cursor.execute("DELETE FROM run_logs WHERE account_id = ?", (account_id,))


def get_run_logs(account_id=None, created_by=None, created_by_type=None, limit=100):

    with db_connection() as cursor:
        if account_id:
            cursor.execute('''
            SELECT r.*, a.username FROM run_logs r
            JOIN accounts a ON r.account_id = a.id
            WHERE r.account_id = ?
            ORDER BY r.run_time DESC
            LIMIT ?
            ''', (account_id, limit))
        elif created_by and created_by_type:
            cursor.execute('''
            SELECT r.*, a.username FROM run_logs r
            JOIN accounts a ON r.account_id = a.id
            WHERE a.created_by = ? AND a.created_by_type = ?
            ORDER BY r.run_time DESC
            LIMIT ?
            ''', (created_by, created_by_type, limit))
        else:
            cursor.execute('''
            SELECT r.*, a.username FROM run_logs r
            JOIN accounts a ON r.account_id = a.id
            ORDER BY r.run_time DESC
            LIMIT ?
            ''', (limit,))
        return [dict(row) for row in cursor.fetchall()]



def get_current_steps(account=None, account_index=0):
    
   
    if account and account.get('custom_steps'):
        base_steps = account['custom_steps']
        # 添加小范围随机偏移，使步数更自然
        offset = random.randint(-100, 100)
        steps = max(1, base_steps + offset)  # 确保不小于1
        logger.info(f"使用自定义步数，生成步数: {steps}")
        return steps

    
    current_hour = datetime.now().hour
    logger.info(f"当前时间: {datetime.now()}, 小时: {current_hour}")

    
    closest_hour = None
    min_diff = float('inf')

    for hour in STEP_RANGES.keys():
        diff = abs(current_hour - hour)
        if diff < min_diff:
            min_diff = diff
            closest_hour = hour

   
    if min_diff <= 2 and closest_hour in STEP_RANGES:
        step_config = STEP_RANGES[closest_hour]
        base_steps = random.randint(step_config['min'], step_config['max'])
        offset = random.randint(-500, 500)
        steps = max(1, base_steps + offset)  
        logger.info(f"使用 {closest_hour} 点配置，生成步数: {steps}")
    else:
        base_steps = DEFAULT_STEPS
        offset = random.randint(-1000, 1000)
        steps = max(1, base_steps + offset)  
        logger.info(f"使用默认步数，生成步数: {steps}")

    return steps


def validate_credentials(username, password):
    """验证账号密码格式"""
    import re

  
    phone_pattern = r'^1[3-9]\d{9}$'
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

    if not username or not password:
        return False, "账号或密码不能为空"

    if ' ' in password:
        return False, "密码不能包含空格"

    if re.match(phone_pattern, username) or re.match(email_pattern, username):
        return True, "账号格式验证通过"
    else:
        return False, "账号格式错误（需要是手机号或邮箱）"


def submit_steps(username, password, steps):
    """提交步数到服务器"""
    try:
        
        is_valid, message = validate_credentials(username, password)
        if not is_valid:
            return False, f"验证失败: {message}"

        
        data = {
            'phone': username,
            'pwd': password,
            'num': steps
        }

        
        session = requests.Session()
        response = session.post(
            BASE_URL,
            data=data,
            headers=HEADERS,
            timeout=30
        )

        
        if response.status_code == 200:
            result = response.json()
            if result.get('code') == 200:
                return True, f"提交成功! 步数: {steps}"
            else:
                error_msg = result.get('data', '未知错误')
                if '频繁' in error_msg:
                    return False, "提交过于频繁，请稍后再试"
                else:
                    return False, f"提交失败: {error_msg}"
        else:
            return False, f"网络错误: {response.status_code}"

    except requests.exceptions.RequestException as e:
        return False, f"网络请求错误: {str(e)}"
    except json.JSONDecodeError:
        return False, "服务器响应格式错误"
    except Exception as e:
        return False, f"未知错误: {str(e)}"


def run_step_submission():
    """执行步数提交任务"""
    logger.info("开始执行自动步数提交任务")

    
    accounts = get_active_accounts()
    if not accounts:
        logger.info("没有需要处理的活跃账号")
        return

    logger.info(f"共有 {len(accounts)} 个活跃账号需要处理")

    
    for i, account in enumerate(accounts):
        logger.info(f"处理账号 {i + 1}/{len(accounts)}: {account['username']}")

        try:
            
            steps = get_current_steps(account, i)

            
            success, message = submit_steps(
                account['username'],
                account['password'],
                steps
            )

           
            add_run_log(account['id'], steps, message)

            if success:
                logger.info(f"账号 {account['username']} - {message}")
                update_last_run(account['id'])
            else:
                logger.error(f"账号 {account['username']} - {message}")
                
                if "验证失败" in message or "密码错误" in message:
                    update_account_status(account['id'], 'invalid')

        except Exception as e:
            logger.error(f"账号 {account['username']} 处理异常: {str(e)}")
            add_run_log(account['id'], 0, f"处理异常: {str(e)}")

        
        if i < len(accounts) - 1:
            logger.info("等待5秒后处理下一个账号...")
            time.sleep(5)

    logger.info("自动步数提交任务完成")



scheduler = BackgroundScheduler()


def start_scheduler():
    """启动定时任务"""
    
    scheduler.add_job(
        run_step_submission,
        'cron',
        hour=7,
        minute=0,
        second=0,
        id='daily_step_submission'
    )
    scheduler.start()
    logger.info("定时任务已启动，每天07:00执行步数提交")



def admin_login_required(f):
    """检查管理员是否已登录的装饰器"""

    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function


def login_required(f):
    """检查用户是否已登录的装饰器（管理员或普通用户）"""

    def decorated_function(*args, **kwargs):
        if 'admin_id' not in session and 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)

    decorated_function.__name__ = f.__name__
    return decorated_function



@app.route('/login', methods=['GET', 'POST'])
def login():
    
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        
        admin = validate_admin(username, password)
        if admin:
            session['admin_id'] = admin['id']
            session['admin_username'] = admin['username']
            logger.info(f"管理员 {username} 登录成功")
            return redirect(url_for('index'))

        
        user = validate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['user_username'] = user['username']
            logger.info(f"用户 {username} 登录成功")
            return redirect(url_for('index'))

       
        logger.warning(f"登录失败: {username}")
        html = '''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>登录 - 自动跑步步数提交系统</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
        </head>
        <body class="bg-gray-100 min-h-screen flex items-center justify-center">
            <div class="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
                <div class="text-center mb-6">
                    <h1 class="text-3xl font-bold text-gray-800">
                        <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                    </h1>
                    <p class="text-gray-600 mt-2">用户登录</p>
                </div>

                <form method="post" class="space-y-4">
                    <div class="p-3 bg-red-100 text-red-700 rounded-md mb-4">
                        <i class="fa fa-exclamation-circle mr-1"></i> 用户名或密码错误
                    </div>

                    <div>
                        <label for="username" class="block text-gray-700 mb-1">账号</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                                <i class="fa fa-user"></i>
                            </span>
                            <input type="text" id="username" name="username" 
                                class="w-full pl-10 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required>
                        </div>
                    </div>

                    <div>
                        <label for="password" class="block text-gray-700 mb-1">密码</label>
                        <div class="relative">
                            <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                                <i class="fa fa-lock"></i>
                            </span>
                            <input type="password" id="password" name="password" 
                                class="w-full pl-10 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required>
                        </div>
                    </div>

                    <button type="submit" class="w-full bg-blue-500 hover:bg-blue-600 text-white py-2 rounded-md transition duration-200">
                        <i class="fa fa-sign-in mr-1"></i> 登录
                    </button>
                </form>
            </div>
        </body>
        </html>
        '''
        return render_template_string(html)

    
    html = '''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>登录 - 自动跑步步数提交系统</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
        <div class="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
            <div class="text-center mb-6">
                <h1 class="text-3xl font-bold text-gray-800">
                    <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                </h1>
                <p class="text-gray-600 mt-2">用户登录</p>
            </div>

            <form method="post" class="space-y-4">
                <div>
                    <label for="username" class="block text-gray-700 mb-1">账号</label>
                    <div class="relative">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                            <i class="fa fa-user"></i>
                        </span>
                        <input type="text" id="username" name="username" 
                            class="w-full pl-10 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            required>
                    </div>
                </div>

                <div>
                    <label for="password" class="block text-gray-700 mb-1">密码</label>
                    <div class="relative">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                            <i class="fa fa-lock"></i>
                        </span>
                        <input type="password" id="password" name="password" 
                            class="w-full pl-10 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            required>
                    </div>
                </div>

                <button type="submit" class="w-full bg-blue-500 hover:bg-blue-600 text-white py-2 rounded-md transition duration-200">
                    <i class="fa fa-sign-in mr-1"></i> 登录
                </button>
            </form>
        </div>
    </body>
    </html>
    '''
    return render_template_string(html)


@app.route('/logout')
def logout():
    """登出"""
    if 'admin_username' in session:
        logger.info(f"管理员 {session['admin_username']} 登出")
    elif 'user_username' in session:
        logger.info(f"用户 {session['user_username']} 登出")
    session.clear()
    return redirect(url_for('login'))


@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    """修改密码（管理员和普通用户）"""
    if request.method == 'POST':
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        # 验证新密码是否一致
        if new_password != confirm_password:
            message = "两次输入的新密码不一致"
            return render_template_string(get_change_password_html(message=message, is_error=True))

        # 验证当前密码并修改
        if 'admin_id' in session:
            # 管理员修改密码
            admin_id = session['admin_id']
            with db_connection() as cursor:
                cursor.execute("SELECT * FROM admins WHERE id = ?", (admin_id,))
                admin = cursor.fetchone()

            if not admin or not check_password_hash(admin['password_hash'], current_password):
                message = "当前密码不正确"
                return render_template_string(get_change_password_html(message=message, is_error=True))

            # 修改密码
            success = change_admin_password(admin_id, new_password)
            user_type = "管理员"
            username = session['admin_username']
        else:
            # 普通用户修改密码
            user_id = session['user_id']
            with db_connection() as cursor:
                cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
                user = cursor.fetchone()

            if not user or not check_password_hash(user['password_hash'], current_password):
                message = "当前密码不正确"
                return render_template_string(get_change_password_html(message=message, is_error=True))

            # 修改密码
            success = update_user(user_id, {'password': new_password})
            user_type = "用户"
            username = session['user_username']

        if success:
            logger.info(f"{user_type} {username} 修改了密码")
            message = "密码修改成功，请重新登录"
            session.clear()
            return render_template_string(get_login_with_message_html(message, is_success=True))
        else:
            message = "密码修改失败，请重试"
            return render_template_string(get_change_password_html(message=message, is_error=True))

    # GET请求显示修改密码页面
    return render_template_string(get_change_password_html())


def get_login_with_message_html(message, is_success=True):
    """生成带消息的登录页面HTML"""
    return f'''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>登录 - 自动跑步步数提交系统</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 min-h-screen flex items-center justify-center">
        <div class="bg-white rounded-lg shadow-lg p-8 max-w-md w-full">
            <div class="text-center mb-6">
                <h1 class="text-3xl font-bold text-gray-800">
                    <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                </h1>
                <p class="text-gray-600 mt-2">用户登录</p>
            </div>

            <div class="p-3 {'bg-green-100 text-green-700' if is_success else 'bg-red-100 text-red-700'} rounded-md mb-4">
                <i class="fa {'fa-check-circle' if is_success else 'fa-exclamation-circle'} mr-1"></i> {message}
            </div>

            <form method="post" class="space-y-4">
                <div>
                    <label for="username" class="block text-gray-700 mb-1">账号</label>
                    <div class="relative">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                            <i class="fa fa-user"></i>
                        </span>
                        <input type="text" id="username" name="username" 
                            class="w-full pl-10 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            required>
                    </div>
                </div>

                <div>
                    <label for="password" class="block text-gray-700 mb-1">密码</label>
                    <div class="relative">
                        <span class="absolute inset-y-0 left-0 flex items-center pl-3 text-gray-500">
                            <i class="fa fa-lock"></i>
                        </span>
                        <input type="password" id="password" name="password" 
                            class="w-full pl-10 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            required>
                    </div>
                </div>

                <button type="submit" class="w-full bg-blue-500 hover:bg-blue-600 text-white py-2 rounded-md transition duration-200">
                    <i class="fa fa-sign-in mr-1"></i> 登录
                </button>
            </form>
        </div>
    </body>
    </html>
    '''


def get_change_password_html(message=None, is_error=False):
    """生成修改密码页面HTML"""
    message_html = ""
    if message:
        message_html = f'''
        <div class="p-3 {'bg-red-100 text-red-700' if is_error else 'bg-green-100 text-green-700'} rounded-md mb-4">
            <i class="fa {'fa-exclamation-circle' if is_error else 'fa-check-circle'} mr-1"></i> {message}
        </div>
        '''

    return f'''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>修改密码 - 自动跑步步数提交系统</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-7xl">
            <header class="mb-8 text-center">
                <h1 class="text-4xl font-bold text-gray-800 mb-2">
                    <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                </h1>
                <p class="text-gray-600">修改密码</p>
            </header>

            <div class="bg-white rounded-lg shadow-md p-6 max-w-md mx-auto">
                {message_html}

                <form method="post" class="space-y-4">
                    <div>
                        <label for="current_password" class="block text-gray-700 mb-1">当前密码</label>
                        <input type="password" id="current_password" name="current_password" 
                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            required>
                    </div>

                    <div>
                        <label for="new_password" class="block text-gray-700 mb-1">新密码</label>
                        <input type="password" id="new_password" name="new_password" 
                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            minlength="6" required>
                        <p class="text-xs text-gray-500 mt-1">密码长度至少6位</p>
                    </div>

                    <div>
                        <label for="confirm_password" class="block text-gray-700 mb-1">确认新密码</label>
                        <input type="password" id="confirm_password" name="confirm_password" 
                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            minlength="6" required>
                    </div>

                    <div class="flex justify-between">
                        <a href="/" class="text-gray-600 hover:text-gray-800 px-4 py-2">
                            <i class="fa fa-arrow-left mr-1"></i> 返回首页
                        </a>
                        <button type="submit" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200">
                            <i class="fa fa-save mr-1"></i> 保存密码
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''


@app.route('/quota-settings', methods=['GET', 'POST'])
@admin_login_required
def quota_settings():
    """额度设置页面（管理员）"""
    if request.method == 'POST':
        try:
            max_accounts = int(request.form.get('max_accounts'))
            if max_accounts <= 0:
                raise ValueError("最大账号数必须大于0")

            # 获取当前账号数量
            current_count = get_account_count()
            if max_accounts < current_count:
                raise ValueError(f"最大账号数不能小于当前账号数({current_count}个)")

            # 更新额度设置
            update_quota_settings(max_accounts, session['admin_id'])
            logger.info(f"管理员 {session['admin_username']} 将最大账号数更新为 {max_accounts}")

            # 显示成功消息
            quota = get_quota_settings()
            return render_template_string(get_quota_settings_html(
                max_accounts=quota['max_accounts'],
                message="额度设置更新成功",
                is_success=True
            ))
        except ValueError as e:
            quota = get_quota_settings()
            return render_template_string(get_quota_settings_html(
                max_accounts=quota['max_accounts'],
                message=str(e),
                is_error=True
            ))
        except Exception as e:
            quota = get_quota_settings()
            return render_template_string(get_quota_settings_html(
                max_accounts=quota['max_accounts'],
                message=f"更新失败: {str(e)}",
                is_error=True
            ))

    # GET请求显示额度设置页面
    quota = get_quota_settings()
    return render_template_string(get_quota_settings_html(max_accounts=quota['max_accounts']))


def get_quota_settings_html(max_accounts, message=None, is_error=False):
    """生成额度设置页面HTML"""
    current_count = get_account_count()
    message_html = ""
    if message:
        message_html = f'''
        <div class="p-3 {'bg-red-100 text-red-700' if is_error else 'bg-green-100 text-green-700'} rounded-md mb-4">
            <i class="fa {'fa-exclamation-circle' if is_error else 'fa-check-circle'} mr-1"></i> {message}
        </div>
        '''

    return f'''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>额度设置 - 自动跑步步数提交系统</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-7xl">
            <header class="mb-8 text-center">
                <h1 class="text-4xl font-bold text-gray-800 mb-2">
                    <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                </h1>
                <p class="text-gray-600">全局额度设置</p>
            </header>

            <div class="bg-white rounded-lg shadow-md p-6 max-w-md mx-auto">
                {message_html}

                <div class="mb-6 p-4 bg-blue-50 rounded-md">
                    <p class="text-gray-700">
                        <i class="fa fa-info-circle mr-1 text-blue-500"></i>
                        当前系统中已添加 <strong>{current_count}</strong> 个跑步账号
                    </p>
                </div>

                <form method="post" class="space-y-4">
                    <div>
                        <label for="max_accounts" class="block text-gray-700 mb-1">系统最大跑步账号数量</label>
                        <input type="number" id="max_accounts" name="max_accounts" 
                            class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                            value="{max_accounts}" min="1" required>
                        <p class="text-xs text-gray-500 mt-1">设置系统可以添加的最大跑步账号总数量</p>
                    </div>

                    <div class="flex justify-between">
                        <a href="/" class="text-gray-600 hover:text-gray-800 px-4 py-2">
                            <i class="fa fa-arrow-left mr-1"></i> 返回首页
                        </a>
                        <button type="submit" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200">
                            <i class="fa fa-save mr-1"></i> 保存设置
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </body>
    </html>
    '''


# 用户管理页面
@app.route('/user-management', methods=['GET', 'POST'])
@admin_login_required
def user_management():
    """用户管理页面（仅管理员）"""
    users = get_all_users()

    if request.method == 'POST':
        action = request.form.get('action')
        user_id = request.form.get('user_id')

        if action == 'delete' and user_id:
            try:
                delete_user(int(user_id))
                logger.info(f"管理员 {session['admin_username']} 删除了用户 ID: {user_id}")
                return redirect(url_for('user_management'))
            except Exception as e:
                message = f"删除用户失败: {str(e)}"
                return render_template_string(get_user_management_html(users, message, is_error=True))

    return render_template_string(get_user_management_html(users))


def get_user_management_html(users, message=None, is_error=False):
    """生成用户管理页面HTML"""
    message_html = ""
    if message:
        message_html = f'''
        <div class="p-3 {'bg-red-100 text-red-700' if is_error else 'bg-green-100 text-green-700'} rounded-md mb-4">
            <i class="fa {'fa-exclamation-circle' if is_error else 'fa-check-circle'} mr-1"></i> {message}
        </div>
        '''

    users_html = ""
    if users:
        for user in users:
            users_html += f'''
            <tr>
                <td class="px-6 py-4 whitespace-nowrap">{user['username']}</td>
                <td class="px-6 py-4 whitespace-nowrap">{user['max_accounts']}</td>
                <td class="px-6 py-4 whitespace-nowrap">
                    {'<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">活跃</span>' if user['status'] == 'active' else '<span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">禁用</span>'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {user['created_at']}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                    {user['last_login'] or '未登录'}
                </td>
                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                    <button onclick="editUser({user['id']}, '{user['username']}', {user['max_accounts']}, '{user['status']}')" 
                            class="text-blue-600 hover:text-blue-900 mr-4">
                        <i class="fa fa-pencil mr-1"></i>编辑
                    </button>
                    <button onclick="deleteUserConfirm({user['id']})" class="text-red-600 hover:text-red-900">
                        <i class="fa fa-trash mr-1"></i>删除
                    </button>
                </td>
            </tr>
            '''
    else:
        users_html = '''
        <tr>
            <td colspan="6" class="px-6 py-8 text-center text-gray-500">
                <i class="fa fa-info-circle text-2xl mb-2"></i>
                <p>暂无用户，请添加新用户</p>
            </td>
        </tr>
        '''

    return f'''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>用户管理 - 自动跑步步数提交系统</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-7xl">
            <header class="mb-8">
                <div class="flex flex-col md:flex-row md:items-center md:justify-between">
                    <div class="text-center md:text-left">
                        <h1 class="text-4xl font-bold text-gray-800 mb-2">
                            <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                        </h1>
                        <p class="text-gray-600">用户管理</p>
                    </div>
                    <div class="mt-4 md:mt-0 flex items-center space-x-4">
                        <div class="text-gray-600">
                            <i class="fa fa-user-circle mr-1"></i> 管理员: {session['admin_username']}
                        </div>
                        <a href="/" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-md transition duration-200">
                            <i class="fa fa-home mr-1"></i> 首页
                        </a>
                        <a href="/logout" class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-md transition duration-200">
                            <i class="fa fa-sign-out mr-1"></i> 退出登录
                        </a>
                    </div>
                </div>
            </header>

            <!-- 添加用户表单 -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4 text-gray-700">
                    <i class="fa fa-plus-circle mr-2"></i>添加新用户
                </h2>
                <form id="addUserForm" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                            <label for="username" class="block text-gray-700 mb-1">用户名</label>
                            <input type="text" id="username" name="username" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required>
                        </div>
                        <div>
                            <label for="password" class="block text-gray-700 mb-1">密码</label>
                            <input type="password" id="password" name="password" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                minlength="6" required>
                            <p class="text-xs text-gray-500 mt-1">密码长度至少6位</p>
                        </div>
                        <div>
                            <label for="maxAccounts" class="block text-gray-700 mb-1">最大跑步账号数量</label>
                            <input type="number" id="maxAccounts" name="maxAccounts" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                min="1" value="5" required>
                        </div>
                    </div>
                    <div class="text-right">
                        <button type="submit" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200">
                            <i class="fa fa-save mr-1"></i>添加用户
                        </button>
                    </div>
                </form>
            </div>

            <!-- 用户列表 -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <h2 class="text-2xl font-semibold mb-4 text-gray-700">
                    <i class="fa fa-users mr-2"></i>用户列表
                </h2>

                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead>
                            <tr>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">用户名</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">最大跑步账号数</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">创建时间</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">最后登录</th>
                                <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            {users_html}
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- 编辑用户模态框 -->
            <div id="editUserModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
                <div class="bg-white rounded-lg p-6 max-w-md w-full">
                    <div class="text-center">
                        <h3 id="editUserTitle" class="text-xl font-semibold text-gray-800 mb-4">编辑用户</h3>
                        <form id="editUserForm" class="space-y-4">
                            <input type="hidden" id="editUserId">
                            <div>
                                <label for="editUsername" class="block text-gray-700 mb-1">用户名</label>
                                <input type="text" id="editUsername" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    required>
                            </div>
                            <div>
                                <label for="editPassword" class="block text-gray-700 mb-1">
                                    密码 (留空则不修改)
                                </label>
                                <input type="password" id="editPassword" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    minlength="6">
                            </div>
                            <div>
                                <label for="editMaxAccounts" class="block text-gray-700 mb-1">最大跑步账号数量</label>
                                <input type="number" id="editMaxAccounts" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    min="1" required>
                            </div>
                            <div>
                                <label for="editStatus" class="block text-gray-700 mb-1">状态</label>
                                <select id="editStatus" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500">
                                    <option value="active">活跃</option>
                                    <option value="inactive">禁用</option>
                                </select>
                            </div>
                            <div class="flex justify-end space-x-3">
                                <button type="button" onclick="closeEditUserModal()" 
                                        class="bg-gray-200 hover:bg-gray-300 px-6 py-2 rounded-md transition duration-200">
                                    取消
                                </button>
                                <button type="submit" 
                                        class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200">
                                    保存修改
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- 删除确认模态框 -->
            <div id="deleteConfirmModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
                <div class="bg-white rounded-lg p-6 max-w-md w-full">
                    <div class="text-center">
                        <h3 class="text-xl font-semibold text-gray-800 mb-4">确认删除</h3>
                        <p class="text-gray-600 mb-6">
                            确定要删除这个用户吗？该用户创建的所有跑步账号和日志也将被删除。
                        </p>
                        <form id="deleteUserForm" method="post" class="flex justify-center space-x-3">
                            <input type="hidden" name="user_id" id="deleteUserId">
                            <input type="hidden" name="action" value="delete">
                            <button type="button" onclick="closeDeleteConfirmModal()" 
                                    class="bg-gray-200 hover:bg-gray-300 px-6 py-2 rounded-md transition duration-200">
                                取消
                            </button>
                            <button type="submit" 
                                    class="bg-red-500 hover:bg-red-600 text-white px-6 py-2 rounded-md transition duration-200">
                                确认删除
                            </button>
                        </form>
                    </div>
                </div>
            </div>

            <!-- 消息提示 -->
            <div id="message" class="fixed bottom-4 right-4 px-6 py-3 rounded-md shadow-lg transform transition-all duration-300 translate-y-20 opacity-0"></div>
        </div>

        <script>
            // 显示消息
            function showMessage(text, isError = false) {{
                const messageEl = document.getElementById('message');
                messageEl.textContent = text;
                messageEl.className = `fixed bottom-4 right-4 px-6 py-3 rounded-md shadow-lg transform transition-all duration-300 ${{isError ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}}`;

                setTimeout(() => {{
                    messageEl.classList.add('translate-y-20', 'opacity-0');
                }}, 3000);
            }}

            // 添加用户表单提交
            document.getElementById('addUserForm').addEventListener('submit', async function(e) {{
                e.preventDefault();

                const formData = new FormData(this);
                const data = {{
                    username: formData.get('username'),
                    password: formData.get('password'),
                    max_accounts: parseInt(formData.get('maxAccounts'))
                }};

                try {{
                    const response = await fetch('/api/users', {{
                        method: 'POST',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify(data)
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        showMessage('用户添加成功');
                        this.reset();
                        // 刷新页面
                        setTimeout(() => window.location.reload(), 1000);
                    }} else {{
                        showMessage(result.message, true);
                    }}
                }} catch (error) {{
                    showMessage('添加用户失败', true);
                    console.error(error);
                }}
            }});

            // 打开编辑用户模态框
            function editUser(userId, username, maxAccounts, status) {{
                document.getElementById('editUserId').value = userId;
                document.getElementById('editUsername').value = username;
                document.getElementById('editMaxAccounts').value = maxAccounts;
                document.getElementById('editStatus').value = status;
                document.getElementById('editUserModal').classList.remove('hidden');
            }}

            // 关闭编辑用户模态框
            function closeEditUserModal() {{
                document.getElementById('editUserModal').classList.add('hidden');
            }}

            // 提交用户编辑表单
            document.getElementById('editUserForm').addEventListener('submit', async function(e) {{
                e.preventDefault();

                const userId = document.getElementById('editUserId').value;
                const data = {{
                    username: document.getElementById('editUsername').value,
                    password: document.getElementById('editPassword').value || null,
                    max_accounts: parseInt(document.getElementById('editMaxAccounts').value),
                    status: document.getElementById('editStatus').value
                }};

                try {{
                    const response = await fetch(`/api/users/${{userId}}`, {{
                        method: 'PUT',
                        headers: {{
                            'Content-Type': 'application/json'
                        }},
                        body: JSON.stringify(data)
                    }});

                    const result = await response.json();

                    if (result.success) {{
                        showMessage('用户信息更新成功');
                        closeEditUserModal();
                        // 刷新页面
                        setTimeout(() => window.location.reload(), 1000);
                    }} else {{
                        showMessage(result.message, true);
                    }}
                }} catch (error) {{
                    showMessage('更新用户信息失败', true);
                    console.error(error);
                }}
            }});

            // 打开删除确认模态框
            function deleteUserConfirm(userId) {{
                document.getElementById('deleteUserId').value = userId;
                document.getElementById('deleteConfirmModal').classList.remove('hidden');
            }}

            // 关闭删除确认模态框
            function closeDeleteConfirmModal() {{
                document.getElementById('deleteConfirmModal').classList.add('hidden');
            }}
        </script>
    </body>
    </html>
    '''


@app.route('/')
@login_required
def index():
    """主页面"""
    # 根据登录角色获取相应的账号
    if 'admin_id' in session:
        # 管理员可以看到所有账号
        accounts = get_all_accounts()
        quota = get_quota_settings()
        current_count = get_account_count()
        max_accounts = quota['max_accounts']
        user_type = 'admin'
        user_id = session['admin_id']
        username = session['admin_username']
    else:
        # 普通用户只能看到自己创建的账号
        user_id = session['user_id']
        accounts = get_all_accounts(user_id, 'user')
        user = get_user(user_id)
        current_count = get_account_count(user_id, 'user')
        max_accounts = user['max_accounts']
        user_type = 'user'
        username = session['user_username']

    # 前端HTML模板
    html = '''
    <!DOCTYPE html>
    <html lang="zh-CN">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>自动跑步步数提交系统</title>
        <script src="https://cdn.tailwindcss.com"></script>
        <link href="https://cdn.jsdelivr.net/npm/font-awesome@4.7.0/css/font-awesome.min.css" rel="stylesheet">
    </head>
    <body class="bg-gray-100 min-h-screen">
        <div class="container mx-auto px-4 py-8 max-w-7xl">
            <header class="mb-8">
                <div class="flex flex-col md:flex-row md:items-center md:justify-between">
                    <div class="text-center md:text-left">
                        <h1 class="text-4xl font-bold text-gray-800 mb-2">
                            <i class="fa fa-running mr-2"></i>自动跑步步数提交系统
                        </h1>
                        <p class="text-gray-600">管理账号并自动提交每日步数</p>
                    </div>
                    <div class="mt-4 md:mt-0 flex items-center space-x-4">
                        <div class="text-gray-600">
                            <i class="fa fa-user-circle mr-1"></i> {{user_type_name}}: {{username}}
                        </div>
                        {% if is_admin %}
                        <a href="/user-management" class="bg-indigo-500 hover:bg-indigo-600 text-white px-4 py-2 rounded-md transition duration-200">
                            <i class="fa fa-users mr-1"></i> 用户管理
                        </a>
                        <a href="/quota-settings" class="bg-purple-500 hover:bg-purple-600 text-white px-4 py-2 rounded-md transition duration-200">
                            <i class="fa fa-sliders mr-1"></i> 额度设置
                        </a>
                        {% endif %}
                        <a href="/change-password" class="bg-gray-500 hover:bg-gray-600 text-white px-4 py-2 rounded-md transition duration-200">
                            <i class="fa fa-key mr-1"></i> 修改密码
                        </a>
                        <a href="/logout" class="bg-red-500 hover:bg-red-600 text-white px-4 py-2 rounded-md transition duration-200">
                            <i class="fa fa-sign-out mr-1"></i> 退出登录
                        </a>
                    </div>
                </div>

                <!-- 额度信息 -->
                <div class="mt-4 p-3 bg-blue-50 border border-blue-100 rounded-md">
                    <div class="flex flex-col sm:flex-row sm:items-center justify-between">
                        <p class="text-gray-700">
                            <i class="fa fa-info-circle mr-1 text-blue-500"></i>
                            账号额度: 当前 <strong>{{current_count}}</strong> / 最大 <strong>{{max_accounts}}</strong> 个
                        </p>
                        <p class="mt-2 sm:mt-0 text-sm text-gray-600">
                            自动提交时间: 每天 07:00
                        </p>
                    </div>
                </div>
            </header>

            <!-- 添加账号表单 -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4 text-gray-700">
                    <i class="fa fa-plus-circle mr-2"></i> 添加新账号
                </h2>
                <form id="addAccountForm" class="space-y-4">
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                        <div>
                            <label for="username" class="block text-gray-700 mb-1">账号 (手机号或邮箱)</label>
                            <input type="text" id="username" name="username" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required>
                        </div>
                        <div>
                            <label for="password" class="block text-gray-700 mb-1">密码</label>
                            <input type="password" id="password" name="password" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required>
                        </div>
                        <div>
                            <label for="expiryDate" class="block text-gray-700 mb-1">到期日期</label>
                            <input type="date" id="expiryDate" name="expiryDate" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                required>
                        </div>
                        <div>
                            <label for="customSteps" class="block text-gray-700 mb-1">
                                自定义步数(可选)
                            </label>
                            <input type="number" id="customSteps" name="customSteps" 
                                class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                min="1" max="60000" placeholder="例如: 20000">
                            <p class="text-xs text-gray-500 mt-1">留空则自动生成</p>
                        </div>
                    </div>
                    <div class="text-right">
                        <button type="submit" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200" {% if current_count >= max_accounts %}disabled{% endif %}>
                            <i class="fa fa-save mr-1"></i> 保存账号
                            {% if current_count >= max_accounts %}
                            <span class="ml-2 text-xs bg-red-100 text-red-800 px-2 py-0.5 rounded">已达上限</span>
                            {% endif %}
                        </button>
                    </div>
                </form>
            </div>

            <!-- 账号列表 -->
            <div class="bg-white rounded-lg shadow-md p-6 mb-8">
                <h2 class="text-2xl font-semibold mb-4 text-gray-700">
                    <i class="fa fa-list mr-2"></i> 账号列表
                </h2>

                {% if accounts %}
                <div class="overflow-x-auto">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead>
                            <tr>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">账号</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">到期日期</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">自定义步数</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">状态</th>
                                <th class="px-6 py-3 bg-gray-50 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">最后运行</th>
                                <th class="px-6 py-3 bg-gray-50 text-right text-xs font-medium text-gray-500 uppercase tracking-wider">操作</th>
                            </tr>
                        </thead>
                        <tbody class="bg-white divide-y divide-gray-200">
                            {% for account in accounts %}
                            <tr>
                                <td class="px-6 py-4 whitespace-nowrap">{{account.username}}</td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    {% if account.expiry_date < now %}
                                    <span class="text-red-600">{{account.expiry_date}}</span>
                                    {% else %}
                                    {{account.expiry_date}}
                                    {% endif %}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    {{account.custom_steps or '自动生成'}}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap">
                                    {% if account.status == 'active' %}
                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-green-100 text-green-800">活跃</span>
                                    {% elif account.status == 'invalid' %}
                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-red-100 text-red-800">无效</span>
                                    {% else %}
                                    <span class="px-2 inline-flex text-xs leading-5 font-semibold rounded-full bg-gray-100 text-gray-800">{{account.status}}</span>
                                    {% endif %}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-sm text-gray-500">
                                    {{account.last_run or '未运行'}}
                                </td>
                                <td class="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                                    <button onclick="setCustomSteps({{ account.id }}, '{{ account.username }}', {{ account.custom_steps or 'null' }})" 
                                            class="text-green-600 hover:text-green-900 mr-4">
                                        <i class="fa fa-cog mr-1"></i> 设置步数
                                    </button>
                                    <button onclick="runNow({{ account.id }}, '{{ account.username }}')" 
                                            class="text-blue-600 hover:text-blue-900 mr-4">
                                        <i class="fa fa-play mr-1"></i> 立即运行
                                    </button>
                                    <button onclick="viewLogs({{ account.id }})" 
                                            class="text-purple-600 hover:text-purple-900 mr-4">
                                        <i class="fa fa-history mr-1"></i> 查看日志
                                    </button>
                                    <button onclick="deleteAccount({{ account.id }})" 
                                            class="text-red-600 hover:text-red-900">
                                        <i class="fa fa-trash mr-1"></i> 删除
                                    </button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
                {% else %}
                <div class="text-center py-8 text-gray-500">
                    <i class="fa fa-info-circle text-2xl mb-2"></i>
                    <p>暂无账号，请添加新账号</p>
                </div>
                {% endif %}
            </div>

            <!-- 日志展示区域 -->
            <div class="bg-white rounded-lg shadow-md p-6">
                <div class="flex flex-col md:flex-row md:items-center md:justify-between mb-4">
                    <h2 class="text-2xl font-semibold text-gray-700">
                        <i class="fa fa-file-text-o mr-2"></i> 运行日志
                    </h2>
                    <div class="mt-2 md:mt-0">
                        <select id="logFilter" class="px-3 py-1 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500" onchange="filterLogs()">
                            <option value="all">所有账号</option>
                            {% for account in accounts %}
                            <option value="{{ account.id }}">{{account.username}}</option>
                            {% endfor %}
                        </select>
                        <button onclick="refreshLogs()" class="ml-2 bg-gray-200 hover:bg-gray-300 px-3 py-1 rounded-md transition duration-200">
                            <i class="fa fa-refresh mr-1"></i> 刷新
                        </button>
                    </div>
                </div>

                <div id="logsContainer" class="overflow-x-auto max-h-96 overflow-y-auto border border-gray-200 rounded-md">
                    <table class="min-w-full divide-y divide-gray-200">
                        <thead class="bg-gray-50 sticky top-0">
                            <tr>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">时间</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">账号</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">步数</th>
                                <th class="px-6 py-3 text-left text-xs font-medium text-gray-500 uppercase tracking-wider">结果</th>
                            </tr>
                        </thead>
                        <tbody id="logsTableBody" class="bg-white divide-y divide-gray-200">
                            <!-- 日志内容将通过JavaScript动态加载 -->
                            <tr>
                                <td colspan="4" class="px-6 py-4 text-center text-gray-500">加载日志中...</td>
                            </tr>
                        </tbody>
                    </table>
                </div>
            </div>

            <!-- 执行状态模态框 -->
            <div id="statusModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
                <div class="bg-white rounded-lg p-6 max-w-md w-full">
                    <div class="text-center">
                        <div id="statusSpinner" class="w-16 h-16 border-4 border-blue-200 border-t-blue-500 rounded-full animate-spin mx-auto mb-4"></div>
                        <h3 id="statusTitle" class="text-xl font-semibold text-gray-800 mb-2">正在执行...</h3>
                        <p id="statusMessage" class="text-gray-600 mb-4">请稍候，正在提交步数...</p>
                        <div id="statusResult" class="hidden mb-4 p-3 rounded-md"></div>
                        <button id="statusCloseBtn" class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200 hidden">
                            关闭
                        </button>
                    </div>
                </div>
            </div>

            <!-- 设置自定义步数模态框 -->
            <div id="stepsModal" class="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 hidden">
                <div class="bg-white rounded-lg p-6 max-w-md w-full">
                    <div class="text-center">
                        <h3 id="stepsModalTitle" class="text-xl font-semibold text-gray-800 mb-4">设置自定义步数</h3>
                        <form id="stepsForm" class="space-y-4">
                            <input type="hidden" id="stepsAccountId">
                            <div>
                                <label for="stepsValue" class="block text-gray-700 mb-1">
                                    自定义步数(1 - 60000，留空则使用自动生成)
                                </label>
                                <input type="number" id="stepsValue" 
                                    class="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
                                    min="1" max="60000" placeholder="例如: 20000">
                            </div>
                            <div class="flex justify-end space-x-3">
                                <button type="button" onclick="closeStepsModal()" 
                                        class="bg-gray-200 hover:bg-gray-300 px-6 py-2 rounded-md transition duration-200">
                                    取消
                                </button>
                                <button type="submit" 
                                        class="bg-blue-500 hover:bg-blue-600 text-white px-6 py-2 rounded-md transition duration-200">
                                    保存设置
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            </div>

            <!-- 消息提示 -->
            <div id="message" class="fixed bottom-4 right-4 px-6 py-3 rounded-md shadow-lg transform transition-all duration-300 translate-y-20 opacity-0"></div>
        </div>

        <script>
            // 当前日期
            document.addEventListener('DOMContentLoaded', function() {
                // 设置默认到期日期为30天后
                const defaultExpiry = new Date();
                defaultExpiry.setDate(defaultExpiry.getDate() + 30);
                const yyyy = defaultExpiry.getFullYear();
                const mm = String(defaultExpiry.getMonth() + 1).padStart(2, '0');
                const dd = String(defaultExpiry.getDate()).padStart(2, '0');
                document.getElementById('expiryDate').value = `${yyyy}-${mm}-${dd}`;

                // 加载日志
                loadLogs();

                // 添加动画类
                const style = document.createElement('style');
                style.textContent = `
                    @keyframes spin {
                        0% { transform: rotate(0deg); }
                        100% { transform: rotate(360deg); }
                    }
                    .animate-spin {
                        animation: spin 1s linear infinite;
                    }
                `;
                document.head.appendChild(style);
            });

            // 显示消息
            function showMessage(text, isError = false) {
                const messageEl = document.getElementById('message');
                messageEl.textContent = text;
                messageEl.className = `fixed bottom-4 right-4 px-6 py-3 rounded-md shadow-lg transform transition-all duration-300 ${isError ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`;

                setTimeout(() => {
                    messageEl.classList.add('translate-y-20', 'opacity-0');
                }, 3000);
            }

            // 显示状态模态框
            function showStatusModal(title, message) {
                document.getElementById('statusTitle').textContent = title;
                document.getElementById('statusMessage').textContent = message;
                document.getElementById('statusResult').classList.add('hidden');
                document.getElementById('statusCloseBtn').classList.add('hidden');
                document.getElementById('statusSpinner').classList.remove('hidden');
                document.getElementById('statusModal').classList.remove('hidden');
            }

            // 更新状态模态框结果
            function updateStatusModal(result, isError = false) {
                document.getElementById('statusSpinner').classList.add('hidden');
                const resultEl = document.getElementById('statusResult');
                resultEl.textContent = result;
                resultEl.className = `mb-4 p-3 rounded-md ${isError ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}`;
                resultEl.classList.remove('hidden');
                document.getElementById('statusCloseBtn').classList.remove('hidden');
            }

            // 关闭状态模态框
            document.getElementById('statusCloseBtn').addEventListener('click', function() {
                document.getElementById('statusModal').classList.add('hidden');
                // 刷新日志
                loadLogs();
                // 刷新页面
                window.location.reload();
            });

            // 添加账号表单提交
            document.getElementById('addAccountForm').addEventListener('submit', async function(e) {
                e.preventDefault();

                const formData = new FormData(this);
                const customSteps = formData.get('customSteps') || null;
                const data = {
                    username: formData.get('username'),
                    password: formData.get('password'),
                    expiry_date: formData.get('expiryDate'),
                    custom_steps: customSteps ? parseInt(customSteps) : null
                };

                try {
                    const response = await fetch('/api/accounts', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify(data)
                    });

                    const result = await response.json();

                    if (result.success) {
                        showMessage('账号添加成功');
                        this.reset();
                        // 刷新页面
                        setTimeout(() => window.location.reload(), 1000);
                    } else {
                        showMessage(result.message, true);
                    }
                } catch (error) {
                    showMessage('添加账号失败', true);
                    console.error(error);
                }
            });

            // 打开设置步数模态框
            function setCustomSteps(accountId, username, currentSteps) {
                document.getElementById('stepsAccountId').value = accountId;
                document.getElementById('stepsModalTitle').textContent = `设置 ${username} 的自定义步数`;
                document.getElementById('stepsValue').value = currentSteps || '';
                document.getElementById('stepsModal').classList.remove('hidden');
            }

            // 关闭设置步数模态框
            function closeStepsModal() {
                document.getElementById('stepsModal').classList.add('hidden');
            }

            // 提交自定义步数设置
            document.getElementById('stepsForm').addEventListener('submit', async function(e) {
                e.preventDefault();

                const accountId = document.getElementById('stepsAccountId').value;
                const stepsValue = document.getElementById('stepsValue').value;
                const customSteps = stepsValue ? parseInt(stepsValue) : null;

                try {
                    const response = await fetch(`/api/accounts/${accountId}/steps`, {
                        method: 'PUT',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({custom_steps: customSteps})
                    });

                    const result = await response.json();

                    if (result.success) {
                        showMessage('自定义步数设置成功');
                        closeStepsModal();
                        // 刷新页面
                        setTimeout(() => window.location.reload(), 1000);
                    } else {
                        showMessage(result.message, true);
                    }
                } catch (error) {
                    showMessage('设置自定义步数失败', true);
                    console.error(error);
                }
            });

            // 立即运行
            async function runNow(accountId, username) {
                showStatusModal(`正在处理账号 ${username}`, '正在生成步数并提交，请稍候...');

                try {
                    const response = await fetch(`/api/run-now/${accountId}`, {
                        method: 'POST'
                    });

                    const result = await response.json();

                    if (result.success) {
                        // 轮询检查结果
                        checkRunResult(accountId, username);
                    } else {
                        updateStatusModal(result.message, true);
                    }
                } catch (error) {
                    updateStatusModal('执行失败: ' + error.message, true);
                    console.error(error);
                }
            }

            // 轮询检查运行结果
            async function checkRunResult(accountId, username) {
                let attempts = 0;
                const maxAttempts = 20; // 最多检查20次
                const interval = 1000; // 每秒检查一次

                const check = async () => {
                    if (attempts >= maxAttempts) {
                        updateStatusModal('执行超时，请查看日志获取详细信息', true);
                        return;
                    }

                    try {
                        const response = await fetch(`/api/logs?account_id=${accountId}&limit=1`);
                        const result = await response.json();

                        if (result.success && result.logs.length > 0) {
                            const log = result.logs[0];
                            // 检查是否是这次运行的日志（1分钟内）
                            const logTime = new Date(log.run_time);
                            const now = new Date();
                            const timeDiff = now - logTime;

                            if (timeDiff < 60000) { // 1分钟内
                                if (log.result.includes('成功')) {
                                    updateStatusModal(`执行成功: ${log.result}`);
                                } else {
                                    updateStatusModal(`执行失败: ${log.result}`, true);
                                }
                                return;
                            }
                        }

                        // 继续轮询
                        attempts++;
                        setTimeout(check, interval);
                    } catch (error) {
                        console.error('检查结果失败:', error);
                        setTimeout(check, interval);
                    }
                };

                // 开始轮询
                setTimeout(check, interval);
            }

            // 查看指定账号日志
            function viewLogs(accountId) {
                document.getElementById('logFilter').value = accountId;
                loadLogs(accountId);
                // 滚动到日志区域
                document.getElementById('logsContainer').scrollIntoView({behavior: 'smooth'});
            }

            // 筛选日志
            function filterLogs() {
                const accountId = document.getElementById('logFilter').value;
                loadLogs(accountId === 'all' ? null : accountId);
            }

            // 刷新日志
            function refreshLogs() {
                const accountId = document.getElementById('logFilter').value;
                loadLogs(accountId === 'all' ? null : accountId);
            }

            // 加载日志
            async function loadLogs(accountId = null) {
                try {
                    let url = '/api/logs';
                    if (accountId) {
                        url += `?account_id=${accountId}`;
                    }

                    const response = await fetch(url);

                    if (!response.ok) {
                        throw new Error(`HTTP错误: ${response.status}`);
                    }

                    const result = await response.json();

                    if (!result.success) {
                        throw new Error(result.message || '获取日志失败');
                    }

                    const tableBody = document.getElementById('logsTableBody');
                    tableBody.innerHTML = '';

                    if (result.logs.length > 0) {
                        result.logs.forEach(log => {
                            const row = document.createElement('tr');
                            // 根据结果添加成功/失败样式
                            const isSuccess = log.result.includes('成功');
                            row.className = isSuccess ? '' : 'bg-red-50';

                            row.innerHTML = `
                                <td class="px-6 py-3 whitespace-nowrap text-sm text-gray-500">${log.run_time}</td>
                                <td class="px-6 py-3 whitespace-nowrap text-sm font-medium text-gray-900">${log.username}</td>
                                <td class="px-6 py-3 whitespace-nowrap text-sm text-gray-500">${log.steps || '-'}</td>
                                <td class="px-6 py-3 text-sm text-gray-500">${log.result}</td>
                            `;
                            tableBody.appendChild(row);
                        });
                    } else {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td colspan="4" class="px-6 py-4 text-center text-gray-500">暂无日志记录</td>
                        `;
                        tableBody.appendChild(row);
                    }
                } catch (error) {
                    console.error('加载日志失败:', error);
                    const tableBody = document.getElementById('logsTableBody');
                    tableBody.innerHTML = `
                        <tr>
                            <td colspan="4" class="px-6 py-4 text-center text-red-500">加载日志失败: ${error.message}</td>
                        </tr>
                    `;
                    showMessage(`加载日志失败: ${error.message}`, true);
                }
            }

            // 删除账号
            async function deleteAccount(accountId) {
                if (!confirm('确定要删除这个账号吗？相关日志也将被删除。')) {
                    return;
                }

                try {
                    const response = await fetch(`/api/accounts/${accountId}`, {
                        method: 'DELETE'
                    });

                    const result = await response.json();

                    if (result.success) {
                        showMessage('账号已删除');
                        // 刷新页面
                        setTimeout(() => window.location.reload(), 1000);
                    } else {
                        showMessage(result.message, true);
                    }
                } catch (error) {
                    showMessage('删除失败', true);
                    console.error(error);
                }
            }
        </script>
    </body>
    </html>
    '''
    return render_template_string(
        html,
        accounts=accounts,
        now=datetime.now().strftime('%Y-%m-%d'),
        username=username,
        max_accounts=max_accounts,
        current_count=current_count,
        is_admin='admin_id' in session,
        user_type_name='管理员' if 'admin_id' in session else '用户',
        user_type=user_type,
        user_id=user_id
    )


# API接口
@app.route('/api/users', methods=['POST'])
@admin_login_required
def api_add_user():
    """添加用户API（仅管理员）"""
    data = request.json
    try:
        # 验证数据
        if not all(k in data for k in ['username', 'password', 'max_accounts']):
            return jsonify({"success": False, "message": "缺少必要参数"})

        # 验证密码长度
        if len(data['password']) < 6:
            return jsonify({"success": False, "message": "密码长度至少6位"})

        # 验证最大账号数
        if data['max_accounts'] < 1:
            return jsonify({"success": False, "message": "最大账号数必须大于0"})

        # 添加用户
        user_id = add_user(
            data['username'],
            data['password'],
            data['max_accounts'],
            session['admin_id']
        )

        return jsonify({
            "success": True,
            "message": "用户添加成功",
            "user_id": user_id
        })
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "用户名已存在"})
    except Exception as e:
        return jsonify({"success": False, "message": f"添加失败: {str(e)}"})


@app.route('/api/users/<int:user_id>', methods=['PUT'])
@admin_login_required
def api_update_user(user_id):
    """更新用户API（仅管理员）"""
    data = request.json
    try:
        # 验证数据
        if not data or all(k not in data for k in ['username', 'password', 'max_accounts', 'status']):
            return jsonify({"success": False, "message": "没有需要更新的字段"})

        # 验证最大账号数（如果提供）
        if 'max_accounts' in data and data['max_accounts'] < 1:
            return jsonify({"success": False, "message": "最大账号数必须大于0"})

        # 验证状态（如果提供）
        if 'status' in data and data['status'] not in ['active', 'inactive']:
            return jsonify({"success": False, "message": "状态必须是'active'或'inactive'"})

        # 更新用户
        success = update_user(user_id, data)
        if success:
            return jsonify({"success": True, "message": "用户信息已更新"})
        else:
            return jsonify({"success": False, "message": "用户不存在或没有更新内容"})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "用户名已存在"})
    except Exception as e:
        return jsonify({"success": False, "message": f"更新失败: {str(e)}"})


@app.route('/api/users')
@admin_login_required
def api_get_users():
    """获取用户列表API（仅管理员）"""
    try:
        users = get_all_users()
        return jsonify({
            "success": True,
            "users": users
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"获取用户列表失败: {str(e)}"})


@app.route('/api/accounts', methods=['POST'])
@login_required
def api_add_account():
    """添加账号API"""
    data = request.json
    try:
        # 验证数据
        if not all(k in data for k in ['username', 'password', 'expiry_date']):
            return jsonify({"success": False, "message": "缺少必要参数"})

        # 验证账号格式
        is_valid, message = validate_credentials(data['username'], data['password'])
        if not is_valid:
            return jsonify({"success": False, "message": message})

        # 确定创建者信息
        if 'admin_id' in session:
            created_by = session['admin_id']
            created_by_type = 'admin'
        else:
            created_by = session['user_id']
            created_by_type = 'user'

        # 检查是否在额度范围内
        if not is_within_quota(created_by, created_by_type):
            if created_by_type == 'user':
                user = get_user(created_by)
                return jsonify({
                    "success": False,
                    "message": f"已达到最大账号数量限制({user['max_accounts']}个)"
                })
            else:
                quota = get_quota_settings()
                return jsonify({
                    "success": False,
                    "message": f"已达到最大账号数量限制({quota['max_accounts']}个)"
                })

        # 添加账号
        account_id = add_account(
            data['username'],
            data['password'],
            data['expiry_date'],
            data.get('custom_steps'),
            created_by,
            created_by_type
        )

        return jsonify({
            "success": True,
            "message": "账号添加成功",
            "account_id": account_id
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"添加失败: {str(e)}"})


@app.route('/api/accounts/<int:account_id>/steps', methods=['PUT'])
@login_required
def api_update_steps(account_id):
    """更新账号的自定义步数"""
    data = request.json
    try:
        custom_steps = data.get('custom_steps')

        # 验证步数范围
        if custom_steps is not None and (custom_steps < 1 or custom_steps > 60000):
            return jsonify({"success": False, "message": "自定义步数必须在1-60000之间"})

        # 检查账号所有权
        with db_connection() as cursor:
            cursor.execute("SELECT created_by, created_by_type FROM accounts WHERE id = ?", (account_id,))
            account = cursor.fetchone()

            if not account:
                return jsonify({"success": False, "message": "账号不存在"})

            # 管理员可以修改所有账号，普通用户只能修改自己的账号
            if 'admin_id' not in session:
                if account['created_by'] != session['user_id'] or account['created_by_type'] != 'user':
                    return jsonify({"success": False, "message": "没有权限修改此账号"})

        update_custom_steps(account_id, custom_steps)
        return jsonify({"success": True, "message": "自定义步数已更新"})
    except Exception as e:
        return jsonify({"success": False, "message": f"更新失败: {str(e)}"})


@app.route('/api/accounts/<int:account_id>', methods=['DELETE'])
@login_required
def api_delete_account(account_id):
    """删除账号API"""
    try:
        # 检查账号所有权
        with db_connection() as cursor:
            cursor.execute("SELECT created_by, created_by_type FROM accounts WHERE id = ?", (account_id,))
            account = cursor.fetchone()

            if not account:
                return jsonify({"success": False, "message": "账号不存在"})

            # 管理员可以删除所有账号，普通用户只能删除自己的账号
            if 'admin_id' not in session:
                if account['created_by'] != session['user_id'] or account['created_by_type'] != 'user':
                    return jsonify({"success": False, "message": "没有权限删除此账号"})

        delete_account(account_id)
        return jsonify({"success": True, "message": "账号已删除"})
    except Exception as e:
        return jsonify({"success": False, "message": f"删除失败: {str(e)}"})


@app.route('/api/run-now/<int:account_id>', methods=['POST'])
@login_required
def api_run_now(account_id):
    """立即执行步数提交 API"""
    try:
        # 检查账号是否存在及权限
        with db_connection() as cursor:
            cursor.execute("""
                SELECT a.*, u.id as user_id
                FROM accounts a
                LEFT JOIN users u ON a.created_by = u.id AND a.created_by_type = 'user'
                WHERE a.id = ?
            """, (account_id,))
            account = cursor.fetchone()

            if not account:
                return jsonify({"success": False, "message": "账号不存在"})

            # 权限检查
            if 'admin_id' not in session:
                if account['created_by'] != session['user_id'] or account['created_by_type'] != 'user':
                    return jsonify({"success": False, "message": "没有权限操作此账号"})

            # 检查账号状态
            if account['status'] != 'active':
                return jsonify({"success": False, "message": f"账号状态为 {account['status']}，无法执行"})

            # 检查是否过期
            if account['expiry_date'] < datetime.now().strftime('%Y-%m-%d'):
                return jsonify({"success": False, "message": "账号已过期，无法执行"})

        # 在后台线程中执行提交，避免请求超时
        def run_in_background(account_id):
            try:
                # 获取账号详情
                with db_connection() as cursor:
                    cursor.execute("SELECT * FROM accounts WHERE id = ?", (account_id,))
                    account = cursor.fetchone()
                    if not account:
                        return

                # 生成步数
                steps = get_current_steps(dict(account))

                # 提交步数
                success, message = submit_steps(
                    account['username'],
                    account['password'],
                    steps
                )

                # 记录日志
                add_run_log(account_id, steps, message)

                if success:
                    update_last_run(account_id)
                # 如果是账号错误，标记为无效
                elif "验证失败" in message or "密码错误" in message:
                    update_account_status(account_id, 'invalid')

            except Exception as e:
                logger.error(f"立即执行任务异常: {str(e)}")
                add_run_log(account_id, 0, f"执行异常: {str(e)}")

        # 启动后台线程执行
        thread = threading.Thread(target=run_in_background, args=(account_id,))
        thread.start()

        return jsonify({
            "success": True,
            "message": "已开始执行步数提交，请等待结果"
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"执行失败: {str(e)}"})


@app.route('/api/logs')
@login_required
def api_get_logs():
    """获取日志 API"""
    try:
        account_id = request.args.get('account_id')
        limit = int(request.args.get('limit', 100))

        # 确定日志查询范围
        if 'admin_id' in session:
            # 管理员可以查看所有日志
            logs = get_run_logs(account_id=int(account_id) if account_id else None, limit=limit)
        else:
            # 普通用户只能查看自己的日志
            logs = get_run_logs(
                account_id=int(account_id) if account_id else None,
                created_by=session['user_id'],
                created_by_type='user',
                limit=limit
            )

        return jsonify({
            "success": True,
            "logs": logs
        })
    except Exception as e:
        return jsonify({"success": False, "message": f"获取日志失败: {str(e)}"})


# 应用启动
if __name__ == '__main__':
    # 初始化数据库
    init_database()

    # 启动定时任务
    start_scheduler()

    # 启动 Flask 应用
    try:
        logger.info("自动跑步步数提交系统启动中...")
        app.run(host='0.0.0.0', port=5000, debug=False)
    except Exception as e:
        logger.error(f"应用启动失败: {str(e)}")
    finally:
        # 关闭定时任务
        scheduler.shutdown()
        logger.info("自动跑步步数提交系统已关闭")