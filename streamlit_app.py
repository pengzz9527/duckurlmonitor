# pip install streamlit duckdb boto3 python-telegram-bot>=21.0 apscheduler requests

import os
import time
import duckdb
import boto3
import requests
import streamlit as st
import threading
import asyncio
import functools
import hashlib
import secrets
import json

from datetime import datetime, timedelta
from threading import Lock

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from apscheduler.schedulers.background import BackgroundScheduler


# =========================
# Streamlit UI Config
# =========================

st.set_page_config(
    page_title="URL Monitor Bot",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded"
)

# =========================
# Session State Init
# =========================

def init_session_state():
    """初始化 session state"""
    defaults = {
        "authenticated": False,
        "user_id": None,
        "user_info": None,
        "login_time": None,
        "session_token": None,
        "bot_thread": None
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()


# =========================
# Secrets
# =========================

BOT_TOKEN = st.secrets["BOT_TOKEN"]
ADMIN_USER_ID = int(st.secrets["ADMIN_USER_ID"])

R2_ENDPOINT = st.secrets["R2_ENDPOINT"]
R2_ACCESS_KEY = st.secrets["R2_ACCESS_KEY"]
R2_SECRET_KEY = st.secrets["R2_SECRET_KEY"]
R2_BUCKET = st.secrets["R2_BUCKET"]
R2_DB_KEY = st.secrets.get("R2_DB_KEY", "url_monitor.duckdb")

# 系统密钥用于加密（需要在 secrets 中设置）
SYSTEM_SECRET = st.secrets.get("SYSTEM_SECRET", "your-secure-secret-key-here")

# =========================
# Paths
# =========================

DB_DIR = "/tmp"
DB_FILE = os.path.join(DB_DIR, "url_monitor.duckdb")

# =========================
# R2 Client
# =========================

s3 = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY,
    aws_secret_access_key=R2_SECRET_KEY
)

# =========================
# Lock
# =========================

db_lock = Lock()
last_upload = 0


# =========================
# Crypto Functions
# =========================

def hash_password(password: str, salt: str = None) -> tuple:
    """哈希密码，返回 (hash, salt)"""
    if salt is None:
        salt = secrets.token_hex(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return pwdhash.hex(), salt


def verify_password(password: str, hashed: str, salt: str) -> bool:
    """验证密码"""
    pwdhash, _ = hash_password(password, salt)
    return pwdhash == hashed


def generate_session_token(user_id: int) -> str:
    """生成会话令牌"""
    timestamp = str(int(time.time()))
    data = f"{user_id}:{timestamp}:{SYSTEM_SECRET}"
    token = hashlib.sha256(data.encode()).hexdigest()
    return f"{user_id}:{timestamp}:{token}"


def verify_session_token(token: str) -> tuple:
    """验证会话令牌，返回 (user_id, 是否有效)"""
    try:
        parts = token.split(":")
        if len(parts) != 3:
            return None, False
        
        user_id, timestamp, hash_part = parts
        user_id = int(user_id)
        timestamp = int(timestamp)
        
        # 检查是否过期（24小时）
        if time.time() - timestamp > 86400:
            return user_id, False
        
        # 验证签名
        expected = hashlib.sha256(f"{user_id}:{timestamp}:{SYSTEM_SECRET}".encode()).hexdigest()
        if hash_part != expected:
            return user_id, False
            
        return user_id, True
    except:
        return None, False


# =========================
# R2 Operations
# =========================

def download_db():
    try:
        s3.download_file(R2_BUCKET, R2_DB_KEY, DB_FILE)
        print("✅ DB downloaded from R2")
    except Exception:
        print("⚠️ No database in R2, create new")


def upload_db():
    global last_upload
    if not os.path.exists(DB_FILE) or time.time() - last_upload < 10:
        return
    
    try:
        s3.upload_file(DB_FILE, R2_BUCKET, R2_DB_KEY)
        last_upload = time.time()
        print("☁️ DB uploaded")
    except Exception as e:
        print("upload failed", e)


download_db()


# =========================
# Database
# =========================

class Database:
    def __init__(self, file):
        self.file = file
        self.init_db()

    def get_conn(self):
        return duckdb.connect(self.file)

    def init_db(self):
        conn = self.get_conn()
        try:
            conn.execute("CREATE SEQUENCE IF NOT EXISTS seq START 1")
            
            conn.execute("""
            CREATE TABLE IF NOT EXISTS authorized_users(
                user_id BIGINT PRIMARY KEY,
                username TEXT,
                password_hash TEXT,
                password_salt TEXT,
                is_admin BOOLEAN DEFAULT false,
                is_active BOOLEAN DEFAULT true,
                expire_at TIMESTAMP,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                added_by BIGINT,
                last_login TIMESTAMP,
                login_attempts INTEGER DEFAULT 0,
                locked_until TIMESTAMP
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS monitored_urls(
                id BIGINT DEFAULT nextval('seq'),
                user_id BIGINT,
                name TEXT,
                url TEXT,
                interval_seconds INTEGER,
                enabled BOOLEAN DEFAULT true,
                last_status TEXT,
                last_check_time TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(id)
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS visit_logs(
                id BIGINT DEFAULT nextval('seq'),
                monitor_id BIGINT,
                status_code INTEGER,
                response_time_ms INTEGER,
                visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS login_history(
                id BIGINT DEFAULT nextval('seq'),
                user_id BIGINT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                success BOOLEAN,
                failure_reason TEXT
            )
            """)

            # 初始化管理员
            admin = conn.execute(
                "SELECT count(*) FROM authorized_users WHERE user_id=?",
                [ADMIN_USER_ID]
            ).fetchone()[0]

            if admin == 0:
                # 默认管理员密码需要在首次登录后修改
                default_pwd = "admin123"
                pwd_hash, pwd_salt = hash_password(default_pwd)
                
                conn.execute("""
                INSERT INTO authorized_users 
                (user_id, username, password_hash, password_salt, is_admin, expire_at, added_by)
                VALUES(?,?,?,?,?,?,?)
                """, [
                    ADMIN_USER_ID,
                    "admin",
                    pwd_hash,
                    pwd_salt,
                    True,
                    datetime.now() + timedelta(days=3650),
                    ADMIN_USER_ID
                ])
                print(f"⚠️ 初始管理员创建成功，默认密码: {default_pwd}，请立即修改！")

            conn.commit()
            upload_db()
        finally:
            conn.close()


db = Database(DB_FILE)


# =========================
# Authentication System
# =========================

class AuthManager:
    @staticmethod
    def authenticate(user_id: int, password: str, ip_address: str = None) -> tuple:
        """
        验证用户凭据
        返回: (success: bool, user_info: dict or None, message: str)
        """
        conn = db.get_conn()
        try:
            row = conn.execute("""
            SELECT user_id, username, password_hash, password_salt, is_admin, 
                   is_active, expire_at, locked_until, login_attempts
            FROM authorized_users 
            WHERE user_id = ?
            """, [user_id]).fetchone()
            
            if not row:
                AuthManager._log_login(conn, user_id, ip_address, False, "用户不存在")
                return False, None, "用户不存在"
            
            (uid, username, pwd_hash, pwd_salt, is_admin, 
             is_active, expire_at, locked_until, attempts) = row
            
            # 检查账户是否被锁定
            if locked_until and datetime.now() < locked_until:
                remaining = int((locked_until - datetime.now()).total_seconds() / 60)
                return False, None, f"账户已锁定，请 {remaining} 分钟后重试"
            
            # 检查是否激活
            if not is_active:
                AuthManager._log_login(conn, user_id, ip_address, False, "账户已禁用")
                return False, None, "账户已禁用"
            
            # 检查是否过期
            if expire_at and datetime.now() > expire_at:
                AuthManager._log_login(conn, user_id, ip_address, False, "账户已过期")
                # 自动禁用
                conn.execute("UPDATE authorized_users SET is_active = false WHERE user_id = ?", [user_id])
                conn.commit()
                return False, None, "账户已过期，请联系管理员"
            
            # 验证密码
            if not verify_password(password, pwd_hash, pwd_salt):
                # 失败次数+1
                new_attempts = (attempts or 0) + 1
                lock_until = None
                
                if new_attempts >= 5:
                    # 锁定30分钟
                    lock_until = datetime.now() + timedelta(minutes=30)
                    new_attempts = 0
                
                conn.execute("""
                UPDATE authorized_users 
                SET login_attempts = ?, locked_until = ? 
                WHERE user_id = ?
                """, [new_attempts, lock_until, user_id])
                
                AuthManager._log_login(conn, user_id, ip_address, False, "密码错误")
                conn.commit()
                
                if lock_until:
                    return False, None, "密码错误次数过多，账户已锁定30分钟"
                return False, None, f"密码错误，还剩 {5 - new_attempts} 次机会"
            
            # 登录成功，重置失败次数，更新最后登录时间
            conn.execute("""
            UPDATE authorized_users 
            SET login_attempts = 0, locked_until = NULL, last_login = ? 
            WHERE user_id = ?
            """, [datetime.now(), user_id])
            
            user_info = {
                "user_id": uid,
                "username": username,
                "is_admin": is_admin,
                "expire_at": expire_at
            }
            
            AuthManager._log_login(conn, user_id, ip_address, True, None)
            conn.commit()
            
            return True, user_info, "登录成功"
            
        finally:
            conn.close()
    
    @staticmethod
    def _log_login(conn, user_id, ip_address, success, failure_reason):
        """记录登录历史"""
        try:
            conn.execute("""
            INSERT INTO login_history (user_id, ip_address, success, failure_reason)
            VALUES(?,?,?,?)
            """, [user_id, ip_address, success, failure_reason])
        except:
            pass  # 不阻断主流程
    
    @staticmethod
    def change_password(user_id: int, old_password: str, new_password: str) -> tuple:
        """修改密码"""
        if len(new_password) < 6:
            return False, "新密码至少需要6位"
        
        conn = db.get_conn()
        try:
            row = conn.execute(
                "SELECT password_hash, password_salt FROM authorized_users WHERE user_id = ?",
                [user_id]
            ).fetchone()
            
            if not row:
                return False, "用户不存在"
            
            if not verify_password(old_password, row[0], row[1]):
                return False, "原密码错误"
            
            # 更新密码
            new_hash, new_salt = hash_password(new_password)
            conn.execute("""
            UPDATE authorized_users 
            SET password_hash = ?, password_salt = ? 
            WHERE user_id = ?
            """, [new_hash, new_salt, user_id])
            conn.commit()
            upload_db()
            
            return True, "密码修改成功"
        finally:
            conn.close()
    
    @staticmethod
    def reset_password(admin_id: int, target_user_id: int, new_password: str) -> tuple:
        """管理员重置用户密码"""
        conn = db.get_conn()
        try:
            # 验证管理员权限
            admin = conn.execute(
                "SELECT is_admin FROM authorized_users WHERE user_id = ? AND is_active = true",
                [admin_id]
            ).fetchone()
            
            if not admin or not admin[0]:
                return False, "无权限"
            
            # 检查目标用户是否存在
            target = conn.execute(
                "SELECT user_id FROM authorized_users WHERE user_id = ?",
                [target_user_id]
            ).fetchone()
            
            if not target:
                return False, "目标用户不存在"
            
            new_hash, new_salt = hash_password(new_password)
            conn.execute("""
            UPDATE authorized_users 
            SET password_hash = ?, password_salt = ?, login_attempts = 0, locked_until = NULL 
            WHERE user_id = ?
            """, [new_hash, new_salt, target_user_id])
            conn.commit()
            upload_db()
            
            return True, f"用户 {target_user_id} 的密码已重置"
        finally:
            conn.close()


# =========================
# Permission Decorators
# =========================

def require_auth(func):
    """Telegram 命令权限装饰器"""
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        
        # 检查 session 或数据库
        conn = db.get_conn()
        try:
            row = conn.execute("""
            SELECT user_id, is_admin, is_active, expire_at 
            FROM authorized_users 
            WHERE user_id = ? AND is_active = true
            """, [user_id]).fetchone()
            
            if not row:
                await update.message.reply_text("⛔ 未经授权，请先通过 Web 界面注册或联系管理员")
                return
            
            if row[3] and datetime.now() > row[3]:
                await update.message.reply_text("⛔ 账户已过期")
                return
            
            context.user_data["user_info"] = {
                "user_id": row[0],
                "is_admin": row[1]
            }
        finally:
            conn.close()
        
        return await func(update, context)
    return wrapper


def require_admin(func):
    """管理员权限装饰器"""
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        
        conn = db.get_conn()
        try:
            row = conn.execute("""
            SELECT is_admin, is_active, expire_at 
            FROM authorized_users 
            WHERE user_id = ?
            """, [user_id]).fetchone()
            
            if not row or not row[0]:
                await update.message.reply_text("⛔ 需要管理员权限")
                return
            
            if not row[1]:
                await update.message.reply_text("⛔ 账户已禁用")
                return
            
            if row[2] and datetime.now() > row[2]:
                await update.message.reply_text("⛔ 账户已过期")
                return
            
            context.user_data["user_info"] = {"user_id": user_id, "is_admin": True}
        finally:
            conn.close()
        
        return await func(update, context)
    return wrapper


# =========================
# URL Check
# =========================

def check_url(url):
    start = time.time()
    try:
        r = requests.get(url, timeout=10)
        code = r.status_code
        status = "UP" if 200 <= code < 400 else "DOWN"
    except:
        code = -1
        status = "DOWN"
    
    cost = int((time.time() - start) * 1000)
    return status, code, cost


def check_monitor_task(mid, uid, name, url):
    with db_lock:
        conn = db.get_conn()
        try:
            status, code, cost = check_url(url)
            now = datetime.now()

            conn.execute(
                "UPDATE monitored_urls SET last_status=?, last_check_time=? WHERE id=?",
                [status, now, mid]
            )
            conn.execute(
                "INSERT INTO visit_logs (monitor_id, status_code, response_time_ms, visit_time) VALUES(?,?,?,?)",
                [mid, code, cost, now]
            )
            conn.commit()
            upload_db()
        finally:
            conn.close()


# =========================
# Scheduler
# =========================

def run_checks():
    conn = db.get_conn()
    try:
        rows = conn.execute("""
        SELECT id, user_id, name, url FROM monitored_urls WHERE enabled = true
        """).fetchall()
    finally:
        conn.close()

    for r in rows:
        check_monitor_task(*r)


scheduler = BackgroundScheduler()
scheduler.add_job(run_checks, "interval", minutes=1)
scheduler.add_job(upload_db, "interval", minutes=5)
scheduler.start()


# =========================
# Telegram Commands
# =========================

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    
    conn = db.get_conn()
    try:
        row = conn.execute("""
        SELECT is_admin, is_active, expire_at, username 
        FROM authorized_users WHERE user_id = ?
        """, [uid]).fetchone()
        
        if not row:
            await update.message.reply_text(
                f"👋 你好！\n"
                f"🆔 你的 Telegram ID: `{uid}`\n"
                f"⛔ 你尚未获得授权\n"
                f"请联系管理员添加权限，或通过 Web 界面自助注册（如开放注册）",
                parse_mode="Markdown"
            )
            return
        
        if not row[1]:
            await update.message.reply_text("⛔ 你的账户已被禁用")
            return
        
        role = "👑 管理员" if row[0] else "👤 普通用户"
        expire = row[2].strftime("%Y-%m-%d") if row[2] else "永久"
        
        msg = f"👋 欢迎回来，{row[3]}！\n\n"
        msg += f"🆔 ID: `{uid}`\n"
        msg += f"{role}\n"
        msg += f"⏰ 过期: {expire}\n\n"
        msg += "📋 命令列表:\n"
        msg += "/add <名称> <URL> <秒数> - 添加监控\n"
        msg += "/list - 查看监控列表\n"
        msg += "/delete <ID> - 删除监控\n"
        msg += "/status <ID> - 查看详情\n"
        
        if row[0]:
            msg += "\n🔧 管理员命令:\n"
            msg += "/adduser <ID> [天数] [admin] - 添加用户\n"
            msg += "/users - 用户列表\n"
            msg += "/deluser <ID> - 删除用户\n"
            msg += "/toggle <ID> - 启用/禁用监控\n"
            msg += "/resetpwd <ID> <新密码> - 重置密码"
        
        await update.message.reply_text(msg, parse_mode="Markdown")
    finally:
        conn.close()


@require_auth
async def add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 3:
        await update.message.reply_text("❌ 用法: /add <名称> <URL> <间隔秒数(≥60)>")
        return
    
    name, url, sec = context.args[0], context.args[1], context.args[2]
    
    try:
        sec = int(sec)
        if sec < 60:
            await update.message.reply_text("❌ 间隔时间至少60秒")
            return
    except ValueError:
        await update.message.reply_text("❌ 间隔必须是整数")
        return
    
    if not url.startswith(('http://', 'https://')):
        await update.message.reply_text("❌ URL必须以 http:// 或 https:// 开头")
        return
    
    uid = update.effective_user.id
    is_admin = context.user_data["user_info"]["is_admin"]
    
    with db_lock:
        conn = db.get_conn()
        try:
            if not is_admin:
                count = conn.execute(
                    "SELECT COUNT(*) FROM monitored_urls WHERE user_id = ?",
                    [uid]
                ).fetchone()[0]
                if count >= 10:
                    await update.message.reply_text("❌ 普通用户最多10个监控")
                    return
            
            conn.execute("""
            INSERT INTO monitored_urls (user_id, name, url, interval_seconds)
            VALUES(?,?,?,?)
            """, [uid, name, url, sec])
            conn.commit()
            upload_db()
            
            await update.message.reply_text(f"✅ 已添加: {name}\n🔗 {url}\n⏱️ {sec}秒")
        finally:
            conn.close()


@require_auth
async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    is_admin = context.user_data["user_info"]["is_admin"]
    
    conn = db.get_conn()
    try:
        if is_admin:
            rows = conn.execute("""
            SELECT m.id, m.name, m.url, m.last_status, m.enabled, m.user_id, u.username
            FROM monitored_urls m
            LEFT JOIN authorized_users u ON m.user_id = u.user_id
            ORDER BY m.id DESC
            """).fetchall()
            
            text = "📊 所有监控（管理员视图）:\n\n"
            for r in rows:
                emoji = "🟢" if r[3] == "UP" else "🔴" if r[3] == "DOWN" else "⚪"
                status = "✅" if r[4] else "❌"
                text += f"ID:{r[0]} | 用户:{r[5]}({r[6] or '未知'}) | {status}\n{emoji} {r[1]}\n{r[2]}\n\n"
        else:
            rows = conn.execute("""
            SELECT id, name, url, last_status, enabled
            FROM monitored_urls WHERE user_id = ? ORDER BY id DESC
            """, [uid]).fetchall()
            
            if not rows:
                await update.message.reply_text("📭 暂无监控，使用 /add 添加")
                return
            
            text = "📊 你的监控:\n\n"
            for r in rows:
                emoji = "🟢" if r[3] == "UP" else "🔴" if r[3] == "DOWN" else "⚪"
                status = "✅" if r[4] else "❌"
                text += f"ID:{r[0]} {status} {emoji} {r[1]}\n{r[2]}\n\n"
        
        # 分段发送避免过长
        for i in range(0, len(text), 4000):
            await update.message.reply_text(text[i:i+4000])
    finally:
        conn.close()


@require_auth
async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ 用法: /delete <监控ID>")
        return
    
    try:
        mid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    uid = update.effective_user.id
    is_admin = context.user_data["user_info"]["is_admin"]
    
    with db_lock:
        conn = db.get_conn()
        try:
            if is_admin:
                result = conn.execute(
                    "DELETE FROM monitored_urls WHERE id = ? RETURNING name",
                    [mid]
                ).fetchone()
            else:
                result = conn.execute(
                    "DELETE FROM monitored_urls WHERE id = ? AND user_id = ? RETURNING name",
                    [mid, uid]
                ).fetchone()
            
            if result:
                conn.commit()
                upload_db()
                await update.message.reply_text(f"✅ 已删除: {result[0]}")
            else:
                await update.message.reply_text("❌ 未找到或无权限")
        finally:
            conn.close()


@require_auth
async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ 用法: /status <监控ID>")
        return
    
    try:
        mid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    uid = update.effective_user.id
    is_admin = context.user_data["user_info"]["is_admin"]
    
    conn = db.get_conn()
    try:
        if is_admin:
            row = conn.execute("SELECT * FROM monitored_urls WHERE id = ?", [mid]).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM monitored_urls WHERE id = ? AND user_id = ?",
                [mid, uid]
            ).fetchone()
        
        if not row:
            await update.message.reply_text("❌ 未找到或无权限")
            return
        
        logs = conn.execute("""
        SELECT status_code, response_time_ms, visit_time
        FROM visit_logs WHERE monitor_id = ? ORDER BY visit_time DESC LIMIT 5
        """, [mid]).fetchall()
        
        text = f"📊 监控 {mid} 详情\n\n"
        text += f"名称: {row[2]}\nURL: {row[3]}\n"
        text += f"状态: {row[6] or '未知'}\n"
        text += f"最后检查: {row[7].strftime('%Y-%m-%d %H:%M') if row[7] else '从未'}\n\n"
        
        if logs:
            text += "最近5次检查:\n"
            for log in logs:
                emoji = "🟢" if 200 <= log[0] < 400 else "🔴"
                text += f"{emoji} {log[2].strftime('%m-%d %H:%M')} | 码:{log[0]} | {log[1]}ms\n"
        
        await update.message.reply_text(text)
    finally:
        conn.close()


# =========================
# Admin Commands
# =========================

@require_admin
async def adduser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 1:
        await update.message.reply_text("❌ 用法: /adduser <ID> [天数] [admin]")
        return
    
    try:
        new_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    days = int(context.args[1]) if len(context.args) > 1 else 30
    is_admin_flag = len(context.args) > 2 and context.args[2].lower() in ['true', '1', 'admin', 'yes']
    
    # 生成随机初始密码
    temp_password = secrets.token_hex(4)  # 8位随机密码
    
    expire = datetime.now() + timedelta(days=days)
    
    with db_lock:
        conn = db.get_conn()
        try:
            exists = conn.execute("SELECT 1 FROM authorized_users WHERE user_id = ?", [new_id]).fetchone()
            
            pwd_hash, pwd_salt = hash_password(temp_password)
            
            if exists:
                conn.execute("""
                UPDATE authorized_users 
                SET is_admin = ?, expire_at = ?, password_hash = ?, password_salt = ?, is_active = true
                WHERE user_id = ?
                """, [is_admin_flag, expire, pwd_hash, pwd_salt, new_id])
                action = "更新"
            else:
                conn.execute("""
                INSERT INTO authorized_users 
                (user_id, username, is_admin, expire_at, password_hash, password_salt, added_by)
                VALUES(?,?,?,?,?,?,?)
                """, [new_id, f"user_{new_id}", is_admin_flag, expire, pwd_hash, pwd_salt, update.effective_user.id])
                action = "添加"
            
            conn.commit()
            upload_db()
            
            role = "👑 管理员" if is_admin_flag else "👤 普通用户"
            await update.message.reply_text(
                f"✅ {action}成功!\n"
                f"🆔 ID: `{new_id}`\n"
                f"{role}\n"
                f"⏰ 过期: {expire.strftime('%Y-%m-%d')}\n"
                f"🔑 初始密码: `{temp_password}`\n"
                f"请提醒用户首次登录后修改密码！",
                parse_mode="Markdown"
            )
        finally:
            conn.close()


@require_admin
async def users_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    conn = db.get_conn()
    try:
        rows = conn.execute("""
        SELECT user_id, username, is_admin, is_active, expire_at, last_login, login_attempts
        FROM authorized_users ORDER BY added_at DESC
        """).fetchall()
        
        text = "👥 用户列表:\n\n"
        for r in rows:
            role = "👑" if r[2] else "👤"
            status = "🟢" if r[3] else "🔴"
            expire = r[4].strftime('%Y-%m-%d') if r[4] else '永久'
            last = r[5].strftime('%Y-%m-%d') if r[5] else '从未'
            text += f"{role}{status} `{r[0]}` ({r[1]})\n"
            text += f"过期:{expire} 最后登录:{last} 失败:{r[6] or 0}\n\n"
        
        await update.message.reply_text(text, parse_mode="Markdown")
    finally:
        conn.close()


@require_admin
async def deluser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ 用法: /deluser <用户ID>")
        return
    
    try:
        del_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    if del_id == ADMIN_USER_ID:
        await update.message.reply_text("⛔ 不能删除主管理员")
        return
    
    if del_id == update.effective_user.id:
        await update.message.reply_text("⛔ 不能删除自己")
        return
    
    with db_lock:
        conn = db.get_conn()
        try:
            # 软删除：标记为禁用而不是物理删除
            conn.execute("UPDATE authorized_users SET is_active = false WHERE user_id = ?", [del_id])
            conn.execute("UPDATE monitored_urls SET enabled = false WHERE user_id = ?", [del_id])
            conn.commit()
            upload_db()
            await update.message.reply_text(f"✅ 已禁用用户 {del_id} 及其所有监控")
        finally:
            conn.close()


@require_admin
async def toggle_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if not context.args:
        await update.message.reply_text("❌ 用法: /toggle <监控ID>")
        return
    
    try:
        mid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    with db_lock:
        conn = db.get_conn()
        try:
            row = conn.execute(
                "SELECT enabled, name FROM monitored_urls WHERE id = ?",
                [mid]
            ).fetchone()
            
            if not row:
                await update.message.reply_text("❌ 未找到")
                return
            
            new_status = not row[0]
            conn.execute("UPDATE monitored_urls SET enabled = ? WHERE id = ?", [new_status, mid])
            conn.commit()
            upload_db()
            
            emoji = "✅ 启用" if new_status else "❌ 禁用"
            await update.message.reply_text(f"{emoji}: {row[1]}")
        finally:
            conn.close()


@require_admin
async def resetpwd_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    if len(context.args) < 2:
        await update.message.reply_text("❌ 用法: /resetpwd <用户ID> <新密码>")
        return
    
    try:
        target_id = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    new_pwd = context.args[1]
    if len(new_pwd) < 6:
        await update.message.reply_text("❌ 密码至少6位")
        return
    
    admin_id = update.effective_user.id
    success, msg = AuthManager.reset_password(admin_id, target_id, new_pwd)
    await update.message.reply_text(f"{'✅' if success else '❌'} {msg}")


# =========================
# Bot Runner
# =========================

async def run_bot_async():
    app = Application.builder().token(BOT_TOKEN).build()
    
    # 公开命令
    app.add_handler(CommandHandler("start", start_cmd))
    
    # 需授权
    app.add_handler(CommandHandler("add", add_cmd))
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("delete", delete_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    
    # 管理员
    app.add_handler(CommandHandler("adduser", adduser_cmd))
    app.add_handler(CommandHandler("users", users_cmd))
    app.add_handler(CommandHandler("deluser", deluser_cmd))
    app.add_handler(CommandHandler("toggle", toggle_cmd))
    app.add_handler(CommandHandler("resetpwd", resetpwd_cmd))

    await app.initialize()
    await app.start()
    await app.updater.start_polling()

    while True:
        await asyncio.sleep(1)


def run_bot():
    asyncio.run(run_bot_async())


# 启动 Bot 线程
if st.session_state.bot_thread is None:
    t = threading.Thread(target=run_bot, daemon=True)
    t.start()
    st.session_state.bot_thread = t


# =========================
# Streamlit UI - Authentication
# =========================

def render_login_page():
    """渲染登录页面"""
    st.markdown("""
    <style>
    .login-container {
        max-width: 400px;
        margin: 0 auto;
        padding: 2rem;
        border-radius: 10px;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        background: #f8f9fa;
    }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-container">', unsafe_allow_html=True)
        st.markdown("### 🔐 用户登录")
        
        # 尝试从 cookie 或 query param 获取记住的 ID
        default_id = ""
        
        user_id = st.number_input("用户 ID (Telegram ID)", value=int(default_id) if default_id else 0, step=1)
        password = st.text_input("密码", type="password")
        
        col_login, col_reg = st.columns(2)
        
        with col_login:
            if st.button("🔑 登录", use_container_width=True):
                # 获取 IP（在 Streamlit Cloud 可能不准确，仅作记录）
                ip = "unknown"
                
                success, user_info, msg = AuthManager.authenticate(int(user_id), password, ip)
                
                if success:
                    st.session_state.authenticated = True
                    st.session_state.user_id = int(user_id)
                    st.session_state.user_info = user_info
                    st.session_state.login_time = datetime.now()
                    st.session_state.session_token = generate_session_token(int(user_id))
                    st.success(msg)
                    time.sleep(1)
                    st.rerun()
                else:
                    st.error(msg)
        
        with col_reg:
            # 检查是否开放注册（可选功能）
            st.button("📝 注册", use_container_width=True, disabled=True, 
                     help="请联系管理员添加账户")
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # 显示初始管理员提示
        st.info("💡 初始管理员 ID: 你的 Telegram ID，默认密码: admin123")


def render_dashboard():
    """渲染主控制台"""
    user = st.session_state.user_info
    is_admin = user.get("is_admin", False)
    
    # 顶部栏
    col1, col2, col3 = st.columns([2, 2, 1])
    with col1:
        st.write(f"👋 欢迎, **{user.get('username', 'User')}**")
        st.caption(f"ID: {st.session_state.user_id} | {'👑 管理员' if is_admin else '👤 普通用户'}")
    with col2:
        if user.get("expire_at"):
            days_left = (user["expire_at"] - datetime.now()).days
            if days_left < 7:
                st.warning(f"⏰ 账户将在 {days_left} 天后过期")
    with col3:
        if st.button("🚪 退出登录", use_container_width=True):
            for key in ["authenticated", "user_id", "user_info", "login_time", "session_token"]:
                st.session_state[key] = None
            st.rerun()
    
    st.divider()
    
    # 侧边栏功能
    with st.sidebar:
        st.header("⚙️ 控制面板")
        
        # 同步数据库
        if st.button("🔄 同步到 R2", use_container_width=True):
            upload_db()
            st.success("✅ 已同步")
        
        # 修改密码
        with st.expander("🔐 修改密码"):
            old_pwd = st.text_input("原密码", type="password", key="old")
            new_pwd = st.text_input("新密码", type="password", key="new")
            confirm_pwd = st.text_input("确认新密码", type="password", key="confirm")
            
            if st.button("确认修改", use_container_width=True):
                if new_pwd != confirm_pwd:
                    st.error("两次输入不一致")
                elif len(new_pwd) < 6:
                    st.error("密码至少6位")
                else:
                    success, msg = AuthManager.change_password(
                        st.session_state.user_id, old_pwd, new_pwd
                    )
                    if success:
                        st.success(msg)
                    else:
                        st.error(msg)
        
        # 管理员专属
        if is_admin:
            st.divider()
            st.header("🔧 管理员功能")
            
            # 添加用户
            with st.expander("➕ 添加用户"):
                new_id = st.number_input("Telegram ID", step=1, value=0, key="new_uid")
                new_username = st.text_input("用户名", key="new_uname")
                new_days = st.number_input("有效期(天)", min_value=1, value=30, key="new_days")
                new_is_admin = st.checkbox("设为管理员", key="new_admin")
                
                if st.button("添加用户", use_container_width=True):
                    # 生成随机密码
                    temp_pwd = secrets.token_hex(4)
                    
                    conn = db.get_conn()
                    try:
                        expire = datetime.now() + timedelta(days=new_days)
                        pwd_hash, pwd_salt = hash_password(temp_pwd)
                        
                        conn.execute("""
                        INSERT INTO authorized_users 
                        (user_id, username, is_admin, expire_at, password_hash, password_salt, added_by)
                        VALUES(?,?,?,?,?,?,?)
                        """, [int(new_id), new_username or f"user_{new_id}", 
                              new_is_admin, expire, pwd_hash, pwd_salt, 
                              st.session_state.user_id])
                        conn.commit()
                        upload_db()
                        
                        st.success(f"✅ 添加成功！初始密码: `{temp_pwd}`")
                        st.info("请复制此密码告知用户，首次登录后需修改")
                    except Exception as e:
                        st.error(f"❌ 失败: {e}")
                    finally:
                        conn.close()
            
            # 用户管理
            with st.expander("👥 管理用户"):
                conn = db.get_conn()
                try:
                    users_df = conn.execute("""
                    SELECT user_id, username, is_admin, is_active, expire_at, last_login, login_attempts
                    FROM authorized_users
                    ORDER BY added_at DESC
                    """).fetchdf()
                    
                    st.dataframe(users_df, use_container_width=True, hide_index=True)
                    
                    # 操作选择
                    action_user = st.number_input("目标用户ID", step=1, value=0, key="act_uid")
                    action = st.selectbox("操作", ["重置密码", "禁用账户", "启用账户", "删除账户"])
                    
                    if st.button("执行", use_container_width=True):
                        if action == "重置密码":
                            new_pwd = st.text_input("新密码", value=secrets.token_hex(4))
                            success, msg = AuthManager.reset_password(
                                st.session_state.user_id, int(action_user), new_pwd
                            )
                            st.info(f"新密码: `{new_pwd}`" if success else msg)
                        elif action == "禁用账户":
                            conn.execute("UPDATE authorized_users SET is_active = false WHERE user_id = ?", 
                                       [int(action_user)])
                            conn.commit()
                            st.success("已禁用")
                        elif action == "启用账户":
                            conn.execute("UPDATE authorized_users SET is_active = true WHERE user_id = ?", 
                                       [int(action_user)])
                            conn.commit()
                            st.success("已启用")
                        elif action == "删除账户":
                            if action_user == ADMIN_USER_ID:
                                st.error("不能删除主管理员")
                            else:
                                conn.execute("DELETE FROM authorized_users WHERE user_id = ?", 
                                           [int(action_user)])
                                conn.execute("DELETE FROM monitored_urls WHERE user_id = ?", 
                                           [int(action_user)])
                                conn.commit()
                                st.success("已删除")
                        upload_db()
                finally:
                    conn.close()
            
            # 登录历史
            with st.expander("📜 登录历史"):
                conn = db.get_conn()
                try:
                    history = conn.execute("""
                    SELECT h.user_id, u.username, h.login_time, h.success, h.failure_reason
                    FROM login_history h
                    LEFT JOIN authorized_users u ON h.user_id = u.user_id
                    ORDER BY h.login_time DESC
                    LIMIT 50
                    """).fetchdf()
                    st.dataframe(history, use_container_width=True)
                finally:
                    conn.close()
    
    # 主内容区
    st.subheader("📊 监控概览")
    
    conn = db.get_conn()
    try:
        # 统计卡片
        col1, col2, col3, col4 = st.columns(4)
        
        if is_admin:
            total_users = conn.execute("SELECT COUNT(*) FROM authorized_users WHERE is_active = true").fetchone()[0]
            total_monitors = conn.execute("SELECT COUNT(*) FROM monitored_urls").fetchone()[0]
            active_monitors = conn.execute("SELECT COUNT(*) FROM monitored_urls WHERE enabled = true").fetchone()[0]
            down_monitors = conn.execute("SELECT COUNT(*) FROM monitored_urls WHERE last_status = 'DOWN'").fetchone()[0]
        else:
            uid = st.session_state.user_id
            total_users = 1
            total_monitors = conn.execute("SELECT COUNT(*) FROM monitored_urls WHERE user_id = ?", [uid]).fetchone()[0]
            active_monitors = conn.execute("SELECT COUNT(*) FROM monitored_urls WHERE user_id = ? AND enabled = true", [uid]).fetchone()[0]
            down_monitors = conn.execute("SELECT COUNT(*) FROM monitored_urls WHERE user_id = ? AND last_status = 'DOWN'", [uid]).fetchone()[0]
        
        col1.metric("👥 用户", total_users)
        col2.metric("📊 监控项", total_monitors)
        col3.metric("✅ 运行中", active_monitors)
        col4.metric("🔴 异常", down_monitors)
        
        st.divider()
        
        # 监控列表
        st.subheader("📋 监控列表")
        
        if is_admin:
            df = conn.execute("""
            SELECT m.id, m.name, m.url, m.last_status, m.enabled, 
                   m.interval_seconds, m.last_check_time, m.user_id, u.username
            FROM monitored_urls m
            LEFT JOIN authorized_users u ON m.user_id = u.user_id
            ORDER BY m.id DESC
            """).fetchdf()
        else:
            df = conn.execute("""
            SELECT id, name, url, last_status, enabled, 
                   interval_seconds, last_check_time
            FROM monitored_urls 
            WHERE user_id = ?
            ORDER BY id DESC
            """, [st.session_state.user_id]).fetchdf()
        
        if not df.empty:
            # 状态颜色标记
            def color_status(val):
                if val == "UP":
                    return "background-color: #d4edda"
                elif val == "DOWN":
                    return "background-color: #f8d7da"
                return ""
            
            styled_df = df.style.applymap(color_status, subset=['last_status'])
            st.dataframe(styled_df, use_container_width=True, height=400)
            
            # 操作区
            if is_admin:
                with st.expander("⚡ 快捷操作"):
                    cols = st.columns(3)
                    with cols[0]:
                        toggle_id = st.number_input("监控ID", step=1, value=0, key="tog_id")
                    with cols[1]:
                        if st.button("切换状态", use_container_width=True):
                            current = conn.execute("SELECT enabled FROM monitored_urls WHERE id = ?", 
                                                 [int(toggle_id)]).fetchone()
                            if current:
                                new_val = not current[0]
                                conn.execute("UPDATE monitored_urls SET enabled = ? WHERE id = ?", 
                                           [new_val, int(toggle_id)])
                                conn.commit()
                                upload_db()
                                st.success(f"已{'启用' if new_val else '禁用'}")
                                st.rerun()
                    with cols[2]:
                        if st.button("删除监控", use_container_width=True):
                            conn.execute("DELETE FROM monitored_urls WHERE id = ?", [int(toggle_id)])
                            conn.commit()
                            upload_db()
                            st.success("已删除")
                            st.rerun()
        else:
            st.info("暂无监控数据，使用 Telegram Bot 添加")
            
    finally:
        conn.close()


# =========================
# Main App Logic
# =========================

if not st.session_state.authenticated:
    render_login_page()
else:
    # 验证 session 是否过期
    if st.session_state.session_token:
        uid, valid = verify_session_token(st.session_state.session_token)
        if not valid or uid != st.session_state.user_id:
            st.session_state.authenticated = False
            st.error("会话已过期，请重新登录")
            st.rerun()
    
    render_dashboard()

# 底部信息
st.divider()
st.caption("🤖 URL Monitor Bot | 安全监控系统")
