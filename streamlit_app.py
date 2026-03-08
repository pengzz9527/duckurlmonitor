# =========================
# 更新后的完整代码（依赖优化版）
# =========================

# pip install streamlit>=1.32.0 duckdb>=0.10.0 boto3>=1.34.0 python-telegram-bot>=21.0 apscheduler>=3.10.4 requests>=2.31.0 cryptography>=42.0.0 pandas>=2.2.0

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
import logging
from datetime import datetime, timedelta
from threading import Lock

# 新增：使用 cryptography 替代标准库进行高级加密（可选）
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    st.warning("cryptography 包未安装，使用标准库加密")

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_ERROR, EVENT_JOB_EXECUTED

# 新增：pandas 用于数据展示
import pandas as pd
import numpy as np

# =========================
# Logging Configuration (新增)
# =========================

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('/tmp/url_monitor.log')
    ]
)
logger = logging.getLogger(__name__)

# =========================
# Streamlit UI Config
# =========================

st.set_page_config(
    page_title="URL Monitor Bot",
    page_icon="🤖",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        'Get Help': 'https://github.com/your-repo',
        'Report a bug': "https://github.com/your-repo/issues",
        'About': "# URL Monitor Bot\n安全监控系统 v2.0"
    }
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
        "bot_thread": None,
        "db_version": None  # 新增：数据库版本追踪
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value

init_session_state()

# =========================
# Secrets
# =========================

try:
    BOT_TOKEN = st.secrets["BOT_TOKEN"]
    ADMIN_USER_ID = int(st.secrets["ADMIN_USER_ID"])
    
    R2_ENDPOINT = st.secrets["R2_ENDPOINT"]
    R2_ACCESS_KEY = st.secrets["R2_ACCESS_KEY"]
    R2_SECRET_KEY = st.secrets["R2_SECRET_KEY"]
    R2_BUCKET = st.secrets["R2_BUCKET"]
    R2_DB_KEY = st.secrets.get("R2_DB_KEY", "url_monitor.duckdb")
    
    SYSTEM_SECRET = st.secrets.get("SYSTEM_SECRET", secrets.token_hex(32))
    ENCRYPTION_KEY = st.secrets.get("ENCRYPTION_KEY")  # 新增：用于 Fernet 加密
    
except Exception as e:
    logger.error(f"Secrets loading failed: {e}")
    st.error("⚠️ 配置加载失败，请检查 secrets.toml")
    st.stop()

# =========================
# Paths
# =========================

DB_DIR = "/tmp"
DB_FILE = os.path.join(DB_DIR, "url_monitor.duckdb")

# =========================
# R2 Client (优化：添加重试和超时)
# =========================

from botocore.config import Config

s3_config = Config(
    retries={'max_attempts': 3, 'mode': 'standard'},
    connect_timeout=10,
    read_timeout=30
)

s3 = boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY,
    aws_secret_access_key=R2_SECRET_KEY,
    config=s3_config
)

# =========================
# Lock & Metrics (新增)
# =========================

db_lock = Lock()
last_upload = 0
upload_metrics = {"success": 0, "failed": 0, "last_error": None}

# =========================
# Enhanced Crypto Functions
# =========================

class CryptoManager:
    """增强加密管理器，优先使用 cryptography 库"""
    
    @staticmethod
    def hash_password(password: str, salt: str = None) -> tuple:
        """使用 PBKDF2 哈希密码"""
        if salt is None:
            salt = secrets.token_hex(16)
        
        if CRYPTO_AVAILABLE:
            # 使用 cryptography 库（更安全）
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt.encode(),
                iterations=600000,  # OWASP 2023 推荐
            )
            pwdhash = kdf.derive(password.encode())
            return pwdhash.hex(), salt
        else:
            # 回退到标准库
            pwdhash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return pwdhash.hex(), salt
    
    @staticmethod
    def verify_password(password: str, hashed: str, salt: str) -> bool:
        """验证密码"""
        try:
            pwdhash, _ = CryptoManager.hash_password(password, salt)
            # 使用 secrets.compare_digest 防止时序攻击
            return secrets.compare_digest(pwdhash, hashed)
        except Exception:
            return False
    
    @staticmethod
    def encrypt_data(data: str) -> str:
        """使用 Fernet 加密敏感数据（可选功能）"""
        if not CRYPTO_AVAILABLE or not ENCRYPTION_KEY:
            return data  # 回退：不加密
        
        try:
            f = Fernet(ENCRYPTION_KEY.encode())
            return f.encrypt(data.encode()).decode()
        except Exception:
            return data
    
    @staticmethod
    def decrypt_data(token: str) -> str:
        """解密数据"""
        if not CRYPTO_AVAILABLE or not ENCRYPTION_KEY:
            return token
        
        try:
            f = Fernet(ENCRYPTION_KEY.encode())
            return f.decrypt(token.encode()).decode()
        except Exception:
            return token


def generate_session_token(user_id: int) -> str:
    """生成带签名的会话令牌"""
    timestamp = str(int(time.time()))
    nonce = secrets.token_hex(8)
    data = f"{user_id}:{timestamp}:{nonce}:{SYSTEM_SECRET}"
    signature = hashlib.sha256(data.encode()).hexdigest()[:16]
    return f"{user_id}:{timestamp}:{nonce}:{signature}"


def verify_session_token(token: str, max_age: int = 86400) -> tuple:
    """验证会话令牌"""
    try:
        parts = token.split(":")
        if len(parts) != 4:
            return None, False
        
        user_id, timestamp, nonce, signature = parts
        user_id = int(user_id)
        timestamp = int(timestamp)
        
        # 检查过期时间
        if time.time() - timestamp > max_age:
            return user_id, False
        
        # 验证签名
        expected_data = f"{user_id}:{timestamp}:{nonce}:{SYSTEM_SECRET}"
        expected_sig = hashlib.sha256(expected_data.encode()).hexdigest()[:16]
        
        if not secrets.compare_digest(signature, expected_sig):
            return user_id, False
            
        return user_id, True
    except Exception as e:
        logger.warning(f"Token verification failed: {e}")
        return None, False


# =========================
# R2 Operations (优化：添加日志和重试)
# =========================

def download_db():
    """从 R2 下载数据库，带重试逻辑"""
    max_retries = 3
    for attempt in range(max_retries):
        try:
            logger.info(f"Downloading DB from R2 (attempt {attempt + 1})")
            s3.download_file(R2_BUCKET, R2_DB_KEY, DB_FILE)
            logger.info("✅ DB downloaded successfully")
            return True
        except Exception as e:
            logger.warning(f"Download attempt {attempt + 1} failed: {e}")
            if attempt == max_retries - 1:
                logger.error("All download attempts failed, creating new DB")
            time.sleep(2 ** attempt)  # 指数退避
    return False


def upload_db(force: bool = False):
    """上传到 R2，带防抖和错误处理"""
    global last_upload, upload_metrics
    
    if not os.path.exists(DB_FILE):
        return False
    
    if not force and time.time() - last_upload < 10:
        return False
    
    try:
        logger.info("Uploading DB to R2")
        s3.upload_file(DB_FILE, R2_BUCKET, R2_DB_KEY)
        last_upload = time.time()
        upload_metrics["success"] += 1
        logger.info("☁️ DB uploaded successfully")
        return True
    except Exception as e:
        upload_metrics["failed"] += 1
        upload_metrics["last_error"] = str(e)
        logger.error(f"Upload failed: {e}")
        return False


# 初始化下载
download_db()


# =========================
# Database (优化：添加版本控制和迁移)
# =========================

class Database:
    CURRENT_VERSION = 2  # 数据库架构版本
    
    def __init__(self, file):
        self.file = file
        self.init_db()
        self.migrate()

    def get_conn(self):
        return duckdb.connect(self.file)

    def init_db(self):
        """初始化数据库架构"""
        conn = self.get_conn()
        try:
            conn.execute("CREATE SEQUENCE IF NOT EXISTS seq START 1")
            
            # 元数据表（新增：用于版本控制）
            conn.execute("""
            CREATE TABLE IF NOT EXISTS db_metadata (
                key TEXT PRIMARY KEY,
                value TEXT,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """)
            
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
                locked_until TIMESTAMP,
                email TEXT,  -- 新增：用于通知
                notify_enabled BOOLEAN DEFAULT true  -- 新增：是否接收通知
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
                notify_on_down BOOLEAN DEFAULT true,  -- 新增：宕机通知
                expected_keyword TEXT,  -- 新增：关键字监控
                PRIMARY KEY(id)
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS visit_logs(
                id BIGINT DEFAULT nextval('seq'),
                monitor_id BIGINT,
                status_code INTEGER,
                response_time_ms INTEGER,
                visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                error_message TEXT  -- 新增：错误详情
            )
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS login_history(
                id BIGINT DEFAULT nextval('seq'),
                user_id BIGINT,
                login_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                ip_address TEXT,
                user_agent TEXT,  -- 新增
                success BOOLEAN,
                failure_reason TEXT,
                session_token TEXT  -- 新增：用于审计
            )
            """)

            # 初始化管理员（使用更安全的默认密码流程）
            admin = conn.execute(
                "SELECT count(*) FROM authorized_users WHERE user_id=?",
                [ADMIN_USER_ID]
            ).fetchone()[0]

            if admin == 0:
                temp_pwd = secrets.token_urlsafe(12)
                pwd_hash, pwd_salt = CryptoManager.hash_password(temp_pwd)
                
                conn.execute("""
                INSERT INTO authorized_users 
                (user_id, username, password_hash, password_salt, is_admin, expire_at, added_by, is_active)
                VALUES(?,?,?,?,?,?,?,true)
                """, [
                    ADMIN_USER_ID,
                    "admin",
                    pwd_hash,
                    pwd_salt,
                    True,
                    datetime.now() + timedelta(days=3650),
                    ADMIN_USER_ID
                ])
                
                # 记录初始密码到日志（实际生产环境应通过安全渠道发送）
                logger.critical(f"🚨 INITIAL ADMIN PASSWORD: {temp_pwd}")
                print(f"⚠️ 初始管理员密码: {temp_pwd} （请立即修改！）")
                
                conn.execute("""
                INSERT INTO db_metadata (key, value) 
                VALUES ('db_version', ?), ('created_at', ?)
                ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = CURRENT_TIMESTAMP
                """, [str(self.CURRENT_VERSION), datetime.now().isoformat()])

            conn.commit()
            upload_db()
        finally:
            conn.close()

    def migrate(self):
        """数据库迁移逻辑"""
        conn = self.get_conn()
        try:
            # 获取当前版本
            result = conn.execute(
                "SELECT value FROM db_metadata WHERE key = 'db_version'"
            ).fetchone()
            current_ver = int(result[0]) if result else 1
            
            if current_ver < self.CURRENT_VERSION:
                logger.info(f"Migrating DB from v{current_ver} to v{self.CURRENT_VERSION}")
                
                # 执行迁移
                if current_ver < 2:
                    # v1 -> v2: 添加新列
                    try:
                        conn.execute("ALTER TABLE authorized_users ADD COLUMN email TEXT")
                        conn.execute("ALTER TABLE authorized_users ADD COLUMN notify_enabled BOOLEAN DEFAULT true")
                        conn.execute("ALTER TABLE monitored_urls ADD COLUMN notify_on_down BOOLEAN DEFAULT true")
                        conn.execute("ALTER TABLE monitored_urls ADD COLUMN expected_keyword TEXT")
                        conn.execute("ALTER TABLE visit_logs ADD COLUMN error_message TEXT")
                        conn.execute("ALTER TABLE login_history ADD COLUMN user_agent TEXT")
                        conn.execute("ALTER TABLE login_history ADD COLUMN session_token TEXT")
                    except Exception as e:
                        logger.warning(f"Migration columns might already exist: {e}")
                
                # 更新版本号
                conn.execute("""
                INSERT INTO db_metadata (key, value) VALUES ('db_version', ?)
                ON CONFLICT (key) DO UPDATE SET value = excluded.value
                """, [str(self.CURRENT_VERSION)])
                conn.commit()
                upload_db()
                logger.info("Migration completed")
        finally:
            conn.close()


db = Database(DB_FILE)


# =========================
# Authentication System (优化)
# =========================

class AuthManager:
    MAX_ATTEMPTS = 5
    LOCKOUT_MINUTES = 30
    
    @staticmethod
    def authenticate(user_id: int, password: str, ip_address: str = None, user_agent: str = None) -> tuple:
        """增强版认证，包含更多审计信息"""
        conn = db.get_conn()
        try:
            row = conn.execute("""
            SELECT user_id, username, password_hash, password_salt, is_admin, 
                   is_active, expire_at, locked_until, login_attempts, notify_enabled
            FROM authorized_users 
            WHERE user_id = ?
            """, [user_id]).fetchone()
            
            if not row:
                AuthManager._log_login(conn, user_id, ip_address, user_agent, False, "用户不存在", None)
                return False, None, "用户不存在或密码错误"  # 模糊提示
            
            (uid, username, pwd_hash, pwd_salt, is_admin, 
             is_active, expire_at, locked_until, attempts, notify_enabled) = row
            
            # 检查锁定
            if locked_until and datetime.now() < locked_until:
                remaining = int((locked_until - datetime.now()).total_seconds() / 60)
                return False, None, f"账户已锁定，请 {remaining} 分钟后重试"
            
            # 检查激活状态
            if not is_active:
                AuthManager._log_login(conn, user_id, ip_address, user_agent, False, "账户已禁用", None)
                return False, None, "账户已禁用"
            
            # 检查过期
            if expire_at and datetime.now() > expire_at:
                conn.execute("UPDATE authorized_users SET is_active = false WHERE user_id = ?", [user_id])
                AuthManager._log_login(conn, user_id, ip_address, user_agent, False, "账户已过期", None)
                conn.commit()
                return False, None, "账户已过期，请联系管理员"
            
            # 验证密码
            if not CryptoManager.verify_password(password, pwd_hash, pwd_salt):
                new_attempts = (attempts or 0) + 1
                lock_until = None
                
                if new_attempts >= AuthManager.MAX_ATTEMPTS:
                    lock_until = datetime.now() + timedelta(minutes=AuthManager.LOCKOUT_MINUTES)
                    new_attempts = 0
                    logger.warning(f"User {user_id} locked due to too many failed attempts")
                
                conn.execute("""
                UPDATE authorized_users 
                SET login_attempts = ?, locked_until = ? 
                WHERE user_id = ?
                """, [new_attempts, lock_until, user_id])
                
                AuthManager._log_login(conn, user_id, ip_address, user_agent, False, "密码错误", None)
                conn.commit()
                
                if lock_until:
                    return False, None, "密码错误次数过多，账户已锁定30分钟"
                return False, None, "用户不存在或密码错误"
            
            # 成功登录
            session_token = generate_session_token(uid)
            conn.execute("""
            UPDATE authorized_users 
            SET login_attempts = 0, locked_until = NULL, last_login = ? 
            WHERE user_id = ?
            """, [datetime.now(), user_id])
            
            user_info = {
                "user_id": uid,
                "username": username,
                "is_admin": is_admin,
                "expire_at": expire_at,
                "notify_enabled": notify_enabled
            }
            
            AuthManager._log_login(conn, user_id, ip_address, user_agent, True, None, session_token)
            conn.commit()
            
            return True, user_info, "登录成功"
            
        finally:
            conn.close()
    
    @staticmethod
    def _log_login(conn, user_id, ip, user_agent, success, failure_reason, session_token):
        """记录登录历史"""
        try:
            conn.execute("""
            INSERT INTO login_history 
            (user_id, ip_address, user_agent, success, failure_reason, session_token)
            VALUES(?,?,?,?,?,?)
            """, [user_id, ip, user_agent, success, failure_reason, session_token])
        except Exception as e:
            logger.error(f"Failed to log login: {e}")
    
    @staticmethod
    def change_password(user_id: int, old_password: str, new_password: str) -> tuple:
        """修改密码，强制要求更复杂"""
        if len(new_password) < 8:  # 提升至8位
            return False, "新密码至少需要8位"
        
        # 简单复杂性检查
        if not any(c.isupper() for c in new_password):
            return False, "密码需包含大写字母"
        if not any(c.islower() for c in new_password):
            return False, "密码需包含小写字母"
        if not any(c.isdigit() for c in new_password):
            return False, "密码需包含数字"
        
        conn = db.get_conn()
        try:
            row = conn.execute(
                "SELECT password_hash, password_salt FROM authorized_users WHERE user_id = ?",
                [user_id]
            ).fetchone()
            
            if not row:
                return False, "用户不存在"
            
            if not CryptoManager.verify_password(old_password, row[0], row[1]):
                return False, "原密码错误"
            
            new_hash, new_salt = CryptoManager.hash_password(new_password)
            conn.execute("""
            UPDATE authorized_users 
            SET password_hash = ?, password_salt = ? 
            WHERE user_id = ?
            """, [new_hash, new_salt, user_id])
            conn.commit()
            upload_db()
            
            logger.info(f"User {user_id} changed password")
            return True, "密码修改成功，请使用新密码重新登录"
        finally:
            conn.close()
    
    @staticmethod
    def reset_password(admin_id: int, target_user_id: int, new_password: str = None) -> tuple:
        """管理员重置密码，生成随机强密码"""
        if new_password is None:
            # 生成16位随机密码
            new_password = secrets.token_urlsafe(12)
        
        if len(new_password) < 8:
            return False, "密码至少8位"
        
        conn = db.get_conn()
        try:
            admin = conn.execute(
                "SELECT is_admin FROM authorized_users WHERE user_id = ? AND is_active = true",
                [admin_id]
            ).fetchone()
            
            if not admin or not admin[0]:
                return False, "无权限"
            
            target = conn.execute(
                "SELECT user_id, username FROM authorized_users WHERE user_id = ?",
                [target_user_id]
            ).fetchone()
            
            if not target:
                return False, "目标用户不存在"
            
            new_hash, new_salt = CryptoManager.hash_password(new_password)
            conn.execute("""
            UPDATE authorized_users 
            SET password_hash = ?, password_salt = ?, login_attempts = 0, locked_until = NULL 
            WHERE user_id = ?
            """, [new_hash, new_salt, target_user_id])
            conn.commit()
            upload_db()
            
            logger.info(f"Admin {admin_id} reset password for user {target_user_id}")
            return True, new_password  # 返回生成的密码
        finally:
            conn.close()


# =========================
# URL Check (优化：添加内容和 SSL 检查)
# =========================

def check_url(url: str, expected_keyword: str = None, verify_ssl: bool = True) -> tuple:
    """
    增强版 URL 检查
    返回: (status, code, cost_ms, error_msg, content_match)
    """
    start = time.time()
    error_msg = None
    content_match = None
    
    try:
        headers = {
            'User-Agent': 'URL-Monitor-Bot/2.0 (+https://github.com/your-repo)'
        }
        
        r = requests.get(
            url, 
            timeout=10, 
            headers=headers,
            verify=verify_ssl,
            allow_redirects=True
        )
        
        code = r.status_code
        status = "UP" if 200 <= code < 400 else "DOWN"
        
        # 关键字检查
        if expected_keyword and status == "UP":
            content_match = expected_keyword in r.text
            if not content_match:
                status = "DOWN"  # 关键字不匹配视为宕机
                error_msg = f"Keyword '{expected_keyword}' not found"
        
    except requests.exceptions.SSLError as e:
        code = -2
        status = "DOWN"
        error_msg = f"SSL Error: {str(e)}"
    except requests.exceptions.Timeout:
        code = -1
        status = "DOWN"
        error_msg = "Timeout"
    except requests.exceptions.RequestException as e:
        code = -1
        status = "DOWN"
        error_msg = str(e)
    except Exception as e:
        code = -1
        status = "DOWN"
        error_msg = f"Unexpected: {str(e)}"
    
    cost = int((time.time() - start) * 1000)
    return status, code, cost, error_msg, content_match


def check_monitor_task(mid, uid, name, url, expected_keyword=None):
    """增强版监控任务"""
    with db_lock:
        conn = db.get_conn()
        try:
            status, code, cost, error_msg, content_match = check_url(url, expected_keyword)
            now = datetime.now()

            conn.execute(
                "UPDATE monitored_urls SET last_status=?, last_check_time=? WHERE id=?",
                [status, now, mid]
            )
            conn.execute(
                """INSERT INTO visit_logs 
                (monitor_id, status_code, response_time_ms, visit_time, error_message) 
                VALUES(?,?,?,?,?)""",
                [mid, code, cost, now, error_msg]
            )
            conn.commit()
            upload_db()
            
            # 如果状态为 DOWN 且用户启用了通知，这里可以触发 Telegram 通知
            if status == "DOWN":
                logger.warning(f"Monitor {mid} ({name}) is DOWN: {error_msg}")
                
        except Exception as e:
            logger.error(f"Check task failed for monitor {mid}: {e}")
        finally:
            conn.close()


# =========================
# Scheduler (优化：添加事件监听)
# =========================

def run_checks():
    """执行所有启用的监控检查"""
    conn = db.get_conn()
    try:
        rows = conn.execute("""
        SELECT id, user_id, name, url, expected_keyword 
        FROM monitored_urls 
        WHERE enabled = true
        """).fetchall()
    finally:
        conn.close()

    for r in rows:
        try:
            check_monitor_task(*r)
        except Exception as e:
            logger.error(f"Failed to check monitor {r[0]}: {e}")


def scheduler_listener(event):
    """监听调度器事件"""
    if event.exception:
        logger.error(f"Job crashed: {event.exception}")
    else:
        logger.debug(f"Job executed: {event.job_id}")


scheduler = BackgroundScheduler({
    'apscheduler.job_defaults.max_instances': 3,
    'apscheduler.timezone': 'UTC'
})
scheduler.add_job(run_checks, "interval", minutes=1, id='url_checker', replace_existing=True)
scheduler.add_job(lambda: upload_db(force=True), "interval", minutes=5, id='db_backup', replace_existing=True)
scheduler.add_listener(scheduler_listener, EVENT_JOB_ERROR | EVENT_JOB_EXECUTED)
scheduler.start()

logger.info("Scheduler started")


# =========================
# Telegram Commands (优化：使用装饰器工厂)
# =========================

def require_auth(level="user"):
    """权限装饰器工厂"""
    def decorator(func):
        @functools.wraps(func)
        async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
            user_id = update.effective_user.id
            
            conn = db.get_conn()
            try:
                row = conn.execute("""
                SELECT user_id, is_admin, is_active, expire_at, username, notify_enabled
                FROM authorized_users 
                WHERE user_id = ? AND is_active = true
                """, [user_id]).fetchone()
                
                if not row:
                    await update.message.reply_text("⛔ 未经授权，请联系管理员")
                    return
                
                if row[3] and datetime.now() > row[3]:
                    await update.message.reply_text("⛔ 账户已过期")
                    return
                
                if level == "admin" and not row[1]:
                    await update.message.reply_text("⛔ 需要管理员权限")
                    return
                
                context.user_data["user_info"] = {
                    "user_id": row[0],
                    "is_admin": row[1],
                    "username": row[4],
                    "notify_enabled": row[5]
                }
            finally:
                conn.close()
            
            return await func(update, context)
        return wrapper
    return decorator


# =========================
# Telegram Handlers (优化：添加更多命令)
# =========================

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """增强版 start 命令"""
    uid = update.effective_user.id
    
    conn = db.get_conn()
    try:
        row = conn.execute("""
        SELECT is_admin, is_active, expire_at, username, notify_enabled, last_login
        FROM authorized_users WHERE user_id = ?
        """, [uid]).fetchone()
        
        if not row:
            await update.message.reply_text(
                f"👋 你好！\n"
                f"🆔 你的 Telegram ID: `{uid}`\n"
                f"⛔ 未授权访问\n"
                f"请联系管理员添加账户",
                parse_mode="Markdown"
            )
            return
        
        role = "👑 管理员" if row[0] else "👤 普通用户"
        expire = row[2].strftime("%Y-%m-%d") if row[2] else "永久"
        last = row[5].strftime("%Y-%m-%d %H:%M") if row[5] else "从未"
        
        msg = f"👋 欢迎，{row[3]}！\n\n"
        msg += f"{role} | ID: `{uid}`\n"
        msg += f"⏰ 过期: {expire} | 上次登录: {last}\n\n"
        msg += "📋 命令:\n"
        msg += "/add `<名称>` `<URL>` `<秒数>` - 添加监控\n"
        msg += "/list - 查看监控\n"
        msg += "/delete `<ID>` - 删除监控\n"
        msg += "/status `<ID>` - 详情\n"
        msg += "/stats - 统计信息\n"
        
        if row[0]:
            msg += "\n🔧 管理:\n"
            msg += "/adduser `<ID>` `[天数]` `[admin]` - 添加用户\n"
            msg += "/users - 用户列表\n"
            msg += "/deluser `<ID>` - 禁用用户\n"
            msg += "/toggle `<ID>` - 切换监控状态\n"
            msg += "/resetpwd `<ID>` - 重置密码\n"
            msg += "/broadcast `<消息>` - 广播消息"
        
        await update.message.reply_text(msg, parse_mode="Markdown")
    finally:
        conn.close()


@require_auth("user")
async def add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """添加监控（支持关键字检查）"""
    args = context.args
    if len(args) < 3:
        await update.message.reply_text(
            "❌ 用法: /add `<名称>` `<URL>` `<间隔秒数>` `[关键字]`",
            parse_mode="Markdown"
        )
        return
    
    name, url, sec = args[0], args[1], args[2]
    keyword = args[3] if len(args) > 3 else None
    
    try:
        sec = int(sec)
        if sec < 60:
            raise ValueError("Too small")
    except:
        await update.message.reply_text("❌ 间隔至少60秒")
        return
    
    if not url.startswith(('http://', 'https://')):
        await update.message.reply_text("❌ URL 必须以 http:// 或 https:// 开头")
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
            INSERT INTO monitored_urls 
            (user_id, name, url, interval_seconds, expected_keyword)
            VALUES(?,?,?,?,?)
            """, [uid, name, url, sec, keyword])
            conn.commit()
            upload_db()
            
            msg = f"✅ 已添加: {name}\n🔗 {url}\n⏱️ {sec}秒"
            if keyword:
                msg += f"\n🔍 关键字: {keyword}"
            await update.message.reply_text(msg)
        finally:
            conn.close()


@require_auth("user")
async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """查看监控列表"""
    uid = update.effective_user.id
    is_admin = context.user_data["user_info"]["is_admin"]
    
    conn = db.get_conn()
    try:
        if is_admin:
            rows = conn.execute("""
            SELECT m.id, m.name, m.url, m.last_status, m.enabled, 
                   m.interval_seconds, m.user_id, u.username, m.expected_keyword
            FROM monitored_urls m
            LEFT JOIN authorized_users u ON m.user_id = u.user_id
            ORDER BY m.id DESC
            LIMIT 20
            """).fetchall()
        else:
            rows = conn.execute("""
            SELECT id, name, url, last_status, enabled, 
                   interval_seconds, expected_keyword
            FROM monitored_urls 
            WHERE user_id = ?
            ORDER BY id DESC
            """, [uid]).fetchall()
        
        if not rows:
            await update.message.reply_text("📭 暂无监控")
            return
        
        # 使用 pandas 格式化输出（如果数据量大）
        if is_admin and len(rows) > 10:
            df = pd.DataFrame(rows, columns=[
                'ID', '名称', 'URL', '状态', '启用', '间隔', '用户ID', '用户名', '关键字'
            ])
            text = "📊 监控列表（最近20条）:\n\n"
            for _, r in df.iterrows():
                emoji = "🟢" if r['状态'] == "UP" else "🔴" if r['状态'] == "DOWN" else "⚪"
                status = "✅" if r['启用'] else "❌"
                text += f"ID:{r['ID']} | 用户:{r['用户ID']} | {status}\n{emoji} {r['名称']}\n{r['URL']}\n\n"
        else:
            text = "📊 你的监控:\n\n"
            for r in rows:
                if is_admin:
                    id_, name, url, status, enabled, sec, uid_, uname, kw = r
                    user_info = f" | 用户:{uid_}"
                else:
                    id_, name, url, status, enabled, sec, kw = r
                    user_info = ""
                
                emoji = "🟢" if status == "UP" else "🔴" if status == "DOWN" else "⚪"
                status_emoji = "✅" if enabled else "❌"
                kw_info = f"\n🔍:{kw}" if kw else ""
                
                text += f"ID:{id_}{user_info} | {status_emoji}\n{emoji} {name}\n{url}{kw_info}\n\n"
        
        # 分段发送
        for chunk in [text[i:i+4000] for i in range(0, len(text), 4000)]:
            await update.message.reply_text(chunk)
    finally:
        conn.close()


@require_auth("user")
async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """删除监控"""
    if not context.args:
        await update.message.reply_text("❌ 用法: /delete `<ID>`", parse_mode="Markdown")
        return
    
    try:
        mid = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID 必须是数字")
        return
    
    uid = update.effective_user.id
    is_admin = context.user_data["user_info"]["is_admin"]
    
    with db_lock:
        conn = db.get_conn()
        try:
            if is_admin:
                result = conn.execute(
                    "DELETE FROM monitored_urls WHERE id = ? RETURNING name, user_id",
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
                msg = f"✅ 已删除: {result[0]}"
                if is_admin:
                    msg += f" (原用户: {result[1]})"
                await update.message.reply_text(msg)
            else:
                await update.message.reply_text("❌ 未找到或无权限")
        finally:
            conn.close()


@require_auth("user")
async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """查看监控详情"""
    if not context.args:
        await update.message.reply_text("❌ 用法: /status `<ID>`", parse_mode="Markdown")
        return
    
    try:
        mid = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID 必须是数字")
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
        
        # 获取统计信息
        stats = conn.execute("""
        SELECT 
            COUNT(*) as total_checks,
            AVG(response_time_ms) as avg_time,
            SUM(CASE WHEN status_code >= 400 OR status_code = -1 THEN 1 ELSE 0 END) as failures
        FROM visit_logs 
        WHERE monitor_id = ? AND visit_time > ?
        """, [mid, datetime.now() - timedelta(days=7)]).fetchone()
        
        logs = conn.execute("""
        SELECT status_code, response_time_ms, visit_time, error_message
        FROM visit_logs 
        WHERE monitor_id = ? 
        ORDER BY visit_time DESC 
        LIMIT 5
        """, [mid]).fetchall()
        
        text = f"📊 监控 {mid} 详情\n\n"
        text += f"名称: {row[2]}\nURL: {row[3]}\n"
        text += f"状态: {row[6] or '未知'} | 启用: {'✅' if row[5] else '❌'}\n"
        text += f"检查间隔: {row[4]}秒\n"
        if row[9]:  # expected_keyword
            text += f"关键字: {row[9]}\n"
        text += f"创建: {row[8].strftime('%Y-%m-%d') if row[8] else '未知'}\n\n"
        
        if stats[0] > 0:
            fail_rate = (stats[2] / stats[0]) * 100
            text += f"📈 近7天统计:\n"
            text += f"检查次数: {stats[0]} | 失败: {stats[2]} ({fail_rate:.1f}%)\n"
            text += f"平均响应: {stats[1]:.0f}ms\n\n"
        
        if logs:
            text += "最近5次检查:\n"
            for log in logs:
                emoji = "🟢" if 200 <= log[0] < 400 else "🔴"
                err = f" | {log[3]}" if log[3] else ""
                text += f"{emoji} {log[2].strftime('%m-%d %H:%M')} | {log[0]} | {log[1]}ms{err}\n"
        
        await update.message.reply_text(text)
    finally:
        conn.close()


@require_auth("user")
async def stats_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """个人统计信息"""
    uid = update.effective_user.id
    
    conn = db.get_conn()
    try:
        # 监控统计
        monitors = conn.execute("""
        SELECT 
            COUNT(*) as total,
            SUM(CASE WHEN enabled THEN 1 ELSE 0 END) as active,
            SUM(CASE WHEN last_status = 'UP' THEN 1 ELSE 0 END) as up,
            SUM(CASE WHEN last_status = 'DOWN' THEN 1 ELSE 0 END) as down
        FROM monitored_urls
        WHERE user_id = ?
        """, [uid]).fetchone()
        
        # 检查历史统计
        checks = conn.execute("""
        SELECT COUNT(*), AVG(response_time_ms)
        FROM visit_logs l
        JOIN monitored_urls m ON l.monitor_id = m.id
        WHERE m.user_id = ? AND l.visit_time > ?
        """, [uid, datetime.now() - timedelta(days=7)]).fetchone()
        
        text = "📊 你的统计\n\n"
        text += f"监控总数: {monitors[0] or 0}\n"
        text += f"运行中: {monitors[1] or 0} | 🟢 {monitors[2] or 0} | 🔴 {monitors[3] or 0}\n\n"
        text += f"近7天检查: {checks[0] or 0} 次\n"
        if checks[1]:
            text += f"平均响应: {checks[1]:.0f}ms"
        
        await update.message.reply_text(text)
    finally:
        conn.close()


# =========================
# Admin Commands (优化)
# =========================

@require_auth("admin")
async def adduser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """添加用户"""
    if len(context.args) < 1:
        await update.message.reply_text("❌ 用法: /adduser `<ID>` `[天数]` `[admin]` `[用户名]`")
        return
    
    try:
        new_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID 必须是数字")
        return
    
    days = int(context.args[1]) if len(context.args) > 1 else 30
    is_admin = len(context.args) > 2 and context.args[2].lower() in ['true', '1', 'admin']
    username = context.args[3] if len(context.args) > 3 else f"user_{new_id}"
    
    temp_pwd = secrets.token_urlsafe(12)
    expire = datetime.now() + timedelta(days=days)
    
    with db_lock:
        conn = db.get_conn()
        try:
            exists = conn.execute("SELECT 1 FROM authorized_users WHERE user_id = ?", [new_id]).fetchone()
            
            pwd_hash, pwd_salt = CryptoManager.hash_password(temp_pwd)
            
            if exists:
                conn.execute("""
                UPDATE authorized_users 
                SET is_admin = ?, expire_at = ?, password_hash = ?, password_salt = ?, 
                    is_active = true, username = ?
                WHERE user_id = ?
                """, [is_admin, expire, pwd_hash, pwd_salt, username, new_id])
                action = "更新"
            else:
                conn.execute("""
                INSERT INTO authorized_users 
                (user_id, username, is_admin, expire_at, password_hash, password_salt, added_by)
                VALUES(?,?,?,?,?,?,?)
                """, [new_id, username, is_admin, expire, pwd_hash, pwd_salt, update.effective_user.id])
                action = "添加"
            
            conn.commit()
            upload_db()
            
            role = "👑 管理员" if is_admin else "👤 普通用户"
            await update.message.reply_text(
                f"✅ {action}成功!\n"
                f"🆔 ID: `{new_id}`\n"
                f"👤 用户名: {username}\n"
                f"{role}\n"
                f"⏰ 过期: {expire.strftime('%Y-%m-%d')}\n"
                f"🔑 初始密码: `{temp_pwd}`\n\n"
                f"请安全地告知用户此密码！",
                parse_mode="Markdown"
            )
        finally:
            conn.close()


@require_auth("admin")
async def users_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """查看所有用户"""
    conn = db.get_conn()
    try:
        rows = conn.execute("""
        SELECT user_id, username, is_admin, is_active, expire_at, last_login, login_attempts, notify_enabled
        FROM authorized_users 
        ORDER BY added_at DESC
        """).fetchall()
        
        if not rows:
            await update.message.reply_text("📭 暂无用户")
            return
        
        # 使用 pandas 处理数据
        df = pd.DataFrame(rows, columns=[
            'ID', '用户名', '管理员', '激活', '过期时间', '最后登录', '失败次数', '通知'
        ])
        
        text = "👥 用户列表:\n\n"
        for _, r in df.iterrows():
            role = "👑" if r['管理员'] else "👤"
            status = "🟢" if r['激活'] else "🔴"
            expire = r['过期时间'].strftime('%Y-%m-%d') if r['过期时间'] else '永久'
            last = r['最后登录'].strftime('%m-%d') if r['最后登录'] else '从未'
            notify = "🔔" if r['通知'] else "🔕"
            text += f"{role}{status}{notify} `{r['ID']}` {r['用户名']}\n"
            text += f"过期:{expire} 登录:{last} 失败:{r['失败次数']}\n\n"
        
        await update.message.reply_text(text, parse_mode="Markdown")
    finally:
        conn.close()


@require_auth("admin")
async def deluser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """禁用用户（软删除）"""
    if not context.args:
        await update.message.reply_text("❌ 用法: /deluser `<ID>`")
        return
    
    try:
        del_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID 必须是数字")
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
            # 获取用户信息用于确认
            user = conn.execute("SELECT username FROM authorized_users WHERE user_id = ?", [del_id]).fetchone()
            if not user:
                await update.message.reply_text("❌ 用户不存在")
                return
            
            conn.execute("UPDATE authorized_users SET is_active = false WHERE user_id = ?", [del_id])
            conn.execute("UPDATE monitored_urls SET enabled = false WHERE user_id = ?", [del_id])
            conn.commit()
            upload_db()
            
            await update.message.reply_text(f"✅ 已禁用用户 {del_id} ({user[0]}) 及其所有监控")
        finally:
            conn.close()


@require_auth("admin")
async def toggle_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """切换监控状态"""
    if not context.args:
        await update.message.reply_text("❌ 用法: /toggle `<ID>`")
        return
    
    try:
        mid = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID 必须是数字")
        return
    
    with db_lock:
        conn = db.get_conn()
        try:
            row = conn.execute(
                "SELECT enabled, name, user_id FROM monitored_urls WHERE id = ?",
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
            await update.message.reply_text(f"{emoji}: {row[1]} (用户: {row[2]})")
        finally:
            conn.close()


@require_auth("admin")
async def resetpwd_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """重置密码"""
    if len(context.args) < 1:
        await update.message.reply_text("❌ 用法: /resetpwd `<ID>` `[新密码]`")
        return
    
    try:
        target_id = int(context.args[0])
    except:
        await update.message.reply_text("❌ ID 必须是数字")
        return
    
    # 如果提供了密码则使用，否则生成随机密码
    new_pwd = context.args[1] if len(context.args) > 1 else None
    
    admin_id = update.effective_user.id
    success, result = AuthManager.reset_password(admin_id, target_id, new_pwd)
    
    if success:
        await update.message.reply_text(
            f"✅ 已重置用户 {target_id} 的密码\n"
            f"🔑 新密码: `{result}`\n\n"
            f"请安全地告知用户！",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(f"❌ {result}")


@require_auth("admin")
async def broadcast_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """向所有用户广播消息"""
    if not context.args:
        await update.message.reply_text("❌ 用法: /broadcast `<消息>`")
        return
    
    message = " ".join(context.args)
    sender = update.effective_user.id
    
    conn = db.get_conn()
    try:
        users = conn.execute(
            "SELECT user_id FROM authorized_users WHERE is_active = true AND user_id != ?",
            [sender]
        ).fetchall()
        
        sent = 0
        failed = 0
        for (uid,) in users:
            try:
                await context.bot.send_message(
                    chat_id=uid,
                    text=f"📢 管理员广播:\n\n{message}\n\n- 来自管理员"
                )
                sent += 1
                await asyncio.sleep(0.1)  # 避免频率限制
            except Exception as e:
                logger.error(f"Broadcast to {uid} failed: {e}")
                failed += 1
        
        await update.message.reply_text(f"✅ 广播完成: 成功 {sent}, 失败 {failed}")
    finally:
        conn.close()


# =========================
# Bot Runner (优化：更好的生命周期管理)
# =========================

async def run_bot_async():
    """运行 Bot，带错误恢复"""
    app = Application.builder().token(BOT_TOKEN).build()
    
    # 注册处理器
    handlers = [
        CommandHandler("start", start_cmd),
        CommandHandler("add", add_cmd),
        CommandHandler("list", list_cmd),
        CommandHandler("delete", delete_cmd),
        CommandHandler("status", status_cmd),
        CommandHandler("stats", stats_cmd),
        CommandHandler("adduser", adduser_cmd),
        CommandHandler("users", users_cmd),
        CommandHandler("deluser", deluser_cmd),
        CommandHandler("toggle", toggle_cmd),
        CommandHandler("resetpwd", resetpwd_cmd),
        CommandHandler("broadcast", broadcast_cmd),
    ]
    
    for handler in handlers:
        app.add_handler(handler)
    
    # 错误处理器
    async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE):
        logger.error(f"Update {update} caused error {context.error}")
    
    app.add_error_handler(error_handler)
    
    await app.initialize()
    await app.start()
    await app.updater.start_polling(drop_pending_updates=True)
    
    logger.info("Bot started successfully")
    
    # 保持运行
    while True:
        await asyncio.sleep(1)


def run_bot():
    """在异常时重启"""
    while True:
        try:
            asyncio.run(run_bot_async())
        except Exception as e:
            logger.error(f"Bot crashed: {e}, restarting in 5 seconds...")
            time.sleep(5)


# 启动 Bot
if st.session_state.bot_thread is None:
    t = threading.Thread(target=run_bot, daemon=True)
    t.start()
    st.session_state.bot_thread = t


# =========================
# Streamlit UI (优化：更好的数据展示)
# =========================

def render_login_page():
    """渲染登录页面"""
    st.markdown("""
    <style>
    .login-box {
        max-width: 450px;
        margin: 2rem auto;
        padding: 2rem;
        border-radius: 15px;
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
    }
    .login-box input {
        border-radius: 8px;
    }
    </style>
    """, unsafe_allow_html=True)
    
    col1, col2, col3 = st.columns([1, 2, 1])
    with col2:
        st.markdown('<div class="login-box">', unsafe_allow_html=True)
        st.markdown("### 🔐 安全登录")
        
        user_id = st.number_input("用户 ID", step=1, value=0, label_visibility="collapsed",
                                 placeholder="输入 Telegram ID")
        password = st.text_input("密码", type="password", label_visibility="collapsed",
                                placeholder="输入密码")
        
        # 获取客户端信息（近似）
        user_agent = "Streamlit Web"
        
        if st.button("🚀 登录", use_container_width=True):
            success, user_info, msg = AuthManager.authenticate(
                int(user_id), password, "web", user_agent
            )
            
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
        
        st.markdown('</div>', unsafe_allow_html=True)
        
        # 系统状态
        with st.expander("ℹ️ 系统信息"):
            st.json({
                "db_version": Database.CURRENT_VERSION,
                "crypto_available": CRYPTO_AVAILABLE,
                "scheduler_running": scheduler.running,
                "upload_stats": upload_metrics
            })


def render_dashboard():
    """渲染主控制台"""
    user = st.session_state.user_info
    is_admin = user.get("is_admin", False)
    
    # 顶部栏
    cols = st.columns([3, 2, 1, 1])
    with cols[0]:
        st.write(f"👋 **{user.get('username', 'User')}**")
        st.caption(f"ID: {st.session_state.user_id} | {'👑 管理员' if is_admin else '👤 用户'}")
    with cols[1]:
        if user.get("expire_at"):
            days = (user["expire_at"] - datetime.now()).days
            color = "red" if days < 7 else "orange" if days < 30 else "green"
            st.markdown(f"<span style='color:{color}'>⏰ 剩余 {days} 天</span>", unsafe_allow_html=True)
    with cols[2]:
        if st.button("🔄 刷新", use_container_width=True):
            st.rerun()
    with cols[3]:
        if st.button("🚪 退出", use_container_width=True):
            for key in ["authenticated", "user_id", "user_info", "login_time", "session_token"]:
                st.session_state[key] = None
            st.rerun()
    
    # 侧边栏
    with st.sidebar:
        st.header("⚙️ 控制面板")
        
        if st.button("☁️ 立即同步", use_container_width=True):
            if upload_db(force=True):
                st.success("✅ 已同步")
            else:
                st.error("❌ 同步失败")
        
        # 密码修改
        with st.expander("🔐 修改密码"):
            with st.form("pwd_form"):
                old = st.text_input("原密码", type="password")
                new = st.text_input("新密码", type="password", 
                                  help="至少8位，含大小写字母和数字")
                confirm = st.text_input("确认新密码", type="password")
                
                if st.form_submit_button("确认修改", use_container_width=True):
                    if new != confirm:
                        st.error("两次输入不一致")
                    else:
                        success, msg = AuthManager.change_password(
                            st.session_state.user_id, old, new
                        )
                        if success:
                            st.success(msg)
                            time.sleep(2)
                            st.session_state.authenticated = False
                            st.rerun()
                        else:
                            st.error(msg)
        
        # 管理员面板
        if is_admin:
            st.divider()
            st.header("🔧 管理")
            
            with st.expander("➕ 添加用户"):
                with st.form("add_user"):
                    new_id = st.number_input("Telegram ID", step=1)
                    new_name = st.text_input("用户名", placeholder="user_123")
                    new_days = st.number_input("有效期(天)", min_value=1, value=30)
                    new_admin = st.checkbox("管理员权限")
                    
                    if st.form_submit_button("添加", use_container_width=True):
                        temp_pwd = secrets.token_urlsafe(12)
                        conn = db.get_conn()
                        try:
                            expire = datetime.now() + timedelta(days=new_days)
                            pwd_hash, pwd_salt = CryptoManager.hash_password(temp_pwd)
                            
                            conn.execute("""
                            INSERT INTO authorized_users 
                            (user_id, username, is_admin, expire_at, password_hash, password_salt, added_by)
                            VALUES(?,?,?,?,?,?,?)
                            """, [int(new_id), new_name or f"user_{new_id}", 
                                  new_admin, expire, pwd_hash, pwd_salt, 
                                  st.session_state.user_id])
                            conn.commit()
                            upload_db()
                            st.success(f"已添加！初始密码: {temp_pwd}")
                        except Exception as e:
                            st.error(f"失败: {e}")
                        finally:
                            conn.close()
            
            with st.expander("👥 用户管理"):
                conn = db.get_conn()
                try:
                    users_df = conn.execute("""
                    SELECT user_id, username, is_admin, is_active, expire_at, last_login, login_attempts
                    FROM authorized_users
                    ORDER BY is_active DESC, added_at DESC
                    """).fetchdf()
                    
                    # 使用 pandas 样式
                    def highlight_status(row):
                        if not row['is_active']:
                            return ['background-color: #ffcccc'] * len(row)
                        if row['expire_at'] and pd.to_datetime(row['expire_at']) < datetime.now():
                            return ['background-color: #ffe6cc'] * len(row)
                        return [''] * len(row)
                    
                    st.dataframe(
                        users_df.style.apply(highlight_status, axis=1),
                        use_container_width=True,
                        height=300
                    )
                finally:
                    conn.close()
                
                # 快捷操作
                col1, col2 = st.columns(2)
                with col1:
                    act_id = st.number_input("用户ID", step=1, key="act_id")
                with col2:
                    action = st.selectbox("操作", ["重置密码", "禁用", "启用", "删除"])
                
                if st.button("执行", use_container_width=True):
                    conn = db.get_conn()
                    try:
                        if action == "重置密码":
                            new_pwd = secrets.token_urlsafe(12)
                            success, _ = AuthManager.reset_password(
                                st.session_state.user_id, int(act_id), new_pwd
                            )
                            st.info(f"新密码: {new_pwd}" if success else "失败")
                        elif action == "禁用":
                            conn.execute("UPDATE authorized_users SET is_active = false WHERE user_id = ?", 
                                       [int(act_id)])
                            conn.commit()
                            st.success("已禁用")
                        elif action == "启用":
                            conn.execute("UPDATE authorized_users SET is_active = true WHERE user_id = ?", 
                                       [int(act_id)])
                            conn.commit()
                            st.success("已启用")
                        elif action == "删除":
                            if int(act_id) == ADMIN_USER_ID:
                                st.error("不能删除主管理员")
                            else:
                                conn.execute("DELETE FROM authorized_users WHERE user_id = ?", 
                                           [int(act_id)])
                                conn.execute("DELETE FROM monitored_urls WHERE user_id = ?", 
                                           [int(act_id)])
                                conn.commit()
                                st.success("已删除")
                        upload_db()
                    finally:
                        conn.close()
            
            with st.expander("📊 系统监控"):
                st.json({
                    "scheduler": scheduler.running,
                    "upload_success": upload_metrics["success"],
                    "upload_failed": upload_metrics["failed"],
                    "last_error": upload_metrics["last_error"]
                })
                
                # 显示最近的登录历史
                conn = db.get_conn()
                try:
                    history = conn.execute("""
                    SELECT h.user_id, u.username, h.login_time, h.success, h.ip_address
                    FROM login_history h
                    LEFT JOIN authorized_users u ON h.user_id = u.user_id
                    ORDER BY h.login_time DESC
                    LIMIT 20
                    """).fetchdf()
                    st.dataframe(history, use_container_width=True)
                finally:
                    conn.close()
    
    # 主内容
    st.subheader("📊 监控仪表板")
    
    conn = db.get_conn()
    try:
        # 指标卡片
        c1, c2, c3, c4, c5 = st.columns(5)
        
        if is_admin:
            stats = conn.execute("""
            SELECT 
                COUNT(DISTINCT user_id) as users,
                COUNT(*) as total,
                SUM(CASE WHEN enabled THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN last_status = 'UP' THEN 1 ELSE 0 END) as up,
                SUM(CASE WHEN last_status = 'DOWN' THEN 1 ELSE 0 END) as down
            FROM monitored_urls
            """).fetchone()
        else:
            uid = st.session_state.user_id
            stats = conn.execute("""
            SELECT 
                1 as users,
                COUNT(*) as total,
                SUM(CASE WHEN enabled THEN 1 ELSE 0 END) as active,
                SUM(CASE WHEN last_status = 'UP' THEN 1 ELSE 0 END) as up,
                SUM(CASE WHEN last_status = 'DOWN' THEN 1 ELSE 0 END) as down
            FROM monitored_urls
            WHERE user_id = ?
            """, [uid]).fetchone()
        
        c1.metric("👥 用户", stats[0] or 0)
        c2.metric("📊 监控", stats[1] or 0)
        c3.metric("✅ 运行", stats[2] or 0)
        c4.metric("🟢 正常", stats[3] or 0)
        c5.metric("🔴 异常", stats[4] or 0)
        
        st.divider()
        
        # 监控列表（使用 pandas 优化）
        if is_admin:
            df = conn.execute("""
            SELECT 
                m.id, m.name, m.url, m.last_status, m.enabled,
                m.interval_seconds, m.last_check_time, m.user_id, 
                u.username, m.expected_keyword
            FROM monitored_urls m
            LEFT JOIN authorized_users u ON m.user_id = u.user_id
            ORDER BY 
                CASE m.last_status 
                    WHEN 'DOWN' THEN 1 
                    WHEN 'UP' THEN 2 
                    ELSE 3 
                END,
                m.id DESC
            """).fetchdf()
        else:
            df = conn.execute("""
            SELECT 
                id, name, url, last_status, enabled,
                interval_seconds, last_check_time, expected_keyword
            FROM monitored_urls 
            WHERE user_id = ?
            ORDER BY 
                CASE last_status 
                    WHEN 'DOWN' THEN 1 
                    WHEN 'UP' THEN 2 
                    ELSE 3 
                END,
                id DESC
            """, [st.session_state.user_id]).fetchdf()
        
        if not df.empty:
            # 添加状态颜色列
            def status_color(val):
                colors = {'UP': '#d4edda', 'DOWN': '#f8d7da', None: '#fff3cd'}
                return f'background-color: {colors.get(val, "white")}'
            
            styled = df.style.applymap(status_color, subset=['last_status'])
            st.dataframe(styled, use_container_width=True, height=500)
            
            # 可视化：状态分布
            if len(df) > 0:
                col1, col2 = st.columns(2)
                with col1:
                    status_counts = df['last_status'].value_counts()
                    st.bar_chart(status_counts)
                with col2:
                    if is_admin:
                        user_counts = df.groupby('username').size().sort_values(ascending=False).head(10)
                        st.bar_chart(user_counts)
        else:
            st.info("暂无监控数据，使用 Telegram Bot 添加")
            
    finally:
        conn.close()


# =========================
# Main Entry
# =========================

if not st.session_state.authenticated:
    render_login_page()
else:
    # 验证 session
    if st.session_state.session_token:
        uid, valid = verify_session_token(st.session_state.session_token)
        if not valid or uid != st.session_state.user_id:
            st.session_state.authenticated = False
            st.error("会话已过期，请重新登录")
            st.rerun()
    
    render_dashboard()

st.divider()
st.caption("🤖 URL Monitor Bot v2.0 | Secure Monitoring System")
