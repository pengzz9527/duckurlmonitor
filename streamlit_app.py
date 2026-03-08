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

from datetime import datetime, timedelta
from threading import Lock

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, filters

from apscheduler.schedulers.background import BackgroundScheduler


# =========================
# Streamlit UI
# =========================

st.set_page_config(
    page_title="URL Monitor Bot",
    page_icon="🤖",
    layout="wide"
)

st.title("🤖 URL Monitor Bot")

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
# R2 Download
# =========================

def download_db():
    try:
        s3.download_file(
            R2_BUCKET,
            R2_DB_KEY,
            DB_FILE
        )
        print("✅ DB downloaded from R2")
    except Exception:
        print("⚠️ No database in R2, create new")


# =========================
# R2 Upload
# =========================

def upload_db():
    global last_upload

    if not os.path.exists(DB_FILE):
        return

    if time.time() - last_upload < 10:
        return

    try:
        s3.upload_file(
            DB_FILE,
            R2_BUCKET,
            R2_DB_KEY
        )
        last_upload = time.time()
        print("☁️ DB uploaded")
    except Exception as e:
        print("upload failed", e)


# =========================
# Download DB on start
# =========================

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

        conn.execute("""
        CREATE SEQUENCE IF NOT EXISTS monitor_seq START 1
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS authorized_users(
            user_id BIGINT PRIMARY KEY,
            is_admin BOOLEAN DEFAULT false,
            expire_at TIMESTAMP,
            added_at TIMESTAMP,
            added_by BIGINT
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS monitored_urls(
            id BIGINT DEFAULT nextval('monitor_seq'),
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
            id BIGINT DEFAULT nextval('monitor_seq'),
            monitor_id BIGINT,
            status_code INTEGER,
            response_time_ms INTEGER,
            visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
        """)

        # 确保管理员存在
        admin = conn.execute(
            "SELECT count(*) FROM authorized_users WHERE user_id=?",
            [ADMIN_USER_ID]
        ).fetchone()[0]

        if admin == 0:
            now = datetime.now()
            conn.execute("""
            INSERT INTO authorized_users (user_id, is_admin, expire_at, added_at, added_by)
            VALUES(?,?,?,?,?)
            """, [
                ADMIN_USER_ID,
                True,
                now + timedelta(days=3650),
                now,
                ADMIN_USER_ID
            ])

        conn.commit()
        upload_db()
        conn.close()


db = Database(DB_FILE)


# =========================
# Permission System
# =========================

def check_user_permission(user_id: int) -> dict:
    """检查用户权限，返回用户信息或 None"""
    conn = db.get_conn()
    try:
        row = conn.execute(
            "SELECT user_id, is_admin, expire_at FROM authorized_users WHERE user_id = ?",
            [user_id]
        ).fetchone()
        
        if not row:
            return None
        
        # 检查是否过期
        if row[2] and datetime.now() > row[2]:
            # 过期自动删除
            conn.execute("DELETE FROM authorized_users WHERE user_id = ?", [user_id])
            conn.commit()
            upload_db()
            return None
            
        return {
            "user_id": row[0],
            "is_admin": row[1],
            "expire_at": row[2]
        }
    finally:
        conn.close()


def require_auth(func):
    """装饰器：检查用户是否已授权"""
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        user_info = check_user_permission(user_id)
        
        if not user_info:
            await update.message.reply_text("⛔ 未经授权。请联系管理员添加权限。")
            return
        
        # 将用户信息存入 context 供后续使用
        context.user_data["user_info"] = user_info
        return await func(update, context)
    return wrapper


def require_admin(func):
    """装饰器：检查是否为管理员"""
    @functools.wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE):
        user_id = update.effective_user.id
        user_info = check_user_permission(user_id)
        
        if not user_info:
            await update.message.reply_text("⛔ 未经授权。")
            return
        
        if not user_info["is_admin"]:
            await update.message.reply_text("⛔ 需要管理员权限。")
            return
        
        context.user_data["user_info"] = user_info
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


# =========================
# Monitor Task
# =========================

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
        SELECT id, user_id, name, url
        FROM monitored_urls
        WHERE enabled = true
        """).fetchall()
    finally:
        conn.close()

    for r in rows:
        check_monitor_task(*r)


def backup_db():
    upload_db()


scheduler = BackgroundScheduler()
scheduler.add_job(run_checks, "interval", minutes=1)
scheduler.add_job(backup_db, "interval", minutes=5)
scheduler.start()


# =========================
# Telegram Commands - Public
# =========================

async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    user_info = check_user_permission(uid)
    
    if user_info:
        role = "管理员" if user_info["is_admin"] else "普通用户"
        expire = user_info["expire_at"].strftime("%Y-%m-%d") if user_info["expire_at"] else "永久"
        await update.message.reply_text(
            f"👋 欢迎回来！\n"
            f"🆔 你的ID: `{uid}`\n"
            f"👤 角色: {role}\n"
            f"⏰ 过期时间: {expire}\n\n"
            f"可用命令:\n"
            f"/add <名称> <URL> <间隔秒数> - 添加监控\n"
            f"/list - 查看我的监控\n"
            f"/delete <ID> - 删除监控\n"
            f"/status <ID> - 查看详细状态",
            parse_mode="Markdown"
        )
    else:
        await update.message.reply_text(
            f"👋 你好！\n"
            f"🆔 你的ID: `{uid}`\n"
            f"⛔ 你尚未获得授权，请联系管理员添加权限。",
            parse_mode="Markdown"
        )


# =========================
# Telegram Commands - User
# =========================

@require_auth
async def add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    
    if len(context.args) < 3:
        await update.message.reply_text("❌ 用法: /add <名称> <URL> <间隔秒数>")
        return
    
    name = context.args[0]
    url = context.args[1]
    
    try:
        sec = int(context.args[2])
        if sec < 60:
            await update.message.reply_text("❌ 间隔时间至少60秒")
            return
    except ValueError:
        await update.message.reply_text("❌ 间隔秒数必须是整数")
        return
    
    # 验证URL格式
    if not url.startswith(('http://', 'https://')):
        await update.message.reply_text("❌ URL必须以 http:// 或 https:// 开头")
        return
    
    with db_lock:
        conn = db.get_conn()
        try:
            # 检查用户监控数量限制（普通用户最多10个）
            user_info = context.user_data.get("user_info", {})
            if not user_info.get("is_admin"):
                count = conn.execute(
                    "SELECT COUNT(*) FROM monitored_urls WHERE user_id = ?",
                    [uid]
                ).fetchone()[0]
                if count >= 10:
                    await update.message.reply_text("❌ 普通用户最多只能添加10个监控")
                    return
            
            conn.execute("""
            INSERT INTO monitored_urls (user_id, name, url, interval_seconds, enabled)
            VALUES(?,?,?,?,true)
            """, [uid, name, url, sec])
            
            conn.commit()
            upload_db()
            
            await update.message.reply_text(f"✅ 已添加监控: {name}\n🔗 URL: {url}\n⏱️ 间隔: {sec}秒")
        finally:
            conn.close()


@require_auth
async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    user_info = context.user_data.get("user_info", {})
    
    conn = db.get_conn()
    try:
        if user_info.get("is_admin"):
            # 管理员查看全部
            rows = conn.execute("""
            SELECT m.id, m.name, m.url, m.last_status, m.enabled, u.user_id
            FROM monitored_urls m
            LEFT JOIN authorized_users u ON m.user_id = u.user_id
            ORDER BY m.id DESC
            """).fetchall()
            
            if not rows:
                await update.message.reply_text("📭 暂无监控项")
                return
            
            text = "📊 所有监控列表（管理员视图）:\n\n"
            for r in rows:
                status_emoji = "🟢" if r[3] == "UP" else "🔴" if r[3] == "DOWN" else "⚪"
                enabled_emoji = "✅" if r[4] else "❌"
                text += f"ID:{r[0]} | 用户:{r[5]} | {enabled_emoji}\n{status_emoji} {r[1]}\n{r[2]}\n\n"
        else:
            # 普通用户只看自己的
            rows = conn.execute("""
            SELECT id, name, url, last_status, enabled
            FROM monitored_urls
            WHERE user_id = ?
            ORDER BY id DESC
            """, [uid]).fetchall()
            
            if not rows:
                await update.message.reply_text("📭 你还没有添加任何监控\n使用 /add 添加")
                return
            
            text = "📊 你的监控列表:\n\n"
            for r in rows:
                status_emoji = "🟢" if r[3] == "UP" else "🔴" if r[3] == "DOWN" else "⚪"
                enabled_emoji = "✅" if r[4] else "❌"
                text += f"ID:{r[0]} {enabled_emoji} {status_emoji} {r[1]}\n{r[2]}\n\n"
        
        # 如果消息太长，分段发送
        if len(text) > 4000:
            for i in range(0, len(text), 4000):
                await update.message.reply_text(text[i:i+4000])
        else:
            await update.message.reply_text(text)
    finally:
        conn.close()


@require_auth
async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    user_info = context.user_data.get("user_info", {})
    
    if not context.args:
        await update.message.reply_text("❌ 用法: /delete <监控ID>")
        return
    
    try:
        mid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    with db_lock:
        conn = db.get_conn()
        try:
            # 检查权限
            if user_info.get("is_admin"):
                # 管理员可以删除任何
                result = conn.execute(
                    "DELETE FROM monitored_urls WHERE id = ? RETURNING name",
                    [mid]
                ).fetchone()
            else:
                # 普通用户只能删除自己的
                result = conn.execute(
                    "DELETE FROM monitored_urls WHERE id = ? AND user_id = ? RETURNING name",
                    [mid, uid]
                ).fetchone()
            
            if result:
                conn.commit()
                upload_db()
                await update.message.reply_text(f"✅ 已删除监控: {result[0]}")
            else:
                await update.message.reply_text("❌ 未找到该监控或无权删除")
        finally:
            conn.close()


@require_auth
async def status_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """查看监控详细状态"""
    uid = update.effective_user.id
    user_info = context.user_data.get("user_info", {})
    
    if not context.args:
        await update.message.reply_text("❌ 用法: /status <监控ID>")
        return
    
    try:
        mid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ ID必须是数字")
        return
    
    conn = db.get_conn()
    try:
        # 检查权限
        if user_info.get("is_admin"):
            row = conn.execute(
                "SELECT * FROM monitored_urls WHERE id = ?",
                [mid]
            ).fetchone()
        else:
            row = conn.execute(
                "SELECT * FROM monitored_urls WHERE id = ? AND user_id = ?",
                [mid, uid]
            ).fetchone()
        
        if not row:
            await update.message.reply_text("❌ 未找到该监控或无权查看")
            return
        
        # 获取最近5条日志
        logs = conn.execute("""
        SELECT status_code, response_time_ms, visit_time
        FROM visit_logs
        WHERE monitor_id = ?
        ORDER BY visit_time DESC
        LIMIT 5
        """, [mid]).fetchall()
        
        text = f"📊 监控详情 (ID: {mid})\n\n"
        text += f"名称: {row[2]}\n"
        text += f"URL: {row[3]}\n"
        text += f"状态: {row[6] or '未知'}\n"
        text += f"最后检查: {row[7].strftime('%Y-%m-%d %H:%M:%S') if row[7] else '从未'}\n"
        text += f"检查间隔: {row[4]}秒\n"
        text += f"启用状态: {'✅' if row[5] else '❌'}\n\n"
        
        if logs:
            text += "最近5次检查记录:\n"
            for log in logs:
                status_emoji = "🟢" if 200 <= log[0] < 400 else "🔴"
                text += f"{status_emoji} {log[2].strftime('%m-%d %H:%M')} | 状态码:{log[0]} | 耗时:{log[1]}ms\n"
        else:
            text += "暂无检查记录"
        
        await update.message.reply_text(text)
    finally:
        conn.close()


# =========================
# Telegram Commands - Admin
# =========================

@require_admin
async def adduser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """管理员添加用户"""
    if len(context.args) < 1:
        await update.message.reply_text("❌ 用法: /adduser <用户ID> [天数] [是否管理员]")
        return
    
    try:
        new_uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ 用户ID必须是数字")
        return
    
    # 默认30天，管理员可指定
    days = int(context.args[1]) if len(context.args) > 1 else 30
    is_admin = context.args[2].lower() in ['true', '1', 'yes', 'admin'] if len(context.args) > 2 else False
    
    expire = datetime.now() + timedelta(days=days)
    
    with db_lock:
        conn = db.get_conn()
        try:
            # 检查是否已存在
            existing = conn.execute(
                "SELECT user_id FROM authorized_users WHERE user_id = ?",
                [new_uid]
            ).fetchone()
            
            if existing:
                # 更新
                conn.execute(
                    "UPDATE authorized_users SET is_admin = ?, expire_at = ? WHERE user_id = ?",
                    [is_admin, expire, new_uid]
                )
                action = "更新"
            else:
                # 新增
                conn.execute("""
                INSERT INTO authorized_users (user_id, is_admin, expire_at, added_at, added_by)
                VALUES(?,?,?,?,?)
                """, [new_uid, is_admin, expire, datetime.now(), update.effective_user.id])
                action = "添加"
            
            conn.commit()
            upload_db()
            
            role = "管理员" if is_admin else "普通用户"
            await update.message.reply_text(
                f"✅ {action}用户成功!\n"
                f"🆔 用户ID: `{new_uid}`\n"
                f"👤 角色: {role}\n"
                f"⏰ 过期时间: {expire.strftime('%Y-%m-%d')}",
                parse_mode="Markdown"
            )
        finally:
            conn.close()


@require_admin
async def users_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """管理员查看所有用户"""
    conn = db.get_conn()
    try:
        rows = conn.execute("""
        SELECT user_id, is_admin, expire_at, added_at, added_by
        FROM authorized_users
        ORDER BY added_at DESC
        """).fetchall()
        
        if not rows:
            await update.message.reply_text("📭 暂无用户")
            return
        
        text = "👥 用户列表:\n\n"
        for r in rows:
            role = "👑 管理员" if r[1] else "👤 普通用户"
            expire = r[2].strftime('%Y-%m-%d') if r[2] else '永久'
            added = r[3].strftime('%Y-%m-%d') if r[3] else '未知'
            text += f"🆔 `{r[0]}` {role}\n"
            text += f"⏰ 过期: {expire} | 添加: {added}\n\n"
        
        await update.message.reply_text(text, parse_mode="Markdown")
    finally:
        conn.close()


@require_admin
async def deluser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """管理员删除用户"""
    if not context.args:
        await update.message.reply_text("❌ 用法: /deluser <用户ID>")
        return
    
    try:
        del_uid = int(context.args[0])
    except ValueError:
        await update.message.reply_text("❌ 用户ID必须是数字")
        return
    
    if del_uid == ADMIN_USER_ID:
        await update.message.reply_text("⛔ 不能删除主管理员")
        return
    
    if del_uid == update.effective_user.id:
        await update.message.reply_text("⛔ 不能删除自己")
        return
    
    with db_lock:
        conn = db.get_conn()
        try:
            # 删除用户及其所有监控
            conn.execute("DELETE FROM authorized_users WHERE user_id = ?", [del_uid])
            conn.execute("DELETE FROM monitored_urls WHERE user_id = ?", [del_uid])
            
            conn.commit()
            upload_db()
            
            await update.message.reply_text(f"✅ 已删除用户 {del_uid} 及其所有监控")
        finally:
            conn.close()


@require_admin
async def toggle_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """管理员启用/禁用监控"""
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
                await update.message.reply_text("❌ 未找到该监控")
                return
            
            new_status = not row[0]
            conn.execute(
                "UPDATE monitored_urls SET enabled = ? WHERE id = ?",
                [new_status, mid]
            )
            conn.commit()
            upload_db()
            
            status_text = "启用" if new_status else "禁用"
            await update.message.reply_text(f"✅ 已{status_text}监控: {row[1]}")
        finally:
            conn.close()


# =========================
# Run Bot
# =========================

async def run_bot_async():
    app = Application.builder().token(BOT_TOKEN).build()

    # 公开命令
    app.add_handler(CommandHandler("start", start_cmd))
    
    # 需要授权的命令
    app.add_handler(CommandHandler("add", add_cmd))
    app.add_handler(CommandHandler("list", list_cmd))
    app.add_handler(CommandHandler("delete", delete_cmd))
    app.add_handler(CommandHandler("status", status_cmd))
    
    # 管理员命令
    app.add_handler(CommandHandler("adduser", adduser_cmd))
    app.add_handler(CommandHandler("users", users_cmd))
    app.add_handler(CommandHandler("deluser", deluser_cmd))
    app.add_handler(CommandHandler("toggle", toggle_cmd))

    await app.initialize()
    await app.start()
    await app.updater.start_polling()

    while True:
        await asyncio.sleep(1)


def run_bot():
    asyncio.run(run_bot_async())


# =========================
# Start bot thread
# =========================

if "bot_thread" not in st.session_state:
    t = threading.Thread(target=run_bot, daemon=True)
    t.start()
    st.session_state.bot_thread = t


# =========================
# UI Dashboard
# =========================

st.sidebar.header("System")

if st.sidebar.button("🔄 同步数据库"):
    upload_db()
    st.sidebar.success("✅ 已上传")


# 检查当前用户权限（模拟登录）
st.sidebar.header("权限验证")
input_user_id = st.sidebar.text_input("输入你的 Telegram ID 查看权限", value=str(ADMIN_USER_ID))

try:
    current_uid = int(input_user_id)
    current_user = check_user_permission(current_uid)
    
    if current_user:
        role = "管理员" if current_user["is_admin"] else "普通用户"
        st.sidebar.success(f"✅ 已验证 - {role}")
        
        # 显示管理面板
        if current_user["is_admin"]:
            st.sidebar.markdown("---")
            st.sidebar.header("🔧 管理面板")
            
            # 添加用户
            with st.sidebar.expander("➕ 添加用户"):
                new_id = st.number_input("用户ID", step=1, value=0)
                new_days = st.number_input("有效期(天)", min_value=1, value=30)

                
                if st.button("确认添加"):
                    # 这里需要调用实际的数据库操作
                    conn = db.get_conn()
                    try:
                        expire = datetime.now() + timedelta(days=new_days)
                        conn.execute("""
                        INSERT OR REPLACE INTO authorized_users (user_id, is_admin, expire_at, added_at, added_by)
                        VALUES(?,?,?,?,?)
                        """, [int(new_id), new_admin, expire, datetime.now(), current_uid])
                        conn.commit()
                        upload_db()
                        st.sidebar.success("✅ 添加成功")
                    except Exception as e:
                        st.sidebar.error(f"❌ 失败: {e}")
                    finally:
                        conn.close()
            
            # 用户列表
            with st.sidebar.expander("👥 用户列表"):
                conn = db.get_conn()
                try:
                    users_df = conn.execute("""
                    SELECT user_id, is_admin, expire_at 
                    FROM authorized_users 
                    ORDER BY added_at DESC
                    """).fetchdf()
                    st.dataframe(users_df)
                finally:
                    conn.close()
    else:
        st.sidebar.error("⛔ 未授权或已过期")
        
except ValueError:
    st.sidebar.error("请输入有效的数字ID")


# 主面板统计
conn = db.get_conn()
try:
    col1, col2, col3 = st.columns(3)
    
    total_users = conn.execute("SELECT count(*) FROM authorized_users").fetchone()[0]
    total_monitors = conn.execute("SELECT count(*) FROM monitored_urls").fetchone()[0]
    active_monitors = conn.execute("SELECT count(*) FROM monitored_urls WHERE enabled = true").fetchone()[0]
    
    col1.metric("👥 总用户", total_users)
    col2.metric("📊 监控项", total_monitors)
    col3.metric("✅ 运行中", active_monitors)
    
    # 监控列表
    st.markdown("---")
    st.subheader("📋 监控列表")
    
    if current_user and current_user["is_admin"]:
        # 管理员看全部
        df = conn.execute("""
        SELECT m.id, m.name, m.url, m.last_status, m.enabled, 
               m.user_id, m.interval_seconds, m.last_check_time
        FROM monitored_urls m
        ORDER BY m.id DESC
        """).fetchdf()
    elif current_user:
        # 普通用户看自己的
        df = conn.execute("""
        SELECT id, name, url, last_status, enabled, 
               interval_seconds, last_check_time
        FROM monitored_urls 
        WHERE user_id = ?
        ORDER BY id DESC
        """, [current_uid]).fetchdf()
    else:
        df = None
        st.info("👈 请在侧边栏验证身份后查看")
    
    if df is not None and not df.empty:
        st.dataframe(df, use_container_width=True)
    elif df is not None:
        st.info("暂无监控数据")
        
finally:
    conn.close()

st.info("🤖 Bot 运行中...")

