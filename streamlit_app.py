# pip install python-telegram-bot>=21.0 duckdb requests apscheduler streamlit

import os
import sys
import time
import requests
import duckdb
import streamlit as st
from datetime import datetime, timedelta
import asyncio
import threading

from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
from apscheduler.schedulers.background import BackgroundScheduler

# ==================== 配置 ====================
# 页面配置（必须是第一个 Streamlit 命令）
st.set_page_config(
    page_title="URL 监控机器人",
    page_icon="🤖",
    layout="wide"
)

# 从 Streamlit Secrets 读取敏感信息
try:
    BOT_TOKEN = st.secrets["BOT_TOKEN"]
    ADMIN_USER_ID = int(st.secrets["ADMIN_USER_ID"])
except KeyError as e:
    st.error(f"❌ 缺少 Secrets 配置: {e}")
    st.info("请在 Streamlit Cloud 后台 Settings → Secrets 中添加：")
    st.code("""
BOT_TOKEN = "你的Telegram Bot Token"
ADMIN_USER_ID = "你的Telegram数字ID"
    """)
    st.stop()

# 数据库路径（使用可写目录）
DB_DIR = "/tmp"  # Streamlit Cloud 使用 /tmp
DB_FILE = os.path.join(DB_DIR, "url_monitor.duckdb")

# ==================== 数据库管理 ====================
class Database:
    def __init__(self, db_file):
        self.db_file = db_file
        self.init_db()
    
    def get_conn(self):
        """获取新的数据库连接"""
        try:
            return duckdb.connect(self.db_file)
        except Exception as e:
            st.error(f"数据库连接失败: {e}")
            if os.path.exists(self.db_file):
                try:
                    os.remove(self.db_file)
                    st.warning("已删除损坏的数据库文件，将重新创建")
                    return duckdb.connect(self.db_file)
                except Exception as e2:
                    st.error(f"无法删除数据库文件: {e2}")
                    raise
            raise
    
    def init_db(self):
        """初始化数据库表结构"""
        if os.path.exists(self.db_file):
            try:
                test_conn = duckdb.connect(self.db_file)
                test_conn.execute("SELECT 1").fetchone()
                test_conn.close()
            except Exception as e:
                st.warning(f"检测到损坏的数据库文件，正在重建...")
                try:
                    os.remove(self.db_file)
                    lock_file = self.db_file + ".wal"
                    if os.path.exists(lock_file):
                        os.remove(lock_file)
                except Exception as e2:
                    st.error(f"无法删除损坏的数据库: {e2}")
                    self.db_file = os.path.join(DB_DIR, "url_monitor_backup.duckdb")
                    st.warning(f"使用备用数据库路径: {self.db_file}")
        
        conn = self.get_conn()
        try:
            conn.execute("""
                CREATE SEQUENCE IF NOT EXISTS monitor_seq START 1
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS authorized_users (
                    user_id BIGINT PRIMARY KEY,
                    is_admin BOOLEAN,
                    expire_at TIMESTAMP,
                    added_at TIMESTAMP,
                    added_by BIGINT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS monitored_urls (
                    id BIGINT DEFAULT nextval('monitor_seq'),
                    user_id BIGINT,
                    name TEXT,
                    url TEXT,
                    interval_seconds INTEGER,
                    enabled BOOLEAN,
                    last_status TEXT,
                    last_check_time TIMESTAMP,
                    PRIMARY KEY (id)
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS visit_logs (
                    monitor_id BIGINT,
                    status_code INTEGER,
                    response_time_ms INTEGER,
                    visit_time TIMESTAMP
                )
            """)
            
            admin_exists = conn.execute("""
                SELECT COUNT(*) FROM authorized_users WHERE user_id=?
            """, [ADMIN_USER_ID]).fetchone()[0]
            
            if admin_exists == 0:
                now = datetime.now()
                conn.execute("""
                    INSERT INTO authorized_users
                    VALUES (?, true, ?, ?, ?)
                """, [ADMIN_USER_ID, now + timedelta(days=3650), now, ADMIN_USER_ID])
                conn.commit()
                print(f"✅ 已创建管理员: {ADMIN_USER_ID}")
        except Exception as e:
            st.error(f"初始化数据库失败: {e}")
            raise
        finally:
            conn.close()

@st.cache_resource(show_spinner=False)
def get_db():
    try:
        return Database(DB_FILE)
    except Exception as e:
        st.error(f"数据库初始化失败: {e}")
        return Database(":memory:")

try:
    db = get_db()
except Exception as e:
    st.error(f"无法初始化数据库: {e}")
    st.stop()

# ==================== 权限管理 ====================
def get_user(uid):
    conn = db.get_conn()
    try:
        result = conn.execute("""
            SELECT is_admin, expire_at FROM authorized_users WHERE user_id=?
        """, [uid]).fetchone()
        return result
    finally:
        conn.close()

def is_authorized(uid):
    r = get_user(uid)
    return r and r[1] > datetime.now()

def is_admin(uid):
    r = get_user(uid)
    return r and r[0]

# ==================== 监控逻辑 ====================
def check_url(url):
    """检查单个 URL 状态"""
    start = time.time()
    try:
        r = requests.get(url, timeout=10, allow_redirects=True)
        status_code = r.status_code
        status = "UP" if 200 <= r.status_code < 400 else "DOWN"
    except Exception as e:
        status_code = -1
        status = "DOWN"
    
    cost = int((time.time() - start) * 1000)
    return status, status_code, cost

def check_monitor_task(monitor_id, user_id, name, url):
    """后台定时任务：检查监控项"""
    conn = db.get_conn()
    try:
        status, code, cost = check_url(url)
        now = datetime.now()
        
        conn.execute("""
            UPDATE monitored_urls
            SET last_status=?, last_check_time=?
            WHERE id=?
        """, [status, now, monitor_id])
        
        conn.execute("""
            INSERT INTO visit_logs VALUES (?, ?, ?, ?)
        """, [monitor_id, code, cost, now])
        
        conn.commit()
        
        if status == "DOWN":
            print(f"⚠️ 监控异常: {name} ({url}) - HTTP {code}")
            
    except Exception as e:
        print(f"❌ 检查监控项失败 {name}: {e}")
    finally:
        conn.close()

def run_scheduled_checks():
    """运行所有启用的监控检查"""
    conn = db.get_conn()
    try:
        rows = conn.execute("""
            SELECT id, user_id, name, url, interval_seconds 
            FROM monitored_urls 
            WHERE enabled=true
        """).fetchall()
        
        now = datetime.now()
        
        for row in rows:
            mid, uid, name, url, interval = row
            
            last_check = conn.execute("""
                SELECT last_check_time FROM monitored_urls WHERE id=?
            """, [mid]).fetchone()
            
            should_check = True
            if last_check and last_check[0]:
                elapsed = (now - last_check[0]).total_seconds()
                should_check = elapsed >= interval
            
            if should_check:
                check_monitor_task(mid, uid, name, url)
                
    except Exception as e:
        print(f"❌ 定时检查失败: {e}")
    finally:
        conn.close()

# ==================== Telegram 命令处理器 ====================
async def start_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    user_info = get_user(uid)
    
    if not user_info:
        await update.message.reply_text(
            f"❌ 你没有权限使用此机器人\\n"
            f"你的 User ID: `{uid}`\\n\\n"
            f"请联系管理员添加权限",
            parse_mode='MarkdownV2'
        )
        return
    
    is_admin_user = user_info[0]
    expire_at = user_info[1]
    
    basic_commands = (
        f"👋 欢迎使用 URL 监控机器人!\\n\\n"
        f"🆔 你的 User ID: `{uid}`\\n"
        f"👤 角色: {'👑 管理员' if is_admin_user else '👤 普通用户'}\\n"
        f"⏰ 权限过期: {expire_at:%Y-%m-%d %H:%M:%S}\\n\\n"
        f"📋 **基本命令:**\\n"
        f"`/add <名称> <URL> <间隔秒数>` - 添加监控\\n"
        f"`/list` - 查看你的监控列表\\n"
        f"`/check [ID]` - 立即检查监控项\\n"
        f"`/delete <ID>` - 删除监控项"
    )
    
    if is_admin_user:
        admin_commands = (
            f"\\n\\n👑 **管理员命令:**\\n"
            f"`/adduser <user_id> <天数> [admin]` - 添加用户\\n"
            f"`/revoke <user_id>` - 撤销用户权限\\n"
            f"`/listusers` - 查看所有用户\\n"
            f"`/listall` - 查看所有监控项"
        )
        await update.message.reply_text(basic_commands + admin_commands, parse_mode='MarkdownV2')
    else:
        await update.message.reply_text(basic_commands, parse_mode='MarkdownV2')

async def add_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_authorized(uid):
        await update.message.reply_text("❌ 未授权访问")
        return
    
    if len(context.args) < 3:
        await update.message.reply_text(
            "❌ 用法: `/add <名称> <URL> <检查间隔秒数>`\\n"
            "示例: `/add 我的博客 https://example.com 300`",
            parse_mode='MarkdownV2'
        )
        return
    
    try:
        name, url, sec = context.args[0], context.args[1], int(context.args[2])
        
        if not url.startswith(('http://', 'https://')):
            await update.message.reply_text("❌ URL 必须以 http:// 或 https:// 开头")
            return
        
        conn = db.get_conn()
        try:
            conn.execute("""
                INSERT INTO monitored_urls
                (user_id, name, url, interval_seconds, enabled)
                VALUES (?, ?, ?, ?, true)
            """, [uid, name, url, sec])
            conn.commit()
        finally:
            conn.close()
        
        await update.message.reply_text(f"✅ 已添加监控: **{name}**", parse_mode='Markdown')
    except Exception as e:
        await update.message.reply_text(f"❌ 添加失败: {str(e)}")

async def list_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_authorized(uid):
        await update.message.reply_text("❌ 未授权访问")
        return
    
    conn = db.get_conn()
    try:
        if is_admin(uid):
            rows = conn.execute("""
                SELECT id, name, url, last_status, last_check_time
                FROM monitored_urls WHERE enabled=true
            """).fetchall()
        else:
            rows = conn.execute("""
                SELECT id, name, url, last_status, last_check_time
                FROM monitored_urls
                WHERE enabled=true AND user_id=?
            """, [uid]).fetchall()
    finally:
        conn.close()
    
    if not rows:
        await update.message.reply_text("📭 没有监控项，使用 `/add` 添加")
        return
    
    for r in rows:
        status_emoji = "🟢" if r[3]=='UP' else ("🔴" if r[3]=='DOWN' else "⚪")
        await update.message.reply_text(
            f"{status_emoji} **{r[1]}**\\n"
            f"🆔 ID: `{r[0]}`\\n"
            f"🔗 {r[2]}\\n"
            f"📊 状态: {r[3] or 'UNKNOWN'}\\n"
            f"🕐 最后检查: {r[4] or '未检查'}",
            parse_mode='MarkdownV2',
            disable_web_page_preview=True
        )

async def check_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_authorized(uid):
        await update.message.reply_text("❌ 未授权访问")
        return
    
    conn = db.get_conn()
    try:
        if context.args:
            monitor_id = int(context.args[0])
            if is_admin(uid):
                rows = conn.execute("""
                    SELECT id, user_id, name, url FROM monitored_urls
                    WHERE id=? AND enabled=true
                """, [monitor_id]).fetchall()
            else:
                rows = conn.execute("""
                    SELECT id, user_id, name, url FROM monitored_urls
                    WHERE id=? AND enabled=true AND user_id=?
                """, [monitor_id, uid]).fetchall()
        else:
            if is_admin(uid):
                rows = conn.execute("""
                    SELECT id, user_id, name, url FROM monitored_urls WHERE enabled=true
                """).fetchall()
            else:
                rows = conn.execute("""
                    SELECT id, user_id, name, url FROM monitored_urls
                    WHERE enabled=true AND user_id=?
                """, [uid]).fetchall()
    finally:
        conn.close()
    
    if not rows:
        await update.message.reply_text("❌ 没有找到监控项")
        return
    
    await update.message.reply_text(f"🔍 开始检查 {len(rows)} 个监控项...")
    
    for r in rows:
        mid, _, name, url = r
        status, code, cost = check_url(url)
        
        conn = db.get_conn()
        try:
            now = datetime.now()
            conn.execute("""
                UPDATE monitored_urls SET last_status=?, last_check_time=? WHERE id=?
            """, [status, now, mid])
            conn.execute("""
                INSERT INTO visit_logs VALUES (?, ?, ?, ?)
            """, [mid, code, cost, now])
            conn.commit()
        finally:
            conn.close()
        
        status_emoji = "🟢" if status=="UP" else "🔴"
        await update.message.reply_text(
            f"{status_emoji} **{name}**\\n"
            f"🆔 ID: `{mid}`\\n"
            f"🔗 {url}\\n"
            f"📊 状态: {status}\\n"
            f"📡 HTTP: {code}\\n"
            f"⏱️ 耗时: {cost} ms\\n"
            f"🕐 {now:%Y-%m-%d %H:%M:%S}",
            parse_mode='MarkdownV2',
            disable_web_page_preview=True
        )

async def delete_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_authorized(uid):
        await update.message.reply_text("❌ 未授权访问")
        return
    
    if len(context.args) < 1:
        await update.message.reply_text("❌ 用法: `/delete <ID>`")
        return
    
    try:
        monitor_id = int(context.args[0])
        conn = db.get_conn()
        try:
            if is_admin(uid):
                result = conn.execute("""
                    SELECT name FROM monitored_urls WHERE id=?
                """, [monitor_id]).fetchone()
            else:
                result = conn.execute("""
                    SELECT name FROM monitored_urls WHERE id=? AND user_id=?
                """, [monitor_id, uid]).fetchone()
            
            if not result:
                await update.message.reply_text("❌ 监控项不存在或无权限删除")
                return
            
            name = result[0]
            conn.execute("DELETE FROM monitored_urls WHERE id=?", [monitor_id])
            conn.commit()
            await update.message.reply_text(f"✅ 已删除监控项: **{name}**", parse_mode='Markdown')
        finally:
            conn.close()
    except Exception as e:
        await update.message.reply_text(f"❌ 删除失败: {str(e)}")

async def adduser_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.message.reply_text("❌ 只有管理员才能添加用户")
        return
    
    if len(context.args) < 2:
        await update.message.reply_text(
            "❌ 用法: `/adduser <user_id> <过期天数> [admin]`\\n"
            "示例: `/adduser 123456789 30`\\n"
            "示例: `/adduser 123456789 30 admin`",
            parse_mode='MarkdownV2'
        )
        return
    
    try:
        target_uid = int(context.args[0])
        days = int(context.args[1])
        is_admin_flag = len(context.args) > 2 and context.args[2].lower() == "admin"
        
        now = datetime.now()
        expire_at = now + timedelta(days=days)
        
        conn = db.get_conn()
        try:
            existing = conn.execute("""
                SELECT user_id FROM authorized_users WHERE user_id=?
            """, [target_uid]).fetchone()
            
            if existing:
                conn.execute("""
                    UPDATE authorized_users
                    SET is_admin=?, expire_at=?, added_at=?, added_by=?
                    WHERE user_id=?
                """, [is_admin_flag, expire_at, now, uid, target_uid])
                action = "更新"
            else:
                conn.execute("""
                    INSERT INTO authorized_users VALUES (?, ?, ?, ?, ?)
                """, [target_uid, is_admin_flag, expire_at, now, uid])
                action = "添加"
            
            conn.commit()
        finally:
            conn.close()
        
        role = "👑 管理员" if is_admin_flag else "👤 普通用户"
        await update.message.reply_text(
            f"✅ 已{action}用户\\n\\n"
            f"🆔 用户ID: `{target_uid}`\\n"
            f"👤 角色: {role}\\n"
            f"⏰ 过期时间: {expire_at:%Y-%m-%d %H:%M:%S}\\n"
            f"🕐 添加时间: {now:%Y-%m-%d %H:%M:%S}\\n"
            f"👤 添加者: {uid}",
            parse_mode='MarkdownV2'
        )
    except Exception as e:
        await update.message.reply_text(f"❌ 添加失败: {str(e)}")

async def revoke_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.message.reply_text("❌ 只有管理员才能撤销权限")
        return
    
    if len(context.args) < 1:
        await update.message.reply_text("❌ 用法: `/revoke <user_id>`")
        return
    
    try:
        target_uid = int(context.args[0])
        
        if target_uid == ADMIN_USER_ID:
            await update.message.reply_text("❌ 不能撤销超级管理员的权限")
            return
        
        conn = db.get_conn()
        try:
            existing = conn.execute("""
                SELECT user_id FROM authorized_users WHERE user_id=?
            """, [target_uid]).fetchone()
            
            if not existing:
                await update.message.reply_text("❌ 用户不存在")
                return
            
            conn.execute("DELETE FROM authorized_users WHERE user_id=?", [target_uid])
            conn.commit()
        finally:
            conn.close()
        
        await update.message.reply_text(f"✅ 已撤销用户 `{target_uid}` 的权限", parse_mode='MarkdownV2')
    except Exception as e:
        await update.message.reply_text(f"❌ 撤销失败: {str(e)}")

async def listall_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.message.reply_text("❌ 只有管理员才能查看所有URL")
        return
    
    conn = db.get_conn()
    try:
        rows = conn.execute("""
            SELECT m.id, m.name, m.url, m.last_status, m.last_check_time, 
                   m.user_id, m.interval_seconds, m.enabled
            FROM monitored_urls m
            ORDER BY m.user_id, m.id
        """).fetchall()
    finally:
        conn.close()
    
    if not rows:
        await update.message.reply_text("📭 没有任何监控项")
        return
    
    current_user = None
    messages = []
    current_msg = ""
    
    for r in rows:
        mid, name, url, status, last_check, owner_uid, interval, enabled = r
        
        if owner_uid != current_user:
            if current_msg:
                messages.append(current_msg)
            current_user = owner_uid
            current_msg = f"👤 用户 `{owner_uid}` 的监控项:\\n\\n"
        
        status_emoji = "🟢" if status == "UP" else ("🔴" if status == "DOWN" else "⚪")
        enabled_emoji = "✅" if enabled else "❌"
        
        item_text = (
            f"{status_emoji} **{name}** [{enabled_emoji}]\\n"
            f"  🆔 `{mid}`\\n"
            f"  🔗 {url}\\n"
            f"  📊 {status or 'UNKNOWN'}\\n"
            f"  ⏱️ {interval}秒\\n"
            f"  🕐 {last_check or '未检查'}\\n\\n"
        )
        
        if len(current_msg) + len(item_text) > 3500:
            messages.append(current_msg)
            current_msg = f"👤 用户 `{owner_uid}` 的监控项 (续):\\n\\n" + item_text
        else:
            current_msg += item_text
    
    if current_msg:
        messages.append(current_msg)
    
    for msg in messages:
        await update.message.reply_text(msg, parse_mode='MarkdownV2', disable_web_page_preview=True)

async def listusers_cmd(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = update.effective_user.id
    if not is_admin(uid):
        await update.message.reply_text("❌ 只有管理员才能查看用户列表")
        return
    
    conn = db.get_conn()
    try:
        rows = conn.execute("""
            SELECT user_id, is_admin, expire_at, added_at, added_by
            FROM authorized_users
            ORDER BY added_at DESC
        """).fetchall()
    finally:
        conn.close()
    
    if not rows:
        await update.message.reply_text("📭 没有授权用户")
        return
    
    msg = "👥 **授权用户列表:**\\n\\n"
    for r in rows:
        user_id, is_admin_flag, expire_at, added_at, added_by = r
        role = "👑 管理员" if is_admin_flag else "👤 普通用户"
        expired = "❌ 已过期" if expire_at < datetime.now() else "✅ 有效"
        
        user_text = (
            f"{role} `{user_id}` [{expired}]\\n"
            f"  ⏰ 过期: {expire_at:%Y-%m-%d}\\n"
            f"  🕐 添加: {added_at:%Y-%m-%d}\\n"
            f"  👤 添加者: `{added_by}`\\n\\n"
        )
        
        if len(msg) + len(user_text) > 3500:
            await update.message.reply_text(msg, parse_mode='MarkdownV2')
            msg = "👥 **授权用户列表 (续):**\\n\\n" + user_text
        else:
            msg += user_text
    
    await update.message.reply_text(msg, parse_mode='MarkdownV2')

# ==================== 后台调度器 ====================
def start_scheduler():
    """启动后台定时调度器"""
    scheduler = BackgroundScheduler()
    scheduler.add_job(run_scheduled_checks, 'interval', minutes=1, id='monitor_job')
    scheduler.start()
    return scheduler

# ==================== Telegram Bot 启动（修复版）====================
async def run_bot_async():
    """异步运行 Bot"""
    try:
        # 使用 Application.builder() 创建应用（v21+ 语法）
        application = (
            Application.builder()
            .token(BOT_TOKEN)
            .build()
        )
        
        # 添加处理器
        application.add_handler(CommandHandler("start", start_cmd))
        application.add_handler(CommandHandler("add", add_cmd))
        application.add_handler(CommandHandler("list", list_cmd))
        application.add_handler(CommandHandler("check", check_cmd))
        application.add_handler(CommandHandler("delete", delete_cmd))
        application.add_handler(CommandHandler("adduser", adduser_cmd))
        application.add_handler(CommandHandler("revoke", revoke_cmd))
        application.add_handler(CommandHandler("listall", listall_cmd))
        application.add_handler(CommandHandler("listusers", listusers_cmd))
        
        # 初始化并启动
        await application.initialize()
        await application.start()
        
        # 使用 Updater 进行 polling（v21+ 语法）
        await application.updater.start_polling(drop_pending_updates=True)
        
        # 保持运行
        while True:
            await asyncio.sleep(1)
            
    except Exception as e:
        print(f"Bot 运行错误: {e}")
        import traceback
        traceback.print_exc()

def run_bot():
    """在线程中运行异步 Bot"""
    try:
        asyncio.run(run_bot_async())
    except Exception as e:
        print(f"Bot 线程错误: {e}")

# ==================== Streamlit UI ====================
def main():
    st.title("🤖 Telegram URL 监控机器人")
    st.markdown("---")
    
    with st.sidebar:
        st.header("📊 系统状态")
        
        try:
            test_conn = db.get_conn()
            test_conn.execute("SELECT 1").fetchone()
            test_conn.close()
            st.success("💾 数据库连接正常")
        except Exception as e:
            st.error(f"💾 数据库异常: {e}")
        
        st.success(f"🤖 Bot 已启动")
        st.info(f"👑 管理员 ID: `{ADMIN_USER_ID}`")
        st.info(f"💾 数据库路径: `{DB_FILE}`")
        
        try:
            conn = db.get_conn()
            try:
                user_count = conn.execute("SELECT COUNT(*) FROM authorized_users").fetchone()[0]
                monitor_count = conn.execute("SELECT COUNT(*) FROM monitored_urls WHERE enabled=true").fetchone()[0]
                st.metric("👥 授权用户", user_count)
                st.metric("📡 活跃监控", monitor_count)
            finally:
                conn.close()
        except Exception as e:
            st.error(f"无法获取统计: {e}")
        
        st.markdown("---")
        st.markdown("### 📝 使用说明")
        st.markdown("""
        1. 在 Telegram 中找到你的 Bot
        2. 发送 `/start` 查看命令列表
        3. 使用 `/add` 添加监控URL
        4. 系统每分钟自动检查一次
        """)
        
        if st.button("🗑️ 重置数据库", type="secondary"):
            if os.path.exists(DB_FILE):
                try:
                    os.remove(DB_FILE)
                    st.warning("数据库已重置，请刷新页面")
                    st.stop()
                except Exception as e:
                    st.error(f"无法删除数据库: {e}")
    
    tab1, tab2, tab3 = st.tabs(["🚀 控制面板", "📋 监控列表", "📜 日志"])
    
    with tab1:
        st.subheader("🚀 Bot 控制")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### 📡 实时监控状态")
            if st.button("🔍 立即检查所有监控", type="primary"):
                with st.spinner("正在检查..."):
                    try:
                        run_scheduled_checks()
                        st.success("✅ 检查完成！")
                        st.rerun()
                    except Exception as e:
                        st.error(f"检查失败: {e}")
        
        with col2:
            st.markdown("#### ⚙️ 系统操作")
            if st.button("🗑️ 清理旧日志"):
                try:
                    conn = db.get_conn()
                    try:
                        cutoff = datetime.now() - timedelta(days=30)
                        conn.execute("DELETE FROM visit_logs WHERE visit_time < ?", [cutoff])
                        conn.commit()
                        st.success("✅ 已清理旧日志")
                    finally:
                        conn.close()
                except Exception as e:
                    st.error(f"清理失败: {e}")
        
        st.markdown("---")
        st.subheader("📊 最近检查记录")
        
        try:
            conn = db.get_conn()
            try:
                logs = conn.execute("""
                    SELECT v.monitor_id, m.name, v.status_code, v.response_time_ms, v.visit_time
                    FROM visit_logs v
                    JOIN monitored_urls m ON v.monitor_id = m.id
                    ORDER BY v.visit_time DESC
                    LIMIT 20
                """).fetchall()
                
                if logs:
                    import pandas as pd
                    df = pd.DataFrame(logs, columns=['ID', '名称', 'HTTP状态', '响应时间(ms)', '检查时间'])
                    st.dataframe(df, use_container_width=True)
                else:
                    st.info("暂无检查记录")
            finally:
                conn.close()
        except Exception as e:
            st.error(f"无法加载日志: {e}")
    
    with tab2:
        st.subheader("📋 所有监控项")
        
        try:
            conn = db.get_conn()
            try:
                monitors = conn.execute("""
                    SELECT m.id, m.name, m.url, m.interval_seconds, m.last_status, m.last_check_time, u.user_id
                    FROM monitored_urls m
                    LEFT JOIN authorized_users u ON m.user_id = u.user_id
                    WHERE m.enabled = true
                    ORDER BY m.id DESC
                """).fetchall()
                
                if monitors:
                    for m in monitors:
                        mid, name, url, interval, status, last_check, owner = m
                        
                        status_color = "green" if status == "UP" else ("red" if status == "DOWN" else "gray")
                        
                        with st.container():
                            cols = st.columns([3, 1, 1, 1])
                            cols[0].markdown(f"**{name}**  \\n`{url}`")
                            cols[1].markdown(f"⏱️ {interval}秒")
                            cols[2].markdown(f":{status_color}[{status or 'UNKNOWN'}]")
                            cols[3].markdown(f"👤 `{owner}`")
                            st.divider()
                else:
                    st.info("暂无监控项")
            finally:
                conn.close()
        except Exception as e:
            st.error(f"无法加载监控列表: {e}")
    
    with tab3:
        st.subheader("📜 系统日志")
        st.info("日志功能需要配置更高级的日志记录，当前版本仅显示基础信息。")

# ==================== 启动逻辑 ====================
if __name__ == "__main__":
    # 启动后台调度器
    if "scheduler_started" not in st.session_state:
        try:
            scheduler = start_scheduler()
            st.session_state.scheduler_started = True
            st.session_state.scheduler = scheduler
            print("✅ 后台调度器已启动")
        except Exception as e:
            st.error(f"调度器启动失败: {e}")
    
    # 在单独线程中运行 Telegram Bot
    if "bot_thread" not in st.session_state:
        bot_thread = threading.Thread(target=run_bot, daemon=True)
        bot_thread.start()
        st.session_state.bot_thread = bot_thread
        print("✅ Telegram Bot 线程已启动")
    
    main()
