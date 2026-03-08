# pip install streamlit duckdb boto3 python-telegram-bot>=21.0 apscheduler requests

import os
import time
import duckdb
import boto3
import requests
import streamlit as st
import threading
import asyncio

from datetime import datetime,timedelta
from threading import Lock

from telegram import Update
from telegram.ext import Application,CommandHandler,ContextTypes

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

BOT_TOKEN=st.secrets["BOT_TOKEN"]
ADMIN_USER_ID=int(st.secrets["ADMIN_USER_ID"])

R2_ENDPOINT=st.secrets["R2_ENDPOINT"]
R2_ACCESS_KEY=st.secrets["R2_ACCESS_KEY"]
R2_SECRET_KEY=st.secrets["R2_SECRET_KEY"]
R2_BUCKET=st.secrets["R2_BUCKET"]
R2_DB_KEY=st.secrets.get("R2_DB_KEY","url_monitor.duckdb")

# =========================
# Paths
# =========================

DB_DIR="/tmp"
DB_FILE=os.path.join(DB_DIR,"url_monitor.duckdb")

# =========================
# R2 Client
# =========================

s3=boto3.client(
    "s3",
    endpoint_url=R2_ENDPOINT,
    aws_access_key_id=R2_ACCESS_KEY,
    aws_secret_access_key=R2_SECRET_KEY
)

# =========================
# Lock
# =========================

db_lock=Lock()
last_upload=0


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

    if time.time()-last_upload<10:
        return

    try:

        s3.upload_file(
            DB_FILE,
            R2_BUCKET,
            R2_DB_KEY
        )

        last_upload=time.time()

        print("☁️ DB uploaded")

    except Exception as e:

        print("upload failed",e)


# =========================
# Download DB on start
# =========================

download_db()

# =========================
# Database
# =========================

class Database:

    def __init__(self,file):

        self.file=file
        self.init_db()

    def get_conn(self):

        return duckdb.connect(self.file)

    def init_db(self):

        conn=self.get_conn()

        conn.execute("""
        CREATE SEQUENCE IF NOT EXISTS monitor_seq START 1
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS authorized_users(
            user_id BIGINT PRIMARY KEY,
            is_admin BOOLEAN,
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
            enabled BOOLEAN,
            last_status TEXT,
            last_check_time TIMESTAMP,
            PRIMARY KEY(id)
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS visit_logs(
            monitor_id BIGINT,
            status_code INTEGER,
            response_time_ms INTEGER,
            visit_time TIMESTAMP
        )
        """)

        admin=conn.execute(
            "SELECT count(*) FROM authorized_users WHERE user_id=?",
            [ADMIN_USER_ID]
        ).fetchone()[0]

        if admin==0:

            now=datetime.now()

            conn.execute("""
            INSERT INTO authorized_users
            VALUES(?,?,?,?,?)
            """,[
                ADMIN_USER_ID,
                True,
                now+timedelta(days=3650),
                now,
                ADMIN_USER_ID
            ])

        conn.commit()

        upload_db()

        conn.close()


db=Database(DB_FILE)


# =========================
# URL Check
# =========================

def check_url(url):

    start=time.time()

    try:

        r=requests.get(url,timeout=10)

        code=r.status_code

        status="UP" if 200<=code<400 else "DOWN"

    except:

        code=-1
        status="DOWN"

    cost=int((time.time()-start)*1000)

    return status,code,cost


# =========================
# Monitor Task
# =========================

def check_monitor_task(mid,uid,name,url):

    with db_lock:

        conn=db.get_conn()

        status,code,cost=check_url(url)

        now=datetime.now()

        conn.execute(
            "UPDATE monitored_urls SET last_status=?,last_check_time=? WHERE id=?",
            [status,now,mid]
        )

        conn.execute(
            "INSERT INTO visit_logs VALUES(?,?,?,?)",
            [mid,code,cost,now]
        )

        conn.commit()

        upload_db()

        conn.close()


# =========================
# Scheduler
# =========================

def run_checks():

    conn=db.get_conn()

    rows=conn.execute("""
    SELECT id,user_id,name,url
    FROM monitored_urls
    WHERE enabled=true
    """).fetchall()

    conn.close()

    for r in rows:

        check_monitor_task(*r)


def backup_db():

    upload_db()


scheduler=BackgroundScheduler()

scheduler.add_job(run_checks,"interval",minutes=1)
scheduler.add_job(backup_db,"interval",minutes=5)

scheduler.start()


# =========================
# Telegram
# =========================

async def start_cmd(update:Update,context:ContextTypes.DEFAULT_TYPE):

    uid=update.effective_user.id

    await update.message.reply_text(
        f"Welcome\nYour id:{uid}"
    )


async def add_cmd(update:Update,context:ContextTypes.DEFAULT_TYPE):

    uid=update.effective_user.id

    name=context.args[0]
    url=context.args[1]
    sec=int(context.args[2])

    with db_lock:

        conn=db.get_conn()

        conn.execute("""
        INSERT INTO monitored_urls
        (user_id,name,url,interval_seconds,enabled)
        VALUES(?,?,?,?,true)
        """,[uid,name,url,sec])

        conn.commit()

        upload_db()

        conn.close()

    await update.message.reply_text("added")


async def list_cmd(update:Update,context:ContextTypes.DEFAULT_TYPE):

    conn=db.get_conn()

    rows=conn.execute("""
    SELECT id,name,url,last_status
    FROM monitored_urls
    """).fetchall()

    conn.close()

    text=""

    for r in rows:

        text+=f"{r[0]} {r[1]} {r[3]}\n{r[2]}\n\n"

    await update.message.reply_text(text)


# =========================
# Run Bot
# =========================

async def run_bot_async():

    app=Application.builder().token(BOT_TOKEN).build()

    app.add_handler(CommandHandler("start",start_cmd))
    app.add_handler(CommandHandler("add",add_cmd))
    app.add_handler(CommandHandler("list",list_cmd))

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

    t=threading.Thread(
        target=run_bot,
        daemon=True
    )

    t.start()

    st.session_state.bot_thread=t


# =========================
# UI Dashboard
# =========================

st.sidebar.header("System")

if st.sidebar.button("sync database"):

    upload_db()

    st.sidebar.success("uploaded")


conn=db.get_conn()

users=conn.execute("SELECT count(*) FROM authorized_users").fetchone()[0]

monitors=conn.execute(
    "SELECT count(*) FROM monitored_urls"
).fetchone()[0]

conn.close()

st.metric("users",users)
st.metric("monitors",monitors)


st.info("Bot running")
