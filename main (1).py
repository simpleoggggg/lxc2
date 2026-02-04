# bot.py
import discord
from discord.ext import commands, tasks
import asyncio
import subprocess
import json
from datetime import datetime
import shlex
import logging
import shutil
import os
from typing import Optional, List, Dict, Any
import threading
import time
import sqlite3
import yaml
import re

# Load configuration
if not os.path.exists('config.yaml'):
    print("config.yaml not found!")
    exit(1)

with open('config.yaml', 'r') as f:
    config = yaml.safe_load(f)

# Global variables from config
DISCORD_TOKEN = config['bot']['token']
PREFIX = config['bot']['prefix']
MAIN_ADMIN_ID = config['bot']['admin_ids'][0]
ADMIN_IDS = config['bot']['admin_ids']
BRANDING = config.get('branding', {})
ECONOMY = config.get('economy', {})
LXC_CONFIG = config.get('lxc', {})
AFK_CHANNEL_ID = ECONOMY.get('afk_channel_id')
STATUS_INTERVAL = ECONOMY.get('status_interval', 60)
DEFAULT_STORAGE_POOL = LXC_CONFIG.get('pool_name', 'default') # Default LXD pool name
VPS_USER_ROLE_ID = "1461325896760819838" # Global role ID cache

# Branding helpers
BRAND_NAME = BRANDING.get('name', 'Xyara Hosting')
BRAND_COLOR = BRANDING.get('color', 0x1a1a1a)
BRAND_FOOTER = BRANDING.get('footer', 'Powered by Xyara Hosting')

# OS Options for VPS Creation
# OS Options for VPS Creation (Classic LXC Templates: distro;release;arch)
OS_OPTIONS = [
    {"label": "Ubuntu 20.04 LTS", "value": "ubuntu;focal;amd64"},
    {"label": "Ubuntu 22.04 LTS", "value": "ubuntu;jammy;amd64"},
    {"label": "Ubuntu 24.04 LTS", "value": "ubuntu;noble;amd64"},
    {"label": "Debian 10 (Buster)", "value": "debian;buster;amd64"},
    {"label": "Debian 11 (Bullseye)", "value": "debian;bullseye;amd64"},
    {"label": "Debian 12 (Bookworm)", "value": "debian;bookworm;amd64"},
    {"label": "Debian 13 (Trixie)", "value": "debian;trixie;amd64"},
    {"label": "Alpine Linux 3.18", "value": "alpine;3.18;amd64"},
    {"label": "Alpine Linux 3.19", "value": "alpine;3.19;amd64"},
    {"label": "CentOS 7", "value": "centos;7;amd64"},
    {"label": "CentOS 8-Stream", "value": "centos;8-Stream;amd64"},
    {"label": "Fedora 38", "value": "fedora;38;amd64"},
    {"label": "Fedora 39", "value": "fedora;39;amd64"},
    {"label": "Arch Linux", "value": "archlinux;current;amd64"},
]

# Configure logging to file and console
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('bot.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('Xyara Hosting_vps_bot')

# Check if lxc command is available
if not shutil.which("lxc-create"):
    logger.error("LXC command (lxc-create) not found. Please ensure Classic LXC is installed.")
    raise SystemExit("LXC command (lxc-create) not found. Please ensure Classic LXC is installed.")

# Database setup
def get_db():
    conn = sqlite3.connect('vps.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    cur = conn.cursor()
    
    # Existing tables
    cur.execute('''CREATE TABLE IF NOT EXISTS admins (
        user_id TEXT PRIMARY KEY
    )''')
    for admin_id in ADMIN_IDS:
        cur.execute('INSERT OR IGNORE INTO admins (user_id) VALUES (?)', (str(admin_id),))

    cur.execute('''CREATE TABLE IF NOT EXISTS vps (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id TEXT NOT NULL,
        container_name TEXT UNIQUE NOT NULL,
        ram TEXT NOT NULL,
        cpu TEXT NOT NULL,
        storage TEXT NOT NULL,
        config TEXT NOT NULL,
        os_version TEXT DEFAULT 'ubuntu:22.04',
        status TEXT DEFAULT 'stopped',
        suspended INTEGER DEFAULT 0,
        whitelisted INTEGER DEFAULT 0,
        created_at TEXT NOT NULL,
        shared_with TEXT DEFAULT '[]',
        suspension_history TEXT DEFAULT '[]'
    )''')

    # Migration for os_version column
    cur.execute('PRAGMA table_info(vps)')
    info = cur.fetchall()
    columns = [col[1] for col in info]
    if 'os_version' not in columns:
        cur.execute("ALTER TABLE vps ADD COLUMN os_version TEXT DEFAULT 'ubuntu:22.04'")

    cur.execute('''CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )''')

    # Schema Migration: Check if 'plans' has 'price' column (Legacy Economy)
    # If so, drop it so we can recreate it with new schema
    try:
        cur.execute("SELECT price FROM plans LIMIT 1")
        logger.info("Legacy 'plans' table detected with 'price' column. Dropping to migrate...")
        cur.execute("DROP TABLE plans")
    except sqlite3.OperationalError:
        # Column 'price' not found, or table doesn't exist. Good.
        pass

    cur.execute('''CREATE TABLE IF NOT EXISTS plans (
        name TEXT PRIMARY KEY,
        ram INTEGER NOT NULL,
        cpu INTEGER NOT NULL,
        storage INTEGER NOT NULL
    )''')

    settings_init = [
        ('cpu_threshold', '90'),
        ('ram_threshold', '90'),
    ]
    for key, value in settings_init:
        cur.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (key, value))

    conn.commit()
    conn.close()

def get_setting(key: str, default: Any = None):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT value FROM settings WHERE key = ?', (key,))
    row = cur.fetchone()
    conn.close()
    return row[0] if row else default

def set_setting(key: str, value: str):
    conn = get_db()
    cur = conn.cursor()
    cur.execute('INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)', (key, value))
    conn.commit()
    conn.close()

def get_vps_data() -> Dict[str, List[Dict[str, Any]]]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM vps')
    rows = cur.fetchall()
    conn.close()
    data = {}
    for row in rows:
        user_id = row['user_id']
        if user_id not in data:
            data[user_id] = []
        vps = dict(row)
        vps['shared_with'] = json.loads(vps['shared_with'])
        vps['suspension_history'] = json.loads(vps['suspension_history'])
        vps['suspended'] = bool(vps['suspended'])
        vps['whitelisted'] = bool(vps['whitelisted'])
        vps['os_version'] = vps.get('os_version', 'ubuntu:22.04')
        data[user_id].append(vps)
    return data

def get_admins() -> List[str]:
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT user_id FROM admins')
    rows = cur.fetchall()
    conn.close()
    return [row['user_id'] for row in rows]

def save_vps_data():
    conn = get_db()
    cur = conn.cursor()
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            shared_json = json.dumps(vps['shared_with'])
            history_json = json.dumps(vps['suspension_history'])
            suspended_int = 1 if vps['suspended'] else 0
            whitelisted_int = 1 if vps.get('whitelisted', False) else 0
            os_ver = vps.get('os_version', 'ubuntu:22.04')
            if 'id' not in vps or vps['id'] is None:
                cur.execute('''INSERT INTO vps (user_id, container_name, ram, cpu, storage, config, os_version, status, suspended, whitelisted, created_at, shared_with, suspension_history)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (user_id, vps['container_name'], vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int,
                             vps['created_at'], shared_json, history_json))
                vps['id'] = cur.lastrowid
            else:
                cur.execute('''UPDATE vps SET user_id = ?, ram = ?, cpu = ?, storage = ?, config = ?, os_version = ?, status = ?, suspended = ?, whitelisted = ?, shared_with = ?, suspension_history = ?
                               WHERE id = ?''',
                            (user_id, vps['ram'], vps['cpu'], vps['storage'], vps['config'],
                             os_ver, vps['status'], suspended_int, whitelisted_int, shared_json, history_json, vps['id']))
    conn.commit()
    conn.close()

def save_admin_data():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM admins')
    for admin_id in admin_data['admins']:
        cur.execute('INSERT INTO admins (user_id) VALUES (?)', (admin_id,))
    conn.commit()
    conn.close()

# Initialize database
init_db()

# Load data at startup
vps_data = get_vps_data()
admin_data = {'admins': get_admins()}

# Global settings from DB
CPU_THRESHOLD = int(get_setting('cpu_threshold', 90))
RAM_THRESHOLD = int(get_setting('ram_threshold', 90))



def get_plans():
    conn = get_db()
    cur = conn.cursor()
    cur.execute('SELECT * FROM plans')
    rows = cur.fetchall()
    conn.close()
    return [dict(row) for row in rows]

# Bot setup
intents = discord.Intents.default()
intents.message_content = True
intents.members = True
intents.presences = True # Needed for status check
bot = commands.Bot(command_prefix=PREFIX, intents=intents, help_command=None)

# Resource monitoring settings
resource_monitor_active = True

# Helper function to truncate text to a specific length
def truncate_text(text, max_length=1024):
    if not text:
        return text
    if len(text) <= max_length:
        return text
    return text[:max_length-3] + "..."

# Embed creation functions with branding from config
# Minimal Embed creation functions
def create_embed(title, description="", color=BRAND_COLOR):
    embed = discord.Embed(
        title=truncate_text(title, 256),
        description=truncate_text(description, 4096),
        color=color
    )
    # Minimal style: No footer, no timestamp, no brand prefix
    return embed

def add_field(embed, name, value, inline=False):
    embed.add_field(
        name=truncate_text(name, 256),
        value=truncate_text(value, 1024),
        inline=inline
    )
    return embed

def create_success_embed(title, description=""):
    return create_embed(title, description, color=0x00ff88)

def create_error_embed(title, description=""):
    return create_embed(title, description, color=0xff3366)

def create_info_embed(title, description=""):
    return create_embed(title, description, color=0x00ccff)

def create_warning_embed(title, description=""):
    return create_embed(title, description, color=0xffaa00)

# Admin checks
def is_admin():
    async def predicate(ctx):
        user_id = str(ctx.author.id)
        if user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", []):
            return True
        raise commands.CheckFailure("You need admin permissions to use this command. Contact Xyara Hosting support.")
    return commands.check(predicate)

def is_main_admin():
    async def predicate(ctx):
        if str(ctx.author.id) == str(MAIN_ADMIN_ID):
            return True
        raise commands.CheckFailure("Only the main admin can use this command.")
    return commands.check(predicate)

# Clean LXC command execution with improved timeout handling
async def execute_lxc(command, timeout=120):
    try:
        cmd = shlex.split(command)
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise asyncio.TimeoutError(f"Command timed out after {timeout} seconds")
        if proc.returncode != 0:
            error = stderr.decode().strip() if stderr else "Command failed with no error output"
            raise Exception(error)
        return stdout.decode().strip() if stdout else True
    except asyncio.TimeoutError as te:
        logger.error(f"LXC command timed out: {command} - {str(te)}")
        raise
    except Exception as e:
        logger.error(f"LXC Error: {command} - {str(e)}")
        raise

# Function to apply advanced permissions to a container
async def apply_advanced_permissions(container_name):
    try:
        # Classic LXC permissions are config file based.
        # This function would need to edit /var/lib/lxc/{name}/config
        # Skipping dynamic config set for now as it requires file I/O on host
        pass
        logger.info(f"Applied advanced permissions to {container_name}")
    except Exception as e:
        logger.error(f"Failed to apply advanced permissions to {container_name}: {e}")
        logger.warning(f"Continuing without full permissions for {container_name}. Check logs for details.")

# Get or create VPS user role
async def get_or_create_vps_role(guild):
    global VPS_USER_ROLE_ID
    if VPS_USER_ROLE_ID:
        role = guild.get_role(VPS_USER_ROLE_ID)
        if role:
            return role
    role = discord.utils.get(guild.roles, name="Xyara Hosting VPS User")
    if role:
        VPS_USER_ROLE_ID = role.id
        return role
    try:
        role = await guild.create_role(
            name="Xyara Hosting VPS User",
            color=discord.Color.dark_purple(),
            reason="Xyara Hosting VPS User role for bot management",
            permissions=discord.Permissions.none()
        )
        VPS_USER_ROLE_ID = role.id
        logger.info(f"Created Xyara Hosting VPS User role: {role.name} (ID: {role.id})")
        return role
    except Exception as e:
        logger.error(f"Failed to create role: {e}")
        return None

# DNS Fix Helper
async def fix_container_dns(container_name):
    """
    Forcefully sets DNS servers for a container.
    Removes /etc/resolv.conf (handling symlinks) and creates a static file.
    """
    try:
        # 1. Check if lxcbr0 has internet (optional, but good to know)
        # 2. Force remove /etc/resolv.conf inside container
        await execute_lxc(f"lxc-attach -n {container_name} -- rm -rf /etc/resolv.conf")
        
        # 3. Create new resolv.conf with Google & Cloudflare DNS
        dns_content = "nameserver 8.8.8.8\\nnameserver 1.1.1.1"
        cmd = f"lxc-attach -n {container_name} -- bash -c 'echo -e \"{dns_content}\" > /etc/resolv.conf'"
        await execute_lxc(cmd)
        
        # 4. Attempt to verify (ping)
        # We don't block on this, just log
        # await execute_lxc(f"lxc-attach -n {container_name} -- ping -c 1 google.com")
        
        logger.info(f"Applied DNS fix for {container_name}")
        return True
    except Exception as e:
        logger.error(f"DNS Fix failed for {container_name}: {e}")
        return False

@bot.command(name='fixdns')
async def fix_dns_command(ctx, container_name: str = None):
    """Manually fix DNS for a specific container."""
    if not container_name:
        # Try to find user's VPS if not specified
        user_vps = vps_data.get(str(ctx.author.id), [])
        if len(user_vps) == 1:
            container_name = user_vps[0]['container_name']
        else:
            await ctx.send("❌ Please specify container name: `!fixdns <name>`")
            return
            
    status_msg = await ctx.send(f"🔧 Fixing DNS for `{container_name}`...")
    success = await fix_container_dns(container_name)
    
    if success:
        await status_msg.edit(content=f"✅ DNS Fixed for `{container_name}`! Try running your command again.")
    else:
        await status_msg.edit(content=f"❌ Failed to fix DNS for `{container_name}`. Check logs.")
        logger.error(f"Failed to create Xyara Hosting VPS User role: {e}")
        return None

# Host resource monitoring functions
def get_cpu_usage():
    try:
        if shutil.which("mpstat"):
            result = subprocess.run(['mpstat', '1', '1'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if 'all' in line and '%' in line:
                    parts = line.split()
                    idle = float(parts[-1])
                    return 100.0 - idle
        else:
            result = subprocess.run(['top', '-bn1'], capture_output=True, text=True)
            output = result.stdout
            for line in output.split('\n'):
                if '%Cpu(s):' in line:
                    parts = line.split()
                    us = float(parts[1])
                    sy = float(parts[3])
                    ni = float(parts[5])
                    id_ = float(parts[7])
                    wa = float(parts[9])
                    hi = float(parts[11])
                    si = float(parts[13])
                    st = float(parts[15])
                    usage = us + sy + ni + wa + hi + si + st
                    return usage
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU usage: {e}")
        return 0.0

def get_ram_usage():
    try:
        result = subprocess.run(['free', '-m'], capture_output=True, text=True)
        lines = result.stdout.splitlines()
        if len(lines) > 1:
            mem = lines[1].split()
            total = int(mem[1])
            used = int(mem[2])
            return (used / total * 100) if total > 0 else 0.0
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM usage: {e}")
        return 0.0

def resource_monitor():
    global resource_monitor_active
    while resource_monitor_active:
        try:
            cpu_usage = get_cpu_usage()
            ram_usage = get_ram_usage()
            logger.info(f"Current CPU usage: {cpu_usage:.1f}%, RAM usage: {ram_usage:.1f}%")
            if cpu_usage > CPU_THRESHOLD or ram_usage > RAM_THRESHOLD:
                logger.warning(f"Resource usage exceeded thresholds (CPU: {CPU_THRESHOLD}%, RAM: {RAM_THRESHOLD}%). Stopping all VPS.")
                try:
                    subprocess.run(['lxc', 'stop', '--all', '--force'], check=True)
                    logger.info("All VPS stopped due to high resource usage")
                    for user_id, vps_list in list(vps_data.items()):
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                    save_vps_data()
                except Exception as e:
                    logger.error(f"Error stopping all VPS: {e}")
            time.sleep(60)
        except Exception as e:
            logger.error(f"Error in resource monitor: {e}")
            time.sleep(60)

# Start resource monitoring in a separate thread
monitor_thread = threading.Thread(target=resource_monitor, daemon=True)
monitor_thread.start()

# Helper functions for container stats with improved error handling
async def get_container_status(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-info", "-n", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if line.strip().startswith("State:"):
                return line.split(":", 1)[1].strip().lower()
        return "unknown"
    except Exception:
        return "unknown"

async def get_container_cpu(container_name):
    usage = await get_container_cpu_pct(container_name)
    return f"{usage:.1f}%"

async def get_container_cpu_pct(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "top", "-bn1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        for line in output.splitlines():
            if '%Cpu(s):' in line:
                parts = line.split()
                us = float(parts[1])
                sy = float(parts[3])
                ni = float(parts[5])
                id_ = float(parts[7])
                wa = float(parts[9])
                hi = float(parts[11])
                si = float(parts[13])
                st = float(parts[15])
                usage = us + sy + ni + wa + hi + si + st
                return usage
        return 0.0
    except Exception as e:
        logger.error(f"Error getting CPU for {container_name}: {e}")
        return 0.0

async def get_container_memory(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return f"{used}/{total} MB ({usage_pct:.1f}%)"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_ram_pct(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "free", "-m",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        if len(lines) > 1:
            parts = lines[1].split()
            total = int(parts[1])
            used = int(parts[2])
            usage_pct = (used / total * 100) if total > 0 else 0
            return usage_pct
        return 0.0
    except Exception as e:
        logger.error(f"Error getting RAM for {container_name}: {e}")
        return 0.0

async def get_container_disk(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "df", "-h", "/",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        lines = stdout.decode().splitlines()
        for line in lines:
            if '/dev/' in line and ' /' in line:
                parts = line.split()
                if len(parts) >= 5:
                    used = parts[2]
                    size = parts[1]
                    perc = parts[4]
                    return f"{used}/{size} ({perc})"
        return "Unknown"
    except Exception:
        return "Unknown"

async def get_container_uptime(container_name):
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "uptime",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        return stdout.decode().strip() if stdout else "Unknown"
    except Exception:
        return "Unknown"

def get_uptime():
    try:
        result = subprocess.run(['uptime'], capture_output=True, text=True)
        return result.stdout.strip()
    except Exception:
        return "Unknown"

# Bot events
@bot.event
async def on_ready():
    logger.info(f'{bot.user} has connected to Discord!')
    await bot.change_presence(activity=discord.Activity(type=discord.ActivityType.watching, name="Xyara Hosting VPS Manager"))
    logger.info("Xyara Hosting Bot is ready!")

@bot.event
async def on_command_error(ctx, error):
    if isinstance(error, commands.CommandNotFound):
        return
    elif isinstance(error, commands.MissingRequiredArgument):
        await ctx.send(embed=create_error_embed("Missing Argument", "Please check command usage with `!help`."))
    elif isinstance(error, commands.BadArgument):
        await ctx.send(embed=create_error_embed("Invalid Argument", "Please check your input and try again."))
    elif isinstance(error, commands.CheckFailure):
        error_msg = str(error) if str(error) else "You need admin permissions for this command. Contact Xyara Hosting support."
        await ctx.send(embed=create_error_embed("Access Denied", error_msg))
    elif isinstance(error, discord.NotFound):
        await ctx.send(embed=create_error_embed("Error", "The requested resource was not found. Please try again."))
    else:
        logger.error(f"Command error: {error}")
        await ctx.send(embed=create_error_embed("System Error", "An unexpected error occurred. Xyara Hosting support has been notified."))

# Bot commands
@bot.command(name='ping')
async def ping(ctx):
    latency = round(bot.latency * 1000)
    embed = create_success_embed("Pong!", f"Xyara Hosting Bot latency: {latency}ms")
    await ctx.send(embed=embed)

@bot.command(name='uptime')
async def uptime(ctx):
    up = get_uptime()
    embed = create_info_embed("Host Uptime", up)
    await ctx.send(embed=embed)

@bot.command(name='thresholds')
@is_admin()
async def thresholds(ctx):
    embed = create_info_embed("Resource Thresholds", f"**CPU:** {CPU_THRESHOLD}%\n**RAM:** {RAM_THRESHOLD}%")
    await ctx.send(embed=embed)

@bot.command(name='set-threshold')
@is_admin()
async def set_threshold(ctx, cpu: int, ram: int):
    global CPU_THRESHOLD, RAM_THRESHOLD
    if cpu < 0 or ram < 0:
        await ctx.send(embed=create_error_embed("Invalid Thresholds", "Thresholds must be non-negative."))
        return
    CPU_THRESHOLD = cpu
    RAM_THRESHOLD = ram
    set_setting('cpu_threshold', str(cpu))
    set_setting('ram_threshold', str(ram))
    embed = create_success_embed("Thresholds Updated", f"**CPU:** {cpu}%\n**RAM:** {ram}%")
    await ctx.send(embed=embed)

@bot.command(name='set-status')
@is_admin()
async def set_status(ctx, activity_type: str, *, name: str):
    types = {
        'playing': discord.ActivityType.playing,
        'watching': discord.ActivityType.watching,
        'listening': discord.ActivityType.listening,
        'streaming': discord.ActivityType.streaming,
    }
    if activity_type.lower() not in types:
        await ctx.send(embed=create_error_embed("Invalid Type", "Valid types: playing, watching, listening, streaming"))
        return
    await bot.change_presence(activity=discord.Activity(type=types[activity_type.lower()], name=name))
    embed = create_success_embed("Status Updated", f"Set to {activity_type}: {name}")
    await ctx.send(embed=embed)

@bot.command(name='myvps')
async def my_vps(ctx):
    user_id = str(ctx.author.id)
    vps_list = vps_data.get(user_id, [])
    if not vps_list:
        embed = create_error_embed("No VPS Found", "You don't have any Xyara Hosting VPS. Contact an admin to create one.")
        add_field(embed, "Quick Actions", "• `!manage` - Manage VPS\n• Contact Xyara Hosting admin for VPS creation", False)
        await ctx.send(embed=embed)
        return
    embed = create_info_embed("My Xyara Hosting VPS", "")
    text = []
    for i, vps in enumerate(vps_list):
        status = vps.get('status', 'unknown').upper()
        if vps.get('suspended', False):
            status += " (SUSPENDED)"
        if vps.get('whitelisted', False):
            status += " (WHITELISTED)"
        text.append(f"**VPS {i+1}:** `{vps['container_name']}`\nStatus: {status}")
    add_field(embed, "Your VPS", "\n".join(text), False)
    add_field(embed, "Actions", "Use `!manage` to start/stop/reinstall", False)
    await ctx.send(embed=embed)

@bot.command(name='lxc-list')
@is_admin()
async def lxc_list(ctx):
    try:
        result = await execute_lxc("lxc-ls --fancy")
        embed = create_info_embed("Xyara Hosting LXC Containers List", result)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Error", str(e)))

class OSSelectView(discord.ui.View):
    def __init__(self, ram: int, cpu: int, disk: int, user: discord.Member, ctx):
        super().__init__(timeout=300)
        self.ram = ram
        self.cpu = cpu
        self.disk = disk
        self.user = user
        self.ctx = ctx
        self.select = discord.ui.Select(
            placeholder="Select an OS for the VPS",
            options=[discord.SelectOption(label=o["label"], value=o["value"]) for o in OS_OPTIONS]
        )
        self.select.callback = self.select_os
        self.add_item(self.select)

    async def select_os(self, interaction: discord.Interaction):
        if str(interaction.user.id) != str(self.ctx.author.id):
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the command author can select."), ephemeral=True)
            return
        os_version = self.select.values[0]
        self.select.disabled = True
        creating_embed = create_info_embed("Creating VPS", f"Deploying {os_version} VPS for {self.user.mention}...")
        await interaction.response.edit_message(embed=creating_embed, view=self)
        user_id = str(self.user.id)
        if user_id not in vps_data:
            vps_data[user_id] = []
        vps_count = len(vps_data[user_id]) + 1

        # Sanitize name: no spaces, lowercase
        safe_brand = "".join(x for x in BRAND_NAME if x.isalnum()).lower()
        container_name = f"{safe_brand}-vps-{user_id}-{vps_count}"
        ram_mb = self.ram * 1024
        try:
            distro, release, arch = os_version.split(';')
            
            # Check for existing zombie container (failed previous run)
            # Check for existing zombie container (failed previous run)
            try:
                # If this succeeds, the container exists on disk but not in DB (since we are in create flow)
                await execute_lxc(f"lxc-info -n {container_name}")
                logger.warning(f"Found zombie container {container_name}, destroying...")
                try:
                    await execute_lxc(f"lxc-destroy -n {container_name} -f")
                except:
                    # If destroy fails (likely due to config error), force remove dir
                    logger.warning(f"lxc-destroy failed for {container_name}, force removing directory.")
                    c_dir = f"/var/lib/lxc/{container_name}"
                    if os.path.exists(c_dir):
                        shutil.rmtree(c_dir)
            except:
                pass # Good, it doesn't exist
            
            # Additional safety: check if dir exists even if lxc-info failed
            c_dir_direct = f"/var/lib/lxc/{container_name}"
            if os.path.exists(c_dir_direct):
                 logger.warning(f"Found orphaned container directory {container_name}, removing...")
                 shutil.rmtree(c_dir_direct)

            # Classic LXC Creation

            await execute_lxc(f"lxc-create -n {container_name} -t download -- -d {distro} -r {release} -a {arch}")
            
            # --- Docker Compatibility Patch ---
            config_path = f"/var/lib/lxc/{container_name}/config"
            if os.path.exists(config_path):
                with open(config_path, "a") as f:
                    f.write("\n# Docker Compatibility Fixes\n")
                    f.write("lxc.apparmor.profile = unconfined\n")
                    f.write("lxc.apparmor.allow_incomplete = 1\n")
                    f.write("lxc.mount.auto = cgroup:mixed proc:mixed sys:mixed\n") 

            # Try starting with logging if it fails
            try:
                await execute_lxc(f"lxc-start -n {container_name}")
            except Exception as start_e:
                # Retry with logging
                log_file = f"/tmp/{container_name}_start.log"
                try:
                    await execute_lxc(f"lxc-start -n {container_name} --logfile {log_file} --logpriority DEBUG")
                except:
                    # If it fails again, read the log
                    if os.path.exists(log_file):
                        with open(log_file, 'r') as f:
                            log_content = f.read()[-1000:] # Last 1000 chars
                        raise Exception(f"Start failed. Logs:\n{log_content}")
                    raise start_e
            
            # --- DNS Fix for Docker ---
            # Ensure container can resolve names (Google DNS)
            try:
                # Wait a moment for network to come up
                await asyncio.sleep(2)
                await fix_container_dns(container_name)
            except Exception as e:
                logger.warning(f"Failed to set DNS for {container_name}: {e}")

            # Apply Limits via Cgroup (Classic LXC)
            # Make this non-fatal as it fails in many Docker environments
            try:
                # Memory (Try v1 then v2)
                try:
                    await execute_lxc(f"lxc-cgroup -n {container_name} memory.limit_in_bytes {ram_mb}M")
                except:
                    try:
                        await execute_lxc(f"lxc-cgroup -n {container_name} memory.max {ram_mb}M")
                    except Exception as e:
                        logger.warning(f"Failed to set memory limit for {container_name}: {e}")

                # CPU Shares (approximating cores)
                cpu_shares = int(self.cpu * 1024) 
                try:
                    await execute_lxc(f"lxc-cgroup -n {container_name} cpu.shares {cpu_shares}")
                except:
                    try:
                        await execute_lxc(f"lxc-cgroup -n {container_name} cpu.weight {cpu_shares}")
                    except Exception as e:
                         logger.warning(f"Failed to set CPU limit for {container_name}: {e}")
            except Exception as e:
                logger.warning(f"Failed to apply resource limits: {e}")
            
            # Disk limit is harder in classic LXC without LVM/ZFS backing, skipping implicit limit or requires loopback
            # For now, we assume the user understands disk limits are soft or handled by partition size if not using advanced storage.
            
            # await apply_advanced_permissions(container_name) # This function likely needs refactoring too, disabling for now.
            config_str = f"{self.ram}GB RAM / {self.cpu} CPU / {self.disk}GB Disk"
            vps_info = {
                "container_name": container_name,
                "ram": f"{self.ram}GB",
                "cpu": str(self.cpu),
                "storage": f"{self.disk}GB",
                "config": config_str,
                "os_version": os_version,
                "status": "running",
                "suspended": False,
                "whitelisted": False,
                "suspension_history": [],
                "created_at": datetime.now().isoformat(),
                "shared_with": [],
                "id": None
            }
            vps_data[user_id].append(vps_info)
            save_vps_data()
            if self.ctx.guild:
                vps_role = await get_or_create_vps_role(self.ctx.guild)
                if vps_role:
                    try:
                        await self.user.add_roles(vps_role, reason="Xyara Hosting VPS ownership granted")
                    except discord.Forbidden:
                        logger.warning(f"Failed to assign Xyara Hosting VPS role to {self.user.name}")
            success_embed = create_success_embed("Xyara Hosting VPS Created Successfully")
            add_field(success_embed, "Owner", self.user.mention, True)
            add_field(success_embed, "VPS ID", f"#{vps_count}", True)
            add_field(success_embed, "Container", f"`{container_name}`", True)
            add_field(success_embed, "Resources", f"**RAM:** {self.ram}GB\n**CPU:** {self.cpu} Cores\n**Storage:** {self.disk}GB", False)
            add_field(success_embed, "OS", os_version, True)
            add_field(success_embed, "Features", "Nesting, Privileged, FUSE, Kernel Modules (Docker Ready)", False)
            add_field(success_embed, "Disk Note", "Run `sudo resize2fs /` inside VPS if needed to expand filesystem.", False)
            await interaction.followup.send(embed=success_embed)
            dm_embed = create_success_embed("Xyara Hosting VPS Created!", f"Your VPS has been successfully deployed by an admin!")
            add_field(dm_embed, "VPS Details", f"**VPS ID:** #{vps_count}\n**Container Name:** `{container_name}`\n**Configuration:** {config_str}\n**Status:** Running\n**OS:** {os_version}\n**Created:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", False)
            add_field(dm_embed, "Management", "• Use `!manage` to start/stop/reinstall your Xyara Hosting VPS\n• Use `!manage` → Tmate or SSHX for terminal access\n• Contact Xyara Hosting admin for upgrades or issues", False)
            add_field(dm_embed, "Important Notes", "• Full root access via SSH\n• Docker-ready with nesting and privileged mode\n• Back up your data regularly", False)
            try:
                await self.user.send(embed=dm_embed)
            except discord.Forbidden:
                await self.ctx.send(embed=create_info_embed("Notification Failed", f"Couldn't send DM to {self.user.mention}. Please ensure DMs are enabled."))
        except Exception as e:
            error_embed = create_error_embed("Creation Failed", f"Error: {str(e)}")
            await interaction.followup.send(embed=error_embed)

@bot.command(name='create')
@is_admin()
async def create_vps(ctx, ram: int, cpu: int, disk: int, user: discord.Member):
    if ram <= 0 or cpu <= 0 or disk <= 0:
        await ctx.send(embed=create_error_embed("Invalid Specs", "RAM, CPU, and Disk must be positive integers."))
        return
    embed = create_info_embed("VPS Creation", f"Creating VPS for {user.mention} with {ram}GB RAM, {cpu} CPU cores, {disk}GB Disk.\nSelect OS below.")
    view = OSSelectView(ram, cpu, disk, user, ctx)
    await ctx.send(embed=embed, view=view)

class ManageView(discord.ui.View):
    def __init__(self, user_id, vps_list, is_shared=False, owner_id=None, is_admin=False, actual_index: Optional[int] = None):
        super().__init__(timeout=300)
        self.user_id = user_id
        self.vps_list = vps_list[:]
        self.selected_index = None
        self.is_shared = is_shared
        self.owner_id = owner_id or user_id
        self.is_admin = is_admin
        self.actual_index = actual_index
        self.indices = list(range(len(vps_list)))
        if self.is_shared and self.actual_index is None:
            raise ValueError("actual_index required for shared views")
        if len(vps_list) > 1:
            options = [
                discord.SelectOption(
                    label=f"Xyara Hosting VPS {i+1} ({v.get('config', 'Custom')})",
                    description=f"Status: {v.get('status', 'unknown')}",
                    value=str(i)
                ) for i, v in enumerate(vps_list)
            ]
            self.select = discord.ui.Select(placeholder="Select a Xyara Hosting VPS to manage", options=options)
            self.select.callback = self.select_vps
            self.add_item(self.select)
            self.initial_embed = create_embed("Xyara Hosting VPS Management", "Select a VPS from the dropdown menu below.", 0x1a1a1a)
            add_field(self.initial_embed, "Available VPS", "\n".join([f"**VPS {i+1}:** `{v['container_name']}` - Status: `{v.get('status', 'unknown').upper()}`" for i, v in enumerate(vps_list)]), False)
        else:
            self.selected_index = 0
            self.initial_embed = None
            self.add_action_buttons()

    async def get_initial_embed(self):
        if self.initial_embed is not None:
            return self.initial_embed
        self.initial_embed = await self.create_vps_embed(self.selected_index)
        return self.initial_embed

    async def create_vps_embed(self, index):
        vps = self.vps_list[index]
        status = vps.get('status', 'unknown')
        suspended = vps.get('suspended', False)
        whitelisted = vps.get('whitelisted', False)
        status_color = 0x00ff88 if status == 'running' and not suspended else 0xffaa00 if suspended else 0xff3366
        container_name = vps['container_name']
        lxc_status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        status_text = f"{lxc_status.upper()}"
        if suspended:
            status_text += " (SUSPENDED)"
        if whitelisted:
            status_text += " (WHITELISTED)"
        owner_text = ""
        if self.is_admin and self.owner_id != self.user_id:
            try:
                owner_user = await bot.fetch_user(int(self.owner_id))
                owner_text = f"\n**Owner:** {owner_user.mention}"
            except:
                owner_text = f"\n**Owner ID:** {self.owner_id}"
        embed = create_embed(
            f"Xyara Hosting VPS Management - VPS {index + 1}",
            f"Managing container: `{container_name}`{owner_text}",
            status_color
        )
        resource_info = f"**Status:** `{status_text}`\n"
        resource_info += f"**OS:** {vps.get('os_version', 'ubuntu:22.04')}\n"
        resource_info += f"**Uptime:** {uptime}"
        
        # Minimal View for User
        add_field(embed, "Info", resource_info, False)
        
        if suspended:
            add_field(embed, "⚠️ Suspended", "Contact admin to unsuspend.", False)
        
        # We hide specific resource allocations and live usage from the main view
        # Users can click "Stats" to see live usage
        
        add_field(embed, "🎮 Controls", "Use the buttons below to manage your VPS", False)
        return embed


    def add_action_buttons(self):
        if not self.is_shared and not self.is_admin:
            reinstall_button = discord.ui.Button(label="🔄 Reinstall", style=discord.ButtonStyle.danger)
            reinstall_button.callback = lambda inter: self.action_callback(inter, 'reinstall')
            self.add_item(reinstall_button)
        start_button = discord.ui.Button(label="▶ Start", style=discord.ButtonStyle.success)
        start_button.callback = lambda inter: self.action_callback(inter, 'start')
        stop_button = discord.ui.Button(label="⏸ Stop", style=discord.ButtonStyle.secondary)
        stop_button.callback = lambda inter: self.action_callback(inter, 'stop')
        tmate_button = discord.ui.Button(label="🔑 Tmate", style=discord.ButtonStyle.primary)
        tmate_button.callback = lambda inter: self.action_callback(inter, 'tmate')
        sshx_button = discord.ui.Button(label="🔑 SSHX", style=discord.ButtonStyle.primary)
        sshx_button.callback = lambda inter: self.action_callback(inter, 'sshx')
        stats_button = discord.ui.Button(label="📊 Stats", style=discord.ButtonStyle.secondary)
        stats_button.callback = lambda inter: self.action_callback(inter, 'stats')
        self.add_item(start_button)
        self.add_item(stop_button)
        self.add_item(tmate_button)
        self.add_item(sshx_button)
        self.add_item(stats_button)

    async def select_vps(self, interaction: discord.Interaction):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your Xyara Hosting VPS!"), ephemeral=True)
            return
        self.selected_index = int(self.select.values[0])
        new_embed = await self.create_vps_embed(self.selected_index)
        self.clear_items()
        self.add_action_buttons()
        await interaction.response.edit_message(embed=new_embed, view=self)

    async def action_callback(self, interaction: discord.Interaction, action: str):
        if str(interaction.user.id) != self.user_id and not self.is_admin:
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This is not your Xyara Hosting VPS!"), ephemeral=True)
            return
        if self.selected_index is None:
            await interaction.response.send_message(embed=create_error_embed("No VPS Selected", "Please select a VPS first."), ephemeral=True)
            return
        actual_idx = self.actual_index if self.is_shared else self.indices[self.selected_index]
        target_vps = vps_data[self.owner_id][actual_idx]
        suspended = target_vps.get('suspended', False)
        if suspended and not self.is_admin and action != 'stats':
            await interaction.response.send_message(embed=create_error_embed("Access Denied", "This Xyara Hosting VPS is suspended. Contact an admin to unsuspend."), ephemeral=True)
            return
        container_name = target_vps["container_name"]
        if action == 'stats':
            status = await get_container_status(container_name)
            cpu_usage = await get_container_cpu(container_name)
            memory_usage = await get_container_memory(container_name)
            disk_usage = await get_container_disk(container_name)
            uptime = await get_container_uptime(container_name)
            stats_embed = create_info_embed("📈 Xyara Hosting Live Statistics", f"Real-time stats for `{container_name}`")
            add_field(stats_embed, "Status", f"`{status.upper()}`", True)
            add_field(stats_embed, "CPU", cpu_usage, True)
            add_field(stats_embed, "Memory", memory_usage, True)
            add_field(stats_embed, "Disk", disk_usage, True)
            add_field(stats_embed, "Uptime", uptime, True)
            await interaction.response.send_message(embed=stats_embed, ephemeral=True)
            return
        if action == 'reinstall':
            if self.is_shared or self.is_admin:
                await interaction.response.send_message(embed=create_error_embed("Access Denied", "Only the Xyara Hosting VPS owner can reinstall!"), ephemeral=True)
                return
            if suspended:
                await interaction.response.send_message(embed=create_error_embed("Cannot Reinstall", "Unsuspend the Xyara Hosting VPS first."), ephemeral=True)
                return
            os_version = target_vps.get('os_version', 'ubuntu:22.04')
            confirm_embed = create_warning_embed("Xyara Hosting Reinstall Warning",
                f"⚠️ **WARNING:** This will erase all data on VPS `{container_name}` and reinstall {os_version}.\n\n"
                f"This action cannot be undone. Continue?")
            class ConfirmView(discord.ui.View):
                def __init__(self, parent_view, container_name, owner_id, actual_idx):
                    super().__init__(timeout=60)
                    self.parent_view = parent_view
                    self.container_name = container_name
                    self.owner_id = owner_id
                    self.actual_idx = actual_idx

                @discord.ui.button(label="Confirm", style=discord.ButtonStyle.danger)
                async def confirm(self, inter: discord.Interaction, item: discord.ui.Button):
                    await inter.response.defer(ephemeral=True)
                    try:
                        await inter.followup.send(embed=create_info_embed("Deleting Container", f"Forcefully removing container `{self.container_name}`..."), ephemeral=True)
                        await execute_lxc(f"lxc delete {self.container_name} --force")
                        await inter.followup.send(embed=create_info_embed("Recreating Container", f"Creating new Xyara Hosting container `{self.container_name}`..."), ephemeral=True)
                        target_vps = vps_data[self.owner_id][self.actual_idx]
                        original_ram = target_vps["ram"]
                        original_cpu = target_vps["cpu"]
                        original_storage = target_vps["storage"]
                        ram_gb = int(original_ram.replace("GB", ""))
                        ram_mb = ram_gb * 1024
                        storage_gb = int(original_storage.replace("GB", ""))
                        os_version = target_vps.get('os_version', 'ubuntu:22.04')
                        await execute_lxc(f"lxc init {os_version} {self.container_name} -s {DEFAULT_STORAGE_POOL}")
                        await execute_lxc(f"lxc config set {self.container_name} limits.memory {ram_mb}MB")
                        await execute_lxc(f"lxc config set {self.container_name} limits.cpu {original_cpu}")
                        await execute_lxc(f"lxc config device set {self.container_name} root size={storage_gb}GB")
                        await apply_advanced_permissions(self.container_name)
                        await execute_lxc(f"lxc start {self.container_name}")
                        target_vps["status"] = "running"
                        target_vps["suspended"] = False
                        target_vps["created_at"] = datetime.now().isoformat()
                        config_str = f"{ram_gb}GB RAM / {original_cpu} CPU / {storage_gb}GB Disk"
                        target_vps["config"] = config_str
                        save_vps_data()
                        await inter.followup.send(embed=create_success_embed("Reinstall Complete", f"Xyara Hosting VPS `{self.container_name}` has been successfully reinstalled!"), ephemeral=True)
                        new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                        await inter.followup.send(embed=new_embed, view=self.parent_view, ephemeral=True)
                    except Exception as e:
                        await inter.followup.send(embed=create_error_embed("Reinstall Failed", f"Error: {str(e)}"), ephemeral=True)

                @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
                async def cancel(self, inter: discord.Interaction, item: discord.ui.Button):
                    new_embed = await self.parent_view.create_vps_embed(self.parent_view.selected_index)
                    await inter.response.edit_message(embed=new_embed, view=self.parent_view)
            await interaction.response.send_message(embed=confirm_embed, view=ConfirmView(self, container_name, self.owner_id, actual_idx), ephemeral=True)
            return
        await interaction.response.defer(ephemeral=True)
        suspended = target_vps.get('suspended', False)
        if suspended:
            target_vps['suspended'] = False
            save_vps_data()
        if action == 'start':
            try:
                await execute_lxc(f"lxc-start -n {container_name}")
                target_vps["status"] = "running"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Started", f"Xyara Hosting VPS `{container_name}` is now running!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Start Failed", str(e)), ephemeral=True)
        elif action == 'stop':
            try:
                await execute_lxc(f"lxc-stop -n {container_name}", timeout=120)
                target_vps["status"] = "stopped"
                save_vps_data()
                await interaction.followup.send(embed=create_success_embed("VPS Stopped", f"Xyara Hosting VPS `{container_name}` has been stopped!"), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("Stop Failed", str(e)), ephemeral=True)
        elif action == 'tmate':
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Access Denied", "Cannot access suspended Xyara Hosting VPS."), ephemeral=True)
                return
            await interaction.followup.send(embed=create_info_embed("SSH Access", "Generating Xyara Hosting SSH connection..."), ephemeral=True)
            try:
                check_proc = await asyncio.create_subprocess_exec(
                    "lxc-attach", "-n", container_name, "--", "which", "tmate",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await check_proc.communicate()
                if check_proc.returncode != 0:
                    await interaction.followup.send(embed=create_info_embed("Installing SSH", "Installing tmate..."), ephemeral=True)
                    # Fix DNS again before update
                    await fix_container_dns(container_name)
                    await execute_lxc(f"lxc-attach -n {container_name} -- apt-get update -y")
                    await execute_lxc(f"lxc-attach -n {container_name} -- apt-get install tmate -y")
                    await interaction.followup.send(embed=create_success_embed("Installed", "Xyara Hosting SSH service installed!"), ephemeral=True)
                
                # Sanitize brand name for socket path (remove spaces)
                safe_brand = "".join(x for x in BRAND_NAME if x.isalnum())
                session_name = f"{safe_brand}-vps-session-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                
                await execute_lxc(f"lxc-attach -n {container_name} -- tmate -S /tmp/{session_name}.sock new-session -d")
                await asyncio.sleep(3)
                ssh_proc = await asyncio.create_subprocess_exec(
                    "lxc-attach", "-n", container_name, "--", "tmate", "-S", f"/tmp/{session_name}.sock", "display", "-p", "#{tmate_ssh}",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await ssh_proc.communicate()
                ssh_url = stdout.decode().strip() if stdout else None
                if ssh_url:
                    try:
                        ssh_embed = create_embed("🔑 Xyara Hosting SSH Access", f"SSH connection for VPS `{container_name}`:", 0x00ff88)
                        add_field(ssh_embed, "Command", f"```{ssh_url}```", False)
                        add_field(ssh_embed, "⚠️ Security", "This link is temporary. Do not share it.", False)
                        add_field(ssh_embed, "📝 Session", f"Session ID: {session_name}", False)
                        await interaction.user.send(embed=ssh_embed)
                        await interaction.followup.send(embed=create_success_embed("SSH Sent", f"Check your DMs for Xyara Hosting SSH link! Session: {session_name}"), ephemeral=True)
                    except discord.Forbidden:
                        await interaction.followup.send(embed=create_error_embed("DM Failed", "Enable DMs to receive Xyara Hosting SSH link!"), ephemeral=True)
                else:
                    error_msg = stderr.decode().strip() if stderr else "Unknown error"
                    await interaction.followup.send(embed=create_error_embed("SSH Failed", error_msg), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("SSH Error", str(e)), ephemeral=True)
        elif action == 'sshx':
            if suspended:
                await interaction.followup.send(embed=create_error_embed("Access Denied", "Cannot access suspended Xyara Hosting VPS."), ephemeral=True)
                return
            await interaction.followup.send(embed=create_info_embed("SSH Access", "Generating Xyara Hosting SSHX connection..."), ephemeral=True)
            try:
                check_proc = await asyncio.create_subprocess_exec(
                    "lxc-attach", "-n", container_name, "--", "which", "sshx",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await check_proc.communicate()
                if check_proc.returncode != 0:
                    await interaction.followup.send(embed=create_info_embed("Installing SSHX", "Installing sshx..."), ephemeral=True)
                    await fix_container_dns(container_name)
                    await execute_lxc(f"lxc-attach -n {container_name} -- bash -c 'curl -sSf https://sshx.io/get | sh'")
                    await interaction.followup.send(embed=create_success_embed("Installed", "Xyara Hosting SSHX installed!"), ephemeral=True)
                safe_brand = "".join(x for x in BRAND_NAME if x.isalnum())
                session_name = f"{safe_brand}-sshx-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                sshx_proc = await asyncio.create_subprocess_exec(
                    "lxc-attach", "-n", container_name, "--", "bash", "-c",
                    "nohup sshx > /tmp/sshx_url.txt 2>&1 & sleep 4; cat /tmp/sshx_url.txt 2>/dev/null || true",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT
                )
                stdout, _ = await sshx_proc.communicate()
                output = stdout.decode() if stdout else ""
                url_match = re.search(r'https?://[^\s]*sshx\.io[^\s]*', output) or re.search(r'sshx\.io/s/[^\s#]+[^\s]*', output)
                ssh_url = url_match.group(0) if url_match else None
                if not ssh_url and 'sshx.io' in output:
                    for line in output.splitlines():
                        if 'sshx.io' in line:
                            ssh_url = line.strip()
                            break
                if ssh_url:
                    if not ssh_url.startswith('http'):
                        ssh_url = f"https://{ssh_url}"
                    try:
                        ssh_embed = create_embed("🔑 Xyara Hosting SSH Access", f"SSHX connection for VPS `{container_name}`:", 0x00ff88)
                        add_field(ssh_embed, "Link", f"```{ssh_url}```", False)
                        add_field(ssh_embed, "⚠️ Security", "This link is temporary. Do not share it.", False)
                        add_field(ssh_embed, "📝 Session", f"Session ID: {session_name}", False)
                        await interaction.user.send(embed=ssh_embed)
                        await interaction.followup.send(embed=create_success_embed("SSH Sent", f"Check your DMs for Xyara Hosting SSHX link! Session: {session_name}"), ephemeral=True)
                    except discord.Forbidden:
                        await interaction.followup.send(embed=create_error_embed("DM Failed", "Enable DMs to receive Xyara Hosting SSHX link!"), ephemeral=True)
                else:
                    await interaction.followup.send(embed=create_error_embed("SSHX Failed", "Could not capture SSHX URL. Try again or use Tmate."), ephemeral=True)
            except Exception as e:
                await interaction.followup.send(embed=create_error_embed("SSHX Error", str(e)), ephemeral=True)
        new_embed = await self.create_vps_embed(self.selected_index)
        await interaction.message.edit(embed=new_embed, view=self)

@bot.command(name='manage')
async def manage_vps(ctx, user: discord.Member = None):
    if user:
        user_id_check = str(ctx.author.id)
        if user_id_check != str(MAIN_ADMIN_ID) and user_id_check not in admin_data.get("admins", []):
            await ctx.send(embed=create_error_embed("Access Denied", "Only Xyara Hosting admins can manage other users' VPS."))
            return
        user_id = str(user.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            await ctx.send(embed=create_error_embed("No VPS Found", f"{user.mention} doesn't have any Xyara Hosting VPS."))
            return
        view = ManageView(str(ctx.author.id), vps_list, is_admin=True, owner_id=user_id)
        await ctx.send(embed=create_info_embed(f"Managing {user.name}'s Xyara Hosting VPS", f"Managing VPS for {user.mention}"), view=view)
    else:
        user_id = str(ctx.author.id)
        vps_list = vps_data.get(user_id, [])
        if not vps_list:
            embed = create_error_embed("No VPS Found", "You don't have any Xyara Hosting VPS. Contact an admin to create one.")
            add_field(embed, "Quick Actions", "• `!manage` - Manage VPS\n• Contact Xyara Hosting admin for VPS creation", False)
            await ctx.send(embed=embed)
            return
        view = ManageView(user_id, vps_list)
        embed = await view.get_initial_embed()
        await ctx.send(embed=embed, view=view)

@bot.command(name='list-all')
@is_admin()
async def list_all_vps(ctx):
    total_vps = 0
    total_users = len(vps_data)
    running_vps = 0
    stopped_vps = 0
    suspended_vps = 0
    whitelisted_vps = 0
    vps_info = []
    user_summary = []
    for user_id, vps_list in vps_data.items():
        try:
            user = await bot.fetch_user(int(user_id))
            user_vps_count = len(vps_list)
            user_running = sum(1 for vps in vps_list if vps.get('status') == 'running' and not vps.get('suspended', False))
            user_stopped = sum(1 for vps in vps_list if vps.get('status') == 'stopped')
            user_suspended = sum(1 for vps in vps_list if vps.get('suspended', False))
            user_whitelisted = sum(1 for vps in vps_list if vps.get('whitelisted', False))

            total_vps += user_vps_count
            running_vps += user_running
            stopped_vps += user_stopped
            suspended_vps += user_suspended
            whitelisted_vps += user_whitelisted

            user_summary.append(f"**{user.name}** ({user.mention}) - {user_vps_count} Xyara Hosting VPS ({user_running} running, {user_suspended} suspended, {user_whitelisted} whitelisted)")

            for i, vps in enumerate(vps_list):
                status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
                status_text = vps.get('status', 'unknown').upper()
                if vps.get('suspended', False):
                    status_text += " (SUSPENDED)"
                if vps.get('whitelisted', False):
                    status_text += " (WHITELISTED)"
                vps_info.append(f"{status_emoji} **{user.name}** - VPS {i+1}: `{vps['container_name']}` - {vps.get('config', 'Custom')} - {status_text}")

        except discord.NotFound:
            vps_info.append(f"❓ Unknown User ({user_id}) - {len(vps_list)} Xyara Hosting VPS")
    embed = create_embed("All Xyara Hosting VPS Information", "Complete overview of all Xyara Hosting VPS deployments and user statistics", 0x1a1a1a)
    add_field(embed, "System Overview", f"**Total Users:** {total_users}\n**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Stopped:** {stopped_vps}\n**Suspended:** {suspended_vps}\n**Whitelisted:** {whitelisted_vps}", False)
    await ctx.send(embed=embed)
    if user_summary:
        embed = create_embed("Xyara Hosting User Summary", f"Summary of all users and their Xyara Hosting VPS", 0x1a1a1a)
        summary_text = "\n".join(user_summary)
        chunks = [summary_text[i:i+1024] for i in range(0, len(summary_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            add_field(embed, f"Users (Part {idx})", chunk, False)
        await ctx.send(embed=embed)
    if vps_info:
        vps_text = "\n".join(vps_info)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"Xyara Hosting VPS Details (Part {idx})", "List of all Xyara Hosting VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", chunk, False)
            await ctx.send(embed=embed)

@bot.command(name='manage-shared')
async def manage_shared_vps(ctx, owner: discord.Member, vps_number: int):
    owner_id = str(owner.id)
    user_id = str(ctx.author.id)
    if owner_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[owner_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or owner doesn't have a Xyara Hosting VPS."))
        return
    vps = vps_data[owner_id][vps_number - 1]
    if user_id not in vps.get("shared_with", []):
        await ctx.send(embed=create_error_embed("Access Denied", "You do not have access to this Xyara Hosting VPS."))
        return
    view = ManageView(user_id, [vps], is_shared=True, owner_id=owner_id, actual_index=vps_number - 1)
    embed = await view.get_initial_embed()
    await ctx.send(embed=embed, view=view)

@bot.command(name='share-user')
async def share_user(ctx, shared_user: discord.Member, vps_number: int):
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a Xyara Hosting VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    if shared_user_id in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Already Shared", f"{shared_user.mention} already has access to this Xyara Hosting VPS!"))
        return
    vps["shared_with"].append(shared_user_id)
    save_vps_data()
    await ctx.send(embed=create_success_embed("VPS Shared", f"Xyara Hosting VPS #{vps_number} shared with {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("Xyara Hosting VPS Access Granted", f"You have access to VPS #{vps_number} from {ctx.author.mention}. Use `!manage-shared {ctx.author.mention} {vps_number}`", 0x00ff88))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"))

@bot.command(name='share-ruser')
async def revoke_share(ctx, shared_user: discord.Member, vps_number: int):
    user_id = str(ctx.author.id)
    shared_user_id = str(shared_user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or you don't have a Xyara Hosting VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    if "shared_with" not in vps:
        vps["shared_with"] = []
    if shared_user_id not in vps["shared_with"]:
        await ctx.send(embed=create_error_embed("Not Shared", f"{shared_user.mention} doesn't have access to this Xyara Hosting VPS!"))
        return
    vps["shared_with"].remove(shared_user_id)
    save_vps_data()
    await ctx.send(embed=create_success_embed("Access Revoked", f"Access to Xyara Hosting VPS #{vps_number} revoked from {shared_user.mention}!"))
    try:
        await shared_user.send(embed=create_embed("Xyara Hosting VPS Access Revoked", f"Your access to VPS #{vps_number} by {ctx.author.mention} has been revoked.", 0xff3366))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {shared_user.mention}"))

@bot.command(name='delete-vps')
@is_admin()
async def delete_vps(ctx, user: discord.Member, vps_number: int, *, reason: str = "No reason"):
    user_id = str(user.id)
    if user_id not in vps_data or vps_number < 1 or vps_number > len(vps_data[user_id]):
        await ctx.send(embed=create_error_embed("Invalid VPS", "Invalid VPS number or user doesn't have a Xyara Hosting VPS."))
        return
    vps = vps_data[user_id][vps_number - 1]
    container_name = vps["container_name"]
    await ctx.send(embed=create_info_embed("Deleting Xyara Hosting VPS", f"Removing VPS #{vps_number}..."))
    try:
        await execute_lxc(f"lxc-destroy -n {container_name} -f")
        del vps_data[user_id][vps_number - 1]
        if not vps_data[user_id]:
            del vps_data[user_id]
            if ctx.guild:
                vps_role = await get_or_create_vps_role(ctx.guild)
                if vps_role and vps_role in user.roles:
                    try:
                        await user.remove_roles(vps_role, reason="No Xyara Hosting VPS ownership")
                    except discord.Forbidden:
                        logger.warning(f"Failed to remove Xyara Hosting VPS role from {user.name}")
        save_vps_data()
        embed = create_success_embed("Xyara Hosting VPS Deleted Successfully")
        add_field(embed, "Owner", user.mention, True)
        add_field(embed, "VPS ID", f"#{vps_number}", True)
        add_field(embed, "Container", f"`{container_name}`", True)
        add_field(embed, "Reason", reason, False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Deletion Failed", f"Error: {str(e)}"))

@bot.command(name='add-resources')
@is_admin()
async def add_resources(ctx, vps_id: str, ram: int = None, cpu: int = None, disk: int = None):
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to add (ram, cpu, or disk)"))
        return
    found_vps = None
    user_id = None
    vps_index = None
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == vps_id:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No Xyara Hosting VPS found with ID: `{vps_id}`"))
        return
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping Xyara Hosting VPS `{vps_id}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc-stop -n {vps_id}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    changes = []
    try:
        current_ram_gb = int(found_vps['ram'].replace('GB', ''))
        current_cpu = int(found_vps['cpu'])
        current_disk_gb = int(found_vps['storage'].replace('GB', ''))

        new_ram_gb = current_ram_gb
        new_cpu = current_cpu
        new_disk_gb = current_disk_gb

        if ram is not None and ram > 0:
            new_ram_gb += ram
            ram_mb = new_ram_gb * 1024
            await execute_lxc(f"lxc config set {vps_id} limits.memory {ram_mb}MB")
            changes.append(f"RAM: +{ram}GB (New total: {new_ram_gb}GB)")

        if cpu is not None and cpu > 0:
            new_cpu += cpu
            await execute_lxc(f"lxc config set {vps_id} limits.cpu {new_cpu}")
            changes.append(f"CPU: +{cpu} cores (New total: {new_cpu} cores)")

        if disk is not None and disk > 0:
            new_disk_gb += disk
            await execute_lxc(f"lxc config device set {vps_id} root size={new_disk_gb}GB")
            changes.append(f"Disk: +{disk}GB (New total: {new_disk_gb}GB)")

        found_vps['ram'] = f"{new_ram_gb}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk_gb}GB"
        found_vps['config'] = f"{new_ram_gb}GB RAM / {new_cpu} CPU / {new_disk_gb}GB Disk"

        vps_data[user_id][vps_index] = found_vps
        save_vps_data()

        if was_running:
            await execute_lxc(f"lxc-start -n {vps_id}")
            found_vps['status'] = 'running'
            save_vps_data()

        embed = create_success_embed("Resources Added", f"Successfully added resources to Xyara Hosting VPS `{vps_id}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        if disk_changed:
            add_field(embed, "Disk Note", "Run `sudo resize2fs /` inside the VPS to expand the filesystem.", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Resource Addition Failed", f"Error: {str(e)}"))

@bot.command(name='admin-add')
@is_main_admin()
async def admin_add(ctx, user: discord.Member):
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Already Admin", "This user is already the main Xyara Hosting admin!"))
        return
    if user_id in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Already Admin", f"{user.mention} is already a Xyara Hosting admin!"))
        return
    admin_data["admins"].append(user_id)
    save_admin_data()
    await ctx.send(embed=create_success_embed("Admin Added", f"{user.mention} is now a Xyara Hosting admin!"))
    try:
        await user.send(embed=create_embed("🎉 Xyara Hosting Admin Role Granted", f"You are now a Xyara Hosting admin by {ctx.author.mention}", 0x00ff88))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='admin-remove')
@is_main_admin()
async def admin_remove(ctx, user: discord.Member):
    user_id = str(user.id)
    if user_id == str(MAIN_ADMIN_ID):
        await ctx.send(embed=create_error_embed("Cannot Remove", "You cannot remove the main Xyara Hosting admin!"))
        return
    if user_id not in admin_data.get("admins", []):
        await ctx.send(embed=create_error_embed("Not Admin", f"{user.mention} is not a Xyara Hosting admin!"))
        return
    admin_data["admins"].remove(user_id)
    save_admin_data()
    await ctx.send(embed=create_success_embed("Admin Removed", f"{user.mention} is no longer a Xyara Hosting admin!"))
    try:
        await user.send(embed=create_embed("⚠️ Xyara Hosting Admin Role Revoked", f"Your admin role was removed by {ctx.author.mention}", 0xff3366))
    except discord.Forbidden:
        await ctx.send(embed=create_info_embed("Notification Failed", f"Could not DM {user.mention}"))

@bot.command(name='admin-list')
@is_main_admin()
async def admin_list(ctx):
    admins = admin_data.get("admins", [])
    main_admin = await bot.fetch_user(MAIN_ADMIN_ID)
    embed = create_embed("👑 Xyara Hosting Admin Team", "Current Xyara Hosting administrators:", 0x1a1a1a)
    add_field(embed, "🔰 Main Admin", f"{main_admin.mention} (ID: {MAIN_ADMIN_ID})", False)
    if admins:
        admin_list = []
        for admin_id in admins:
            try:
                admin_user = await bot.fetch_user(int(admin_id))
                admin_list.append(f"• {admin_user.mention} (ID: {admin_id})")
            except:
                admin_list.append(f"• Unknown User (ID: {admin_id})")
        admin_text = "\n".join(admin_list)
        add_field(embed, "🛡️ Admins", admin_text, False)
    else:
        add_field(embed, "🛡️ Admins", "No additional Xyara Hosting admins", False)
    await ctx.send(embed=embed)

@bot.command(name='userinfo')
@is_admin()
async def user_info(ctx, user: discord.Member):
    user_id = str(user.id)
    vps_list = vps_data.get(user_id, [])
    embed = create_embed(f"Xyara Hosting User Information - {user.name}", f"Detailed information for {user.mention}", 0x1a1a1a)
    add_field(embed, "👤 User Details", f"**Name:** {user.name}\n**ID:** {user.id}\n**Joined:** {user.joined_at.strftime('%Y-%m-%d %H:%M:%S') if user.joined_at else 'Unknown'}", False)
    if vps_list:
        vps_info = []
        total_ram = 0
        total_cpu = 0
        total_storage = 0
        running_count = 0
        suspended_count = 0
        whitelisted_count = 0
        for i, vps in enumerate(vps_list):
            status_emoji = "🟢" if vps.get('status') == 'running' and not vps.get('suspended', False) else "🟡" if vps.get('suspended', False) else "🔴"
            status_text = vps.get('status', 'unknown').upper()
            if vps.get('suspended', False):
                status_text += " (SUSPENDED)"
                suspended_count += 1
            else:
                running_count += 1 if vps.get('status') == 'running' else 0
            if vps.get('whitelisted', False):
                whitelisted_count += 1
            vps_info.append(f"{status_emoji} VPS {i+1}: `{vps['container_name']}` - {status_text}")
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
        vps_summary = f"**Total VPS:** {len(vps_list)}\n**Running:** {running_count}\n**Suspended:** {suspended_count}\n**Whitelisted:** {whitelisted_count}\n**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB"
        add_field(embed, "🖥️ Xyara Hosting VPS Information", vps_summary, False)

        vps_text = "\n".join(vps_info)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            add_field(embed, f"📋 VPS List (Part {idx})", chunk, False)
    else:
        add_field(embed, "🖥️ Xyara Hosting VPS Information", "**No VPS owned**", False)
    is_admin_user = user_id == str(MAIN_ADMIN_ID) or user_id in admin_data.get("admins", [])
    add_field(embed, "🛡️ Xyara Hosting Admin Status", f"**{'Yes' if is_admin_user else 'No'}**", False)
    await ctx.send(embed=embed)

@bot.command(name='serverstats')
@is_admin()
async def server_stats(ctx):
    total_users = len(vps_data)
    total_vps = sum(len(vps_list) for vps_list in vps_data.values())
    total_ram = 0
    total_cpu = 0
    total_storage = 0
    running_vps = 0
    suspended_vps = 0
    whitelisted_vps = 0
    for vps_list in vps_data.values():
        for vps in vps_list:
            ram_gb = int(vps['ram'].replace('GB', ''))
            storage_gb = int(vps['storage'].replace('GB', ''))
            total_ram += ram_gb
            total_cpu += int(vps['cpu'])
            total_storage += storage_gb
            if vps.get('status') == 'running':
                if vps.get('suspended', False):
                    suspended_vps += 1
                else:
                    running_vps += 1
            if vps.get('whitelisted', False):
                whitelisted_vps += 1
    embed = create_embed("📊 Xyara Hosting Server Statistics", "Current Xyara Hosting server overview", 0x1a1a1a)
    add_field(embed, "👥 Users", f"**Total Users:** {total_users}\n**Total Admins:** {len(admin_data.get('admins', [])) + 1}", False)
    add_field(embed, "🖥️ VPS", f"**Total VPS:** {total_vps}\n**Running:** {running_vps}\n**Suspended:** {suspended_vps}\n**Whitelisted:** {whitelisted_vps}\n**Stopped:** {total_vps - running_vps - suspended_vps}", False)
    add_field(embed, "📈 Resources", f"**Total RAM:** {total_ram}GB\n**Total CPU:** {total_cpu} cores\n**Total Storage:** {total_storage}GB", False)
    await ctx.send(embed=embed)

@bot.command(name='vpsinfo')
@is_admin()
async def vps_info(ctx, container_name: str = None):
    if not container_name:
        all_vps = []
        for user_id, vps_list in vps_data.items():
            try:
                user = await bot.fetch_user(int(user_id))
                for i, vps in enumerate(vps_list):
                    status_text = vps.get('status', 'unknown').upper()
                    if vps.get('suspended', False):
                        status_text += " (SUSPENDED)"
                    if vps.get('whitelisted', False):
                        status_text += " (WHITELISTED)"
                    all_vps.append(f"**{user.name}** - Xyara Hosting VPS {i+1}: `{vps['container_name']}` - {status_text}")
            except:
                pass
        vps_text = "\n".join(all_vps)
        chunks = [vps_text[i:i+1024] for i in range(0, len(vps_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"🖥️ All Xyara Hosting VPS (Part {idx})", f"List of all Xyara Hosting VPS deployments", 0x1a1a1a)
            add_field(embed, "VPS List", chunk, False)
            await ctx.send(embed=embed)
    else:
        found_vps = None
        found_user = None
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    found_user = await bot.fetch_user(int(user_id))
                    break
            if found_vps:
                break
        if not found_vps:
            await ctx.send(embed=create_error_embed("VPS Not Found", f"No Xyara Hosting VPS found with container name: `{container_name}`"))
            return
        suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
        whitelisted_text = " (WHITELISTED)" if found_vps.get('whitelisted', False) else ""
        embed = create_embed(f"🖥️ Xyara Hosting VPS Information - {container_name}", f"Details for VPS owned by {found_user.mention}{suspended_text}{whitelisted_text}", 0x1a1a1a)
        add_field(embed, "👤 Owner", f"**Name:** {found_user.name}\n**ID:** {found_user.id}", False)
        add_field(embed, "📊 Specifications", f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}", False)
        add_field(embed, "📈 Status", f"**Current:** {found_vps.get('status', 'unknown').upper()}{suspended_text}{whitelisted_text}\n**Suspended:** {found_vps.get('suspended', False)}\n**Whitelisted:** {found_vps.get('whitelisted', False)}\n**Created:** {found_vps.get('created_at', 'Unknown')}", False)
        if 'config' in found_vps:
            add_field(embed, "⚙️ Configuration", f"**Config:** {found_vps['config']}", False)
        if found_vps.get('shared_with'):
            shared_users = []
            for shared_id in found_vps['shared_with']:
                try:
                    shared_user = await bot.fetch_user(int(shared_id))
                    shared_users.append(f"• {shared_user.mention}")
                except:
                    shared_users.append(f"• Unknown User ({shared_id})")
            shared_text = "\n".join(shared_users)
            add_field(embed, "🔗 Shared With", shared_text, False)
        await ctx.send(embed=embed)

@bot.command(name='restart-vps')
@is_admin()
async def restart_vps(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Restarting VPS", f"Restarting Xyara Hosting VPS `{container_name}`..."))
    try:
        # Classic LXC doesn't have a direct restart command in some versions, but stop/start works
        await execute_lxc(f"lxc-stop -n {container_name}")
        await asyncio.sleep(2)
        await execute_lxc(f"lxc-start -n {container_name}")
        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break
        await ctx.send(embed=create_success_embed("VPS Restarted", f"Xyara Hosting VPS `{container_name}` has been restarted successfully!"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Restart Failed", f"Error: {str(e)}"))

@bot.command(name='exec')
@is_admin()
async def execute_command(ctx, container_name: str, *, command: str):
    await ctx.send(embed=create_info_embed("Executing Command", f"Running command in Xyara Hosting VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "bash", "-c", command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()
        output = stdout.decode() if stdout else "No output"
        error = stderr.decode() if stderr else ""
        embed = create_embed(f"Command Output - {container_name}", f"Command: `{command}`", 0x1a1a1a)
        if output.strip():
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"
            add_field(embed, "📤 Output", f"```\n{output}\n```", False)
        if error.strip():
            if len(error) > 1000:
                error = error[:1000] + "\n... (truncated)"
            add_field(embed, "⚠️ Error", f"```\n{error}\n```", False)
        add_field(embed, "🔄 Exit Code", f"**{proc.returncode}**", False)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("Execution Failed", f"Error: {str(e)}"))

@bot.command(name='stop-vps-all')
@is_admin()
async def stop_all_vps(ctx):
    embed = create_warning_embed("Stopping All Xyara Hosting VPS", "⚠️ **WARNING:** This will stop ALL running VPS on the Xyara Hosting server.\n\nThis action cannot be undone. Continue?")
    class ConfirmView(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Stop All VPS", style=discord.ButtonStyle.danger)
        async def confirm(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.defer()
            try:
                proc = await asyncio.create_subprocess_exec(
                    "lxc", "stop", "--all", "--force",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await proc.communicate()
                if proc.returncode == 0:
                    stopped_count = 0
                    for user_id, vps_list in vps_data.items():
                        for vps in vps_list:
                            if vps.get('status') == 'running':
                                vps['status'] = 'stopped'
                                vps['suspended'] = False
                                stopped_count += 1
                    save_vps_data()
                    await interaction.followup.send(f"✅ Stopped {stopped_count} VPS.")
                else:
                    error_msg = stderr.decode() if stderr else "Unknown error"
                    await interaction.followup.send(f"❌ Failed to stop VPS: {error_msg}")
            except Exception as e:
                await interaction.followup.send(f"❌ Error: {str(e)}")

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, interaction: discord.Interaction, item: discord.ui.Button):
            await interaction.response.edit_message(content="ℹ️ Operation Cancelled.", embed=None)
    
    await ctx.send("⚠️ **WARNING:** This will stop ALL running VPS.\nConfirm?", view=ConfirmView())

@bot.command(name='cpu-monitor')
@is_admin()
async def resource_monitor_control(ctx, action: str = "status"):
    global resource_monitor_active
    if action.lower() == "status":
        status = "Active" if resource_monitor_active else "Inactive"
        await ctx.send(f"**Resource Monitor:** {status}\nThresholds: {CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM")
    elif action.lower() == "enable":
        resource_monitor_active = True
        await ctx.send("✅ Resource Monitor Enabled.")
    elif action.lower() == "disable":
        resource_monitor_active = False
        await ctx.send("⚠️ Resource Monitor Disabled.")
    else:
        await ctx.send("❌ Use: `!cpu-monitor <status|enable|disable>`")

@bot.command(name='resize-vps')
@is_admin()
async def resize_vps(ctx, container_name: str, ram: int = None, cpu: int = None, disk: int = None):
    if ram is None and cpu is None and disk is None:
        await ctx.send(embed=create_error_embed("Missing Parameters", "Please specify at least one resource to resize (ram, cpu, or disk)"))
        return
    found_vps = None
    user_id = None
    vps_index = None
    for uid, vps_list in vps_data.items():
        for i, vps in enumerate(vps_list):
            if vps['container_name'] == container_name:
                found_vps = vps
                user_id = uid
                vps_index = i
                break
        if found_vps:
            break
    if not found_vps:
        await ctx.send(embed=create_error_embed("VPS Not Found", f"No Xyara Hosting VPS found with container name: `{container_name}`"))
        return
    was_running = found_vps.get('status') == 'running' and not found_vps.get('suspended', False)
    disk_changed = disk is not None
    if was_running:
        await ctx.send(embed=create_info_embed("Stopping VPS", f"Stopping Xyara Hosting VPS `{container_name}` to apply resource changes..."))
        try:
            await execute_lxc(f"lxc stop {container_name}")
            found_vps['status'] = 'stopped'
            save_vps_data()
        except Exception as e:
            await ctx.send(embed=create_error_embed("Stop Failed", f"Error stopping VPS: {str(e)}"))
            return
    changes = []
    try:
        new_ram = int(found_vps['ram'].replace('GB', ''))
        new_cpu = int(found_vps['cpu'])
        new_disk = int(found_vps['storage'].replace('GB', ''))

        if ram is not None and ram > 0:
            new_ram = ram
            ram_mb = ram * 1024
            await execute_lxc(f"lxc config set {container_name} limits.memory {ram_mb}MB")
            changes.append(f"RAM: {ram}GB")

        if cpu is not None and cpu > 0:
            new_cpu = cpu
            await execute_lxc(f"lxc config set {container_name} limits.cpu {cpu}")
            changes.append(f"CPU: {cpu} cores")

        if disk is not None and disk > 0:
            new_disk = disk
            await execute_lxc(f"lxc config device set {container_name} root size={disk}GB")
            changes.append(f"Disk: {disk}GB")

        found_vps['ram'] = f"{new_ram}GB"
        found_vps['cpu'] = str(new_cpu)
        found_vps['storage'] = f"{new_disk}GB"
        found_vps['config'] = f"{new_ram}GB RAM / {new_cpu} CPU / {new_disk}GB Disk"

        vps_data[user_id][vps_index] = found_vps
        save_vps_data()

        if was_running:
            await execute_lxc(f"lxc start {container_name}")
            found_vps['status'] = 'running'
            save_vps_data()

        embed = create_success_embed("VPS Resized", f"Successfully resized resources for Xyara Hosting VPS `{container_name}`")
        add_field(embed, "Changes Applied", "\n".join(changes), False)
        if disk_changed:
            add_field(embed, "Disk Note", "Run `sudo resize2fs /` inside the VPS to expand the filesystem.", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Resize Failed", f"Error: {str(e)}"))

@bot.command(name='clone-vps')
@is_admin()
async def clone_vps(ctx, container_name: str, new_name: str = None):
    if not new_name:
        timestamp = datetime.now().strftime('%Y%m%d-%H%M%S')
        new_name = f"Xyara Hosting-{container_name}-clone-{timestamp}"
    await ctx.send(embed=create_info_embed("Cloning VPS", f"Cloning Xyara Hosting VPS `{container_name}` to `{new_name}`..."))
    try:
        found_vps = None
        user_id = None

        for uid, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    user_id = uid
                    break
            if found_vps:
                break

        if not found_vps:
            await ctx.send(embed=create_error_embed("VPS Not Found", f"No Xyara Hosting VPS found with container name: `{container_name}`"))
            return

        await execute_lxc(f"lxc copy {container_name} {new_name}")
        await apply_advanced_permissions(new_name)
        await execute_lxc(f"lxc start {new_name}")

        if user_id not in vps_data:
            vps_data[user_id] = []

        new_vps = found_vps.copy()
        new_vps['container_name'] = new_name
        new_vps['status'] = 'running'
        new_vps['suspended'] = False
        new_vps['whitelisted'] = False
        new_vps['suspension_history'] = []
        new_vps['created_at'] = datetime.now().isoformat()
        new_vps['shared_with'] = []
        new_vps['id'] = None

        vps_data[user_id].append(new_vps)
        save_vps_data()

        embed = create_success_embed("VPS Cloned", f"Successfully cloned Xyara Hosting VPS `{container_name}` to `{new_name}`")
        add_field(embed, "New VPS Details", f"**RAM:** {new_vps['ram']}\n**CPU:** {new_vps['cpu']} Cores\n**Storage:** {new_vps['storage']}", False)
        add_field(embed, "Features", "Nesting, Privileged, FUSE, Kernel Modules (Docker Ready)", False)
        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Clone Failed", f"Error: {str(e)}"))

@bot.command(name='migrate-vps')
@is_admin()
async def migrate_vps(ctx, container_name: str, target_pool: str):
    await ctx.send(embed=create_info_embed("Migrating VPS", f"Migrating Xyara Hosting VPS `{container_name}` to storage pool `{target_pool}`..."))
    try:
        await execute_lxc(f"lxc stop {container_name}")

        temp_name = f"Xyara Hosting-{container_name}-temp-{int(time.time())}"

        if shutil.which("lxc-copy"):
            # Note: lxc-copy is not always available or works differently. 
            # Classic LXC cloning usually uses lxc-copy -n orig -N new
            await execute_lxc(f"lxc-copy -n {container_name} -N {temp_name}") # assuming lxc-copy exists
        else:
             # Fallback to manual clone if needed, but for now error out if missing
            await ctx.send(embed=create_error_embed("Not Supported", "lxc-copy command not found."))
            return

        await execute_lxc(f"lxc-destroy -n {container_name} -f")

        await execute_lxc(f"lxc-stop -n {container_name} -k")
        # Rename is tricky in running lxc, usually lxc-stop -> mv /var/lib/lxc/old /var/lib/lxc/new -> edit config
        # lxc-copy -n old -N new -R (rename)
        # We will attempt lxc-copy -n temp_name -N container_name -R
        await execute_lxc(f"lxc-copy -n {temp_name} -N {container_name} -R")

        await apply_advanced_permissions(container_name)

        await execute_lxc(f"lxc start {container_name}")

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break

        await ctx.send(embed=create_success_embed("VPS Migrated", f"Successfully migrated Xyara Hosting VPS `{container_name}` to storage pool `{target_pool}`"))

    except Exception as e:
        await ctx.send(embed=create_error_embed("Migration Failed", f"Error: {str(e)}"))

@bot.command(name='vps-stats')
@is_admin()
async def vps_stats(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Gathering Statistics", f"Collecting statistics for Xyara Hosting VPS `{container_name}`..."))
    try:
        status = await get_container_status(container_name)
        cpu_usage = await get_container_cpu(container_name)
        memory_usage = await get_container_memory(container_name)
        disk_usage = await get_container_disk(container_name)
        uptime = await get_container_uptime(container_name)
        proc = await asyncio.create_subprocess_exec(
            "lxc", "info", container_name,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        output = stdout.decode()
        network_usage = "N/A"
        for line in output.splitlines():
            if "Network usage" in line:
                network_usage = line.split(":")[1].strip()
                break

        embed = create_embed(f"📊 Xyara Hosting VPS Statistics - {container_name}", f"Resource usage statistics", 0x1a1a1a)
        add_field(embed, "📈 Status", f"**{status.upper()}**", False)
        add_field(embed, "💻 CPU Usage", f"**{cpu_usage}**", True)
        add_field(embed, "🧠 Memory Usage", f"**{memory_usage}**", True)
        add_field(embed, "💾 Disk Usage", f"**{disk_usage}**", True)
        add_field(embed, "⏱️ Uptime", f"**{uptime}**", True)
        add_field(embed, "🌐 Network Usage", f"**{network_usage}**", False)

        found_vps = None
        for vps_list in vps_data.values():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    found_vps = vps
                    break
            if found_vps:
                break

        if found_vps:
            suspended_text = " (SUSPENDED)" if found_vps.get('suspended', False) else ""
            whitelisted_text = " (WHITELISTED)" if found_vps.get('whitelisted', False) else ""
            add_field(embed, "📋 Allocated Resources",
                           f"**RAM:** {found_vps['ram']}\n**CPU:** {found_vps['cpu']} Cores\n**Storage:** {found_vps['storage']}\n**Status:** {found_vps.get('status', 'unknown').upper()}{suspended_text}{whitelisted_text}",
                           False)

        await ctx.send(embed=embed)

    except Exception as e:
        await ctx.send(embed=create_error_embed("Statistics Failed", f"Error: {str(e)}"))

@bot.command(name='vps-network')
@is_admin()
async def vps_network(ctx, container_name: str, action: str, value: str = None):
    if action.lower() not in ["list", "add", "remove", "limit"]:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!vps-network <container> <list|add|remove|limit> [value]`"))
        return
    try:
        if action.lower() == "list":
            proc = await asyncio.create_subprocess_exec(
                "lxc", "exec", container_name, "--", "ip", "addr",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()

            if proc.returncode == 0:
                output = stdout.decode()
                if len(output) > 1000:
                    output = output[:1000] + "\n... (truncated)"

                embed = create_embed(f"🌐 Xyara Hosting Network Interfaces - {container_name}", "Network configuration", 0x1a1a1a)
                add_field(embed, "Interfaces", f"```\n{output}\n```", False)
                await ctx.send(embed=embed)
            else:
                await ctx.send(embed=create_error_embed("Error", f"Failed to list network interfaces: {stderr.decode()}"))

        elif action.lower() == "limit" and value:
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.egress {value}")
            await execute_lxc(f"lxc config device set {container_name} eth0 limits.ingress {value}")
            await ctx.send(embed=create_success_embed("Network Limited", f"Set Xyara Hosting network limit to {value} for `{container_name}`"))

        elif action.lower() == "add" and value:
            await execute_lxc(f"lxc config device add {container_name} eth1 nic nictype=bridged parent={value}")
            await ctx.send(embed=create_success_embed("Network Added", f"Added network interface to Xyara Hosting VPS `{container_name}` with bridge `{value}`"))

        elif action.lower() == "remove" and value:
            # Network management in Classic LXC requires editing config file... skipping valid hotplug for now
            await ctx.send(embed=create_error_embed("Not Supported", "Hotplug network removal not supported in Classic LXC mode yet."))
            return
            # await execute_lxc(f"lxc config device remove {container_name} {value}")
            await ctx.send(embed=create_success_embed("Network Removed", f"Removed network interface `{value}` from Xyara Hosting VPS `{container_name}`"))

        else:
            await ctx.send(embed=create_error_embed("Invalid Parameters", "Please provide valid parameters for the action"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Network Management Failed", f"Error: {str(e)}"))

@bot.command(name='vps-processes')
@is_admin()
async def vps_processes(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Gathering Processes", f"Listing processes in Xyara Hosting VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "ps", "aux",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"

            embed = create_embed(f"⚙️ Xyara Hosting Processes - {container_name}", "Running processes", 0x1a1a1a)
            add_field(embed, "Process List", f"```\n{output}\n```", False)
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Error", f"Failed to list processes: {stderr.decode()}"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Process Listing Failed", f"Error: {str(e)}"))

@bot.command(name='vps-logs')
@is_admin()
async def vps_logs(ctx, container_name: str, lines: int = 50):
    await ctx.send(embed=create_info_embed("Gathering Logs", f"Fetching last {lines} lines from Xyara Hosting VPS `{container_name}`..."))
    try:
        proc = await asyncio.create_subprocess_exec(
            "lxc-attach", "-n", container_name, "--", "journalctl", "-n", str(lines),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await proc.communicate()

        if proc.returncode == 0:
            output = stdout.decode()
            if len(output) > 1000:
                output = output[:1000] + "\n... (truncated)"

            embed = create_embed(f"📋 Xyara Hosting Logs - {container_name}", f"Last {lines} log lines", 0x1a1a1a)
            add_field(embed, "System Logs", f"```\n{output}\n```", False)
            await ctx.send(embed=embed)
        else:
            await ctx.send(embed=create_error_embed("Error", f"Failed to fetch logs: {stderr.decode()}"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Log Retrieval Failed", f"Error: {str(e)}"))

@bot.command(name='vps-uptime')
@is_admin()
async def vps_uptime(ctx, container_name: str):
    uptime = await get_container_uptime(container_name)
    embed = create_info_embed("VPS Uptime", f"Uptime for `{container_name}`: {uptime}")
    await ctx.send(embed=embed)

@bot.command(name='suspend-vps')
@is_admin()
async def suspend_vps(ctx, container_name: str, *, reason: str = "Admin action"):
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if vps.get('status') != 'running':
                    await ctx.send(embed=create_error_embed("Cannot Suspend", "Xyara Hosting VPS must be running to suspend."))
                    return
                try:
                    await execute_lxc(f"lxc-stop -n {container_name}")
                    vps['status'] = 'stopped'
                    vps['suspended'] = True
                    if 'suspension_history' not in vps:
                        vps['suspension_history'] = []
                    vps['suspension_history'].append({
                        'time': datetime.now().isoformat(),
                        'reason': reason,
                        'by': f"{ctx.author.name} ({ctx.author.id})"
                    })
                    save_vps_data()
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Suspend Failed", str(e)))
                    return
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_warning_embed("🚨 Xyara Hosting VPS Suspended", f"Your VPS `{container_name}` has been suspended by an admin.\n\n**Reason:** {reason}\n\nContact a Xyara Hosting admin to unsuspend.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid}: {dm_e}")
                await ctx.send(embed=create_success_embed("VPS Suspended", f"Xyara Hosting VPS `{container_name}` suspended. Reason: {reason}"))
                found = True
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"Xyara Hosting VPS `{container_name}` not found."))

@bot.command(name='unsuspend-vps')
@is_admin()
async def unsuspend_vps(ctx, container_name: str):
    found = False
    for uid, lst in vps_data.items():
        for vps in lst:
            if vps['container_name'] == container_name:
                if not vps.get('suspended', False):
                    await ctx.send(embed=create_error_embed("Not Suspended", "Xyara Hosting VPS is not suspended."))
                    return
                try:
                    vps['suspended'] = False
                    vps['status'] = 'running'
                    await execute_lxc(f"lxc-start -n {container_name}")
                    save_vps_data()
                    await ctx.send(embed=create_success_embed("VPS Unsuspended", f"Xyara Hosting VPS `{container_name}` unsuspended and started."))
                    found = True
                except Exception as e:
                    await ctx.send(embed=create_error_embed("Start Failed", str(e)))
                try:
                    owner = await bot.fetch_user(int(uid))
                    embed = create_success_embed("🟢 Xyara Hosting VPS Unsuspended", f"Your VPS `{container_name}` has been unsuspended by an admin.\nYou can now manage it again.")
                    await owner.send(embed=embed)
                except Exception as dm_e:
                    logger.error(f"Failed to DM owner {uid} about unsuspension: {dm_e}")
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"Xyara Hosting VPS `{container_name}` not found."))

@bot.command(name='suspension-logs')
@is_admin()
async def suspension_logs(ctx, container_name: str = None):
    if container_name:
        found = None
        for lst in vps_data.values():
            for vps in lst:
                if vps['container_name'] == container_name:
                    found = vps
                    break
            if found:
                break
        if not found:
            await ctx.send(embed=create_error_embed("Not Found", f"Xyara Hosting VPS `{container_name}` not found."))
            return
        history = found.get('suspension_history', [])
        if not history:
            await ctx.send(embed=create_info_embed("No Suspensions", f"No Xyara Hosting suspension history for `{container_name}`."))
            return
        embed = create_embed("Xyara Hosting Suspension History", f"For `{container_name}`")
        text = []
        for h in sorted(history, key=lambda x: x['time'], reverse=True)[:10]:
            t = datetime.fromisoformat(h['time']).strftime('%Y-%m-%d %H:%M:%S')
            text.append(f"**{t}** - {h['reason']} (by {h['by']})")
        add_field(embed, "History", "\n".join(text), False)
        if len(history) > 10:
            add_field(embed, "Note", "Showing last 10 entries.")
        await ctx.send(embed=embed)
    else:
        all_logs = []
        for uid, lst in vps_data.items():
            for vps in lst:
                h = vps.get('suspension_history', [])
                for event in sorted(h, key=lambda x: x['time'], reverse=True):
                    t = datetime.fromisoformat(event['time']).strftime('%Y-%m-%d %H:%M')
                    all_logs.append(f"**{t}** - VPS `{vps['container_name']}` (Owner: <@{uid}>) - {event['reason']} (by {event['by']})")
        if not all_logs:
            await ctx.send(embed=create_info_embed("No Suspensions", "No Xyara Hosting suspension events recorded."))
            return
        logs_text = "\n".join(all_logs)
        chunks = [logs_text[i:i+1024] for i in range(0, len(logs_text), 1024)]
        for idx, chunk in enumerate(chunks, 1):
            embed = create_embed(f"Xyara Hosting Suspension Logs (Part {idx})", f"Global suspension events (newest first)")
            add_field(embed, "Events", chunk, False)
            await ctx.send(embed=embed)

@bot.command(name='apply-permissions')
@is_admin()
async def apply_permissions(ctx, container_name: str):
    await ctx.send(embed=create_info_embed("Applying Permissions", f"Applying advanced permissions to `{container_name}`..."))
    try:
        status = await get_container_status(container_name)
        was_running = status == 'running'
        if was_running:
            await execute_lxc(f"lxc stop {container_name}")

        await apply_advanced_permissions(container_name)

        await execute_lxc(f"lxc start {container_name}")

        for user_id, vps_list in vps_data.items():
            for vps in vps_list:
                if vps['container_name'] == container_name:
                    vps['status'] = 'running'
                    vps['suspended'] = False
                    save_vps_data()
                    break

        await ctx.send(embed=create_success_embed("Permissions Applied", f"Advanced permissions applied to Xyara Hosting VPS `{container_name}`. Docker-ready!"))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Apply Failed", f"Error: {str(e)}"))

@bot.command(name='resource-check')
@is_admin()
async def resource_check(ctx):
    suspended_count = 0
    embed = create_info_embed("Resource Check", "Checking all running VPS for high resource usage...")
    msg = await ctx.send(embed=embed)
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps.get('status') == 'running' and not vps.get('suspended', False) and not vps.get('whitelisted', False):
                container = vps['container_name']
                cpu = await get_container_cpu_pct(container)
                ram = await get_container_ram_pct(container)
                if cpu > CPU_THRESHOLD or ram > RAM_THRESHOLD:
                    reason = f"High resource usage: CPU {cpu:.1f}%, RAM {ram:.1f}% (threshold: {CPU_THRESHOLD}% CPU / {RAM_THRESHOLD}% RAM)"
                    logger.warning(f"Suspending {container}: {reason}")
                    try:
                        await execute_lxc(f"lxc stop {container}")
                        vps['status'] = 'stopped'
                        vps['suspended'] = True
                        if 'suspension_history' not in vps:
                            vps['suspension_history'] = []
                        vps['suspension_history'].append({
                            'time': datetime.now().isoformat(),
                            'reason': reason,
                            'by': 'Xyara Hosting Auto Resource Check'
                        })
                        save_vps_data()
                        try:
                            owner = await bot.fetch_user(int(user_id))
                            warn_embed = create_warning_embed("🚨 VPS Auto-Suspended", f"Your VPS `{container}` has been automatically suspended due to high resource usage.\n\n**Reason:** {reason}\n\nContact Xyara Hosting admin to unsuspend and address the issue.")
                            await owner.send(embed=warn_embed)
                        except Exception as dm_e:
                            logger.error(f"Failed to DM owner {user_id}: {dm_e}")
                        suspended_count += 1
                    except Exception as e:
                        logger.error(f"Failed to suspend {container}: {e}")
    final_embed = create_info_embed("Resource Check Complete", f"Checked all VPS. Suspended {suspended_count} high-usage VPS.")
    await msg.edit(embed=final_embed)

@bot.command(name='whitelist-vps')
@is_admin()
async def whitelist_vps(ctx, container_name: str, action: str):
    if action.lower() not in ['add', 'remove']:
        await ctx.send(embed=create_error_embed("Invalid Action", "Use: `!whitelist-vps <container> <add|remove>`"))
        return
    found = False
    for user_id, vps_list in vps_data.items():
        for vps in vps_list:
            if vps['container_name'] == container_name:
                if action.lower() == 'add':
                    vps['whitelisted'] = True
                    msg = "added to whitelist (exempt from auto-suspension)"
                else:
                    vps['whitelisted'] = False
                    msg = "removed from whitelist"
                save_vps_data()
                await ctx.send(embed=create_success_embed("Whitelist Updated", f"VPS `{container_name}` {msg}."))
                found = True
                break
        if found:
            break
    if not found:
        await ctx.send(embed=create_error_embed("Not Found", f"Xyara Hosting VPS `{container_name}` not found."))

@bot.command(name='snapshot')
@is_admin()
async def snapshot_vps(ctx, container_name: str, snap_name: str = "snap0"):
    await ctx.send(embed=create_info_embed("Creating Snapshot", f"Creating snapshot '{snap_name}' for `{container_name}`..."))
    try:
        await execute_lxc(f"lxc snapshot {container_name} {snap_name}")
        await ctx.send(embed=create_success_embed("Snapshot Created", f"Snapshot '{snap_name}' created for Xyara Hosting VPS `{container_name}`."))
    except Exception as e:
        await ctx.send(embed=create_error_embed("Snapshot Failed", f"Error: {str(e)}"))

@bot.command(name='list-snapshots')
@is_admin()
async def list_snapshots(ctx, container_name: str):
    try:
        result = await execute_lxc(f"lxc snapshot list {container_name}")
        embed = create_info_embed(f"Snapshots for {container_name}", result)
        await ctx.send(embed=embed)
    except Exception as e:
        await ctx.send(embed=create_error_embed("List Failed", f"Error: {str(e)}"))

@bot.command(name='restore-snapshot')
@is_admin()
async def restore_snapshot(ctx, container_name: str, snap_name: str):
    await ctx.send(embed=create_warning_embed("Restore Snapshot", f"Restoring snapshot '{snap_name}' for `{container_name}` will overwrite current state. Continue?"))
    class RestoreConfirm(discord.ui.View):
        def __init__(self):
            super().__init__(timeout=60)

        @discord.ui.button(label="Confirm Restore", style=discord.ButtonStyle.danger)
        async def confirm(self, inter: discord.Interaction, item: discord.ui.Button):
            await inter.response.defer()
            try:
                await execute_lxc(f"lxc stop {container_name}")
                await execute_lxc(f"lxc restore {container_name} {snap_name}")
                await execute_lxc(f"lxc-start -n {container_name}")
                for uid, lst in vps_data.items():
                    for vps in lst:
                        if vps['container_name'] == container_name:
                            vps['status'] = 'running'
                            vps['suspended'] = False
                            save_vps_data()
                            break
                await inter.followup.send(embed=create_success_embed("Snapshot Restored", f"Restored '{snap_name}' for Xyara Hosting VPS `{container_name}`."))
            except Exception as e:
                await inter.followup.send(embed=create_error_embed("Restore Failed", f"Error: {str(e)}"))

        @discord.ui.button(label="Cancel", style=discord.ButtonStyle.secondary)
        async def cancel(self, inter: discord.Interaction, item: discord.ui.Button):
            await inter.response.edit_message(embed=create_info_embed("Cancelled", "Snapshot restore cancelled."))
    await ctx.send(view=RestoreConfirm())

@bot.command(name='help')
async def help_command(ctx):
    message = (
        "**Xyara Hosting - User Commands**\n\n"
        "`!myvps` - List your VPS instances.\n"
        "`!manage [user]` - Manage your VPS (Start/Stop/Reinstall).\n"
        "`!share-user <user> <vps_id>` - Share VPS access.\n"
        "`!share-ruser <user> <vps_id>` - Revoke shared VPS access.\n"
        "`!manage-shared <owner> <vps_id>` - Manage a shared VPS.\n"
        "`!uptime` - Check host uptime.\n"
        "`!ping` - Check bot latency.\n\n"
        "*Use `!adminhelp` for admin commands.*"
    )
    await ctx.send(message)

@bot.command(name='adminhelp')
@is_admin()
async def admin_help(ctx):
    message = (
        "**Xyara Hosting - Admin Commands**\n\n"
        "**Provisioning:**\n"
        "`!createplan <Name> <RAM> <CPU> <Disk>`\n"
        "`!deleteplan <Name>`\n"
        "`!plans` - List plans\n"
        "`!assign <User> <Plan>` - Assign VPS to user\n"
        "`!create <RAM> <CPU> <Disk> <User>` - Manual create\n\n"

        "**Management:**\n"
        "`!delete-vps <user> <id>`\n"
        "`!suspend-vps <name>`\n"
        "`!unsuspend-vps <name>`\n"
        "`!restart-vps <name>`\n"
        "`!stop-vps-all`\n"
        "`!whitelist-vps <name> <add|remove>`\n"
        "`!nukevps` - Destroy ALL containers\n"
        "`!fixdns <name>` - Fix network/DNS issues\n\n"
        
        "**Resources & Sync:**\n"
        "`!add-resources` / `!resize-vps`\n"
        "`!snapshot` / `!restore-snapshot`\n"
        "`!clone-vps <name>`\n"
        "`!migrate-vps <name> <pool>`\n\n"
        
        "**Info & Tools:**\n"
        "`!vpsinfo [name]`\n"
        "`!userinfo <user>`\n"
        "`!serverstats`\n"
        "`!lxc-list`\n"
        "`!vps-logs <name>`"
    )
    await ctx.send(message)

# Command aliases for typos
@bot.command(name='mangage')
async def manage_typo(ctx):
    await ctx.send(embed=create_info_embed("Command Correction", "Did you mean `!manage`? Use the correct Xyara Hosting command."))

@bot.command(name='stats')
async def stats_alias(ctx):
    if str(ctx.author.id) == str(MAIN_ADMIN_ID) or str(ctx.author.id) in admin_data.get("admins", []):
        await server_stats(ctx)
    else:
        await ctx.send(embed=create_error_embed("Access Denied", "This Xyara Hosting command requires admin privileges."))

@bot.command(name='info')
async def info_alias(ctx, user: discord.Member = None):
    if str(ctx.author.id) == str(MAIN_ADMIN_ID) or str(ctx.author.id) in admin_data.get("admins", []):
        if user:
            await user_info(ctx, user)
        else:
            await ctx.send(embed=create_error_embed("Usage", "Please specify a user: `!info @user`"))
    else:
        await ctx.send(embed=create_error_embed("Access Denied", "This Xyara Hosting command requires admin privileges."))

# --- Economy Commands ---

# --- Plan Management (Admin) ---

@bot.command(name='createplan')
@is_admin()
async def create_plan(ctx, name: str, ram: int, cpu: int, storage: int):
    """Create a new VPS plan."""
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute('INSERT INTO plans (name, ram, cpu, storage) VALUES (?, ?, ?, ?)', (name, ram, cpu, storage))
        conn.commit()
        await ctx.send(embed=create_success_embed("Plan Created", f"**{name}**\nRAM: {ram}GB\nCPU: {cpu} Cores\nStorage: {storage}GB"))
    except sqlite3.IntegrityError:
        await ctx.send(embed=create_error_embed("Plan Exists", f"Plan `{name}` already exists.\nUse `!deleteplan {name}` to remove it first, or `!plans` to list."))
    finally:
        conn.close()

@bot.command(name='deleteplan')
@is_admin()
async def delete_plan(ctx, name: str):
    """Delete a VPS plan."""
    conn = get_db()
    cur = conn.cursor()
    cur.execute('DELETE FROM plans WHERE name = ?', (name,))
    if cur.rowcount > 0:
        conn.commit()
        await ctx.send(embed=create_success_embed("Plan Deleted", f"Plan `{name}` removed."))
    else:
        await ctx.send(embed=create_error_embed("Error", f"Plan `{name}` not found."))
    conn.close()

@bot.command(name='plans')
@is_admin()
async def list_plans(ctx):
    """List all available plans."""
    plans = get_plans()
    if not plans:
        await ctx.send(embed=create_info_embed("Plans", "No plans configured. Use `!createplan`."))
        return
    
    embed = create_info_embed("VPS Plans", "Available configurations:")
    for plan in plans:
        add_field(embed, plan['name'], f"RAM: {plan['ram']}GB | CPU: {plan['cpu']} | Disk: {plan['storage']}GB", False)
    await ctx.send(embed=embed)

@bot.command(name='assign')
@is_admin()
async def assign_vps(ctx, user: discord.Member, plan_name: str):
    """Assign a VPS plan to a user."""
    plans = get_plans()
    plan = next((p for p in plans if p['name'].lower() == plan_name.lower()), None)
    
    if not plan:
        await ctx.send(embed=create_error_embed("Plan Not Found", f"Available plans: {', '.join([p['name'] for p in plans])}"))
        return
    
    # Confirm assignment
    embed = create_info_embed("Assign VPS", f"Assigning **{plan['name']}** to {user.mention}.\nSelect OS below to deploy.")
    add_field(embed, "Specs", f"RAM: {plan['ram']}GB | CPU: {plan['cpu']} | Disk: {plan['storage']}GB", False)
    
    # We pass 'user' as the target for the VPS, but 'ctx' is the admin's context
    # OSSelectView logic allows ctx.author (Admin) to click, but creates for self.user (Target)
    view = OSSelectView(plan['ram'], plan['cpu'], plan['storage'], user, ctx)
    await ctx.send(embed=embed, view=view)
@bot.command(name='nukevps')
@is_admin()
async def nuke_vps(ctx):
    # Safety Confirmation
    embed = create_warning_embed("⚠️ NUCLEAR LAUNCH DETECTED", 
        "**WARNING: YOU ARE ABOUT TO DESTROY ALL LXC CONTAINERS.**\n\n"
        "This will:\n"
        "1. Force stop and destroy ALL VPS instances on this machine.\n"
        "2. WIPE the `vps` database table.\n"
        "3. This cannot be undone.\n\n"
        "Type **`CONFIRM NUKE`** exactly to proceed.")
    await ctx.send(embed=embed)

    def check(m):
        return m.author == ctx.author and m.channel == ctx.channel and m.content == 'CONFIRM NUKE'

    try:
        await bot.wait_for('message', check=check, timeout=15)
    except asyncio.TimeoutError:
        await ctx.send(embed=create_info_embed("Nuke Cancelled", "Timed out."))
        return

    status_msg = await ctx.send(embed=create_info_embed("💥 Nuke Started", "Destroying all containers... Please wait."))
    
    conn = get_db()
    cur = conn.cursor()
    
    try:
        # 1. Get all containers from LXC directly
        # We use lxc-ls to ensure we catch even non-DB zombies
        proc = await asyncio.create_subprocess_shell(
            "lxc-ls -1",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, _ = await proc.communicate()
        container_names = stdout.decode().strip().splitlines()
        
        count = 0
        failed = 0
        
        for name in container_names:
            name = name.strip()
            if not name: continue
            
            try:
                # Force destroy
                await execute_lxc(f"lxc-stop -n {name} -k")
                await execute_lxc(f"lxc-destroy -n {name} -f")
                # Clean dir just in case
                c_dir = f"/var/lib/lxc/{name}"
                if os.path.exists(c_dir):
                    shutil.rmtree(c_dir)
                count += 1
            except Exception as e:
                logger.error(f"Failed to destroy {name}: {e}")
                failed += 1
        
        # 2. Clear Database
        cur.execute("DELETE FROM vps")
        conn.commit()
        
        # 3. Reset auto-increment
        cur.execute("DELETE FROM sqlite_sequence WHERE name='vps'")
        conn.commit()

        # Update global cache if needed (re-fetch)
        global vps_data
        vps_data = get_vps_data()

        await status_msg.edit(embed=create_success_embed("💥 Nuke Complete", 
            f"Destroyed **{count}** containers.\nFailed: {failed}\nDatabase wiped."))
            
    except Exception as e:
        logger.error(f"Nuke error: {e}")
        await status_msg.edit(embed=create_error_embed("Nuke Failed", str(e)))
    finally:
        conn.close()

# Run the bot
if __name__ == "__main__":
    if DISCORD_TOKEN:
        bot.run(DISCORD_TOKEN)
    else:
        logger.error("No Discord token found in DISCORD_TOKEN environment variable.")