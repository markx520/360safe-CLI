#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qihoo360_cli.core - 360 安全卫士底层探测与交互引擎
"""

import os
import sys
import time
import winreg
import sqlite3
import subprocess
from typing import Dict, Any, List, Optional

# Windows 终端输出 UTF-8 兼容
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# 常见默认安装路径与常量
DEFAULT_SAFE_PATHS = [
    r"D:\Software\360\360Safe",
    r"C:\Program Files (x86)\360\360Safe",
    r"C:\Program Files\360\360Safe",
    r"E:\Software\360\360Safe",
]

QUARANT_DIR = r"C:\ProgramData\360SD\Quarant"
QUARANT_UNION = os.path.join(QUARANT_DIR, "360SD.Summary.union1")
QUARANT_DB = os.path.join(QUARANT_DIR, "360safe.Summary.dat")
SCAN_LOG_FILE = os.path.expandvars(r"%APPDATA%\360Safe\360ScanLog\360safeScanLog.txt")

REG_SCAN_KEY = r"SOFTWARE\WOW6432Node\360Safe\360Scan"
REG_DEVMODE_KEY = r"SOFTWARE\WOW6432Node\360Safe\safemon\DevMode"


def detect_360_root() -> str:
    """
    自适应动态探测 360 安全卫士安装主根目录。
    探测优先级：
    1. 用户自定义环境变量 %SAFE360_PATH%
    2. Windows 卸载注册表 InstallLocation / DisplayIcon
    3. 当前运行的 360 进程物理可执行路径
    4. 常见盘符默认标准路径
    """
    # 1. 环境变量
    env_path = os.environ.get("SAFE360_PATH")
    if env_path and os.path.exists(env_path):
        return os.path.abspath(env_path)

    # 2. 注册表卸载信息检索
    uninstall_keys = [
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\360Safe"),
        (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\360Safe"),
        (winreg.HKEY_CURRENT_USER, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\360Safe"),
    ]
    for root_k, sub_k in uninstall_keys:
        try:
            with winreg.OpenKey(root_k, sub_k) as k:
                try:
                    loc, _ = winreg.QueryValueEx(k, "InstallLocation")
                    if loc and os.path.exists(loc):
                        return os.path.abspath(loc)
                except OSError:
                    pass
                try:
                    icon, _ = winreg.QueryValueEx(k, "DisplayIcon")
                    if icon:
                        base = os.path.dirname(icon.split(",")[0].strip('"'))
                        if os.path.exists(base):
                            return os.path.abspath(base)
                except OSError:
                    pass
        except OSError:
            pass

    # 3. 活跃进程路径推导
    try:
        import psutil
        for p in psutil.process_iter(["name", "exe"]):
            name = (p.info.get("name") or "").lower()
            if "360" in name:
                exe = p.info.get("exe")
                if exe and os.path.exists(exe):
                    p_dir = os.path.dirname(exe)
                    if os.path.basename(p_dir).lower() == "safemon":
                        p_dir = os.path.dirname(p_dir)
                    if os.path.exists(os.path.join(p_dir, "360Safe.exe")) or os.path.exists(os.path.join(p_dir, "safemon")):
                        return os.path.abspath(p_dir)
    except Exception:
        pass

    # 4. 标准候选目录枚举
    for cand in DEFAULT_SAFE_PATHS:
        if os.path.exists(cand):
            return os.path.abspath(cand)

    return ""


def get_safe_executables() -> Dict[str, str]:
    """获取 360 核心功能程序的物理绝对路径字典"""
    root = detect_360_root()
    return {
        "root": root,
        "restore_exe": os.path.join(root, "360Restore.exe") if root else "",
        "logcenter_exe": os.path.join(root, "safemon", "360LogCenter.exe") if root else "",
        "safe_main_exe": os.path.join(root, "360Safe.exe") if root else "",
        "tray_exe": os.path.join(root, "safemon", "360tray.exe") if root else "",
    }


def get_360_processes() -> List[Dict[str, Any]]:
    """获取当前系统中所有活跃的 360 相关进程"""
    procs = []
    try:
        import psutil
        for p in psutil.process_iter(["pid", "name", "memory_info", "cmdline"]):
            p_name = p.info.get("name", "")
            if p_name and "360" in p_name.lower():
                mem_mb = round(p.info["memory_info"].rss / (1024 * 1024), 2) if p.info.get("memory_info") else 0
                procs.append({
                    "pid": p.info["pid"],
                    "name": p_name,
                    "memory_mb": mem_mb,
                    "cmdline": " ".join(p.info.get("cmdline") or [])
                })
    except Exception:
        try:
            out = subprocess.check_output(
                ["tasklist", "/FI", "IMAGENAME eq 360*", "/FO", "CSV", "/NH"],
                shell=False
            ).decode("gbk", errors="ignore")
            for line in out.strip().splitlines():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 2:
                    procs.append({"pid": int(parts[1]), "name": parts[0], "memory_mb": 0, "cmdline": ""})
        except Exception:
            pass
    return procs


def get_registry_info() -> Dict[str, Any]:
    """读取 360 注册表核心状态"""
    root = detect_360_root()
    info = {
        "installed": bool(root and os.path.exists(root)),
        "root_path": root,
        "last_kill_time": None,
        "last_kill_timestamp": None,
        "kunpeng_open": False,
        "net_check": False,
        "trust_count": 0,
        "accumu_trust": 0,
    }
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_SCAN_KEY) as k:
            try:
                lkt, _ = winreg.QueryValueEx(k, "last_kill_time")
                info["last_kill_timestamp"] = lkt
                info["last_kill_time"] = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lkt))
            except Exception:
                pass

            try:
                kp, _ = winreg.QueryValueEx(k, "KunpengOpen")
                info["kunpeng_open"] = bool(kp)
            except Exception:
                pass

            try:
                nc, _ = winreg.QueryValueEx(k, "NetCheck")
                info["net_check"] = bool(nc)
            except Exception:
                pass

            try:
                tc, _ = winreg.QueryValueEx(k, "TrustCount")
                info["trust_count"] = tc
            except Exception:
                pass

            try:
                at, _ = winreg.QueryValueEx(k, "accumu_trust")
                info["accumu_trust"] = at
            except Exception:
                pass
    except Exception:
        pass
    return info


def get_360_drivers() -> List[Dict[str, str]]:
    """枚举系统中已加载的 360 内核过滤驱动"""
    drivers = []
    try:
        out = subprocess.check_output(["driverquery", "/NH", "/FO", "CSV"], shell=False).decode("gbk", errors="ignore")
        for line in out.strip().splitlines():
            if "360" in line.lower():
                parts = [p.strip('"') for p in line.split('","')]
                if len(parts) >= 3:
                    drivers.append({
                        "name": parts[0],
                        "display_name": parts[1],
                        "type": parts[2]
                    })
    except Exception:
        pass
    return drivers


def get_quarantine_db_records() -> List[Dict[str, Any]]:
    """直接解析 360 隔离区 SQLite 数据库文件 (360safe.Summary.dat)"""
    records = []
    if not os.path.exists(QUARANT_DB):
        return records

    try:
        conn = sqlite3.connect(f"file:{QUARANT_DB}?mode=ro", uri=True)
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='FI'")
        if cur.fetchone():
            cur.execute("SELECT ID, FO, FQ, M5, S1, S6, SZ, VR FROM FI")
            for row in cur.fetchall():
                records.append({
                    "id": row[0],
                    "original_path": row[1],
                    "quarantine_id": row[2],
                    "md5": row[3],
                    "sha1": row[4],
                    "sha256": row[5],
                    "size_bytes": row[6],
                    "virus_id": row[7]
                })
        conn.close()
    except Exception:
        pass
    return records


def get_quarantine_summary() -> Dict[str, Any]:
    """汇总隔离区 SQLite 账本数据与文件状态"""
    reg = get_registry_info()
    union_exists = os.path.exists(QUARANT_UNION)
    db_exists = os.path.exists(QUARANT_DB)
    db_records = get_quarantine_db_records()

    items = []
    for r in db_records:
        orig = r.get("original_path") or ""
        items.append({
            "target": os.path.basename(orig) if orig else "未知目标",
            "original_path": orig,
            "threat_name": f"病毒标识ID: {r.get('virus_id')}",
            "quarantine_time": reg.get("last_kill_time") or "未知",
            "size_mb": round((r.get("size_bytes") or 0) / (1024 * 1024), 2),
            "status": "QUARANTINED",
            "is_false_positive": any(k in orig.lower() for k in ["vmp", "ai", "tools", "patch", "build"]),
        })

    return {
        "quarantine_union_file": QUARANT_UNION,
        "union_exists": union_exists,
        "quarantine_db_file": QUARANT_DB,
        "db_exists": db_exists,
        "sqlite_records_count": len(db_records),
        "last_kill_time": reg.get("last_kill_time"),
        "items_count": len(items),
        "quarantined_items": items,
    }


def read_scan_logs(limit: int = 50) -> Dict[str, Any]:
    """读取并解密 UTF-16 格式的 360 官方查杀日志"""
    if not os.path.exists(SCAN_LOG_FILE):
        return {"log_file": SCAN_LOG_FILE, "exists": False, "lines": []}

    try:
        with open(SCAN_LOG_FILE, "r", encoding="utf-16", errors="ignore") as f:
            lines = [l.strip() for l in f.readlines() if l.strip()]
        return {
            "log_file": SCAN_LOG_FILE,
            "exists": True,
            "total_lines": len(lines),
            "lines": lines[-limit:]
        }
    except Exception as e:
        return {"log_file": SCAN_LOG_FILE, "exists": True, "error": str(e), "lines": []}


def add_trust_dir(target_dir: str) -> tuple[bool, str]:
    """向 360 开发者模式添加信任目录"""
    abs_dir = os.path.abspath(target_dir)
    if not os.path.exists(abs_dir):
        return False, f"目标路径不存在: {abs_dir}"

    dev_trust_dir = ""
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, REG_DEVMODE_KEY) as k:
            dev_trust_dir, _ = winreg.QueryValueEx(k, "TrustDir")
    except Exception:
        pass

    try:
        with winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, REG_DEVMODE_KEY) as k:
            new_val = f"{dev_trust_dir};{abs_dir}".strip(";") if dev_trust_dir else abs_dir
            winreg.SetValueEx(k, "TrustDir", 0, winreg.REG_SZ, new_val)
        return True, f"信任路径更新成功: {new_val}"
    except PermissionError:
        return False, "需要管理员权限修改此注册表项，请以管理员身份运行终端或通过 360 原生界面添加。"
    except Exception as e:
        return False, f"写入注册表失败: {e}"


def launch_360_ui(target: str = "restore") -> tuple[bool, str]:
    """秒级调起 360 原生桌面窗口"""
    exes = get_safe_executables()
    target_lower = target.lower()

    if target_lower in ["restore", "quar", "quarantine"]:
        exe = exes["restore_exe"] if os.path.exists(exes["restore_exe"]) else exes["logcenter_exe"]
    elif target_lower in ["logcenter", "center", "ops"]:
        exe = exes["logcenter_exe"] if os.path.exists(exes["logcenter_exe"]) else exes["restore_exe"]
    elif target_lower in ["main", "safe", "gui"]:
        exe = exes["safe_main_exe"] if os.path.exists(exes["safe_main_exe"]) else exes["tray_exe"]
    else:
        exe = exes["restore_exe"] if os.path.exists(exes["restore_exe"]) else exes["logcenter_exe"]

    if not exe or not os.path.exists(exe):
        return False, f"目标可执行程序不存在，请检查 360 安装: {exe}"

    try:
        subprocess.Popen([exe], cwd=os.path.dirname(exe))
        return True, f"成功启动: {exe}"
    except Exception as e:
        return False, f"启动进程失败: {e}"


def trigger_scan(target_path: str) -> tuple[bool, str]:
    """调用 360Safe.exe 执行定向文件/目录扫描"""
    abs_path = os.path.abspath(target_path)
    if not os.path.exists(abs_path):
        return False, f"待扫描路径不存在: {abs_path}"

    exes = get_safe_executables()
    main_exe = exes["safe_main_exe"]
    if not main_exe or not os.path.exists(main_exe):
        return False, f"360Safe.exe 主程序未找到: {main_exe}"

    try:
        subprocess.Popen([main_exe, "/scan", abs_path], cwd=exes["root"])
        return True, f"360 扫描指令已成功投递执行: {abs_path}"
    except Exception as e:
        return False, f"投递扫描指令异常: {e}"
