#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qihoo360_cli - 360 安全卫士命令行与自动化运维工具包
"""

__version__ = "1.0.0"
__author__ = "markx520"
__license__ = "Apache-2.0"

from .core import (
    detect_360_root,
    get_360_processes,
    get_registry_info,
    get_360_drivers,
    get_quarantine_db_records,
    get_quarantine_summary,
    read_scan_logs,
    add_trust_dir,
    launch_360_ui,
    trigger_scan,
)

__all__ = [
    "detect_360_root",
    "get_360_processes",
    "get_registry_info",
    "get_360_drivers",
    "get_quarantine_db_records",
    "get_quarantine_summary",
    "read_scan_logs",
    "add_trust_dir",
    "launch_360_ui",
    "trigger_scan",
]
