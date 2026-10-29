#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
tests/test_qihoo360_cli.py - 360safe-cli 自动化单元测试套件
"""

import os
import sys
import json
import unittest
from io import StringIO

# 将 src 加入模块寻址路径
SRC_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src"))
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

from qihoo360_cli.core import (
    detect_360_root,
    get_360_processes,
    get_registry_info,
    get_360_drivers,
    get_quarantine_summary,
    read_scan_logs,
    get_safe_executables,
)
from qihoo360_cli.cli import cmd_status, cmd_quarantine, cmd_drivers


class TestQihoo360CLI(unittest.TestCase):

    def test_01_dynamic_root_detection(self):
        """测试 360 安装目录自适应动态探测"""
        root = detect_360_root()
        self.assertIsInstance(root, str)
        self.assertTrue(len(root) > 0, "未能动态探测到 360 安装根目录")
        self.assertTrue(os.path.exists(root), f"探测到的 360 目录不存在: {root}")

    def test_02_safe_executables(self):
        """测试核心可执行程序字典生成"""
        exes = get_safe_executables()
        self.assertIn("root", exes)
        self.assertIn("restore_exe", exes)
        self.assertIn("safe_main_exe", exes)
        self.assertTrue(len(exes["root"]) > 0)

    def test_03_processes_enumeration(self):
        """测试 360 系统守护进程枚举"""
        procs = get_360_processes()
        self.assertIsInstance(procs, list)
        self.assertGreater(len(procs), 0, "当前系统必须捕获到活跃的 360 进程")
        first = procs[0]
        self.assertIn("pid", first)
        self.assertIn("name", first)
        self.assertIn("memory_mb", first)

    def test_04_registry_inspection(self):
        """测试 360 注册表安全状态解析"""
        reg = get_registry_info()
        self.assertIsInstance(reg, dict)
        self.assertTrue(reg.get("installed"))
        self.assertIn("kunpeng_open", reg)
        self.assertIn("trust_count", reg)

    def test_05_kernel_drivers(self):
        """测试 360 内核安全驱动枚举"""
        drivers = get_360_drivers()
        self.assertIsInstance(drivers, list)
        self.assertGreater(len(drivers), 0, "未能枚举到任何已加载的 360 内核安全驱动")
        d = drivers[0]
        self.assertIn("name", d)
        self.assertIn("type", d)

    def test_06_quarantine_summary(self):
        """测试 SQLite 隔离区账本直接穿透解析"""
        summary = get_quarantine_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("quarantined_items", summary)
        self.assertIn("sqlite_records_count", summary)

    def test_07_cli_status_json_contract(self):
        """测试 CLI status 子命令以 JSON 输出格式契约"""
        class Args:
            json = True
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = cmd_status(Args())
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertTrue(data.get("installed"))
        self.assertIn("processes", data)
        self.assertIn("drivers", data)

    def test_08_cli_quarantine_json_contract(self):
        """测试 CLI quarantine 子命令以 JSON 输出格式契约"""
        class Args:
            json = True
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        try:
            code = cmd_quarantine(Args())
            output = sys.stdout.getvalue()
        finally:
            sys.stdout = old_stdout

        self.assertEqual(code, 0)
        data = json.loads(output)
        self.assertIn("quarantined_items", data)


if __name__ == "__main__":
    unittest.main()
