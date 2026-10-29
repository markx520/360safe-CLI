#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
qihoo360_cli.cli - 360 安全卫士全功能 CLI 命令行交互中枢
"""

import os
import sys
import json
import argparse
from typing import Dict, Any

if __package__ is None or __package__ == "":
    src_parent = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    if src_parent not in sys.path:
        sys.path.insert(0, src_parent)
    from qihoo360_cli.core import (
        detect_360_root,
        get_safe_executables,
        get_360_processes,
        get_registry_info,
        get_360_drivers,
        get_quarantine_summary,
        read_scan_logs,
        add_trust_dir,
        launch_360_ui,
        trigger_scan,
    )
else:
    from .core import (
        detect_360_root,
        get_safe_executables,
        get_360_processes,
        get_registry_info,
        get_360_drivers,
        get_quarantine_summary,
        read_scan_logs,
        add_trust_dir,
        launch_360_ui,
        trigger_scan,
    )


def cmd_status(args: argparse.Namespace) -> int:
    """输出系统运行、引擎状态与进程列表"""
    procs = get_360_processes()
    reg = get_registry_info()
    drivers = get_360_drivers()
    exes = get_safe_executables()

    if getattr(args, "json", False):
        payload = {
            "installed": reg.get("installed", False),
            "root_path": reg.get("root_path", ""),
            "executables": exes,
            "processes_count": len(procs),
            "processes": procs,
            "drivers_count": len(drivers),
            "drivers": drivers,
            "registry": reg,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    print("======================================================================")
    print("【360 安全卫士系统运行与防护状态】")
    print("======================================================================")
    print(f"安装主目录   : {reg.get('root_path') or '[未检测到]'} (就绪: {reg.get('installed')})")
    print(f"恢复区程序   : {exes.get('restore_exe') or '[未找到]'}")
    print(f"操作中心     : {exes.get('logcenter_exe') or '[未找到]'}")
    print(f"鲲鹏查杀引擎 : {'[已开启]' if reg.get('kunpeng_open') else '[关闭]'}")
    print(f"云查杀网络检 : {'[已就绪]' if reg.get('net_check') else '[异常]'}")
    print(f"信任区项目数 : {reg.get('trust_count', 0)}")
    print(f"最后查杀时间 : {reg.get('last_kill_time') or '未检测到记录'}")
    print("----------------------------------------------------------------------")
    print(f"活跃 360 进程数: {len(procs)}")
    for p in procs:
        print(f"  - PID: {p['pid']:5d} | {p['memory_mb']:6.1f} MB | {p['name']}")
    print("----------------------------------------------------------------------")
    print(f"加载内核安全驱动: {len(drivers)} 个")
    for d in drivers:
        print(f"  - {d['name']:15s} | {d['type']:12s} | {d['display_name']}")
    print("======================================================================")
    return 0


def cmd_quarantine(args: argparse.Namespace) -> int:
    """输出隔离区 SQLite 账本明细与文件状态"""
    summary = get_quarantine_summary()

    if getattr(args, "json", False):
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0

    print("======================================================================")
    print("【360 安全操作中心 - 可恢复区 / 隔离区深度透视】")
    print("======================================================================")
    print(f"隔离区索引 : {summary['quarantine_union_file']} (物理存在: {summary['union_exists']})")
    print(f"隔离区账本 : {summary['quarantine_db_file']} (物理存在: {summary['db_exists']})")
    print(f"底层账本项 : SQLite 活跃记录数 = {summary['sqlite_records_count']}")
    print(f"最新拦截点 : {summary['last_kill_time'] or '无'}")
    print("----------------------------------------------------------------------")
    items = summary.get("quarantined_items", [])
    if not items:
        print("隔离区干净：底层 SQLite 账本无残留文件，所有核心生产工具均正常在位。")
    else:
        print(f"检测到 {len(items)} 项被隔离/缺失的资产明细：")
        for idx, item in enumerate(items, 1):
            print(f"[{idx}] {item['target']}")
            print(f"    原始路径 : {item['original_path']}")
            print(f"    威胁特征 : {item['threat_name']}")
            print(f"    处理时间 : {item['quarantine_time']}")
            print(f"    占用空间 : {item['size_mb']} MB")
            print(f"    定性结论 : {'[100% 误报 - 建议立即恢复并加入信任]' if item['is_false_positive'] else '[风险样本]'}")
    print("======================================================================")
    print("提示: 可执行 `360 open` 直接调起 360 原生可恢复区窗口进行一键解密还原。")
    return 0


def cmd_drivers(args: argparse.Namespace) -> int:
    """枚举 360 内核过滤驱动"""
    drivers = get_360_drivers()
    if getattr(args, "json", False):
        print(json.dumps({"count": len(drivers), "drivers": drivers}, indent=2, ensure_ascii=False))
        return 0

    print("======================================================================")
    print("【360 安全卫士 - 内核安全过滤驱动巡检】")
    print("======================================================================")
    print(f"已加载内核驱动总数: {len(drivers)}")
    for idx, d in enumerate(drivers, 1):
        print(f"[{idx:02d}] 驱动名称: {d['name']:15s} | 类型: {d['type']:12s} | 描述: {d['display_name']}")
    print("======================================================================")
    return 0


def cmd_open(args: argparse.Namespace) -> int:
    """拉起 360 桌面窗口"""
    target = getattr(args, "target", "restore")
    ok, msg = launch_360_ui(target)
    if ok:
        print(f"[SUCCESS] {msg}")
        return 0
    print(f"[ERROR] {msg}")
    return 1


def cmd_logs(args: argparse.Namespace) -> int:
    """读取扫描日志"""
    res = read_scan_logs(limit=30)
    if getattr(args, "json", False):
        print(json.dumps(res, indent=2, ensure_ascii=False))
        return 0

    print("======================================================================")
    print(f"【360 扫描日志摘要】({res.get('log_file')})")
    print("======================================================================")
    lines = res.get("lines", [])
    if not lines:
        print("未检测到扫描日志或日志文件为空。")
    else:
        for l in lines:
            print(f"  {l}")
    print("======================================================================")
    return 0


def cmd_trust(args: argparse.Namespace) -> int:
    """查询或添加信任区"""
    if hasattr(args, "add") and args.add:
        ok, msg = add_trust_dir(args.add)
        if ok:
            print(f"[SUCCESS] {msg}")
            return 0
        print(f"[ERROR] {msg}")
        return 1

    reg = get_registry_info()
    if getattr(args, "json", False):
        print(json.dumps({
            "trust_count": reg.get("trust_count", 0),
            "accumu_trust": reg.get("accumu_trust", 0),
        }, indent=2, ensure_ascii=False))
        return 0

    print("======================================================================")
    print("【360 信任区与白名单配置】")
    print("======================================================================")
    print(f"已信任项目计数 : {reg.get('trust_count', 0)}")
    print(f"累计信任配置项 : {reg.get('accumu_trust', 0)}")
    print("----------------------------------------------------------------------")
    print("说明: 360 信任区受内核驱动与自保护机制防护。在 `360 open` 界面恢复文件时勾选【同时添加到信任区】即可永久信任。")
    print("======================================================================")
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    """触发指定路径查杀扫描"""
    target_path = getattr(args, "path", "")
    ok, msg = trigger_scan(target_path)
    if ok:
        print(f"[SUCCESS] {msg}")
        return 0
    print(f"[ERROR] {msg}")
    return 1


def run_self_tests() -> int:
    """自动化单元自测套件，断言退出码恒为 0"""
    print("[INFO] 开始执行 360safe-cli 满血全功能单元自测试套件...")

    # 1. 动态寻址测试
    root = detect_360_root()
    assert isinstance(root, str), "360 根路径必须为字符串"
    assert len(root) > 0 and os.path.exists(root), "必须成功动态探测到 360 安装根目录"
    print(f"[PASS] 1. 成功动态探测 360 安装目录: {root}")

    # 2. 进程枚举测试
    procs = get_360_processes()
    assert isinstance(procs, list), "进程列表必须为 list"
    assert len(procs) > 0, "必须能捕获到活跃的 360 系统进程"
    print(f"[PASS] 2. 成功捕获活跃 360 进程: {len(procs)} 个")

    # 3. 注册表防护状态抓取
    reg = get_registry_info()
    assert isinstance(reg, dict), "注册表信息必须为 dict"
    assert reg.get("installed") is True, "注册表安装状态必须为 True"
    print(f"[PASS] 3. 成功获取注册表状态: 安装状态={reg['installed']}, 拦截时间={reg['last_kill_time']}")

    # 4. 内核驱动枚举测试
    drivers = get_360_drivers()
    assert isinstance(drivers, list), "内核驱动必须为 list"
    assert len(drivers) > 0, "必须成功捕获到加载的 360 内核驱动"
    print(f"[PASS] 4. 成功枚举 360 内核驱动: {len(drivers)} 个已加载")

    # 5. 隔离区数据穿透与结构验证
    summary = get_quarantine_summary()
    assert isinstance(summary, dict), "隔离区汇总必须为 dict"
    assert "quarantined_items" in summary, "quarantined_items 字段缺失"
    print(f"[PASS] 5. 隔离区汇总直接穿透成功: 包含 {summary['items_count']} 项明细")

    print("[SUCCESS] 360safe-cli 满血全功能 5 维自测项 100% 物理通过，退出码恒为 0！")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """构建命令行解析器"""
    parser = argparse.ArgumentParser(
        prog="360",
        description="Qihoo 360 Total Security (360安全卫士) CLI & Automation Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""常用命令示例:
  360 status                 查看 360 守护进程、运行内存与防护引擎状态
  360 quarantine             穿透 SQLite 隔离区账本，查看被隔离文件明细
  360 drivers                枚举底层加载的 360 内核过滤驱动
  360 open                   直接调起桌面 360 原生可恢复区窗口
  360 open logcenter         调起 360 安全操作中心
  360 logs                   读取 360 官方查杀与扫描日志
  360 trust                  查看 360 信任区与白名单配置
  360 scan D:\\Software       调用 360 查杀引擎扫描指定路径
  360 --test                 执行五维物理自测套件
"""
    )
    parser.add_argument("--test", action="store_true", help="运行内部五维物理自测试套件")
    parser.add_argument("--json", action="store_true", help="以结构化 JSON 格式输出战果")

    subparsers = parser.add_subparsers(dest="subcommand", help="子命令")

    p_status = subparsers.add_parser("status", help="查看 360 核心进程与引擎就绪状态")
    p_status.add_argument("--json", action="store_true", help="JSON 格式输出")

    p_quar = subparsers.add_parser("quarantine", aliases=["quar", "list"], help="查看隔离区/可恢复区中的文件明细")
    p_quar.add_argument("--json", action="store_true", help="JSON 格式输出")

    p_drivers = subparsers.add_parser("drivers", help="枚举底层加载的 360 内核过滤驱动")
    p_drivers.add_argument("--json", action="store_true", help="JSON 格式输出")

    p_open = subparsers.add_parser("open", aliases=["gui", "restore-ui"], help="调起 360 原生桌面界面")
    p_open.add_argument("target", nargs="?", default="restore", choices=["restore", "quar", "logcenter", "center", "main", "safe"], help="打开目标窗口 (默认: restore)")

    p_logs = subparsers.add_parser("logs", help="解密查看 360 扫描与查杀日志")
    p_logs.add_argument("--json", action="store_true", help="JSON 格式输出")

    p_trust = subparsers.add_parser("trust", help="查看 360 信任区配置与项目数")
    p_trust.add_argument("--add", help="添加指定目录至开发者信任目录")
    p_trust.add_argument("--json", action="store_true", help="JSON 格式输出")

    p_scan = subparsers.add_parser("scan", help="调用 360 扫描指定路径")
    p_scan.add_argument("path", help="待扫描的文件或目录绝对路径")

    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.test:
        return run_self_tests()

    if not args.subcommand or args.subcommand == "status":
        return cmd_status(args)
    elif args.subcommand in ["quarantine", "quar", "list"]:
        return cmd_quarantine(args)
    elif args.subcommand == "drivers":
        return cmd_drivers(args)
    elif args.subcommand in ["open", "gui", "restore-ui"]:
        return cmd_open(args)
    elif args.subcommand == "logs":
        return cmd_logs(args)
    elif args.subcommand == "trust":
        return cmd_trust(args)
    elif args.subcommand == "scan":
        return cmd_scan(args)
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
