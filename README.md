# 360safe-cli (360 安全卫士全功能 CLI 与自动化运维工具包)

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-Windows%2010%20%7C%2011-0078D6.svg)](https://microsoft.com)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Code Style](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

面向开发人员、系统运维工程师与 AI 智能体打造的 **360 安全卫士 (Qihoo 360 Total Security)** 满血命令行控制中枢与自动化工具包。

提供了对 360 核心守护进程、内核过滤驱动、注册表安全引擎、SQLite 隔离区底层账本、查杀日志以及开发者信任白名单的**全可编程、极速、无头控制能力**。

---

## 核心特性 (Key Features)

1. **自适应动态安装定位 (Dynamic Auto-Discovery)**：
   - 彻底废除硬编码路径；自动穿透 Windows 注册表卸载项与活跃进程信息，在任意机器与自定义盘符下开箱即用。
2. **底层隔离区账本直接穿透 (SQLite Quarantine Forensics)**：
   - 直接只读挂载读取 `360safe.Summary.dat`，毫秒级提取被隔离文件的 MD5、SHA256、原始路径与病毒类型，智能识别误报资产。
3. **内核安全驱动实时巡检 (Kernel Drivers Inspection)**：
   - 一键枚举当前 Windows 内核中已加载的全部 360 安全过滤驱动（如 `360Box64`, `360FsFlt`, `360netmon` 等）。
4. **一键唤起与免密控制 (Instant GUI Launcher)**：
   - 终端秒级调起 360 原生可恢复区窗口（`360Restore.exe`）、安全操作中心（`360LogCenter.exe`）或主界面。
5. **开发者信任区与白名单运维 (DevMode Trust Manager)**：
   - 支持自动化查询信任配置与为指定工程目录添加开发者信任路径。
6. **AI Agent 与脚本友好 (JSON Output First)**：
   - 全命令原生支持 `--json` 参数，提供确定性结构化数据输出，完美适配自动化管道与大模型工具调用。

---

## 环境要求与前置依赖 (Prerequisites)

> **重要使用前提 (Must Read Before Use)**：
> 本工具是面向已安装 360 软件的**自动化运维、无头控制与分析中枢**，自身不内置第三方杀毒引擎二进制。为了让所有管控、驱动巡检与隔离区穿透功能完整生效，运行环境要求如下：

1. **操作系统支持**：
   - Windows 10 / Windows 11 (64 位架构系统)。
2. **宿主机前置软件依赖**：
   - 宿主机需已安装 **360 安全卫士** 或 **360 安全卫士极速版**；
   - 允许安装在任意自定义盘符（例如 `C:\Program Files (x86)\360\360Safe` 或 `D:\Software\360\360Safe` 等），CLI 具备自动穿透 Windows 注册表与活跃进程的动态发现能力，无需手动配置路径环境变量；
   - **未安装时的表现**：若当前机器尚未安装 360，CLI 仍可正常执行，会自动识别并优雅输出“未检测到 360 安装”，不会引发异常崩溃或阻塞管道。
3. **Python 运行与开发环境**：
   - Python 3.8 或更高版本（推荐 Python 3.10 ~ 3.13）；
   - 仅依赖官方成熟系统巡检库 `psutil>=5.8.0`（通过 `pip install -e .` 或 `pip install -r` 自动下载）。

---

## 快速上手 (Quick Start)

### 1. 本地安装
```powershell
# 克隆仓库 (GitHub 或 Gitee)
git clone https://github.com/markx520/360safe-CLI.git
# 或国内镜像
git clone https://gitee.com/brother_xuan/360safe-cli.git

cd 360safe-CLI

# 安装依赖并以可编辑模式注册命令
pip install -e .
```

### 2. 便携批处理运行 (免安装)
仓库根目录内置 `360.bat`，可直接在终端中调用：
```powershell
.\360.bat status
.\360.bat quarantine
```

---

## 命令行使用手册 (CLI Usage)

```text
用法: 360 [-h] [--test] [--json] {status,quarantine,drivers,open,logs,trust,scan} ...

子命令:
  status                   查看 360 核心进程与引擎就绪状态
  quarantine (quar, list)  查看隔离区/可恢复区中的文件明细 (SQLite 穿透)
  drivers                  枚举底层加载的 360 内核过滤驱动
  open (gui)               调起 360 原生桌面界面 (restore/logcenter/main)
  logs                     解密查看 360 扫描与查杀日志
  trust                    查看 360 信任区配置与项目数
  scan                     调用 360 扫描指定路径
```

### 示例 1：查询系统状态与守护进程
```powershell
360 status
```
*输出示例：*
```text
======================================================================
【360 安全卫士系统运行与防护状态】
======================================================================
安装主目录   : D:\Software\360\360Safe (就绪: True)
恢复区程序   : D:\Software\360\360Safe\360Restore.exe
操作中心     : D:\Software\360\360Safe\safemon\360LogCenter.exe
鲲鹏查杀引擎 : [已开启]
云查杀网络检 : [已就绪]
信任区项目数 : 8
最后查杀时间 : 2026-10-28 20:55:15
----------------------------------------------------------------------
活跃 360 进程数: 2
  - PID:  6248 |   61.5 MB | 360tray.exe
  - PID: 12840 |   10.2 MB | 360UDiskPro.exe
----------------------------------------------------------------------
加载内核安全驱动: 10 个
  - 360FsFlt        | File System  | 360FsFlt
  - 360netmon       | Kernel       | 360netmon
======================================================================
```

### 示例 2：穿透查看隔离区文件
```powershell
360 quarantine
```

### 示例 3：调起原生可恢复区界面
```powershell
360 open restore
```

### 示例 4：输出结构化 JSON 数据
```powershell
360 status --json
360 quarantine --json
```

### 示例 5：执行五维物理自测套件
```powershell
360 --test
```

---

## Python API 调用示例 (Python SDK)

除了命令行外，本工具亦可作为标准 Python 库导入使用：

```python
from qihoo360_cli import (
    detect_360_root,
    get_360_processes,
    get_registry_info,
    get_quarantine_summary,
    get_360_drivers,
)

# 动态探测安装目录
safe_root = detect_360_root()
print(f"360 安装目录: {safe_root}")

# 获取当前活跃进程
procs = get_360_processes()
for p in procs:
    print(f"PID: {p['pid']} - 内存占用: {p['memory_mb']} MB")

# 读取隔离区 SQLite 摘要
summary = get_quarantine_summary()
print(f"隔离区记录数: {summary['sqlite_records_count']}")
```

---

## 架构示意图 (Architecture)

```text
[ 用户 / AI 智能体 / CI 管道 ]
             │
             ▼
      [ 360 CLI 门面 ] (qihoo360_cli.cli)
             │
   ┌─────────┼─────────┬──────────────┬──────────────┐
   ▼         ▼         ▼              ▼              ▼
[进程探针] [注册表]  [驱动枚举]     [SQLite 隔离区]  [日志解析]
(psutil)  (winreg) (driverquery)  (Summary.dat)   (UTF-16LE)
   │         │         │              │              │
   └─────────┴─────────┼──────────────┴──────────────┘
                       ▼
           [ 360 安全卫士底层运行时 ]
```

---

## 本地开发与测试指南 (Development & Testing)

为确保开发者克隆本仓库后能清晰、无阻碍地进行本地二次开发与贡献调试，推荐开发流程如下：

### 1. 搭建虚拟开发环境
```powershell
# 1. 创建独立虚拟环境
python -m venv .venv

# 2. 激活虚拟环境
.\.venv\Scripts\activate

# 3. 安装依赖并以可编辑模式挂载当前源码
pip install -e .
```

### 2. 执行本地自动化回归测试
```powershell
# 运行全部 8 项标准单元测试
python -m unittest discover -s tests

# 或使用便携批处理执行 5 维物理自检
.\360.bat --test
```

---

## 开源协议与合规免责声明 (License & Disclaimer)

1. 本项目采用 **[Apache License 2.0](LICENSE)** 商业友好型开源许可证（Copyright 2026 markx520）。
2. **商标中立声明（Trademark Notice）**：本项目为第三方中立开源运维工具。根据 Apache 2.0 协议第 6 条，“360”、“360安全卫士”以及相关徽标均为奇虎 360 技术有限公司（Qihoo 360 Technology Co., Ltd.）之注册商标。本项目非 360 官方出品，亦未获得其官方赞助或背书。
3. **法律级免责条款（Limitation of Liability）**：根据 Apache 2.0 协议第 7 条及第 8 条，本项目按“现状”（AS-IS）提供，不提供任何明示或暗示的担保。用户因使用本工具查看/恢复隔离区文件、配置信任白名单或调用查杀扫描而导致的任何直接或间接后果，作者概不承担任何法律责任。
4. 本项目严格遵守国家网络安全法规，严禁用于任何侵犯他人合法权益或破坏计算机信息系统的违法用途。
