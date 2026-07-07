"""
基于大模型的攻击行为全方位检测、捕获和溯源系统
主启动器

启动方式:
    python app_launcher.py
    python app_launcher.py --port 5000 --debug
"""
import argparse
import sys
import os
import subprocess
import atexit
import signal
from typing import Optional

# 确保项目根目录在路径中
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from xiaoxueqi import create_app

_vite_process: Optional[subprocess.Popen] = None


def start_vite():
    """在后台启动 Vite 前端开发服务器"""
    global _vite_process
    frontend_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend")
    if not os.path.isdir(frontend_dir):
        print("[*] frontend/ 目录不存在，跳过 Vite 启动")
        return
    try:
        _vite_process = subprocess.Popen(
            ["npx", "vite", "--host"],
            cwd=frontend_dir,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            shell=True,
        )
        print(f"[*] Vite 前端开发服务器启动中... (http://localhost:5173)")
    except Exception as e:
        print(f"[!] Vite 启动失败: {e}")


def stop_vite():
    """停止 Vite 开发服务器"""
    global _vite_process
    if _vite_process:
        try:
            _vite_process.terminate()
            _vite_process.wait(timeout=3)
        except Exception:
            try:
                _vite_process.kill()
            except Exception:
                pass
        _vite_process = None


# 注册退出时自动清理
atexit.register(stop_vite)


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════╗
║    基于大模型的攻击行为全方位检测、捕获和溯源系统              ║
║    LLM-based Attack Detection, Capture & Attribution System   ║
║                                                              ║
║    模块:                                                      ║
║    🛡️  Detection  - LLM+RAG增强检测引擎                      ║
║    🔗  Capture    - 多智能体协作捕获框架                      ║
║    🎯  Attribution- 证据路径推理归因引擎                      ║
║    📋  Report     - 自动化结构化报告生成                       ║
║    🌐  Network    - 企业网络环境模拟器                        ║
║    🎭  Scenarios  - APT/AI攻击场景生成器                      ║
║                                                              ║
║    分析场景:                                                  ║
║    场景一: APT全链条攻击检测与溯源                             ║
║    场景二: AI智能体滥用行为检测与溯源                          ║
╚══════════════════════════════════════════════════════════════╝
    """)


def main():
    parser = argparse.ArgumentParser(description='攻击行为全方位检测捕获溯源系统')
    parser.add_argument('--port', type=int, default=5000, help='服务端口 (默认: 5000)')
    parser.add_argument('--host', type=str, default='0.0.0.0', help='绑定地址 (默认: 0.0.0.0)')
    parser.add_argument('--debug', action='store_true', help='启用调试模式')
    parser.add_argument('--no-llm', action='store_true', help='禁用LLM功能(仅使用规则引擎)')
    parser.add_argument('--no-vite', action='store_true', help='不自动启动 Vite 前端（使用传统模板模式）')

    args = parser.parse_args()

    print_banner()

    print(f"[*] 初始化系统...")
    print(f"[*] LLM状态: {'禁用' if args.no_llm else '启用 (Qwen-Flash)'}")
    print(f"[*] 启动Web服务: http://{args.host}:{args.port}")

    if args.no_llm:
        os.environ["LLM_DISABLED"] = "1"

    app = create_app()

    # 自动启动 Vite 开发服务器
    if not args.no_vite and not args.debug:
        start_vite()

    print(f"[*] Web界面:")
    if not args.no_vite:
        print(f"    - 🆕 SPA前端:     http://localhost:5173/")
    print(f"    - 主页:           http://localhost:{args.port}/")
    print(f"    - 检测仪表盘:     http://localhost:{args.port}/detection")
    print(f"    - 场景管理:       http://localhost:{args.port}/scenario")
    print(f"    - 网络拓扑:       http://localhost:{args.port}/scenario/network")
    print(f"    - 归因分析:       http://localhost:{args.port}/attribution")
    print(f"    - 溯源分析:       http://localhost:{args.port}/traceback")
    print(f"    - 攻击链:         http://localhost:{args.port}/attack")
    print(f"    - 仪表盘:         http://localhost:{args.port}/dashboard")
    print(f"    - 日志分析:       http://localhost:{args.port}/logs")
    print(f"    - 行为分析:       http://localhost:{args.port}/behavior")
    print(f"    - 流量分析:       http://localhost:{args.port}/traffic")
    print(f"\n[*] 使用流程:")
    print(f"    1. 进入'场景管理' → 启动攻击场景")
    print(f"    2. 进入'检测仪表盘' → 执行全管线分析")
    print(f"    3. 进入'归因分析' → 查看溯源报告")
    print(f"\n[*] 按 Ctrl+C 停止服务")

    try:
        app.run(
            debug=args.debug,
            use_reloader=False,
            host=args.host,
            port=args.port
        )
    finally:
        stop_vite()


if __name__ == '__main__':
    main()
