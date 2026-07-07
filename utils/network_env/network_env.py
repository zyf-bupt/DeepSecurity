"""
企业网络环境模拟器
模拟包含DMZ、内网、管理区的多层企业网络拓扑
支持至少6个节点、2层网络、高低安全区域配置
"""
import json
import uuid
import random
import threading
import time
from datetime import datetime, timedelta
from typing import Any

# ============================================================
# 网络拓扑定义
# ============================================================
NETWORK_TOPOLOGY = {
    "zones": {
        "external": {
            "name": "外部威胁区 (Internet)",
            "cidr": "45.33.22.0/24",
            "security_level": "none",
            "description": "互联网区域，C2服务器所在"
        },
        "dmz": {
            "name": "DMZ隔离区",
            "cidr": "192.168.86.0/26",
            "security_level": "low",
            "description": "对外提供服务，部分暴露在互联网",
            "firewall_rules": ["allow_http(80,443)", "allow_dns(53)", "deny_internal_access"]
        },
        "internal": {
            "name": "内网核心区",
            "cidr": "192.168.86.128/26",
            "security_level": "medium",
            "description": "核心业务服务器所在，有基础防御",
            "firewall_rules": ["allow_internal_only", "ids_enabled", "log_all"]
        },
        "secure_internal": {
            "name": "内网高安全区",
            "cidr": "192.168.86.192/26",
            "security_level": "high",
            "description": "域控等高价值目标，多层防御",
            "firewall_rules": ["allow_internal_only", "ids_enabled", "ips_enabled", "mfa_required", "log_audit_all"]
        },
        "management": {
            "name": "安全管理区",
            "cidr": "192.168.86.200/29",
            "security_level": "high",
            "description": "SOC/安全分析平台所在，隔离管理",
            "firewall_rules": ["isolated_vlan", "monitor_all", "read_only_to_other_zones"]
        }
    },
    "nodes": [
        {
            "id": "node-1",
            "name": "External-C2-Server",
            "hostname": "c2-threat.external.com",
            "ip": "45.33.22.11",
            "zone": "external",
            "type": "linux_server",
            "os": "Ubuntu 22.04",
            "role": "C2控制服务器",
            "services": ["http(80)", "https(443)", "dns(53-tunnel)"],
            "is_threat_source": True,
            "description": "APT组织的C2基础设施，用于下发指令和接收外传数据"
        },
        {
            "id": "node-2",
            "name": "DMZ-Web-Server",
            "hostname": "web01.dmz.local",
            "ip": "192.168.86.10",
            "zone": "dmz",
            "type": "linux_server",
            "os": "CentOS 8",
            "role": "DMZ Web服务器",
            "services": ["http(80)", "https(443)", "ssh(22)"],
            "is_initial_victim": True,
            "description": "面向公网的Web服务器，安全防护较低，作为初始入侵点"
        },
        {
            "id": "node-3",
            "name": "Internal-Linux-App",
            "hostname": "app-srv.internal.local",
            "ip": "192.168.86.130",
            "zone": "internal",
            "type": "linux_server",
            "os": "Ubuntu 20.04",
            "role": "核心业务服务器",
            "services": ["ssh(22)", "postgresql(5432)", "app(8080)"],
            "contains_sensitive_data": True,
            "description": "运行核心业务应用，存储敏感客户数据"
        },
        {
            "id": "node-4",
            "name": "Internal-Windows-DC",
            "hostname": "dc01.internal.local",
            "ip": "192.168.86.131",
            "zone": "secure_internal",
            "type": "windows_server",
            "os": "Windows Server 2019",
            "role": "域控制器",
            "services": ["ldap(389)", "kerberos(88)", "smb(445)", "rdp(3389)"],
            "is_domain_controller": True,
            "description": "企业域控制器，高安全区域，攻击者的高价值目标"
        },
        {
            "id": "node-5",
            "name": "SOC-Analysis-Server",
            "hostname": "soc01.mgmt.local",
            "ip": "192.168.86.200",
            "zone": "management",
            "type": "linux_server",
            "os": "Ubuntu 22.04",
            "role": "安全分析平台",
            "services": ["flask(5000)", "neo4j(7687)", "sqlserver(1433)"],
            "is_soc": True,
            "description": "运行本溯源分析系统的服务器，全知全能的安全监控节点"
        },
        {
            "id": "node-6",
            "name": "Internal-Workstation",
            "hostname": "ws01.internal.local",
            "ip": "192.168.86.132",
            "zone": "internal",
            "type": "windows_workstation",
            "os": "Windows 10",
            "role": "员工工作站（失陷跳板机）",
            "services": ["rdp(3389)", "smb(445)"],
            "is_patient_zero": True,
            "description": "内网中第一台被攻陷的主机，攻击者用于横向移动的跳板"
        }
    ],
    "network_routes": [
        {"from": "node-1", "to": "node-2", "allowed": True, "protocols": ["TCP", "UDP"], "ports": [80, 443, 53]},
        {"from": "node-2", "to": "node-1", "allowed": True, "protocols": ["TCP", "UDP"], "ports": [80, 443, 53]},
        {"from": "node-2", "to": "node-3", "allowed": False, "note": "DMZ不应直接访问内网核心"},
        {"from": "node-6", "to": "node-3", "allowed": True, "protocols": ["TCP"], "ports": [22, 8080]},
        {"from": "node-6", "to": "node-4", "allowed": True, "protocols": ["TCP"], "ports": [445, 3389, 135]},
        {"from": "node-5", "to": "all", "allowed": True, "note": "SOC监控所有节点"},
        {"from": "node-3", "to": "node-1", "allowed": False, "note": "内网不应直接访问外部C2"},
        {"from": "node-4", "to": "node-1", "allowed": False, "note": "高安全区不应访问外网"}
    ]
}


class NetworkNode:
    """模拟单个网络节点"""

    def __init__(self, config: dict):
        self.id: str = config["id"]
        self.name: str = config["name"]
        self.hostname: str = config["hostname"]
        self.ip: str = config["ip"]
        self.zone: str = config["zone"]
        self.node_type: str = config["type"]
        self.os: str = config["os"]
        self.role: str = config["role"]
        self.services: list = config.get("services", [])
        self.config: dict = config

        # 运行状态
        self.status: str = "running"  # running/compromised/isolated/stopped
        self.cpu_usage: float = random.uniform(5, 40)
        self.memory_usage: float = random.uniform(20, 60)
        self.active_connections: list = []
        self.security_events: list = []
        self.last_updated: str = datetime.now().isoformat()

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "hostname": self.hostname,
            "ip": self.ip,
            "zone": self.zone,
            "type": self.node_type,
            "os": self.os,
            "role": self.role,
            "services": self.services,
            "status": self.status,
            "cpu_usage": round(self.cpu_usage, 1),
            "memory_usage": round(self.memory_usage, 1),
            "active_connections": len(self.active_connections),
            "security_events": len(self.security_events),
            "last_updated": self.last_updated,
            "is_threat_source": self.config.get("is_threat_source", False),
            "is_initial_victim": self.config.get("is_initial_victim", False),
            "is_domain_controller": self.config.get("is_domain_controller", False),
            "is_soc": self.config.get("is_soc", False),
            "is_patient_zero": self.config.get("is_patient_zero", False),
            "contains_sensitive_data": self.config.get("contains_sensitive_data", False)
        }

    def compromise(self):
        """标记节点为已攻陷"""
        self.status = "compromised"
        self.last_updated = datetime.now().isoformat()

    def isolate(self):
        """隔离节点"""
        self.status = "isolated"
        self.last_updated = datetime.now().isoformat()

    def restore(self):
        """恢复节点"""
        self.status = "running"
        self.security_events.clear()
        self.last_updated = datetime.now().isoformat()


class NetworkEnvironment:
    """企业网络环境管理器"""

    def __init__(self):
        self.nodes: dict[str, NetworkNode] = {}
        self._init_nodes()
        self._monitor_thread: threading.Thread | None = None
        self._stop_monitor: bool = False

    def _init_nodes(self):
        for node_cfg in NETWORK_TOPOLOGY["nodes"]:
            self.nodes[node_cfg["id"]] = NetworkNode(node_cfg)

    def get_topology(self) -> dict:
        """获取完整网络拓扑"""
        return {
            "zones": NETWORK_TOPOLOGY["zones"],
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "routes": NETWORK_TOPOLOGY["network_routes"],
            "summary": {
                "total_nodes": len(self.nodes),
                "compromised": sum(1 for n in self.nodes.values() if n.status == "compromised"),
                "isolated": sum(1 for n in self.nodes.values() if n.status == "isolated"),
                "running": sum(1 for n in self.nodes.values() if n.status == "running")
            }
        }

    def get_node(self, node_id: str) -> NetworkNode | None:
        return self.nodes.get(node_id)

    def compromise_node(self, node_id: str) -> bool:
        node = self.nodes.get(node_id)
        if node:
            node.compromise()
            return True
        return False

    def isolate_node(self, node_id: str) -> bool:
        node = self.nodes.get(node_id)
        if node:
            node.isolate()
            return True
        return False

    def restore_all(self):
        for node in self.nodes.values():
            node.restore()

    def get_security_posture(self) -> dict:
        """获取安全态势概览"""
        zones = {}
        for node in self.nodes.values():
            if node.zone not in zones:
                zones[node.zone] = {
                    "name": NETWORK_TOPOLOGY["zones"][node.zone]["name"],
                    "security_level": NETWORK_TOPOLOGY["zones"][node.zone]["security_level"],
                    "nodes": [],
                    "compromised_count": 0
                }
            zones[node.zone]["nodes"].append(node.to_dict())
            if node.status == "compromised":
                zones[node.zone]["compromised_count"] += 1

        return {
            "zones": zones,
            "overall_risk": self._calculate_risk_level(),
            "timestamp": datetime.now().isoformat()
        }

    def _calculate_risk_level(self) -> str:
        compromised = sum(1 for n in self.nodes.values() if n.status == "compromised")
        if compromised >= 3:
            return "critical"
        elif compromised >= 2:
            return "high"
        elif compromised >= 1:
            return "medium"
        return "low"

    def start_monitor(self):
        """启动后台监控线程"""
        if self._monitor_thread and self._monitor_thread.is_alive():
            return
        self._stop_monitor = False
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop_monitor(self):
        self._stop_monitor = True

    def _monitor_loop(self):
        while not self._stop_monitor:
            for node in self.nodes.values():
                node.cpu_usage = random.uniform(5, 80)
                node.memory_usage = random.uniform(20, 90)
                node.last_updated = datetime.now().isoformat()
            time.sleep(5)

    def generate_traffic_log(self, src_node_id: str, dst_node_id: str,
                              protocol: str, dst_port: int, payload_size: int = 100,
                              is_suspicious: bool = False) -> dict:
        """生成模拟流量日志"""
        src = self.nodes.get(src_node_id)
        dst = self.nodes.get(dst_node_id)
        if not src or not dst:
            return {}

        log = {
            "timestamp": datetime.now().isoformat(),
            "data_source": "network_traffic",
            "host_ip": src.ip,
            "src_ip": src.ip,
            "dst_ip": dst.ip,
            "src_port": random.randint(30000, 60000),
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_length": payload_size,
            "event_type": "network_flow",
            "entities": {
                "src_hostname": src.hostname,
                "dst_hostname": dst.hostname,
                "src_zone": src.zone,
                "dst_zone": dst.zone
            },
            "traffic_features": {
                "is_suspicious": is_suspicious,
                "cross_zone": src.zone != dst.zone
            }
        }
        src.active_connections.append({"to": dst.ip, "port": dst_port, "proto": protocol})
        return log

    def generate_host_log(self, node_id: str, event_type: str,
                           username: str = "admin", is_suspicious: bool = False) -> dict:
        """生成模拟主机日志"""
        node = self.nodes.get(node_id)
        if not node:
            return {}

        log_types = {
            "user_logon": {"entities": {"user": username, "session_id": str(uuid.uuid4())[:8]}},
            "user_logon_failed": {"entities": {"user": username, "failure_reason": "bad_password"}},
            "user_logoff": {"entities": {"user": username, "session_id": str(uuid.uuid4())[:8]}},
            "log_clear": {"entities": {"user": username, "log_type": "Security"}},
            "group_membership_add": {"entities": {"user": username, "target_group": "Administrators"}}
        }

        log_type_info = log_types.get(event_type, {"entities": {"user": username}})
        return {
            "timestamp": datetime.now().isoformat(),
            "data_source": "host_log",
            "host_ip": node.ip,
            "hostname": node.hostname,
            "event_type": event_type,
            "entities": log_type_info["entities"],
            "is_suspicious": is_suspicious,
            "zone": node.zone
        }

    def generate_behavior_log(self, node_id: str, event_type: str,
                               process_name: str = "cmd.exe",
                               cmdline: str = "",
                               is_suspicious: bool = False) -> dict:
        """生成模拟主机行为日志"""
        node = self.nodes.get(node_id)
        if not node:
            return {}

        pid = random.randint(1000, 60000)
        ppid = random.randint(500, 3000)

        log = {
            "timestamp": datetime.now().isoformat(),
            "data_source": "host_behavior",
            "host_ip": node.ip,
            "hostname": node.hostname,
            "event_type": event_type,
            "entities": {
                "process_name": process_name,
                "pid": pid,
                "parent_pid": ppid,
                "parent_process": "explorer.exe",
                "command_line": cmdline or process_name,
                "user": "SYSTEM" if node.node_type == "windows_server" else "root"
            },
            "behavior_features": {
                "is_abnormal_parent": is_suspicious,
                "is_suspicious_cmd": is_suspicious,
                "is_sensitive_path": is_suspicious,
                "has_memory_injection": is_suspicious and event_type == "process_injection"
            },
            "zone": node.zone
        }

        if event_type == "file_read":
            log["entities"]["file_path"] = "/etc/shadow" if is_suspicious else "/var/log/syslog"
            log["entities"]["file_name"] = log["entities"]["file_path"].split("/")[-1]
        elif event_type == "file_create":
            log["entities"]["file_path"] = "/var/www/html/cmd.php" if is_suspicious else "/tmp/output.txt"
        elif event_type == "registry_set_value":
            log["entities"]["registry_key"] = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\Evil"

        return log


# 全局网络环境实例
_network_env: NetworkEnvironment | None = None


def get_network_env() -> NetworkEnvironment:
    global _network_env
    if _network_env is None:
        _network_env = NetworkEnvironment()
    return _network_env
