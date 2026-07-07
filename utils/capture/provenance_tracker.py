"""
系统溯源数据追踪器
构建系统级溯源图 (process→file→network→user)
支持时序排序、向量时钟模拟、因果推断
"""
import uuid
from datetime import datetime
from collections import defaultdict, deque
from typing import Any


class ProvenanceNode:
    """溯源图节点"""

    def __init__(self, node_type: str, node_id: str, **attrs):
        self.node_type = node_type
        self.node_id = node_id
        self.attrs = attrs
        self.vector_clock = 0

    def to_dict(self) -> dict:
        return {
            "type": self.node_type,
            "id": self.node_id,
            "attrs": self.attrs,
            "clock": self.vector_clock
        }


class ProvenanceEdge:
    """溯源图边"""

    def __init__(self, edge_type: str, src_id: str, dst_id: str,
                 timestamp: str = "", **attrs):
        self.edge_type = edge_type
        self.src_id = src_id
        self.dst_id = dst_id
        self.timestamp = timestamp
        self.attrs = attrs

    def to_dict(self) -> dict:
        return {
            "type": self.edge_type,
            "from": self.src_id,
            "to": self.dst_id,
            "timestamp": self.timestamp,
            "attrs": self.attrs
        }


class ProvenanceTracker:
    """溯源数据追踪器"""

    def __init__(self):
        self.nodes: dict[str, ProvenanceNode] = {}
        self.edges: list[ProvenanceEdge] = []
        self._global_clock = 0
        self._node_creation_order: dict[str, int] = {}

    def add_process(self, pid: int, process_name: str, host_ip: str,
                    parent_pid: int | None = None, cmdline: str = "",
                    timestamp: str = "") -> str:
        node_id = f"{host_ip}_{pid}_{timestamp or 'unknown'}"
        if node_id not in self.nodes:
            self._global_clock += 1
            node = ProvenanceNode("Process", node_id,
                                  pid=pid, name=process_name, host=host_ip,
                                  cmdline=cmdline)
            node.vector_clock = self._global_clock
            self.nodes[node_id] = node
            self._node_creation_order[node_id] = self._global_clock

            # 记录父子关系
            if parent_pid:
                parent_id = f"{host_ip}_{parent_pid}_unknown"
                if parent_id in self.nodes:
                    edge = ProvenanceEdge("Fork", parent_id, node_id, timestamp,
                                          parent_pid=parent_pid, child_pid=pid)
                    self.edges.append(edge)
        return node_id

    def add_file_access(self, process_node_id: str, file_path: str,
                         access_type: str, timestamp: str = "") -> str:
        file_id = f"file://{file_path}"
        if file_id not in self.nodes:
            self._global_clock += 1
            node = ProvenanceNode("File", file_id, path=file_path)
            node.vector_clock = self._global_clock
            self.nodes[file_id] = node

        edge = ProvenanceEdge(access_type, process_node_id, file_id, timestamp)
        self.edges.append(edge)
        return file_id

    def add_network_connection(self, process_node_id: str, src_ip: str,
                                dst_ip: str, dst_port: int, protocol: str,
                                timestamp: str = "") -> str:
        ip_id = f"ip://{dst_ip}"
        if ip_id not in self.nodes:
            self._global_clock += 1
            node = ProvenanceNode("IP", ip_id, ip=dst_ip)
            node.vector_clock = self._global_clock
            self.nodes[ip_id] = node

        edge = ProvenanceEdge("Connect", process_node_id, ip_id, timestamp,
                              src_ip=src_ip, dst_ip=dst_ip, port=dst_port,
                              protocol=protocol)
        self.edges.append(edge)
        return ip_id

    def add_user_logon(self, username: str, host_ip: str, src_ip: str | None = None,
                        session_id: str = "", timestamp: str = "") -> str:
        user_id = f"{host_ip}_{username}"
        if user_id not in self.nodes:
            self._global_clock += 1
            node = ProvenanceNode("User", user_id, username=username, host=host_ip)
            node.vector_clock = self._global_clock
            self.nodes[user_id] = node

        host_ip_id = f"ip://{host_ip}"
        if host_ip_id not in self.nodes:
            self._global_clock += 1
            node = ProvenanceNode("IP", host_ip_id, ip=host_ip)
            node.vector_clock = self._global_clock
            self.nodes[host_ip_id] = node

        edge = ProvenanceEdge("Logon", user_id, host_ip_id, timestamp,
                              session_id=session_id, src_ip=src_ip)
        self.edges.append(edge)
        return user_id

    def get_causal_chain(self, start_node_id: str,
                          max_depth: int = 10) -> dict:
        """获取从某节点出发的因果链"""
        if start_node_id not in self.nodes:
            return {"nodes": [], "edges": []}

        visited_nodes: set[str] = set()
        visited_edges: list[dict] = []
        queue = deque([(start_node_id, 0)])

        while queue:
            node_id, depth = queue.popleft()
            if node_id in visited_nodes or depth > max_depth:
                continue
            visited_nodes.add(node_id)

            for edge in self.edges:
                if edge.src_id == node_id and edge.dst_id not in visited_nodes:
                    visited_edges.append(edge.to_dict())
                    queue.append((edge.dst_id, depth + 1))
                elif edge.dst_id == node_id and edge.src_id not in visited_nodes:
                    visited_edges.append(edge.to_dict())
                    queue.append((edge.src_id, depth + 1))

        return {
            "nodes": [self.nodes[nid].to_dict() for nid in visited_nodes if nid in self.nodes],
            "edges": visited_edges
        }

    def get_full_graph(self) -> dict:
        return {
            "nodes": [n.to_dict() for n in self.nodes.values()],
            "edges": [e.to_dict() for e in self.edges]
        }

    def reconstruct_attack_path(self, suspicious_ip: str) -> list[dict]:
        """重建与可疑IP相关的攻击路径"""
        ip_id = f"ip://{suspicious_ip}"
        if ip_id not in self.nodes:
            return []

        # BFS从可疑IP反向追溯
        path = []
        visited: set[str] = set()
        queue = deque([(ip_id, [])])

        while queue:
            node_id, current_path = queue.popleft()
            if node_id in visited:
                continue
            visited.add(node_id)

            node = self.nodes.get(node_id)
            if node:
                path.append({
                    "node": node.to_dict(),
                    "path_to_here": current_path
                })

            for edge in self.edges:
                if edge.dst_id == node_id and edge.src_id not in visited:
                    new_path = current_path + [
                        {"from": edge.src_id, "relation": edge.edge_type, "to": edge.dst_id}
                    ]
                    queue.append((edge.src_id, new_path))

        return path
