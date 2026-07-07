import logging
from neo4j import GraphDatabase

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


class GraphIngestionEngine:
    def __init__(self, uri, user, password, initial_pid_cache=None):
        self.driver = GraphDatabase.driver(
            uri, auth=(user, password),
            connection_timeout=5,         # 5 秒连接超时
            connection_acquisition_timeout=5,
        )
        self.pid_cache = initial_pid_cache if initial_pid_cache else {}

    def get_current_pid_cache(self):
        return self.pid_cache

    def close(self):
        self.driver.close()

    def _batch_execute(self, query, data_list, batch_size=1000, param_name="events", **kwargs):
        if not data_list: return
        total = len(data_list)
        with self.driver.session() as session:
            for i in range(0, total, batch_size):
                batch = data_list[i: i + batch_size]
                try:
                    params = {param_name: batch}
                    params.update(kwargs)
                    session.execute_write(lambda tx: tx.run(query, **params))
                except Exception as e:
                    logging.error(f"批量写入失败: {e}")

    def _run_massive_update(self, query, **kwargs):
        try:
            with self.driver.session() as session:
                session.run(query, **kwargs)
        except Exception as e:
            logging.error(f"大规模更新任务失败: {e}")

    def _generate_process_id(self, host_ip, pid, timestamp=None):
        key = f"{host_ip}_{pid}"
        if timestamp and timestamp != "unknown":
            self.pid_cache[key] = timestamp
            time_suffix = timestamp
        else:
            time_suffix = self.pid_cache.get(key, "unknown")
        return f"{host_ip}_{pid}_{time_suffix}"

    # ... [主机行为、网络流量、主机日志的入库函数保持不变，此处省略以节省篇幅，重点在后面] ...
    # 请保留您原有的 ingest_host_behavior, ingest_network_traffic, ingest_host_log 函数内容

    # -----------------------------------------------------------
    # 为了方便您直接复制，我把未修改的这三个函数名列在这里，
    # 实际文件中请保留原来的代码，或者如果需要我提供包含这部分的完整版请告诉我。
    # 这里直接提供修改最核心的 ingest_attack_events 和 build_causal_chains
    # -----------------------------------------------------------

    def ingest_host_behavior(self, data_list):
        # ... (保持您上传文件中的原样逻辑) ...
        # 为避免篇幅过长，此处省略，逻辑与您原文件一致
        if not data_list: return
        # 预处理
        for item in data_list:
            if item.get("event_type") == "process_create":
                entities = item.get("entities", {})
                self._generate_process_id(item.get("host_ip"), entities.get("pid"), item.get("timestamp"))

        processed_data = []
        for item in data_list:
            entities = item.get("entities", {})
            features = item.get("behavior_features", {})
            ts_for_id = item.get("timestamp") if item.get("event_type") == "process_create" else None
            pid = entities.get("pid")
            proc_id = None
            if pid: proc_id = self._generate_process_id(item.get("host_ip"), pid, ts_for_id)
            processed_data.append({
                "host_ip": item.get("host_ip"), "timestamp": item.get("timestamp"),
                "event_type": item.get("event_type"), "entities": entities, "features": features,
                "pid": pid, "proc_name": entities.get("process_name"), "proc_hash": entities.get("hash"),
                "proc_id": proc_id,
                "parent_id": f"{item.get('host_ip')}_{entities.get('parent_pid')}_unknown" if item.get(
                    "event_type") == "process_create" else None
            })
        # SQLs
        spawn_query = """UNWIND $events AS event WITH event WHERE event.event_type = 'process_create' AND event.pid IS NOT NULL MERGE (p:Process {id: event.parent_id}) ON CREATE SET p.name = event.entities.parent_process MERGE (c:Process {id: event.proc_id}) ON CREATE SET c.name = event.proc_name, c.pid = event.pid, c.cmdline = event.entities.command_line, c.host = event.host_ip, c.timestamp = event.timestamp, c.hash = event.proc_hash, c.ports = event.entities.listen_ports MERGE (p)-[r:Spawn]->(c) SET r.timestamp = event.timestamp, r.is_abnormal = event.features.is_abnormal_parent"""
        self._batch_execute(spawn_query, [d for d in processed_data if d["event_type"] == "process_create"],
                            param_name="events")

        terminate_query = """UNWIND $events AS event WITH event WHERE event.proc_id IS NOT NULL MATCH (p:Process {id: event.proc_id}) SET p.timestamp_end = event.timestamp"""
        self._batch_execute(terminate_query, [d for d in processed_data if d["event_type"] == "process_terminate"],
                            param_name="events")

        file_ops_map = {"file_create": "Write", "file_modify": "Write", "file_delete": "Delete", "file_read": "Read",
                        "image_load": "Load"}
        for evt_type, relation in file_ops_map.items():
            file_query = f"""UNWIND $events AS event WITH event MERGE (p:Process {{id: event.proc_id}}) MERGE (f:File {{id: event.host_ip + '_' + event.entities.file_path}}) ON CREATE SET f.path = event.entities.file_path, f.name = event.entities.file_name, f.host = event.host_ip, f.hash = event.entities.hash MERGE (p)-[r:{relation}]->(f) SET r.timestamp = event.timestamp"""
            self._batch_execute(file_query, [d for d in processed_data if
                                             d["event_type"] == evt_type and d["entities"].get("file_path")],
                                param_name="events")

        reg_query = """UNWIND $events AS event WITH event MERGE (p:Process {id: event.proc_id}) MERGE (r:Registry {id: event.entities.registry_key}) ON CREATE SET r.key = event.entities.registry_key, r.value_name = event.entities.registry_value_name, r.value_data = event.entities.registry_value_data MERGE (p)-[rel:Write]->(r) SET rel.timestamp = event.timestamp"""
        self._batch_execute(reg_query, [d for d in processed_data if d["event_type"] == "registry_set_value"],
                            param_name="events")

        net_conn_query = """UNWIND $events AS event WITH event MERGE (p:Process {id: event.proc_id}) MERGE (ip:IP {id: event.entities.dst_ip}) ON CREATE SET ip.ip = event.entities.dst_ip MERGE (p)-[r:Connect]->(ip) SET r.timestamp = event.timestamp, r.dst_port = event.entities.dst_port"""
        self._batch_execute(net_conn_query, [d for d in processed_data if
                                             d["event_type"] == "network_connection" and d["entities"].get("dst_ip")],
                            param_name="events")

        inject_query = """UNWIND $events AS event WITH event MERGE (src:Process {id: event.proc_id}) MERGE (target:Process {id: event.target_proc_id}) MERGE (src)-[r:Inject]->(target) SET r.timestamp = event.timestamp, r.is_memory_injection = true"""
        inject_data = []
        for d in processed_data:
            if d["event_type"] == "process_injection" and d["entities"].get("target_pid"):
                d["target_proc_id"] = self._generate_process_id(d["host_ip"], d["entities"].get("target_pid"),
                                                                "unknown")
                inject_data.append(d)
        self._batch_execute(inject_query, inject_data, param_name="events")

    def ingest_network_traffic(self, data_list):
        # ... (保持不变) ...
        if not data_list: return
        processed_data = []
        for item in data_list:
            entities = item.get("entities", {})
            host_ip = item.get("host_ip") or item.get("src_ip")
            proc_id = None
            pid = entities.get("pid")
            if pid and host_ip: proc_id = self._generate_process_id(host_ip, pid)
            processed_data.append({
                "src_ip": item.get("src_ip"), "dst_ip": item.get("dst_ip"), "src_port": item.get("src_port"),
                "dst_port": item.get("dst_port"),
                "timestamp": item.get("timestamp"), "event_type": item.get("event_type"),
                "domain": entities.get("domain"), "protocol": item.get("protocol"),
                "features": item.get("traffic_features", {}), "proc_id": proc_id, "entities": entities
            })

        flow_query = """UNWIND $events AS event WITH event WHERE event.src_ip IS NOT NULL AND event.dst_ip IS NOT NULL MERGE (src:IP {id: event.src_ip}) ON CREATE SET src.ip = event.src_ip, src.type = CASE WHEN event.src_ip STARTS WITH '192.168.' OR event.src_ip STARTS WITH '10.' THEN 'Internal' ELSE 'External' END MERGE (dst:IP {id: event.dst_ip}) ON CREATE SET dst.ip = event.dst_ip, dst.type = CASE WHEN event.dst_ip STARTS WITH '192.168.' OR event.dst_ip STARTS WITH '10.' THEN 'Internal' ELSE 'External' END MERGE (src)-[r:Traffic_Flow]->(dst) SET r.timestamp = event.timestamp, r.protocol = event.protocol, r.src_port = event.src_port, r.dst_port = event.dst_port, r.event_type = event.event_type FOREACH (ignoreMe IN CASE WHEN event.proc_id IS NOT NULL THEN [1] ELSE [] END | MERGE (p:Process {id: event.proc_id}) MERGE (p)-[conn:Connect]->(dst) SET conn.timestamp = event.timestamp, conn.dst_port = event.dst_port)"""
        self._batch_execute(flow_query, processed_data, param_name="events")

        dns_query = """UNWIND $events AS event WITH event WHERE event.domain IS NOT NULL MERGE (src:IP {id: event.src_ip}) MERGE (d:Domain {id: event.domain}) ON CREATE SET d.name = event.domain FOREACH (ignoreMe IN CASE WHEN event.proc_id IS NOT NULL THEN [1] ELSE [] END | MERGE (p:Process {id: event.proc_id}) MERGE (p)-[r:Resolve]->(d) SET r.timestamp = event.timestamp, r.query_type = event.entities.query_type, r.is_suspicious = event.features.is_covert_channel) FOREACH (ignoreMe IN CASE WHEN event.proc_id IS NULL THEN [1] ELSE [] END | MERGE (src)-[r:Resolve]->(d) SET r.timestamp = event.timestamp, r.query_type = event.entities.query_type, r.is_suspicious = event.features.is_covert_channel)"""
        self._batch_execute(dns_query, processed_data, param_name="events")

    def ingest_host_log(self, data_list):
        # ... (保持不变) ...
        if not data_list: return
        processed_data = []
        for item in data_list:
            if item.get("event_type") in ["user_logon", "user_logoff"]:
                entities = item.get("entities", {})
                processed_data.append({
                    "host_ip": item.get("host_ip"), "timestamp": item.get("timestamp"),
                    "event_type": item.get("event_type"),
                    "user": entities.get("user"), "src_ip": entities.get("src_ip"),
                    "session_id": entities.get("session_id"), "raw_id": item.get("raw_id")
                })
        logon_query = """UNWIND $events AS event WITH event WHERE event.user IS NOT NULL AND event.event_type = 'user_logon' MERGE (u:User {id: event.host_ip + '_' + event.user}) ON CREATE SET u.username = event.user MERGE (host:IP {id: event.host_ip}) ON CREATE SET host.ip = event.host_ip MERGE (u)-[r:Logon]->(host) SET r.timestamp = event.timestamp, r.session_id = event.session_id, r.raw_id = event.raw_id FOREACH (ignoreMe IN CASE WHEN event.src_ip IS NOT NULL THEN [1] ELSE [] END | MERGE (src:IP {id: event.src_ip}) ON CREATE SET src.ip = event.src_ip MERGE (src)-[rel:Logon_Source]->(host) SET rel.timestamp = event.timestamp, rel.user = event.user)"""
        self._batch_execute(logon_query, processed_data, param_name="events")

        logoff_query = """UNWIND $events AS event WITH event WHERE event.user IS NOT NULL AND event.event_type = 'user_logoff' MATCH (u:User {id: event.host_ip + '_' + event.user})-[r:Logon]->(host:IP {id: event.host_ip}) WHERE (event.session_id IS NULL) OR (r.session_id = event.session_id) SET r.end_time = event.timestamp"""
        self._batch_execute(logoff_query, processed_data, param_name="events")

    # =========================================================================
    # [核心修改区] 攻击事件与因果链
    # =========================================================================
    def ingest_attack_events(self, attack_data_list):
        if not attack_data_list:
            return

        # [Fix 1] 显式写入 ae.attacker_ip，这是横向移动关联的根本！
        ingest_query = """
        UNWIND $batch AS data
        MERGE (t:Technique {id: data.technique.id})
        ON CREATE SET t.name = data.technique.name, t.tactic_id = data.tactic.id, t.tactic_name = data.tactic.name
        MERGE (ae:AttackEvent {id: data.attack_id})
        ON CREATE SET 
            ae.confidence = data.confidence, 
            ae.timestamp_start = data.timestamp_start,
            ae.timestamp_end = data.timestamp_end, 
            ae.stage_order = data.stage_order,
            ae.victim_ip = data.victim_ip,
            ae.attacker_ip = data.attacker_ip  // <--- 这一行是救命的关键
        MERGE (ae)-[:IS_TYPE]->(t)

        WITH ae, data.related_events AS evidence_ids
        UNWIND evidence_ids AS eid
        OPTIONAL MATCH (exact_p:Process {id: eid})
        FOREACH (_ IN CASE WHEN exact_p IS NOT NULL THEN [1] ELSE [] END | MERGE (exact_p)-[:TRIGGERED]->(ae))

        WITH ae, eid
        OPTIONAL MATCH (fuzzy_p:Process)
        WHERE eid ENDS WITH 'unknown' AND fuzzy_p.id STARTS WITH split(eid, '_unknown')[0] 
        FOREACH (_ IN CASE WHEN fuzzy_p IS NOT NULL THEN [1] ELSE [] END | MERGE (fuzzy_p)-[:TRIGGERED]->(ae))

        WITH ae, eid
        OPTIONAL MATCH (d:Domain {id: eid})
        FOREACH (_ IN CASE WHEN d IS NOT NULL THEN [1] ELSE [] END | MERGE (d)-[:TRIGGERED]->(ae))
        WITH ae, eid
        OPTIONAL MATCH (f:File {id: eid})
        FOREACH (_ IN CASE WHEN f IS NOT NULL THEN [1] ELSE [] END | MERGE (f)-[:TRIGGERED]->(ae))
        WITH ae, eid
        OPTIONAL MATCH (r:Registry {id: eid})
        FOREACH (_ IN CASE WHEN r IS NOT NULL THEN [1] ELSE [] END | MERGE (r)-[:TRIGGERED]->(ae))
        WITH ae, eid
        OPTIONAL MATCH (i:IP {id: eid})
        FOREACH (_ IN CASE WHEN i IS NOT NULL THEN [1] ELSE [] END | MERGE (i)-[:TRIGGERED]->(ae))
        """
        self._batch_execute(ingest_query, attack_data_list, param_name="batch")

        # 4.2 时序链 (Temporal Chain) - 单机内的时间关联
        chain_query = """
        MATCH (a:AttackEvent)
        WITH a.victim_ip as victim, a
        ORDER BY a.timestamp_start ASC, a.id ASC
        WITH victim, collect(a) as events
        WHERE size(events) > 1
        UNWIND range(0, size(events)-2) as i
        WITH events[i] as a1, events[i+1] as a2
        WHERE duration.inSeconds(datetime(a1.timestamp_end), datetime(a2.timestamp_start)).seconds < $window
        MERGE (a1)-[r:NEXT_STAGE]->(a2)
        SET r.type = 'temporal', r.confidence = 'Low'
        """
        self._run_massive_update(chain_query, window=10000)
        logging.info(f"已更新 {len(attack_data_list)} 条事件的单机时序链")

    def build_causal_chains(self, time_window_seconds=36000, max_hops=10):
        logging.info("开始执行跨主机因果关联分析...")

        # [Fix 2] 横向移动逻辑：如果 事件A.victim == 事件B.attacker，则连接它们
        causal_query = """
                MATCH (a1:AttackEvent)
                MATCH (a2:AttackEvent)
                WHERE a1.attack_id <> a2.attack_id
                  // 时间先后：a1 发生时间 <= a2 发生时间
                  AND datetime(a1.timestamp_start) <= datetime(a2.timestamp_start)

                  // 时间窗口
                  AND duration.inSeconds(datetime(a1.timestamp_start), datetime(a2.timestamp_start)).seconds < $window

                // 核心判定：满足以下任意条件即建立连接
                AND (
                    // 条件A: 横向移动 (A是跳板机，B是受害者，且A的受害IP就是B记录的攻击者IP)
                    (a1.victim_ip = a2.attacker_ip)
                    OR
                    // 条件B: 强关联路径 (通过网络连接、登录来源等边相连)
                    EXISTS {
                        MATCH (e1)-[:TRIGGERED]->(a1)
                        MATCH (e2)-[:TRIGGERED]->(a2)
                        MATCH path = shortestPath((e1)-[:Spawn|Write|Read|Inject|Connect|Resolve|Load|Traffic_Flow|Logon|Logon_Source*1..8]-(e2))
                        WHERE any(r IN relationships(path) WHERE type(r) IN ['Connect', 'Traffic_Flow', 'Logon_Source'])
                    }
                )

                MERGE (a1)-[r:NEXT_STAGE]->(a2)
                SET r.type = 'causal',
                    r.confidence = 'High',
                    r.description = CASE 
                        WHEN a1.victim_ip = a2.attacker_ip THEN 'Lateral Movement' 
                        ELSE 'Cross-Host Causal' 
                    END,
                    r.time_gap = duration.inSeconds(datetime(a1.timestamp_start), datetime(a2.timestamp_start)).seconds
                """

        self._run_massive_update(causal_query, window=time_window_seconds)
        logging.info("因果推断分析更新完成")