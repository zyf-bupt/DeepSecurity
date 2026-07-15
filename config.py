"""项目配置文件"""
import os
from typing import Optional


class Config:
    """基础配置"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-only-change-me'

    # ========== SQL Server 连接串（给 pyodbc/dbutils 用）==========
    DB_DRIVER = os.environ.get("DB_DRIVER") or "ODBC Driver 17 for SQL Server"
    DB_SERVER = os.environ.get("DB_SERVER") or "localhost,1433"
    DB_DATABASE = os.environ.get("DB_DATABASE") or "SecurityTraceDB"
    DB_USERNAME = os.environ.get("DB_USERNAME") or "sa"
    DB_PASSWORD = os.environ.get("DB_PASSWORD") or ""

    SQL_CONN_STR = (
        f"DRIVER={{{DB_DRIVER}}};"
        f"SERVER={DB_SERVER};"
        f"DATABASE={DB_DATABASE};"
        f"UID={DB_USERNAME};"
        f"PWD={DB_PASSWORD};"
        "TrustServerCertificate=yes;"
    )

    @classmethod
    def build_sql_conn_str(cls, server: Optional[str] = None) -> str:
        db_server = server or cls.DB_SERVER
        return (
            f"DRIVER={{{cls.DB_DRIVER}}};"
            f"SERVER={db_server};"
            f"DATABASE={cls.DB_DATABASE};"
            f"UID={cls.DB_USERNAME};"
            f"PWD={cls.DB_PASSWORD};"
            "TrustServerCertificate=yes;"
        )

    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or ''
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = 'data/uploads'
    MAX_CONTENT_LENGTH = 100 * 1024 * 1024  # 100MB

    # ===== 新增：dumpcap + 在线抓包临时文件目录 =====
    DUMPCAP_PATH = os.environ.get("DUMPCAP_PATH") or ""
    LIVE_CAPTURE_DIR = os.environ.get("LIVE_CAPTURE_DIR") or "data/live_captures"

    TIME_WINDOW = 300
    ATTCK_THRESHOLD = 0.7
    MAX_PROCESS_DEPTH = 10

    KNOWLEDGE_BASE_PATH = 'knowledge_base/'
    ATTCK_DATA_FILE = 'knowledge_base/attck_techniques.json'
    APT_GROUPS_FILE = 'knowledge_base/apt_groups.json'
    RAG_CORPUS_FILE = 'knowledge_base/rag_corpus.json'
    CHROMA_PERSIST_DIR = os.environ.get("CHROMA_PERSIST_DIR") or "data/chroma"
    CHROMA_COLLECTION_NAME = os.environ.get("CHROMA_COLLECTION_NAME") or "deepsecurity_kb"
    RAG_EMBEDDING_BACKEND = os.environ.get("RAG_EMBEDDING_BACKEND") or "local"
    EMBEDDING_API_KEY = os.environ.get("EMBEDDING_API_KEY") or ""
    EMBEDDING_BASE_URL = os.environ.get("EMBEDDING_BASE_URL") or ""
    EMBEDDING_MODEL = os.environ.get("EMBEDDING_MODEL") or "text-embedding-3-small"

    # ===== LLM Detection Engine Settings =====
    LLM_API_KEY = os.environ.get("LLM_API_KEY") or ""
    LLM_BASE_URL = os.environ.get("LLM_BASE_URL") or "https://dashscope.aliyuncs.com/compatible-mode/v1"
    LLM_MODEL = os.environ.get("LLM_MODEL") or "qwen-flash"
    RAG_TOP_K = int(os.environ.get("RAG_TOP_K", "5"))
    DETECTION_THRESHOLD = float(os.environ.get("DETECTION_THRESHOLD", "0.6"))

    # ===== Multi-Agent Capture Settings =====
    CAPTURE_AGENT_COUNT = 4
    EVIDENCE_CHAIN_ALGORITHM = "SHA-256"
    MAX_CAUSAL_CHAIN_DEPTH = 10

    # ===== Scenario Settings =====
    SCENARIO_DELAY_SECONDS = float(os.environ.get("SCENARIO_DELAY", "2.0"))
    MAX_EVENTS_BUFFER = int(os.environ.get("MAX_EVENTS_BUFFER", "5000"))
    ALERT_POLL_INTERVAL = int(os.environ.get("ALERT_POLL_INTERVAL", "3000"))

    # ===== Network Simulation Settings =====
    NETWORK_MONITOR_INTERVAL = int(os.environ.get("NETWORK_MONITOR_INTERVAL", "5"))
