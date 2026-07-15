"""
RAG 知识库
优先使用 Chroma 持久化向量检索；当 Chroma 不可用或未建索引时，自动回退到本地 TF-IDF。
"""
import json
import math
import os
import re
from collections import Counter
from typing import Any

from config import Config
from .chroma_rag_store import ChromaRAGStore


def _project_root() -> str:
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _kb_path(kb_dir: str = "knowledge_base") -> str:
    path = kb_dir
    if not os.path.isabs(path):
        path = os.path.join(_project_root(), kb_dir)
    return path


def _load_json(path: str) -> dict:
    if not os.path.exists(path):
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def load_knowledge_documents(kb_dir: str = "knowledge_base") -> tuple[list[dict], dict]:
    """从本地 JSON 组装统一知识文档。"""
    kb_path = _kb_path(kb_dir)
    documents: list[dict] = []
    versions: dict[str, Any] = {}

    corpus_path = os.path.join(kb_path, "rag_corpus.json")
    corpus_data = _load_json(corpus_path)
    for item in corpus_data.get("corpus", []):
        documents.append({
            "doc_id": str(item["id"]),
            "title": item["title"],
            "category": str(item["category"]),
            "content": item["content"],
            "keywords": list(item.get("keywords", [])),
            "metadata": {
                "source_file": "rag_corpus.json",
                "technique_id": "",
                "apt_group": "",
                "cve_id": "",
                "version": str(corpus_data.get("version", "local-json")),
                "updated_at": str(corpus_data.get("updated_at", "")),
            },
        })

    attck_path = os.path.join(kb_path, "attck_techniques.json")
    attck_data = _load_json(attck_path)
    for tech in attck_data.get("techniques", []):
        documents.append({
            "doc_id": f"attck_{str(tech['id']).replace('.', '_')}",
            "title": f"{tech['id']} - {tech['name']}",
            "category": "attck_technique",
            "content": (
                f"ATT&CK 技术 {tech['id']} ({tech['name']})。"
                f"战术: {tech.get('tactic', '')}。"
                f"描述: {tech.get('description', '')}。"
                f"检测模式: {', '.join(tech.get('detection_patterns', []))}。"
            ),
            "keywords": [tech.get("id", ""), tech.get("name", "")] + list(tech.get("detection_patterns", [])),
            "metadata": {
                "source_file": "attck_techniques.json",
                "technique_id": str(tech.get("id", "")),
                "apt_group": "",
                "cve_id": "",
                "version": str(attck_data.get("version", "MITRE ATT&CK v18")),
                "updated_at": str(attck_data.get("updated_at", "")),
                "tactic": str(tech.get("tactic", "")),
            },
        })

    apt_path = os.path.join(kb_path, "apt_groups.json")
    apt_data = _load_json(apt_path)
    cve_groups: dict[str, list[str]] = {}
    tool_groups: dict[str, list[str]] = {}
    for group in apt_data.get("apt_groups", []):
        group_name = str(group.get("name", ""))
        documents.append({
            "doc_id": f"apt_{group['id']}",
            "title": f"{group_name} ({group.get('country', 'Unknown')})",
            "category": "apt_group",
            "content": (
                f"APT组织 {group_name}。"
                f"别名: {', '.join(group.get('aliases', []))}。"
                f"国家: {group.get('country', 'Unknown')}。"
                f"动机: {', '.join(group.get('motivation', []))}。"
                f"目标行业: {', '.join(group.get('target_sectors', []))}。"
                f"TTP: {', '.join(group.get('signature_ttps', []))}。"
                f"恶意软件/工具: {', '.join(group.get('signature_malware', []))}。"
                f"利用CVE: {', '.join(group.get('exploited_cves', []))}。"
                f"描述: {group.get('description', '')}"
            ),
            "keywords": (
                [group_name] +
                list(group.get("aliases", [])) +
                list(group.get("signature_ttps", [])) +
                list(group.get("signature_malware", [])) +
                list(group.get("exploited_cves", []))
            ),
            "metadata": {
                "source_file": "apt_groups.json",
                "technique_id": "",
                "apt_group": group_name,
                "cve_id": "",
                "version": str(apt_data.get("updated", "local-json")),
                "updated_at": str(apt_data.get("updated", "")),
                "group_id": str(group.get("id", "")),
            },
        })
        for cve_id in group.get("exploited_cves", []):
            cve_groups.setdefault(str(cve_id), []).append(group_name)
        for tool_name in group.get("signature_malware", []):
            tool_groups.setdefault(str(tool_name), []).append(group_name)

    for cve_id, group_names in sorted(cve_groups.items()):
        documents.append({
            "doc_id": f"cve_{cve_id.replace('-', '_')}",
            "title": cve_id,
            "category": "cve",
            "content": f"漏洞 {cve_id}。已知关联组织: {', '.join(sorted(set(group_names)))}。",
            "keywords": [cve_id] + sorted(set(group_names)),
            "metadata": {
                "source_file": "apt_groups.json",
                "technique_id": "",
                "apt_group": ", ".join(sorted(set(group_names))),
                "cve_id": cve_id,
                "version": str(apt_data.get("updated", "local-json")),
                "updated_at": str(apt_data.get("updated", "")),
            },
        })

    for tool_name, group_names in sorted(tool_groups.items()):
        documents.append({
            "doc_id": f"tool_{re.sub(r'[^a-zA-Z0-9_]+', '_', tool_name.lower())}",
            "title": tool_name,
            "category": "tool_malware",
            "content": f"工具/恶意软件 {tool_name}。已知关联组织: {', '.join(sorted(set(group_names)))}。",
            "keywords": [tool_name] + sorted(set(group_names)),
            "metadata": {
                "source_file": "apt_groups.json",
                "technique_id": "",
                "apt_group": ", ".join(sorted(set(group_names))),
                "cve_id": "",
                "version": str(apt_data.get("updated", "local-json")),
                "updated_at": str(apt_data.get("updated", "")),
            },
        })

    versions = {
        "apt_groups": str(apt_data.get("updated", "local-json")),
        "attck_techniques": str(attck_data.get("version", "MITRE ATT&CK v18")),
        "rag_corpus": str(corpus_data.get("version", "local-json")),
        "sources": list(apt_data.get("sources", [])),
    }
    return documents, versions


class RAGKnowledgeBase:
    """兼容现有接口的 RAG 检索增强知识库。"""

    def __init__(self, kb_dir: str = "knowledge_base"):
        self.kb_dir = kb_dir
        self.documents: list[dict] = []
        self.vocabulary: dict[str, int] = {}
        self.inverted_index: dict[str, list[int]] = {}
        self.doc_vectors: list[dict[str, float]] = []
        self.versions: dict[str, Any] = {}
        self.chroma_store = ChromaRAGStore(
            persist_dir=os.getenv("CHROMA_PERSIST_DIR", "data/chroma"),
            collection_name=os.getenv("CHROMA_COLLECTION_NAME", "deepsecurity_kb"),
            embedding_backend=os.getenv("RAG_EMBEDDING_BACKEND", "local"),
        )
        self._loaded = False

    def load(self):
        if self._loaded:
            return
        self.documents, self.versions = load_knowledge_documents(self.kb_dir)
        self._build_index()
        self._loaded = True

    def _tokenize(self, text: str) -> list[str]:
        tokens = []
        eng_words = re.findall(r"[a-zA-Z0-9_]+(?:\.[a-zA-Z0-9_]+)*", str(text or "").lower())
        tokens.extend(eng_words)
        chinese = re.findall(r"[\u4e00-\u9fff]+", str(text or ""))
        for segment in chinese:
            tokens.append(segment)
            for i in range(len(segment) - 1):
                tokens.append(segment[i:i + 2])
        return tokens

    def _build_index(self):
        doc_count = len(self.documents)
        if doc_count == 0:
            return

        self.vocabulary = {}
        self.inverted_index = {}
        self.doc_vectors = []

        df: dict[str, int] = Counter()
        all_doc_tokens = []
        for doc in self.documents:
            text = str(doc["content"]) + " " + " ".join(doc.get("keywords", []))
            tokens = self._tokenize(text)
            all_doc_tokens.append(tokens)
            for token in set(tokens):
                df[token] = df.get(token, 0) + 1

        self.vocabulary = {word: idx for idx, word in enumerate(sorted(df.keys()))}
        self.inverted_index = {word: [] for word in self.vocabulary}
        for doc_idx, tokens in enumerate(all_doc_tokens):
            for word in set(tokens):
                if word in self.inverted_index:
                    self.inverted_index[word].append(doc_idx)

        for tokens in all_doc_tokens:
            tf = Counter(tokens)
            vec: dict[str, float] = {}
            norm = 0.0
            for word, count in tf.items():
                if word in self.vocabulary and word in df:
                    idf = math.log((doc_count + 1) / (df[word] + 1)) + 1
                    weight = count * idf
                    vec[word] = weight
                    norm += weight * weight
            norm = math.sqrt(norm) if norm > 0 else 1.0
            self.doc_vectors.append({w: v / norm for w, v in vec.items()})

    def rebuild_chroma(self, reset: bool = True) -> dict:
        if not self._loaded:
            self.load()
        return self.chroma_store.build(self.documents, reset=reset)

    def _search_tfidf(self, query: str, top_k: int = 5) -> list[dict]:
        if not self.doc_vectors:
            return []
        query_tokens = self._tokenize(query)
        tf = Counter(query_tokens)
        df = {w: len(self.inverted_index.get(w, [])) for w in query_tokens if w in self.vocabulary}
        doc_count = len(self.documents)
        query_vec: dict[str, float] = {}
        norm = 0.0
        for word, count in tf.items():
            if word in self.vocabulary:
                idf = math.log((doc_count + 1) / (df.get(word, 0) + 1)) + 1
                weight = count * idf
                query_vec[word] = weight
                norm += weight * weight
        norm = math.sqrt(norm) if norm > 0 else 1.0
        query_vec = {w: v / norm for w, v in query_vec.items()}

        scores = []
        for idx, doc_vec in enumerate(self.doc_vectors):
            dot = sum(doc_vec.get(w, 0.0) * query_vec.get(w, 0.0) for w in query_vec)
            scores.append((idx, dot))
        scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        candidate_limit = max(top_k * 4, top_k + 8)
        for idx, score in scores[:candidate_limit]:
            if score <= 0.01:
                continue
            doc = self.documents[idx]
            results.append({
                "id": doc["doc_id"],
                "title": doc["title"],
                "category": doc["category"],
                "content": str(doc["content"])[:500],
                "snippet": str(doc["content"])[:220],
                "similarity": round(score, 4),
                "metadata": doc.get("metadata", {}),
                "engine": "tfidf",
                "source_id": doc["doc_id"],
                "source_file": doc.get("metadata", {}).get("source_file", ""),
            })
        return self._rerank_results(query, results, top_k=top_k)

    def _rerank_results(self, query: str, results: list[dict], top_k: int) -> list[dict]:
        query_lower = str(query or "").strip().lower()
        query_tokens = [t for t in self._tokenize(query_lower) if t]
        reranked = []
        for item in results:
            title = str(item.get("title", "")).lower()
            content = str(item.get("content", "")).lower()
            metadata = item.get("metadata", {}) or {}
            keywords = str(metadata.get("keywords", "")).lower()
            bonus = 0.0
            if query_lower and query_lower in title:
                bonus += 0.35
            elif query_lower and query_lower in content:
                bonus += 0.12
            for token in query_tokens:
                if token and token in title:
                    bonus += 0.08
                if token and token in keywords:
                    bonus += 0.05
                if token and token == str(metadata.get("technique_id", "")).lower():
                    bonus += 0.15
                if token and token in str(metadata.get("apt_group", "")).lower():
                    bonus += 0.12
                if token and token == str(metadata.get("cve_id", "")).lower():
                    bonus += 0.15
            item["similarity"] = round(min(1.0, float(item.get("similarity", 0)) + bonus), 4)
            reranked.append(item)
        reranked.sort(key=lambda x: x.get("similarity", 0), reverse=True)
        return reranked[:top_k]

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if not self._loaded:
            self.load()
        query = str(query or "").strip()
        if not query:
            return []

        if self.chroma_store.available and self.chroma_store.count() > 0:
            chroma_hits = self.chroma_store.search(query, top_k=top_k)
            if chroma_hits:
                return self._rerank_results(query, chroma_hits, top_k=top_k)
        return self._search_tfidf(query, top_k=top_k)

    def get_attck_context(self, technique_ids: list[str]) -> list[dict]:
        if not self._loaded:
            self.load()
        results = []
        for doc in self.documents:
            if doc["category"] != "attck_technique":
                continue
            title = str(doc.get("title", ""))
            doc_tid = str(doc.get("metadata", {}).get("technique_id", ""))
            for tid in technique_ids:
                if tid and (tid == doc_tid or tid in title):
                    results.append(doc)
                    break
        return results

    def get_apt_context(self, apt_name: str) -> dict | None:
        if not self._loaded:
            self.load()
        q = str(apt_name or "").lower()
        for doc in self.documents:
            if doc["category"] == "apt_group" and q in str(doc.get("title", "")).lower():
                return doc
        return None

    def collect_supporting_references(self,
                                      technique_ids: list[str] | None = None,
                                      technique_names: list[str] | None = None,
                                      apt_name: str = "",
                                      top_k: int = 4) -> list[dict]:
        if not self._loaded:
            self.load()
        queries: list[str] = []
        queries.extend([str(x) for x in (technique_ids or []) if x])
        queries.extend([str(x) for x in (technique_names or []) if x])
        if apt_name:
            queries.append(str(apt_name))
        merged: dict[str, dict] = {}
        for query in queries[:8]:
            for hit in self.search(query, top_k=2):
                existing = merged.get(hit["id"])
                if existing is None or hit.get("similarity", 0) > existing.get("similarity", 0):
                    merged[hit["id"]] = hit
        refs = list(merged.values())
        refs.sort(key=lambda item: item.get("similarity", 0), reverse=True)
        return refs[:top_k]

    def get_stats(self) -> dict:
        if not self._loaded:
            self.load()
        categories = sorted({str(d.get("category", "")) for d in self.documents})
        chroma_stats = self.chroma_store.get_stats()
        active_backend = "chroma" if chroma_stats.get("available") and chroma_stats.get("count", 0) > 0 else "tfidf"
        return {
            "documents_count": len(self.documents),
            "vocabulary_size": len(self.vocabulary),
            "categories": categories,
            "backend": active_backend,
            "fallback_backend": "tfidf",
            "chroma": chroma_stats,
            "versions": self.versions,
        }


_rag_kb: RAGKnowledgeBase | None = None


def get_rag_kb() -> RAGKnowledgeBase:
    global _rag_kb
    if _rag_kb is None:
        _rag_kb = RAGKnowledgeBase(
            kb_dir=getattr(Config, "KNOWLEDGE_BASE_PATH", "knowledge_base"),
        )
        _rag_kb.load()
    return _rag_kb
