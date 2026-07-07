"""
RAG知识库构建器
使用MITRE ATT&CK技术库、APT组织档案和攻击模式语料
基于TF-IDF向量化和余弦相似度进行语义检索
"""
import json
import os
import re
import math
from collections import Counter
from typing import Any


class RAGKnowledgeBase:
    """RAG检索增强知识库"""

    def __init__(self, kb_dir: str = "knowledge_base"):
        self.kb_dir = kb_dir
        self.documents: list[dict] = []
        self.vocabulary: dict[str, int] = {}
        self.inverted_index: dict[str, list[int]] = {}
        self.doc_vectors: list[dict[str, float]] = []
        self._loaded = False

    def load(self):
        """加载知识库"""
        if self._loaded:
            return

        base = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        kb_path = os.path.join(base, self.kb_dir)

        # 1. 加载RAG语料库
        corpus_path = os.path.join(kb_path, "rag_corpus.json")
        if os.path.exists(corpus_path):
            with open(corpus_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for item in data.get("corpus", []):
                    self.documents.append({
                        "id": item["id"],
                        "title": item["title"],
                        "category": item["category"],
                        "content": item["content"],
                        "keywords": item.get("keywords", [])
                    })

        # 2. 加载ATT&CK技术库
        attck_path = os.path.join(kb_path, "attck_techniques.json")
        if os.path.exists(attck_path):
            with open(attck_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for tech in data.get("techniques", []):
                    self.documents.append({
                        "id": f"attck_{tech['id'].replace('.', '_')}",
                        "title": f"{tech['id']} - {tech['name']}",
                        "category": "attck_technique",
                        "content": f"技术{tech['id']}: {tech['name']}。战术: {tech['tactic']}。"
                                   f"描述: {tech['description']}。"
                                   f"检测模式: {', '.join(tech.get('detection_patterns', []))}。",
                        "keywords": tech.get("detection_patterns", [])
                    })

        # 3. 加载APT组织档案
        apt_path = os.path.join(kb_path, "apt_groups.json")
        if os.path.exists(apt_path):
            with open(apt_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                for group in data.get("apt_groups", []):
                    self.documents.append({
                        "id": f"apt_{group['id']}",
                        "title": f"{group['name']} ({group.get('country', 'Unknown')})",
                        "category": "apt_group",
                        "content": f"APT组织 {group['name']} (别名: {', '.join(group.get('aliases', []))})。"
                                   f"动机: {group.get('motivation', 'Unknown')}。"
                                   f"目标行业: {', '.join(group.get('target_sectors', []))}。"
                                   f"特征TTP: {', '.join(group.get('signature_ttps', []))}。"
                                   f"常用工具: {', '.join(group.get('tools', []))}。"
                                   f"描述: {group.get('description', '')}",
                        "keywords": group.get("signature_ttps", []) + group.get("tools", [])
                    })

        # 构建TF-IDF索引
        self._build_index()
        self._loaded = True

    def _tokenize(self, text: str) -> list[str]:
        """中文+英文混合分词"""
        tokens = []
        # 英文单词
        eng_words = re.findall(r'[a-zA-Z_]+(?:\.[a-zA-Z_]+)*', text.lower())
        tokens.extend(eng_words)
        # 中文分词(简单按字符切分+双字组合)
        chinese = re.findall(r'[一-鿿]+', text)
        for segment in chinese:
            tokens.append(segment)
            for i in range(len(segment) - 1):
                tokens.append(segment[i:i + 2])
        return tokens

    def _build_index(self):
        """构建TF-IDF向量索引"""
        doc_count = len(self.documents)
        if doc_count == 0:
            return

        # 文档频率
        df: dict[str, int] = Counter()

        # 先计算所有token
        all_doc_tokens = []
        for doc in self.documents:
            text = doc["content"] + " " + " ".join(doc.get("keywords", []))
            tokens = self._tokenize(text)
            all_doc_tokens.append(tokens)
            unique_tokens = set(tokens)
            for t in unique_tokens:
                df[t] = df.get(t, 0) + 1

        # 构建词表
        self.vocabulary = {word: idx for idx, word in enumerate(sorted(df.keys()))}

        # 构建倒排索引
        for word, idx in self.vocabulary.items():
            self.inverted_index[word] = []

        for doc_idx, tokens in enumerate(all_doc_tokens):
            for word in set(tokens):
                if word in self.inverted_index:
                    self.inverted_index[word].append(doc_idx)

        # 计算TF-IDF向量
        for doc_idx, tokens in enumerate(all_doc_tokens):
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

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        """检索最相关的知识条目"""
        if not self._loaded:
            self.load()

        if not self.doc_vectors:
            return []

        # 构建查询向量
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

        # 计算余弦相似度
        scores = []
        for idx, doc_vec in enumerate(self.doc_vectors):
            dot = sum(doc_vec.get(w, 0) * query_vec.get(w, 0) for w in query_vec)
            scores.append((idx, dot))

        scores.sort(key=lambda x: x[1], reverse=True)

        results = []
        for idx, score in scores[:top_k]:
            if score > 0.01:
                doc = self.documents[idx]
                results.append({
                    "id": doc["id"],
                    "title": doc["title"],
                    "category": doc["category"],
                    "content": doc["content"][:500],
                    "similarity": round(score, 4)
                })
        return results

    def get_attck_context(self, technique_ids: list[str]) -> list[dict]:
        """获取特定ATT&CK技术的上下文"""
        if not self._loaded:
            self.load()

        results = []
        for doc in self.documents:
            if doc["category"] == "attck_technique":
                for tid in technique_ids:
                    if tid in doc["id"] or tid in doc["title"]:
                        results.append(doc)
        return results

    def get_apt_context(self, apt_name: str) -> dict | None:
        """获取特定APT组织的上下文"""
        if not self._loaded:
            self.load()

        for doc in self.documents:
            if doc["category"] == "apt_group" and apt_name.lower() in doc["title"].lower():
                return doc
        return None


# 全局知识库实例
_rag_kb: RAGKnowledgeBase | None = None


def get_rag_kb() -> RAGKnowledgeBase:
    global _rag_kb
    if _rag_kb is None:
        _rag_kb = RAGKnowledgeBase()
        _rag_kb.load()
    return _rag_kb
