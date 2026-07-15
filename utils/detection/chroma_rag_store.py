"""
Chroma 持久化 RAG 存储
默认使用本地确定性 embedding；若配置了 OpenAI 兼容 embedding API，则可切换远程向量化。
"""
import math
import os
import re
from collections import Counter
from typing import Any

try:
    import chromadb
except Exception:  # pragma: no cover - 依赖缺失时允许自动降级
    chromadb = None


class _LocalHashEmbedder:
    """不依赖外网和额外模型下载的本地 embedding。"""

    def __init__(self, dimension: int = 256):
        self.dimension = max(64, int(dimension))

    def _tokenize(self, text: str) -> list[str]:
        text = str(text or "")
        tokens = re.findall(r"[a-zA-Z0-9_\\.\\-]+", text.lower())
        chinese_segments = re.findall(r"[\u4e00-\u9fff]+", text)
        for segment in chinese_segments:
            tokens.append(segment)
            for i in range(len(segment) - 1):
                tokens.append(segment[i:i + 2])
        return tokens

    def _embed_one(self, text: str) -> list[float]:
        vec = [0.0] * self.dimension
        tf = Counter(self._tokenize(text))
        for token, count in tf.items():
            idx = hash(token) % self.dimension
            sign = -1.0 if (hash(token + "::sign") % 2) else 1.0
            vec[idx] += float(count) * sign
        norm = math.sqrt(sum(v * v for v in vec)) or 1.0
        return [v / norm for v in vec]

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return [self._embed_one(t) for t in texts]

    def embed_query(self, text: str) -> list[float]:
        return self._embed_one(text)


class _OpenAICompatibleEmbedder:
    """OpenAI 兼容 embedding 客户端。"""

    def __init__(self):
        from openai import OpenAI

        api_key = os.getenv("EMBEDDING_API_KEY") or os.getenv("LLM_API_KEY") or ""
        base_url = os.getenv("EMBEDDING_BASE_URL") or os.getenv("LLM_BASE_URL") or ""
        model = os.getenv("EMBEDDING_MODEL", "text-embedding-3-small")
        if not api_key:
            raise RuntimeError("embedding api key not configured")
        self.client = OpenAI(api_key=api_key, base_url=base_url or None)
        self.model = model

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        resp = self.client.embeddings.create(model=self.model, input=texts)
        return [item.embedding for item in resp.data]

    def embed_query(self, text: str) -> list[float]:
        resp = self.client.embeddings.create(model=self.model, input=[text])
        return list(resp.data[0].embedding)


class ChromaRAGStore:
    """Chroma 持久化检索封装。"""

    def __init__(self,
                 persist_dir: str = "data/chroma",
                 collection_name: str = "deepsecurity_kb",
                 embedding_backend: str = "local"):
        self.persist_dir = persist_dir
        self.collection_name = collection_name
        self.embedding_backend = (embedding_backend or "local").lower()
        self._client = None
        self._collection = None
        self._available = False
        self._reason = ""
        self._embedder = self._build_embedder()
        self._init_client()

    def _build_embedder(self):
        if self.embedding_backend == "openai":
            try:
                return _OpenAICompatibleEmbedder()
            except Exception as exc:
                self._reason = f"openai embedding unavailable: {exc}"
        return _LocalHashEmbedder(dimension=int(os.getenv("RAG_EMBED_DIM", "256")))

    def _init_client(self):
        if chromadb is None:
            self._available = False
            if not self._reason:
                self._reason = "chromadb not installed"
            return
        try:
            abs_dir = self.persist_dir
            if not os.path.isabs(abs_dir):
                abs_dir = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                    self.persist_dir,
                )
            os.makedirs(abs_dir, exist_ok=True)
            self.persist_dir = abs_dir
            self._client = chromadb.PersistentClient(path=abs_dir)
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )
            self._available = True
        except Exception as exc:
            self._available = False
            self._reason = str(exc)
            self._client = None
            self._collection = None

    @property
    def available(self) -> bool:
        return self._available and self._collection is not None

    def count(self) -> int:
        if not self.available:
            return 0
        try:
            return int(self._collection.count())
        except Exception:
            return 0

    def build(self, documents: list[dict], reset: bool = False) -> dict:
        if not self.available:
            return {"ok": False, "error": self._reason or "chroma unavailable"}
        if reset:
            try:
                self._client.delete_collection(self.collection_name)
            except Exception:
                pass
            self._collection = self._client.get_or_create_collection(
                name=self.collection_name,
                metadata={"hnsw:space": "cosine"},
            )

        if not documents:
            return {"ok": True, "count": 0}

        ids = [str(doc["doc_id"]) for doc in documents]
        doc_texts = [str(doc.get("content", "")) for doc in documents]
        metadatas = []
        for doc in documents:
            md = dict(doc.get("metadata", {}))
            md["doc_id"] = str(doc["doc_id"])
            md["title"] = str(doc.get("title", ""))
            md["category"] = str(doc.get("category", ""))
            md["source_file"] = str(md.get("source_file", ""))
            md["technique_id"] = str(md.get("technique_id", ""))
            md["apt_group"] = str(md.get("apt_group", ""))
            md["cve_id"] = str(md.get("cve_id", ""))
            md["version"] = str(md.get("version", ""))
            md["updated_at"] = str(md.get("updated_at", ""))
            md["keywords"] = ", ".join(doc.get("keywords", []))
            metadatas.append(md)

        embeddings = self._embedder.embed_documents(doc_texts)
        self._collection.add(
            ids=ids,
            documents=doc_texts,
            metadatas=metadatas,
            embeddings=embeddings,
        )
        return {"ok": True, "count": self.count(), "persist_dir": self.persist_dir}

    def search(self, query: str, top_k: int = 5) -> list[dict]:
        if not self.available or self.count() <= 0:
            return []
        q = str(query or "").strip()
        if not q:
            return []
        try:
            result = self._collection.query(
                query_embeddings=[self._embedder.embed_query(q)],
                n_results=max(1, int(top_k)),
                include=["documents", "metadatas", "distances"],
            )
        except Exception:
            return []

        hits: list[dict] = []
        docs = (result.get("documents") or [[]])[0]
        metadatas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]
        for idx, doc_text in enumerate(docs):
            md = metadatas[idx] if idx < len(metadatas) else {}
            distance = float(distances[idx]) if idx < len(distances) else 1.0
            similarity = max(0.0, min(1.0, 1.0 - (distance / 2.0)))
            hits.append({
                "id": md.get("doc_id", ""),
                "title": md.get("title", ""),
                "category": md.get("category", ""),
                "content": str(doc_text or "")[:500],
                "snippet": str(doc_text or "")[:220],
                "similarity": round(similarity, 4),
                "metadata": md,
                "engine": "chroma",
                "source_id": md.get("doc_id", ""),
                "source_file": md.get("source_file", ""),
            })
        return hits

    def get_stats(self) -> dict:
        return {
            "available": self.available,
            "count": self.count(),
            "collection_name": self.collection_name,
            "persist_dir": self.persist_dir,
            "embedding_backend": "openai" if isinstance(self._embedder, _OpenAICompatibleEmbedder) else "local",
            "reason": self._reason,
        }
