"""构建 Chroma 持久化知识库索引。"""
import argparse
import json
import os
import sys


def main() -> int:
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    if project_root not in sys.path:
        sys.path.insert(0, project_root)

    from utils.detection.rag_knowledge_base import load_knowledge_documents
    from utils.detection.chroma_rag_store import ChromaRAGStore

    parser = argparse.ArgumentParser(description="Build Chroma index for DeepSecurity knowledge base")
    parser.add_argument("--kb-dir", default="knowledge_base", help="知识库目录")
    parser.add_argument("--persist-dir", default=os.getenv("CHROMA_PERSIST_DIR", "data/chroma"), help="Chroma 持久化目录")
    parser.add_argument("--collection", default=os.getenv("CHROMA_COLLECTION_NAME", "deepsecurity_kb"), help="集合名")
    parser.add_argument("--reset", action="store_true", help="重建前删除旧集合")
    args = parser.parse_args()

    documents, versions = load_knowledge_documents(args.kb_dir)
    store = ChromaRAGStore(
        persist_dir=args.persist_dir,
        collection_name=args.collection,
        embedding_backend=os.getenv("RAG_EMBEDDING_BACKEND", "local"),
    )
    result = store.build(documents, reset=args.reset)
    print(json.dumps({
        "ok": bool(result.get("ok")),
        "documents": len(documents),
        "persist_dir": store.persist_dir,
        "collection": args.collection,
        "categories": sorted({doc.get("category", "") for doc in documents}),
        "versions": versions,
        "store": result,
    }, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
