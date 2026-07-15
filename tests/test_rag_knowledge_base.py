import unittest

from utils.detection.rag_knowledge_base import RAGKnowledgeBase, load_knowledge_documents


class RAGKnowledgeBaseTest(unittest.TestCase):
    def test_documents_include_required_categories(self):
        docs, versions = load_knowledge_documents("knowledge_base")
        categories = {doc.get("category") for doc in docs}
        self.assertTrue({"attck_technique", "apt_group", "cve", "tool_malware"}.issubset(categories))
        self.assertIn("attck_techniques", versions)
        self.assertGreater(len(docs), 0)

    def test_search_finds_expected_entries(self):
        kb = RAGKnowledgeBase("knowledge_base")
        kb.load()

        lazarus_hits = kb.search("Lazarus", top_k=5)
        self.assertTrue(any("Lazarus" in hit.get("title", "") for hit in lazarus_hits))

        dns_hits = kb.search("dns tunnel", top_k=5)
        self.assertTrue(any(hit.get("category") in {"attck_technique", "dns_tunneling", "apt_behavior"} for hit in dns_hits))

        t1059_hits = kb.search("T1059", top_k=5)
        self.assertTrue(any("T1059" in hit.get("title", "") or hit.get("metadata", {}).get("technique_id") == "T1059" for hit in t1059_hits))

    def test_stats_expose_backend_and_versions(self):
        kb = RAGKnowledgeBase("knowledge_base")
        stats = kb.get_stats()
        self.assertIn(stats.get("backend"), {"tfidf", "chroma"})
        self.assertEqual("tfidf", stats.get("fallback_backend"))
        self.assertIn("versions", stats)
        self.assertGreater(stats.get("documents_count", 0), 0)


if __name__ == "__main__":
    unittest.main()
