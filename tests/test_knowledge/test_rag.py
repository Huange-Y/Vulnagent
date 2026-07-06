"""Tests for TF-IDF knowledge retriever."""
from pathlib import Path

from vulnagent.knowledge.rag import KnowledgeRetriever, KnowledgeDoc, _tokenize, _guess_arch


class TestTokenize:
    def test_basic(self):
        assert _tokenize("hello world test") == ["hello", "world", "test"]

    def test_filters_short(self):
        result = _tokenize("a big test")
        assert "a" not in result
        assert "big" in result


class TestGuessArch:
    def test_mips(self):
        assert _guess_arch("mips32 big endian") == "mips"

    def test_arm(self):
        assert _guess_arch("arm cortex-m4") == "arm"
        assert _guess_arch("aarch64 little") == "arm"

    def test_unknown(self):
        assert _guess_arch("some text") == ""


class TestKnowledgeRetriever:
    def test_empty(self):
        kr = KnowledgeRetriever()
        assert kr.retrieve("any") == []

    def test_add_retrieve(self):
        kr = KnowledgeRetriever()
        kr.add(KnowledgeDoc(id="1", title="MIPS Overflow",
                            content="MIPS sprintf format string",
                            category="arch", architecture="mips"))
        results = kr.retrieve("sprintf overflow")
        assert len(results) >= 1
        assert results[0].title == "MIPS Overflow"

    def test_context_for_arch(self):
        kr = KnowledgeRetriever()
        kr.add(KnowledgeDoc(id="2", title="ARM Guide",
                            content="ARM buffer overflow bypass",
                            category="arch", architecture="arm"))
        ctx = kr.context_for_architecture("arm")
        assert "ARM Guide" in ctx

    def test_index_directory(self, tmp_path: Path):
        d = tmp_path / "docs"
        d.mkdir()
        (d / "test.md").write_text("# MIPS ROP\nMIPS return gadgets\n", encoding="utf-8")
        kr = KnowledgeRetriever()
        kr.index_directory(d)
        assert len(kr._docs) == 1
        results = kr.retrieve("rop gadgets")
        assert len(results) == 1
