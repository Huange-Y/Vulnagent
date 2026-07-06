"""Lightweight TF-IDF knowledge retriever for RTOS/architecture docs.

No heavy dependencies (no Chroma/FAISS). Good for <1000 documents.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class KnowledgeDoc:
    id: str
    title: str
    content: str
    category: str = ""
    architecture: str = ""


def _tokenize(text: str) -> list[str]:
    return [w.strip().lower() for w in text.split() if len(w.strip()) > 1]


def _guess_arch(text: str) -> str:
    t = text.lower()
    if "mips" in t:
        return "mips"
    if "arm" in t or "aarch64" in t:
        return "arm"
    if "x86" in t:
        return "x86"
    if "riscv" in t:
        return "riscv"
    return ""


class KnowledgeRetriever:
    """TF-IDF document retriever for firmware/RTOS knowledge injection."""

    def __init__(self, docs_dir: str | None = None) -> None:
        self._docs: list[KnowledgeDoc] = []
        self._idf: dict[str, float] = {}
        self._built = False
        if docs_dir:
            self.index_directory(Path(docs_dir))

    def add(self, doc: KnowledgeDoc) -> None:
        self._docs.append(doc)
        self._built = False

    def index_directory(self, directory: Path) -> None:
        if not directory.exists():
            return
        for fp in directory.rglob("*.md"):
            try:
                text = fp.read_text(encoding="utf-8")
                title = fp.stem.replace("-", " ").replace("_", " ")
                self._docs.append(KnowledgeDoc(
                    id=str(fp), title=title, content=text,
                    category=fp.parent.name,
                    architecture=_guess_arch(title + " " + text),
                ))
            except Exception:
                pass
        self._build_index()

    def retrieve(self, query: str, top_k: int = 5) -> list[KnowledgeDoc]:
        if not self._built:
            self._build_index()
        if not self._docs:
            return []
        terms = _tokenize(query)
        scored = [(d, self._tfidf_score(d, terms)) for d in self._docs]
        scored.sort(key=lambda x: x[1], reverse=True)
        return [d for d, s in scored[:top_k] if s > 0]

    def context_for_architecture(self, arch: str) -> str:
        docs = [d for d in self._docs if d.architecture == arch]
        if not docs:
            docs = self.retrieve(f"{arch} firmware analysis", top_k=3)
        return "\n\n".join(
            f"## {d.title}\n{d.content[:2000]}" for d in docs[:5]
        )

    def context_for_rtos(self, rtos: str) -> str:
        docs = self.retrieve(f"{rtos} RTOS vulnerability", top_k=5)
        return "\n\n".join(
            f"## {d.title}\n{d.content[:2000]}" for d in docs
        )

    def _build_index(self) -> None:
        self._idf.clear()
        N = len(self._docs)
        if N == 0:
            self._built = True
            return
        df: dict[str, int] = {}
        for doc in self._docs:
            seen: set[str] = set()
            for term in _tokenize(doc.content):
                if term not in seen:
                    df[term] = df.get(term, 0) + 1
                    seen.add(term)
        for term, count in df.items():
            self._idf[term] = math.log((N + 1) / (count + 1)) + 1
        self._built = True

    def _tfidf_score(self, doc: KnowledgeDoc, qterms: list[str]) -> float:
        dterms = _tokenize(doc.content + " " + doc.title)
        tf: dict[str, float] = {}
        for t in dterms:
            tf[t] = tf.get(t, 0.0) + 1.0
        score = 0.0
        for t in qterms:
            if t in tf and t in self._idf:
                score += (1 + math.log(tf[t])) * self._idf[t]
        return score
