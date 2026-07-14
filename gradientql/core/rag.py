"""RAG vector store wrapper using FAISS and HuggingFace embeddings."""

from __future__ import annotations

import logging
from typing import Any

from langchain_core.documents import Document

logger = logging.getLogger("gradientql.rag")


class SchemaVectorStore:
    """FAISS-backed similarity index over GraphQL schema chunks."""

    def __init__(self, model_name: str = "all-MiniLM-L6-v2") -> None:
        self._model_name = model_name
        self._embeddings = None
        self.store = None

    @property
    def embeddings(self):
        if self._embeddings is None:
            from langchain_community.embeddings import HuggingFaceEmbeddings
            self._embeddings = HuggingFaceEmbeddings(model_name=self._model_name)
        return self._embeddings

    def build_from_chunks(
        self,
        chunks: list[str],
        metadatas: list[dict[str, Any]] | None = None,
    ) -> None:
        if not chunks:
            logger.warning("No chunks provided to build vector store")
            return

        from langchain_community.vectorstores import FAISS

        logger.info("Building FAISS index from %d chunks", len(chunks))
        self.store = FAISS.from_texts(
            chunks,
            self.embeddings,
            metadatas=metadatas,
        )
        logger.info("FAISS index built successfully")

    def similarity_search(
        self,
        query: str,
        k: int = 5,
        filter_type: str | None = None,
    ) -> list[Document]:
        """Return up to k schema chunks most similar to the query.

        Args:
            filter_type: If set, restrict results to chunks whose metadata
                "type" matches, over-fetching and issuing a secondary query
                as needed to fill k.
        """
        if self.store is None:
            logger.warning("Vector store not initialized, returning empty results")
            return []
        search_k = k * 3 if filter_type else k
        results = self.store.similarity_search(query, k=search_k)
        if filter_type:
            filtered = [
                doc for doc in results
                if doc.metadata.get("type") == filter_type
            ]
            if len(filtered) < k and len(results) == search_k:
                logger.debug("Expanding search for filter_type=%s", filter_type)
                more_results = self.store.similarity_search(query, k=search_k * 2)
                for doc in more_results[search_k:]:
                    if doc.metadata.get("type") == filter_type and len(filtered) < k:
                        filtered.append(doc)
            return filtered[:k]
        return results
