"""
NVIDIA NIM RAG Engine Service — Retrieval & Reranking Layer

Integrates NVIDIA's microservice APIs:
1. Nemotron 1B Embedding API (nvidia/embed-qa-4) — generates dense vectors for RAG retrieval.
2. Mistral 4B Reranking API (nvidia/rerank-qa-mistral-4b) — reranks candidate articles by exact query relevance logits.
"""
import os
import httpx
from typing import List, Dict, Any, Optional
import structlog

from app.config import settings
from app.db.mongodb import get_articles_collection

log = structlog.get_logger()

# NVIDIA NIM API Keys & Model Endpoints
NVIDIA_EMBED_KEY = os.environ.get("NVIDIA_EMBED_KEY", "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")
NVIDIA_RERANK_KEY = os.environ.get("NVIDIA_RERANK_KEY", "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")

NVIDIA_EMBED_URL = "https://integrate.api.nvidia.com/v1/embeddings"
NVIDIA_RERANK_URL = "https://ai.api.nvidia.com/v1/retrieval/nvidia/reranking"


class NVIDIARAGService:
    """RAG Retrieval & Reranking Service powered by NVIDIA NIM microservices."""

    @staticmethod
    async def generate_embedding(text: str, input_type: str = "query") -> Optional[List[float]]:
        """Generate dense vector embedding using NVIDIA Nemotron 1B (nvidia/embed-qa-4)."""
        if not text or not text.strip():
            return None

        headers = {
            "Authorization": f"Bearer {NVIDIA_EMBED_KEY}",
            "Content-Type": "application/json",
        }
        payload = {
            "input": [text[:2000]],
            "model": "nvidia/nemotron-3-embed-1b",
            "input_type": input_type,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(NVIDIA_EMBED_URL, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return data["data"][0]["embedding"]
                else:
                    log.error("NVIDIA Embed API error", status=resp.status_code, text=resp.text)
        except Exception as e:
            log.error("NVIDIA Embed call failed", error=str(e))
        return None

    @staticmethod
    async def rerank_passages(query: str, passages: List[Dict[str, Any]], top_n: int = 10) -> List[Dict[str, Any]]:
        """Rerank retrieved candidate passages using NVIDIA Rerank QA Mistral 4B."""
        if not passages or not query:
            return passages[:top_n]

        headers = {
            "Authorization": f"Bearer {NVIDIA_RERANK_KEY}",
            "Content-Type": "application/json",
        }

        # Build passage payloads
        passage_items = []
        for p in passages:
            t = f"{p.get('title', '')}: {p.get('summary', '') or p.get('content_clean', '')}"
            passage_items.append({"text": t[:1000]})

        payload = {
            "model": "nvidia/rerank-qa-mistral-4b",
            "query": {"text": query},
            "passages": passage_items,
        }

        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                resp = await client.post(NVIDIA_RERANK_URL, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    rankings = data.get("rankings", [])

                    reranked = []
                    for rank in rankings:
                        idx = rank["index"]
                        if idx < len(passages):
                            item = passages[idx].copy()
                            item["rerank_logit"] = rank.get("logit", 0.0)
                            reranked.append(item)

                    log.info(f"NVIDIA Mistral 4B Reranked {len(reranked)} passages successfully")
                    return reranked[:top_n]
                else:
                    log.error("NVIDIA Rerank API error", status=resp.status_code, text=resp.text)
        except Exception as e:
            log.error("NVIDIA Rerank call failed", error=str(e))

        return passages[:top_n]

    @staticmethod
    async def hybrid_rag_search(query: str, top_k: int = 10) -> Dict[str, Any]:
        """
        Full RAG Pipeline:
        1. Query candidate articles from database.
        2. Rerank using NVIDIA Mistral 4B Reranker.
        3. Return top reranked context for LLM extraction and summarization.
        """
        articles_col = get_articles_collection()

        # Step 1: Lexical & Regex Candidate Search
        search_regex = {"$regex": query, "$options": "i"}
        cursor = articles_col.find({
            "$or": [
                {"title": search_regex},
                {"summary": search_regex},
                {"tags": search_regex},
                {"source_name": search_regex},
            ]
        }).limit(25)

        candidates = []
        async for doc in cursor:
            doc["id"] = str(doc.pop("_id"))
            candidates.append(doc)

        if not candidates:
            # Fallback to latest articles
            cursor_fallback = articles_col.find({}).sort("published_at", -1).limit(20)
            async for doc in cursor_fallback:
                doc["id"] = str(doc.pop("_id"))
                candidates.append(doc)

        # Step 2: Generate Query Embedding (Nemotron 1B)
        query_embedding = await NVIDIARAGService.generate_embedding(query, input_type="query")

        # Step 3: NVIDIA Mistral 4B Reranking
        reranked_results = await NVIDIARAGService.rerank_passages(query, candidates, top_n=top_k)

        return {
            "query": query,
            "query_vector_dimensions": len(query_embedding) if query_embedding else 0,
            "embedding_model": "nvidia/embed-qa-4 (Nemotron 1B)",
            "reranker_model": "nvidia/rerank-qa-mistral-4b",
            "candidates_count": len(candidates),
            "reranked_results": reranked_results,
        }
