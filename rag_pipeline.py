"""
LlamaIndex RAG Pipeline
Connects to Qdrant and provides:
  - index_logs()     : index log documents into Qdrant
  - query_logs()     : semantic search + LLM synthesis
  - build_pipeline() : returns a configured QueryEngine
"""

import os
import logging
from typing import List, Optional

log = logging.getLogger(__name__)

QDRANT_HOST    = os.getenv("QDRANT_HOST", "qdrant")
QDRANT_PORT    = int(os.getenv("QDRANT_PORT", 6333))
OLLAMA_HOST    = os.getenv("OLLAMA_HOST", "ollama")
OLLAMA_PORT    = int(os.getenv("OLLAMA_PORT", 11434))
COLLECTION     = os.getenv("COLLECTION_NAME", "logs_collection")


def build_pipeline():
    """
    Build and return a LlamaIndex QueryEngine backed by Qdrant + Ollama.
    Falls back gracefully if services are unavailable.
    """
    try:
        from llama_index.core import VectorStoreIndex, Settings
        from llama_index.vector_stores.qdrant import QdrantVectorStore
        from llama_index.llms.ollama import Ollama
        from llama_index.embeddings.huggingface import HuggingFaceEmbedding
        from qdrant_client import QdrantClient

        # Configure global settings
        Settings.llm = Ollama(
            model="mistral",
            base_url=f"http://{OLLAMA_HOST}:{OLLAMA_PORT}",
            request_timeout=60.0,
        )
        Settings.embed_model = HuggingFaceEmbedding(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )
        Settings.chunk_size = 512

        # Qdrant vector store
        client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
        vector_store = QdrantVectorStore(
            client=client,
            collection_name=COLLECTION,
        )

        index = VectorStoreIndex.from_vector_store(vector_store=vector_store)
        query_engine = index.as_query_engine(similarity_top_k=5)

        log.info("✅ LlamaIndex RAG pipeline initialized")
        return query_engine

    except Exception as e:
        log.warning(f"LlamaIndex pipeline init failed (using fallback): {e}")
        return None


def index_logs(documents: List[dict], query_engine=None) -> bool:
    """
    Index a list of log dicts into the Qdrant collection via LlamaIndex.
    Each dict must have at least a 'message' key.
    """
    try:
        from llama_index.core import Document, VectorStoreIndex, Settings
        from llama_index.vector_stores.qdrant import QdrantVectorStore
        from llama_index.embeddings.huggingface import HuggingFaceEmbedding
        from qdrant_client import QdrantClient

        Settings.embed_model = HuggingFaceEmbedding(
            model_name="sentence-transformers/all-MiniLM-L6-v2"
        )

        docs = []
        for l in documents:
            text = f"[{l.get('level','INFO')}] {l.get('source','unknown')}: {l.get('message','')}"
            docs.append(Document(
                text=text,
                metadata={k: v for k, v in l.items() if k != "message"}
            ))

        client = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
        vector_store = QdrantVectorStore(client=client, collection_name=COLLECTION)
        VectorStoreIndex.from_documents(docs, vector_store=vector_store)
        log.info(f"✅ Indexed {len(docs)} documents via LlamaIndex")
        return True

    except Exception as e:
        log.error(f"LlamaIndex indexing failed: {e}")
        return False


async def query_logs(question: str, engine=None) -> dict:
    """
    RAG query: semantic search over logs + LLM answer synthesis.
    Returns dict with 'answer' and 'source_nodes'.
    """
    if engine is None:
        engine = build_pipeline()

    if engine is None:
        return {"answer": f"[RAG unavailable] Question: {question}", "source_nodes": []}

    try:
        response = engine.query(question)
        sources = []
        for node in getattr(response, "source_nodes", []):
            sources.append({
                "text": node.node.get_content()[:200],
                "score": round(node.score or 0, 4),
                "metadata": node.node.metadata,
            })
        return {
            "answer": str(response),
            "source_nodes": sources,
        }
    except Exception as e:
        log.error(f"RAG query failed: {e}")
        return {"answer": f"Query error: {e}", "source_nodes": []}
