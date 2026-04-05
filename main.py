"""
Agentic Log Pipeline — Agents Service
Exposes FastAPI endpoints for:
  - /ingest          : receive logs from NiFi, embed & store in Qdrant
  - /agent/classify  : Log Classification Agent
  - /agent/threat    : Threat Detection Agent
  - /agent/alert     : Alert Agent
  - /agent/summary   : Summary Agent
  - /query           : RAG query interface
  - /health          : healthcheck
"""

import os
import json
import uuid
import asyncio
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.models import (
    Distance, VectorParams, PointStruct, Filter, FieldCondition, MatchValue
)

# ─── Config ────────────────────────────────────────────────────────────────
QDRANT_HOST   = os.getenv("QDRANT_HOST", "qdrant")
QDRANT_PORT   = int(os.getenv("QDRANT_PORT", 6333))
OLLAMA_HOST   = os.getenv("OLLAMA_HOST", "ollama")
OLLAMA_PORT   = int(os.getenv("OLLAMA_PORT", 11434))
COLLECTION    = os.getenv("COLLECTION_NAME", "logs_collection")
VECTOR_SIZE   = 384   # all-MiniLM-L6-v2 output size
OLLAMA_URL    = f"http://{OLLAMA_HOST}:{OLLAMA_PORT}"

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

# ─── FastAPI ────────────────────────────────────────────────────────────────
app = FastAPI(title="Agentic Log Pipeline", version="1.0.0")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# ─── Qdrant client (lazy init) ──────────────────────────────────────────────
qdrant: Optional[QdrantClient] = None

def get_qdrant() -> QdrantClient:
    global qdrant
    if qdrant is None:
        qdrant = QdrantClient(host=QDRANT_HOST, port=QDRANT_PORT)
        _ensure_collection(qdrant)
    return qdrant

def _ensure_collection(client: QdrantClient):
    existing = [c.name for c in client.get_collections().collections]
    if COLLECTION not in existing:
        client.create_collection(
            collection_name=COLLECTION,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )
        log.info(f"Created Qdrant collection: {COLLECTION}")
    else:
        log.info(f"Qdrant collection already exists: {COLLECTION}")

# ─── Embedding (local, no external dep) ─────────────────────────────────────
_embed_model = None

def get_embedder():
    global _embed_model
    if _embed_model is None:
        from sentence_transformers import SentenceTransformer
        _embed_model = SentenceTransformer("all-MiniLM-L6-v2")
    return _embed_model

def embed_text(text: str) -> List[float]:
    return get_embedder().encode(text, normalize_embeddings=True).tolist()

# ─── Ollama LLM call ─────────────────────────────────────────────────────────
async def llm_generate(prompt: str, model: str = "mistral") -> str:
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            r = await client.post(f"{OLLAMA_URL}/api/generate", json={
                "model": model,
                "prompt": prompt,
                "stream": False
            })
            r.raise_for_status()
            return r.json().get("response", "").strip()
    except Exception as e:
        log.warning(f"Ollama unavailable ({e}), returning mock response")
        return f"[Mock LLM] Analysis of: {prompt[:80]}..."

# ─── Pydantic models ─────────────────────────────────────────────────────────
class LogEvent(BaseModel):
    timestamp: Optional[str] = None
    level: Optional[str] = "INFO"
    source: Optional[str] = "unknown"
    message: str
    metadata: Optional[Dict[str, Any]] = {}

class AgentRequest(BaseModel):
    log_data: str  # JSON string or plain text

class QueryRequest(BaseModel):
    query: str
    top_k: int = 5

# ─── Startup: seed sample logs ───────────────────────────────────────────────
SAMPLE_LOGS = [
    {"level": "INFO",     "source": "auth-service",    "message": "User admin logged in successfully from 192.168.1.10"},
    {"level": "WARN",     "source": "api-gateway",     "message": "Rate limit approaching for client_id=abc123"},
    {"level": "ERROR",    "source": "db-service",      "message": "Connection timeout after 30s — retrying (attempt 3/5)"},
    {"level": "CRITICAL", "source": "firewall",        "message": "SQL injection attempt detected from IP 10.0.0.99"},
    {"level": "CRITICAL", "source": "auth-service",    "message": "Brute force login: 50 failed attempts in 60s from 203.0.113.5"},
    {"level": "INFO",     "source": "scheduler",       "message": "Cron job backup_db completed in 12.3s"},
    {"level": "ERROR",    "source": "payment-service", "message": "Payment gateway timeout — transaction rolled back"},
    {"level": "WARN",     "source": "storage",         "message": "Disk usage at 87% on /var/data"},
    {"level": "CRITICAL", "source": "network",         "message": "Port scan detected from 198.51.100.42 — 1024 ports in 5s"},
    {"level": "INFO",     "source": "app-service",     "message": "Deployed version 2.3.1 to production"},
]

@app.on_event("startup")
async def startup():
    await asyncio.sleep(2)
    try:
        client = get_qdrant()
        points = []
        for i, l in enumerate(SAMPLE_LOGS):
            text = f"[{l['level']}] {l['source']}: {l['message']}"
            vec  = embed_text(text)
            classification = _classify_local(l["level"], l["message"])
            points.append(PointStruct(
                id=str(uuid.uuid4()),
                vector=vec,
                payload={**l, "text": text, "classification": classification,
                         "timestamp": datetime.utcnow().isoformat(), "indexed": True}
            ))
        client.upsert(collection_name=COLLECTION, points=points)
        log.info(f"Seeded {len(points)} sample logs into Qdrant")
    except Exception as e:
        log.error(f"Startup seed failed: {e}")

# ─── Helpers ─────────────────────────────────────────────────────────────────
def _classify_local(level: str, message: str) -> str:
    msg = message.lower()
    malicious_kw = ["injection", "brute force", "port scan", "exploit", "payload", "malware", "ransomware"]
    deny_kw = ["timeout", "failed", "error", "denied", "refused", "rejected"]
    if any(k in msg for k in malicious_kw) or level == "CRITICAL":
        return "malicious"
    elif any(k in msg for k in deny_kw) or level == "ERROR":
        return "deny"
    else:
        return "allowed"

# ─── Endpoints ───────────────────────────────────────────────────────────────
@app.get("/health")
def health():
    return {"status": "ok", "service": "agents", "timestamp": datetime.utcnow().isoformat()}

@app.post("/ingest")
async def ingest_log(event: LogEvent):
    """Receive log from NiFi, embed, classify, store in Qdrant."""
    text = f"[{event.level}] {event.source}: {event.message}"
    vec  = embed_text(text)
    classification = _classify_local(event.level or "INFO", event.message)
    point = PointStruct(
        id=str(uuid.uuid4()),
        vector=vec,
        payload={
            "timestamp": event.timestamp or datetime.utcnow().isoformat(),
            "level": event.level,
            "source": event.source,
            "message": event.message,
            "text": text,
            "classification": classification,
            "metadata": event.metadata,
        }
    )
    get_qdrant().upsert(collection_name=COLLECTION, points=[point])
    return {"status": "indexed", "classification": classification, "id": point.id}

@app.post("/agent/classify")
async def classify_agent(req: AgentRequest):
    """Log Classification Agent — labels log as allowed/deny/malicious."""
    try:
        data = json.loads(req.log_data)
        level = data.get("level", "INFO")
        message = data.get("message", req.log_data)
    except Exception:
        level, message = "INFO", req.log_data

    classification = _classify_local(level, message)
    prompt = (
        f"You are a security log classifier. Classify this log entry as 'allowed', 'deny', or 'malicious'.\n"
        f"Log: [{level}] {message}\n"
        f"Quick assessment: {classification}\n"
        f"Provide a one-sentence explanation."
    )
    explanation = await llm_generate(prompt)
    return {"classification": classification, "explanation": explanation, "level": level}

@app.post("/agent/threat")
async def threat_agent(req: AgentRequest):
    """Threat Detection Agent — deep analysis of malicious/critical logs."""
    prompt = (
        f"You are a cybersecurity threat detection expert.\n"
        f"Analyze this log for threats, attack vectors, and recommended actions:\n\n"
        f"{req.log_data}\n\n"
        f"Respond with: threat_type, severity (1-10), attack_vector, recommended_action."
    )
    analysis = await llm_generate(prompt)

    # Also do RAG — find similar past threats
    vec = embed_text(req.log_data)
    hits = get_qdrant().search(
        collection_name=COLLECTION,
        query_vector=vec,
        query_filter=Filter(must=[FieldCondition(key="classification", match=MatchValue(value="malicious"))]),
        limit=3
    )
    similar = [h.payload.get("message", "") for h in hits]
    return {"agent": "threat_detection", "analysis": analysis, "similar_threats": similar}

@app.post("/agent/alert")
async def alert_agent(req: AgentRequest):
    """Alert Agent — handles error/deny logs, suggests remediation."""
    prompt = (
        f"You are an operations alert handler.\n"
        f"This log indicates a problem. Provide: root_cause_hypothesis, impact_assessment, immediate_action.\n\n"
        f"Log: {req.log_data}"
    )
    analysis = await llm_generate(prompt)
    return {"agent": "alert", "analysis": analysis, "priority": "high"}

@app.post("/agent/summary")
async def summary_agent(req: AgentRequest):
    """Summary Agent — produces human-readable summary of normal logs."""
    prompt = (
        f"Summarize this log event in one clear sentence for an operations dashboard:\n{req.log_data}"
    )
    summary = await llm_generate(prompt)
    return {"agent": "summary", "summary": summary}

@app.post("/query")
async def rag_query(req: QueryRequest):
    """RAG query — semantic search over stored logs + LLM synthesis."""
    vec  = embed_text(req.query)
    hits = get_qdrant().search(collection_name=COLLECTION, query_vector=vec, limit=req.top_k)
    context = "\n".join([f"- {h.payload.get('text', '')}" for h in hits])
    prompt = (
        f"Based on these log entries:\n{context}\n\n"
        f"Answer this question: {req.query}\n"
        f"Be concise and specific."
    )
    answer = await llm_generate(prompt)
    sources = [{"text": h.payload.get("text"), "score": h.score,
                "classification": h.payload.get("classification")} for h in hits]
    return {"answer": answer, "sources": sources}

@app.get("/logs/recent")
def recent_logs(limit: int = 20):
    """Return recent logs from Qdrant for dashboard."""
    results = get_qdrant().scroll(collection_name=COLLECTION, limit=limit, with_payload=True, with_vectors=False)
    logs = [p.payload for p in results[0]]
    return {"logs": logs, "count": len(logs)}

@app.get("/stats")
def stats():
    """Aggregate stats for dashboard."""
    client = get_qdrant()
    total = client.count(collection_name=COLLECTION).count
    def count_class(cls):
        return client.count(
            collection_name=COLLECTION,
            count_filter=Filter(must=[FieldCondition(key="classification", match=MatchValue(value=cls))])
        ).count
    return {
        "total_logs": total,
        "malicious": count_class("malicious"),
        "deny": count_class("deny"),
        "allowed": count_class("allowed"),
        "collection": COLLECTION,
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
