# 🛡️ Agentic Log Pipeline

A fully automated, 7-layer agentic log processing pipeline. **Zero manual UI setup required** — everything is scripted and auto-configured.

```
Layer 7 │ Streamlit Dashboard      → http://localhost:8501
Layer 6 │ n8n Orchestration        → http://localhost:5678
Layer 5 │ LlamaIndex + 3 Agents    → http://localhost:8000/docs
Layer 4 │ Ollama (Mistral LLM)     → http://localhost:11434
Layer 3 │ Qdrant Vector DB         → http://localhost:6333/dashboard
Layer 2 │ Apache NiFi (Ingestion)  → http://localhost:8080/nifi
Layer 1 │ Docker Infrastructure
```

## ⚡ One-command startup

```bash
make up
```

All services are **auto-configured** — no manual UI steps.

## ✅ What gets auto-configured

| Tool | Auto-configuration |
|------|-------------------|
| **Qdrant** | Creates `logs_collection` (384-dim Cosine), seeds 10 sample logs |
| **Ollama** | Pulls `mistral` model on first boot |
| **n8n** | Imports + activates routing workflow via REST API |
| **NiFi** | Flow template imported via NiFi REST API |
| **Agents** | 3 pre-wired agents (Classify, Threat, Alert/Summary) start automatically |
| **Dashboard** | Streamlit auto-starts, auto-connects to agents API |

## 🤖 Agents

### 1. Log Classification Agent (`/agent/classify`)
- Labels every log as `allowed` / `deny` / `malicious`
- Uses keyword heuristics + LLM explanation

### 2. Threat Detection Agent (`/agent/threat`)
- Deep analysis of malicious/critical logs
- RAG: finds similar past threats in Qdrant
- Returns: threat_type, severity, attack_vector, recommended_action

### 3. Summary/Alert Agent (`/agent/summary` & `/agent/alert`)
- Summary Agent: human-readable summary for normal logs
- Alert Agent: root cause + remediation for errors

## 🔀 n8n Routing Logic

```
Webhook → Classify & Route
              ├── malicious / CRITICAL → Threat Detection Agent
              ├── deny / ERROR         → Alert Agent
              └── allowed              → Summary Agent
```

## 📡 API Endpoints

```
GET  /health           Health check
GET  /stats            Log counts by classification
GET  /logs/recent      Latest logs from Qdrant
POST /ingest           Ingest a log event (from NiFi)
POST /agent/classify   Classify a log
POST /agent/threat     Threat analysis
POST /agent/alert      Alert/remediation
POST /agent/summary    Summarize a log
POST /query            RAG semantic search
```

## 🧪 Testing

```bash
# Check service status
make status

# Test agents API
make test-agents

# Send a test event through n8n workflow
make test-event

# View all logs
make logs
```

## 🛑 Teardown

```bash
make down        # Stop services
make clean       # Stop + remove volumes
```

## Architecture

```
                    ┌─────────────────────────────────┐
                    │  Layer 7: Streamlit Dashboard    │
                    └─────────────┬───────────────────┘
                                  │
                    ┌─────────────▼───────────────────┐
                    │  Layer 6: n8n Orchestration      │
                    │  (webhook → route → agent)       │
                    └──────┬──────────┬───────┬────────┘
                           │          │       │
               ┌───────────▼┐  ┌──────▼─┐  ┌─▼────────┐
               │  Threat    │  │ Alert  │  │ Summary  │
               │  Agent     │  │ Agent  │  │  Agent   │
               └───────────┬┘  └──────┬─┘  └─┬────────┘
                           └──────────┴───────┘
                                      │  Layer 5: LlamaIndex RAG
                    ┌─────────────────▼───────────────┐
                    │  Layer 4: Ollama (Mistral LLM)  │
                    └─────────────────────────────────┘
                    ┌─────────────────────────────────┐
                    │  Layer 3: Qdrant Vector DB       │
                    │  (logs_collection, 384-dim)      │
                    └─────────────────────────────────┘
                    ┌─────────────────────────────────┐
                    │  Layer 2: Apache NiFi            │
                    │  (GenerateFlowFile → HTTP POST)  │
                    └─────────────────────────────────┘
                    ┌─────────────────────────────────┐
                    │  Layer 1: Docker Compose         │
                    └─────────────────────────────────┘
```

## 🚀 Deployment Notes
- Restart-safe: all services use `restart: unless-stopped`
- Volumes persist across restarts (qdrant_storage, ollama_models, n8n_data)
- Bootstrap container runs once and exits cleanly
