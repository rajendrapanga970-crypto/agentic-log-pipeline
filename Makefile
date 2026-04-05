.PHONY: up down restart logs status clean

## Start the full pipeline (build + run)
up:
	docker compose up --build -d
	@echo ""
	@echo "╔══════════════════════════════════════════════╗"
	@echo "║   AGENTIC LOG PIPELINE — STARTING UP         ║"
	@echo "╠══════════════════════════════════════════════╣"
	@echo "║  Dashboard  → http://localhost:8501          ║"
	@echo "║  Agents API → http://localhost:8000/docs     ║"
	@echo "║  n8n        → http://localhost:5678          ║"
	@echo "║  NiFi       → http://localhost:8080/nifi     ║"
	@echo "║  Qdrant     → http://localhost:6333/dashboard║"
	@echo "║  Ollama     → http://localhost:11434         ║"
	@echo "╚══════════════════════════════════════════════╝"
	@echo ""

## Stop all services
down:
	docker compose down

## Restart all services
restart:
	docker compose down && docker compose up --build -d

## View logs
logs:
	docker compose logs -f

## Show service status
status:
	docker compose ps

## Remove everything including volumes
clean:
	docker compose down -v --remove-orphans

## Bootstrap only (re-run config)
bootstrap:
	docker compose run --rm bootstrap

## Send a test log event to n8n webhook
test-event:
	curl -X POST http://localhost:5678/webhook/log-event \
	  -H "Content-Type: application/json" \
	  -d '{"level":"ERROR","source":"test","message":"Connection refused on port 5432","classification":"deny"}'

## Test the agents API
test-agents:
	@echo "=== Health ==="
	curl -s http://localhost:8000/health | python3 -m json.tool
	@echo "\n=== Stats ==="
	curl -s http://localhost:8000/stats | python3 -m json.tool
	@echo "\n=== Classify ==="
	curl -s -X POST http://localhost:8000/agent/classify \
	  -H "Content-Type: application/json" \
	  -d '{"log_data":"{\"level\":\"CRITICAL\",\"message\":\"SQL injection attempt detected\"}"}' \
	  | python3 -m json.tool
