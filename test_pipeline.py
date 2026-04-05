"""
Test suite for Agentic Log Pipeline
Run: pytest tests/ -v
"""

import json
import pytest
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch


# ─── Agent definitions tests ──────────────────────────────────────────────────
class TestRuleClassify:
    """Unit tests for deterministic rule-based classifier."""

    def _classify(self, level, message):
        from agents.agent_definitions import _rule_classify
        return _rule_classify(level, message)

    def test_sql_injection_is_malicious(self):
        cls, sev = self._classify("ERROR", "SQL injection attempt detected from 10.0.0.1")
        assert cls == "malicious"
        assert sev >= 8

    def test_brute_force_is_malicious(self):
        cls, sev = self._classify("WARN", "brute force login: 50 failed attempts")
        assert cls == "malicious"

    def test_critical_level_is_malicious(self):
        cls, sev = self._classify("CRITICAL", "disk full")
        assert cls == "malicious"
        assert sev >= 8

    def test_connection_timeout_is_deny(self):
        cls, sev = self._classify("ERROR", "connection timeout after 30s")
        assert cls == "deny"
        assert 4 <= sev <= 8

    def test_error_level_is_deny(self):
        cls, sev = self._classify("ERROR", "payment gateway unreachable")
        assert cls == "deny"

    def test_warn_level_is_deny(self):
        cls, sev = self._classify("WARN", "disk usage at 87%")
        assert cls == "deny"
        assert sev <= 4

    def test_info_login_is_allowed(self):
        cls, sev = self._classify("INFO", "User admin logged in successfully")
        assert cls == "allowed"
        assert sev == 1

    def test_info_deploy_is_allowed(self):
        cls, sev = self._classify("INFO", "Deployed version 2.3.1 to production")
        assert cls == "allowed"


class TestLogClassificationAgent:
    """Tests for the LLM classification agent."""

    @pytest.mark.asyncio
    async def test_classify_malicious_log(self):
        from agents.agent_definitions import LogClassificationAgent
        agent = LogClassificationAgent()

        with patch.object(agent, "_llm", return_value="This is a SQL injection attempt."):
            result = await agent.run({
                "level": "CRITICAL",
                "source": "firewall",
                "message": "SQL injection attempt from 10.0.0.1"
            })

        assert result.agent == "log_classification"
        assert result.classification == "malicious"
        assert result.severity >= 8
        assert result.analysis is not None

    @pytest.mark.asyncio
    async def test_classify_normal_log(self):
        from agents.agent_definitions import LogClassificationAgent
        agent = LogClassificationAgent()

        with patch.object(agent, "_llm", return_value="Normal operational log."):
            result = await agent.run({
                "level": "INFO",
                "source": "app",
                "message": "Cache warmed up successfully"
            })

        assert result.classification == "allowed"
        assert result.severity == 1

    @pytest.mark.asyncio
    async def test_result_has_required_fields(self):
        from agents.agent_definitions import LogClassificationAgent
        agent = LogClassificationAgent()

        with patch.object(agent, "_llm", return_value="Analysis."):
            result = await agent.run({"level": "INFO", "message": "test"})

        assert result.agent == "log_classification"
        assert result.classification in ("allowed", "deny", "malicious")
        assert isinstance(result.severity, int)
        d = result.to_dict()
        assert "agent" in d
        assert "classification" in d


class TestThreatDetectionAgent:
    """Tests for the threat detection agent."""

    @pytest.mark.asyncio
    async def test_threat_agent_runs(self):
        from agents.agent_definitions import ThreatDetectionAgent
        agent = ThreatDetectionAgent()

        with patch.object(agent, "_llm", return_value="threat_type: Port Scan\nseverity: 8\nattack_vector: network\nrecommended_action: Block IP immediately."):
            result = await agent.run({
                "level": "CRITICAL",
                "source": "network",
                "message": "Port scan from 198.51.100.42"
            })

        assert result.agent == "threat_detection"
        assert result.classification == "malicious"
        assert result.severity == 8

    @pytest.mark.asyncio
    async def test_threat_agent_with_qdrant(self):
        from agents.agent_definitions import ThreatDetectionAgent

        mock_qdrant = MagicMock()
        mock_hit = MagicMock()
        mock_hit.score = 0.9
        mock_hit.payload = {"message": "Previous port scan from 10.0.0.5"}
        mock_qdrant.search.return_value = [mock_hit]

        embed_fn = lambda x: [0.0] * 384

        agent = ThreatDetectionAgent(qdrant_client=mock_qdrant, embed_fn=embed_fn)

        with patch.object(agent, "_llm", return_value="severity: 9"):
            result = await agent.run({
                "level": "CRITICAL",
                "source": "firewall",
                "message": "Exploit payload detected"
            })

        assert len(result.similar_events) == 1
        assert "port scan" in result.similar_events[0].lower()


class TestSummaryAgent:
    """Tests for the summary / alert agent."""

    @pytest.mark.asyncio
    async def test_summary_for_info_log(self):
        from agents.agent_definitions import SummaryAgent
        agent = SummaryAgent()

        with patch.object(agent, "_llm", return_value="Backup completed in 12 seconds."):
            result = await agent.run({
                "level": "INFO",
                "source": "scheduler",
                "message": "Cron job backup_db completed"
            })

        assert result.agent == "summary"
        assert result.summary == "Backup completed in 12 seconds."

    @pytest.mark.asyncio
    async def test_alert_for_error_log(self):
        from agents.agent_definitions import SummaryAgent
        agent = SummaryAgent()

        with patch.object(agent, "_llm", return_value="root_cause: DB overloaded"):
            result = await agent.run({
                "level": "ERROR",
                "source": "db",
                "message": "connection timeout"
            })

        assert result.agent == "alert"
        assert result.classification == "deny"

    @pytest.mark.asyncio
    async def test_to_dict_excludes_none(self):
        from agents.agent_definitions import SummaryAgent
        agent = SummaryAgent()

        with patch.object(agent, "_llm", return_value="Summary text"):
            result = await agent.run({"level": "INFO", "message": "startup complete"})

        d = result.to_dict()
        assert None not in d.values()


class TestAgentFactory:
    def test_create_agents_returns_all_three(self):
        from agents.agent_definitions import create_agents
        agents = create_agents()
        assert "classify" in agents
        assert "threat"   in agents
        assert "summary"  in agents

    def test_agents_have_correct_types(self):
        from agents.agent_definitions import (
            create_agents, LogClassificationAgent,
            ThreatDetectionAgent, SummaryAgent
        )
        agents = create_agents()
        assert isinstance(agents["classify"], LogClassificationAgent)
        assert isinstance(agents["threat"],   ThreatDetectionAgent)
        assert isinstance(agents["summary"],  SummaryAgent)


# ─── n8n workflow validation ──────────────────────────────────────────────────
class TestN8nWorkflow:
    def _load_workflow(self):
        with open("n8n/workflow.json") as f:
            return json.load(f)

    def test_workflow_has_required_keys(self):
        wf = self._load_workflow()
        assert "name" in wf
        assert "nodes" in wf
        assert "connections" in wf

    def test_workflow_has_webhook_trigger(self):
        wf = self._load_workflow()
        types = [n["type"] for n in wf["nodes"]]
        assert "n8n-nodes-base.webhook" in types

    def test_workflow_has_three_agent_calls(self):
        wf = self._load_workflow()
        http_nodes = [n for n in wf["nodes"] if n["type"] == "n8n-nodes-base.httpRequest"]
        assert len(http_nodes) >= 3

    def test_agent_urls_point_to_agents_service(self):
        wf = self._load_workflow()
        for node in wf["nodes"]:
            if node["type"] == "n8n-nodes-base.httpRequest":
                url = node["parameters"].get("url", "")
                assert "agents:8000" in url, f"Node {node['name']} URL doesn't point to agents service"

    def test_workflow_is_active(self):
        wf = self._load_workflow()
        assert wf.get("active") is True


# ─── docker-compose validation ────────────────────────────────────────────────
class TestDockerCompose:
    def _load_compose(self):
        import yaml  # pyyaml
        with open("docker-compose.yml") as f:
            return yaml.safe_load(f)

    def test_all_required_services_present(self):
        try:
            compose = self._load_compose()
        except ImportError:
            pytest.skip("pyyaml not installed")
        services = compose["services"]
        required = ["qdrant", "nifi", "n8n", "ollama", "agents", "dashboard", "bootstrap"]
        for svc in required:
            assert svc in services, f"Missing service: {svc}"

    def test_all_services_on_same_network(self):
        try:
            compose = self._load_compose()
        except ImportError:
            pytest.skip("pyyaml not installed")
        for name, svc in compose["services"].items():
            nets = svc.get("networks", [])
            if isinstance(nets, list):
                assert "pipeline_net" in nets, f"{name} not on pipeline_net"
            elif isinstance(nets, dict):
                assert "pipeline_net" in nets, f"{name} not on pipeline_net"

    def test_qdrant_has_healthcheck(self):
        try:
            compose = self._load_compose()
        except ImportError:
            pytest.skip("pyyaml not installed")
        assert "healthcheck" in compose["services"]["qdrant"]

    def test_bootstrap_depends_on_healthy_services(self):
        try:
            compose = self._load_compose()
        except ImportError:
            pytest.skip("pyyaml not installed")
        deps = compose["services"]["bootstrap"].get("depends_on", {})
        assert "qdrant" in deps
        assert "n8n"    in deps
        assert "ollama" in deps


# ─── NiFi template validation ─────────────────────────────────────────────────
class TestNifiTemplate:
    def _load_template(self):
        with open("nifi/flow_template.json") as f:
            return json.load(f)

    def test_template_has_flow_contents(self):
        t = self._load_template()
        assert "flowContents" in t

    def test_template_has_two_processors(self):
        t = self._load_template()
        procs = t["flowContents"]["processors"]
        assert len(procs) == 2

    def test_generator_sends_to_agents(self):
        t = self._load_template()
        http_proc = next(
            p for p in t["flowContents"]["processors"]
            if "HTTP" in p["type"] or "InvokeHTTP" in p["type"]
        )
        url = http_proc["config"]["properties"].get("Remote URL", "")
        assert "agents:8000/ingest" in url

    def test_connection_links_processors(self):
        t = self._load_template()
        conns = t["flowContents"]["connections"]
        assert len(conns) >= 1
        assert conns[0]["selectedRelationships"] == ["success"]
