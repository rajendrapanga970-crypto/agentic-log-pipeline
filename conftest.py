"""Shared pytest fixtures."""
import sys
import os
import pytest

# Make agents/ importable from project root
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "agents"))


@pytest.fixture
def sample_log_allowed():
    return {"level": "INFO", "source": "app-service", "message": "Service started on port 8080"}

@pytest.fixture
def sample_log_deny():
    return {"level": "ERROR", "source": "db-service", "message": "Connection timeout after 30s"}

@pytest.fixture
def sample_log_malicious():
    return {"level": "CRITICAL", "source": "firewall", "message": "SQL injection attempt from 10.0.0.1"}

@pytest.fixture
def all_sample_logs(sample_log_allowed, sample_log_deny, sample_log_malicious):
    return [sample_log_allowed, sample_log_deny, sample_log_malicious]
