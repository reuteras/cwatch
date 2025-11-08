"""Shared test fixtures for cwatch tests."""
import sqlite3
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_db():
    """Create a temporary database file."""
    with tempfile.NamedTemporaryFile(delete=False, suffix=".db") as tmp:
        db_path = tmp.name
    yield db_path
    # Cleanup
    Path(db_path).unlink(missing_ok=True)


@pytest.fixture
def sample_config(temp_db):
    """Create a sample configuration dictionary."""
    return {
        "cwatch": {
            "DB_FILE": temp_db,
            "quiet": False,
            "report": True,
            "simple": False,
            "verbose": False,
            "header": "Test Report",
            "footer": "End of Report",
            "ignore_engines": ["urlhaus"],
            "ignore_engines_partly": [["virustotal", "last_analysis_date"]],
        },
        "cyberbro": {
            "url": "http://localhost:8000",
            "engines": ["abuseipdb", "shodan", "virustotal", "threatfox"],
        },
        "iocs": {
            "domains": ["example.com", "8.8.8.8"],
        },
    }


@pytest.fixture
def sample_json_response():
    """Create a sample JSON response from cyberbro."""
    return [
        {
            "abuseipdb": {
                "reports": 0,
                "risk_score": 0,
            },
            "shodan": {
                "link": "https://www.shodan.io/host/8.8.8.8",
                "open_ports": [53, 443],
            },
            "virustotal": {
                "community_score": 0,
                "total_malicious": 0,
                "last_analysis_date": "2024-01-01",
            },
            "threatfox": {
                "count": 0,
                "malware_printable": [],
            },
        }
    ]


@pytest.fixture
def initialized_db(sample_config):
    """Create and initialize a test database."""
    conn = sqlite3.connect(sample_config["cwatch"]["DB_FILE"])
    cursor = conn.cursor()
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS json_data (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            json_hash TEXT NOT NULL,
            json_content TEXT NOT NULL
        )
    """
    )
    conn.commit()
    conn.close()
    return sample_config["cwatch"]["DB_FILE"]
