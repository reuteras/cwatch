"""Tests for database operations."""
import json
import sqlite3

import pytest

from cwatch.cw import (
    calculate_hash,
    detect_changes,
    save_json_data,
    setup_database,
)


@pytest.mark.unit
def test_setup_database(sample_config):
    """Test database setup creates proper schema."""
    assert setup_database(sample_config)

    # Verify table was created
    conn = sqlite3.connect(sample_config["cwatch"]["DB_FILE"])
    cursor = conn.cursor()
    cursor.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='json_data'"
    )
    result = cursor.fetchone()
    conn.close()

    assert result is not None
    assert result[0] == "json_data"


@pytest.mark.unit
def test_setup_database_invalid_path():
    """Test database setup with invalid path."""
    config = {"cwatch": {"DB_FILE": "/invalid/path/db.db"}}
    assert not setup_database(config)


@pytest.mark.unit
def test_calculate_hash():
    """Test hash calculation for JSON data."""
    data1 = {"key": "value", "number": 42}
    data2 = {"number": 42, "key": "value"}  # Same data, different order
    data3 = {"key": "different", "number": 42}

    hash1 = calculate_hash(data1)
    hash2 = calculate_hash(data2)
    hash3 = calculate_hash(data3)

    # Same data should produce same hash regardless of order
    assert hash1 == hash2
    # Different data should produce different hash
    assert hash1 != hash3


@pytest.mark.unit
def test_save_json_data(sample_config, initialized_db, sample_json_response):
    """Test saving JSON data to database."""
    assert save_json_data(sample_config, "test.example.com", sample_json_response)

    # Verify data was saved
    conn = sqlite3.connect(sample_config["cwatch"]["DB_FILE"])
    cursor = conn.cursor()
    cursor.execute("SELECT target, json_content FROM json_data WHERE target = ?", ("test.example.com",))
    result = cursor.fetchone()
    conn.close()

    assert result is not None
    assert result[0] == "test.example.com"
    assert json.loads(result[1]) == sample_json_response


@pytest.mark.unit
def test_save_json_data_invalid_db():
    """Test save_json_data with invalid database."""
    config = {"cwatch": {"DB_FILE": "/invalid/path/db.db"}}
    assert not save_json_data(config, "test.com", [{}])


@pytest.mark.unit
def test_detect_changes_insufficient_data(sample_config, initialized_db, sample_json_response):
    """Test change detection with only one entry."""
    save_json_data(sample_config, "test.com", sample_json_response)

    # Should return False (no changes) when there's only one entry
    result = detect_changes(sample_config, "test.com")
    assert result is False


@pytest.mark.unit
def test_detect_changes_no_changes(sample_config, initialized_db, sample_json_response):
    """Test change detection when data hasn't changed."""
    # Save same data twice
    save_json_data(sample_config, "test.com", sample_json_response)
    save_json_data(sample_config, "test.com", sample_json_response)

    result = detect_changes(sample_config, "test.com")
    assert result is False


@pytest.mark.unit
def test_detect_changes_with_changes(sample_config, initialized_db, sample_json_response, capsys):
    """Test change detection when data has changed."""
    # Save initial data
    save_json_data(sample_config, "test.com", sample_json_response)

    # Modify and save again
    modified_response = sample_json_response.copy()
    modified_response[0]["abuseipdb"]["reports"] = 5
    modified_response[0]["abuseipdb"]["risk_score"] = 50
    save_json_data(sample_config, "test.com", modified_response)

    result = detect_changes(sample_config, "test.com")
    captured = capsys.readouterr()

    assert result is True
    assert "Changes detected" in captured.out
    assert "abuseipdb" in captured.out


@pytest.mark.unit
def test_detect_changes_invalid_db():
    """Test detect_changes with invalid database."""
    config = {"cwatch": {"DB_FILE": "/invalid/path/db.db", "quiet": False}}
    result = detect_changes(config, "test.com")
    assert result is False
