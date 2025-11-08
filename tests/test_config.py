"""Tests for configuration loading."""

import tomllib

import pytest

from cwatch.cw import main


@pytest.mark.unit
def test_config_file_not_found(monkeypatch, tmp_path):
    """Test that missing config file raises appropriate error."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["cwatch"])

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1


@pytest.mark.unit
def test_config_invalid_toml(monkeypatch, tmp_path):
    """Test that invalid TOML raises appropriate error."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("sys.argv", ["cwatch"])

    # Create invalid TOML
    config_file = tmp_path / "cwatch.toml"
    config_file.write_text("invalid toml content [[[")

    with pytest.raises(SystemExit) as exc_info:
        main()

    assert exc_info.value.code == 1


@pytest.mark.unit
def test_config_valid_toml(tmp_path):
    """Test that valid TOML can be loaded."""
    config_file = tmp_path / "cwatch.toml"
    config_content = """
[cwatch]
DB_FILE = "test.db"
quiet = false
report = true
simple = false
verbose = false
header = "Test"
footer = "End"
ignore_engines = []
ignore_engines_partly = []

[cyberbro]
url = "http://localhost:8000"
engines = ["abuseipdb"]

[iocs]
domains = []
"""
    config_file.write_text(config_content)

    # Load and verify
    with open(config_file, "rb") as f:
        config = tomllib.load(f)

    assert "cwatch" in config
    assert "cyberbro" in config
    assert "iocs" in config
    assert config["cwatch"]["DB_FILE"] == "test.db"
