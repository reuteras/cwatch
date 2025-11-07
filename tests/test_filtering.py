"""Tests for change filtering logic."""
import pytest

from cwatch.cw import (
    handle_abuseipdb,
    handle_changes,
    handle_shodan,
    handle_threatfox,
    handle_virustotal,
)


@pytest.mark.unit
def test_handle_abuseipdb_no_reports():
    """Test filtering abuseipdb with no reports."""
    change = {
        "abuseipdb": {
            "reports": 0,
            "risk_score": 0,
        }
    }

    result = handle_abuseipdb(change)

    assert "abuseipdb" not in result


@pytest.mark.unit
def test_handle_abuseipdb_with_reports():
    """Test keeping abuseipdb with reports."""
    change = {
        "abuseipdb": {
            "reports": 5,
            "risk_score": 50,
        }
    }

    result = handle_abuseipdb(change)

    assert "abuseipdb" in result
    assert result["abuseipdb"]["reports"] == 5


@pytest.mark.unit
def test_handle_abuseipdb_list_format():
    """Test filtering abuseipdb in list format."""
    change = {
        "abuseipdb": [
            {"old": "value"},
            {"reports": 0, "risk_score": 0}
        ]
    }

    result = handle_abuseipdb(change)

    assert "abuseipdb" not in result


@pytest.mark.unit
def test_handle_abuseipdb_list_with_reports():
    """Test keeping abuseipdb list with reports."""
    change = {
        "abuseipdb": [
            {"reports": 0, "risk_score": 0},
            {"reports": 5, "risk_score": 50}
        ]
    }

    result = handle_abuseipdb(change)

    assert "abuseipdb" in result


@pytest.mark.unit
def test_handle_shodan_no_link():
    """Test filtering shodan without link."""
    change = {
        "shodan": {
            "data": "some_data"
        }
    }

    result = handle_shodan(change)

    assert "shodan" not in result


@pytest.mark.unit
def test_handle_shodan_with_link():
    """Test keeping shodan with link."""
    change = {
        "shodan": {
            "link": "https://www.shodan.io/host/1.2.3.4",
            "data": "some_data"
        }
    }

    result = handle_shodan(change)

    assert "shodan" in result
    assert result["shodan"]["link"] == "https://www.shodan.io/host/1.2.3.4"


@pytest.mark.unit
def test_handle_threatfox_no_matches():
    """Test filtering threatfox with no matches."""
    change = {
        "threatfox": {
            "count": 0,
            "malware_printable": []
        }
    }

    result = handle_threatfox(change)

    assert "threatfox" not in result


@pytest.mark.unit
def test_handle_threatfox_with_matches():
    """Test keeping threatfox with matches."""
    change = {
        "threatfox": {
            "count": 1,
            "malware_printable": ["malware1"]
        }
    }

    result = handle_threatfox(change)

    assert "threatfox" in result


@pytest.mark.unit
def test_handle_threatfox_null():
    """Test filtering threatfox with null value."""
    change = {
        "threatfox": None
    }

    result = handle_threatfox(change)

    assert "threatfox" not in result


@pytest.mark.unit
def test_handle_threatfox_list_format():
    """Test filtering threatfox in list format."""
    change = {
        "threatfox": [
            {"old": "value"},
            {"count": 0, "malware_printable": []}
        ]
    }

    result = handle_threatfox(change)

    assert "threatfox" not in result


@pytest.mark.unit
def test_handle_virustotal_no_threats():
    """Test filtering virustotal with no threats."""
    change = {
        "virustotal": {
            "community_score": 0,
            "total_malicious": 0
        }
    }

    result = handle_virustotal(change)

    assert "virustotal" not in result


@pytest.mark.unit
def test_handle_virustotal_with_threats():
    """Test keeping virustotal with threats."""
    change = {
        "virustotal": {
            "community_score": -5,
            "total_malicious": 3
        }
    }

    result = handle_virustotal(change)

    assert "virustotal" in result


@pytest.mark.unit
def test_handle_virustotal_null():
    """Test filtering virustotal with null value."""
    change = {
        "virustotal": [
            {"old": "value"},
            None
        ]
    }

    result = handle_virustotal(change)

    assert "virustotal" not in result


@pytest.mark.unit
def test_handle_changes_quiet_mode_no_changes(sample_config):
    """Test handle_changes in quiet mode with no significant changes."""
    sample_config["cwatch"]["quiet"] = True

    changes = {
        "abuseipdb": {"reports": 0, "risk_score": 0},
        "virustotal": {"community_score": 0, "total_malicious": 0}
    }

    result = handle_changes(sample_config, "test.com", changes)

    assert result is False


@pytest.mark.unit
def test_handle_changes_quiet_mode_with_changes(sample_config, capsys):
    """Test handle_changes in quiet mode with significant changes."""
    sample_config["cwatch"]["quiet"] = True

    changes = {
        "abuseipdb": {"reports": 5, "risk_score": 50}
    }

    result = handle_changes(sample_config, "test.com", changes)
    captured = capsys.readouterr()

    assert result is True
    assert "Changes detected" in captured.out
    assert "test.com" in captured.out


@pytest.mark.unit
def test_handle_changes_verbose_mode(sample_config, capsys):
    """Test handle_changes in verbose mode."""
    sample_config["cwatch"]["quiet"] = False

    changes = {
        "shodan": {"link": "https://shodan.io/test"}
    }

    result = handle_changes(sample_config, "test.com", changes)
    captured = capsys.readouterr()

    assert result is True
    assert "Changes detected" in captured.out


@pytest.mark.unit
def test_handle_changes_mixed_engines(sample_config, capsys):
    """Test handle_changes with multiple engines in quiet mode."""
    sample_config["cwatch"]["quiet"] = True

    changes = {
        "abuseipdb": {"reports": 0, "risk_score": 0},  # Should be filtered
        "shodan": {"link": "https://shodan.io/test"},   # Should remain
        "threatfox": None                                # Should be filtered
    }

    result = handle_changes(sample_config, "test.com", changes)
    captured = capsys.readouterr()

    assert result is True
    assert "shodan" in captured.out
