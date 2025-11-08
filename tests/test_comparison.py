"""Tests for JSON comparison logic."""
import pytest

from cwatch.cw import compare_json


@pytest.mark.unit
def test_compare_json_no_changes(sample_config):
    """Test JSON comparison with identical data."""
    old = {
        "abuseipdb": {"reports": 0},
        "shodan": {"link": "test"}
    }
    new = {
        "abuseipdb": {"reports": 0},
        "shodan": {"link": "test"}
    }

    result = compare_json(sample_config, old, new)

    assert result == {}


@pytest.mark.unit
def test_compare_json_with_changes(sample_config):
    """Test JSON comparison with changes."""
    old = {
        "abuseipdb": {"reports": 0},
        "shodan": {"link": "test"}
    }
    new = {
        "abuseipdb": {"reports": 5},
        "shodan": {"link": "test"}
    }

    result = compare_json(sample_config, old, new)

    assert "abuseipdb" in result
    assert "shodan" not in result


@pytest.mark.unit
def test_compare_json_ignore_engines(sample_config):
    """Test JSON comparison with ignored engines."""
    sample_config["cwatch"]["ignore_engines"] = ["urlhaus"]

    old = {
        "abuseipdb": {"reports": 0},
        "urlhaus": {"count": 0}
    }
    new = {
        "abuseipdb": {"reports": 5},
        "urlhaus": {"count": 10}
    }

    result = compare_json(sample_config, old, new)

    assert "abuseipdb" in result
    assert "urlhaus" not in result


@pytest.mark.unit
def test_compare_json_ignore_engines_partly(sample_config):
    """Test JSON comparison with partially ignored engines."""
    sample_config["cwatch"]["ignore_engines_partly"] = [["virustotal", "last_analysis_date"]]

    old = {
        "virustotal": {
            "total_malicious": 0,
            "last_analysis_date": "2024-01-01"
        }
    }
    new = {
        "virustotal": {
            "total_malicious": 0,
            "last_analysis_date": "2024-01-02"
        }
    }

    result = compare_json(sample_config, old, new)

    # Should not report change since only ignored field changed
    assert result == {}


@pytest.mark.unit
def test_compare_json_ignore_partly_with_other_changes(sample_config):
    """Test partial ignore when other fields also change."""
    sample_config["cwatch"]["ignore_engines_partly"] = [["virustotal", "last_analysis_date"]]

    old = {
        "virustotal": {
            "total_malicious": 0,
            "last_analysis_date": "2024-01-01"
        }
    }
    new = {
        "virustotal": {
            "total_malicious": 5,
            "last_analysis_date": "2024-01-02"
        }
    }

    result = compare_json(sample_config, old, new)

    # Should report change in total_malicious but not last_analysis_date
    assert "virustotal" in result
    assert "last_analysis_date" not in result["virustotal"]


@pytest.mark.unit
@pytest.mark.xfail(
    reason="Bug in compare_json: when simple=True, jsondiff returns dict but code tries json.loads() on it"
)
def test_compare_json_simple_mode(sample_config):
    """Test JSON comparison in simple mode."""
    sample_config["cwatch"]["simple"] = True

    old = {
        "abuseipdb": {"reports": 0}
    }
    new = {
        "abuseipdb": {"reports": 5}
    }

    result = compare_json(sample_config, old, new)

    # In simple mode, no filtering is applied and result is a dict
    assert isinstance(result, dict)
    # jsondiff symmetric format returns the diff directly
    assert result != {}


@pytest.mark.unit
def test_compare_json_verbose_mode(sample_config, capsys):
    """Test JSON comparison in verbose mode."""
    sample_config["cwatch"]["verbose"] = True
    sample_config["cwatch"]["ignore_engines"] = ["urlhaus"]

    old = {
        "abuseipdb": {"reports": 0},
        "urlhaus": {"count": 0}
    }
    new = {
        "abuseipdb": {"reports": 5},
        "urlhaus": {"count": 10}
    }

    result = compare_json(sample_config, old, new)
    captured = capsys.readouterr()

    assert "abuseipdb" in result
    assert "Removed diff in urlhaus" in captured.out


@pytest.mark.unit
def test_compare_json_new_field_added(sample_config):
    """Test JSON comparison when new field is added."""
    old = {
        "abuseipdb": {"reports": 0}
    }
    new = {
        "abuseipdb": {"reports": 0},
        "shodan": {"link": "test"}
    }

    result = compare_json(sample_config, old, new)

    # jsondiff symmetric format uses $insert for added fields
    assert "$insert" in result or "shodan" in result


@pytest.mark.unit
def test_compare_json_field_removed(sample_config):
    """Test JSON comparison when field is removed."""
    old = {
        "abuseipdb": {"reports": 0},
        "shodan": {"link": "test"}
    }
    new = {
        "abuseipdb": {"reports": 0}
    }

    result = compare_json(sample_config, old, new)

    # jsondiff symmetric format uses $delete for removed fields
    assert "$delete" in result or "shodan" in result


@pytest.mark.unit
def test_compare_json_nested_changes(sample_config):
    """Test JSON comparison with nested structure changes."""
    old = {
        "virustotal": {
            "analysis": {
                "malicious": 0,
                "suspicious": 0
            }
        }
    }
    new = {
        "virustotal": {
            "analysis": {
                "malicious": 5,
                "suspicious": 0
            }
        }
    }

    result = compare_json(sample_config, old, new)

    assert "virustotal" in result
