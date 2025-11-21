"""Tests for reporter filtering logic."""

import pytest

from cwatch.reporters import HtmlReporter, JsonReporter, TextReporter


@pytest.mark.unit
def test_filter_changes_with_invalid_type_html(sample_config):
    """Test that HtmlReporter._filter_changes handles non-dict input gracefully."""
    reporter = HtmlReporter(sample_config)

    # Test with list input (invalid)
    result = reporter._filter_changes([1, 2, 3])

    assert isinstance(result, dict)
    assert result == {}


@pytest.mark.unit
def test_filter_changes_with_invalid_type_json(sample_config):
    """Test that JsonReporter._filter_changes handles non-dict input gracefully."""
    reporter = JsonReporter(sample_config)

    # Test with list input (invalid)
    result = reporter._filter_changes([1, 2, 3])

    assert isinstance(result, dict)
    assert result == {}


@pytest.mark.unit
def test_filter_changes_with_invalid_type_text(sample_config):
    """Test that TextReporter._filter_changes handles non-dict input gracefully."""
    reporter = TextReporter(sample_config)

    # Test with list input (invalid)
    result = reporter._filter_changes([1, 2, 3])

    assert isinstance(result, dict)
    assert result == {}


@pytest.mark.unit
def test_filter_changes_with_none(sample_config):
    """Test that _filter_changes handles None input gracefully."""
    reporter = HtmlReporter(sample_config)

    # Test with None input (invalid)
    result = reporter._filter_changes(None)

    assert isinstance(result, dict)
    assert result == {}


@pytest.mark.unit
def test_filter_changes_with_valid_dict(sample_config):
    """Test that _filter_changes works correctly with valid dict input."""
    reporter = HtmlReporter(sample_config)
    sample_config["cwatch"]["quiet"] = False

    changes = {
        "abuseipdb": {"reports": 5, "risk_score": 50},
        "shodan": {"link": "https://shodan.io/test"},
    }

    result = reporter._filter_changes(changes)

    assert isinstance(result, dict)
    assert result == changes
