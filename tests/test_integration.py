"""Integration tests for the two-phase architecture."""
import json
from datetime import datetime

import pytest

from cwatch.collector import DataCollector
from cwatch.data_structures import CollectedData, TargetResult
from cwatch.reporters import JsonReporter, TextReporter, get_reporter


@pytest.mark.integration
def test_data_collector_integration(sample_config, initialized_db, mocker):
    """Test DataCollector end-to-end."""
    # Mock DNS and API calls
    sample_config["iocs"]["domains"] = ["8.8.8.8"]

    mock_request_response = {"link": "/result/123"}
    mock_api_response = [{"abuseipdb": {"reports": 0, "risk_score": 0}}]

    mocker.patch("cwatch.collector.submit_request", return_value=mock_request_response)
    mocker.patch("cwatch.collector.get_response", return_value=mock_api_response)

    collector = DataCollector(sample_config)
    result = collector.collect_all()

    assert isinstance(result, CollectedData)
    assert result.total_targets > 0
    assert result.successful >= 0
    assert result.collection_start <= result.collection_end


@pytest.mark.integration
def test_text_reporter_integration(sample_config):
    """Test TextReporter with sample data."""
    # Create sample collected data
    target1 = TargetResult(
        target="8.8.8.8",
        success=True,
        timestamp=datetime.now(),
        response={"test": "data"},
        changes={"abuseipdb": {"reports": 5, "risk_score": 50}},
        errors=[],
    )

    target2 = TargetResult(
        target="1.1.1.1",
        success=True,
        timestamp=datetime.now(),
        response={"test": "data"},
        changes=None,
        errors=[],
    )

    collected_data = CollectedData(
        targets=[target1, target2],
        configuration=sample_config,
        collection_start=datetime.now(),
        collection_end=datetime.now(),
        total_targets=2,
        successful=2,
        failed=0,
    )

    reporter = TextReporter(sample_config)
    report = reporter.generate(collected_data)

    assert isinstance(report, str)
    assert "8.8.8.8" in report
    assert "Changes detected" in report


@pytest.mark.integration
def test_json_reporter_integration(sample_config):
    """Test JsonReporter with sample data."""
    target1 = TargetResult(
        target="8.8.8.8",
        success=True,
        timestamp=datetime.now(),
        response={"test": "data"},
        changes={"shodan": {"link": "https://shodan.io/host/8.8.8.8"}},
        errors=[],
    )

    collected_data = CollectedData(
        targets=[target1],
        configuration=sample_config,
        collection_start=datetime.now(),
        collection_end=datetime.now(),
        total_targets=1,
        successful=1,
        failed=0,
    )

    reporter = JsonReporter(sample_config)
    report = reporter.generate(collected_data)

    assert isinstance(report, str)
    # Verify it's valid JSON
    report_dict = json.loads(report)
    assert "metadata" in report_dict
    assert "targets" in report_dict
    assert report_dict["metadata"]["total_targets"] == 1


@pytest.mark.integration
def test_get_reporter_factory(sample_config):
    """Test reporter factory function."""
    text_reporter = get_reporter("text", sample_config)
    assert isinstance(text_reporter, TextReporter)

    json_reporter = get_reporter("json", sample_config)
    assert isinstance(json_reporter, JsonReporter)

    # Default should be text
    default_reporter = get_reporter("unknown", sample_config)
    assert isinstance(default_reporter, TextReporter)


@pytest.mark.integration
def test_collected_data_has_changes(sample_config):
    """Test CollectedData.has_changes method."""
    # No changes
    target1 = TargetResult(
        target="8.8.8.8",
        success=True,
        timestamp=datetime.now(),
        response={},
        changes=None,
        errors=[],
    )

    data = CollectedData(
        targets=[target1],
        configuration=sample_config,
        collection_start=datetime.now(),
        collection_end=datetime.now(),
        total_targets=1,
        successful=1,
        failed=0,
    )

    assert not data.has_changes()

    # With changes
    target2 = TargetResult(
        target="1.1.1.1",
        success=True,
        timestamp=datetime.now(),
        response={},
        changes={"abuseipdb": {"reports": 5}},
        errors=[],
    )

    data_with_changes = CollectedData(
        targets=[target2],
        configuration=sample_config,
        collection_start=datetime.now(),
        collection_end=datetime.now(),
        total_targets=1,
        successful=1,
        failed=0,
    )

    assert data_with_changes.has_changes()


@pytest.mark.integration
def test_collected_data_get_targets_with_changes(sample_config):
    """Test CollectedData.get_targets_with_changes method."""
    target1 = TargetResult(
        target="8.8.8.8",
        success=True,
        timestamp=datetime.now(),
        response={},
        changes=None,
        errors=[],
    )

    target2 = TargetResult(
        target="1.1.1.1",
        success=True,
        timestamp=datetime.now(),
        response={},
        changes={"abuseipdb": {"reports": 5}},
        errors=[],
    )

    data = CollectedData(
        targets=[target1, target2],
        configuration=sample_config,
        collection_start=datetime.now(),
        collection_end=datetime.now(),
        total_targets=2,
        successful=2,
        failed=0,
    )

    targets_with_changes = data.get_targets_with_changes()
    assert len(targets_with_changes) == 1
    assert targets_with_changes[0].target == "1.1.1.1"


@pytest.mark.integration
def test_quiet_mode_filtering(sample_config):
    """Test that quiet mode filters out non-significant changes."""
    sample_config["cwatch"]["quiet"] = True

    # Changes that should be filtered out
    target1 = TargetResult(
        target="8.8.8.8",
        success=True,
        timestamp=datetime.now(),
        response={},
        changes={"abuseipdb": {"reports": 0, "risk_score": 0}},
        errors=[],
    )

    # Significant changes
    target2 = TargetResult(
        target="1.1.1.1",
        success=True,
        timestamp=datetime.now(),
        response={},
        changes={"abuseipdb": {"reports": 5, "risk_score": 50}},
        errors=[],
    )

    data = CollectedData(
        targets=[target1, target2],
        configuration=sample_config,
        collection_start=datetime.now(),
        collection_end=datetime.now(),
        total_targets=2,
        successful=2,
        failed=0,
    )

    reporter = TextReporter(sample_config)
    report = reporter.generate(data)

    # Should only show significant changes
    assert "1.1.1.1" in report
    assert "Changes detected for 1.1.1.1" in report
