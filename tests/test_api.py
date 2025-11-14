"""Tests for API interactions and retry logic."""
import json
from unittest.mock import Mock

import httpcore
import httpx
import pytest

from cwatch.cw import (
    check_analysis_complete,
    get_response,
    get_results,
    retry_with_backoff,
    submit_request,
)


@pytest.mark.unit
def test_submit_request_success(sample_config, mocker):
    """Test successful API request submission."""
    mock_response = Mock()
    mock_response.text = json.dumps({"analysis_id": "abc123xyz"})

    mocker.patch("httpx.post", return_value=mock_response)

    result = submit_request(sample_config, "example.com")

    assert result == "abc123xyz"


@pytest.mark.unit
def test_submit_request_network_error(sample_config, mocker, capsys):
    """Test API request with network error and retries."""
    mocker.patch(
        "httpx.post",
        side_effect=httpcore.ConnectError("Connection failed")
    )

    result = submit_request(sample_config, "example.com")
    captured = capsys.readouterr()

    assert result is None
    assert "Failed after" in captured.err
    assert "retries" in captured.err


@pytest.mark.unit
def test_submit_request_timeout(sample_config, mocker, capsys):
    """Test API request with timeout."""
    mocker.patch(
        "httpx.post",
        side_effect=httpx.TimeoutException("Request timeout")
    )

    result = submit_request(sample_config, "example.com")
    captured = capsys.readouterr()

    assert result is None
    assert "Failed after" in captured.err


@pytest.mark.unit
def test_submit_request_invalid_json(sample_config, mocker, capsys):
    """Test API request with invalid JSON response."""
    mock_response = Mock()
    mock_response.text = "Invalid JSON{"

    mocker.patch("httpx.post", return_value=mock_response)

    result = submit_request(sample_config, "example.com")
    captured = capsys.readouterr()

    assert result == ""
    assert "Error parsing response" in captured.err


@pytest.mark.unit
def test_get_response_success(sample_config, mocker):
    """Test successful response retrieval with completion check."""
    # Mock completion check to return True
    completion_response = Mock()
    completion_response.text = json.dumps({"complete": True})

    # Mock results retrieval
    results_response = Mock()
    results_response.text = json.dumps([{"result": "data"}])

    mocker.patch(
        "httpx.get",
        side_effect=[completion_response, results_response]
    )
    mocker.patch("time.sleep")  # Speed up test

    result = get_response(sample_config, "abc123xyz")

    assert result == [{"result": "data"}]


@pytest.mark.unit
def test_get_response_polling(sample_config, mocker):
    """Test response retrieval with polling for completion."""
    # First two completion checks return False, third returns True, then results
    mock_responses = [
        Mock(text=json.dumps({"complete": False})),  # First check
        Mock(text=json.dumps({"complete": False})),  # Second check
        Mock(text=json.dumps({"complete": True})),   # Third check
        Mock(text=json.dumps([{"result": "data"}])), # Results
    ]

    mock_get = mocker.patch("httpx.get", side_effect=mock_responses)
    mocker.patch("time.sleep")  # Speed up test

    result = get_response(sample_config, "abc123xyz")

    assert result == [{"result": "data"}]
    assert mock_get.call_count == 4


@pytest.mark.unit
def test_get_response_connection_error(sample_config, mocker, capsys):
    """Test response retrieval with connection errors during polling."""
    mocker.patch(
        "httpx.get",
        side_effect=httpcore.ConnectError("Connection failed")
    )
    mocker.patch("time.sleep")

    result = get_response(sample_config, "abc123xyz")
    captured = capsys.readouterr()

    assert result == {}
    assert "Failed to check analysis completion" in captured.err or "Failed to" in captured.err


@pytest.mark.unit
def test_get_response_invalid_json(sample_config, mocker, capsys):
    """Test response retrieval with invalid JSON in completion check."""
    mock_response = Mock()
    mock_response.text = "Invalid JSON{"

    mocker.patch("httpx.get", return_value=mock_response)
    mocker.patch("time.sleep")

    result = get_response(sample_config, "abc123xyz")
    captured = capsys.readouterr()

    assert result == {}
    assert "Error parsing" in captured.err


@pytest.mark.unit
def test_check_analysis_complete_true(sample_config, mocker):
    """Test checking if analysis is complete (true)."""
    mock_response = Mock()
    mock_response.text = json.dumps({"complete": True})

    mocker.patch("httpx.get", return_value=mock_response)

    result = check_analysis_complete(sample_config, "abc123xyz")

    assert result is True


@pytest.mark.unit
def test_check_analysis_complete_false(sample_config, mocker):
    """Test checking if analysis is complete (false)."""
    mock_response = Mock()
    mock_response.text = json.dumps({"complete": False})

    mocker.patch("httpx.get", return_value=mock_response)

    result = check_analysis_complete(sample_config, "abc123xyz")

    assert result is False


@pytest.mark.unit
def test_check_analysis_complete_connection_error(sample_config, mocker, capsys):
    """Test checking analysis completion with connection error."""
    mocker.patch(
        "httpx.get",
        side_effect=httpcore.ConnectError("Connection failed")
    )
    mocker.patch("time.sleep")

    result = check_analysis_complete(sample_config, "abc123xyz")
    captured = capsys.readouterr()

    assert result is False
    assert "Failed to check analysis completion" in captured.err


@pytest.mark.unit
def test_get_results_success(sample_config, mocker):
    """Test successful results retrieval."""
    mock_response = Mock()
    mock_response.text = json.dumps([{"engine": "virustotal", "data": "result"}])

    mocker.patch("httpx.get", return_value=mock_response)

    result = get_results(sample_config, "abc123xyz")

    assert result == [{"engine": "virustotal", "data": "result"}]


@pytest.mark.unit
def test_get_results_connection_error(sample_config, mocker, capsys):
    """Test results retrieval with connection error."""
    mocker.patch(
        "httpx.get",
        side_effect=httpcore.ConnectError("Connection failed")
    )
    mocker.patch("time.sleep")

    result = get_results(sample_config, "abc123xyz")
    captured = capsys.readouterr()

    assert result == {}
    assert "Failed to get results" in captured.err


@pytest.mark.unit
def test_retry_decorator_success():
    """Test retry decorator with successful function."""
    call_count = []

    @retry_with_backoff(max_retries=3)
    def successful_function():
        call_count.append(1)
        return "success"

    result = successful_function()

    assert result == "success"
    assert len(call_count) == 1


@pytest.mark.unit
def test_retry_decorator_eventual_success(mocker):
    """Test retry decorator that succeeds after failures."""
    mocker.patch("time.sleep")  # Speed up test
    call_count = []

    @retry_with_backoff(max_retries=3, initial_delay=0.1)
    def eventually_successful():
        call_count.append(1)
        if len(call_count) < 3:
            raise httpcore.ConnectError("Connection failed")
        return "success"

    result = eventually_successful()

    assert result == "success"
    assert len(call_count) == 3


@pytest.mark.unit
def test_retry_decorator_max_retries(mocker, capsys):
    """Test retry decorator reaching max retries."""
    mocker.patch("time.sleep")  # Speed up test

    @retry_with_backoff(max_retries=2, initial_delay=0.1)
    def always_fails():
        raise httpcore.ConnectError("Connection failed")

    result = always_fails()
    captured = capsys.readouterr()

    assert result is None
    assert "Failed after 2 retries" in captured.err


@pytest.mark.unit
def test_retry_decorator_unexpected_error(capsys):
    """Test retry decorator with unexpected error type."""
    @retry_with_backoff(max_retries=3)
    def unexpected_error():
        raise ValueError("Unexpected error")

    result = unexpected_error()
    captured = capsys.readouterr()

    assert result is None
    assert "Unexpected error" in captured.err
