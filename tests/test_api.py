"""Tests for API interactions and retry logic."""
import json
from unittest.mock import Mock

import httpcore
import httpx
import pytest

from cwatch.cw import get_response, retry_with_backoff, submit_request


@pytest.mark.unit
def test_submit_request_success(sample_config, mocker):
    """Test successful API request submission."""
    mock_response = Mock()
    mock_response.text = json.dumps({"link": "/result/123"})

    mocker.patch("httpx.post", return_value=mock_response)

    result = submit_request(sample_config, "example.com")

    assert result == {"link": "/result/123"}


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
    assert "Failed after" in captured.out
    assert "retries" in captured.out


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
    assert "Failed after" in captured.out


@pytest.mark.unit
def test_submit_request_invalid_json(sample_config, mocker, capsys):
    """Test API request with invalid JSON response."""
    mock_response = Mock()
    mock_response.text = "Invalid JSON{"

    mocker.patch("httpx.post", return_value=mock_response)

    result = submit_request(sample_config, "example.com")
    captured = capsys.readouterr()

    assert result == {}
    assert "Error parsing response" in captured.out


@pytest.mark.unit
def test_get_response_success(sample_config, mocker):
    """Test successful response retrieval."""
    mock_response = Mock()
    mock_response.text = json.dumps([{"result": "data"}])

    mocker.patch("httpx.get", return_value=mock_response)

    result = get_response(sample_config, "/result/123")

    assert result == [{"result": "data"}]


@pytest.mark.unit
def test_get_response_polling(sample_config, mocker):
    """Test response retrieval with polling."""
    # First two calls return empty, third returns data
    mock_responses = [
        Mock(text="[]\n"),
        Mock(text="[]\n"),
        Mock(text=json.dumps([{"result": "data"}])),
    ]

    mock_get = mocker.patch("httpx.get", side_effect=mock_responses)
    mocker.patch("time.sleep")  # Speed up test

    result = get_response(sample_config, "/result/123")

    assert result == [{"result": "data"}]
    assert mock_get.call_count == 3


@pytest.mark.unit
def test_get_response_connection_error(sample_config, mocker, capsys):
    """Test response retrieval with connection errors."""
    mocker.patch(
        "httpx.get",
        side_effect=httpcore.ConnectError("Connection failed")
    )
    mocker.patch("time.sleep")

    result = get_response(sample_config, "/result/123")
    captured = capsys.readouterr()

    assert result == {}
    assert "Failed to connect" in captured.out


@pytest.mark.unit
def test_get_response_invalid_json(sample_config, mocker, capsys):
    """Test response retrieval with invalid JSON."""
    mock_response = Mock()
    mock_response.text = "Invalid JSON{"

    mocker.patch("httpx.get", return_value=mock_response)

    result = get_response(sample_config, "/result/123")
    captured = capsys.readouterr()

    assert result == {}
    assert "Error parsing response" in captured.out


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
    assert "Failed after 2 retries" in captured.out


@pytest.mark.unit
def test_retry_decorator_unexpected_error(capsys):
    """Test retry decorator with unexpected error type."""
    @retry_with_backoff(max_retries=3)
    def unexpected_error():
        raise ValueError("Unexpected error")

    result = unexpected_error()
    captured = capsys.readouterr()

    assert result is None
    assert "Unexpected error" in captured.out
