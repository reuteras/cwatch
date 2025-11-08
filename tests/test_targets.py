"""Tests for target resolution and handling."""
import socket

import pytest

from cwatch.cw import get_targets


@pytest.mark.unit
def test_get_targets_with_ip_address(sample_config):
    """Test target resolution with direct IP address."""
    sample_config["iocs"]["domains"] = ["8.8.8.8"]
    targets = []

    result = get_targets(sample_config, targets)

    assert "8.8.8.8" in result
    assert len(result) == 1


@pytest.mark.unit
def test_get_targets_with_private_ip(sample_config):
    """Test that private IPs are filtered out."""
    sample_config["iocs"]["domains"] = ["192.168.1.1", "10.0.0.1"]
    targets = []

    result = get_targets(sample_config, targets)

    assert "192.168.1.1" not in result
    assert "10.0.0.1" not in result
    assert len(result) == 0


@pytest.mark.unit
def test_get_targets_with_domain(sample_config, mocker):
    """Test target resolution with domain name."""
    sample_config["iocs"]["domains"] = ["example.com"]
    targets = []

    # Mock DNS resolution
    mock_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
    ]
    mocker.patch("socket.getaddrinfo", return_value=mock_addresses)

    result = get_targets(sample_config, targets)

    assert "example.com" in result
    assert "93.184.216.34" in result


@pytest.mark.unit
def test_get_targets_dns_failure(sample_config, mocker, capsys):
    """Test target resolution when DNS lookup fails."""
    sample_config["iocs"]["domains"] = ["nonexistent.invalid"]
    targets = []

    # Mock DNS failure
    mocker.patch("socket.getaddrinfo", side_effect=socket.gaierror("Name resolution failed"))

    result = get_targets(sample_config, targets)
    captured = capsys.readouterr()

    # Domain should not be in targets
    assert "nonexistent.invalid" not in result
    assert "Failed to lookup DNS" in captured.out


@pytest.mark.unit
def test_get_targets_mixed_inputs(sample_config, mocker):
    """Test target resolution with mixed IPs and domains."""
    sample_config["iocs"]["domains"] = ["8.8.8.8", "example.com", "192.168.1.1"]
    targets = []

    # Mock DNS resolution for example.com
    mock_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 80))
    ]
    mocker.patch("socket.getaddrinfo", return_value=mock_addresses)

    result = get_targets(sample_config, targets)

    # Public IP should be included
    assert "8.8.8.8" in result
    # Domain should be included
    assert "example.com" in result
    # Domain's IP should be included
    assert "93.184.216.34" in result
    # Private IP should NOT be included
    assert "192.168.1.1" not in result


@pytest.mark.unit
def test_get_targets_no_duplicates(sample_config, mocker):
    """Test that duplicate IPs are not added."""
    sample_config["iocs"]["domains"] = ["8.8.8.8", "dns.google"]
    targets = []

    # Mock DNS resolution to return 8.8.8.8 for dns.google
    mock_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 80))
    ]
    mocker.patch("socket.getaddrinfo", return_value=mock_addresses)

    result = get_targets(sample_config, targets)

    # Should only have one entry for 8.8.8.8
    # Note: dns.google is NOT added because it only resolves to IPs already in the list
    assert result.count("8.8.8.8") == 1
    assert len(result) == 1


@pytest.mark.unit
def test_get_targets_domain_with_private_ip(sample_config, mocker):
    """Test that domains resolving to private IPs are excluded."""
    sample_config["iocs"]["domains"] = ["internal.local"]
    targets = []

    # Mock DNS resolution to return private IP
    mock_addresses = [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.168.1.100", 80))
    ]
    mocker.patch("socket.getaddrinfo", return_value=mock_addresses)

    result = get_targets(sample_config, targets)

    # Domain should not be included if it only resolves to private IPs
    assert "internal.local" not in result
    assert "192.168.1.100" not in result
