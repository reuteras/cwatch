"""cwatch is a tool to monitor cyberbro for changes for questions."""
import argparse
import functools
import hashlib
import importlib.metadata
import ipaddress
import json
import socket
import sqlite3
import sys
import time
import tomllib
from collections.abc import Callable
from datetime import datetime
from http.client import HTTPException
from pathlib import Path
from typing import Any, cast

import httpcore
import httpx
import jsondiff

# Configuration for retries
MAX_RETRIES = 5
INITIAL_RETRY_DELAY = 1.0
MAX_RETRY_DELAY = 30.0
HTTP_TIMEOUT = 30.0


def retry_with_backoff(
    max_retries: int = MAX_RETRIES,
    initial_delay: float = INITIAL_RETRY_DELAY,
    max_delay: float = MAX_RETRY_DELAY,
    exceptions: tuple = (httpcore.ConnectError, HTTPException, httpx.TimeoutException, httpx.ConnectError)
) -> Callable:
    """Decorator to retry a function with exponential backoff.

    Args:
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay between retries in seconds
        max_delay: Maximum delay between retries in seconds
        exceptions: Tuple of exceptions to catch and retry on

    Returns:
        Decorated function with retry logic
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            delay = initial_delay

            for attempt in range(max_retries + 1):
                try:
                    return func(*args, **kwargs)
                except exceptions as err:
                    if attempt == max_retries:
                        print(f"Failed after {max_retries} retries in {func.__name__}: {err}")
                        return None

                    print(f"Attempt {attempt + 1}/{max_retries + 1} failed in {func.__name__}: {err}. Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    delay = min(delay * 2, max_delay)  # Exponential backoff with cap
                except Exception as err:
                    # For unexpected exceptions, don't retry
                    print(f"Unexpected error in {func.__name__}: {err}")
                    return None

            return None
        return wrapper
    return decorator


@retry_with_backoff()
def submit_request(configuration, name) -> str:
    """Submit question to Cyberbro and return analysis_id with retry logic.

    Args:
        configuration: Configuration dictionary
        name: Target name to query

    Returns:
        Analysis ID string or empty string on failure
    """
    data: dict[str, dict] = {"text": name, "engines": configuration["cyberbro"]["engines"]}
    r: httpx.Response = httpx.post(
        url=configuration["cyberbro"]["url"] + "/api/analyze",
        json=data,
        timeout=HTTP_TIMEOUT
    )
    try:
        response = json.loads(r.text)
        analysis_id = response.get("analysis_id")
        if analysis_id:
            return analysis_id
        print(f"No analysis_id in response for {name}: {r.text}")
        return ""
    except Exception as err:
        print(f"Error parsing response for {name}: {r.text}. Error was {err}")
        return ""


def check_analysis_complete(configuration, analysis_id) -> bool:
    """Check if analysis is complete.

    Args:
        configuration: Configuration dictionary
        analysis_id: Analysis ID to check

    Returns:
        True if complete, False otherwise
    """
    connect_error_count: int = 0
    delay: float = INITIAL_RETRY_DELAY

    while connect_error_count <= MAX_RETRIES:
        try:
            r: httpx.Response = httpx.get(
                url=configuration["cyberbro"]["url"] + f"/api/is_analysis_complete/{analysis_id}",
                timeout=HTTP_TIMEOUT
            )
            # Reset error count on successful connection
            connect_error_count = 0

            try:
                response = json.loads(r.text)
                return response.get("complete", False)
            except Exception as err:
                print(f"Error parsing completion response for {analysis_id}: {r.text}. Error was {err}")
                return False

        except (HTTPException, httpcore.ConnectError, httpx.TimeoutException, httpx.ConnectError) as err:
            connect_error_count += 1
            if connect_error_count > MAX_RETRIES:
                print(f"Failed to check analysis completion after {MAX_RETRIES} retries: {err}")
                return False
            print(f"Connection attempt {connect_error_count}/{MAX_RETRIES + 1} failed: {err}. Retrying in {delay:.1f}s...")
            time.sleep(delay)
            delay = min(delay * 2, MAX_RETRY_DELAY)
            continue

    return False


def get_results(configuration, analysis_id) -> dict:
    """Get analysis results from Cyberbro.

    Args:
        configuration: Configuration dictionary
        analysis_id: Analysis ID to get results for

    Returns:
        Results dictionary or empty dict on failure
    """
    connect_error_count: int = 0
    delay: float = INITIAL_RETRY_DELAY

    while connect_error_count <= MAX_RETRIES:
        try:
            r: httpx.Response = httpx.get(
                url=configuration["cyberbro"]["url"] + f"/api/results/{analysis_id}",
                timeout=HTTP_TIMEOUT
            )
            # Reset error count on successful connection
            connect_error_count = 0

            try:
                return json.loads(r.text)
            except Exception as err:
                print(f"Error parsing results for {analysis_id}: {r.text}. Error was {err}")
                return {}

        except (HTTPException, httpcore.ConnectError, httpx.TimeoutException, httpx.ConnectError) as err:
            connect_error_count += 1
            if connect_error_count > MAX_RETRIES:
                print(f"Failed to get results after {MAX_RETRIES} retries: {err}")
                return {}
            print(f"Connection attempt {connect_error_count}/{MAX_RETRIES + 1} failed: {err}. Retrying in {delay:.1f}s...")
            time.sleep(delay)
            delay = min(delay * 2, MAX_RETRY_DELAY)
            continue

    return {}


def get_response(configuration, analysis_id) -> dict:
    """Poll for analysis completion and get results from Cyberbro.

    Args:
        configuration: Configuration dictionary
        analysis_id: Analysis ID to poll

    Returns:
        Response dictionary or empty dict on failure
    """
    max_wait_time: int = 3600  # 1 hour maximum wait time
    elapsed_time: int = 0
    poll_interval: int = 5  # Start with 5 second polls

    while elapsed_time < max_wait_time:
        if check_analysis_complete(configuration, analysis_id):
            return get_results(configuration, analysis_id)

        print(f"Analysis {analysis_id} not complete yet. Waiting {poll_interval}s before next check...")
        time.sleep(poll_interval)
        elapsed_time += poll_interval
        # Gradually increase poll interval to reduce server load
        poll_interval = min(poll_interval + 5, 60)

    print(f"Analysis {analysis_id} did not complete within {max_wait_time} seconds")
    return {}


def setup_database(configuration) -> bool:
    """Create database with error handling.

    Args:
        configuration: Configuration dictionary

    Returns:
        True if successful, False otherwise
    """
    try:
        conn: sqlite3.Connection = sqlite3.connect(database=configuration["cwatch"]["DB_FILE"])
        cursor: sqlite3.Cursor = conn.cursor()
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
        return True
    except sqlite3.Error as err:
        print(f"Database error during setup: {err}")
        return False
    except Exception as err:
        print(f"Unexpected error during database setup: {err}")
        return False


def calculate_hash(json_data) -> str:
    """Function to calculate a hash for a JSON object."""
    json_string: str = json.dumps(obj=json_data, sort_keys=True)
    return hashlib.sha256(string=json_string.encode(encoding="utf-8")).hexdigest()


def save_json_data(configuration, item, json_data) -> bool:
    """Save JSON data if changes are detected.

    Args:
        configuration: Configuration dictionary
        item: Target name
        json_data: JSON data to save

    Returns:
        True if successful, False otherwise
    """
    try:
        conn: sqlite3.Connection = sqlite3.connect(database=configuration["cwatch"]["DB_FILE"])
        cursor: sqlite3.Cursor = conn.cursor()

        # Calculate hash for the current JSON
        json_hash: str = calculate_hash(json_data=json_data)

        # Insert the new JSON data
        cursor.execute(
            """
            INSERT INTO json_data (target, timestamp, json_hash, json_content)
            VALUES (?, ?, ?, ?)
        """,
            (item, datetime.now().isoformat(), json_hash, json.dumps(json_data)),
        )

        conn.commit()
        conn.close()
        return True
    except sqlite3.Error as err:
        print(f"Database error saving data for {item}: {err}")
        return False
    except Exception as err:
        print(f"Unexpected error saving data for {item}: {err}")
        return False


def handle_abuseipdb(change) -> dict:
    """Remove change from abuseipdb if no relevant changes."""
    report = True
    if isinstance(change["abuseipdb"], list) and len(change["abuseipdb"]) == 2: # noqa: PLR2004
        if "reports" in change["abuseipdb"][1] and "risk_score" in change["abuseipdb"][1]:
            if change["abuseipdb"][1]["reports"] == 0 and change["abuseipdb"][1]["risk_score"] == 0:
                report = False
        else:
            report = False
    if "reports" in change["abuseipdb"] and "risk_score" in change["abuseipdb"]:
        if change["abuseipdb"]["reports"] == 0 and change["abuseipdb"]["risk_score"] == 0:
            report = False
    if not report:
        change.pop("abuseipdb")
    return change


def handle_shodan(change) -> dict:
    """Remove change from shodan if change is to null."""
    if "link" not in change["shodan"]:
        change.pop("shodan")
    return change


def handle_threatfox(change) -> dict:
    """Remove change from threatfox if no matches."""
    report = True
    try:
        if isinstance(change["threatfox"], list) and len(change["threatfox"]) == 2: # noqa: PLR2004
            if "count" in change["threatfox"][1] and change["threatfox"][1]["count"] == 0 \
                    and "malware_printable" in change["threatfox"][1] and change["threatfox"][1]["malware_printable"] == []:
                report = False
            elif change["threatfox"][1] is None:
                report = False
        if change["threatfox"] is None or ("count" in change["threatfox"]):
            if change["threatfox"]["count"] == 0 and change["threatfox"]["malware_printable"] == []:
                report = False
    except (TypeError, KeyError, RuntimeError):
        # If the key is not present, we assume no matches
        report = False
    if not report:
        change.pop("threatfox")
    return change


def handle_virustotal(change) -> dict:
    """Remove change from virustotal if no matches."""
    report = True
    if isinstance(change["virustotal"], list) and len(change["virustotal"]) == 2: # noqa: PLR2004
        if change["virustotal"][1] is None:
            report = False
        elif "community_score" in change["virustotal"][1] and change["virustotal"][1]["community_score"] == 0 \
                and "total_malicious" in change["virustotal"][1] and change["virustotal"][1]["total_malicious"] == 0:
            report = False
    if change["virustotal"] is None or ("community_score" in change["virustotal"]):
        if change["virustotal"]["community_score"] == 0 and change["virustotal"]["total_malicious"] == 0:
            report = False
    if not report:
        change.pop("virustotal")
    return change


def handle_changes(configuration, target: str, changes: dict) -> bool:
    """Handle changes."""
    if configuration["cwatch"]["quiet"]:
        if "abuseipdb" in changes:
            changes = handle_abuseipdb(change=changes)
        if "shodan" in changes:
            changes = handle_shodan(change=changes)
        if "threatfox" in changes:
            changes = handle_threatfox(change=changes)
        if "virustotal" in changes:
            changes = handle_virustotal(change=changes)
        if changes != {}:
            print(f"Changes detected for {target}:")
            print(json.dumps(obj=changes, indent=4))
            return True
        return False
    print(f"Changes detected for {target}:")
    print(json.dumps(changes, indent=4))
    return True


def detect_changes(configuration, item) -> bool:
    """Detect changes in json with error handling.

    Args:
        configuration: Configuration dictionary
        item: Target name

    Returns:
        True if changes detected, False otherwise
    """
    try:
        conn: sqlite3.Connection = sqlite3.connect(database=configuration["cwatch"]["DB_FILE"])
        cursor: sqlite3.Cursor = conn.cursor()
        changed: bool = False

        # Fetch the last two entries
        cursor.execute(
            """
            SELECT json_content FROM json_data WHERE target = ?
            ORDER BY id DESC LIMIT 2
        """,
            (item,),
        )
        rows: list[Any] = cursor.fetchall()

        if len(rows) == 2: # noqa: PLR2004
            old_json: dict = json.loads(rows[1][0])[0]
            new_json: dict = json.loads(rows[0][0])[0]
            changes: dict = compare_json(configuration=configuration, old=old_json, new=new_json)
            if changes != {}:
                changed = handle_changes(configuration=configuration, target=item, changes=changes)
            if configuration["cwatch"]["report"] and not configuration["cwatch"]["quiet"]:
                print("- No changes.")
        elif not configuration["cwatch"]["quiet"]:
            print("- Not enough data for comparison.")

        conn.close()
        return changed
    except sqlite3.Error as err:
        print(f"Database error detecting changes for {item}: {err}")
        return False
    except Exception as err:
        print(f"Unexpected error detecting changes for {item}: {err}")
        return False


def compare_json(configuration, old, new) -> dict:
    """Compare json objects."""
    simple: bool = configuration["cwatch"]["simple"]
    verbose: bool = configuration["cwatch"]["verbose"]
    if simple:
        json_diff: str = cast(str, jsondiff.diff(old, new, syntax="symmetric"))
        return json.loads(json_diff)
    json_diff: str = cast(str, jsondiff.diff(old, new, syntax="symmetric", dump=True))
    diff: dict = json.loads(json_diff)
    for engine in configuration["cwatch"]["ignore_engines"]:
        if engine in diff:
            removed: dict = diff.pop(engine)
            if verbose:
                print(f"Removed diff in {engine}: {removed}")
    for combo in configuration["cwatch"]["ignore_engines_partly"]:
        engine: str = combo[0]
        part: str = combo[1]
        if engine in diff:
            if part in diff[engine]:
                removed = diff[engine].pop(part)
                if verbose:
                    print(f"Removed diff in {engine}->{part}: {removed}")
            if diff[engine] == {}:
                diff.pop(engine)
    return diff


def report_header(configuration) -> None:
    """Print header in report mode."""
    print(configuration["cwatch"]["header"])
    print("=" * len(configuration["cwatch"]["header"]))
    print("")
    print(f"Report generation start at {datetime.now().isoformat()}")
    print("")
    print("Will report changes in the following engines.")
    engines:list = configuration["cyberbro"]["engines"]
    engines.sort()
    for engine in engines:
        if engine not in configuration["cwatch"]["ignore_engines"]:
            print(f"- {engine}")
    print("")
    if configuration["cwatch"]["ignore_engines_partly"]:
        print("Ignore change if the only change is in one of:")
        for combo in configuration["cwatch"]["ignore_engines_partly"]:
            print(f"- {combo[0]} -> {combo[1]}")
        print("")


def report_footer(configuration) -> None:
    """Print footer in report mode."""
    print("")
    print(f"Report done at {datetime.now().isoformat()}.")
    if configuration["cwatch"]["footer"]:
        print("")
        print(configuration["cwatch"]["footer"])
    print("")
    print(f"Report generated with cwatch {importlib.metadata.version(distribution_name='cwatch')}.")


def get_targets(configuration, targets) -> list:  # noqa: PLR0912
    """Get targets for check with error handling.

    Args:
        configuration: Configuration dictionary
        targets: List to append targets to

    Returns:
        List of target IPs and domains
    """
    domain: str
    for domain in configuration["iocs"]["domains"]:
        public_ip = False
        try:
            # Handle IP addresses in domain list
            if ipaddress.ip_address(address=domain) and not ipaddress.ip_address(address=domain).is_private and domain not in targets:
                targets.append(domain)
                continue
            elif ipaddress.ip_address(address=domain).is_private:
                continue
        except ValueError:
            pass

        # DNS lookup with retry logic
        addresses = None
        delay = INITIAL_RETRY_DELAY
        for attempt in range(MAX_RETRIES + 1):
            try:
                addresses = socket.getaddrinfo(host=domain, port="http", proto=socket.IPPROTO_TCP)
                break
            except socket.gaierror as err:
                if attempt == MAX_RETRIES:
                    print(f"Failed to lookup DNS for {domain} after {MAX_RETRIES} retries: {err}. Skipping this domain.")
                    break
                print(f"DNS lookup attempt {attempt + 1}/{MAX_RETRIES + 1} failed for {domain}: {err}. Retrying in {delay:.1f}s...")
                time.sleep(delay)
                delay = min(delay * 2, MAX_RETRY_DELAY)
            except Exception as err:
                print(f"Unexpected error looking up {domain}: {err}. Skipping this domain.")
                break

        if addresses is None:
            continue

        for address in addresses:
            ip: str = str(address[4][0])
            if ip not in targets and not ipaddress.ip_address(address=ip).is_private:
                public_ip = True
        if public_ip and domain not in targets:
            targets.append(domain)
        for address in addresses:
            ip = str(address[4][0])
            if ip not in targets and not ipaddress.ip_address(address=ip).is_private:
                targets.append(ip)
    return targets

def main() -> None:
    """Main function with two-phase architecture."""
    # Parse command-line arguments
    parser = argparse.ArgumentParser(
        description="Monitor cyberbro for changes in IOCs"
    )
    parser.add_argument(
        "--email-stdout",
        action="store_true",
        help="Output email-formatted report to stdout (useful for cron jobs)"
    )
    args = parser.parse_args()

    # Load configuration with error handling
    try:
        with open(file="cwatch.toml", mode="rb") as file:
            conf: dict[str, Any] = tomllib.load(file)
    except FileNotFoundError:
        print("Error: Configuration file 'cwatch.toml' not found in current directory.")
        print("Please create a configuration file based on 'example-config.toml'.")
        sys.exit(1)
    except tomllib.TOMLDecodeError as err:
        print(f"Error: Invalid TOML configuration file: {err}")
        sys.exit(1)
    except Exception as err:
        print(f"Error loading configuration: {err}")
        sys.exit(1)

    # Setup database if needed
    if not Path(conf["cwatch"]["DB_FILE"]).is_file():
        if not setup_database(configuration=conf):
            print("Error: Failed to setup database. Exiting.")
            sys.exit(1)

    # Phase 1: Data Collection
    from cwatch.collector import DataCollector  # noqa: PLC0415

    collector = DataCollector(conf)
    collected_data = collector.collect_all()

    if collected_data.total_targets == 0:
        print("Warning: No valid targets found. Exiting.")
        sys.exit(0)

    # Phase 2: Reporting
    from cwatch.reporters import get_reporter  # noqa: PLC0415

    report_format = conf["cwatch"].get("output_format", "text")
    reporter = get_reporter(report_format, conf)
    report = reporter.generate(collected_data)

    # Handle email output (for cron)
    if args.email_stdout:
        from cwatch.email_sender import output_email_to_stdout  # noqa: PLC0415

        output_email_to_stdout(conf, collected_data)
    else:
        # Output report to stdout/file
        output_destination = conf["cwatch"].get("output_file")
        if output_destination:
            with open(output_destination, "w") as f:
                f.write(report)
        else:
            print(report)

    # Exit code based on results
    sys.exit(0 if collected_data.successful > 0 else 1)


# Call main if used as a program.
if __name__ == "__main__":
    main()
