"""cwatch is a tool to monitor cyberbro for changes for questions."""

import hashlib
import importlib.metadata
import ipaddress
import json
import socket
import sqlite3
import sys
import time
import tomllib
from datetime import datetime
from http.client import HTTPException
from pathlib import Path
from typing import Any, cast

import httpcore
import httpx
import jsondiff


def submit_request(configuration, name) -> dict:
    """Submit question to Cyberbro."""
    data: dict[str, dict] = {
        "text": name,
        "engines": configuration["cyberbro"]["engines"],
    }
    try:
        r: httpx.Response = httpx.post(
            url=configuration["cyberbro"]["url"] + "/analyze", json=data
        )
    except (httpcore.ConnectError, HTTPException):
        return {}
    try:
        return json.loads(r.text)
    except Exception as err:
        print(f"Error submitting request: {r.text}. Error was {err}")
        return {}


def get_response(configuration, link) -> dict:
    """Get the response from Cyberbro."""
    done: bool = False
    r: httpx.Response | None = None
    connect_error_count: int = 0

    while not done:
        try:
            r = httpx.get(url=configuration["cyberbro"]["url"] + link)
        except HTTPException:
            time.sleep(1)
            continue
        except httpcore.ConnectError:
            if connect_error_count > 5:  # noqa: PLR2004
                print("Can't connect to server. Exiting.")
                sys.exit(1)
            connect_error_count += 1
            time.sleep(1)
            continue
        if r.text != "[]\n":
            done = True
        else:
            time.sleep(1)

    assert r is not None
    return json.loads(r.text)


def setup_database(configuration) -> None:
    """Create database."""
    conn: sqlite3.Connection = sqlite3.connect(
        database=configuration["cwatch"]["DB_FILE"]
    )
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


def calculate_hash(json_data) -> str:
    """Function to calculate a hash for a JSON object."""
    json_string: str = json.dumps(obj=json_data, sort_keys=True)
    return hashlib.sha256(string=json_string.encode(encoding="utf-8")).hexdigest()


def save_json_data(configuration, item, json_data) -> None:
    """Save JSON data if changes are detected."""
    conn: sqlite3.Connection = sqlite3.connect(
        database=configuration["cwatch"]["DB_FILE"]
    )
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


def handle_abuseipdb(change) -> dict:
    """Remove change from abuseipdb if no relevant changes."""
    report = True
    if isinstance(change["abuseipdb"], list) and len(change["abuseipdb"]) == 2:  # noqa: PLR2004
        if (
            "reports" in change["abuseipdb"][1]
            and "risk_score" in change["abuseipdb"][1]
        ):
            if (
                change["abuseipdb"][1]["reports"] == 0
                and change["abuseipdb"][1]["risk_score"] == 0
            ):
                report = False
        else:
            report = False
    if "reports" in change["abuseipdb"] and "risk_score" in change["abuseipdb"]:
        if (
            change["abuseipdb"]["reports"] == 0
            and change["abuseipdb"]["risk_score"] == 0
        ):
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
        if isinstance(change["threatfox"], list) and len(change["threatfox"]) == 2:  # noqa: PLR2004
            if (
                "count" in change["threatfox"][1]
                and change["threatfox"][1]["count"] == 0
                and "malware_printable" in change["threatfox"][1]
                and change["threatfox"][1]["malware_printable"] == []
            ):
                report = False
            elif change["threatfox"][1] is None:
                report = False
        if change["threatfox"] is None or ("count" in change["threatfox"]):
            if (
                change["threatfox"]["count"] == 0
                and change["threatfox"]["malware_printable"] == []
            ):
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
    if isinstance(change["virustotal"], list) and len(change["virustotal"]) == 2:  # noqa: PLR2004
        if change["virustotal"][1] is None:
            report = False
        elif (
            "community_score" in change["virustotal"][1]
            and change["virustotal"][1]["community_score"] == 0
            and "total_malicious" in change["virustotal"][1]
            and change["virustotal"][1]["total_malicious"] == 0
        ):
            report = False
    if change["virustotal"] is None or ("community_score" in change["virustotal"]):
        if (
            change["virustotal"]["community_score"] == 0
            and change["virustotal"]["total_malicious"] == 0
        ):
            report = False
    if not report:
        change.pop("virustotal")
    return change


def format_value_change(old_val: Any, new_val: Any) -> str:
    """Format a value change in a human-readable way."""
    if isinstance(old_val, dict | list) and isinstance(new_val, dict | list):
        return f"Updated from {len(old_val) if hasattr(old_val, '__len__') else 'N/A'} to {len(new_val) if hasattr(new_val, '__len__') else 'N/A'} items"
    if old_val is None:
        return f"Added: {new_val}"
    if new_val is None:
        return f"Removed: {old_val}"
    return f"Changed from '{old_val}' to '{new_val}'"


def format_engine_changes(engine: str, change_data: Any) -> str:
    """Format changes for a specific engine in a human-readable way."""
    if isinstance(change_data, list) and len(change_data) == 2:  # noqa: PLR2004
        old_val, new_val = change_data
        return format_value_change(old_val, new_val)
    elif isinstance(change_data, dict):
        changes = []
        for key, value in change_data.items():
            if isinstance(value, list) and len(value) == 2:  # noqa: PLR2004
                changes.append(f"  - {key}: {format_value_change(value[0], value[1])}")
            else:
                changes.append(f"  - {key}: {value}")
        return "\n".join(changes)
    else:
        return str(change_data)


def generate_markdown_summary(target: str, changes: dict) -> str:
    """Generate a markdown summary of changes."""
    lines = [f"### Changes for {target}"]

    for engine, change_data in changes.items():
        lines.append(f"\n**{engine.upper()}:**")
        formatted_change = format_engine_changes(engine, change_data)
        lines.append(formatted_change)

    return "\n".join(lines)


def handle_changes(
    configuration, target: str, changes: dict, all_changes: list | None = None
) -> bool:
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
            # Store changes for summary report
            if all_changes is not None:
                all_changes.append({"target": target, "changes": changes.copy()})

            if configuration["cwatch"].get("markdown_report", False):
                print(generate_markdown_summary(target, changes))
            else:
                print(f"Changes detected for {target}:")
                print(json.dumps(obj=changes, indent=4))
            return True
        return False

    # Store changes for summary report
    if all_changes is not None:
        all_changes.append({"target": target, "changes": changes.copy()})

    if configuration["cwatch"].get("markdown_report", False):
        print(generate_markdown_summary(target, changes))
    else:
        print(f"Changes detected for {target}:")
        print(json.dumps(changes, indent=4))
    return True


def detect_changes(configuration, item, all_changes: list | None = None) -> bool:
    """Detect changes in json."""
    conn: sqlite3.Connection = sqlite3.connect(
        database=configuration["cwatch"]["DB_FILE"]
    )
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

    if len(rows) == 2:  # noqa: PLR2004
        old_json: dict = json.loads(rows[1][0])[0]
        new_json: dict = json.loads(rows[0][0])[0]
        changes: dict = compare_json(
            configuration=configuration, old=old_json, new=new_json
        )
        if changes != {}:
            changed: bool = handle_changes(
                configuration=configuration,
                target=item,
                changes=changes,
                all_changes=all_changes,
            )
        if configuration["cwatch"]["report"] and not configuration["cwatch"]["quiet"]:
            print("- No changes.")
    elif not configuration["cwatch"]["quiet"]:
        print("- Not enough data for comparison.")

    conn.close()
    return changed


def compare_json(configuration, old, new) -> dict:
    """Compare json objects."""
    simple: bool = configuration["cwatch"]["simple"]
    verbose: bool = configuration["cwatch"]["verbose"]
    if simple:
        diff = jsondiff.diff(old, new, syntax="symmetric")
        return diff if isinstance(diff, dict) else {}
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
    engines: list = configuration["cyberbro"]["engines"]
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


def generate_summary_report(configuration, all_changes: list) -> None:
    """Generate a summary report of all changes."""
    if not all_changes:
        return

    print("\n## Summary of Changes\n")

    for item in all_changes:
        target = item["target"]
        changes = item["changes"]

        if configuration["cwatch"].get("markdown_report", False):
            print(generate_markdown_summary(target, changes))
            print("")
        else:
            print(f"**{target}:**")
            for engine in changes.keys():
                print(f"  - {engine}")
            print("")


def generate_detailed_appendix(configuration, all_changes: list) -> None:
    """Generate detailed JSON diff appendix."""
    if not all_changes or not configuration["cwatch"].get("detailed_appendix", False):
        return

    print("\n---\n")
    print("## Detailed Changes (JSON Diff)\n")

    for item in all_changes:
        target = item["target"]
        changes = item["changes"]

        print(f"### {target}\n")
        print("```json")
        print(json.dumps(changes, indent=2))
        print("```\n")


def report_footer(configuration, all_changes: list | None = None) -> None:
    """Print footer in report mode."""
    # Generate summary if we have collected changes and it's enabled
    if all_changes and configuration["cwatch"].get("summary_report", False):
        generate_summary_report(configuration, all_changes)

    # Generate detailed appendix if enabled
    if all_changes:
        generate_detailed_appendix(configuration, all_changes)

    print("")
    print(f"Report done at {datetime.now().isoformat()}.")
    if configuration["cwatch"]["footer"]:
        print("")
        print(configuration["cwatch"]["footer"])
    print("")
    print(
        f"Report generated with cwatch {importlib.metadata.version(distribution_name='cwatch')}."
    )


def get_targets(configuration, targets) -> list:
    """Get targets for check."""
    domain: str
    for domain in configuration["iocs"]["domains"]:
        public_ip = False
        try:
            # Handle IP addresses in domain list
            if (
                ipaddress.ip_address(address=domain)
                and not ipaddress.ip_address(address=domain).is_private
                and domain not in targets
            ):
                targets.append(domain)
                continue
            elif ipaddress.ip_address(address=domain).is_private:
                continue
        except ValueError:
            pass
        try:
            addresses = socket.getaddrinfo(
                host=domain, port="http", proto=socket.IPPROTO_TCP
            )
        except Exception as err:
            print(f"Error looking up ip for domain {domain}: {err}")
            sys.exit(1)
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
    """Main function."""
    targets: list[str] = []
    changes: bool = False
    all_changes: list = []

    with open(file="cwatch.toml", mode="rb") as file:
        conf: dict[str, Any] = tomllib.load(file)

    if conf["cwatch"]["report"]:
        report_header(configuration=conf)

    if not Path(conf["cwatch"]["DB_FILE"]).is_file():
        setup_database(configuration=conf)

    # Create list with domains and their IP addresses
    get_targets(configuration=conf, targets=targets)

    # Check for changes
    if conf["cwatch"]["report"]:
        print(f"Will check {len(targets)} hosts.")
    item: str
    for item in targets:
        if conf["cwatch"]["report"] and not conf["cwatch"]["quiet"]:
            print(f"Checking for changes for: {item}")
        request_id: dict = submit_request(configuration=conf, name=item)
        if not request_id or request_id == {}:
            print(f"Error submitting request for {item}.")
            continue
        results_json: dict = get_response(configuration=conf, link=request_id["link"])
        save_json_data(configuration=conf, item=item, json_data=results_json)
        if detect_changes(configuration=conf, item=item, all_changes=all_changes):
            changes = True

    if conf["cwatch"]["report"] and conf["cwatch"]["quiet"] and not changes:
        print("")
        print("No changes to report.")
    if conf["cwatch"]["report"]:
        report_footer(configuration=conf, all_changes=all_changes)


# Call main if used as a program.
if __name__ == "__main__":
    main()
