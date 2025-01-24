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
from pathlib import Path

import httpx
import jsondiff


def submit_request(configuration, name):
    """Submit question to Cybero."""
    data = {"text": name, "engines": configuration["cyberbro"]["engines"]}
    r = httpx.post(configuration["cyberbro"]["url"] + "/api/analyze", json=data)
    try:
        return json.loads(r.text)
    except Exception as err:
        print(f"Error submiting request: {r.text}. Error was {err}")
        return ""


def get_response(configuration, link):
    """Get the response from Cybero."""
    done = False
    r = None

    while not done:
        r = httpx.get(configuration["cyberbro"]["url"] + "/api" + link)
        if r.text != "[]\n":
            done = True
        else:
            time.sleep(1)

    assert r is not None
    return json.loads(r.text)


def setup_database(configuration):
    """Create database."""
    conn = sqlite3.connect(configuration["cwatch"]["DB_FILE"])
    cursor = conn.cursor()
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


def calculate_hash(json_data):
    """Function to calculate a hash for a JSON object."""
    json_string = json.dumps(json_data, sort_keys=True)
    return hashlib.sha256(json_string.encode("utf-8")).hexdigest()


def save_json_data(configuration, item, json_data):
    """Save JSON data if changes are detected."""
    conn = sqlite3.connect(configuration["cwatch"]["DB_FILE"])
    cursor = conn.cursor()

    # Calculate hash for the current JSON
    json_hash = calculate_hash(json_data)

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


def handle_abuseipdb(change):
    """Remove change from abuseipdb if no relevant changes."""
    report = True
    if isinstance(change["abuseipdb"], list) and len(change["abuseipdb"]) == 2: # noqa: PLR2004
        if change["abuseipdb"][1]["reports"] == 0 and change["abuseipdb"][1]["risk_score"] == 0:
            report = False
    if "reports" in change["abuseipdb"] and "risk_score" in change["abuseipdb"]:
        if change["abuseipdb"]["reports"] == 0 and change["abuseipdb"]["risk_score"] == 0:
            report = False
    if not report:
        change.pop("abuseipdb")
    return change


def handle_shodan(change):
    """Remove change from shodan if change is to null."""
    if "link" not in change["shodan"]:
        change.pop("shodan")
    return change


def handle_threatfox(change):
    """Remove change from threatfox if no matches."""
    report = True
    if isinstance(change["threatfox"], list) and len(change["threatfox"]) == 2: # noqa: PLR2004
        if "count" in change["threatfox"][1] and change["threatfox"][1]["count"] == 0 \
                and "malware_printable" in change["threatfox"][1] and change["threatfox"][1]["malware_printable"] == []:
            report = False
        elif change["threatfox"][1] is None:
            report = False
    if change["threatfox"] is None or ("count" in change["threatfox"]):
        if change["threatfox"]["count"] == 0 and change["threatfox"]["malware_printable"] == []:
            report = False
    if not report:
        change.pop("threatfox")
    return change


def handle_virustotal(change):
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


def handle_changes(configuration, target, changes):
    """Handle changes."""
    if configuration["cwatch"]["quiet"]:
        if "abuseipdb" in changes:
            changes = handle_abuseipdb(changes)
        if "shodan" in changes:
            changes = handle_shodan(changes)
        if "threatfox" in changes:
            changes = handle_threatfox(changes)
        if "virustotal" in changes:
            changes = handle_virustotal(changes)
        if changes != {}:
            print(f"Changes detected for {target}:")
            print(json.dumps(changes, indent=4))
            return True
        return False
    print(f"Changes detected for {target}:")
    print(json.dumps(changes, indent=4))
    return True


def detect_changes(configuration, item):
    """Detect changes in json."""
    conn = sqlite3.connect(configuration["cwatch"]["DB_FILE"])
    cursor = conn.cursor()
    changes = False

    # Fetch the last two entries
    cursor.execute(
        """
        SELECT json_content FROM json_data WHERE target = ?
        ORDER BY id DESC LIMIT 2
    """,
        (item,),
    )
    rows = cursor.fetchall()

    if len(rows) == 2: # noqa: PLR2004
        old_json = json.loads(rows[1][0])[0]
        new_json = json.loads(rows[0][0])[0]
        changes = compare_json(configuration, old_json, new_json)
        if changes != {}:
            changes = handle_changes(configuration, item, changes)
        if configuration["cwatch"]["report"] and not configuration["cwatch"]["quiet"]:
            print("- No changes.")
    elif not configuration["cwatch"]["quiet"]:
        print("- Not enough data for comparison.")

    conn.close()
    return changes


def compare_json(configuration, old, new):
    """Compare json objects."""
    simple = configuration["cwatch"]["simple"]
    verbose = configuration["cwatch"]["verbose"]
    if simple:
        return jsondiff.diff(old, new, syntax="symmetric")
    diff = json.loads(jsondiff.diff(old, new, syntax="symmetric", dump=True))
    for engine in configuration["cwatch"]["ignore_engines"]:
        if engine in diff:
            removed = diff.pop(engine)
            if verbose:
                print(f"Removed diff in {engine}: {removed}")
    for combo in configuration["cwatch"]["ignore_engines_partly"]:
        engine = combo[0]
        part = combo[1]
        if engine in diff:
            if part in diff[engine]:
                removed = diff[engine].pop(part)
                if verbose:
                    print(f"Removed diff in {engine}->{part}: {removed}")
            if diff[engine] == {}:
                diff.pop(engine)
    return diff


def report_header(conf):
    """Print header in report mode."""
    print(conf["cwatch"]["header"])
    print("=" * len(conf["cwatch"]["header"]))
    print("")
    print(f"Report generation start at {datetime.now().isoformat()}")
    print("")
    print("Will report changes in the following engines.")
    engines = conf["cyberbro"]["engines"]
    engines.sort()
    for engine in engines:
        if engine not in conf["cwatch"]["ignore_engines"]:
            print(f"- {engine}")
    print("")
    if conf["cwatch"]["ignore_engines_partly"]:
        print("Ignore change if the only change is in one of:")
        for combo in conf["cwatch"]["ignore_engines_partly"]:
            print(f"- {combo[0]} -> {combo[1]}")
        print("")


def report_footer(conf):
    """Print footer in report mode."""
    print("")
    print(f"Report done at {datetime.now().isoformat()}.")
    if conf["cwatch"]["footer"]:
        print("")
        print(conf["cwatch"]["footer"])
    print("")
    print(f"Report generated with cwatch {importlib.metadata.version('cwatch')}.")


def get_targets(configuration, targets):
    """Get targets for check."""
    for domain in configuration["iocs"]["domains"]:
        public_ip = False
        try:
            addresses = socket.getaddrinfo(domain, "http", proto=socket.IPPROTO_TCP)
        except Exception as err:
            print(f"Error looking up ip for domain {domain}: {err}")
            sys.exit(1)
        for address in addresses:
            ip = address[4][0]
            if ip not in targets and not ipaddress.ip_address(ip).is_private:
                public_ip = True
        if public_ip and domain not in targets:
            targets.append(domain)
        for address in addresses:
            ip = address[4][0]
            if ip not in targets and not ipaddress.ip_address(ip).is_private:
                targets.append(ip)
    return targets

def main():
    """Main function."""
    targets = []
    changes = False

    with open("cwatch.toml", "rb") as file:
        conf = tomllib.load(file)

    if conf["cwatch"]["report"]:
        report_header(conf)

    if not Path(conf["cwatch"]["DB_FILE"]).is_file():
        setup_database(conf)

    # Create list with domains and their IP addresses
    get_targets(conf, targets)

    # Check for changes
    if conf["cwatch"]["report"]:
        print(f"Will check {len(targets)} hosts.")
    for item in targets:
        if conf["cwatch"]["report"] and not conf["cwatch"]["quiet"]:
            print(f"Checking for changes for: {item}")
        request_id = submit_request(conf, item)
        results_json = get_response(conf, request_id["link"])
        save_json_data(conf, item, results_json)
        if detect_changes(conf, item):
            changes = True

    if conf["cwatch"]["report"] and conf["cwatch"]["quiet"] and not changes:
        print("")
        print("No changes to report.")
    if conf["cwatch"]["report"]:
        report_footer(conf)


# Call main if used as a program.
if __name__ == "__main__":
    main()
