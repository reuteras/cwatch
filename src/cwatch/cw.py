"""cwatch is a tool to monitor cyberbro for changes for questions."""

import hashlib
import json
import socket
import sqlite3
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
    while not done:
        r = httpx.get(configuration["cyberbro"]["url"] + "/api" + link)
        if r.text != "[]\n":
            done = True
        else:
            time.sleep(1)
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


def detect_changes(configuration, item):
    """Detect changes in json."""
    conn = sqlite3.connect(configuration["cwatch"]["DB_FILE"])
    cursor = conn.cursor()

    # Fetch the last two entries
    cursor.execute(
        """
        SELECT json_content FROM json_data WHERE target = ?
        ORDER BY id DESC LIMIT 2
    """,
        (item,),
    )
    rows = cursor.fetchall()

    if len(rows) == 2:  # noqa: PLR2004
        old_json = json.loads(rows[1][0])[0]
        new_json = json.loads(rows[0][0])[0]
        changes = compare_json(configuration, old_json, new_json)
        if changes != {}:
            print(f"Changes detected for {item}:")
            print(json.dumps(changes, indent=4))
        elif configuration["cwatch"]["report"]:
            print("- No changes.")
    else:
        print("- Not enough data for comparison.")

    conn.close()


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
        print("Ignore changes if the changes only are in:")
        for combo in conf["cwatch"]["ignore_engines_partly"]:
            print(f"- {combo[0]} -> {combo[1]}")
        print("")


def report_footer(conf):
    """Print footer in report mode."""
    print("")
    print(f"Report done at {datetime.now().isoformat()}")
    print(conf["cwatch"]["footer"])


def main():
    """Main function."""
    targets = []

    with open("cwatch.toml", "rb") as file:
        conf = tomllib.load(file)

    if conf["cwatch"]["report"]:
        report_header(conf)

    if not Path(conf["cwatch"]["DB_FILE"]).is_file():
        setup_database(conf)

    # Create list with domains and their IP addresses
    for domain in conf["iocs"]["domains"]:
        addresses = socket.getaddrinfo(domain, "http", proto=socket.IPPROTO_TCP)
        if domain not in targets:
            targets.append(domain)
        for address in addresses:
            ip = address[4][0]
            if ip not in targets:
                targets.append(ip)

    # Check for changes
    for item in targets:
        if conf["cwatch"]["report"]:
            print(f"Checking for changes for: {item}")
        request_id = submit_request(conf, item)
        results_json = get_response(conf, request_id["link"])
        save_json_data(conf, item, results_json)
        detect_changes(conf, item)

    if conf["cwatch"]["report"]:
        report_footer(conf)


# Call main if used as a program.
if __name__ == "__main__":
    main()
