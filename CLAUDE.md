# cwatch Project Instructions

## Project Overview

cwatch is a monitoring tool that regularly queries [cyberbro](https://github.com/stanfrbd/cyberbro) to track changes in security intelligence data for specified domains and IP addresses. It stores historical data in SQLite and reports on changes detected across various security engines.

## Key Architecture

### Two-Phase Design
1. **Data Collection Phase** (`collector.py`): Queries cyberbro API for each target and stores results
2. **Reporting Phase** (`reporters.py`): Analyzes collected data and generates reports in multiple formats

### Core Components
- **cw.py**: Main entry point and core logic (API communication, database operations, change detection)
- **data_structures.py**: Data models for targets and collected results
- **reporters.py**: Report generation (text, JSON, HTML formats)
- **collector.py**: Data collection logic
- **email_sender.py**: Email output functionality

## Development Guidelines

### Python Environment
- Always run Python as `uv run python` (per user's global instructions)
- Use `uv sync` for dependency management
- Use `uv run pytest` for testing

### Code Style
- Follow existing patterns in the codebase
- Use type hints consistently
- Add docstrings for all functions
- Handle errors gracefully with try/except blocks
- Use configuration dictionary for all settings

### Important Functions

#### Change Detection
- `normalize_json()`: Normalizes JSON data to ignore order-only changes by sorting dicts and lists recursively
- `calculate_hash()`: Creates SHA256 hash of normalized JSON for change detection
- `compare_json()`: Compares normalized old and new JSON using jsondiff
- `detect_changes()`: Main function that fetches last two database entries and compares them

#### Filtering Logic
Each security engine has a handler function that filters out non-relevant changes:
- `handle_abuseipdb()`: Filters zero-risk/zero-report entries
- `handle_shodan()`: Filters null entries
- `handle_threatfox()`: Filters zero-count threats
- `handle_virustotal()`: Filters zero-malicious/zero-score entries
- `handle_abusix()`: Filters whitelisted abuse email addresses

### Configuration

#### Key Config Options (cwatch.toml)
- `output_format`: "text" (default, user-friendly), "json", or "html"
- `quiet`: Filters out noise (zero-risk items, no-match results)
- `report`: Includes headers/footers vs. changes-only output
- `ignore_engines`: Completely skip these engines in reports
- `ignore_engines_partly`: Ignore specific fields within engines
- `ignore_abuse_addresses`: Whitelist abuse emails to not report as changes

#### Default Behavior
- Default output is **text format** with user-friendly summaries (not JSON)
- Changes are normalized to ignore order-only differences
- Text format shows readable summaries with links for each engine

### Database
- SQLite database stores: target, timestamp, json_hash, json_content
- Comparison uses last two entries per target
- Hash-based deduplication prevents storing identical data

### Testing
- Test changes with different configurations (quiet mode, report mode, etc.)
- Verify filtering logic doesn't remove legitimate changes
- Test with all three output formats (text, json, html)

## Common Tasks

### Adding a New Security Engine Handler
1. Add handler function in `cw.py` following pattern of existing handlers
2. Import and call in `handle_changes()` function
3. Import in `reporters.py` and add to `_filter_changes()`
4. Update text reporter's `_format_changes_readable()` for custom formatting
5. Update HTML reporter's badge/summary/links methods if needed

### Modifying Output Format
- Text format: Update `TextReporter._format_changes_readable()`
- JSON format: Update `JsonReporter.generate()`
- HTML format: Update `HtmlReporter` methods

### Adding Configuration Options
1. Add to `example-config.toml` with comments
2. Access via `configuration["cwatch"]["option_name"]`
3. Provide sensible defaults with `.get("option_name", default_value)`

## Important Notes

- Changes that only affect the order of items in arrays are ignored (via `normalize_json()`)
- Abuse addresses can be whitelisted to prevent false positives for your own domains
- The tool is designed to run from cron jobs
- Exit code 0 if any successful checks, 1 if all failed
