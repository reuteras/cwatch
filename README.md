# cwatch

A simple tool to regurarly run queries against [cyberbro](https://github.com/stanfrbd/cyberbro) and generate a report.

## Configuration

Create a directory where you like to store your configuration and database. Create a configuration file named _cwatch.toml_ in that directory, an example is available in the file _example-config.toml _.

### Configuration Sections

#### `[iocs]`
- `domains` - List of domains and IP addresses to monitor

#### `[cyberbro]`
- `url` - URL to your cyberbro instance
- `engines` - List of threat intelligence engines to query

#### `[cwatch]`
- `header` - Report title (e.g., "Report for example.com")
- `footer` - Optional footer text for reports
- `DB_FILE` - SQLite database filename (default: "cwatch.db")

##### Filtering Options
- `ignore_engines` - List of engines to completely ignore in diff comparison
- `ignore_engines_partly` - List of `[engine, field]` pairs to ignore specific fields within engines

##### Output Control
- `quiet` - Set to `true` to suppress "Checking for changes for: [host]" messages (recommended for 100+ hosts)
- `verbose` - Set to `true` to show debug information about filtering

### Output Format

cwatch provides a consistent, two-part output format:

1. **Human-readable summaries** - Markdown-formatted change descriptions for each target as they're processed
2. **Detailed JSON diffs** - Complete technical details in an appendix at the end of the report

New targets show "Initial data collected" on first run, then changes are detected on subsequent runs.

## Install

Run the following in the directory where you have placed _cwatch.toml_.

```
uv venv
uv pip install cwatch
```

## Usage

Run *cwatch*:

```
uv run cwatch
```

Designed to be run from *cron*.
