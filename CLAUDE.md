# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

cwatch is a Python tool that monitors cyberbro API queries for changes and generates reports. It's designed to regularly check threat intelligence data for specified domains/IPs and detect changes over time.

## Core Architecture

The application is structured as a single-module Python package:

- `src/cwatch/cw.py` - Main application logic containing all functionality
- `src/cwatch/__init__.py` - Entry point that imports and calls main()
- Configuration via TOML files (example in `example-config.toml`)
- SQLite database for storing query results and tracking changes

## Key Components

- **Configuration Management**: Uses TOML configuration files with sections for IOCs, cyberbro settings, and cwatch options
- **Data Flow**: Submit requests to cyberbro → Poll for results → Store in SQLite → Compare with previous results → Report changes
- **Change Detection**: JSON diffing with configurable engine filtering and partial ignoring
- **Database Schema**: Stores target, timestamp, JSON hash, and full JSON content for comparison

## Development Commands

### Installation and Setup

```bash
uv venv
uv pip install -e .
```

### Development Dependencies

```bash
uv pip install -e .[dev]  # Installs pre-commit, pylint, ruff
```

### Code Quality

```bash
ruff check .      # Lint with ruff
ruff format .     # Format code
pylint src/       # Additional linting with pylint
```

### Running the Application

```bash
uv run cwatch     # Run from any directory with cwatch.toml
```

## Configuration Structure

The application expects a `cwatch.toml` file in the working directory with:

- `[iocs]` - List of domains to monitor
- `[cyberbro]` - API URL and engines to use
- `[cwatch]` - Application settings including database file, reporting options, and engine filtering

### New Reporting Options

- `markdown_report = true` - Use markdown formatting for human-readable change summaries instead of raw JSON
- `summary_report = true` - Generate a summary section at the end showing all changes
- `detailed_appendix = true` - Include detailed JSON diffs as an appendix for full technical details

## Code Style

- Uses Google-style docstrings (configured in pyproject.toml)
- Ruff configuration targets Python 3.11+ with comprehensive rule set
- Type hints throughout with explicit return types
- Defensive programming with extensive exception handling
