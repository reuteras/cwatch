# cwatch Refactoring Design Document

## Overview

This document outlines the design for refactoring cwatch into a two-phase architecture that separates data collection from reporting/presentation. This separation will improve code maintainability, testability, and enable flexible output formats.

## Current Architecture Issues

### Problems with Current Design

1. **Tight Coupling**: Data collection and reporting are interleaved in the main loop (lines 508-527 in cw.py)
2. **Limited Flexibility**: Cannot easily add new output formats (JSON, CSV, HTML, etc.)
3. **Poor Testability**: Hard to test reporting logic independently from data collection
4. **No Batching**: Cannot optimize database operations or parallelize API calls
5. **Immediate Output**: Prints as it goes, making it hard to control final presentation
6. **Error Handling**: Partial failures may produce incomplete reports

### Current Flow

```text
For each target:
  1. Submit API request
  2. Get response
  3. Save to database
  4. Detect changes
  5. Print changes immediately  ← Tightly coupled
```

## Proposed Two-Phase Architecture

### Phase 1: Data Collection

Responsibilities:
- Resolve targets (DNS, IPs)
- Submit API requests to cyberbro
- Poll for results
- Save results to database
- Detect changes
- Collect all data and changes into structured format
- Handle errors gracefully (continue processing other targets)

Output: Structured data object containing all results

### Phase 2: Reporting & Presentation

Responsibilities:
- Accept structured data from Phase 1
- Apply filtering rules (quiet mode, engine ignoring)
- Format output according to selected reporter
- Generate final report

Output: Formatted report (text, JSON, HTML, etc.)

### New Flow

```text
Phase 1 (Data Collection):
  For each target:
    1. Submit API request
    2. Get response
    3. Save to database
    4. Detect changes
    5. Store in collection structure

  Return: CollectedData object

Phase 2 (Reporting):
  1. Accept CollectedData
  2. Apply filters
  3. Generate report based on format
  4. Output to destination (stdout, file, etc.)
```

## Detailed Design

### Data Structures

#### CollectedData

```python
@dataclass
class TargetResult:
    """Results for a single target."""
    target: str
    success: bool
    timestamp: datetime
    response: dict | None
    changes: dict | None
    errors: list[str]
    metadata: dict  # For additional info like retry counts, timing, etc.

@dataclass
class CollectedData:
    """Collection of all target results."""
    targets: list[TargetResult]
    configuration: dict
    collection_start: datetime
    collection_end: datetime
    total_targets: int
    successful: int
    failed: int

    def has_changes(self) -> bool:
        """Check if any target has changes."""
        return any(t.changes for t in self.targets if t.success)

    def get_targets_with_changes(self) -> list[TargetResult]:
        """Get only targets that have changes."""
        return [t for t in self.targets if t.success and t.changes]
```

### Module Structure

#### 1. Data Collection Module (`collector.py`)

```python
class DataCollector:
    """Handles all data collection operations."""

    def __init__(self, configuration: dict):
        self.config = configuration
        self.targets: list[str] = []

    def collect_all(self) -> CollectedData:
        """Main entry point for data collection."""
        start_time = datetime.now()
        results = []

        # Resolve targets
        self.targets = self._resolve_targets()

        # Collect data for each target
        for target in self.targets:
            result = self._collect_target(target)
            results.append(result)

        end_time = datetime.now()

        return CollectedData(
            targets=results,
            configuration=self.config,
            collection_start=start_time,
            collection_end=end_time,
            total_targets=len(results),
            successful=sum(1 for r in results if r.success),
            failed=sum(1 for r in results if not r.success)
        )

    def _resolve_targets(self) -> list[str]:
        """Resolve all targets from configuration."""
        # Current get_targets() logic
        pass

    def _collect_target(self, target: str) -> TargetResult:
        """Collect data for a single target."""
        errors = []

        try:
            # Submit request
            request_id = submit_request(self.config, target)
            if not request_id:
                return TargetResult(
                    target=target,
                    success=False,
                    timestamp=datetime.now(),
                    response=None,
                    changes=None,
                    errors=["Failed to submit request"]
                )

            # Get response
            response = get_response(self.config, request_id["link"])
            if not response:
                return TargetResult(
                    target=target,
                    success=False,
                    timestamp=datetime.now(),
                    response=None,
                    changes=None,
                    errors=["Failed to get response"]
                )

            # Save to database
            if not save_json_data(self.config, target, response):
                errors.append("Failed to save to database")

            # Detect changes
            changes = self._detect_changes_for_target(target)

            return TargetResult(
                target=target,
                success=True,
                timestamp=datetime.now(),
                response=response,
                changes=changes,
                errors=errors,
                metadata={}
            )

        except Exception as e:
            return TargetResult(
                target=target,
                success=False,
                timestamp=datetime.now(),
                response=None,
                changes=None,
                errors=[str(e)],
                metadata={}
            )
```

#### 2. Reporting Module (`reporters.py`)

```python
from abc import ABC, abstractmethod

class Reporter(ABC):
    """Base class for all reporters."""

    def __init__(self, configuration: dict):
        self.config = configuration

    @abstractmethod
    def generate(self, data: CollectedData) -> str:
        """Generate report from collected data."""
        pass

    def _filter_changes(self, changes: dict) -> dict:
        """Apply filtering rules based on configuration."""
        if not self.config["cwatch"]["quiet"]:
            return changes

        filtered = changes.copy()

        # Apply engine-specific filtering
        if "abuseipdb" in filtered:
            filtered = handle_abuseipdb(filtered)
        if "shodan" in filtered:
            filtered = handle_shodan(filtered)
        if "threatfox" in filtered:
            filtered = handle_threatfox(filtered)
        if "virustotal" in filtered:
            filtered = handle_virustotal(filtered)

        return filtered


class TextReporter(Reporter):
    """Traditional text-based reporter (current behavior)."""

    def generate(self, data: CollectedData) -> str:
        """Generate text report."""
        output = []

        # Header
        output.append(self._generate_header(data))

        # Target results
        for target_result in data.targets:
            if not target_result.success:
                output.append(f"\nError processing {target_result.target}:")
                output.extend(f"  - {error}" for error in target_result.errors)
                continue

            if target_result.changes:
                filtered_changes = self._filter_changes(target_result.changes)
                if filtered_changes:
                    output.append(f"\nChanges detected for {target_result.target}:")
                    output.append(json.dumps(filtered_changes, indent=4))

        # Footer
        output.append(self._generate_footer(data))

        return "\n".join(output)

    def _generate_header(self, data: CollectedData) -> str:
        """Generate report header."""
        lines = []
        lines.append(self.config["cwatch"]["header"])
        lines.append("=" * len(self.config["cwatch"]["header"]))
        lines.append("")
        lines.append(f"Report generation start at {data.collection_start.isoformat()}")
        lines.append("")
        lines.append(f"Will check {data.total_targets} hosts.")
        # ... rest of header logic
        return "\n".join(lines)

    def _generate_footer(self, data: CollectedData) -> str:
        """Generate report footer."""
        lines = []
        lines.append("")
        lines.append(f"Report done at {data.collection_end.isoformat()}.")
        if self.config["cwatch"]["footer"]:
            lines.append("")
            lines.append(self.config["cwatch"]["footer"])
        lines.append("")
        lines.append(f"Report generated with cwatch {importlib.metadata.version('cwatch')}.")
        return "\n".join(lines)


class JsonReporter(Reporter):
    """JSON output reporter."""

    def generate(self, data: CollectedData) -> str:
        """Generate JSON report."""
        report = {
            "metadata": {
                "collection_start": data.collection_start.isoformat(),
                "collection_end": data.collection_end.isoformat(),
                "total_targets": data.total_targets,
                "successful": data.successful,
                "failed": data.failed,
            },
            "targets": []
        }

        for target_result in data.targets:
            target_data = {
                "target": target_result.target,
                "success": target_result.success,
                "timestamp": target_result.timestamp.isoformat(),
            }

            if target_result.success:
                filtered_changes = self._filter_changes(target_result.changes or {})
                target_data["changes"] = filtered_changes
            else:
                target_data["errors"] = target_result.errors

            report["targets"].append(target_data)

        return json.dumps(report, indent=2)


class HtmlReporter(Reporter):
    """HTML output reporter."""

    def generate(self, data: CollectedData) -> str:
        """Generate HTML report."""
        # Implementation for HTML report
        pass


class CsvReporter(Reporter):
    """CSV output reporter."""

    def generate(self, data: CollectedData) -> str:
        """Generate CSV report."""
        # Implementation for CSV report
        pass


def get_reporter(format_type: str, configuration: dict) -> Reporter:
    """Factory function to get appropriate reporter."""
    reporters = {
        "text": TextReporter,
        "json": JsonReporter,
        "html": HtmlReporter,
        "csv": CsvReporter,
    }

    reporter_class = reporters.get(format_type, TextReporter)
    return reporter_class(configuration)
```

#### 3. Updated Main Function

```python
def main() -> None:
    """Main function with two-phase architecture."""
    # Load configuration
    try:
        with open("cwatch.toml", "rb") as file:
            config = tomllib.load(file)
    except FileNotFoundError:
        print("Error: Configuration file 'cwatch.toml' not found.")
        sys.exit(1)
    except tomllib.TOMLDecodeError as err:
        print(f"Error: Invalid TOML configuration file: {err}")
        sys.exit(1)

    # Setup database if needed
    if not Path(config["cwatch"]["DB_FILE"]).is_file():
        if not setup_database(config):
            print("Error: Failed to setup database. Exiting.")
            sys.exit(1)

    # Phase 1: Data Collection
    collector = DataCollector(config)
    collected_data = collector.collect_all()

    # Phase 2: Reporting
    report_format = config["cwatch"].get("output_format", "text")
    reporter = get_reporter(report_format, config)
    report = reporter.generate(collected_data)

    # Output report
    output_destination = config["cwatch"].get("output_file")
    if output_destination:
        with open(output_destination, "w") as f:
            f.write(report)
    else:
        print(report)

    # Exit code based on results
    sys.exit(0 if collected_data.successful > 0 else 1)
```

## Configuration Changes

Add new configuration options to `cwatch.toml`:

```toml
[cwatch]
# ... existing options ...

# Output format: text, json, html, csv
output_format = "text"

# Optional: write to file instead of stdout
output_file = ""  # empty string means stdout

# Optional: parallel processing
parallel_requests = false
max_workers = 5
```

## Migration Path

### Phase 1: Add Tests (DONE)
- ✅ Comprehensive test coverage for existing functionality

### Phase 2: Refactor Incrementally
1. Create new modules (`collector.py`, `reporters.py`)
2. Implement `DataCollector` class
3. Implement `TextReporter` (maintaining current behavior)
4. Update `main()` to use new architecture
5. Run tests to ensure behavior unchanged

### Phase 3: Add New Features
1. Implement `JsonReporter`
2. Implement `HtmlReporter`
3. Add parallel processing option
4. Add output file option

### Phase 4: Cleanup
1. Remove deprecated code
2. Update documentation
3. Update examples

## Benefits

### 1. Separation of Concerns
- Data collection logic isolated from presentation
- Each phase has single responsibility
- Easier to test and maintain

### 2. Flexibility
- Easy to add new output formats
- Can output to multiple destinations
- Can process data multiple times without re-collecting

### 3. Performance
- Can batch database operations
- Can parallelize API requests
- Better error recovery

### 4. Testability
- Can test collectors independently
- Can test reporters with mock data
- Integration tests easier to write

### 5. User Experience
- Consistent report formatting
- Better error messages
- Progress indicators possible
- Can generate multiple report types from single run

## Future Enhancements

1. **Parallel Data Collection**: Use asyncio or multiprocessing
2. **Report Comparison**: Compare multiple reports over time
3. **Webhook Reporter**: POST results to webhook
4. **Dashboard**: Real-time web dashboard
5. **Report Templates**: Customizable templates for HTML reports
6. **Change Alerting**: Integrate with alerting systems (Slack, PagerDuty, etc.)

## Testing Strategy

### Unit Tests
- Test each collector method independently
- Test each reporter format independently
- Test filtering logic
- Test error handling

### Integration Tests
- Test full flow with mock API
- Test database interactions
- Test configuration loading

### End-to-End Tests
- Test with real cyberbro instance (optional)
- Test all output formats
- Test error scenarios

## Backward Compatibility

- Default output format is "text" (current behavior)
- All existing configuration options respected
- Existing reports look identical by default
- Can run with existing `cwatch.toml` files

## Implementation Checklist

- [x] Write comprehensive tests for existing code
- [x] Design document (this document)
- [ ] Implement `collector.py` module
- [ ] Implement `reporters.py` module with `TextReporter`
- [ ] Update `main()` function
- [ ] Run tests to verify behavior unchanged
- [ ] Implement `JsonReporter`
- [ ] Add configuration options
- [ ] Update documentation
- [ ] Add examples for new features
- [ ] Update CHANGELOG.md

## Questions for Discussion

1. Should we support streaming output for large numbers of targets?
2. Should we add progress indicators during data collection?
3. Should we support outputting to multiple formats simultaneously?
4. Should we add caching to avoid redundant API calls?
5. Should we add rate limiting for API requests?
