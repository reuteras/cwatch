"""Reporting module for cwatch."""
import importlib.metadata
import json
from abc import ABC, abstractmethod

from cwatch.cw import (
    handle_abuseipdb,
    handle_shodan,
    handle_threatfox,
    handle_virustotal,
)
from cwatch.data_structures import CollectedData


class Reporter(ABC):
    """Base class for all reporters."""

    def __init__(self, configuration: dict):
        """Initialize the reporter.

        Args:
            configuration: Configuration dictionary
        """
        self.config = configuration

    @abstractmethod
    def generate(self, data: CollectedData) -> str:
        """Generate report from collected data.

        Args:
            data: CollectedData object with all results

        Returns:
            Formatted report as string
        """

    def _filter_changes(self, changes: dict) -> dict:
        """Apply filtering rules based on configuration.

        Args:
            changes: Dictionary of changes to filter

        Returns:
            Filtered changes dictionary
        """
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
        """Generate text report.

        Args:
            data: CollectedData object with all results

        Returns:
            Text report as string
        """
        output = []

        # Header
        if self.config["cwatch"]["report"]:
            output.append(self._generate_header(data))

        # Target results
        for target_result in data.targets:
            if not target_result.success:
                if not self.config["cwatch"]["quiet"]:
                    output.append(f"\nError processing {target_result.target}:")
                    for error in target_result.errors:
                        output.append(f"  - {error}")
                continue

            if target_result.changes:
                filtered_changes = self._filter_changes(target_result.changes)
                if filtered_changes:
                    output.append(f"\nChanges detected for {target_result.target}:")
                    output.append(json.dumps(filtered_changes, indent=4))
            elif self.config["cwatch"]["report"] and not self.config["cwatch"]["quiet"]:
                output.append(f"\nChecking for changes for: {target_result.target}")
                output.append("- No changes.")

        # Handle "no changes" message for quiet mode
        if (
            self.config["cwatch"]["report"]
            and self.config["cwatch"]["quiet"]
            and not data.has_changes()
        ):
            output.append("\nNo changes to report.")

        # Footer
        if self.config["cwatch"]["report"]:
            output.append(self._generate_footer(data))

        return "\n".join(output)

    def _generate_header(self, data: CollectedData) -> str:
        """Generate report header.

        Args:
            data: CollectedData object

        Returns:
            Header text
        """
        lines = []
        lines.append(self.config["cwatch"]["header"])
        lines.append("=" * len(self.config["cwatch"]["header"]))
        lines.append("")
        lines.append(f"Report generation start at {data.collection_start.isoformat()}")
        lines.append("")
        lines.append("Will report changes in the following engines.")
        engines = self.config["cyberbro"]["engines"].copy()
        engines.sort()
        for engine in engines:
            if engine not in self.config["cwatch"]["ignore_engines"]:
                lines.append(f"- {engine}")
        lines.append("")

        if self.config["cwatch"]["ignore_engines_partly"]:
            lines.append("Ignore change if the only change is in one of:")
            for combo in self.config["cwatch"]["ignore_engines_partly"]:
                lines.append(f"- {combo[0]} -> {combo[1]}")
            lines.append("")

        lines.append(f"Will check {data.total_targets} hosts.")
        return "\n".join(lines)

    def _generate_footer(self, data: CollectedData) -> str:
        """Generate report footer.

        Args:
            data: CollectedData object

        Returns:
            Footer text
        """
        lines = []
        lines.append("")
        lines.append(f"Report done at {data.collection_end.isoformat()}.")
        if self.config["cwatch"]["footer"]:
            lines.append("")
            lines.append(self.config["cwatch"]["footer"])
        lines.append("")
        lines.append(
            f"Report generated with cwatch {importlib.metadata.version('cwatch')}."
        )
        return "\n".join(lines)


class JsonReporter(Reporter):
    """JSON output reporter."""

    def generate(self, data: CollectedData) -> str:
        """Generate JSON report.

        Args:
            data: CollectedData object with all results

        Returns:
            JSON report as string
        """
        report = {
            "metadata": {
                "collection_start": data.collection_start.isoformat(),
                "collection_end": data.collection_end.isoformat(),
                "total_targets": data.total_targets,
                "successful": data.successful,
                "failed": data.failed,
            },
            "targets": [],
        }

        for target_result in data.targets:
            target_data = {
                "target": target_result.target,
                "success": target_result.success,
                "timestamp": target_result.timestamp.isoformat(),
            }

            if target_result.success:
                filtered_changes = (
                    self._filter_changes(target_result.changes)
                    if target_result.changes
                    else {}
                )
                target_data["changes"] = filtered_changes
            else:
                target_data["errors"] = target_result.errors

            report["targets"].append(target_data)

        return json.dumps(report, indent=2)


def get_reporter(format_type: str, configuration: dict) -> Reporter:
    """Factory function to get appropriate reporter.

    Args:
        format_type: Type of reporter ("text", "json")
        configuration: Configuration dictionary

    Returns:
        Reporter instance
    """
    reporters = {
        "text": TextReporter,
        "json": JsonReporter,
    }

    reporter_class = reporters.get(format_type, TextReporter)
    return reporter_class(configuration)
