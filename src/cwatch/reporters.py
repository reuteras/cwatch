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


class HtmlReporter(Reporter):
    """HTML output reporter with expandable sections."""

    def generate(self, data: CollectedData) -> str:
        """Generate HTML report with tables and expandable JSON.

        Args:
            data: CollectedData object with all results

        Returns:
            HTML report as string
        """
        html = []
        html.append(self._generate_html_header(data))
        html.append(self._generate_summary_section(data))
        html.append(self._generate_changes_section(data))
        html.append(self._generate_no_changes_section(data))
        html.append(self._generate_errors_section(data))
        html.append(self._generate_html_footer(data))
        return "\n".join(html)

    def _generate_html_header(self, data: CollectedData) -> str:
        """Generate HTML header with CSS.

        Args:
            data: CollectedData object

        Returns:
            HTML header
        """
        title = self.config["cwatch"].get("header", "cwatch Report")
        return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            background-color: white;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #2c3e50;
            border-bottom: 3px solid #3498db;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #34495e;
            margin-top: 30px;
        }}
        .summary {{
            background-color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            margin: 20px 0;
        }}
        .summary-stat {{
            display: inline-block;
            margin-right: 20px;
            font-weight: bold;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }}
        th {{
            background-color: #3498db;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: 600;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }}
        tr:hover {{
            background-color: #f5f5f5;
        }}
        .change-badge {{
            display: inline-block;
            padding: 4px 8px;
            border-radius: 3px;
            font-size: 0.9em;
            font-weight: 600;
        }}
        .badge-warning {{
            background-color: #f39c12;
            color: white;
        }}
        .badge-danger {{
            background-color: #e74c3c;
            color: white;
        }}
        .badge-info {{
            background-color: #3498db;
            color: white;
        }}
        .badge-success {{
            background-color: #27ae60;
            color: white;
        }}
        details {{
            margin: 10px 0;
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 10px;
        }}
        summary {{
            cursor: pointer;
            font-weight: 600;
            padding: 5px;
            user-select: none;
        }}
        summary:hover {{
            background-color: #f8f9fa;
        }}
        pre {{
            background-color: #2c3e50;
            color: #ecf0f1;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
            font-size: 0.9em;
        }}
        .footer {{
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid #ddd;
            color: #7f8c8d;
            font-size: 0.9em;
        }}
        a {{
            color: #3498db;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{title}</h1>
        <p><strong>Generated:</strong> {data.collection_start.strftime("%Y-%m-%d %H:%M:%S")}</p>
"""

    def _generate_summary_section(self, data: CollectedData) -> str:
        """Generate summary statistics section.

        Args:
            data: CollectedData object

        Returns:
            HTML summary section
        """
        changes_count = len(data.get_targets_with_changes())
        return f"""
        <div class="summary">
            <span class="summary-stat">📊 Total Targets: {data.total_targets}</span>
            <span class="summary-stat">✅ Successful: {data.successful}</span>
            <span class="summary-stat">❌ Failed: {data.failed}</span>
            <span class="summary-stat">🔄 Changes Detected: {changes_count}</span>
        </div>
"""

    def _generate_changes_section(self, data: CollectedData) -> str:
        """Generate changes section with tables and expandable JSON.

        Args:
            data: CollectedData object

        Returns:
            HTML changes section
        """
        targets_with_changes = data.get_targets_with_changes()

        if not targets_with_changes:
            return ""

        html = ['<h2>🚨 Changes Detected</h2>']

        for target_result in targets_with_changes:
            filtered_changes = self._filter_changes(target_result.changes)
            if not filtered_changes:
                continue

            html.append(f'<h3>{target_result.target}</h3>')
            html.append('<table>')
            html.append('<tr><th>Engine</th><th>Changes</th><th>Details</th></tr>')

            for engine, change_data in filtered_changes.items():
                badge_class = self._get_badge_class(engine, change_data)
                summary = self._get_change_summary(engine, change_data)
                links = self._get_engine_links(engine, target_result.target, change_data)

                html.append('<tr>')
                html.append(f'<td><span class="change-badge {badge_class}">{engine}</span></td>')
                html.append(f'<td>{summary}</td>')
                html.append(f'<td>{links}</td>')
                html.append('</tr>')

            html.append('</table>')

            # Expandable raw JSON
            html.append('<details>')
            html.append('<summary>📄 View Raw JSON</summary>')
            html.append(f'<pre>{json.dumps(filtered_changes, indent=2)}</pre>')
            html.append('</details>')

        return "\n".join(html)

    def _generate_no_changes_section(self, data: CollectedData) -> str:
        """Generate section for targets with no changes.

        Args:
            data: CollectedData object

        Returns:
            HTML section for targets without changes
        """
        if self.config["cwatch"]["quiet"]:
            return ""

        no_change_targets = [
            t for t in data.targets
            if t.success and not t.changes
        ]

        if not no_change_targets:
            return ""

        html = ['<h2>✅ No Changes Detected</h2>', '<ul>']
        for target in no_change_targets:
            html.append(f'<li>{target.target}</li>')
        html.append('</ul>')

        return "\n".join(html)

    def _generate_errors_section(self, data: CollectedData) -> str:
        """Generate errors section.

        Args:
            data: CollectedData object

        Returns:
            HTML errors section
        """
        failed_targets = [t for t in data.targets if not t.success]

        if not failed_targets:
            return ""

        html = ['<h2>❌ Errors</h2>', '<table>']
        html.append('<tr><th>Target</th><th>Errors</th></tr>')

        for target in failed_targets:
            errors = "<br>".join(target.errors)
            html.append(f'<tr><td>{target.target}</td><td>{errors}</td></tr>')

        html.append('</table>')
        return "\n".join(html)

    def _generate_html_footer(self, data: CollectedData) -> str:
        """Generate HTML footer.

        Args:
            data: CollectedData object

        Returns:
            HTML footer
        """
        footer_text = self.config["cwatch"].get("footer", "")
        return f"""
        <div class="footer">
            <p><strong>Completed:</strong> {data.collection_end.strftime("%Y-%m-%d %H:%M:%S")}</p>
            {f'<p>{footer_text}</p>' if footer_text else ''}
            <p>Generated with cwatch {importlib.metadata.version('cwatch')}</p>
        </div>
    </div>
</body>
</html>
"""

    def _get_badge_class(self, engine: str, change_data: dict) -> str:
        """Get CSS badge class based on engine and data.

        Args:
            engine: Engine name
            change_data: Change data

        Returns:
            CSS class name
        """
        if engine == "abuseipdb" and isinstance(change_data, dict):
            if change_data.get("risk_score", 0) > 50:  # noqa: PLR2004
                return "badge-danger"
            if change_data.get("reports", 0) > 0:
                return "badge-warning"
        elif engine == "virustotal" and isinstance(change_data, dict):
            if change_data.get("total_malicious", 0) > 0:
                return "badge-danger"
        elif engine == "threatfox" and isinstance(change_data, dict):
            if change_data.get("count", 0) > 0:
                return "badge-danger"

        return "badge-info"

    def _get_change_summary(self, engine: str, change_data: dict) -> str:
        """Get human-readable summary of changes.

        Args:
            engine: Engine name
            change_data: Change data

        Returns:
            Summary text
        """
        if isinstance(change_data, list):
            return f"Changed: {len(change_data)} items"

        if engine == "abuseipdb" and isinstance(change_data, dict):
            reports = change_data.get("reports", 0)
            risk = change_data.get("risk_score", 0)
            return f"Reports: {reports}, Risk Score: {risk}%"
        elif engine == "virustotal" and isinstance(change_data, dict):
            malicious = change_data.get("total_malicious", 0)
            score = change_data.get("community_score", 0)
            return f"Malicious: {malicious}, Community Score: {score}"
        elif engine == "threatfox" and isinstance(change_data, dict):
            count = change_data.get("count", 0)
            return f"Threats: {count}"
        elif engine == "shodan" and isinstance(change_data, dict):
            if "link" in change_data:
                return "New data available"

        return "Changed"

    def _get_engine_links(self, engine: str, target: str, change_data: dict) -> str:
        """Get clickable links for engine results.

        Args:
            engine: Engine name
            target: Target IP/domain
            change_data: Change data

        Returns:
            HTML links
        """
        links = []

        if engine == "shodan":
            if isinstance(change_data, dict) and "link" in change_data:
                links.append(f'<a href="{change_data["link"]}" target="_blank">View on Shodan</a>')
            else:
                links.append(f'<a href="https://www.shodan.io/host/{target}" target="_blank">View on Shodan</a>')

        if engine == "virustotal":
            links.append(f'<a href="https://www.virustotal.com/gui/ip-address/{target}" target="_blank">View on VirusTotal</a>')

        if engine == "abuseipdb":
            links.append(f'<a href="https://www.abuseipdb.com/check/{target}" target="_blank">View on AbuseIPDB</a>')

        if engine == "threatfox":
            links.append(f'<a href="https://threatfox.abuse.ch/browse.php?search=ioc%3A{target}" target="_blank">View on ThreatFox</a>')

        return " | ".join(links) if links else "-"


def get_reporter(format_type: str, configuration: dict) -> Reporter:
    """Factory function to get appropriate reporter.

    Args:
        format_type: Type of reporter ("text", "json", "html")
        configuration: Configuration dictionary

    Returns:
        Reporter instance
    """
    reporters = {
        "text": TextReporter,
        "json": JsonReporter,
        "html": HtmlReporter,
    }

    reporter_class = reporters.get(format_type, TextReporter)
    return reporter_class(configuration)
