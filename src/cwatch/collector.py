"""Data collection module for cwatch."""
import json
import sqlite3
from datetime import datetime

from cwatch.cw import (
    get_response,
    get_targets,
    save_json_data,
    submit_request,
)
from cwatch.data_structures import CollectedData, TargetResult


class DataCollector:
    """Handles all data collection operations."""

    def __init__(self, configuration: dict):
        """Initialize the data collector.

        Args:
            configuration: Configuration dictionary
        """
        self.config = configuration
        self.targets: list[str] = []

    def collect_all(self) -> CollectedData:
        """Main entry point for data collection.

        Returns:
            CollectedData object containing all results
        """
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
            failed=sum(1 for r in results if not r.success),
        )

    def _resolve_targets(self) -> list[str]:
        """Resolve all targets from configuration.

        Returns:
            List of target IPs and domains
        """
        targets: list[str] = []
        return get_targets(self.config, targets)

    def _collect_target(self, target: str) -> TargetResult:
        """Collect data for a single target.

        Args:
            target: Target domain or IP address

        Returns:
            TargetResult object with collection results
        """
        errors = []

        try:
            # Submit request and get analysis_id
            analysis_id = submit_request(self.config, target)
            if not analysis_id:
                return TargetResult(
                    target=target,
                    success=False,
                    timestamp=datetime.now(),
                    response=None,
                    changes=None,
                    errors=["Failed to submit request"],
                )

            # Poll for completion and get response
            response = get_response(self.config, analysis_id)
            if not response:
                return TargetResult(
                    target=target,
                    success=False,
                    timestamp=datetime.now(),
                    response=None,
                    changes=None,
                    errors=["Failed to get response"],
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
                metadata={},
            )

        except Exception as e:
            return TargetResult(
                target=target,
                success=False,
                timestamp=datetime.now(),
                response=None,
                changes=None,
                errors=[str(e)],
                metadata={},
            )

    def _detect_changes_for_target(self, target: str) -> dict | None:
        """Detect changes for a specific target.

        Args:
            target: Target domain or IP address

        Returns:
            Dictionary of changes, or None if no changes or error
        """
        try:
            conn = sqlite3.connect(self.config["cwatch"]["DB_FILE"])
            cursor = conn.cursor()

            # Fetch the last two entries
            cursor.execute(
                """
                SELECT json_content FROM json_data WHERE target = ?
                ORDER BY id DESC LIMIT 2
            """,
                (target,),
            )
            rows = cursor.fetchall()
            conn.close()

            if len(rows) < 2:  # noqa: PLR2004
                return None

            old_json = json.loads(rows[1][0])[0]
            new_json = json.loads(rows[0][0])[0]

            # Import here to avoid circular dependency
            from cwatch.cw import compare_json  # noqa: PLC0415

            changes = compare_json(self.config, old_json, new_json)

            return changes if changes else None

        except Exception:
            return None
