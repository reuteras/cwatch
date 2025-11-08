"""Data structures for cwatch two-phase architecture."""
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class TargetResult:
    """Results for a single target."""

    target: str
    success: bool
    timestamp: datetime
    response: dict | None
    changes: dict | None
    errors: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


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
        """Check if any target has changes.

        Returns:
            True if any target has changes, False otherwise
        """
        return any(t.changes for t in self.targets if t.success and t.changes)

    def get_targets_with_changes(self) -> list[TargetResult]:
        """Get only targets that have changes.

        Returns:
            List of TargetResult objects that have changes
        """
        return [t for t in self.targets if t.success and t.changes]
