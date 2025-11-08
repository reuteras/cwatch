"""Email output functionality for cwatch."""
from cwatch.data_structures import CollectedData
from cwatch.reporters import HtmlReporter, TextReporter


def output_email_to_stdout(configuration: dict, collected_data: CollectedData) -> None:
    """Output email report to stdout in email format.

    Args:
        configuration: Configuration dictionary
        collected_data: CollectedData object with all results
    """
    try:
        # Generate both HTML and plain text versions
        html_reporter = HtmlReporter(configuration)
        text_reporter = TextReporter(configuration)

        html_content = html_reporter.generate(collected_data)
        text_content = text_reporter.generate(collected_data)

        # Generate subject
        changes_count = len(collected_data.get_targets_with_changes())
        if changes_count > 0:
            subject = f"cwatch Report: {changes_count} change(s) detected"
        else:
            subject = "cwatch Report: No changes"

        # Output in email format (headers + body)
        print("=" * 70)
        print(f"Subject: {subject}")
        print("=" * 70)
        print()
        print("--- Plain Text Version ---")
        print(text_content)
        print()
        print("=" * 70)
        print("--- HTML Version ---")
        print(html_content)
        print("=" * 70)

    except Exception as e:
        print(f"Error generating email output: {e}")
