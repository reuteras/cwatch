"""Email output functionality for cwatch."""
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from cwatch.data_structures import CollectedData
from cwatch.reporters import HtmlReporter, TextReporter


def output_email_to_stdout(configuration: dict, collected_data: CollectedData) -> None:
    """Output email report to stdout as multipart MIME message.

    Creates a proper multipart/alternative email with both text and HTML versions
    suitable for cron jobs (cron will automatically email the output).

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

        # Create multipart message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = "cwatch@localhost"
        msg["To"] = "admin@localhost"

        # Attach both versions (plain text first, then HTML)
        # Email clients will prefer the last alternative (HTML)
        text_part = MIMEText(text_content, "plain")
        html_part = MIMEText(html_content, "html")

        msg.attach(text_part)
        msg.attach(html_part)

        # Output the complete message
        print(msg.as_string())

    except Exception as e:
        print(f"Error generating email output: {e}")
