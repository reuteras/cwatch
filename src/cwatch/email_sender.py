"""Email output functionality for cwatch."""

from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from cwatch.data_structures import CollectedData
from cwatch.reporters import HtmlReporter, TextReporter


def _generate_subject(collected_data: CollectedData) -> str:
    """Generate email subject based on changes detected.

    Args:
        collected_data: CollectedData object with all results

    Returns:
        Email subject string
    """
    changes_count = len(collected_data.get_targets_with_changes())
    if changes_count > 0:
        return f"cwatch Report: {changes_count} change(s) detected"
    return "cwatch Report: No changes"


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
        subject = _generate_subject(collected_data)

        # Create multipart message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = configuration["cwatch"].get("email_from", "cwatch@localhost")
        msg["To"] = configuration["cwatch"].get("email_to", "admin@localhost")

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


def output_email_text_to_stdout(configuration: dict, collected_data: CollectedData) -> None:
    """Output email report to stdout as plain text only.

    Creates a plain text email suitable for cron jobs that don't handle multipart MIME well.

    Args:
        configuration: Configuration dictionary
        collected_data: CollectedData object with all results
    """
    try:
        text_reporter = TextReporter(configuration)
        text_content = text_reporter.generate(collected_data)

        # Generate subject
        subject = _generate_subject(collected_data)

        # Create plain text message
        msg = MIMEText(text_content, "plain")
        msg["Subject"] = subject
        msg["From"] = configuration["cwatch"].get("email_from", "cwatch@localhost")
        msg["To"] = configuration["cwatch"].get("email_to", "admin@localhost")

        # Output the complete message
        print(msg.as_string())

    except Exception as e:
        print(f"Error generating email output: {e}")


def output_email_html_to_stdout(configuration: dict, collected_data: CollectedData) -> None:
    """Output email report to stdout as HTML only.

    Creates an HTML email suitable for cron jobs that don't handle multipart MIME well.

    Args:
        configuration: Configuration dictionary
        collected_data: CollectedData object with all results
    """
    try:
        html_reporter = HtmlReporter(configuration)
        html_content = html_reporter.generate(collected_data)

        # Generate subject
        subject = _generate_subject(collected_data)

        # Create HTML message
        msg = MIMEText(html_content, "html")
        msg["Subject"] = subject
        msg["From"] = configuration["cwatch"].get("email_from", "cwatch@localhost")
        msg["To"] = configuration["cwatch"].get("email_to", "admin@localhost")

        # Output the complete message
        print(msg.as_string())

    except Exception as e:
        print(f"Error generating email output: {e}")
