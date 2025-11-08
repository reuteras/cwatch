"""Email sending functionality for cwatch."""
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

from cwatch.data_structures import CollectedData
from cwatch.reporters import HtmlReporter, TextReporter


def send_email_report(configuration: dict, collected_data: CollectedData) -> bool:
    """Send email report with both HTML and plain text.

    Args:
        configuration: Configuration dictionary with email settings
        collected_data: CollectedData object with all results

    Returns:
        True if email sent successfully, False otherwise
    """
    email_config = configuration.get("email", {})

    if not email_config.get("enabled", False):
        return False

    # Check if we should only send on changes
    if email_config.get("only_on_changes", True) and not collected_data.has_changes():
        return False

    try:
        # Generate both HTML and plain text versions
        html_reporter = HtmlReporter(configuration)
        text_reporter = TextReporter(configuration)

        html_content = html_reporter.generate(collected_data)
        text_content = text_reporter.generate(collected_data)

        # Create multipart message
        msg = MIMEMultipart("alternative")
        msg["Subject"] = _generate_subject(email_config, collected_data)
        msg["From"] = email_config["from"]
        msg["To"] = ", ".join(email_config["to"])

        # Attach both versions (plain text first, then HTML)
        msg.attach(MIMEText(text_content, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        # Send email
        with smtplib.SMTP(
            email_config["smtp_host"],
            email_config.get("smtp_port", 587)
        ) as server:
            if email_config.get("use_tls", True):
                server.starttls()

            if email_config.get("smtp_user") and email_config.get("smtp_password"):
                server.login(
                    email_config["smtp_user"],
                    email_config["smtp_password"]
                )

            server.send_message(msg)

        return True

    except Exception as e:
        print(f"Error sending email: {e}")
        return False


def _generate_subject(email_config: dict, collected_data: CollectedData) -> str:
    """Generate email subject line.

    Args:
        email_config: Email configuration
        collected_data: CollectedData object

    Returns:
        Email subject
    """
    subject_template = email_config.get("subject", "cwatch Report")

    changes_count = len(collected_data.get_targets_with_changes())

    if "{changes}" in subject_template:
        subject = subject_template.replace("{changes}", str(changes_count))
    elif changes_count > 0:
        subject = f"{subject_template}: {changes_count} change(s) detected"
    else:
        subject = f"{subject_template}: No changes"

    return subject
