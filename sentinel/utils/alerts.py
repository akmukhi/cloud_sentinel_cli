"""Alert utilities for Slack and Email."""

from __future__ import annotations

import json
import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Any, Dict, List, Optional

import requests

logger = logging.getLogger(__name__)


def send_slack_alert(
    webhook_url: str,
    findings_summary: Dict[str, int],
    findings: List[Dict[str, Any]],
    scan_type: str = "Cloud Sentinel Scan",
) -> bool:
    """Send alert to Slack via webhook."""
    try:
        # Format message
        blocks = [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"⚠️ {scan_type} - Findings Detected",
                },
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Summary:*\n"
                    f"• Failed DAGs: {findings_summary.get('failed_dags', 0)}\n"
                    f"• Slow Tasks: {findings_summary.get('slow_tasks', 0)}\n"
                    f"• Unhealthy Workers: {findings_summary.get('unhealthy_workers', 0)}\n"
                    f"• Stale DAGs: {findings_summary.get('stale_dags', 0)}\n"
                    f"• Missing Retries: {findings_summary.get('missing_retries', 0)}\n"
                    f"• IAM Risks: {findings_summary.get('iam_risks', 0)}\n"
                    f"• Storage Issues: {findings_summary.get('storage_issues', 0)}\n"
                    f"• Service Issues: {findings_summary.get('service_issues', 0)}",
                },
            },
        ]

        # Add top findings
        if findings:
            top_findings = findings[:10]  # Limit to top 10
            findings_text = "\n".join(
                [
                    f"• *{f.get('resource', f.get('dag_id', f.get('service', 'Unknown')))}*: {f.get('message', f.get('issue', 'Issue detected'))}"
                    for f in top_findings
                ]
            )
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Top Findings:*\n{findings_text}",
                    },
                }
            )

        payload = {"blocks": blocks}
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        return True
    except Exception as exc:
        logger.error("Failed to send Slack alert: %s", exc)
        return False


def send_email_alert(
    to_email: str,
    from_email: str,
    smtp_server: str,
    smtp_port: int,
    findings_summary: Dict[str, int],
    findings: List[Dict[str, Any]],
    scan_type: str = "Cloud Sentinel Scan",
    smtp_user: Optional[str] = None,
    smtp_password: Optional[str] = None,
) -> bool:
    """Send alert via email."""
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"{scan_type} - Findings Detected"
        msg["From"] = from_email
        msg["To"] = to_email

        # Create HTML email
        html = f"""
        <html>
          <body>
            <h2>⚠️ {scan_type} - Findings Detected</h2>
            <h3>Summary</h3>
            <ul>
              <li>Failed DAGs: {findings_summary.get('failed_dags', 0)}</li>
              <li>Slow Tasks: {findings_summary.get('slow_tasks', 0)}</li>
              <li>Unhealthy Workers: {findings_summary.get('unhealthy_workers', 0)}</li>
              <li>Stale DAGs: {findings_summary.get('stale_dags', 0)}</li>
              <li>Missing Retries: {findings_summary.get('missing_retries', 0)}</li>
              <li>IAM Risks: {findings_summary.get('iam_risks', 0)}</li>
              <li>Storage Issues: {findings_summary.get('storage_issues', 0)}</li>
              <li>Service Issues: {findings_summary.get('service_issues', 0)}</li>
            </ul>
        """

        if findings:
            html += "<h3>Top Findings</h3><ul>"
            for finding in findings[:20]:  # Limit to top 20
                resource = finding.get("resource", finding.get("dag_id", finding.get("service", "Unknown")))
                message = finding.get("message", finding.get("issue", "Issue detected"))
                severity = finding.get("severity", "UNKNOWN")
                html += f"<li><strong>{resource}</strong> ({severity}): {message}</li>"
            html += "</ul>"

        html += """
          </body>
        </html>
        """

        msg.attach(MIMEText(html, "html"))

        # Send email
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            if smtp_user and smtp_password:
                server.starttls()
                server.login(smtp_user, smtp_password)
            server.send_message(msg)

        return True
    except Exception as exc:
        logger.error("Failed to send email alert: %s", exc)
        return False

