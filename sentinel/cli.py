"""Cloud Sentinel CLI entry point."""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

import click
import json
import yaml

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    Console = None  # type: ignore
    Table = None  # type: ignore
    Panel = None  # type: ignore
    box = None  # type: ignore

from sentinel import __version__
from sentinel.modules import cloud_run, etl_airflow, gcp_iam, gcp_storage
from sentinel.utils import alerts as alert_utils
from sentinel.utils.output import create_rich_table, format_output, write_output

OUTPUT_FORMATS = ("table", "json", "yaml")


@click.group(
    help="Cloud Sentinel detects misconfigurations across your GCP footprint."
)
@click.option(
    "--project",
    "-p",
    metavar="PROJECT_ID",
    envvar="GOOGLE_CLOUD_PROJECT",
    help="Default Google Cloud project to target.",
)
@click.option(
    "--format",
    "output_format",
    type=click.Choice(OUTPUT_FORMATS, case_sensitive=False),
    default="table",
    show_default=True,
    help="Output format for command results.",
)
@click.option(
    "--output",
    "-o",
    metavar="FILE",
    help="Write output to file instead of stdout.",
)
@click.option(
    "--quiet",
    "-q",
    is_flag=True,
    help="Suppress summary output when writing to file.",
)
@click.version_option(__version__, prog_name="cloudsentinal")
@click.pass_context
def cli(ctx: click.Context, project: str | None, output_format: str, output: str | None, quiet: bool) -> None:
    """Root command storing global options on the Click context."""

    ctx.ensure_object(dict)
    ctx.obj["project"] = project
    ctx.obj["format"] = output_format.lower()
    ctx.obj["output"] = output
    ctx.obj["quiet"] = quiet
    ctx.obj["console"] = Console() if RICH_AVAILABLE else None


@cli.group(help="Scanning commands for supported GCP services.")
def scan() -> None:
    """Grouping for scan subcommands."""


@scan.command("gcp", help="Scan GCP IAM and Storage for common misconfigurations.")
@click.option(
    "--project",
    "-p",
    metavar="PROJECT_ID",
    help="Override the project inherited from the root command.",
)
@click.option(
    "--include-public/--skip-public",
    default=True,
    show_default=True,
    help="Toggle checks that require IAM policy evaluation for public access.",
)
@click.option(
    "--key-age-threshold",
    type=int,
    default=90,
    show_default=True,
    help="Threshold in days for detecting old service account keys.",
)
@click.option(
    "--fail-on-high",
    is_flag=True,
    help="Exit with code 1 if any HIGH severity findings are detected.",
)
@click.option(
    "--slack-webhook",
    metavar="URL",
    help="Send alerts to Slack webhook URL.",
)
@click.option(
    "--email-to",
    metavar="EMAIL",
    help="Send email alerts to this address.",
)
@click.option(
    "--email-from",
    metavar="EMAIL",
    help="Send email alerts from this address.",
)
@click.option(
    "--smtp-server",
    metavar="HOST",
    default="smtp.gmail.com",
    help="SMTP server hostname.",
)
@click.option(
    "--smtp-port",
    type=int,
    default=587,
    help="SMTP server port.",
)
@click.option(
    "--smtp-user",
    metavar="USERNAME",
    help="SMTP username for authentication.",
)
@click.option(
    "--smtp-password",
    metavar="PASSWORD",
    help="SMTP password for authentication.",
)
@click.pass_context
def scan_gcp(
    ctx: click.Context,
    project: str | None,
    include_public: bool,
    key_age_threshold: int,
    fail_on_high: bool,
    slack_webhook: str | None,
    email_to: str | None,
    email_from: str | None,
    smtp_server: str,
    smtp_port: int,
    smtp_user: str | None,
    smtp_password: str | None,
) -> None:
    """Entry point for `cloudsentinal scan gcp`."""

    project_id = _resolve_project(ctx, project)
    output_format = ctx.obj.get("format", "table")

    # Scan IAM
    iam_result = None
    try:
        iam_result = gcp_iam.scan_iam(
            project_id=project_id, key_age_threshold_days=key_age_threshold
        )
    except gcp_iam.IAMModuleError as exc:
        if output_format == "json":
            # In JSON mode, include error in output structure
            iam_result = gcp_iam.IAMResult(risks=[], passed=[])
            click.echo(
                json.dumps(
                    {
                        "error": {"iam": str(exc)},
                        "gcp": {"iam": iam_result.to_dict(), "storage": {}},
                        "services": {},
                    },
                    indent=2,
                )
            )
            ctx.exit(1)
        else:
            raise click.ClickException(f"IAM scan failed: {exc}") from exc
    except Exception as exc:  # pragma: no cover
        if output_format == "json":
            iam_result = gcp_iam.IAMResult(risks=[], passed=[])
        else:
            raise click.ClickException(f"IAM scan failed: {exc}") from exc

    # Scan Storage
    storage_result = None
    try:
        storage_result = gcp_storage.scan_buckets_structured(
            project_id=project_id, include_public=include_public
        )
    except gcp_storage.StorageModuleError as exc:
        if output_format == "json":
            # In JSON mode, include error in output structure
            if iam_result is None:
                iam_result = gcp_iam.IAMResult(risks=[], passed=[])
            click.echo(
                json.dumps(
                    {
                        "error": {"storage": str(exc)},
                        "gcp": {
                            "iam": iam_result.to_dict(),
                            "storage": {"public_buckets": [], "encryption_issues": []},
                        },
                        "services": {},
                    },
                    indent=2,
                )
            )
            ctx.exit(1)
        else:
            raise click.ClickException(f"Storage scan failed: {exc}") from exc

    # Collect all findings for alerts
    all_findings = []
    high_severity_findings = []
    
    if iam_result:
        for risk in iam_result.risks:
            finding_dict = risk.to_dict()
            all_findings.append(finding_dict)
            if risk.severity.upper() in ("HIGH", "CRITICAL"):
                high_severity_findings.append(finding_dict)
    
    if storage_result:
        for bucket in storage_result.public_buckets:
            finding_dict = {"resource": bucket.get("resource", "unknown"), "issue": "Public bucket", "severity": "HIGH", "message": "Bucket grants public access"}
            all_findings.append(finding_dict)
            high_severity_findings.append(finding_dict)
        for issue in storage_result.encryption_issues:
            finding_dict = {"resource": issue.get("resource", "unknown"), "issue": issue.get("issue", "Encryption issue"), "severity": issue.get("severity", "HIGH"), "message": issue.get("issue", "Encryption issue")}
            all_findings.append(finding_dict)
            if issue.get("severity", "HIGH").upper() in ("HIGH", "CRITICAL"):
                high_severity_findings.append(finding_dict)

    # Prepare output data
    output_data = {
        "gcp": {
            "iam": (iam_result.to_dict() if iam_result else {"risks": [], "passed": []}),
            "storage": (storage_result.to_dict() if storage_result else {"public_buckets": [], "encryption_issues": []}),
        },
        "services": {},
    }
    
    # Emit results
    output_content = ""
    if output_format in ("json", "yaml"):
        output_content = format_output(output_data, output_format)
        if not ctx.obj.get("quiet", False):
            console = ctx.obj.get("console")
            if console:
                console.print(output_content)
            else:
                click.echo(output_content)
    else:
        _emit_gcp_table_output(iam_result, storage_result, ctx.obj.get("console"))
        if output_format in ("json", "yaml"):
            output_content = format_output(output_data, output_format)

    # Write to file if specified
    output_path = ctx.obj.get("output")
    if output_path and output_content:
        write_output(output_content, output_path, ctx.obj.get("console"))
    elif output_path and output_format == "table":
        # For table format, write the formatted text
        console = ctx.obj.get("console")
        if console:
            from io import StringIO
            buffer = StringIO()
            temp_console = Console(file=buffer, force_terminal=False)
            _emit_gcp_table_output(iam_result, storage_result, temp_console)
            write_output(buffer.getvalue(), output_path, console)

    # Send alerts
    if slack_webhook or email_to:
        summary = {
            "iam_risks": len(iam_result.risks) if iam_result else 0,
            "storage_issues": len(storage_result.public_buckets) + len(storage_result.encryption_issues) if storage_result else 0,
            "service_issues": 0,
            "failed_dags": 0,
            "slow_tasks": 0,
            "unhealthy_workers": 0,
            "stale_dags": 0,
            "missing_retries": 0,
        }
        if slack_webhook:
            alert_utils.send_slack_alert(slack_webhook, summary, all_findings, "GCP Scan")
        if email_to and email_from:
            alert_utils.send_email_alert(
                email_to, email_from, smtp_server, smtp_port,
                summary, all_findings, "GCP Scan",
                smtp_user, smtp_password
            )

    # Exit with error code
    if fail_on_high and high_severity_findings:
        ctx.exit(1)
    
    has_issues = (
        (iam_result and len(iam_result.risks) > 0)
        or (storage_result and len(storage_result.public_buckets) > 0)
        or (storage_result and len(storage_result.encryption_issues) > 0)
    )
    ctx.exit(1 if has_issues else 0)


@scan.command("services", help="Scan Cloud Run services for misconfigurations.")
@click.option(
    "--project",
    "-p",
    metavar="PROJECT_ID",
    help="Override the project inherited from the root command.",
)
@click.option(
    "--region",
    metavar="REGION",
    default="-",
    show_default=True,
    help="Cloud Run region to target (use '-' for all regions).",
)
@click.option(
    "--max-revision-age",
    type=int,
    default=30,
    show_default=True,
    help="Flag revisions older than this many days.",
)
@click.option(
    "--max-revisions",
    type=int,
    default=5,
    show_default=True,
    help="Flag when retained revisions exceed this count.",
)
@click.option(
    "--image-age-threshold",
    type=int,
    default=90,
    show_default=True,
    help="Flag container images older than this many days.",
)
@click.option(
    "--include-public/--skip-public",
    default=True,
    show_default=True,
    help="Toggle IAM policy checks for unauthenticated access.",
)
@click.pass_context
def scan_services_cmd(
    ctx: click.Context,
    project: str | None,
    region: str,
    max_revision_age: int,
    max_revisions: int,
    image_age_threshold: int,
    include_public: bool,
) -> None:
    """Entry point for `cloudsentinal scan services`."""

    project_id = _resolve_project(ctx, project)
    output_format = ctx.obj.get("format", "table")

    try:
        service_result = cloud_run.scan_services(
            project_id=project_id,
            region=region,
            include_public=include_public,
            max_revision_age_days=max_revision_age,
            max_revisions=max_revisions,
            image_age_days=image_age_threshold,
        )
    except cloud_run.CloudRunModuleError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format == "json":
        _emit_services_json_output(service_result)
    else:
        _emit_services_table_output(service_result)

    ctx.exit(1 if service_result.all_findings() else 0)


@scan.command("etl", help="Scan Airflow/ETL instances for health and configuration issues.")
@click.option(
    "--airflow-url",
    required=True,
    metavar="URL",
    help="Airflow webserver URL (e.g., http://airflow.example.com:8080).",
)
@click.option(
    "--username",
    metavar="USERNAME",
    help="Username for basic authentication.",
)
@click.option(
    "--password",
    metavar="PASSWORD",
    help="Password for basic authentication.",
)
@click.option(
    "--api-token",
    metavar="TOKEN",
    help="API token for authentication (alternative to username/password).",
)
@click.option(
    "--stale-dag-threshold",
    type=int,
    default=7,
    show_default=True,
    help="Flag DAGs not updated in this many days.",
)
@click.option(
    "--slow-task-multiplier",
    type=float,
    default=2.0,
    show_default=True,
    help="Flag tasks slower than baseline * this multiplier.",
)
@click.option(
    "--failure-window-hours",
    type=int,
    default=24,
    show_default=True,
    help="Look back this many hours for failed DAG runs.",
)
@click.pass_context
def scan_etl_cmd(
    ctx: click.Context,
    airflow_url: str,
    username: str | None,
    password: str | None,
    api_token: str | None,
    stale_dag_threshold: int,
    slow_task_multiplier: float,
    failure_window_hours: int,
) -> None:
    """Entry point for `cloudsentinal scan etl`."""

    output_format = ctx.obj.get("format", "table")

    try:
        etl_result = etl_airflow.scan_airflow(
            airflow_url=airflow_url,
            username=username,
            password=password,
            api_token=api_token,
            stale_dag_threshold_days=stale_dag_threshold,
            slow_task_multiplier=slow_task_multiplier,
            failure_window_hours=failure_window_hours,
        )
    except etl_airflow.AirflowModuleError as exc:
        raise click.ClickException(str(exc)) from exc

    if output_format == "json":
        _emit_etl_json_output(etl_result)
    else:
        _emit_etl_table_output(etl_result)

    ctx.exit(1 if etl_result.all_findings() else 0)


@scan.command("all", help="Run all available scans (gcp, services, etl).")
@click.option(
    "--project",
    "-p",
    metavar="PROJECT_ID",
    help="Override the project inherited from the root command.",
)
@click.option(
    "--airflow-url",
    metavar="URL",
    help="Airflow webserver URL (required for ETL scan).",
)
@click.option(
    "--region",
    metavar="REGION",
    default="-",
    help="Cloud Run region (for services scan).",
)
@click.option(
    "--fail-on-high",
    is_flag=True,
    help="Exit with code 1 if any HIGH severity findings are detected.",
)
@click.option(
    "--slack-webhook",
    metavar="URL",
    help="Send alerts to Slack webhook URL.",
)
@click.option(
    "--email-to",
    metavar="EMAIL",
    help="Send email alerts to this address.",
)
@click.option(
    "--email-from",
    metavar="EMAIL",
    help="Send email alerts from this address.",
)
@click.pass_context
def scan_all_cmd(
    ctx: click.Context,
    project: str | None,
    airflow_url: str | None,
    region: str,
    fail_on_high: bool,
    slack_webhook: str | None,
    email_to: str | None,
    email_from: str | None,
) -> None:
    """Entry point for `cloudsentinal scan all`."""
    output_format = ctx.obj.get("format", "table")
    output_path = ctx.obj.get("output")
    console = ctx.obj.get("console")
    
    all_results = {
        "gcp": {},
        "services": {},
        "etl": {},
    }
    
    all_findings = []
    high_severity_findings = []
    
    # Run GCP scan
    if console:
        console.print("[bold cyan]Running GCP scan...[/bold cyan]")
    try:
        project_id = _resolve_project(ctx, project)
        iam_result = gcp_iam.scan_iam(project_id=project_id, key_age_threshold_days=90)
        storage_result = gcp_storage.scan_buckets_structured(project_id=project_id, include_public=True)
        all_results["gcp"] = {
            "iam": iam_result.to_dict(),
            "storage": storage_result.to_dict(),
        }
        for risk in iam_result.risks:
            finding = risk.to_dict()
            all_findings.append(finding)
            if risk.severity.upper() in ("HIGH", "CRITICAL"):
                high_severity_findings.append(finding)
    except Exception as exc:
        if console:
            console.print(f"[red]GCP scan failed: {exc}[/red]")
        else:
            click.echo(f"GCP scan failed: {exc}")
    
    # Run services scan
    if console:
        console.print("[bold cyan]Running services scan...[/bold cyan]")
    try:
        project_id = _resolve_project(ctx, project)
        service_result = cloud_run.scan_services(project_id=project_id, region=region)
        all_results["services"] = {"cloud_run": service_result.to_dict()}
        for finding in service_result.all_findings():
            finding_dict = finding.to_dict()
            all_findings.append(finding_dict)
            if finding.severity.upper() in ("HIGH", "CRITICAL"):
                high_severity_findings.append(finding_dict)
    except Exception as exc:
        if console:
            console.print(f"[yellow]Services scan failed: {exc}[/yellow]")
        else:
            click.echo(f"Services scan failed: {exc}")
    
    # Run ETL scan if URL provided
    if airflow_url:
        if console:
            console.print("[bold cyan]Running ETL scan...[/bold cyan]")
        try:
            etl_result = etl_airflow.scan_airflow(airflow_url=airflow_url)
            all_results["etl"] = {"airflow": etl_result.to_dict(), "summary": etl_result.get_summary()}
            for finding in etl_result.all_findings():
                finding_dict = finding.to_dict()
                all_findings.append(finding_dict)
                if finding.severity.upper() in ("HIGH", "CRITICAL"):
                    high_severity_findings.append(finding_dict)
        except Exception as exc:
            if console:
                console.print(f"[yellow]ETL scan failed: {exc}[/yellow]")
            else:
                click.echo(f"ETL scan failed: {exc}")
    
    # Emit results
    if output_format in ("json", "yaml"):
        output_content = format_output(all_results, output_format)
        if not ctx.obj.get("quiet", False):
            if console:
                console.print(output_content)
            else:
                click.echo(output_content)
        if output_path:
            write_output(output_content, output_path, console)
    else:
        # Table format - show summary
        if console:
            console.print("\n[bold]Scan Summary[/bold]")
            console.print(f"Total findings: [bold]{len(all_findings)}[/bold]")
            console.print(f"High severity: [red]{len(high_severity_findings)}[/red]")
        else:
            click.echo(f"\nScan Summary:")
            click.echo(f"Total findings: {len(all_findings)}")
            click.echo(f"High severity: {len(high_severity_findings)}")
    
    # Send alerts
    if slack_webhook or email_to:
        summary = {
            "iam_risks": len(all_results.get("gcp", {}).get("iam", {}).get("risks", [])),
            "storage_issues": len(all_results.get("gcp", {}).get("storage", {}).get("public_buckets", [])) + len(all_results.get("gcp", {}).get("storage", {}).get("encryption_issues", [])),
            "service_issues": len(all_results.get("services", {}).get("cloud_run", {}).get("public_access", [])) + len(all_results.get("services", {}).get("cloud_run", {}).get("resource_limits", [])),
            "failed_dags": all_results.get("etl", {}).get("summary", {}).get("failed_dags", 0),
            "slow_tasks": all_results.get("etl", {}).get("summary", {}).get("slow_tasks", 0),
            "unhealthy_workers": all_results.get("etl", {}).get("summary", {}).get("unhealthy_workers", 0),
            "stale_dags": all_results.get("etl", {}).get("summary", {}).get("stale_dags", 0),
            "missing_retries": all_results.get("etl", {}).get("summary", {}).get("missing_retries", 0),
        }
        if slack_webhook:
            alert_utils.send_slack_alert(slack_webhook, summary, all_findings, "Full Scan")
        if email_to and email_from:
            alert_utils.send_email_alert(email_to, email_from, "smtp.gmail.com", 587, summary, all_findings, "Full Scan")
    
    # Exit with error code
    if fail_on_high and high_severity_findings:
        ctx.exit(1)
    ctx.exit(1 if all_findings else 0)


def _resolve_project(ctx: click.Context, override: str | None) -> str:
    project = override or ctx.obj.get("project") or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise click.UsageError(
            "Missing project. Pass --project or set GOOGLE_CLOUD_PROJECT."
        )
    return project


def _emit_gcp_json_output(
    iam_result: gcp_iam.IAMResult | None,
    storage_result: gcp_storage.StorageResult | None,
) -> None:
    """Emit nested JSON output format."""
    output = {
        "gcp": {
            "iam": (iam_result.to_dict() if iam_result else {"risks": [], "passed": []}),
            "storage": (
                storage_result.to_dict()
                if storage_result
                else {"public_buckets": [], "encryption_issues": []}
            ),
        },
        "services": {},
    }
    click.echo(json.dumps(output, indent=2))


def _emit_gcp_table_output(
    iam_result: gcp_iam.IAMResult | None,
    storage_result: gcp_storage.StorageResult | None,
    console: Optional[Console] = None,
) -> None:
    """Emit human-readable table output."""
    all_findings: List[Tuple[str, str, str, str]] = []

    # IAM risks
    if iam_result and iam_result.risks:
        for risk in iam_result.risks:
            all_findings.append(
                (
                    risk.resource,
                    risk.issue,
                    risk.severity.upper(),
                    _short_metadata(risk.metadata),
                )
            )

    # Storage public buckets
    if storage_result and storage_result.public_buckets:
        for bucket in storage_result.public_buckets:
            all_findings.append(
                (
                    bucket.get("resource", bucket.get("bucket", "unknown")),
                    "Bucket grants access to allUsers/allAuthenticatedUsers",
                    "HIGH",
                    _short_metadata(bucket),
                )
            )

    # Storage encryption issues
    if storage_result and storage_result.encryption_issues:
        for issue in storage_result.encryption_issues:
            all_findings.append(
                (
                    issue.get("resource", issue.get("bucket", "unknown")),
                    issue.get("issue", "Encryption issue"),
                    issue.get("severity", "HIGH").upper(),
                    _short_metadata(issue),
                )
            )

    if not all_findings:
        if console:
            console.print("[green]✓[/green] No misconfigurations detected.")
        else:
            click.echo("✅ No misconfigurations detected.")
        if iam_result and iam_result.passed:
            if console:
                console.print("\n[bold]Passed checks:[/bold]")
                for check in iam_result.passed:
                    console.print(f"  [green]✓[/green] {check.get('message', 'Check passed')}")
            else:
                click.echo("\nPassed checks:")
                for check in iam_result.passed:
                    click.echo(f"  ✓ {check.get('message', 'Check passed')}")
        return

    headers = ("Resource", "Issue", "Severity", "Metadata")
    if console and RICH_AVAILABLE:
        try:
            table = create_rich_table(headers, all_findings, title="GCP Scan Results")
            console.print(table)
        except Exception:
            # Fallback to ASCII
            click.echo(_format_table(headers, all_findings))
    else:
        click.echo(_format_table(headers, all_findings))

    # Show passed checks
    if iam_result and iam_result.passed:
        if console:
            console.print("\n[bold]Passed checks:[/bold]")
            for check in iam_result.passed:
                console.print(f"  [green]✓[/green] {check.get('message', 'Check passed')}")
        else:
            click.echo("\nPassed checks:")
            for check in iam_result.passed:
                click.echo(f"  ✓ {check.get('message', 'Check passed')}")


def _emit_services_json_output(service_result: cloud_run.ServiceScanResult) -> None:
    output = {"services": {"cloud_run": service_result.to_dict()}}
    click.echo(json.dumps(output, indent=2))


def _emit_services_table_output(service_result: cloud_run.ServiceScanResult) -> None:
    findings = [
        (
            finding.service,
            finding.message,
            finding.severity.upper(),
            _short_metadata(finding.metadata),
        )
        for finding in service_result.all_findings()
    ]

    if not findings:
        click.echo("✅ No Cloud Run service misconfigurations detected.")
        return

    headers = ("Service", "Issue", "Severity", "Metadata")
    click.echo(_format_table(headers, findings))


def _emit_etl_json_output(etl_result: etl_airflow.ETLScanResult) -> None:
    """Emit ETL scan results in JSON format with summary."""
    summary = etl_result.get_summary()
    output = {
        "etl": {
            "airflow": etl_result.to_dict(),
            "summary": summary,
        }
    }
    click.echo(json.dumps(output, indent=2))


def _emit_etl_table_output(etl_result: etl_airflow.ETLScanResult) -> None:
    """Emit ETL scan results in table format with alert summary."""
    summary = etl_result.get_summary()

    # Show alert summary
    alerts = []
    if summary["failed_dags"] > 0:
        alerts.append(f"{summary['failed_dags']} failed DAG(s)")
    if summary["slow_tasks"] > 0:
        alerts.append(f"{summary['slow_tasks']} slow task(s)")
    if summary["unhealthy_workers"] > 0:
        alerts.append(f"{summary['unhealthy_workers']} unhealthy worker(s)")
    if summary["stale_dags"] > 0:
        alerts.append(f"{summary['stale_dags']} stale DAG(s)")
    if summary["missing_retries"] > 0:
        alerts.append(f"{summary['missing_retries']} DAG(s) missing retries")

    if alerts:
        click.echo(f"⚠️  Alert Summary: {', '.join(alerts)}\n")

    findings = [
        (
            finding.dag_id,
            finding.message,
            finding.severity.upper(),
            _short_metadata(finding.metadata),
        )
        for finding in etl_result.all_findings()
    ]

    if not findings:
        click.echo("✅ No Airflow/ETL issues detected.")
        return

    # Group by severity for better readability
    high_findings = [f for f in findings if f[2] == "HIGH"]
    medium_findings = [f for f in findings if f[2] == "MEDIUM"]
    low_findings = [f for f in findings if f[2] == "LOW"]

    headers = ("DAG ID", "Issue", "Severity", "Metadata")

    if high_findings:
        click.echo("HIGH Severity:")
        click.echo(_format_table(headers, high_findings))
        click.echo()

    if medium_findings:
        click.echo("MEDIUM Severity:")
        click.echo(_format_table(headers, medium_findings))
        click.echo()

    if low_findings:
        click.echo("LOW Severity:")
        click.echo(_format_table(headers, low_findings))


def _short_metadata(metadata: Dict[str, object], limit: int = 60) -> str:
    parts = [
        f"{key}={_stringify_value(metadata[key])}" for key in sorted(metadata.keys())
    ]
    summary = ", ".join(parts) or "-"
    if len(summary) <= limit:
        return summary
    return summary[: limit - 3] + "..."


def _stringify_value(value: object) -> str:
    if isinstance(value, datetime):
        return value.isoformat()
    if value is None:
        return "-"
    return str(value)


def _format_table(headers: Tuple[str, ...], rows: Iterable[Tuple[str, ...]]) -> str:
    all_rows: List[Tuple[str, ...]] = list(rows)
    widths = [len(col) for col in headers]

    for row in all_rows:
        widths = [max(width, len(col)) for width, col in zip(widths, row)]

    def _fmt(row: Tuple[str, ...]) -> str:
        padded = [col.ljust(widths[idx]) for idx, col in enumerate(row)]
        return "  ".join(padded)

    divider = "  ".join("-" * width for width in widths)
    lines = [_fmt(headers), divider]
    lines.extend(_fmt(row) for row in all_rows)
    return "\n".join(lines)


def main() -> None:
    """Executable entry point for `python -m sentinel.cli`."""

    cli(prog_name="cloudsentinal")  # pragma: no cover


if __name__ == "__main__":  # pragma: no cover
    main()
