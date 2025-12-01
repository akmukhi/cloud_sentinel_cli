"""Cloud Sentinel CLI entry point."""

from __future__ import annotations

import os
from datetime import datetime
from typing import Dict, Iterable, List, Tuple

import click
import json

from sentinel import __version__
from sentinel.modules import cloud_run, gcp_iam, gcp_storage

OUTPUT_FORMATS = ("table", "json")


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
@click.version_option(__version__, prog_name="cloudsentinal")
@click.pass_context
def cli(ctx: click.Context, project: str | None, output_format: str) -> None:
    """Root command storing global options on the Click context."""

    ctx.ensure_object(dict)
    ctx.obj["project"] = project
    ctx.obj["format"] = output_format.lower()


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
@click.pass_context
def scan_gcp(
    ctx: click.Context,
    project: str | None,
    include_public: bool,
    key_age_threshold: int,
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

    # Emit results
    if output_format == "json":
        _emit_gcp_json_output(iam_result, storage_result)
    else:
        _emit_gcp_table_output(iam_result, storage_result)

    # Exit with error code if any risks/issues found
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
        click.echo("✅ No misconfigurations detected.")
        if iam_result and iam_result.passed:
            click.echo("\nPassed checks:")
            for check in iam_result.passed:
                click.echo(f"  ✓ {check.get('message', 'Check passed')}")
        return

    headers = ("Resource", "Issue", "Severity", "Metadata")
    click.echo(_format_table(headers, all_findings))

    # Show passed checks
    if iam_result and iam_result.passed:
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
