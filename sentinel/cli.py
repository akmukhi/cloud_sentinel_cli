"""Cloud Sentinel CLI entry point."""

from __future__ import annotations

import os
from typing import Dict, Iterable, List, Tuple

import click

from sentinel import __version__
from sentinel.modules import gcp_storage

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


@scan.command("gcp", help="Scan GCP Storage buckets for common misconfigurations.")
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
@click.pass_context
def scan_gcp(
    ctx: click.Context,
    project: str | None,
    include_public: bool,
) -> None:
    """Entry point for `cloudsentinal scan gcp`."""

    project_id = _resolve_project(ctx, project)
    output_format = ctx.obj.get("format", "table")

    try:
        findings = gcp_storage.scan_buckets(
            project_id=project_id, include_public=include_public
        )
    except gcp_storage.StorageModuleError as exc:
        raise click.ClickException(str(exc)) from exc

    _emit_findings(findings, output_format)
    ctx.exit(1 if findings else 0)


def _resolve_project(ctx: click.Context, override: str | None) -> str:
    project = override or ctx.obj.get("project") or os.getenv("GOOGLE_CLOUD_PROJECT")
    if not project:
        raise click.UsageError(
            "Missing project. Pass --project or set GOOGLE_CLOUD_PROJECT."
        )
    return project


def _emit_findings(findings: List[gcp_storage.Finding], fmt: str) -> None:
    fmt = fmt.lower()
    if fmt not in OUTPUT_FORMATS:
        raise click.ClickException(f"Unsupported output format: {fmt}")

    if fmt == "json":
        click.echo(gcp_storage.serialize_findings(findings))
        return

    if not findings:
        click.echo("✅ No bucket misconfigurations detected.")
        return

    headers = ("Resource", "Issue", "Severity", "Metadata")
    rows = [
        (
            finding.resource,
            finding.issue,
            finding.severity.upper(),
            _short_metadata(finding.metadata),
        )
        for finding in findings
    ]
    click.echo(_format_table(headers, rows))


def _short_metadata(metadata: Dict[str, object], limit: int = 60) -> str:
    parts = [f"{key}={metadata[key]}" for key in sorted(metadata.keys())]
    summary = ", ".join(parts) or "-"
    if len(summary) <= limit:
        return summary
    return summary[: limit - 3] + "..."


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
