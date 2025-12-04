"""Output formatting utilities."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

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

import yaml


def get_severity_color(severity: str) -> str:
    """Get color for severity level."""
    severity_upper = severity.upper()
    if severity_upper == "HIGH" or severity_upper == "CRITICAL":
        return "red"
    elif severity_upper == "MEDIUM":
        return "yellow"
    elif severity_upper == "LOW":
        return "green"
    return "white"


def create_rich_table(headers: tuple[str, ...], rows: List[tuple[str, ...]], title: Optional[str] = None) -> Table:
    """Create a rich table with headers and rows."""
    if not RICH_AVAILABLE:
        raise ImportError("rich library is not available")
    
    table = Table(title=title, box=box.ROUNDED, show_header=True, header_style="bold magenta")
    
    for header in headers:
        table.add_column(header, style="cyan", no_wrap=False)
    
    for row in rows:
        # Color code severity column if present
        styled_row = list(row)
        for idx, header in enumerate(headers):
            if header.lower() == "severity" and idx < len(styled_row):
                severity = styled_row[idx]
                color = get_severity_color(severity)
                styled_row[idx] = f"[{color}]{severity}[/{color}]"
        
        table.add_row(*styled_row)
    
    return table


def format_output(data: Dict[str, Any], format_type: str) -> str:
    """Format data as JSON, YAML, or return as-is for table."""
    format_type = format_type.lower()
    
    if format_type == "json":
        return json.dumps(data, indent=2, default=str)
    elif format_type == "yaml":
        return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False)
    else:
        return str(data)


def write_output(content: str, output_path: Optional[str], console: Optional[Console] = None) -> None:
    """Write output to file if path provided, otherwise print to console."""
    if output_path:
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        if console:
            console.print(f"[green]✓[/green] Report written to: {output_path}")
        else:
            print(f"✓ Report written to: {output_path}")
    else:
        if console:
            console.print(content)
        else:
            print(content)

