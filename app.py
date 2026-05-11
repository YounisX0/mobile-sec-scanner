import sys
from pathlib import Path
from collections import Counter

from rich.console import Console
from rich.table import Table

from scanner.manifest_parser import scan_manifest


console = Console()


def validate_input_path(path: str) -> Path:
    target_path = Path(path)

    if not target_path.exists():
        console.print(f"[red]Error:[/red] Path does not exist: {target_path}")
        sys.exit(1)

    if not target_path.is_dir():
        console.print(f"[red]Error:[/red] Please provide an extracted APK folder, not a file.")
        sys.exit(1)

    return target_path


def print_findings_table(findings):
    if not findings:
        console.print("[green]No issues found.[/green]")
        return

    table = Table(title="Manifest Scan Findings")

    table.add_column("#", style="cyan", justify="right")
    table.add_column("Severity", style="bold")
    table.add_column("Rule ID")
    table.add_column("Title")
    table.add_column("Evidence")

    for index, finding in enumerate(findings, start=1):
        table.add_row(
            str(index),
            finding.severity,
            finding.rule_id,
            finding.title,
            finding.evidence,
        )

    console.print(table)


def print_summary(findings):
    severity_counts = Counter(finding.severity for finding in findings)

    console.print("\n[bold]Scan Summary[/bold]")
    console.print(f"Total findings: [bold]{len(findings)}[/bold]")
    console.print(f"Critical: {severity_counts.get('Critical', 0)}")
    console.print(f"High: {severity_counts.get('High', 0)}")
    console.print(f"Medium: {severity_counts.get('Medium', 0)}")
    console.print(f"Low: {severity_counts.get('Low', 0)}")


def main():
    console.print("[bold cyan]APKLab Security Scanner[/bold cyan]")
    console.print("Phase 2: Manifest Parser\n")

    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python app.py extracted_apps/sample_app")
        sys.exit(1)

    extracted_app_path = validate_input_path(sys.argv[1])

    console.print("[green]Input folder is valid.[/green]")
    console.print(f"Scanning target: [bold]{extracted_app_path}[/bold]\n")

    findings = scan_manifest(extracted_app_path)

    print_findings_table(findings)
    print_summary(findings)

    console.print("\n[bold green]Manifest scan completed.[/bold green]")


if __name__ == "__main__":
    main()