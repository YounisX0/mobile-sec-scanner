import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from scanner.rule_engine import RuleEngine
from scanner.report_generator import generate_report_files


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


def print_module_results(scanner_counts):
    table = Table(title="Scanner Module Results")

    table.add_column("Scanner Module", style="cyan")
    table.add_column("Findings", style="bold", justify="right")

    for scanner_name, count in scanner_counts.items():
        table.add_row(scanner_name, str(count))

    console.print(table)


def print_findings_table(findings):
    if not findings:
        console.print("[green]No issues found.[/green]")
        return

    table = Table(title="APK Static Security Scan Findings")

    table.add_column("#", style="cyan", justify="right")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Rule ID")
    table.add_column("Title")
    table.add_column("Evidence")

    for index, finding in enumerate(findings, start=1):
        table.add_row(
            str(index),
            finding.severity,
            finding.category,
            finding.rule_id,
            finding.title,
            finding.evidence,
        )

    console.print(table)


def print_summary(summary):
    severity_counts = summary["severity_counts"]
    category_counts = summary["category_counts"]

    console.print("\n[bold]Scan Summary[/bold]")
    console.print(f"Total findings: [bold]{summary['total_findings']}[/bold]")
    console.print(f"Critical: {severity_counts.get('Critical', 0)}")
    console.print(f"High: {severity_counts.get('High', 0)}")
    console.print(f"Medium: {severity_counts.get('Medium', 0)}")
    console.print(f"Low: {severity_counts.get('Low', 0)}")

    console.print("\n[bold]Findings by Category[/bold]")
    for category, count in category_counts.items():
        console.print(f"{category}: {count}")


def print_report_paths(json_report_path: Path, html_report_path: Path):
    console.print("\n[bold]Generated Reports[/bold]")
    console.print(f"JSON report: [green]{json_report_path}[/green]")
    console.print(f"HTML report: [green]{html_report_path}[/green]")


def main():
    console.print("[bold cyan]APKLab Security Scanner[/bold cyan]")
    console.print("Phase 6: Report Generator\n")

    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python app.py extracted_apps/sample_app")
        sys.exit(1)

    extracted_app_path = validate_input_path(sys.argv[1])

    console.print("[green]Input folder is valid.[/green]")
    console.print(f"Scanning target: [bold]{extracted_app_path}[/bold]\n")

    engine = RuleEngine(extracted_app_path)

    findings = engine.run(
        progress_callback=lambda message: console.print(f"[cyan]{message}[/cyan]")
    )

    summary = engine.build_summary()

    console.print()
    print_module_results(engine.get_scanner_counts())

    console.print()
    print_findings_table(findings)

    print_summary(summary)

    json_report_path, html_report_path = generate_report_files(
        extracted_app_path=extracted_app_path,
        findings=findings,
        summary=summary,
    )

    print_report_paths(json_report_path, html_report_path)

    console.print("\n[bold green]Static scan completed successfully.[/bold green]")


if __name__ == "__main__":
    main()