import sys
from pathlib import Path
from rich.console import Console
from scanner.models import Finding


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


def main():
    console.print("[bold cyan]APKLab Security Scanner[/bold cyan]")
    console.print("Phase 1 setup test is running...\n")

    if len(sys.argv) < 2:
        console.print("[yellow]Usage:[/yellow] python app.py extracted_apps/sample_app")
        sys.exit(1)

    extracted_app_path = validate_input_path(sys.argv[1])

    sample_finding = Finding(
        rule_id="SETUP_TEST",
        title="Project setup completed",
        severity="Low",
        file_path=str(extracted_app_path),
        evidence="Scanner structure initialized successfully.",
        impact="This is only a setup test finding.",
        recommendation="Continue to Phase 2 and start implementing the manifest parser.",
        category="Setup"
    )

    console.print("[green]Input folder is valid.[/green]")
    console.print(f"Scanning target: [bold]{extracted_app_path}[/bold]\n")

    console.print("[bold]Sample Finding:[/bold]")
    console.print(sample_finding.to_dict())

    console.print("\n[bold green]Phase 1 setup completed successfully.[/bold green]")


if __name__ == "__main__":
    main()