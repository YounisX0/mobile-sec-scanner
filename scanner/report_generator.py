import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Tuple
from html import escape

from jinja2 import Template

from scanner.models import Finding


def safe_app_name(extracted_app_path: Path) -> str:
    """
    Creates a safe app name based on the extracted folder name.
    """
    return extracted_app_path.name.replace(" ", "_")


def generate_report_files(
    extracted_app_path: Path,
    findings: List[Finding],
    summary: Dict[str, object],
    output_dir: Path = Path("reports"),
) -> Tuple[Path, Path]:
    """
    Generates both JSON and HTML reports.

    Returns:
        Tuple containing:
        - JSON report path
        - HTML report path
    """
    output_dir.mkdir(parents=True, exist_ok=True)

    app_name = safe_app_name(extracted_app_path)
    scan_timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    json_report_path = output_dir / f"{app_name}_security_report_{scan_timestamp}.json"
    html_report_path = output_dir / f"{app_name}_security_report_{scan_timestamp}.html"

    report_data = build_report_data(
        extracted_app_path=extracted_app_path,
        findings=findings,
        summary=summary,
        scan_timestamp=scan_timestamp,
    )

    write_json_report(json_report_path, report_data)
    write_html_report(html_report_path, report_data)

    return json_report_path, html_report_path


def build_report_data(
    extracted_app_path: Path,
    findings: List[Finding],
    summary: Dict[str, object],
    scan_timestamp: str,
) -> Dict[str, object]:
    """
    Builds the final report data object used by JSON and HTML reports.
    """
    return {
        "tool_name": "APKLab Security Scanner",
        "scan_timestamp": scan_timestamp,
        "app": {
            "name": extracted_app_path.name,
            "path": str(extracted_app_path),
        },
        "summary": summary,
        "findings": [finding.to_dict() for finding in findings],
    }


def write_json_report(report_path: Path, report_data: Dict[str, object]) -> None:
    """
    Writes the JSON report.
    """
    with report_path.open("w", encoding="utf-8") as file:
        json.dump(report_data, file, indent=4, ensure_ascii=False)


def severity_badge_class(severity: str) -> str:
    """
    Maps severity names to CSS classes.
    """
    severity = severity.lower()

    if severity == "critical":
        return "critical"

    if severity == "high":
        return "high"

    if severity == "medium":
        return "medium"

    if severity == "low":
        return "low"

    return "info"


def write_html_report(report_path: Path, report_data: Dict[str, object]) -> None:
    """
    Writes the HTML report using a Jinja2 template.
    """
    template = Template(HTML_TEMPLATE)

    findings = report_data.get("findings", [])
    summary = report_data.get("summary", {})

    rendered_html = template.render(
        tool_name=escape(str(report_data.get("tool_name", ""))),
        scan_timestamp=escape(str(report_data.get("scan_timestamp", ""))),
        app=report_data.get("app", {}),
        summary=summary,
        findings=findings,
        severity_badge_class=severity_badge_class,
        escape=escape,
    )

    with report_path.open("w", encoding="utf-8") as file:
        file.write(rendered_html)


HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>{{ tool_name }} Report</title>

    <style>
        body {
            font-family: Arial, Helvetica, sans-serif;
            background: #0f172a;
            color: #e5e7eb;
            margin: 0;
            padding: 0;
        }

        .container {
            width: 92%;
            margin: 30px auto;
        }

        .header {
            background: linear-gradient(135deg, #1e293b, #020617);
            padding: 28px;
            border-radius: 18px;
            border: 1px solid #334155;
            margin-bottom: 24px;
        }

        .header h1 {
            margin: 0;
            font-size: 32px;
            color: #38bdf8;
        }

        .header p {
            margin: 8px 0 0 0;
            color: #cbd5e1;
        }

        .grid {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 24px;
        }

        .card {
            background: #111827;
            border: 1px solid #334155;
            padding: 18px;
            border-radius: 16px;
        }

        .card h3 {
            margin: 0;
            color: #94a3b8;
            font-size: 14px;
            text-transform: uppercase;
        }

        .card .number {
            font-size: 32px;
            font-weight: bold;
            margin-top: 10px;
        }

        .critical-text {
            color: #ef4444;
        }

        .high-text {
            color: #f97316;
        }

        .medium-text {
            color: #facc15;
        }

        .low-text {
            color: #22c55e;
        }

        .section {
            background: #111827;
            border: 1px solid #334155;
            border-radius: 16px;
            padding: 22px;
            margin-bottom: 24px;
        }

        .section h2 {
            margin-top: 0;
            color: #38bdf8;
        }

        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 14px;
            font-size: 14px;
        }

        th {
            background: #1e293b;
            color: #f8fafc;
            text-align: left;
            padding: 12px;
            border-bottom: 1px solid #334155;
        }

        td {
            padding: 12px;
            border-bottom: 1px solid #334155;
            vertical-align: top;
        }

        tr:hover {
            background: #0f172a;
        }

        .badge {
            padding: 5px 9px;
            border-radius: 999px;
            font-size: 12px;
            font-weight: bold;
            display: inline-block;
        }

        .critical {
            background: #7f1d1d;
            color: #fecaca;
        }

        .high {
            background: #7c2d12;
            color: #fed7aa;
        }

        .medium {
            background: #713f12;
            color: #fef3c7;
        }

        .low {
            background: #14532d;
            color: #bbf7d0;
        }

        .info {
            background: #1e3a8a;
            color: #bfdbfe;
        }

        .evidence {
            font-family: Consolas, monospace;
            background: #020617;
            padding: 8px;
            border-radius: 8px;
            color: #e2e8f0;
            word-break: break-word;
        }

        .small {
            color: #94a3b8;
            font-size: 13px;
        }

        .footer {
            text-align: center;
            color: #64748b;
            margin: 30px 0;
            font-size: 13px;
        }

        @media print {
            body {
                background: white;
                color: black;
            }

            .header, .section, .card {
                background: white;
                color: black;
                border: 1px solid #ccc;
            }

            th {
                background: #eee;
                color: black;
            }

            .evidence {
                background: #f3f4f6;
                color: black;
            }
        }
    </style>
</head>

<body>
    <div class="container">

        <div class="header">
            <h1>{{ tool_name }}</h1>
            <p>Android Static Security Analysis Report</p>
            <p class="small">
                App: {{ escape(app.name) }} |
                Path: {{ escape(app.path) }} |
                Scan Time: {{ scan_timestamp }}
            </p>
        </div>

        {% set severity_counts = summary.severity_counts %}
        {% set category_counts = summary.category_counts %}
        {% set scanner_counts = summary.scanner_counts %}

        <div class="grid">
            <div class="card">
                <h3>Total Findings</h3>
                <div class="number">{{ summary.total_findings }}</div>
            </div>

            <div class="card">
                <h3>Critical</h3>
                <div class="number critical-text">{{ severity_counts.Critical }}</div>
            </div>

            <div class="card">
                <h3>High</h3>
                <div class="number high-text">{{ severity_counts.High }}</div>
            </div>

            <div class="card">
                <h3>Medium / Low</h3>
                <div class="number">
                    <span class="medium-text">{{ severity_counts.Medium }}</span>
                    /
                    <span class="low-text">{{ severity_counts.Low }}</span>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Scanner Module Results</h2>
            <table>
                <thead>
                    <tr>
                        <th>Scanner Module</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {% for scanner_name, count in scanner_counts.items() %}
                    <tr>
                        <td>{{ escape(scanner_name) }}</td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Findings by Category</h2>
            <table>
                <thead>
                    <tr>
                        <th>Category</th>
                        <th>Findings</th>
                    </tr>
                </thead>
                <tbody>
                    {% for category, count in category_counts.items() %}
                    <tr>
                        <td>{{ escape(category) }}</td>
                        <td>{{ count }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="section">
            <h2>Detailed Findings</h2>

            <table>
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Severity</th>
                        <th>Category</th>
                        <th>Rule ID</th>
                        <th>Title</th>
                        <th>File</th>
                        <th>Evidence</th>
                        <th>Impact</th>
                        <th>Recommendation</th>
                    </tr>
                </thead>

                <tbody>
                    {% for finding in findings %}
                    <tr>
                        <td>{{ loop.index }}</td>

                        <td>
                            <span class="badge {{ severity_badge_class(finding.severity) }}">
                                {{ escape(finding.severity) }}
                            </span>
                        </td>

                        <td>{{ escape(finding.category) }}</td>
                        <td>{{ escape(finding.rule_id) }}</td>
                        <td>{{ escape(finding.title) }}</td>
                        <td class="small">{{ escape(finding.file_path) }}</td>

                        <td>
                            <div class="evidence">{{ escape(finding.evidence) }}</div>
                        </td>

                        <td>{{ escape(finding.impact) }}</td>
                        <td>{{ escape(finding.recommendation) }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>

        <div class="footer">
            Generated by APKLab Security Scanner
        </div>

    </div>
</body>
</html>
"""