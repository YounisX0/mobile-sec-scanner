# APKLab Security Scanner

APKLab Security Scanner is a Python-based Android static security analysis tool.

The project uses APKLab only as a reverse-engineering helper to extract APK files into readable content. The custom Python scanner then analyzes the extracted files, applies security rules, classifies findings by severity, and generates a vulnerability report.

## First MVP Scope

The first version scans an already extracted APK folder.

## Main Pipeline

1. APK is extracted using APKLab.
2. Extracted files are placed inside `extracted_apps/`.
3. Python scanner reads manifest, resources, and code files.
4. Rule engine detects vulnerabilities.
5. Severity engine classifies findings.
6. Report generator exports the results.

## Project Structure

```text
mobile-sec-scanner/
├── input_apks/
├── extracted_apps/
├── reports/
├── scanner/
│   ├── manifest_parser.py
│   ├── resource_scanner.py
│   ├── code_scanner.py
│   ├── rule_engine.py
│   ├── severity_engine.py
│   ├── report_generator.py
│   └── models.py
├── app.py
└── requirements.txt