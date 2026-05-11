import re
from pathlib import Path
from typing import List, Dict, Pattern, Tuple

from scanner.models import Finding


CODE_FILE_EXTENSIONS = {
    ".java",
    ".kt",
    ".kts",
    ".smali",
    ".js",
}

MAX_CODE_FILE_SIZE_BYTES = 3 * 1024 * 1024


IGNORED_DIRS = {
    "__pycache__",
    ".git",
    "build",
    "dist",
    "node_modules",
    "reports",
    "venv",
}


THIRD_PARTY_PATH_HINTS = (
    "/androidx/",
    "\\androidx\\",
    "/kotlin/",
    "\\kotlin\\",
    "/kotlinx/",
    "\\kotlinx\\",
    "/okhttp3/",
    "\\okhttp3\\",
    "/retrofit2/",
    "\\retrofit2\\",
    "/com/google/android/gms/",
    "\\com\\google\\android\\gms\\",
    "/com/google/firebase/",
    "\\com\\google\\firebase\\",
    "/org/apache/",
    "\\org\\apache\\",
)


CODE_PATTERNS: List[Dict[str, object]] = [
    {
        "rule_id": "CODE_WEAK_HASH_MD5",
        "title": "Weak hash algorithm MD5 used",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(
            r"(MessageDigest\.getInstance\s*\(\s*[\"']MD5[\"']|const-string[^\n]*[\"']MD5[\"'])",
            re.IGNORECASE,
        ),
        "impact": "MD5 is cryptographically weak and should not be used for password hashing, integrity protection, or security-sensitive operations.",
        "recommendation": "Use stronger algorithms such as SHA-256 for hashing, or password hashing algorithms like bcrypt, scrypt, or Argon2 for passwords.",
    },
    {
        "rule_id": "CODE_WEAK_HASH_SHA1",
        "title": "Weak hash algorithm SHA-1 used",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(
            r"(MessageDigest\.getInstance\s*\(\s*[\"']SHA-?1[\"']|const-string[^\n]*[\"']SHA-?1[\"'])",
            re.IGNORECASE,
        ),
        "impact": "SHA-1 is considered weak for collision resistance and should not be used in security-sensitive contexts.",
        "recommendation": "Use SHA-256 or stronger hashing algorithms where hashing is required.",
    },
    {
        "rule_id": "CODE_AES_ECB_MODE",
        "title": "AES ECB mode used",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(
            r"(Cipher\.getInstance\s*\(\s*[\"']AES/ECB[^\"']*[\"']|const-string[^\n]*[\"']AES/ECB[^\"']*[\"'])",
            re.IGNORECASE,
        ),
        "impact": "ECB mode does not provide semantic security and can reveal patterns in encrypted data.",
        "recommendation": "Use AES-GCM where possible, or AES-CBC with a random IV and proper authentication.",
    },
    {
        "rule_id": "CODE_DES_USAGE",
        "title": "DES or 3DES encryption used",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(
            r"(Cipher\.getInstance\s*\(\s*[\"']DES[^\"']*[\"']|Cipher\.getInstance\s*\(\s*[\"']DESede[^\"']*[\"']|const-string[^\n]*[\"']DESede?[\"'])",
            re.IGNORECASE,
        ),
        "impact": "DES is obsolete and 3DES is deprecated for modern security requirements.",
        "recommendation": "Replace DES/3DES with modern authenticated encryption such as AES-GCM.",
    },
    {
        "rule_id": "CODE_HARDCODED_CRYPTO_KEY",
        "title": "Possible hardcoded cryptographic key",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(
            r"(?i)\b(secretKey|secret_key|cryptoKey|crypto_key|encryptionKey|encryption_key|aesKey|aes_key|privateKey|private_key)\b\s*(?:=|:)\s*[\"'][A-Za-z0-9_\-+/=]{12,}[\"']"
        ),
        "impact": "Hardcoded cryptographic keys can be extracted from the APK and used to decrypt protected data or impersonate services.",
        "recommendation": "Do not store cryptographic keys in client-side code. Use Android Keystore or backend-managed key material.",
    },
    {
        "rule_id": "CODE_SECRET_KEY_SPEC_LITERAL",
        "title": "Hardcoded key used in SecretKeySpec",
        "severity": "High",
        "category": "Crypto",
        "pattern": re.compile(
            r"SecretKeySpec\s*\(\s*[\"'][A-Za-z0-9_\-+/=]{12,}[\"']\.getBytes\s*\(",
            re.IGNORECASE,
        ),
        "impact": "Using a hardcoded literal key in SecretKeySpec can expose encryption keys through reverse engineering.",
        "recommendation": "Generate or retrieve keys securely using Android Keystore or a secure backend service.",
    },
    {
        "rule_id": "CODE_HARDCODED_IV",
        "title": "Possible hardcoded initialization vector",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(
            r"(?i)(\biv\b|initializationVector)\s*(?:=|:)\s*[\"'][A-Za-z0-9_\-+/=]{12,}[\"']|IvParameterSpec\s*\(\s*[\"'][A-Za-z0-9_\-+/=]{12,}[\"']\.getBytes\s*\("
        ),
        "impact": "A fixed IV can weaken encryption and may allow attackers to detect repeated encrypted values.",
        "recommendation": "Generate a new random IV for every encryption operation and store it safely with the ciphertext.",
    },
    {
        "rule_id": "CODE_WEBVIEW_JAVASCRIPT_ENABLED",
        "title": "WebView JavaScript enabled",
        "severity": "Medium",
        "category": "WebView",
        "pattern": re.compile(r"setJavaScriptEnabled\s*\(\s*true\s*\)", re.IGNORECASE),
        "impact": "Enabling JavaScript in WebView can increase attack surface, especially if untrusted content is loaded.",
        "recommendation": "Enable JavaScript only when required and avoid loading untrusted content in WebView.",
    },
    {
        "rule_id": "CODE_WEBVIEW_FILE_ACCESS_ENABLED",
        "title": "WebView file access enabled",
        "severity": "High",
        "category": "WebView",
        "pattern": re.compile(r"setAllowFileAccess\s*\(\s*true\s*\)", re.IGNORECASE),
        "impact": "File access in WebView may allow local file exposure or abuse when combined with unsafe content loading.",
        "recommendation": "Disable file access unless strictly required by setting setAllowFileAccess(false).",
    },
    {
        "rule_id": "CODE_WEBVIEW_UNIVERSAL_FILE_ACCESS",
        "title": "WebView universal access from file URLs enabled",
        "severity": "High",
        "category": "WebView",
        "pattern": re.compile(r"setAllowUniversalAccessFromFileURLs\s*\(\s*true\s*\)", re.IGNORECASE),
        "impact": "Universal access from file URLs can allow local files to access remote origins, increasing the risk of data exposure.",
        "recommendation": "Keep universal access from file URLs disabled unless there is a strong and controlled reason.",
    },
    {
        "rule_id": "CODE_SENSITIVE_LOGGING",
        "title": "Possible sensitive data logging",
        "severity": "Medium",
        "category": "Logging",
        "pattern": re.compile(
            r"(?i)Log\.(d|e|i|v|w)\s*\([^;]*(password|token|secret|apikey|api_key|authorization|bearer)[^;]*\)"
        ),
        "impact": "Sensitive data written to logs may be exposed through logcat, debugging tools, or compromised devices.",
        "recommendation": "Remove sensitive values from logs and avoid logging authentication data or secrets.",
    },
    {
        "rule_id": "CODE_INSECURE_RANDOM",
        "title": "Insecure random generator used in security context",
        "severity": "Medium",
        "category": "Crypto",
        "pattern": re.compile(r"new\s+Random\s*\(", re.IGNORECASE),
        "impact": "java.util.Random is not suitable for security-sensitive randomness such as tokens, keys, salts, or IVs.",
        "recommendation": "Use SecureRandom for security-sensitive random values.",
        "requires_security_context": True,
    },
]


SECURITY_CONTEXT_KEYWORDS = {
    "token",
    "key",
    "secret",
    "password",
    "salt",
    "iv",
    "nonce",
    "crypto",
    "encrypt",
    "decrypt",
    "auth",
}


def is_code_file(file_path: Path) -> bool:
    return file_path.suffix.lower() in CODE_FILE_EXTENSIONS


def normalized_path(file_path: Path) -> str:
    return str(file_path).replace("\\", "/")


def should_skip_file(file_path: Path) -> bool:
    if any(part in IGNORED_DIRS for part in file_path.parts):
        return True

    path_text = normalized_path(file_path).lower()

    if any(hint.lower().replace("\\", "/") in path_text for hint in THIRD_PARTY_PATH_HINTS):
        return True

    try:
        if file_path.stat().st_size > MAX_CODE_FILE_SIZE_BYTES:
            return True
    except OSError:
        return True

    return False


def read_text_safely(file_path: Path) -> str:
    try:
        return file_path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return ""


def clean_evidence(line_text: str, line_number: int) -> str:
    evidence = line_text.strip().replace("\t", " ")

    if len(evidence) > 170:
        evidence = evidence[:170] + "..."

    return f"Line {line_number}: {evidence}"


def has_security_context(content: str, line_index: int) -> bool:
    lines = content.splitlines()

    start = max(0, line_index - 3)
    end = min(len(lines), line_index + 4)

    context = "\n".join(lines[start:end]).lower()

    return any(keyword in context for keyword in SECURITY_CONTEXT_KEYWORDS)


def scan_code(extracted_app_path: Path) -> List[Finding]:
    findings: List[Finding] = []
    seen_findings = set()

    candidate_files = [
        file_path
        for file_path in extracted_app_path.rglob("*")
        if file_path.is_file()
        and is_code_file(file_path)
        and not should_skip_file(file_path)
    ]

    for file_path in candidate_files:
        content = read_text_safely(file_path)

        if not content:
            continue

        lines = content.splitlines()

        for line_index, line_text in enumerate(lines):
            line_number = line_index + 1

            stripped_line = line_text.strip()

            if not stripped_line:
                continue

            if stripped_line.startswith("//") or stripped_line.startswith("*"):
                continue

            for rule in CODE_PATTERNS:
                pattern: Pattern[str] = rule["pattern"]  # type: ignore

                if not pattern.search(line_text):
                    continue

                if bool(rule.get("requires_security_context")):
                    if not has_security_context(content, line_index):
                        continue

                evidence = clean_evidence(line_text, line_number)

                duplicate_key: Tuple[str, str, str] = (
                    str(rule["rule_id"]),
                    str(file_path),
                    evidence,
                )

                if duplicate_key in seen_findings:
                    continue

                seen_findings.add(duplicate_key)

                findings.append(
                    Finding(
                        rule_id=str(rule["rule_id"]),
                        title=str(rule["title"]),
                        severity=str(rule["severity"]),
                        file_path=str(file_path),
                        evidence=evidence,
                        impact=str(rule["impact"]),
                        recommendation=str(rule["recommendation"]),
                        category=str(rule["category"]),
                    )
                )

    return findings