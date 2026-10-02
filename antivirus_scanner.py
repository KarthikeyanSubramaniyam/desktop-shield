"""Non-destructive, heuristic desktop malware scanner.

It reports suspicious files and never deletes, quarantines, uploads, or
executes anything. Use Microsoft Defender for authoritative malware removal.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path

SUSPICIOUS_EXTENSIONS = {".scr", ".pif", ".hta", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".ps1", ".bat", ".cmd"}
SUSPICIOUS_NAMES = {"mimikatz.exe", "psexec.exe", "procdump.exe"}


def sha256(path: Path, chunk_size: int = 1024 * 1024) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(chunk_size), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan(root: Path, max_bytes: int) -> list[dict[str, object]]:
    findings: list[dict[str, object]] = []
    for current, _, files in os.walk(root):
        for name in files:
            path = Path(current) / name
            try:
                stat = path.stat()
                reasons = []
                if path.suffix.lower() in SUSPICIOUS_EXTENSIONS:
                    reasons.append("script_or_executable_extension")
                if path.name.lower() in SUSPICIOUS_NAMES:
                    reasons.append("known_dual_use_tool_name")
                if stat.st_size > max_bytes:
                    reasons.append("large_file_skipped_hash")
                if reasons:
                    item = {"path": str(path), "size": stat.st_size, "reasons": reasons}
                    if stat.st_size <= max_bytes:
                        item["sha256"] = sha256(path)
                    findings.append(item)
            except (OSError, PermissionError) as exc:
                findings.append({"path": str(path), "error": str(exc)})
    return findings


def main() -> int:
    parser = argparse.ArgumentParser(description="Report suspicious files without modifying them.")
    parser.add_argument("path", nargs="?", default=".", type=Path)
    parser.add_argument("--max-hash-mb", type=int, default=256)
    parser.add_argument("--json", action="store_true", help="Emit machine-readable JSON.")
    args = parser.parse_args()
    findings = scan(args.path.resolve(), args.max_hash_mb * 1024 * 1024)
    if args.json:
        print(json.dumps(findings, indent=2))
    else:
        print(f"Scanned: {args.path.resolve()}")
        print(f"Findings: {len(findings)}")
        for item in findings:
            print(f"- {item.get('path')}: {', '.join(item.get('reasons', ['unreadable']))}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
