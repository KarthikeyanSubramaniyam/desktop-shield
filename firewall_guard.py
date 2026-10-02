"""Cross-platform, opt-in firewall helper for desktop users.

Status is read-only. Changes require --apply and administrator/root rights.
The tool never disables a firewall or opens a port range.
"""
from __future__ import annotations

import argparse
import platform
import shutil
import subprocess
import sys
from pathlib import Path


def run(command: list[str]) -> str:
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def status() -> str:
    system = platform.system()
    if system == "Windows":
        return run(["netsh", "advfirewall", "show", "allprofiles"])
    if system == "Darwin":
        tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        return "\n".join([run([tool, "--getglobalstate"]), run([tool, "--getstealthmode"])])
    if system == "Linux":
        if shutil.which("ufw"):
            return run(["ufw", "status", "verbose"])
        if shutil.which("firewall-cmd"):
            return run(["firewall-cmd", "--state"])
        if shutil.which("nft"):
            return run(["nft", "list", "ruleset"])
        return "No supported firewall command found (checked ufw, firewalld, nftables)."
    return f"Unsupported operating system: {system}"


def allow_program(path: Path, rule_name: str, apply: bool) -> str:
    system = platform.system()
    if not path.is_absolute():
        raise ValueError("Program path must be absolute.")
    if not apply:
        return f"DRY RUN: would add an allow rule for {path}. Re-run with --apply after review."
    if system == "Windows":
        return run(["netsh", "advfirewall", "firewall", "add", "rule", f"name={rule_name}", "dir=in", "action=allow", f"program={path}", "enable=yes", "profile=private,domain"])
    if system == "Darwin":
        tool = "/usr/libexec/ApplicationFirewall/socketfilterfw"
        return run(["sudo", tool, "--add", str(path)]) + "\n" + run(["sudo", tool, "--unblockapp", str(path)])
    if system == "Linux":
        raise RuntimeError("Linux firewalls generally allow ports/services, not executable paths. Configure a specific service with ufw/firewalld instead.")
    raise RuntimeError(f"Unsupported operating system: {system}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or safely configure the native desktop firewall.")
    parser.add_argument("--status", action="store_true", help="Show firewall status (default).")
    parser.add_argument("--allow-program", metavar="PATH", help="Absolute program path to allow where supported.")
    parser.add_argument("--rule-name", default="DesktopShield Allow Program")
    parser.add_argument("--apply", action="store_true", help="Apply the reviewed change; requires elevation.")
    args = parser.parse_args()
    try:
        print(status() if not args.allow_program else allow_program(Path(args.allow_program), args.rule_name, args.apply))
    except (OSError, RuntimeError, ValueError) as exc:
        print(f"Firewall operation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
