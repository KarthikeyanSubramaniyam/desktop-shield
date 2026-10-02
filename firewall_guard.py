"""Safe Windows Firewall helper.

This tool only reads status by default. Rule changes require --apply and an
explicit rule name/action; it never disables the firewall or opens broad ports.
Run from an elevated PowerShell prompt for rule changes.
"""
from __future__ import annotations

import argparse
import subprocess
import sys


def run_netsh(args: list[str]) -> str:
    result = subprocess.run(["netsh", *args], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout.strip()


def main() -> int:
    parser = argparse.ArgumentParser(description="Inspect or safely add a Windows Firewall rule.")
    parser.add_argument("--status", action="store_true", help="Show all firewall profiles (default).")
    parser.add_argument("--allow-program", metavar="PATH", help="Program path to allow inbound traffic for.")
    parser.add_argument("--rule-name", default="DesktopShield Allow Program", help="Name for the rule.")
    parser.add_argument("--apply", action="store_true", help="Actually add the rule; requires administrator rights.")
    args = parser.parse_args()

    if not args.allow_program:
        print(run_netsh(["advfirewall", "show", "allprofiles"]))
        return 0

    if not args.apply:
        print(f"DRY RUN: would allow inbound TCP traffic for {args.allow_program!r}.")
        print("Re-run with --apply only after reviewing the path and rule name.")
        return 0

    rule_args = [
        "advfirewall", "firewall", "add", "rule",
        f"name={args.rule_name}", "dir=in", "action=allow",
        f"program={args.allow_program}", "enable=yes", "profile=private,domain",
    ]
    try:
        print(run_netsh(rule_args))
    except RuntimeError as exc:
        print(f"Firewall update failed: {exc}", file=sys.stderr)
        return 1
    print(f"Added rule {args.rule_name!r} for private/domain profiles.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
