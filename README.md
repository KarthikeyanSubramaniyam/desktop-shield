# Desktop Shield

Two conservative cross-platform desktop security helpers:

- `firewall_guard.py` detects Windows Defender Firewall, macOS Application Firewall, or Linux UFW/firewalld/nftables and reports status. Changes are opt-in with `--apply`.
- `antivirus_scanner.py` performs a non-destructive heuristic scan and reports suspicious extensions/names with SHA-256 hashes. It does not claim to replace Microsoft Defender.

## Requirements

Python 3.10+ on Windows, macOS, or Linux. No third-party dependencies.

## Usage

```text
python firewall_guard.py --status
python firewall_guard.py --allow-program "/absolute/path/to/app"
python firewall_guard.py --allow-program "/absolute/path/to/app" --rule-name "My app" --apply

python antivirus_scanner.py ~/Downloads
python antivirus_scanner.py . --json > findings.json
```

Run firewall changes from an Administrator PowerShell on Windows or with `sudo` where required on macOS/Linux. Linux executable-path rules are intentionally not created because Linux firewalls normally manage ports/services instead. Review every change before using `--apply`. Keep the platform's built-in antivirus enabled and investigate findings before taking action.
