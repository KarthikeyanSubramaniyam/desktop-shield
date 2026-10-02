# Desktop Shield

Two conservative Windows desktop security helpers:

- `firewall_guard.py` reports Windows Firewall profile status and can add one narrowly scoped, private/domain program rule after an explicit `--apply`.
- `antivirus_scanner.py` performs a non-destructive heuristic scan and reports suspicious extensions/names with SHA-256 hashes. It does not claim to replace Microsoft Defender.

## Requirements

Python 3.10+ on Windows. No third-party dependencies.

## Usage

```powershell
python firewall_guard.py --status
python firewall_guard.py --allow-program "C:\Path\app.exe"
python firewall_guard.py --allow-program "C:\Path\app.exe" --rule-name "My app" --apply

python antivirus_scanner.py "$env:USERPROFILE\Downloads"
python antivirus_scanner.py . --json > findings.json
```

Run firewall changes from an Administrator PowerShell. Review every path and rule before using `--apply`. For real-time protection and remediation, keep Microsoft Defender enabled and investigate findings before taking action.
