# Axios Compromise Scanner

> **One command. Zero dependencies. Know in seconds if you're exposed.**

[![Demo](https://img.shields.io/badge/demo-terminal%20scanner-0ea5e9)](#demo)

A fast, interactive terminal scanner that checks your Node.js projects for exposure to the [axios@1.14.1 supply chain attack](https://socket.dev/blog/axios-1-14-1-supply-chain-attack) (March 31 2026).

```
╔════════════════════════════════════════════════════════════════════╗
║                 axios compromise scanner                          ║
║  v1.0.0 · checks axios@1.14.1 + plain-crypto-js@4.2.1            ║
╚════════════════════════════════════════════════════════════════════╝

  Select folders to scan  (SPACE=toggle  A=all  ENTER=scan  Q=quit)

   [✓]  /Users/you/Documents/vibecoding  (26 projects)
   [ ]  /Users/you/code  (4 projects)
   [ ]  /Users/you/Desktop  (1 projects)

  1 folder(s) selected
```

## The attack

An attacker compromised an Axios maintainer's npm account and published a poisoned release:

- **`axios@1.14.1`** — the trojanised version
- **`plain-crypto-js@4.2.1`** — the malicious dependency it pulled in

npm yanked both within hours, but any project that installed during the window may still have it in lockfiles or `node_modules`.

## Quick start

```bash
# Clone or download
git clone https://github.com/noahsark/axios-compromise-scanner.git
cd axios-compromise-scanner

# Run the interactive scanner
python3 scan.py

# Optional: richer terminal UI (spinners + polished progress bars)
pip install rich

# Or scan specific folders directly
python3 scan.py ~/code ~/projects ~/work
```

## One-command install

### macOS / Linux

```bash
curl -fsSL https://raw.githubusercontent.com/noahsark/axios-compromise-scanner/main/install.sh | sh
axios-scan
```

### Windows (PowerShell)

```powershell
irm https://raw.githubusercontent.com/noahsark/axios-compromise-scanner/main/install.ps1 | iex
python $HOME/.local/bin/axios-scan.py
```

No required `pip install`. No `npm install`. Just Python 3 (pre-installed on macOS/Linux).
If `rich` is installed, the scanner automatically upgrades to prettier spinners/progress bars.

## Features

- **Interactive folder picker** — auto-detects common project directories (`~/code`, `~/dev`, `~/projects`, etc.) and shows how many JS projects each contains
- **Live progress + loading sequence** — a quick startup animation and real-time per-project progress bar
- **Fast** — only checks root-level manifest files, no deep `node_modules` crawl. Scans 50+ projects in under a second
- **Size-safe** — automatically skips lockfiles over 10MB to avoid hanging on massive monorepos
- **JSON output** — pipe results into CI or other tools with `--json`
- **Quiet mode** — just the verdict with `--quiet`
- **Zero dependencies** — pure Python 3 standard library

## Demo

Drop a short GIF at `docs/demo.gif` and embed it here:

```md
![axios scanner demo](docs/demo.gif)
```

Ideal demo flow (10-15 seconds):

1. run command,
2. loading/progress sequence,
3. final verdict.

## Usage

### Interactive mode (default)

```bash
python3 scan.py
```

Arrow keys to navigate, `SPACE` to toggle folders, `A` to select all, `ENTER` to scan, `Q` to quit.

### Direct mode

```bash
python3 scan.py ~/Documents/vibecoding ~/code
```

### CI / Pipeline mode

```bash
python3 scan.py ~/code --json
```

Returns structured JSON:
```json
{
  "roots": ["/Users/you/code"],
  "projects": [
    {"name": "my-app", "status": "CLEAN", "findings": []},
    {"name": "api-server", "status": "AT RISK", "findings": [
      {"file": "/Users/you/code/api-server/package.json", "hits": ["axios@1.14.1"]}
    ]}
  ],
  "total": 2,
  "clean": 1,
  "at_risk": 1,
  "elapsed": 0.01
}
```

### Quiet mode

```bash
python3 scan.py ~/code --quiet
# CLEAN  26 projects scanned in 0.01s — no axios@1.14.1 exposure found.
```

## What it checks

Scans these files in each project root:

| File | Why |
|------|-----|
| `package.json` | Direct dependency declarations |
| `package-lock.json` | Resolved dependency tree (npm) |
| `pnpm-lock.yaml` | Resolved dependency tree (pnpm) |
| `yarn.lock` | Resolved dependency tree (yarn) |
| `bun.lock` | Resolved dependency tree (bun) |

Searches for these indicators:

- `axios@1.14.1` / `"axios": "1.14.1"` / `^1.14.1` / `~1.14.1`
- `plain-crypto-js` / `plain-crypto-js@4.2.1`

## If you're at risk

```bash
# 1. Update axios
npm install axios@latest   # or pnpm add / yarn add / bun add

# 2. Nuke node_modules and reinstall clean
rm -rf node_modules
npm install

# 3. Check for signs of compromise
# The malicious package attempted to exfiltrate environment variables
# Review your .env files and rotate any exposed secrets
```

## Report

A JSON report is saved to `~/axios-scan-report.json` in normal output mode (interactive/direct, non-quiet, non-json).

## Trust and limitations

- This scanner checks lockfiles/manifests for known indicators tied to the March 31, 2026 axios compromise.
- It is a fast triage tool, not a full malware forensics scanner.
- It inspects root-level JS manifest/lockfiles only.
- It can miss compromised environments where indicators were removed or heavily obfuscated.
- If flagged, rotate secrets and follow your incident response process.

## Stay in touch

- Contact: https://x.com/TheArk_Master
- Project repo: https://github.com/noahsark/axios-compromise-scanner

## Contributing

PRs welcome. This is a community tool built in response to a real supply chain attack.

```bash
# Fork, clone, make changes, test
python3 scan.py ~/your-projects

# Submit a PR
```

## License

MIT -- see [LICENSE](LICENSE)

---

Built by [@TheArk_Master](https://x.com/TheArk_Master)
