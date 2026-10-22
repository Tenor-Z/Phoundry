# Phoundry

An ultra-fast, high-performance, asynchronous vulnerability audit utility designed to flag unpatched PHP core runtime instances susceptible to **PHP2Shell (CVE-2026-109618 & CVE-2026-109619)**. 

Phoundry runs **completely non-destructive, passive architectural fingerprinting**. It safely catalogs infrastructure without introducing runtime overhead, risking service disruptions, or executing payloads.

<img width="1457" height="632" alt="Screenshot 2026-10-21 213948" src="https://github.com/user-attachments/assets/c6ff3ebd-e323-42cd-a33f-bf3ecdfd2cbb" />

## Main Features
* ⚡ **High-Concurrency Engine:** Uses an asynchronous network pool powered by `httpx` to analyze hundreds of domains concurrently.
* 🛡️ **Detection Resiliency:** Inspects server architectures for hidden or suppressed headers by analyzing cookie state drops and passive signature triggers.
* 🧱 **WAF Visibility:** Proactively alerts operators when results might be obscured or blocked by Web Application Firewalls (Cloudflare, AWS WAF, Akamai, etc.).
* 📊 **Structured Reporting:** Supports raw JSON processing formats for automated orchestration pipelines alongside CSV tracking matrices for security risk teams.
* 🎨 **Rich UI Output:** Features an animated live-rendering bootstrap banner and an interactive, color-coded terminal dashboard.

## Installation

Ensure you have **Python 3.10+** installed, then clone this repository and install the dependencies:

```bash
git clone https://github.com
cd phoundry
pip install -r requirements.txt
```

## Usage Matrix

### Single Target Assessment
Analyze a specific standalone interface deployment directly:
```bash
python main.py -t example.com
```

### Bulk Network Audit (File Input)
Feed a line-separated text file of internal target infrastructure endpoints directly to the processing loop:
```bash
python main.py -f inventory.txt --concurrency 50
```

### Reporting Outputs
Export the final assessment logs directly to data management tiers:
```bash
python main.py -f inventory.txt --json report.json --csv audit_log.csv
```

## Parameter Matrix

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-t, --target` | String URL address of a single asset target vector. | None |
| `-f, --file` | Path to a text document listing target items line-by-line. | None |
| `--json` | Destination file path for full raw JSON structural logs. | None |
| `--csv` | Destination file path for clear tabular Excel-friendly logs. | None |
| `-c, --concurrency` | Total number of background network tasks running at once. | `25` |
| `-o, --timeout` | Network socket connection drop threshold (seconds). | `5` |

## Legal & Compliance Notice
Phoundry is built entirely for system administration inventory, threat management modeling, and defensive corporate compliance audits. Only deploy this scanning platform against infrastructure assets you explicitly own or have explicit written authority to inspect. The creator maintains no liability for operational misuse.
