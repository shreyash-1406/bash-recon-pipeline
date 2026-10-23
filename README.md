# Bash Recon Pipeline

A single Bash script that automates the first phase of a web security assessment: finding subdomains, checking which are live, scanning their ports, and collecting known URLs. Everything for a target lands in one folder with a short summary report.

> ⚠️ **Authorised use only.** Run this only against domains you own, are in a bug bounty program's scope, or are covered by a signed VAPT engagement.

## Why

Manual recon means running five or six tools one after another and stitching their output together by hand. This script chains them, cleans the results (lowercase, de-duplicated, filtered to the target), and keeps each run's output organised so it can be compared later.

## Pipeline

```
 domain
   │
   ▼
 1. Subdomain enumeration ── subfinder + assetfinder + crt.sh
   │
   ▼
 2. Live host detection ──── httpx (status code, title, tech stack)
   │
   ▼
 3. Port scanning ────────── nmap --top-ports
   │
   ▼
 4. URL discovery ────────── gau / waybackurls → params, JS files, admin/api/swagger
   │
   ▼
 summary.md
```

## Requirements

- Linux or macOS with Bash 4+
- `curl`, `jq`, `nmap`
- [`subfinder`](https://github.com/projectdiscovery/subfinder) and/or [`assetfinder`](https://github.com/tomnomnom/assetfinder)
- [`httpx`](https://github.com/projectdiscovery/httpx)
- [`gau`](https://github.com/lc/gau) or [`waybackurls`](https://github.com/tomnomnom/waybackurls)

On Kali / Debian:

```bash
sudo apt install -y curl jq nmap golang
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/lc/gau/v2/cmd/gau@latest
export PATH="$PATH:$HOME/go/bin"
```

The script checks for these on startup and tells you what is missing.

## Usage

```bash
git clone https://github.com/shreyash-1406/bash-recon-pipeline.git
cd bash-recon-pipeline
chmod +x recon.sh

./recon.sh -d example.com
```

| Option | Description |
|---|---|
| `-d <domain>` | Target domain (required) |
| `-o <dir>` | Output folder (default `results/<domain>_<timestamp>`) |
| `-p <number>` | Number of top ports for nmap (default 1000) |
| `--skip-ports` | Skip the nmap scan (faster, quieter) |
| `--skip-urls` | Skip archive URL discovery |
| `-h` | Help |

Examples:

```bash
# Quick passive-ish run, no port scan
./recon.sh -d example.com --skip-ports

# Top 100 ports, custom output folder
./recon.sh -d example.com -p 100 -o scans/example
```

## Output

```
results/example.com_20261023_103000/
├── subdomains.txt          # unique, cleaned subdomains
├── live_details.txt        # httpx output: URL, status, title, tech
├── live_hosts.txt          # live URLs only
├── nmap.txt                # open ports per host
├── urls.txt                # all archived URLs
├── urls_with_params.txt    # URLs with query parameters (XSS/SQLi/IDOR candidates)
├── js_files.txt            # JavaScript files (secrets, hidden endpoints)
├── urls_interesting.txt    # admin, login, api, swagger, graphql, backup, .env...
└── summary.md              # counts + open ports
```

## Design notes

- **Fails fast**: validates the domain and checks tools before doing any work.
- **Scoped output**: subdomains are filtered so only hosts under the target domain are kept.
- **Modular**: each step is its own function, so adding a tool (e.g. `nuclei`) is one new function plus one line in `main`.
- **Skippable steps**: port and URL steps can be turned off when a program's rules forbid active scanning.

## Roadmap

- [ ] Optional `nuclei` scan on live hosts
- [ ] Scope file support (in-scope / out-of-scope lists)
- [ ] Diff mode to show new subdomains since the last run
- [ ] Screenshots of live hosts

## Author

**Shreyash Uparkar** · [GitHub](https://github.com/shreyash-1406)

## License

MIT, see [LICENSE](LICENSE).
