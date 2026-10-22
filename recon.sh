#!/usr/bin/env bash
#
# recon.sh - Automated reconnaissance pipeline
#
# Runs the usual first steps of a web security assessment in one go:
#   1. Subdomain enumeration   (subfinder, assetfinder, crt.sh)
#   2. Live host detection     (httpx)
#   3. Port scanning           (nmap)
#   4. URL / endpoint discovery (gau or waybackurls)
#   5. A short summary report
#
# Use ONLY against targets you own or are authorised to test
# (bug bounty scope, signed VAPT engagement, your own lab).
#
# Usage:
#   ./recon.sh -d example.com [-o output_dir] [-p top_ports] [--skip-ports] [--skip-urls]

set -uo pipefail

# ---------- colours for readable output ----------
RED="\033[0;31m"; GREEN="\033[0;32m"; YELLOW="\033[1;33m"; BLUE="\033[0;34m"; NC="\033[0m"

info()  { echo -e "${BLUE}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*" >&2; exit 1; }

# ---------- defaults ----------
DOMAIN=""
OUTDIR=""
TOP_PORTS=1000
SKIP_PORTS=false
SKIP_URLS=false

usage() {
  cat <<EOF
Usage: $0 -d <domain> [options]

Options:
  -d <domain>      Target domain (required), e.g. example.com
  -o <dir>         Output directory (default: results/<domain>_<timestamp>)
  -p <number>      Number of top ports for nmap (default: 1000)
  --skip-ports     Skip the nmap port scan
  --skip-urls      Skip URL discovery
  -h               Show this help

Only scan targets you are authorised to test.
EOF
  exit 0
}

# ---------- argument parsing ----------
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="${2:-}"; shift 2 ;;
    -o) OUTDIR="${2:-}"; shift 2 ;;
    -p) TOP_PORTS="${2:-}"; shift 2 ;;
    --skip-ports) SKIP_PORTS=true; shift ;;
    --skip-urls)  SKIP_URLS=true; shift ;;
    -h|--help) usage ;;
    *) fail "Unknown option: $1 (use -h for help)" ;;
  esac
done

[[ -z "$DOMAIN" ]] && fail "No domain given. Example: $0 -d example.com"

# Basic sanity check on the domain so we don't pass junk to the tools
if ! [[ "$DOMAIN" =~ ^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
  fail "'$DOMAIN' does not look like a valid domain"
fi

[[ "$TOP_PORTS" =~ ^[0-9]+$ ]] || fail "-p must be a number"

OUTDIR="${OUTDIR:-results/${DOMAIN}_$(date +%Y%m%d_%H%M%S)}"
mkdir -p "$OUTDIR"

# ---------- tool check ----------
# A tool is only required if the step that uses it is enabled.
has() { command -v "$1" >/dev/null 2>&1; }

check_tools() {
  info "Checking installed tools..."
  local missing=()

  has curl || missing+=("curl")
  has jq   || missing+=("jq")
  has httpx || missing+=("httpx")
  if ! has subfinder && ! has assetfinder; then
    missing+=("subfinder or assetfinder")
  fi
  if [[ "$SKIP_PORTS" == false ]] && ! has nmap; then
    missing+=("nmap")
  fi
  if [[ "$SKIP_URLS" == false ]] && ! has gau && ! has waybackurls; then
    missing+=("gau or waybackurls")
  fi

  if [[ ${#missing[@]} -gt 0 ]]; then
    warn "Missing tools: ${missing[*]}"
    fail "Install them first (see README) or use --skip-ports / --skip-urls"
  fi
  ok "All required tools found"
}

# ---------- step 1: subdomains ----------
enum_subdomains() {
  info "Step 1/4: Enumerating subdomains for $DOMAIN"
  local raw="$OUTDIR/subdomains_raw.txt"
  : > "$raw"

  if has subfinder; then
    subfinder -d "$DOMAIN" -silent >> "$raw" 2>/dev/null
    ok "subfinder done"
  fi

  if has assetfinder; then
    assetfinder --subs-only "$DOMAIN" >> "$raw" 2>/dev/null
    ok "assetfinder done"
  fi

  # Certificate transparency logs via crt.sh (free, no API key)
  curl -s --max-time 60 "https://crt.sh/?q=%25.${DOMAIN}&output=json" \
    | jq -r '.[].name_value' 2>/dev/null \
    | sed 's/\*\.//g' >> "$raw"
  ok "crt.sh done"

  # Keep only entries that belong to the target, lowercase, de-duplicate
  tr '[:upper:]' '[:lower:]' < "$raw" \
    | grep -E "(^|\.)${DOMAIN//./\\.}$" \
    | sort -u > "$OUTDIR/subdomains.txt"

  ok "Found $(wc -l < "$OUTDIR/subdomains.txt") unique subdomains"
}

# ---------- step 2: live hosts ----------
find_live_hosts() {
  info "Step 2/4: Checking which subdomains are live"

  if [[ ! -s "$OUTDIR/subdomains.txt" ]]; then
    warn "No subdomains to probe, skipping"
    : > "$OUTDIR/live_hosts.txt"
    return
  fi

  # Full details (status code, title, tech) for the report
  httpx -l "$OUTDIR/subdomains.txt" -silent -status-code -title -tech-detect \
    -o "$OUTDIR/live_details.txt" >/dev/null 2>&1

  # Plain list of live URLs for the next steps
  cut -d' ' -f1 "$OUTDIR/live_details.txt" | sort -u > "$OUTDIR/live_hosts.txt"

  ok "Found $(wc -l < "$OUTDIR/live_hosts.txt") live hosts"
}

# ---------- step 3: ports ----------
scan_ports() {
  if [[ "$SKIP_PORTS" == true ]]; then
    warn "Step 3/4: Port scan skipped (--skip-ports)"
    return
  fi
  info "Step 3/4: Scanning top $TOP_PORTS ports on live hosts"

  if [[ ! -s "$OUTDIR/live_hosts.txt" ]]; then
    warn "No live hosts, skipping port scan"
    return
  fi

  # nmap wants hostnames, not URLs, so strip scheme and path
  sed -E 's#^https?://##; s#[:/].*$##' "$OUTDIR/live_hosts.txt" \
    | sort -u > "$OUTDIR/live_hostnames.txt"

  nmap -iL "$OUTDIR/live_hostnames.txt" --top-ports "$TOP_PORTS" -T4 --open \
    -oN "$OUTDIR/nmap.txt" >/dev/null 2>&1

  ok "Port scan saved to nmap.txt"
}

# ---------- step 4: URLs ----------
collect_urls() {
  if [[ "$SKIP_URLS" == true ]]; then
    warn "Step 4/4: URL discovery skipped (--skip-urls)"
    return
  fi
  info "Step 4/4: Collecting known URLs from web archives"

  if has gau; then
    gau --subs "$DOMAIN" 2>/dev/null | sort -u > "$OUTDIR/urls.txt"
  else
    echo "$DOMAIN" | waybackurls 2>/dev/null | sort -u > "$OUTDIR/urls.txt"
  fi

  # Pull out URLs that tend to be interesting for testing
  grep -E '\?[^=]+=' "$OUTDIR/urls.txt" > "$OUTDIR/urls_with_params.txt" || true
  grep -Ei '\.(js)(\?|$)' "$OUTDIR/urls.txt" > "$OUTDIR/js_files.txt" || true
  grep -Ei '(admin|login|api|swagger|graphql|debug|backup|\.env|config)' \
    "$OUTDIR/urls.txt" > "$OUTDIR/urls_interesting.txt" || true

  ok "Collected $(wc -l < "$OUTDIR/urls.txt") URLs"
}

# ---------- summary ----------
write_summary() {
  local report="$OUTDIR/summary.md"
  count() { [[ -f "$1" ]] && wc -l < "$1" | tr -d ' ' || echo 0; }

  {
    echo "# Recon summary: $DOMAIN"
    echo
    echo "Generated: $(date '+%Y-%m-%d %H:%M:%S')"
    echo
    echo "| Item | Count |"
    echo "|---|---|"
    echo "| Unique subdomains | $(count "$OUTDIR/subdomains.txt") |"
    echo "| Live hosts | $(count "$OUTDIR/live_hosts.txt") |"
    echo "| Archived URLs | $(count "$OUTDIR/urls.txt") |"
    echo "| URLs with parameters | $(count "$OUTDIR/urls_with_params.txt") |"
    echo "| JavaScript files | $(count "$OUTDIR/js_files.txt") |"
    echo "| Interesting URLs (admin, api, swagger...) | $(count "$OUTDIR/urls_interesting.txt") |"
    echo
    if [[ -s "$OUTDIR/nmap.txt" ]]; then
      echo "## Open ports"
      echo
      echo '```'
      grep -E '^(Nmap scan report|[0-9]+/tcp)' "$OUTDIR/nmap.txt"
      echo '```'
    fi
  } > "$report"

  ok "Summary written to $report"
}

# ---------- main ----------
main() {
  echo
  echo "=============================================="
  echo "  Bash Recon Pipeline  |  target: $DOMAIN"
  echo "=============================================="
  warn "Only scan targets you are authorised to test."
  echo

  local start=$SECONDS
  check_tools
  enum_subdomains
  find_live_hosts
  scan_ports
  collect_urls
  write_summary

  echo
  ok "Done in $((SECONDS - start))s. Results in: $OUTDIR"
}

main
