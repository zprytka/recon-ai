#!/bin/bash

# reconAI.sh - Optimized Recon Tool with LLM Analysis
# Requirements: subfinder, httpx, nuclei, curl, jq, ollama with mistral
# Usage: ./reconAI.sh targetdomain.com

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
  echo "[!] Usage: $0 targetdomain.com"
  exit 1
fi

# Validate domain format (security: prevent command injection)
if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$ ]]; then
  echo "[!] Invalid domain format: $DOMAIN"
  echo "[!] Domain must contain only alphanumeric characters, hyphens, and dots"
  exit 1
fi

# Validate required tools
REQUIRED_TOOLS=(subfinder httpx nuclei curl jq ollama dig xargs)
for tool in "${REQUIRED_TOOLS[@]}"; do
  command -v $tool >/dev/null 2>&1 || { echo "[!] $tool not found in PATH"; exit 1; }
done

# Paths and directories
NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"
OUTDIR="data/$DOMAIN"
mkdir -p "$OUTDIR/headers" "$OUTDIR/nuclei" "$OUTDIR/shodan"

# Set restrictive permissions on output directory (security: protect sensitive data)
chmod 700 "$OUTDIR"
chmod 700 "$OUTDIR/headers" "$OUTDIR/nuclei" "$OUTDIR/shodan"

# 1. Subdomain Enumeration (timeout: 5 min)
echo "[*] Enumerating subdomains with subfinder..."
timeout 300 subfinder -silent -d "$DOMAIN" > "$OUTDIR/subdomains_raw.txt" || {
  echo "[!] Subfinder timeout or error"
  touch "$OUTDIR/subdomains_raw.txt"
}

# 1.1 Filter valid FQDNs
SUBDOMAINS_CLEAN="$OUTDIR/subdomains.txt"
grep -Eo '([a-zA-Z0-9._-]+\.)+'"$DOMAIN" "$OUTDIR/subdomains_raw.txt" \
  | grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -u > "$SUBDOMAINS_CLEAN"

if [[ ! -s "$SUBDOMAINS_CLEAN" ]]; then
  echo "[!] No valid subdomains found. Using $DOMAIN instead..."
  echo "$DOMAIN" > "$SUBDOMAINS_CLEAN"
fi

# 2. Filter Active Subdomains (performance: 2-3x faster scans, timeout: 10 min)
echo "[*] Filtering active subdomains..."
ALIVE_SUBS="$OUTDIR/alive_subdomains.txt"
ALIVE_URLS="$OUTDIR/alive_urls.txt"

# Get active hosts and their full URLs
timeout 600 httpx -silent -l "$SUBDOMAINS_CLEAN" > "$ALIVE_URLS"
HTTPX_EXIT=$?

if [[ ! -s "$ALIVE_URLS" ]]; then
  echo "[!] No active subdomains found via httpx. Testing main domain directly..."
  # Fallback: test main domain directly
  timeout 30 httpx -silent "$DOMAIN" > "$ALIVE_URLS"

  if [[ ! -s "$ALIVE_URLS" ]]; then
    echo "[!] Domain $DOMAIN is not responding or unreachable."
    echo "[!] This may be a protected/offline domain or network issue."
    exit 1
  fi
fi

# Extract just the hostnames (remove protocol and path)
sed -E 's#https?://([^/]+).*#\1#' "$ALIVE_URLS" | sort -u > "$ALIVE_SUBS"

TOTAL_SUBS=$(wc -l < "$SUBDOMAINS_CLEAN")
ALIVE_COUNT=$(wc -l < "$ALIVE_SUBS")
echo "[+] Found $ALIVE_COUNT active subdomains out of $TOTAL_SUBS total"

# 3. Technology Fingerprinting (timeout: 5 min)
echo "[*] Fingerprinting technologies with httpx..."
HTTPX_OUT="$OUTDIR/tech.txt"
timeout 300 httpx -silent -title -tech-detect -status-code -json -l "$ALIVE_SUBS" > "$HTTPX_OUT" || {
  echo "[!] httpx tech detection timeout or error"
  echo "[]" > "$HTTPX_OUT"
}

# Summarize httpx output for prompt (handle empty/invalid JSON)
if [ -s "$HTTPX_OUT" ] && jq empty "$HTTPX_OUT" 2>/dev/null; then
  jq -r 'select(. != null) | [.host, .title, .status_code, ((.technologies // [])|join(", "))] | @tsv' "$HTTPX_OUT" > "$OUTDIR/tech_summary.tsv" 2>/dev/null || touch "$OUTDIR/tech_summary.tsv"
else
  touch "$OUTDIR/tech_summary.tsv"
fi

# 4. HTTP Header Collection (Parallel, timeout: 10s per request, SSL verification enabled)
echo "[*] Collecting HTTP headers in parallel..."
cat "$ALIVE_SUBS" | xargs -P 10 -I{} bash -c \
'curl -sIL --max-time 10 --max-redirs 3 "https://{}" > "'"$OUTDIR"'/headers/{}.txt" 2>/dev/null || \
 curl -sIL --max-time 10 --max-redirs 3 "http://{}" > "'"$OUTDIR"'/headers/{}.txt" 2>/dev/null'

# Header summary for prompt
find "$OUTDIR/headers" -type f | while read f; do
  echo "[$(basename "$f" .txt)]"
  grep -iE 'Server:|X-Powered-By:|Strict|Location:' "$f" | head -n 2
done > "$OUTDIR/headers_summary.txt"

# 5. Nuclei Scan (timeout: 10 min)
echo "[*] Running Nuclei scan..."
timeout 600 nuclei -l "$ALIVE_SUBS" -t "$NUCLEI_TEMPLATES_DIR" \
  -o "$OUTDIR/nuclei/output.txt" -severity low,medium,high,critical || {
  echo "[!] Nuclei timeout or error"
  touch "$OUTDIR/nuclei/output.txt"
}

# 6. Shodan Queries (Optional & Parallel with IP deduplication, timeout: 5s per request)
if [ -z "$SHODAN_API_KEY" ]; then
  echo "[!] SHODAN_API_KEY not set. Skipping Shodan."
else
  echo "[*] Resolving IPs and deduplicating..."
  UNIQUE_IPS="$OUTDIR/unique_ips.txt"
  cat "$ALIVE_SUBS" | xargs -P 10 -I{} timeout 5 dig +short +time=2 +tries=1 {} | \
    grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | sort -u > "$UNIQUE_IPS"

  IP_COUNT=$(wc -l < "$UNIQUE_IPS")
  echo "[+] Querying Shodan for $IP_COUNT unique IPs..."

  cat "$UNIQUE_IPS" | xargs -P 5 -I{} bash -c \
    'curl -s --max-time 10 "https://api.shodan.io/shodan/host/{}?key=$SHODAN_API_KEY" > "'"$OUTDIR"'/shodan/{}.json"'
fi

# 6. Prompt Generation (Structured JSON Output)
echo "[*] Creating LLM prompt..."
cat > "$OUTDIR/prompt.txt" <<EOF
You are a cybersecurity expert specializing in external attack surface analysis.

Analyze the reconnaissance data below for domain: $DOMAIN

Provide your response in the following JSON structure:
{
  "executive_summary": "Brief overview of the security posture",
  "risk_score": 0-10,
  "critical_findings": [
    {
      "title": "Finding name",
      "severity": "critical|high|medium|low",
      "description": "Detailed description",
      "affected_hosts": ["host1", "host2"],
      "exploitation_difficulty": "easy|medium|hard",
      "recommended_action": "Immediate action required"
    }
  ],
  "attack_vectors": [
    {
      "vector": "Attack vector name",
      "priority": 1-10,
      "entry_points": ["endpoint1", "endpoint2"],
      "prerequisites": "What is needed to exploit",
      "impact": "Potential impact"
    }
  ],
  "technology_risks": {
    "outdated_technologies": ["tech1", "tech2"],
    "misconfigured_services": ["service1", "service2"],
    "missing_security_headers": ["host1: header", "host2: header"]
  },
  "manual_verification_steps": [
    "Step-by-step manual testing recommendations"
  ],
  "next_actions": {
    "immediate": ["Action 1", "Action 2"],
    "short_term": ["Action 3", "Action 4"],
    "long_term": ["Action 5", "Action 6"]
  }
}

=== RECONNAISSANCE DATA ===

--- Detected Technologies ---
Host | Title | Status Code | Technologies
$(cat "$OUTDIR/tech_summary.tsv")

--- HTTP Headers (Security Analysis) ---
$(cat "$OUTDIR/headers_summary.txt")

--- Nuclei Vulnerability Scan Results ---
$(cat "$OUTDIR/nuclei/output.txt")

Provide only valid JSON in your response, no additional text.
EOF

# 7. Run Mistral (via Ollama, timeout: 5 min)
echo "[*] Sending prompt to mistral via Ollama..."
timeout 300 ollama run mistral "$(cat "$OUTDIR/prompt.txt")" > "$OUTDIR/analysis.txt" || {
  echo "[!] Ollama timeout or error"
  echo "Analysis could not be completed due to timeout" > "$OUTDIR/analysis.txt"
}

# 8. Validate and format JSON output
if command -v jq >/dev/null 2>&1 && [ -s "$OUTDIR/analysis.txt" ]; then
  if jq empty "$OUTDIR/analysis.txt" 2>/dev/null; then
    echo "[+] JSON analysis validated and formatted"
    jq '.' "$OUTDIR/analysis.txt" > "$OUTDIR/analysis.json"
    echo "[+] Results saved to: $OUTDIR/analysis.json"
  else
    echo "[!] Warning: LLM output is not valid JSON, saved as text"
  fi
fi

# 9. Set restrictive permissions on sensitive files
echo "[*] Securing sensitive files..."
find "$OUTDIR" -type f -exec chmod 600 {} \;
[ -d "$OUTDIR/shodan" ] && chmod 600 "$OUTDIR/shodan"/*.json 2>/dev/null
[ -f "$OUTDIR/analysis.txt" ] && chmod 600 "$OUTDIR/analysis.txt"
[ -f "$OUTDIR/analysis.json" ] && chmod 600 "$OUTDIR/analysis.json"

# 10. Generate Summary Metrics
echo ""
echo "=========================================="
echo "           SCAN SUMMARY METRICS           "
echo "=========================================="
echo "Domain: $DOMAIN"
echo "Scan Date: $(date '+%Y-%m-%d %H:%M:%S')"
echo "------------------------------------------"
echo "Subdomains discovered: $TOTAL_SUBS"
echo "Active subdomains: $ALIVE_COUNT"
echo "Inactive subdomains: $((TOTAL_SUBS - ALIVE_COUNT))"

# Count unique IPs
if [ -f "$UNIQUE_IPS" ]; then
  UNIQUE_IP_COUNT=$(wc -l < "$UNIQUE_IPS")
  echo "Unique IP addresses: $UNIQUE_IP_COUNT"
fi

# Count vulnerabilities by severity
if [ -f "$OUTDIR/nuclei/output.txt" ]; then
  CRITICAL_COUNT=$(grep -c "\[critical\]" "$OUTDIR/nuclei/output.txt" 2>/dev/null || echo "0")
  HIGH_COUNT=$(grep -c "\[high\]" "$OUTDIR/nuclei/output.txt" 2>/dev/null || echo "0")
  MEDIUM_COUNT=$(grep -c "\[medium\]" "$OUTDIR/nuclei/output.txt" 2>/dev/null || echo "0")
  LOW_COUNT=$(grep -c "\[low\]" "$OUTDIR/nuclei/output.txt" 2>/dev/null || echo "0")
  TOTAL_VULNS=$((CRITICAL_COUNT + HIGH_COUNT + MEDIUM_COUNT + LOW_COUNT))

  echo "------------------------------------------"
  echo "Nuclei Findings:"
  echo "  Critical: $CRITICAL_COUNT"
  echo "  High: $HIGH_COUNT"
  echo "  Medium: $MEDIUM_COUNT"
  echo "  Low: $LOW_COUNT"
  echo "  Total: $TOTAL_VULNS"
fi

# Count technologies detected
if [ -f "$HTTPX_OUT" ]; then
  TECH_COUNT=$(jq -r '.technologies[]?' "$HTTPX_OUT" 2>/dev/null | sort -u | wc -l)
  echo "------------------------------------------"
  echo "Technologies detected: $TECH_COUNT"
fi

echo "=========================================="
echo "[+] Full results in: $OUTDIR/"
echo "[+] Analysis report: $OUTDIR/analysis.txt"
