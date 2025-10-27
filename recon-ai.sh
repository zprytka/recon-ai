#!/bin/bash

# reconAI.sh - Optimized Recon Tool with LLM Analysis
# Requirements: subfinder, httpx, nuclei, curl, jq, ollama with mistral
# Usage: ./reconAI.sh targetdomain.com

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
  echo "[!] Usage: $0 targetdomain.com"
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

# 1. Subdomain Enumeration
echo "[*] Enumerating subdomains with subfinder..."
subfinder -silent -d "$DOMAIN" > "$OUTDIR/subdomains_raw.txt"

# 1.1 Filter valid FQDNs
SUBDOMAINS_CLEAN="$OUTDIR/subdomains.txt"
grep -Eo '([a-zA-Z0-9._-]+\.)+'"$DOMAIN" "$OUTDIR/subdomains_raw.txt" \
  | grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -u > "$SUBDOMAINS_CLEAN"

if [[ ! -s "$SUBDOMAINS_CLEAN" ]]; then
  echo "[!] No valid subdomains found. Using $DOMAIN instead..."
  echo "$DOMAIN" > "$SUBDOMAINS_CLEAN"
fi

# 2. Technology Fingerprinting
echo "[*] Fingerprinting technologies with httpx..."
HTTPX_OUT="$OUTDIR/tech.txt"
httpx -silent -title -tech-detect -status-code -json -l "$SUBDOMAINS_CLEAN" > "$HTTPX_OUT"

# Summarize httpx output for prompt
jq -r '[.host, .title, .status_code, (.technologies|join(", "))] | @tsv' "$HTTPX_OUT" > "$OUTDIR/tech_summary.tsv"

# 3. HTTP Header Collection (Parallel)
echo "[*] Collecting HTTP headers in parallel..."
cat "$SUBDOMAINS_CLEAN" | xargs -P 10 -I{} bash -c \
'curl -sILk --max-redirs 3 "https://{}" > "'"$OUTDIR"'/headers/{}.txt" || \
 curl -sILk --max-redirs 3 "http://{}" > "'"$OUTDIR"'/headers/{}.txt"'

# Header summary for prompt
find "$OUTDIR/headers" -type f | while read f; do
  echo "[$(basename "$f" .txt)]"
  grep -iE 'Server:|X-Powered-By:|Strict|Location:' "$f" | head -n 2
done > "$OUTDIR/headers_summary.txt"

# 4. Nuclei Scan
echo "[*] Running Nuclei scan..."
nuclei -l "$SUBDOMAINS_CLEAN" -t "$NUCLEI_TEMPLATES_DIR" \
  -o "$OUTDIR/nuclei/output.txt" -severity low,medium,high,critical

# 5. Shodan Queries (Optional & Parallel)
if [ -z "$SHODAN_API_KEY" ]; then
  echo "[!] SHODAN_API_KEY not set. Skipping Shodan."
else
  echo "[*] Querying Shodan in parallel..."
  cat "$SUBDOMAINS_CLEAN" | xargs -P 10 -I{} bash -c '
    ip=$(dig +short {} | grep -Eo "([0-9]{1,3}\.){3}[0-9]{1,3}" | head -n1)
    [ -n "$ip" ] && curl -s "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY" > "'"$OUTDIR"'/shodan/{}.json"'
fi

# 6. Prompt Generation (Summarized)
echo "[*] Creating LLM prompt..."
cat > "$OUTDIR/prompt.txt" <<EOF
You are a cybersecurity expert specializing in external attack surface analysis.

Below is technical reconnaissance information collected on the domain: $DOMAIN

Your tasks:

1. Identify potential attack vectors or weaknesses.
2. Assess the overall exposure of the target.
3. Prioritize the most critical findings.
4. Recommend next steps for manual or automated exploration.

--- Detected Technologies (summary) ---
Host  Title Status Code Technologies
$(cat "$OUTDIR/tech_summary.tsv")

--- HTTP Headers (summary) ---
$(cat "$OUTDIR/headers_summary.txt")

--- Nuclei Vulnerabilities (first 50 lines) ---
$(head -n 50 "$OUTDIR/nuclei/output.txt")
EOF

# 7. Run Mistral (via Ollama)
echo "[*] Sending prompt to mistral via Ollama..."
ollama run mistral "$(cat "$OUTDIR/prompt.txt")" > "$OUTDIR/analysis.txt"

echo "[+] Recon analysis complete. See: $OUTDIR/analysis.txt"
