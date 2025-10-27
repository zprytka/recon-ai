#!/bin/bash

# reconIA.sh
# Requirements: amass, httpx, nuclei, curl, jq, testssl.sh, ollama with mistral
# Optional: SHODAN_API_KEY (export it in your environment)
# Usage: ./reconIA.sh targetdomain.com

DOMAIN=$1
if [ -z "$DOMAIN" ]; then
  echo "[!] Usage: $0 targetdomain.com"
  exit 1
fi

# Tool paths
TESTSSL_PATH="/home/zprytka/Tools/testssl/testssl.sh"
NUCLEI_TEMPLATES_DIR="$HOME/nuclei-templates"

# Output directories
OUTDIR="data/$DOMAIN"
mkdir -p "$OUTDIR/headers" "$OUTDIR/tls" "$OUTDIR/nuclei" "$OUTDIR/shodan"

# 1. Subdomain Enumeration
echo "[*] Enumerating subdomains with amass..."
amass enum -passive -d "$DOMAIN" -o "$OUTDIR/subdomains_raw.txt"

# 1.1 Clean subdomains (only valid FQDNs from target domain)
SUBDOMAINS_CLEAN="$OUTDIR/subdomains.txt"
grep -Eo '([a-zA-Z0-9._-]+\.)+'"$DOMAIN" "$OUTDIR/subdomains_raw.txt" \
  | grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -u > "$SUBDOMAINS_CLEAN"

# If no valid subdomains, continue using the main domain
if [[ ! -s "$SUBDOMAINS_CLEAN" ]]; then
  echo "[!] No valid subdomains found. Continuing with $DOMAIN..."
  echo "$DOMAIN" > "$SUBDOMAINS_CLEAN"
fi

# 2. Technology Fingerprinting
echo "[*] Detecting technologies with httpx..."
httpx -silent -title -tech-detect -status-code -json -l "$SUBDOMAINS_CLEAN" > "$OUTDIR/tech.txt"

# 3. HTTP Headers Analysis
for host in $(cat "$SUBDOMAINS_CLEAN"); do
  echo "[*] Analyzing headers for $host..."
  curl -sILk --max-redirs 3 "https://$host" > "$OUTDIR/headers/$host.txt" || \
  curl -sILk --max-redirs 3 "http://$host" > "$OUTDIR/headers/$host.txt"
done

# 4. TLS Analysis
for host in $(cat "$SUBDOMAINS_CLEAN"); do
  echo "[*] Scanning TLS for $host..."
  "$TESTSSL_PATH" --quiet --warnings off "$host" > "$OUTDIR/tls/$host.txt" 2>"$OUTDIR/tls/$host.err"
  
  if grep -qi "permission denied" "$OUTDIR/tls/$host.err"; then
    echo "[!] testssl.sh failed for $host due to permission issues."
    read -p "[?] Retry with sudo? (y/N): " retry_tls
    if [[ "$retry_tls" =~ ^[yY]$ ]]; then
      sudo "$TESTSSL_PATH" --quiet --warnings off "$host" > "$OUTDIR/tls/$host.txt"
    else
      echo "[!] Skipped testssl.sh for $host."
    fi
  fi
done

# 5. Nuclei Scan
echo "[*] Running Nuclei..."

NUCLEI_SUPPORTS_CODE=$(nuclei -h 2>&1 | grep -q "\-code" && echo "yes" || echo "no")
REQUIRES_CODE=$(grep -rEl "(code:|flow:|internal:)" "$NUCLEI_TEMPLATES_DIR" 2>/dev/null | head -n1)

# Basic scan
nuclei -l "$SUBDOMAINS_CLEAN" -t "$NUCLEI_TEMPLATES_DIR" \
  -o "$OUTDIR/nuclei/output.txt" -severity low,medium,high,critical

# Run with -code if supported and needed
if [[ "$NUCLEI_SUPPORTS_CODE" == "yes" && -n "$REQUIRES_CODE" ]]; then
  echo "[*] Some templates require code analysis. Running nuclei with -code..."
  nuclei -l "$SUBDOMAINS_CLEAN" -code -t "$NUCLEI_TEMPLATES_DIR" \
    -o "$OUTDIR/nuclei/code_output.txt" 2>&1 | tee "$OUTDIR/nuclei/code_log.txt"

  if grep -qi "permission denied" "$OUTDIR/nuclei/code_log.txt"; then
    echo "[!] nuclei -code failed due to permission issues."
    read -p "[?] Retry with sudo? (y/N): " retry
    if [[ "$retry" =~ ^[yY]$ ]]; then
      sudo nuclei -l "$SUBDOMAINS_CLEAN" -code -t "$NUCLEI_TEMPLATES_DIR" \
        -o "$OUTDIR/nuclei/code_output.txt"
    else
      echo "[!] Skipped execution with sudo."
    fi
  fi
fi

# 6. Shodan (optional)
if [ -z "$SHODAN_API_KEY" ]; then
  echo "[!] SHODAN_API_KEY not found in environment. Skipping Shodan."
else
  echo "[*] Querying Shodan..."
  for host in $(cat "$SUBDOMAINS_CLEAN"); do
    ip=$(dig +short "$host" | grep -Eo '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n1)
    if [ -n "$ip" ]; then
      curl -s "https://api.shodan.io/shodan/host/$ip?key=$SHODAN_API_KEY" > "$OUTDIR/shodan/$host.json"
    fi
  done
fi

# 7. Prompt for Mistral (LLM)
echo "[*] Generating prompt for Mistral..."
cat > "$OUTDIR/prompt.txt" <<EOF
You are an expert in penetration testing and attack surface analysis. Below is the technical information collected about the domain $DOMAIN.

Your task is to:

1. Identify potential attack vectors or vulnerabilities.
2. Assess the target’s exposure from an external attacker’s perspective.
3. Prioritize findings based on impact and ease of exploitation.
4. Recommend next steps for manual or automated exploration.

--- Detected technologies (httpx) ---
$(cat "$OUTDIR/tech.txt")

--- HTTP headers (selected) ---
$(grep -iE "Server:|X-Powered-By:|Strict|Location:" "$OUTDIR"/headers/* 2>/dev/null)

--- TLS summary (testssl) ---
$(grep -Ei "TLS|SSLv3|RC4|Insecure" "$OUTDIR"/tls/* 2>/dev/null)

--- Nuclei findings ---
$(cat "$OUTDIR/nuclei/output.txt" | head -n 50)
EOF

# 8. Run LLM with Ollama
echo "[*] Sending prompt to Mistral..."
ollama run deepseek-r1:8b "$(cat "$OUTDIR/prompt.txt")" > "$OUTDIR/analysis.txt"

echo "[+] Analysis completed. Review at '$OUTDIR/analysis.txt'"
