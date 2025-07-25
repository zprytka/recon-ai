# ReconIA

A streamlined attack surface and subdomain enumeration script for pentesters, powered by tools like Amass, Nuclei, TestSSL, and an AI assistant (Mistral via Ollama).

## Features

- Subdomain enumeration with Amass
- Technology fingerprinting using httpx
- Header and TLS inspection
- Nuclei vulnerability scanning (with optional -code support)
- Shodan integration (optional)
- LLM-assisted analysis via Mistral/Ollama

## Requirements
- **amass** (go install -v github.com/owasp-amass/amass/v3/...@latest)
- **httpx** (go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)
- **nuclei** (go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest)
- **curl, jq** (sudo apt update && sudo apt install -y curl git unzip jq)
- **testssl.sh** (git clone --depth 1 https://github.com/drwetter/testssl.sh.git Tools/testssl)
- **ollama with Mistral (or whatever you want) model installed**


## Usage

```bash
./reconIA.sh example.com
