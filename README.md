# reconIA.sh

A streamlined attack surface and subdomain enumeration script for pentesters, powered by tools like Amass, Nuclei, TestSSL, and an AI assistant (Mistral via Ollama).

## Features

- Subdomain enumeration with Amass
- Technology fingerprinting using httpx
- Header and TLS inspection
- Nuclei vulnerability scanning (with optional -code support)
- Shodan integration (optional)
- LLM-assisted analysis via Mistral/Ollama

## Requirements
- sudo apt update && sudo apt install -y curl git unzip jq
- go install -v github.com/owasp-amass/amass/v3/...@latest
- go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
- go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

- git clone --depth 1 https://github.com/drwetter/testssl.sh.git Tools/testssl
- chmod +x Tools/testssl/testssl.sh

## Usage

```bash
./reconIA.sh example.com
