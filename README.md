# ReconAI

A streamlined attack surface and subdomain enumeration script for pentesters, powered by tools like Subfinder, Nuclei, httpx, and an AI assistant (Mistral via Ollama).

[![asciicast](https://asciinema.org/a/730482.svg)](https://asciinema.org/a/730482)

## Features

- Subdomain enumeration with Subfinder
- Technology fingerprinting using httpx
- Nuclei vulnerability scanning (with optional -code support)
- Shodan integration (optional)
- LLM-assisted analysis via Mistral/Ollama

## Requirements
- **Subfinder** (go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest)
- **httpx** (go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest)
- **nuclei** (go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest)
- **curl, jq** (sudo apt update && sudo apt install -y curl git unzip jq)
- **ollama with mistral** (or whatever you want) model installed


## Usage

```bash
./reconIA.sh example.com
