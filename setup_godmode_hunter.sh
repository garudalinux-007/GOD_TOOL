#!/bin/bash

# ========================================================================
# GODMODE BUG HUNTER SETUP SCRIPT
# Automated installation of all required tools and dependencies
# ========================================================================

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${PURPLE}🚀 GODMODE BUG HUNTER SETUP${NC}"
echo -e "${CYAN}Setting up advanced bug hunting environment...${NC}"
echo ""

# Update system
echo -e "${BLUE}[1/6] Updating system packages...${NC}"
sudo apt-get update -qq
sudo apt-get install -y curl wget git python3 python3-pip jq nmap masscan

# Install Go if not present
if ! command -v go &> /dev/null; then
    echo -e "${BLUE}[2/6] Installing Go...${NC}"
    wget -q https://go.dev/dl/go1.21.0.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
    rm go1.21.0.linux-amd64.tar.gz
else
    echo -e "${GREEN}[2/6] Go already installed${NC}"
fi

# Install Go-based security tools
echo -e "${BLUE}[3/6] Installing Go security tools...${NC}"
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/notify/cmd/notify@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/gf@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/ffuf/ffuf@latest
go install github.com/hahwul/dalfox/v2@latest

# Setup wordlists
echo -e "${BLUE}[4/6] Setting up wordlists...${NC}"
mkdir -p ~/wordlists
cd ~/wordlists

# Download SecLists
if [[ ! -d "SecLists" ]]; then
    git clone https://github.com/danielmiessler/SecLists.git
fi

# Download additional wordlists
wget -q -O subdomains.txt https://raw.githubusercontent.com/assetnote/commonspeak2-wordlists/master/subdomains/subdomains.txt
wget -q -O directory-list-2.3-medium.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-medium.txt
wget -q -O parameters.txt https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/burp-parameter-names.txt

# Setup gf patterns
echo -e "${BLUE}[5/6] Setting up gf patterns...${NC}"
if [[ ! -d ~/.gf ]]; then
    git clone https://github.com/1ndianl33t/Gf-Patterns ~/.gf
fi

# Update nuclei templates
echo -e "${BLUE}[6/6] Updating nuclei templates...${NC}"
nuclei -update-templates -silent

# Make hunting script executable
chmod +x /home/user/Desktop/nut/new_new/hunting_working.sh

echo ""
echo -e "${GREEN}✅ SETUP COMPLETED SUCCESSFULLY!${NC}"
echo ""
echo -e "${CYAN}🔧 CONFIGURATION TIPS:${NC}"
echo -e "${YELLOW}1. Set OpenAI API key: export OPENAI_API_KEY='your-key-here'${NC}"
echo -e "${YELLOW}2. Set Telegram bot: export TELEGRAM_BOT_TOKEN='your-token' TELEGRAM_CHAT_ID='your-chat-id'${NC}"
echo -e "${YELLOW}3. Set Discord webhook: export DISCORD_WEBHOOK='your-webhook-url'${NC}"
echo ""
echo -e "${CYAN}🚀 USAGE:${NC}"
echo -e "${YELLOW}./hunting_working.sh example.com${NC}"
echo ""
echo -e "${GREEN}Happy hunting! 🎯${NC}"
